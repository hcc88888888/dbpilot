BEGIN;

ALTER TABLE inspection_runs
    ADD COLUMN target_timeout_seconds INTEGER,
    ADD COLUMN max_concurrency INTEGER;

UPDATE inspection_runs
SET target_timeout_seconds = CASE
        WHEN jsonb_typeof(policy_snapshot->'target_timeout') = 'number'
            THEN GREATEST(1, LEAST(3600, ((policy_snapshot->>'target_timeout')::NUMERIC / 1000000000)::INTEGER))
        ELSE 60
    END,
    max_concurrency = CASE
        WHEN jsonb_typeof(policy_snapshot->'max_concurrency') = 'number'
            THEN GREATEST(1, LEAST(1000, (policy_snapshot->>'max_concurrency')::INTEGER))
        ELSE 1
    END;

ALTER TABLE inspection_runs
    ALTER COLUMN target_timeout_seconds SET DEFAULT 60,
    ALTER COLUMN target_timeout_seconds SET NOT NULL,
    ALTER COLUMN max_concurrency SET DEFAULT 1,
    ALTER COLUMN max_concurrency SET NOT NULL,
    ADD CONSTRAINT inspection_runs_target_timeout_bounds CHECK (target_timeout_seconds BETWEEN 1 AND 3600),
    ADD CONSTRAINT inspection_runs_max_concurrency_bounds CHECK (max_concurrency BETWEEN 1 AND 1000);

CREATE OR REPLACE FUNCTION reject_inspection_run_immutable_field_mutation() RETURNS trigger AS $$
BEGIN
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.project_id IS DISTINCT FROM NEW.project_id
       OR OLD.id IS DISTINCT FROM NEW.id
       OR OLD.policy_id IS DISTINCT FROM NEW.policy_id
       OR OLD.policy_version IS DISTINCT FROM NEW.policy_version
       OR OLD.retry_of_run_id IS DISTINCT FROM NEW.retry_of_run_id
       OR OLD.job_id IS DISTINCT FROM NEW.job_id
       OR OLD.trigger_source IS DISTINCT FROM NEW.trigger_source
       OR OLD.occurrence_key IS DISTINCT FROM NEW.occurrence_key
       OR OLD.scheduled_for IS DISTINCT FROM NEW.scheduled_for
       OR OLD.policy_snapshot IS DISTINCT FROM NEW.policy_snapshot
       OR OLD.item_snapshot IS DISTINCT FROM NEW.item_snapshot
       OR OLD.target_count IS DISTINCT FROM NEW.target_count
       OR OLD.target_timeout_seconds IS DISTINCT FROM NEW.target_timeout_seconds
       OR OLD.max_concurrency IS DISTINCT FROM NEW.max_concurrency
       OR OLD.audit_correlation IS DISTINCT FROM NEW.audit_correlation
       OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
       OR OLD.initiated_by IS DISTINCT FROM NEW.initiated_by
       OR OLD.request_id IS DISTINCT FROM NEW.request_id
       OR OLD.trace_id IS DISTINCT FROM NEW.trace_id
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'inspection run identity and snapshots are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMIT;
