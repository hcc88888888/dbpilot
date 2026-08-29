BEGIN;

ALTER TABLE inspection_runs
    ADD COLUMN idempotency_actor TEXT,
    ADD COLUMN idempotency_operation TEXT,
    ADD COLUMN idempotency_fingerprint TEXT;

UPDATE inspection_runs
SET idempotency_actor = initiated_by,
    idempotency_operation = CASE
        WHEN trigger_source = 'retry' THEN 'RetryInspectionRun'
        WHEN trigger_source = 'scheduled' THEN 'ScheduleInspectionPolicy'
        WHEN policy_id IS NOT NULL THEN 'RunInspectionPolicy'
        ELSE 'CreateInspectionRun'
    END,
    idempotency_fingerprint = 'sha256:' || md5(COALESCE(idempotency_key, '') || ':' || id) || md5(id || ':' || COALESCE(idempotency_key, ''));

ALTER TABLE inspection_runs
    ALTER COLUMN idempotency_actor SET NOT NULL,
    ALTER COLUMN idempotency_operation SET NOT NULL,
    ALTER COLUMN idempotency_fingerprint SET NOT NULL,
    ADD CONSTRAINT inspection_runs_idempotency_actor_not_blank CHECK (btrim(idempotency_actor) <> ''),
    ADD CONSTRAINT inspection_runs_idempotency_operation_not_blank CHECK (btrim(idempotency_operation) <> ''),
    ADD CONSTRAINT inspection_runs_idempotency_fingerprint_shape CHECK (idempotency_fingerprint ~ '^sha256:[0-9a-f]{64}$');

DROP INDEX inspection_runs_idempotency_idx;
CREATE UNIQUE INDEX inspection_runs_idempotency_v2_idx
    ON inspection_runs (tenant_id, project_id, idempotency_actor, idempotency_operation, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

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
       OR OLD.idempotency_actor IS DISTINCT FROM NEW.idempotency_actor
       OR OLD.idempotency_operation IS DISTINCT FROM NEW.idempotency_operation
       OR OLD.idempotency_fingerprint IS DISTINCT FROM NEW.idempotency_fingerprint
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
