BEGIN;

ALTER TABLE inspection_runs
    ADD COLUMN worker_claim_token TEXT,
    ADD COLUMN worker_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN report_generated_at TIMESTAMPTZ,
    ADD COLUMN report_audit_pending BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN report_audit_event JSONB,
    ADD COLUMN report_audit_dedupe_key TEXT,
    ADD COLUMN report_audit_claim_token TEXT,
    ADD COLUMN report_audit_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN report_audit_attempts INTEGER NOT NULL DEFAULT 0 CHECK (report_audit_attempts >= 0),
    ADD COLUMN report_audit_recorded_at TIMESTAMPTZ,
    ADD CONSTRAINT inspection_runs_worker_claim_pair CHECK ((worker_claim_token IS NULL) = (worker_lease_expires_at IS NULL)),
    ADD CONSTRAINT inspection_runs_report_audit_claim_pair CHECK ((report_audit_claim_token IS NULL) = (report_audit_lease_expires_at IS NULL)),
    ADD CONSTRAINT inspection_runs_report_audit_payload CHECK (
        NOT report_audit_pending OR (report_audit_event IS NOT NULL AND report_audit_dedupe_key IS NOT NULL)
    );

CREATE INDEX inspection_runs_worker_claim_idx
ON inspection_runs (status, worker_lease_expires_at, created_at, tenant_id, project_id, id)
WHERE status IN ('queued', 'collecting', 'evaluating', 'generating_report');

CREATE INDEX inspection_runs_report_audit_idx
ON inspection_runs (report_audit_lease_expires_at, finished_at, tenant_id, project_id, id)
WHERE report_audit_pending = TRUE;

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
       OR OLD.audit_correlation IS DISTINCT FROM NEW.audit_correlation
       OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
       OR OLD.initiated_by IS DISTINCT FROM NEW.initiated_by
       OR OLD.request_id IS DISTINCT FROM NEW.request_id
       OR OLD.trace_id IS DISTINCT FROM NEW.trace_id
       OR OLD.created_at IS DISTINCT FROM NEW.created_at
       OR (OLD.report_generated_at IS NOT NULL AND OLD.report_generated_at IS DISTINCT FROM NEW.report_generated_at)
       OR (OLD.report_audit_event IS NOT NULL AND OLD.report_audit_event IS DISTINCT FROM NEW.report_audit_event)
       OR (OLD.report_audit_dedupe_key IS NOT NULL AND OLD.report_audit_dedupe_key IS DISTINCT FROM NEW.report_audit_dedupe_key) THEN
        RAISE EXCEPTION 'inspection run identity and snapshots are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

COMMIT;
