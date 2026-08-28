BEGIN;

CREATE OR REPLACE FUNCTION reject_inspection_history_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER inspection_items_immutable
BEFORE UPDATE OR DELETE ON inspection_items
FOR EACH ROW EXECUTE FUNCTION reject_inspection_history_mutation();

CREATE TRIGGER inspection_findings_immutable
BEFORE UPDATE OR DELETE ON inspection_findings
FOR EACH ROW EXECUTE FUNCTION reject_inspection_history_mutation();

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
       OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'inspection run identity and snapshots are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER inspection_runs_immutable_fields
BEFORE UPDATE ON inspection_runs
FOR EACH ROW EXECUTE FUNCTION reject_inspection_run_immutable_field_mutation();

COMMIT;
