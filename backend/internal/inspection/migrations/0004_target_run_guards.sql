BEGIN;

CREATE OR REPLACE FUNCTION guard_inspection_target_run_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'inspection target runs cannot be deleted';
    END IF;
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
       OR OLD.project_id IS DISTINCT FROM NEW.project_id
       OR OLD.run_id IS DISTINCT FROM NEW.run_id
       OR OLD.target_id IS DISTINCT FROM NEW.target_id
       OR OLD.agent_id IS DISTINCT FROM NEW.agent_id
       OR OLD.command_id IS DISTINCT FROM NEW.command_id
       OR OLD.target_snapshot IS DISTINCT FROM NEW.target_snapshot THEN
        RAISE EXCEPTION 'inspection target run identity and snapshot are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER inspection_target_runs_guard
BEFORE UPDATE OR DELETE ON inspection_target_runs
FOR EACH ROW EXECUTE FUNCTION guard_inspection_target_run_mutation();

CREATE OR REPLACE FUNCTION reject_inspection_run_delete() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'inspection runs cannot be deleted';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER inspection_runs_delete_guard
BEFORE DELETE ON inspection_runs
FOR EACH ROW EXECUTE FUNCTION reject_inspection_run_delete();

COMMIT;
