BEGIN;

CREATE FUNCTION dbpilot_reject_agent_credential_import_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'agent credential import records are immutable'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER agent_credential_imports_immutable
BEFORE UPDATE OR DELETE ON agent_credential_imports
FOR EACH ROW
EXECUTE FUNCTION dbpilot_reject_agent_credential_import_mutation();

COMMIT;
