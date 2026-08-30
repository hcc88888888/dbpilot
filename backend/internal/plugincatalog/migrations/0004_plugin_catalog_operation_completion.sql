BEGIN;

ALTER TABLE plugin_catalog_operations
    ADD COLUMN completion_reconciled_at TIMESTAMPTZ;

CREATE INDEX plugin_catalog_operations_completion_idx
    ON plugin_catalog_operations (updated_at, tenant_id, project_id, operation_record_id)
    WHERE state = 'committed' AND completion_reconciled_at IS NULL;

CREATE OR REPLACE FUNCTION dbpilot_guard_plugin_catalog_operation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'plugin catalog operation history is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.state = 'committed' AND NEW.state = 'committed'
       AND OLD.completion_reconciled_at IS NULL AND NEW.completion_reconciled_at IS NOT NULL
       AND NEW.operation_record_id = OLD.operation_record_id
       AND NEW.tenant_id = OLD.tenant_id AND NEW.project_id = OLD.project_id
       AND NEW.actor = OLD.actor AND NEW.operation_id = OLD.operation_id
       AND NEW.idempotency_key = OLD.idempotency_key
       AND NEW.request_fingerprint = OLD.request_fingerprint
       AND NEW.owner_token = OLD.owner_token AND NEW.kind = OLD.kind
       AND NEW.version_id = OLD.version_id AND NEW.plugin_id = OLD.plugin_id
       AND NEW.semantic_version = OLD.semantic_version
       AND NEW.artifact_id = OLD.artifact_id AND NEW.artifact_sha256 = OLD.artifact_sha256
       AND NEW.artifact_bytes = OLD.artifact_bytes
       AND NEW.definition_json = OLD.definition_json AND NEW.version_json = OLD.version_json
       AND NEW.response_status = OLD.response_status AND NEW.response_etag = OLD.response_etag
       AND NEW.response_body = OLD.response_body AND NEW.audit_event_json = OLD.audit_event_json
       AND NEW.created_at = OLD.created_at AND NEW.updated_at = OLD.updated_at
       AND NEW.lease_expires_at = OLD.lease_expires_at AND NEW.abandoned_at IS NOT DISTINCT FROM OLD.abandoned_at THEN
        RETURN NEW;
    END IF;
    IF NOT ((OLD.state = 'pending' AND NEW.state IN ('committed', 'abandoned'))
        OR (OLD.state = 'abandoned' AND NEW.state = 'pending'))
       OR NEW.operation_record_id <> OLD.operation_record_id
       OR NEW.tenant_id <> OLD.tenant_id OR NEW.project_id <> OLD.project_id
       OR NEW.actor <> OLD.actor OR NEW.operation_id <> OLD.operation_id
       OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.request_fingerprint <> OLD.request_fingerprint
       OR NEW.owner_token <> OLD.owner_token OR NEW.kind <> OLD.kind
       OR NEW.version_id <> OLD.version_id OR NEW.plugin_id <> OLD.plugin_id
       OR NEW.semantic_version <> OLD.semantic_version
       OR NEW.artifact_id <> OLD.artifact_id OR NEW.artifact_sha256 <> OLD.artifact_sha256
       OR NEW.artifact_bytes <> OLD.artifact_bytes
       OR NEW.definition_json <> OLD.definition_json OR NEW.audit_event_json <> OLD.audit_event_json
       OR NEW.response_status <> OLD.response_status OR NEW.response_etag <> OLD.response_etag
       OR NEW.response_body <> OLD.response_body OR NEW.created_at <> OLD.created_at
       OR NEW.completion_reconciled_at IS DISTINCT FROM OLD.completion_reconciled_at THEN
        RAISE EXCEPTION 'plugin catalog operation immutable fields cannot change' USING ERRCODE = '55000';
    END IF;
    IF OLD.state = 'pending' AND NEW.lease_expires_at <> OLD.lease_expires_at THEN
        RAISE EXCEPTION 'active plugin operation lease cannot change' USING ERRCODE = '55000';
    END IF;
    IF OLD.state = 'abandoned' AND (NEW.lease_expires_at <= OLD.lease_expires_at OR NEW.abandoned_at IS NOT NULL) THEN
        RAISE EXCEPTION 'adopted plugin operation requires a newer lease' USING ERRCODE = '55000';
    END IF;
    IF NEW.state = 'committed' AND NEW.abandoned_at IS NOT NULL THEN
        RAISE EXCEPTION 'committed plugin operation cannot be abandoned' USING ERRCODE = '55000';
    END IF;
    IF NEW.state = 'abandoned' AND NEW.abandoned_at IS NULL THEN
        RAISE EXCEPTION 'abandoned plugin operation requires timestamp' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

COMMIT;
