BEGIN;

CREATE TABLE plugin_catalog_operations (
    operation_record_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    owner_token TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('upload', 'approve', 'publish', 'revoke')),
    state TEXT NOT NULL CHECK (state IN ('pending', 'committed')),
    version_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    semantic_version TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    artifact_bytes BIGINT NOT NULL CHECK (artifact_bytes >= 0),
    definition_json JSONB NOT NULL,
    version_json JSONB NOT NULL,
    response_status INTEGER,
    response_etag TEXT,
    response_body BYTEA,
    audit_event_json BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, operation_record_id),
    UNIQUE (tenant_id, project_id, actor, operation_id, idempotency_key),
    CHECK ((state = 'pending' AND response_status IS NULL AND response_etag IS NULL AND response_body IS NULL)
        OR (state = 'committed' AND response_status BETWEEN 100 AND 599 AND response_etag <> '' AND response_body IS NOT NULL))
);

CREATE UNIQUE INDEX plugin_catalog_upload_reservation_idx
    ON plugin_catalog_operations (tenant_id, project_id, plugin_id, semantic_version)
    WHERE kind = 'upload';

CREATE INDEX plugin_catalog_operations_pending_idx
    ON plugin_catalog_operations (state, updated_at, tenant_id, project_id)
    WHERE state = 'pending';

CREATE OR REPLACE FUNCTION dbpilot_guard_plugin_catalog_operation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'plugin catalog operation history is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.state <> 'pending' OR NEW.state <> 'committed'
       OR NEW.operation_record_id <> OLD.operation_record_id
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.project_id <> OLD.project_id
       OR NEW.actor <> OLD.actor
       OR NEW.operation_id <> OLD.operation_id
       OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.request_fingerprint <> OLD.request_fingerprint
       OR NEW.owner_token <> OLD.owner_token
       OR NEW.kind <> OLD.kind
       OR NEW.version_id <> OLD.version_id
       OR NEW.plugin_id <> OLD.plugin_id
       OR NEW.semantic_version <> OLD.semantic_version
       OR NEW.artifact_id <> OLD.artifact_id
       OR NEW.artifact_sha256 <> OLD.artifact_sha256
       OR NEW.artifact_bytes <> OLD.artifact_bytes
       OR NEW.definition_json <> OLD.definition_json
       OR NEW.audit_event_json <> OLD.audit_event_json
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'plugin catalog operation immutable fields cannot change' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS plugin_catalog_operations_immutable ON plugin_catalog_operations;
CREATE TRIGGER plugin_catalog_operations_immutable
    BEFORE UPDATE OR DELETE ON plugin_catalog_operations
    FOR EACH ROW EXECUTE FUNCTION dbpilot_guard_plugin_catalog_operation_mutation();

COMMIT;
