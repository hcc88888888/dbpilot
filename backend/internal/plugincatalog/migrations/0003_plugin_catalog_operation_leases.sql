BEGIN;

ALTER TABLE plugin_catalog_operations
    ADD COLUMN lease_expires_at TIMESTAMPTZ,
    ADD COLUMN abandoned_at TIMESTAMPTZ;

UPDATE plugin_catalog_operations
SET lease_expires_at = created_at + INTERVAL '10 minutes'
WHERE lease_expires_at IS NULL;

ALTER TABLE plugin_catalog_operations
    ALTER COLUMN lease_expires_at SET NOT NULL;

DO $$
DECLARE constraint_row RECORD;
BEGIN
    FOR constraint_row IN
        SELECT conname, pg_get_constraintdef(oid) AS definition
        FROM pg_constraint
        WHERE conrelid = 'plugin_catalog_operations'::regclass AND contype = 'c'
    LOOP
        IF constraint_row.definition LIKE '%state%' OR constraint_row.definition LIKE '%response_status%' THEN
            EXECUTE format('ALTER TABLE plugin_catalog_operations DROP CONSTRAINT %I', constraint_row.conname);
        END IF;
    END LOOP;
END;
$$;

ALTER TABLE plugin_catalog_operations DISABLE TRIGGER plugin_catalog_operations_immutable;
UPDATE plugin_catalog_operations
SET state = 'abandoned', response_status = 409, response_etag = '"0"',
    response_body = convert_to('{"code":"legacy_pending_abandoned"}', 'UTF8'),
    abandoned_at = NOW(), updated_at = NOW()
WHERE state = 'pending' AND response_status IS NULL;
ALTER TABLE plugin_catalog_operations ENABLE TRIGGER plugin_catalog_operations_immutable;

ALTER TABLE plugin_catalog_operations
    ADD CONSTRAINT plugin_catalog_operations_state_v2_check
        CHECK (state IN ('pending', 'committed', 'abandoned')),
    ADD CONSTRAINT plugin_catalog_operations_response_v2_check
        CHECK ((state IN ('pending', 'committed') AND response_status BETWEEN 100 AND 599 AND response_etag <> '' AND response_body IS NOT NULL AND abandoned_at IS NULL)
            OR (state = 'abandoned' AND response_status BETWEEN 100 AND 599 AND response_etag <> '' AND response_body IS NOT NULL AND abandoned_at IS NOT NULL));

DROP INDEX plugin_catalog_upload_reservation_idx;
CREATE UNIQUE INDEX plugin_catalog_upload_reservation_idx
    ON plugin_catalog_operations (tenant_id, project_id, plugin_id, semantic_version)
    WHERE kind = 'upload' AND state IN ('pending', 'committed');

CREATE INDEX plugin_catalog_operations_expired_lease_idx
    ON plugin_catalog_operations (lease_expires_at, tenant_id, project_id, operation_record_id)
    WHERE kind = 'upload' AND state = 'pending';

CREATE OR REPLACE FUNCTION dbpilot_guard_plugin_catalog_operation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'plugin catalog operation history is immutable' USING ERRCODE = '55000';
    END IF;
    IF NOT ((OLD.state = 'pending' AND NEW.state IN ('committed', 'abandoned'))
        OR (OLD.state = 'abandoned' AND NEW.state = 'pending'))
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
       OR NEW.response_status <> OLD.response_status
       OR NEW.response_etag <> OLD.response_etag
       OR NEW.response_body <> OLD.response_body
       OR NEW.created_at <> OLD.created_at THEN
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
