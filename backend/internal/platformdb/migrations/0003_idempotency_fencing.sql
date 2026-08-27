BEGIN;

ALTER TABLE idempotency_records
    ADD COLUMN owner_token TEXT;

-- Existing unresolved rows receive an unguessable-to-clients legacy fence.
-- They remain processing and require future administrative reconciliation.
UPDATE idempotency_records
SET owner_token = 'owner-'
    || md5(tenant_id || project_id || actor || operation_id || idempotency_key || request_fingerprint || created_at::text)
    || md5(updated_at::text || request_fingerprint || idempotency_key || operation_id || actor || project_id || tenant_id);

ALTER TABLE idempotency_records
    ALTER COLUMN owner_token SET NOT NULL,
    ADD CONSTRAINT idempotency_owner_token_format
        CHECK (owner_token ~ '^owner-[0-9a-f]{64}$');

COMMIT;
