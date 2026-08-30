BEGIN;

ALTER TABLE managed_hosts
    ADD COLUMN decommission_actor TEXT
        CHECK (decommission_actor IS NULL OR (char_length(decommission_actor) BETWEEN 1 AND 256 AND decommission_actor = btrim(decommission_actor))),
    ADD COLUMN decommission_operation TEXT
        CHECK (decommission_operation IS NULL OR decommission_operation = 'decommissionHost'),
    ADD COLUMN decommission_idempotency_key TEXT
        CHECK (decommission_idempotency_key IS NULL OR (char_length(decommission_idempotency_key) BETWEEN 1 AND 256 AND decommission_idempotency_key = btrim(decommission_idempotency_key))),
    ADD COLUMN decommission_fingerprint TEXT
        CHECK (decommission_fingerprint IS NULL OR decommission_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN decommission_owner_token TEXT
        CHECK (decommission_owner_token IS NULL OR decommission_owner_token ~ '^owner-[0-9a-f]{64}$'),
    ADD CONSTRAINT managed_hosts_decommission_correlation CHECK (
        (decommission_actor IS NULL AND decommission_operation IS NULL AND decommission_idempotency_key IS NULL AND decommission_fingerprint IS NULL AND decommission_owner_token IS NULL)
        OR
        (status = 'decommissioned' AND decommission_actor IS NOT NULL AND decommission_operation IS NOT NULL AND decommission_idempotency_key IS NOT NULL AND decommission_fingerprint IS NOT NULL AND decommission_owner_token IS NOT NULL)
    );

COMMIT;
