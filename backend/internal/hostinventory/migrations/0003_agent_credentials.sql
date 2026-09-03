BEGIN;

ALTER TABLE managed_hosts
    ADD COLUMN credential_generation BIGINT NOT NULL DEFAULT 0 CHECK (credential_generation >= 0),
    ADD COLUMN active_certificate_fingerprint BYTEA NOT NULL DEFAULT ''::bytea
        CHECK (octet_length(active_certificate_fingerprint) IN (0, 32)),
    ADD COLUMN active_certificate_serial TEXT NOT NULL DEFAULT ''
        CHECK (active_certificate_serial = '' OR active_certificate_serial ~ '^[0-9a-f]+$'),
    ADD COLUMN credential_revoked_at TIMESTAMPTZ,
    ADD CONSTRAINT managed_hosts_active_credential_shape CHECK (
        (octet_length(active_certificate_fingerprint) = 32 AND active_certificate_serial <> '' AND credential_generation >= 1 AND credential_revoked_at IS NULL AND status <> 'decommissioned')
        OR
        (octet_length(active_certificate_fingerprint) = 0 AND active_certificate_serial = '' AND credential_revoked_at IS NULL AND credential_generation = 0)
        OR
        (octet_length(active_certificate_fingerprint) = 0 AND active_certificate_serial = '' AND credential_revoked_at IS NOT NULL AND credential_generation >= 1 AND status = 'decommissioned')
    );

COMMIT;
