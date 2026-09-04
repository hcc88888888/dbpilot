BEGIN;

CREATE TABLE agent_credential_imports (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    credential_generation BIGINT NOT NULL CHECK (credential_generation = 1),
    certificate_fingerprint BYTEA NOT NULL CHECK (octet_length(certificate_fingerprint) = 32),
    certificate_serial TEXT NOT NULL CHECK (certificate_serial ~ '^[0-9a-f]+$'),
    imported_at TIMESTAMPTZ NOT NULL,
    import_source TEXT NOT NULL CHECK (import_source = 'verified_mtls'),
    PRIMARY KEY (tenant_id, project_id, host_id, agent_id),
    UNIQUE (certificate_fingerprint),
    FOREIGN KEY (tenant_id, project_id, host_id, agent_id)
        REFERENCES managed_hosts (tenant_id, project_id, host_id, agent_id)
);

CREATE UNIQUE INDEX managed_hosts_active_certificate_fingerprint_idx
    ON managed_hosts (active_certificate_fingerprint)
    WHERE octet_length(active_certificate_fingerprint) = 32;

COMMIT;
