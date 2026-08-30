BEGIN;

CREATE TABLE agent_enrollment_tokens (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    tenant_id TEXT NOT NULL CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    project_id TEXT NOT NULL CHECK (project_id <> '' AND project_id = btrim(project_id)),
    host_id TEXT NOT NULL CHECK (host_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    agent_id TEXT NOT NULL CHECK (agent_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120 AND display_name = btrim(display_name)),
    labels JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(labels) = 'object' AND octet_length(labels::text) <= 16384),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    enrollment_revision BIGINT NOT NULL CHECK (enrollment_revision >= 1),
    issued_by TEXT NOT NULL CHECK (char_length(issued_by) BETWEEN 1 AND 256 AND issued_by = btrim(issued_by)),
    idempotency_key TEXT NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128 AND idempotency_key = btrim(idempotency_key)),
    request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    generation BIGINT NOT NULL CHECK (generation >= 1),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at),
    UNIQUE (tenant_id, project_id, issued_by, idempotency_key)
);

CREATE INDEX agent_enrollment_tokens_expiry_idx
    ON agent_enrollment_tokens (expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE agent_enrollment_issuances (
    token_hash BYTEA PRIMARY KEY REFERENCES agent_enrollment_tokens (token_hash),
    csr_digest BYTEA NOT NULL CHECK (octet_length(csr_digest) = 32),
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    certificate_pem BYTEA NOT NULL CHECK (octet_length(certificate_pem) BETWEEN 1 AND 262144),
    certificate_chain_pem BYTEA NOT NULL CHECK (octet_length(certificate_chain_pem) BETWEEN 1 AND 262144),
    expires_at TIMESTAMPTZ NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    enrollment_revision BIGINT NOT NULL CHECK (enrollment_revision >= 1),
    FOREIGN KEY (tenant_id, project_id, host_id, agent_id)
        REFERENCES managed_hosts (tenant_id, project_id, host_id, agent_id)
);

CREATE UNIQUE INDEX agent_enrollment_issuances_identity_idx
    ON agent_enrollment_issuances (tenant_id, project_id, host_id, agent_id, csr_digest);

COMMIT;
