BEGIN;

ALTER TABLE agent_enrollment_tokens
    ADD COLUMN IF NOT EXISTS request_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS generation BIGINT;

UPDATE agent_enrollment_tokens
SET request_fingerprint = COALESCE(request_fingerprint, 'sha256:' || encode(token_hash, 'hex')),
    generation = COALESCE(generation, 1)
WHERE request_fingerprint IS NULL OR generation IS NULL;

ALTER TABLE agent_enrollment_tokens
    ALTER COLUMN request_fingerprint SET NOT NULL,
    ALTER COLUMN generation SET NOT NULL;

ALTER TABLE agent_enrollment_tokens
    DROP CONSTRAINT IF EXISTS agent_enrollment_tokens_request_fingerprint_check,
    DROP CONSTRAINT IF EXISTS agent_enrollment_tokens_generation_check;

ALTER TABLE agent_enrollment_tokens
    ADD CONSTRAINT agent_enrollment_tokens_request_fingerprint_check
        CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    ADD CONSTRAINT agent_enrollment_tokens_generation_check
        CHECK (generation >= 1);

CREATE TABLE IF NOT EXISTS agent_enrollment_issuances (
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

CREATE UNIQUE INDEX IF NOT EXISTS agent_enrollment_issuances_identity_idx
    ON agent_enrollment_issuances (tenant_id, project_id, host_id, agent_id, csr_digest);

WITH ranked_active_tokens AS (
    SELECT token_hash,
           row_number() OVER (
               PARTITION BY tenant_id, project_id, host_id, agent_id
               ORDER BY created_at DESC, encode(token_hash, 'hex') DESC
           ) AS position
    FROM agent_enrollment_tokens
    WHERE consumed_at IS NULL
)
UPDATE agent_enrollment_tokens AS token
SET consumed_at = CURRENT_TIMESTAMP
FROM ranked_active_tokens AS ranked
WHERE token.token_hash = ranked.token_hash
  AND ranked.position > 1;

CREATE UNIQUE INDEX IF NOT EXISTS agent_enrollment_tokens_active_host_idx
    ON agent_enrollment_tokens (tenant_id, project_id, host_id, agent_id)
    WHERE consumed_at IS NULL;

COMMIT;
