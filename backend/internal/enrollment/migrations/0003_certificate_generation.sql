BEGIN;

ALTER TABLE agent_enrollment_issuances
    ADD COLUMN credential_generation BIGINT CHECK (credential_generation >= 1),
    ADD COLUMN certificate_fingerprint BYTEA CHECK (certificate_fingerprint IS NULL OR octet_length(certificate_fingerprint) = 32),
    ADD COLUMN certificate_serial TEXT CHECK (certificate_serial IS NULL OR certificate_serial ~ '^[0-9a-f]+$'),
    ADD COLUMN revoked_at TIMESTAMPTZ;

WITH ranked_generations AS (
    SELECT token_hash,
           row_number() OVER (
               PARTITION BY tenant_id, project_id, host_id, agent_id
               ORDER BY created_at, encode(token_hash, 'hex')
           ) AS credential_generation
    FROM agent_enrollment_tokens
)
UPDATE agent_enrollment_tokens token
SET generation = ranked.credential_generation
FROM ranked_generations ranked
WHERE token.token_hash = ranked.token_hash
  AND token.generation <> ranked.credential_generation;

CREATE UNIQUE INDEX agent_enrollment_tokens_identity_generation_idx
    ON agent_enrollment_tokens (tenant_id, project_id, host_id, agent_id, generation);

CREATE UNIQUE INDEX agent_enrollment_issuances_fingerprint_idx
    ON agent_enrollment_issuances (certificate_fingerprint)
    WHERE certificate_fingerprint IS NOT NULL;

COMMIT;
