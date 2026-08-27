BEGIN;

CREATE TABLE idempotency_records (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('processing', 'completed')),
    response_status INTEGER NOT NULL DEFAULT 0,
    response_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_json BYTEA,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, actor, operation_id, idempotency_key),
    CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (expires_at > created_at),
    CHECK (
        (state = 'processing' AND response_status = 0 AND response_json IS NULL)
        OR
        (state = 'completed' AND response_status BETWEEN 100 AND 599 AND response_json IS NOT NULL)
    )
);

CREATE INDEX idempotency_records_expiry_idx
    ON idempotency_records (expires_at);

COMMIT;
