CREATE TABLE job_cancellation_snapshots (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    owner_token TEXT NOT NULL,
    if_match TEXT NOT NULL,
    current_version BIGINT NOT NULL CHECK (current_version >= 1),
    job_snapshot BYTEA NOT NULL,
    audit_event_json BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, job_id),
    UNIQUE (tenant_id, project_id, actor, operation_id, idempotency_key),
    FOREIGN KEY (tenant_id, project_id, job_id)
        REFERENCES jobs (tenant_id, project_id, id) ON DELETE CASCADE,
    CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    CHECK (owner_token ~ '^owner-[0-9a-f]{64}$'),
    CHECK (octet_length(job_snapshot) > 0),
    CHECK (octet_length(audit_event_json) > 0)
);

CREATE INDEX job_cancellation_snapshots_correlation_idx
    ON job_cancellation_snapshots (
        tenant_id, project_id, actor, operation_id, idempotency_key,
        request_fingerprint, if_match
    );
