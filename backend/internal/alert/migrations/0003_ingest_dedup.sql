BEGIN;

CREATE TABLE ingest_batch_dedup (
    agent_id TEXT NOT NULL,
    batch_id TEXT NOT NULL,
    accepted BOOLEAN NOT NULL,
    retryable BOOLEAN NOT NULL,
    error_code TEXT NOT NULL DEFAULT '',
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (agent_id, batch_id)
);

COMMIT;
