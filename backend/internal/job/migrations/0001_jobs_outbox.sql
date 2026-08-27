CREATE TABLE jobs (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'dispatched', 'running', 'succeeded', 'failed', 'cancelling', 'cancelled', 'timed_out')),
    outcome TEXT NOT NULL CHECK (outcome IN ('complete', 'partial', 'none')),
    instance_id TEXT NOT NULL DEFAULT '',
    initiated_by TEXT NOT NULL DEFAULT '',
    source_resource_type TEXT NOT NULL,
    source_resource_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    version BIGINT NOT NULL CHECK (version >= 1),
    total_targets INTEGER NOT NULL CHECK (total_targets >= 0),
    completed_targets INTEGER NOT NULL DEFAULT 0 CHECK (completed_targets >= 0),
    failed_targets INTEGER NOT NULL DEFAULT 0 CHECK (failed_targets >= 0),
    skipped_targets INTEGER NOT NULL DEFAULT 0 CHECK (skipped_targets >= 0),
    error_summary TEXT NOT NULL DEFAULT '',
    result_summary TEXT NOT NULL DEFAULT '',
    artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    dispatched_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    timeout_at TIMESTAMPTZ,
    cancel_requested_by TEXT NOT NULL DEFAULT '',
    cancel_requested_at TIMESTAMPTZ,
    request_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    PRIMARY KEY (tenant_id, project_id, id),
    UNIQUE (tenant_id, project_id, idempotency_key, job_type),
    CHECK (completed_targets + failed_targets + skipped_targets <= total_targets)
);

CREATE INDEX jobs_scope_idx ON jobs (tenant_id, project_id, created_at DESC, id);
CREATE INDEX jobs_scope_status_idx ON jobs (tenant_id, project_id, status, created_at, id);

CREATE TABLE job_targets (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'skipped', 'cancelled', 'timed_out')),
    error_summary TEXT NOT NULL DEFAULT '',
    result_summary TEXT NOT NULL DEFAULT '',
    artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    finished_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, project_id, job_id, target_id),
    FOREIGN KEY (tenant_id, project_id, job_id) REFERENCES jobs (tenant_id, project_id, id) ON DELETE CASCADE
);

CREATE INDEX job_targets_scope_idx ON job_targets (tenant_id, project_id, job_id, status, target_id);

CREATE TABLE command_outbox (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    target_id TEXT NOT NULL DEFAULT '',
    message_type TEXT NOT NULL,
    payload JSONB NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    FOREIGN KEY (tenant_id, project_id, job_id) REFERENCES jobs (tenant_id, project_id, id) ON DELETE CASCADE
);

CREATE INDEX command_outbox_scope_idx ON command_outbox (tenant_id, project_id, job_id, created_at, id);
CREATE INDEX command_outbox_lease_idx ON command_outbox (available_at, lease_expires_at, created_at, id) WHERE published_at IS NULL;
