BEGIN;

CREATE TABLE inspection_items (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    enabled BOOLEAN NOT NULL,
    system BOOLEAN NOT NULL,
    category TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('metric', 'metadata', 'log_summary')),
    snapshot JSONB NOT NULL CHECK (octet_length(snapshot::text) <= 262144),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, item_id, version)
);

CREATE INDEX inspection_items_scope_created_idx ON inspection_items (tenant_id, project_id, created_at DESC, item_id DESC);

CREATE TABLE inspection_policies (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    schedule_cron TEXT,
    schedule_timezone TEXT,
    next_run_at TIMESTAMPTZ,
    target_selector JSONB NOT NULL CHECK (octet_length(target_selector::text) <= 1048576),
    item_snapshot JSONB NOT NULL CHECK (octet_length(item_snapshot::text) <= 262144),
    target_timeout_seconds INTEGER NOT NULL CHECK (target_timeout_seconds BETWEEN 1 AND 3600),
    max_concurrency INTEGER NOT NULL CHECK (max_concurrency BETWEEN 1 AND 1000),
    claim_token TEXT,
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, id),
    CHECK ((schedule_cron IS NULL) = (schedule_timezone IS NULL)),
    CHECK ((claim_token IS NULL) = (lease_expires_at IS NULL))
);

CREATE INDEX inspection_policies_due_idx ON inspection_policies (enabled, next_run_at, lease_expires_at);
CREATE INDEX inspection_policies_scope_created_idx ON inspection_policies (tenant_id, project_id, created_at DESC, id DESC);

CREATE TABLE inspection_policy_items (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    item_version INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    PRIMARY KEY (tenant_id, project_id, policy_id, item_id, item_version),
    UNIQUE (tenant_id, project_id, policy_id, ordinal),
    FOREIGN KEY (tenant_id, project_id, policy_id) REFERENCES inspection_policies (tenant_id, project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, project_id, item_id, item_version) REFERENCES inspection_items (tenant_id, project_id, item_id, version)
);

CREATE TABLE inspection_runs (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    id TEXT NOT NULL,
    policy_id TEXT,
    policy_version BIGINT,
    retry_of_run_id TEXT,
    job_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'collecting', 'evaluating', 'generating_report', 'completed', 'partial', 'failed', 'cancelled')),
    trigger_source TEXT NOT NULL CHECK (trigger_source IN ('manual', 'scheduled', 'retry')),
    occurrence_key TEXT,
    scheduled_for TIMESTAMPTZ,
    policy_snapshot JSONB CHECK (policy_snapshot IS NULL OR octet_length(policy_snapshot::text) <= 1048576),
    item_snapshot JSONB NOT NULL CHECK (octet_length(item_snapshot::text) <= 1048576),
    target_count INTEGER NOT NULL CHECK (target_count BETWEEN 1 AND 10000),
    completed_target_count INTEGER NOT NULL DEFAULT 0,
    failed_target_count INTEGER NOT NULL DEFAULT 0,
    report_id TEXT,
    audit_correlation TEXT NOT NULL,
    idempotency_key TEXT,
    initiated_by TEXT NOT NULL,
    request_id TEXT NOT NULL,
    trace_id TEXT NOT NULL DEFAULT '',
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, id),
    UNIQUE (tenant_id, project_id, occurrence_key),
    FOREIGN KEY (tenant_id, project_id, policy_id) REFERENCES inspection_policies (tenant_id, project_id, id),
    FOREIGN KEY (tenant_id, project_id, retry_of_run_id) REFERENCES inspection_runs (tenant_id, project_id, id),
    FOREIGN KEY (tenant_id, project_id, job_id) REFERENCES jobs (tenant_id, project_id, id) DEFERRABLE INITIALLY DEFERRED
);

CREATE UNIQUE INDEX inspection_runs_idempotency_idx ON inspection_runs (tenant_id, project_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX inspection_runs_scope_created_idx ON inspection_runs (tenant_id, project_id, created_at DESC, id DESC);

CREATE TABLE inspection_target_runs (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'collecting', 'evaluating', 'succeeded', 'failed', 'unsupported', 'cancelled')),
    target_snapshot JSONB NOT NULL CHECK (octet_length(target_snapshot::text) <= 262144),
    error_code TEXT NOT NULL DEFAULT '',
    observed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, project_id, run_id, target_id),
    UNIQUE (tenant_id, project_id, command_id),
    FOREIGN KEY (tenant_id, project_id, run_id) REFERENCES inspection_runs (tenant_id, project_id, id) ON DELETE CASCADE
);

CREATE INDEX inspection_target_runs_agent_idx ON inspection_target_runs (tenant_id, project_id, agent_id, run_id);

CREATE TABLE inspection_findings (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    item_id TEXT NOT NULL,
    item_version INTEGER NOT NULL,
    level TEXT NOT NULL CHECK (level IN ('healthy', 'warning', 'critical', 'unsupported', 'missing_data')),
    observed_at TIMESTAMPTZ NOT NULL,
    evidence JSONB NOT NULL CHECK (octet_length(evidence::text) <= 65536),
    warning_threshold DOUBLE PRECISION,
    critical_threshold DOUBLE PRECISION,
    summary TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, project_id, id),
    UNIQUE (tenant_id, project_id, run_id, target_id, item_id, item_version),
    FOREIGN KEY (tenant_id, project_id, run_id, target_id) REFERENCES inspection_target_runs (tenant_id, project_id, run_id, target_id),
    FOREIGN KEY (tenant_id, project_id, item_id, item_version) REFERENCES inspection_items (tenant_id, project_id, item_id, version)
);

CREATE INDEX inspection_findings_run_idx ON inspection_findings (tenant_id, project_id, run_id, target_id, item_id, item_version);

CREATE TABLE inspection_reports (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    policy_id TEXT,
    status TEXT NOT NULL CHECK (status IN ('generating', 'completed', 'failed')),
    summary TEXT NOT NULL DEFAULT '',
    snapshot JSONB NOT NULL CHECK (octet_length(snapshot::text) <= 1048576),
    artifacts JSONB NOT NULL CHECK (octet_length(artifacts::text) <= 65536),
    generated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, id),
    UNIQUE (tenant_id, project_id, run_id),
    FOREIGN KEY (tenant_id, project_id, run_id) REFERENCES inspection_runs (tenant_id, project_id, id),
    FOREIGN KEY (tenant_id, project_id, policy_id) REFERENCES inspection_policies (tenant_id, project_id, id)
);

CREATE INDEX inspection_reports_scope_created_idx ON inspection_reports (tenant_id, project_id, generated_at DESC, id DESC);

CREATE OR REPLACE FUNCTION reject_inspection_report_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'inspection reports are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER inspection_reports_immutable
BEFORE UPDATE OR DELETE ON inspection_reports
FOR EACH ROW EXECUTE FUNCTION reject_inspection_report_mutation();

COMMIT;
