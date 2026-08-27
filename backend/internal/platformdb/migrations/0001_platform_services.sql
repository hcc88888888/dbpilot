BEGIN;

CREATE TABLE artifacts (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    checksum TEXT NOT NULL,
    source_resource_type TEXT NOT NULL DEFAULT '',
    source_resource_id TEXT NOT NULL DEFAULT '',
    job_id TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    storage_reference TEXT NOT NULL,
    PRIMARY KEY (tenant_id, project_id, id),
    CHECK ((source_resource_type = '') = (source_resource_id = '')),
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX artifacts_scope_created_idx
    ON artifacts (tenant_id, project_id, created_at DESC, id DESC);
CREATE INDEX artifacts_scope_job_idx
    ON artifacts (tenant_id, project_id, job_id)
    WHERE job_id <> '';

CREATE TABLE audit_events (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    action TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    result TEXT NOT NULL,
    request_id TEXT NOT NULL,
    trace_id TEXT NOT NULL DEFAULT '',
    job_id TEXT NOT NULL DEFAULT '',
    command_id TEXT NOT NULL DEFAULT '',
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, project_id, id)
);

CREATE INDEX audit_events_scope_cursor_idx
    ON audit_events (tenant_id, project_id, created_at ASC, id ASC);
CREATE INDEX audit_events_scope_resource_idx
    ON audit_events (tenant_id, project_id, resource_type, resource_id, created_at DESC);
CREATE INDEX audit_events_scope_request_idx
    ON audit_events (tenant_id, project_id, request_id, created_at DESC);

CREATE OR REPLACE FUNCTION dbpilot_reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events;
CREATE TRIGGER audit_events_append_only
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION dbpilot_reject_audit_event_mutation();

COMMIT;
