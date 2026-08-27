BEGIN;

-- Inventory is updated only by the authenticated metric ingestion path. It
-- retains liveness independently from the selected metrics display range.
CREATE TABLE monitoring_instances (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    engine TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    collect_every_ns BIGINT NOT NULL DEFAULT 60000000000,
    last_sample_at TIMESTAMPTZ NOT NULL,
    last_heartbeat_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, instance_id)
);
CREATE INDEX monitoring_instances_scope_heartbeat_idx ON monitoring_instances (tenant_id, project_id, last_heartbeat_at DESC, instance_id);

COMMIT;
