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

-- Preserve visibility after an upgrade. These historic observations are not
-- treated as fresh heartbeats: last_heartbeat_at deliberately equals the last
-- persisted sample timestamp until the Agent next authenticates an ingest.
INSERT INTO monitoring_instances (tenant_id, project_id, instance_id, agent_id, engine, host, labels, collect_every_ns, last_sample_at, last_heartbeat_at)
SELECT DISTINCT ON (tenant_id, project_id, labels ->> 'instance')
    tenant_id,
    project_id,
    labels ->> 'instance',
    agent_id,
    COALESCE(labels ->> 'engine', ''),
    COALESCE(labels ->> 'host', ''),
    labels,
    60000000000,
    sampled_at,
    sampled_at
FROM metric_samples
WHERE COALESCE(labels ->> 'instance', '') <> ''
ORDER BY tenant_id, project_id, labels ->> 'instance', sampled_at DESC, agent_id ASC
ON CONFLICT (tenant_id, project_id, instance_id) DO NOTHING;

COMMIT;
