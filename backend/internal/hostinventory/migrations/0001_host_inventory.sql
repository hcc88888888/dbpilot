BEGIN;

CREATE TABLE managed_hosts (
    tenant_id TEXT NOT NULL CHECK (tenant_id <> '' AND tenant_id = btrim(tenant_id)),
    project_id TEXT NOT NULL CHECK (project_id <> '' AND project_id = btrim(project_id)),
    host_id TEXT PRIMARY KEY CHECK (host_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    agent_id TEXT NOT NULL CHECK (agent_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    display_name TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120 AND display_name = btrim(display_name)),
    hostname TEXT NOT NULL CHECK (char_length(hostname) BETWEEN 1 AND 253 AND hostname = btrim(hostname)),
    operating_system TEXT NOT NULL CHECK (char_length(operating_system) BETWEEN 1 AND 64 AND operating_system = btrim(operating_system)),
    operating_system_version TEXT NOT NULL DEFAULT '' CHECK (char_length(operating_system_version) <= 128),
    kernel_version TEXT NOT NULL DEFAULT '' CHECK (char_length(kernel_version) <= 128),
    architecture TEXT NOT NULL CHECK (char_length(architecture) BETWEEN 1 AND 32 AND architecture = btrim(architecture)),
    logical_cpu_count INTEGER NOT NULL DEFAULT 0 CHECK (logical_cpu_count >= 0),
    memory_capacity_bytes BIGINT NOT NULL DEFAULT 0 CHECK (memory_capacity_bytes >= 0),
    filesystems JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(filesystems) = 'array' AND jsonb_array_length(filesystems) <= 128 AND octet_length(filesystems::text) <= 131072),
    network_addresses JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(network_addresses) = 'array' AND jsonb_array_length(network_addresses) <= 32 AND octet_length(network_addresses::text) <= 8192),
    labels JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(labels) = 'object' AND octet_length(labels::text) <= 16384),
    container_runtime TEXT NOT NULL DEFAULT 'none' CHECK (container_runtime IN ('none', 'docker')),
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(capabilities) = 'array' AND jsonb_array_length(capabilities) <= 64 AND octet_length(capabilities::text) <= 32768),
    agent_version TEXT NOT NULL DEFAULT '' CHECK (char_length(agent_version) <= 64),
    enrollment_revision BIGINT NOT NULL DEFAULT 1 CHECK (enrollment_revision >= 1),
    observation_revision BIGINT NOT NULL CHECK (observation_revision >= 0),
    enrolled_at TIMESTAMPTZ NOT NULL,
    last_hello_at TIMESTAMPTZ,
    last_heartbeat_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('pending', 'enrolling', 'online', 'stale', 'offline', 'decommissioned')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1),
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (agent_id),
    UNIQUE (tenant_id, project_id, host_id),
    UNIQUE (tenant_id, project_id, agent_id),
    UNIQUE (tenant_id, project_id, host_id, agent_id)
);

CREATE INDEX managed_hosts_scope_page_idx
    ON managed_hosts (tenant_id, project_id, host_id);
CREATE INDEX managed_hosts_scope_status_page_idx
    ON managed_hosts (tenant_id, project_id, status, host_id);

CREATE TABLE host_observations (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    observation_revision BIGINT NOT NULL CHECK (observation_revision >= 1),
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot) = 'object' AND octet_length(snapshot::text) <= 262144),
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, host_id, observation_revision),
    FOREIGN KEY (tenant_id, project_id, host_id)
        REFERENCES managed_hosts (tenant_id, project_id, host_id),
    FOREIGN KEY (tenant_id, project_id, agent_id)
        REFERENCES managed_hosts (tenant_id, project_id, agent_id),
    FOREIGN KEY (tenant_id, project_id, host_id, agent_id)
        REFERENCES managed_hosts (tenant_id, project_id, host_id, agent_id)
);

CREATE OR REPLACE FUNCTION reject_host_observation_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'host observations are append-only';
END;
$$;

CREATE TRIGGER host_observations_append_only
BEFORE UPDATE OR DELETE ON host_observations
FOR EACH ROW EXECUTE FUNCTION reject_host_observation_mutation();

COMMIT;
