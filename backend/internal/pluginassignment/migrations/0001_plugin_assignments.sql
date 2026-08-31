BEGIN;

CREATE TABLE plugin_assignments (
    assignment_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    database_family TEXT NOT NULL,
    desired_version_id TEXT NOT NULL,
    desired_version TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_digest TEXT NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    desired_state TEXT NOT NULL CHECK (desired_state IN ('absent','installed','running','stopped')),
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision >= 1),
    operation_revision BIGINT NOT NULL CHECK (operation_revision >= 1),
    rollout_percentage INTEGER NOT NULL CHECK (rollout_percentage BETWEEN 1 AND 100),
    instance_ids JSONB NOT NULL CHECK (jsonb_typeof(instance_ids) = 'array' AND jsonb_array_length(instance_ids) BETWEEN 0 AND 1000),
    template_revision_ids JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(template_revision_ids) = 'array' AND jsonb_array_length(template_revision_ids) <= 1000),
    reconcile_state TEXT NOT NULL CHECK (reconcile_state IN ('pending','converged','blocked','state_conflict')),
    blocked_reason TEXT NOT NULL DEFAULT '',
    revision BIGINT NOT NULL CHECK (revision >= 1),
    reconcile_claim_token TEXT,
    reconcile_lease_expires_at TIMESTAMPTZ,
    last_scheduled_configuration_revision BIGINT NOT NULL DEFAULT 0,
    last_scheduled_operation_revision BIGINT NOT NULL DEFAULT 0,
    last_scheduled_job_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, assignment_id),
    UNIQUE (tenant_id, project_id, agent_id, database_family),
    FOREIGN KEY (tenant_id, project_id, host_id) REFERENCES managed_hosts (tenant_id, project_id, host_id),
    FOREIGN KEY (tenant_id, project_id, plugin_id) REFERENCES plugin_definitions (tenant_id, project_id, plugin_id),
    FOREIGN KEY (tenant_id, project_id, desired_version_id) REFERENCES plugin_versions (tenant_id, project_id, version_id),
    CHECK ((reconcile_claim_token IS NULL) = (reconcile_lease_expires_at IS NULL)),
    CHECK ((reconcile_state = 'blocked' AND blocked_reason <> '') OR (reconcile_state <> 'blocked' AND blocked_reason = ''))
);

CREATE INDEX plugin_assignments_scope_cursor_idx ON plugin_assignments (tenant_id,project_id,assignment_id);
CREATE INDEX plugin_assignments_reconcile_idx ON plugin_assignments (reconcile_lease_expires_at,updated_at,assignment_id) WHERE reconcile_state IN ('pending','converged');

CREATE TABLE plugin_assignment_instances (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    template_revision_ids JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(template_revision_ids)='array' AND jsonb_array_length(template_revision_ids)<=1000),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,project_id,assignment_id,instance_id),
    UNIQUE (tenant_id,project_id,instance_id),
    FOREIGN KEY (tenant_id,project_id,assignment_id) REFERENCES plugin_assignments (tenant_id,project_id,assignment_id),
    FOREIGN KEY (instance_id) REFERENCES managed_database_instances (instance_id)
);

CREATE TABLE plugin_observations (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    database_family TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    active_slot TEXT NOT NULL CHECK (active_slot IN ('none','a','b')),
    process_state TEXT NOT NULL,
    process_id BIGINT NOT NULL CHECK (process_id >= 0),
    started_at TIMESTAMPTZ,
    health TEXT NOT NULL CHECK (health IN ('unknown','healthy','degraded','unhealthy')),
    restart_count BIGINT NOT NULL CHECK (restart_count >= 0),
    circuit_state TEXT NOT NULL CHECK (circuit_state IN ('closed','open','half_open')),
    bound_instance_count INTEGER NOT NULL CHECK (bound_instance_count BETWEEN 0 AND 1000),
    active_configuration_revision BIGINT NOT NULL CHECK (active_configuration_revision >= 0),
    observed_operation_revision BIGINT NOT NULL CHECK (observed_operation_revision >= 0),
    last_error_code TEXT NOT NULL DEFAULT '',
    observation_revision BIGINT NOT NULL CHECK (observation_revision >= 1),
    observation_digest TEXT NOT NULL CHECK (observation_digest ~ '^[0-9a-f]{64}$'),
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,project_id,assignment_id),
    FOREIGN KEY (tenant_id,project_id,assignment_id) REFERENCES plugin_assignments (tenant_id,project_id,assignment_id)
);

CREATE TABLE plugin_assignment_mutations (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    action TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    response_snapshot JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,project_id,actor_id,operation_id,idempotency_key)
);

CREATE TABLE plugin_reconcile_operations (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    configuration_revision BIGINT NOT NULL,
    operation_revision BIGINT NOT NULL,
    job_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,project_id,assignment_id,configuration_revision,operation_revision),
    UNIQUE (job_id),
    UNIQUE (command_id),
    FOREIGN KEY (tenant_id,project_id,assignment_id) REFERENCES plugin_assignments (tenant_id,project_id,assignment_id),
    FOREIGN KEY (tenant_id,project_id,job_id) REFERENCES jobs (tenant_id,project_id,id)
);

COMMIT;
