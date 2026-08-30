BEGIN;

ALTER TABLE discovery_candidates
    ADD COLUMN IF NOT EXISTS accepted_instance_id TEXT NOT NULL DEFAULT '';

CREATE TABLE managed_database_instances (
    instance_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    discovery_source TEXT NOT NULL CHECK (discovery_source IN ('native', 'docker')),
    source_fingerprint TEXT NOT NULL CHECK (source_fingerprint ~ '^[a-f0-9]{64}$'),
    source_identity TEXT NOT NULL,
    database_family TEXT NOT NULL,
    database_variant TEXT NOT NULL,
    display_name TEXT NOT NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    unix_socket TEXT NOT NULL DEFAULT '',
    version_hint TEXT NOT NULL DEFAULT '',
    edition TEXT NOT NULL DEFAULT '',
    discovered_role TEXT NOT NULL DEFAULT '',
    topology TEXT NOT NULL DEFAULT '',
    credential_ref TEXT NOT NULL,
    tls_ref TEXT NOT NULL DEFAULT '',
    plugin_id TEXT NOT NULL DEFAULT '',
    desired_plugin_version TEXT NOT NULL DEFAULT '',
    template_profile_id TEXT NOT NULL DEFAULT '',
    labels JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(labels) = 'object'),
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(capabilities) = 'array'),
    capability_state TEXT NOT NULL CHECK (capability_state IN ('plugin_not_installed')),
    connection_test_status TEXT NOT NULL CHECK (connection_test_status IN ('not_tested')),
    connection_test_at TIMESTAMPTZ,
    plugin_assignment_revision BIGINT NOT NULL DEFAULT 0 CHECK (plugin_assignment_revision >= 0),
    management_status TEXT NOT NULL CHECK (management_status IN ('accepted','provisioning','connection_testing','managed','monitoring','plugin_failed','authentication_failed','tls_failed','unreachable','unsupported_version','degraded','offline','retired')),
    revision BIGINT NOT NULL CHECK (revision >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ,
    canonical_connection TEXT NOT NULL,
    UNIQUE (tenant_id, project_id, candidate_id),
    UNIQUE (tenant_id, project_id, host_id, database_family, source_identity),
    FOREIGN KEY (tenant_id, project_id, host_id, agent_id)
        REFERENCES managed_hosts (tenant_id, project_id, host_id, agent_id),
    FOREIGN KEY (tenant_id, project_id, candidate_id)
        REFERENCES discovery_candidates (tenant_id, project_id, candidate_id),
    CHECK ((endpoint = '') <> (unix_socket = '')),
    CHECK (credential_ref LIKE 'secret://%'),
    CHECK (tls_ref = '' OR tls_ref LIKE 'secret://%'),
    CHECK ((management_status = 'retired') = (retired_at IS NOT NULL))
);

CREATE UNIQUE INDEX managed_database_instances_active_connection_idx
    ON managed_database_instances (tenant_id, project_id, host_id, database_family, canonical_connection)
    WHERE management_status <> 'retired';
CREATE INDEX managed_database_instances_scope_page_idx
    ON managed_database_instances (tenant_id, project_id, instance_id);
CREATE INDEX managed_database_instances_scope_filter_page_idx
    ON managed_database_instances (tenant_id, project_id, host_id, database_family, management_status, instance_id);

CREATE TABLE database_instance_mutations (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^sha256:[a-f0-9]{64}$'),
    action TEXT NOT NULL CHECK (action IN ('accept','update','retire')),
    resource_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    expected_revision BIGINT NOT NULL CHECK (expected_revision >= 1),
    resulting_revision BIGINT NOT NULL CHECK (resulting_revision >= 1),
    response_snapshot JSONB NOT NULL CHECK (jsonb_typeof(response_snapshot) = 'object'),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, actor_id, operation_id, idempotency_key),
    FOREIGN KEY (instance_id) REFERENCES managed_database_instances (instance_id)
);

COMMIT;
