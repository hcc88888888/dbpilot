BEGIN;

CREATE TABLE credential_lease_audits (
    audit_id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision >= 1),
    operation_revision BIGINT NOT NULL CHECK (operation_revision >= 1),
    instance_revision BIGINT NOT NULL CHECK (instance_revision >= 1),
    credential_revision BIGINT NOT NULL CHECK (credential_revision >= 0),
    result TEXT NOT NULL CHECK (result IN ('issued','rejected')),
    expiry_class TEXT NOT NULL CHECK (expiry_class IN ('short')),
    occurred_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (tenant_id, project_id, assignment_id) REFERENCES plugin_assignments(tenant_id, project_id, assignment_id),
    FOREIGN KEY (instance_id) REFERENCES managed_database_instances(instance_id)
);

CREATE INDEX credential_lease_audits_scope_time_idx ON credential_lease_audits(tenant_id,project_id,occurred_at DESC);

COMMIT;
