BEGIN;

ALTER TABLE managed_database_instances
    DROP CONSTRAINT IF EXISTS managed_database_instances_capability_state_check,
    DROP CONSTRAINT IF EXISTS managed_database_instances_connection_test_status_check;

ALTER TABLE managed_database_instances
    ADD CONSTRAINT managed_database_instances_capability_state_check
        CHECK (capability_state IN ('plugin_not_installed','plugin_available','plugin_unavailable','plugin_failed','degraded')),
    ADD CONSTRAINT managed_database_instances_connection_test_status_check
        CHECK (connection_test_status IN ('not_tested','queued','running','succeeded','authentication_failed','tls_failed','unreachable','unsupported_version','plugin_failed')),
    ADD COLUMN connection_test_error_code TEXT NOT NULL DEFAULT ''
        CHECK (connection_test_error_code IN ('','instance_authentication_failed','instance_tls_failed','instance_unreachable','database_version_unsupported','plugin_failed')),
    ADD CONSTRAINT managed_database_instances_connection_error_state_check CHECK (
        (connection_test_status IN ('not_tested','queued','running','succeeded') AND connection_test_error_code = '') OR
        (connection_test_status = 'authentication_failed' AND connection_test_error_code = 'instance_authentication_failed') OR
        (connection_test_status = 'tls_failed' AND connection_test_error_code = 'instance_tls_failed') OR
        (connection_test_status = 'unreachable' AND connection_test_error_code = 'instance_unreachable') OR
        (connection_test_status = 'unsupported_version' AND connection_test_error_code = 'database_version_unsupported') OR
        (connection_test_status = 'plugin_failed' AND connection_test_error_code = 'plugin_failed')
    );

CREATE TABLE database_instance_validations (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    command_id TEXT NOT NULL UNIQUE,
    instance_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision >= 1),
    operation_revision BIGINT NOT NULL CHECK (operation_revision >= 1),
    actor_id TEXT NOT NULL,
    operation_id TEXT NOT NULL CHECK (operation_id = 'testDatabaseInstanceConnection'),
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^sha256:[a-f0-9]{64}$'),
    request_id TEXT NOT NULL,
    trace_id TEXT NOT NULL DEFAULT '',
    previous_management_status TEXT NOT NULL CHECK (previous_management_status IN ('accepted','provisioning','connection_testing','managed','monitoring','plugin_failed','authentication_failed','tls_failed','unreachable','unsupported_version','degraded','offline')),
    status TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','authentication_failed','tls_failed','unreachable','unsupported_version','plugin_failed')),
    error_code TEXT NOT NULL DEFAULT '' CHECK (error_code IN ('','instance_authentication_failed','instance_tls_failed','instance_unreachable','database_version_unsupported','plugin_failed')),
    requested_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, project_id, job_id),
    UNIQUE (tenant_id, project_id, actor_id, operation_id, idempotency_key),
    FOREIGN KEY (instance_id)
        REFERENCES managed_database_instances (instance_id)
);

CREATE INDEX database_instance_validations_instance_idx
    ON database_instance_validations (tenant_id, project_id, instance_id, requested_at DESC);

COMMIT;
