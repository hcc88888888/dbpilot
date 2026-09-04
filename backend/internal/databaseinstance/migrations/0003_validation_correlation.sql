BEGIN;

ALTER TABLE managed_database_instances
    ADD COLUMN connection_validation_job_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN connection_validation_command_id TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT managed_database_instances_validation_correlation_shape CHECK (
        (connection_validation_job_id = '' AND connection_validation_command_id = '')
        OR
        (connection_validation_job_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
         AND connection_validation_command_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
    );

WITH active_validation AS (
    SELECT DISTINCT ON (tenant_id, project_id, instance_id)
           tenant_id, project_id, instance_id, job_id, command_id
    FROM database_instance_validations
    WHERE status IN ('queued', 'running')
    ORDER BY tenant_id, project_id, instance_id, requested_at DESC, job_id DESC
)
UPDATE managed_database_instances AS instance
SET connection_validation_job_id = validation.job_id,
    connection_validation_command_id = validation.command_id
FROM active_validation AS validation
WHERE instance.tenant_id = validation.tenant_id
  AND instance.project_id = validation.project_id
  AND instance.instance_id = validation.instance_id
  AND instance.connection_test_status IN ('queued', 'running')
  AND instance.connection_validation_job_id = ''
  AND instance.connection_validation_command_id = '';

CREATE INDEX database_instance_validations_pending_idx
    ON database_instance_validations (requested_at, tenant_id, project_id, job_id)
    WHERE status IN ('queued', 'running');

COMMIT;
