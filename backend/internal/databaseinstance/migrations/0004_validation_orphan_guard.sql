BEGIN;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM managed_database_instances instance
        LEFT JOIN database_instance_validations validation
          ON validation.tenant_id = instance.tenant_id
         AND validation.project_id = instance.project_id
         AND validation.instance_id = instance.instance_id
         AND validation.job_id = instance.connection_validation_job_id
         AND validation.command_id = instance.connection_validation_command_id
         AND validation.status IN ('queued', 'running')
        WHERE (
            instance.connection_test_status IN ('queued', 'running')
            AND (
                instance.connection_validation_job_id = ''
                OR instance.connection_validation_command_id = ''
                OR validation.job_id IS NULL
            )
        ) OR (
            instance.connection_test_status NOT IN ('queued', 'running')
            AND (
                instance.connection_validation_job_id <> ''
                OR instance.connection_validation_command_id <> ''
            )
        )
    ) THEN
        RAISE EXCEPTION 'orphan database instance connection validation state'
            USING ERRCODE = '23514';
    END IF;
END
$$;

ALTER TABLE managed_database_instances
    ADD CONSTRAINT managed_database_instances_active_validation_shape CHECK (
        (
            connection_test_status IN ('queued', 'running')
            AND connection_validation_job_id <> ''
            AND connection_validation_command_id <> ''
        ) OR (
            connection_test_status NOT IN ('queued', 'running')
            AND connection_validation_job_id = ''
            AND connection_validation_command_id = ''
        )
    );

COMMIT;
