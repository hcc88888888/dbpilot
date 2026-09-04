BEGIN;

DO $$
DECLARE
    orphan_operation BOOLEAN;
BEGIN
    IF to_regclass('jobs') IS NOT NULL AND to_regclass('job_targets') IS NOT NULL THEN
        EXECUTE $job_targets$
        UPDATE job_targets target
        SET status = 'cancelled',
            error_summary = '',
            result_summary = 'database instance connection validation cancelled',
            artifacts = '[]'::jsonb,
            finished_at = COALESCE(target.finished_at, CURRENT_TIMESTAMP)
        WHERE EXISTS (
            SELECT 1
            FROM database_instance_validations validation
            JOIN managed_database_instances instance
              ON instance.tenant_id = validation.tenant_id
             AND instance.project_id = validation.project_id
             AND instance.instance_id = validation.instance_id
            WHERE validation.tenant_id = target.tenant_id
              AND validation.project_id = target.project_id
              AND validation.job_id = target.job_id
              AND target.target_id = instance.agent_id
              AND validation.status IN ('queued', 'running')
              AND instance.management_status = 'retired'
        )
        $job_targets$;

        EXECUTE $jobs$
        UPDATE jobs value
        SET status = 'cancelled',
            outcome = 'none',
            version = value.version + 1,
            completed_targets = 0,
            failed_targets = 1,
            skipped_targets = 0,
            error_summary = '',
            result_summary = 'database instance connection validation cancelled',
            artifacts = '[]'::jsonb,
            finished_at = COALESCE(value.finished_at, CURRENT_TIMESTAMP),
            cancel_requested_by = 'instance-retire-migration',
            cancel_requested_at = COALESCE(value.cancel_requested_at, CURRENT_TIMESTAMP)
        WHERE value.status IN ('queued', 'dispatched', 'running', 'cancelling')
          AND EXISTS (
              SELECT 1
              FROM database_instance_validations validation
              JOIN managed_database_instances instance
                ON instance.tenant_id = validation.tenant_id
               AND instance.project_id = validation.project_id
               AND instance.instance_id = validation.instance_id
              WHERE validation.tenant_id = value.tenant_id
                AND validation.project_id = value.project_id
                AND validation.job_id = value.id
                AND validation.status IN ('queued', 'running')
                AND instance.management_status = 'retired'
          )
        $jobs$;
    END IF;

    IF to_regclass('command_outbox') IS NOT NULL
       AND EXISTS (
           SELECT 1 FROM information_schema.columns
           WHERE table_schema = current_schema()
             AND table_name = 'command_outbox'
             AND column_name = 'command_status'
       ) THEN
        EXECUTE $outbox$
        UPDATE command_outbox outbox
        SET command_status = 'cancelled',
            command_phase = 'cancelled',
            terminal_at = COALESCE(outbox.terminal_at, CURRENT_TIMESTAMP),
            published_at = COALESCE(outbox.published_at, CURRENT_TIMESTAMP),
            lease_expires_at = NULL,
            execution_deadline_at = NULL,
            recovery_lease_expires_at = NULL,
            recovery_claim_token = NULL,
            recovery_claimed_deadline = NULL,
            recovery_claimed_revision = NULL,
            cancellation_lease_expires_at = NULL
        WHERE outbox.command_status IN ('pending', 'active', 'rejected')
          AND EXISTS (
              SELECT 1
              FROM database_instance_validations validation
              JOIN managed_database_instances instance
                ON instance.tenant_id = validation.tenant_id
               AND instance.project_id = validation.project_id
               AND instance.instance_id = validation.instance_id
              WHERE validation.tenant_id = outbox.tenant_id
                AND validation.project_id = outbox.project_id
                AND validation.job_id = outbox.job_id
                AND validation.command_id = outbox.id
                AND validation.status IN ('queued', 'running')
                AND instance.management_status = 'retired'
          )
        $outbox$;
    END IF;

    IF to_regclass('jobs') IS NOT NULL AND to_regclass('command_outbox') IS NOT NULL THEN
        EXECUTE $orphan$
        SELECT EXISTS (
           SELECT 1
           FROM database_instance_validations validation
           JOIN managed_database_instances instance
             ON instance.tenant_id = validation.tenant_id
            AND instance.project_id = validation.project_id
            AND instance.instance_id = validation.instance_id
           LEFT JOIN jobs value
             ON value.tenant_id = validation.tenant_id
            AND value.project_id = validation.project_id
            AND value.id = validation.job_id
           LEFT JOIN command_outbox outbox
             ON outbox.tenant_id = validation.tenant_id
            AND outbox.project_id = validation.project_id
            AND outbox.job_id = validation.job_id
            AND outbox.id = validation.command_id
           WHERE validation.status IN ('queued', 'running')
             AND instance.management_status <> 'retired'
             AND (value.id IS NULL OR outbox.id IS NULL)
        )
        $orphan$ INTO orphan_operation;
        IF orphan_operation THEN
            RAISE EXCEPTION 'orphan database instance validation Job or Outbox'
                USING ERRCODE = '23514';
        END IF;
    END IF;
END
$$;

UPDATE database_instance_validations validation
SET status = 'plugin_failed',
    error_code = 'plugin_failed',
    started_at = COALESCE(validation.started_at, CURRENT_TIMESTAMP),
    completed_at = COALESCE(validation.completed_at, CURRENT_TIMESTAMP)
FROM managed_database_instances instance
WHERE instance.tenant_id = validation.tenant_id
  AND instance.project_id = validation.project_id
  AND instance.instance_id = validation.instance_id
  AND instance.management_status = 'retired'
  AND validation.status IN ('queued', 'running');

UPDATE managed_database_instances
SET connection_test_status = 'plugin_failed',
    connection_test_error_code = 'plugin_failed',
    connection_test_at = COALESCE(connection_test_at, updated_at, CURRENT_TIMESTAMP),
    connection_validation_job_id = '',
    connection_validation_command_id = ''
WHERE management_status = 'retired'
  AND (
      connection_test_status IN ('queued', 'running')
      OR connection_validation_job_id <> ''
      OR connection_validation_command_id <> ''
  );

COMMIT;
