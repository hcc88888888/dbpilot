BEGIN;

-- A pre-atomic validation could durably finish its Job target before the raw
-- Command status was committed with the opposite terminal classification.
-- 0008 deliberately rejects that conflict, so bridge only the narrow case
-- where the non-retired validation is still active, the Job is nonterminal,
-- and the independently persisted target is terminal. The target is the sole
-- effective-outcome evidence; an evidence-free row remains for the later
-- database-instance quarantine migration.
DO $migration$
BEGIN
    IF to_regclass('database_instance_validations') IS NULL
       OR to_regclass('managed_database_instances') IS NULL
       OR to_regclass('jobs') IS NULL
       OR to_regclass('job_targets') IS NULL
       OR to_regclass('command_outbox') IS NULL THEN
        RETURN;
    END IF;

    EXECUTE $bridge$
        UPDATE command_outbox outbox
        SET command_status = CASE target.status
                WHEN 'succeeded' THEN 'succeeded'
                WHEN 'cancelled' THEN 'cancelled'
                WHEN 'timed_out' THEN 'timed_out'
                ELSE 'failed'
            END,
            command_phase = CASE target.status
                WHEN 'succeeded' THEN 'succeeded'
                WHEN 'cancelled' THEN 'cancelled'
                WHEN 'timed_out' THEN 'timed_out'
                ELSE 'failed'
            END
        FROM database_instance_validations validation
        JOIN managed_database_instances instance
          ON instance.tenant_id = validation.tenant_id
         AND instance.project_id = validation.project_id
         AND instance.instance_id = validation.instance_id
        JOIN jobs value
          ON value.tenant_id = validation.tenant_id
         AND value.project_id = validation.project_id
         AND value.id = validation.job_id
        JOIN job_targets target
          ON target.tenant_id = validation.tenant_id
         AND target.project_id = validation.project_id
         AND target.job_id = validation.job_id
         AND target.target_id = instance.agent_id
        WHERE outbox.tenant_id = validation.tenant_id
          AND outbox.project_id = validation.project_id
          AND outbox.job_id = validation.job_id
          AND outbox.id = validation.command_id
          AND value.job_type = 'database_instance.validate'
          AND validation.status IN ('queued', 'running')
          AND instance.management_status <> 'retired'
          AND target.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
          AND (
              value.status NOT IN ('succeeded', 'failed', 'cancelled', 'timed_out')
              OR value.status = CASE target.status
                  WHEN 'succeeded' THEN 'succeeded'
                  WHEN 'cancelled' THEN 'cancelled'
                  WHEN 'timed_out' THEN 'timed_out'
                  ELSE 'failed'
                END
          )
          AND outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
          AND outbox.command_status <> CASE target.status
                WHEN 'succeeded' THEN 'succeeded'
                WHEN 'cancelled' THEN 'cancelled'
                WHEN 'timed_out' THEN 'timed_out'
                ELSE 'failed'
              END
    $bridge$;
END
$migration$;

COMMIT;
