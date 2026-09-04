BEGIN;

DO $$
DECLARE
    conflicting_winner BOOLEAN;
BEGIN
    IF to_regclass('database_instance_validations') IS NULL
       OR to_regclass('managed_database_instances') IS NULL THEN
        RETURN;
    END IF;

    EXECUTE $conflict$
        SELECT EXISTS (
            SELECT 1
            FROM database_instance_validations validation
            JOIN managed_database_instances instance
              ON instance.tenant_id = validation.tenant_id
             AND instance.project_id = validation.project_id
             AND instance.instance_id = validation.instance_id
            JOIN jobs value
              ON value.tenant_id = validation.tenant_id
             AND value.project_id = validation.project_id
             AND value.id = validation.job_id
            JOIN command_outbox outbox
              ON outbox.tenant_id = validation.tenant_id
             AND outbox.project_id = validation.project_id
             AND outbox.job_id = validation.job_id
             AND outbox.id = validation.command_id
            WHERE instance.management_status = 'retired'
              AND value.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
              AND outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
              AND value.status <> CASE outbox.command_status
                    WHEN 'rejected' THEN 'failed'
                    ELSE outbox.command_status
                  END
        )
    $conflict$ INTO conflicting_winner;
    IF conflicting_winner THEN
        RAISE EXCEPTION 'conflicting retired validation Job and Outbox terminal winners'
            USING ERRCODE = '23514';
    END IF;

    EXECUTE $repair_target$
        UPDATE job_targets target
        SET status = winner.status,
            error_summary = CASE winner.status
                WHEN 'failed' THEN 'plugin_failed'
                WHEN 'timed_out' THEN 'command_timed_out'
                ELSE ''
            END,
            result_summary = CASE winner.status
                WHEN 'succeeded' THEN 'database instance connection validation succeeded'
                WHEN 'cancelled' THEN 'database instance connection validation cancelled'
                WHEN 'timed_out' THEN 'database instance connection validation timed out'
                ELSE 'database instance connection validation failed'
            END,
            artifacts = '[]'::jsonb,
            finished_at = COALESCE(target.finished_at, CURRENT_TIMESTAMP)
        FROM (
            SELECT validation.tenant_id,
                   validation.project_id,
                   validation.job_id,
                   outbox.target_id,
                   CASE
                       WHEN outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
                           THEN CASE outbox.command_status WHEN 'rejected' THEN 'failed' ELSE outbox.command_status END
                       ELSE value.status
                   END AS status
            FROM database_instance_validations validation
            JOIN managed_database_instances instance
              ON instance.tenant_id = validation.tenant_id
             AND instance.project_id = validation.project_id
             AND instance.instance_id = validation.instance_id
            JOIN jobs value
              ON value.tenant_id = validation.tenant_id
             AND value.project_id = validation.project_id
             AND value.id = validation.job_id
            JOIN command_outbox outbox
              ON outbox.tenant_id = validation.tenant_id
             AND outbox.project_id = validation.project_id
             AND outbox.job_id = validation.job_id
             AND outbox.id = validation.command_id
            WHERE instance.management_status = 'retired'
              AND (
                  value.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
                  OR outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
              )
        ) winner
        WHERE target.tenant_id = winner.tenant_id
          AND target.project_id = winner.project_id
          AND target.job_id = winner.job_id
          AND target.target_id = winner.target_id
    $repair_target$;
END
$$;

COMMIT;
