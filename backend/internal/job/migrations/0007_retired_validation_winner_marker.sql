BEGIN;

CREATE TABLE IF NOT EXISTS dbpilot_retired_validation_winner_markers (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    winner TEXT NOT NULL CHECK (winner IN ('succeeded', 'failed', 'cancelled', 'timed_out')),
    target_error_summary TEXT NOT NULL DEFAULT '',
    target_result_summary TEXT NOT NULL DEFAULT '',
    target_artifacts JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(target_artifacts) = 'array'),
    terminal_at TIMESTAMPTZ NOT NULL,
    original_job_version BIGINT NOT NULL CHECK (original_job_version >= 1),
    original_public_snapshot JSONB NOT NULL CHECK (jsonb_typeof(original_public_snapshot) = 'object'),
    force_version_fence BOOLEAN NOT NULL DEFAULT FALSE,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, project_id, command_id)
);

DO $$
DECLARE
    conflicting_winner BOOLEAN;
BEGIN
    IF to_regclass('database_instance_validations') IS NULL
       OR to_regclass('managed_database_instances') IS NULL THEN
        RETURN;
    END IF;

    EXECUTE $conflict$
        WITH candidates AS (
            SELECT validation.status AS validation_status,
                   value.status AS job_status,
                   value.cancel_requested_by,
                   outbox.command_status,
                   CASE outbox.command_status WHEN 'rejected' THEN 'failed' ELSE outbox.command_status END AS command_winner
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
        )
        SELECT EXISTS (
            SELECT 1
            FROM candidates
            WHERE job_status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
              AND command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
              AND job_status <> command_winner
              AND NOT (
                  validation_status = 'plugin_failed'
                  AND (
                      (job_status <> 'cancelled' AND command_winner = 'cancelled' AND cancel_requested_by <> 'instance-retire-migration')
                      OR
                      (job_status = 'cancelled' AND cancel_requested_by = 'instance-retire-migration' AND command_winner <> 'cancelled')
                  )
              )
        )
    $conflict$ INTO conflicting_winner;
    IF conflicting_winner THEN
        RAISE EXCEPTION 'conflicting retired validation Job and Outbox terminal winners'
            USING ERRCODE = '23514';
    END IF;

    EXECUTE $capture$
        INSERT INTO dbpilot_retired_validation_winner_markers (
            tenant_id, project_id, job_id, command_id, instance_id, agent_id,
            winner, target_error_summary, target_result_summary, target_artifacts,
            terminal_at, original_job_version, original_public_snapshot
        )
        WITH source AS (
            SELECT validation.tenant_id,
                   validation.project_id,
                   validation.job_id,
                   validation.command_id,
                   validation.instance_id,
                   validation.status AS validation_status,
                   instance.agent_id,
                   value.status AS job_status,
                   value.outcome,
                   value.version,
                   value.completed_targets,
                   value.failed_targets,
                   value.skipped_targets,
                   value.error_summary AS job_error_summary,
                   value.result_summary AS job_result_summary,
                   value.artifacts AS job_artifacts,
                   value.finished_at AS job_finished_at,
                   value.cancel_requested_by,
                   value.cancel_requested_at,
                   target.status AS target_status,
                   target.error_summary AS target_error_summary,
                   target.result_summary AS target_result_summary,
                   target.artifacts AS target_artifacts,
                   target.finished_at AS target_finished_at,
                   outbox.command_status,
                   outbox.terminal_at,
                   CASE outbox.command_status WHEN 'rejected' THEN 'failed' ELSE outbox.command_status END AS command_winner
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
            JOIN job_targets target
              ON target.tenant_id = validation.tenant_id
             AND target.project_id = validation.project_id
             AND target.job_id = validation.job_id
             AND target.target_id = instance.agent_id
            WHERE instance.management_status = 'retired'
        ), winners AS (
            SELECT source.*,
                   CASE
                       WHEN validation_status = 'plugin_failed'
                            AND job_status IN ('succeeded', 'failed', 'timed_out')
                            AND command_winner = 'cancelled'
                            AND cancel_requested_by <> 'instance-retire-migration'
                           THEN job_status
                       WHEN validation_status = 'plugin_failed'
                            AND job_status = 'cancelled'
                            AND cancel_requested_by = 'instance-retire-migration'
                            AND command_winner IN ('succeeded', 'failed', 'timed_out')
                           THEN command_winner
                       WHEN command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
                           THEN command_winner
                       WHEN job_status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
                           THEN job_status
                       ELSE 'cancelled'
                   END AS winner
            FROM source
        )
        SELECT tenant_id,
               project_id,
               job_id,
               command_id,
               instance_id,
               agent_id,
               winner,
               CASE
                   WHEN winner = 'failed' AND target_status = 'failed'
                        AND target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed')
                       THEN target_error_summary
                   WHEN winner = 'failed' THEN 'plugin_failed'
                   WHEN winner = 'timed_out' THEN 'command_timed_out'
                   ELSE ''
               END,
               CASE
                   WHEN target_status = winner AND target_result_summary <> '' THEN target_result_summary
                   WHEN job_status = winner AND job_result_summary <> '' THEN job_result_summary
                   WHEN winner = 'succeeded' THEN 'database instance connection validation succeeded'
                   WHEN winner = 'cancelled' THEN 'database instance connection validation cancelled'
                   WHEN winner = 'timed_out' THEN 'database instance connection validation timed out'
                   ELSE 'database instance connection validation failed'
               END,
               CASE
                   WHEN target_status = winner THEN target_artifacts
                   WHEN job_status = winner THEN job_artifacts
                   ELSE '[]'::jsonb
               END,
               COALESCE(terminal_at, target_finished_at, job_finished_at, CURRENT_TIMESTAMP),
               version,
               jsonb_build_object(
                   'status', job_status,
                   'outcome', outcome,
                   'completed_targets', completed_targets,
                   'failed_targets', failed_targets,
                   'skipped_targets', skipped_targets,
                   'error_summary', job_error_summary,
                   'result_summary', job_result_summary,
                   'artifacts', job_artifacts,
                   'finished_at', job_finished_at,
                   'cancel_requested_by', cancel_requested_by,
                   'cancel_requested_at', cancel_requested_at,
                   'target_status', target_status,
                   'target_error_summary', target_error_summary,
                   'target_result_summary', target_result_summary,
                   'target_artifacts', target_artifacts,
                   'target_finished_at', target_finished_at
               )
        FROM winners
        ON CONFLICT (tenant_id, project_id, command_id) DO NOTHING
    $capture$;

    IF to_regclass('audit_events') IS NOT NULL THEN
        EXECUTE $version_fence$
            UPDATE dbpilot_retired_validation_winner_markers marker
            SET force_version_fence = TRUE
            WHERE EXISTS (
                SELECT 1
                FROM audit_events event
                WHERE event.tenant_id = marker.tenant_id
                  AND event.project_id = marker.project_id
                  AND event.job_id = marker.job_id
                  AND event.command_id = marker.command_id
                  AND event.action IN (
                      'database_instance.connection_test_succeeded',
                      'database_instance.connection_test_failed',
                      'database_instance.connection_test_cancelled_on_retire'
                  )
            )
        $version_fence$;
    END IF;

    EXECUTE $jobs$
        UPDATE jobs value
        SET status = marker.winner,
            outcome = CASE marker.winner WHEN 'succeeded' THEN 'complete' ELSE 'none' END,
            version = value.version + CASE WHEN marker.force_version_fence
                OR value.status IS DISTINCT FROM marker.winner
                OR value.outcome IS DISTINCT FROM CASE marker.winner WHEN 'succeeded' THEN 'complete' ELSE 'none' END
                OR value.completed_targets IS DISTINCT FROM CASE marker.winner WHEN 'succeeded' THEN 1 ELSE 0 END
                OR value.failed_targets IS DISTINCT FROM CASE marker.winner WHEN 'succeeded' THEN 0 ELSE 1 END
                OR value.skipped_targets IS DISTINCT FROM 0
                OR value.error_summary IS DISTINCT FROM ''
                OR value.result_summary IS DISTINCT FROM CASE marker.winner
                    WHEN 'succeeded' THEN 'database instance connection validation succeeded'
                    WHEN 'cancelled' THEN 'database instance connection validation cancelled'
                    WHEN 'timed_out' THEN 'database instance connection validation timed out'
                    ELSE 'database instance connection validation failed'
                END
                OR value.artifacts IS DISTINCT FROM marker.target_artifacts
                OR value.finished_at IS DISTINCT FROM COALESCE(value.finished_at, marker.terminal_at)
                OR (marker.winner = 'cancelled' AND value.cancel_requested_by = '')
                OR (marker.winner = 'cancelled' AND value.cancel_requested_at IS NULL)
                OR EXISTS (
                    SELECT 1 FROM job_targets target
                    WHERE target.tenant_id = marker.tenant_id
                      AND target.project_id = marker.project_id
                      AND target.job_id = marker.job_id
                      AND target.target_id = marker.agent_id
                      AND (
                          target.status IS DISTINCT FROM marker.winner
                          OR target.error_summary IS DISTINCT FROM marker.target_error_summary
                          OR target.result_summary IS DISTINCT FROM marker.target_result_summary
                          OR target.artifacts IS DISTINCT FROM marker.target_artifacts
                          OR target.finished_at IS DISTINCT FROM COALESCE(target.finished_at, marker.terminal_at)
                      )
                )
                THEN 1 ELSE 0 END,
            completed_targets = CASE marker.winner WHEN 'succeeded' THEN 1 ELSE 0 END,
            failed_targets = CASE marker.winner WHEN 'succeeded' THEN 0 ELSE 1 END,
            skipped_targets = 0,
            error_summary = '',
            result_summary = CASE marker.winner
                WHEN 'succeeded' THEN 'database instance connection validation succeeded'
                WHEN 'cancelled' THEN 'database instance connection validation cancelled'
                WHEN 'timed_out' THEN 'database instance connection validation timed out'
                ELSE 'database instance connection validation failed'
            END,
            artifacts = marker.target_artifacts,
            finished_at = COALESCE(value.finished_at, marker.terminal_at),
            cancel_requested_by = CASE WHEN marker.winner = 'cancelled' AND value.cancel_requested_by = '' THEN 'instance-retire-migration' ELSE value.cancel_requested_by END,
            cancel_requested_at = CASE WHEN marker.winner = 'cancelled' THEN COALESCE(value.cancel_requested_at, marker.terminal_at) ELSE value.cancel_requested_at END
        FROM dbpilot_retired_validation_winner_markers marker
        WHERE value.tenant_id = marker.tenant_id
          AND value.project_id = marker.project_id
          AND value.id = marker.job_id
    $jobs$;

    EXECUTE $targets$
        UPDATE job_targets target
        SET status = marker.winner,
            error_summary = marker.target_error_summary,
            result_summary = marker.target_result_summary,
            artifacts = marker.target_artifacts,
            finished_at = COALESCE(target.finished_at, marker.terminal_at)
        FROM dbpilot_retired_validation_winner_markers marker
        WHERE target.tenant_id = marker.tenant_id
          AND target.project_id = marker.project_id
          AND target.job_id = marker.job_id
          AND target.target_id = marker.agent_id
    $targets$;

    EXECUTE $outbox$
        UPDATE command_outbox outbox
        SET command_status = CASE WHEN marker.winner = 'failed' AND outbox.command_status = 'rejected' THEN 'rejected' ELSE marker.winner END,
            command_phase = CASE WHEN marker.winner = 'failed' AND outbox.command_status = 'rejected' THEN 'rejected' ELSE marker.winner END,
            terminal_at = COALESCE(outbox.terminal_at, marker.terminal_at),
            published_at = COALESCE(outbox.published_at, marker.terminal_at),
            lease_expires_at = NULL,
            execution_deadline_at = NULL,
            recovery_lease_expires_at = NULL,
            recovery_claim_token = NULL,
            recovery_claimed_deadline = NULL,
            recovery_claimed_revision = NULL,
            cancellation_lease_expires_at = NULL
        FROM dbpilot_retired_validation_winner_markers marker
        WHERE outbox.tenant_id = marker.tenant_id
          AND outbox.project_id = marker.project_id
          AND outbox.job_id = marker.job_id
          AND outbox.id = marker.command_id
    $outbox$;
END
$$;

COMMIT;
