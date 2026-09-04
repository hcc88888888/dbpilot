BEGIN;

DO $$
DECLARE
    conflicting_winner BOOLEAN;
BEGIN
    IF to_regclass('jobs') IS NULL
       OR to_regclass('job_targets') IS NULL
       OR to_regclass('command_outbox') IS NULL THEN
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

    EXECUTE $winners$
        CREATE TEMP TABLE dbpilot_retired_validation_winners ON COMMIT DROP AS
        SELECT validation.tenant_id,
               validation.project_id,
               validation.job_id,
               validation.command_id,
               validation.instance_id,
               validation.assignment_id,
               validation.configuration_revision,
               validation.operation_revision,
               validation.actor_id,
               validation.request_id,
               validation.trace_id,
               instance.agent_id,
               outbox.terminal_at,
               outbox.terminal_target_error_summary,
               outbox.terminal_target_result_summary,
               outbox.terminal_target_artifacts,
               CASE
                   WHEN outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
                       THEN CASE outbox.command_status WHEN 'rejected' THEN 'failed' ELSE outbox.command_status END
                   WHEN value.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
                       THEN value.status
                   ELSE 'cancelled'
               END AS winner
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
        WHERE instance.management_status = 'retired'
    $winners$;

    EXECUTE $targets$
        UPDATE job_targets target
        SET status = winner.winner,
            error_summary = CASE
                WHEN winner.winner = 'failed'
                     AND winner.terminal_target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed')
                    THEN winner.terminal_target_error_summary
                WHEN winner.winner = 'failed' THEN 'plugin_failed'
                WHEN winner.winner = 'timed_out' THEN 'command_timed_out'
                ELSE ''
            END,
            result_summary = COALESCE(NULLIF(winner.terminal_target_result_summary, ''), CASE winner.winner
                WHEN 'succeeded' THEN 'database instance connection validation succeeded'
                WHEN 'cancelled' THEN 'database instance connection validation cancelled'
                WHEN 'timed_out' THEN 'database instance connection validation timed out'
                ELSE 'database instance connection validation failed'
            END),
            artifacts = COALESCE(winner.terminal_target_artifacts, '[]'::jsonb),
            finished_at = COALESCE(target.finished_at, winner.terminal_at, CURRENT_TIMESTAMP)
        FROM dbpilot_retired_validation_winners winner
        WHERE target.tenant_id = winner.tenant_id
          AND target.project_id = winner.project_id
          AND target.job_id = winner.job_id
          AND target.target_id = winner.agent_id
    $targets$;

    EXECUTE $jobs$
        UPDATE jobs value
        SET status = winner.winner,
            outcome = CASE winner.winner WHEN 'succeeded' THEN 'complete' ELSE 'none' END,
            version = value.version + CASE
                WHEN value.status <> winner.winner
                  OR value.completed_targets <> CASE winner.winner WHEN 'succeeded' THEN 1 ELSE 0 END
                  OR value.failed_targets <> CASE winner.winner WHEN 'succeeded' THEN 0 ELSE 1 END
                  OR value.skipped_targets <> 0
                THEN 1 ELSE 0 END,
            completed_targets = CASE winner.winner WHEN 'succeeded' THEN 1 ELSE 0 END,
            failed_targets = CASE winner.winner WHEN 'succeeded' THEN 0 ELSE 1 END,
            skipped_targets = 0,
            error_summary = '',
            result_summary = CASE winner.winner
                WHEN 'succeeded' THEN 'database instance connection validation succeeded'
                WHEN 'cancelled' THEN 'database instance connection validation cancelled'
                WHEN 'timed_out' THEN 'database instance connection validation timed out'
                ELSE 'database instance connection validation failed'
            END,
            artifacts = COALESCE(winner.terminal_target_artifacts, '[]'::jsonb),
            finished_at = COALESCE(value.finished_at, winner.terminal_at, CURRENT_TIMESTAMP),
            cancel_requested_by = CASE WHEN winner.winner = 'cancelled' AND value.cancel_requested_by = '' THEN 'instance-retire-migration' ELSE value.cancel_requested_by END,
            cancel_requested_at = CASE WHEN winner.winner = 'cancelled' THEN COALESCE(value.cancel_requested_at, winner.terminal_at, CURRENT_TIMESTAMP) ELSE value.cancel_requested_at END
        FROM dbpilot_retired_validation_winners winner
        WHERE value.tenant_id = winner.tenant_id
          AND value.project_id = winner.project_id
          AND value.id = winner.job_id
    $jobs$;

    EXECUTE $outbox$
        UPDATE command_outbox outbox
        SET command_status = CASE WHEN winner.winner = 'failed' AND outbox.command_status = 'rejected' THEN 'rejected' ELSE winner.winner END,
            command_phase = CASE WHEN winner.winner = 'failed' AND outbox.command_status = 'rejected' THEN 'rejected' ELSE winner.winner END,
            terminal_at = COALESCE(outbox.terminal_at, CURRENT_TIMESTAMP),
            published_at = COALESCE(outbox.published_at, outbox.terminal_at, CURRENT_TIMESTAMP),
            lease_expires_at = NULL,
            execution_deadline_at = NULL,
            recovery_lease_expires_at = NULL,
            recovery_claim_token = NULL,
            recovery_claimed_deadline = NULL,
            recovery_claimed_revision = NULL,
            cancellation_lease_expires_at = NULL,
            terminal_target_status = winner.winner,
            terminal_target_error_summary = CASE
                WHEN winner.winner = 'failed'
                     AND winner.terminal_target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed')
                    THEN winner.terminal_target_error_summary
                WHEN winner.winner = 'failed' THEN 'plugin_failed'
                WHEN winner.winner = 'timed_out' THEN 'command_timed_out'
                ELSE ''
            END,
            terminal_target_result_summary = CASE winner.winner
                WHEN 'succeeded' THEN 'database instance connection validation succeeded'
                WHEN 'cancelled' THEN 'database instance connection validation cancelled'
                WHEN 'timed_out' THEN 'database instance connection validation timed out'
                ELSE 'database instance connection validation failed'
            END,
            terminal_target_artifacts = COALESCE(winner.terminal_target_artifacts, '[]'::jsonb),
            terminal_reconcile_pending = FALSE,
            terminal_audit_pending = CASE WHEN outbox.terminal_audit_dedupe_key = '' THEN outbox.terminal_audit_recorded_at IS NULL ELSE outbox.terminal_audit_pending END,
            terminal_audit_dedupe_key = CASE WHEN outbox.terminal_audit_dedupe_key <> '' THEN outbox.terminal_audit_dedupe_key ELSE CASE winner.winner
                WHEN 'cancelled' THEN 'command.validation_cancelled_on_retire:' || outbox.id
                WHEN 'timed_out' THEN 'command.execution_timed_out:' || outbox.id
                ELSE 'command.result:' || outbox.id
            END END,
            terminal_audit_action = CASE WHEN outbox.terminal_audit_action <> '' THEN outbox.terminal_audit_action ELSE CASE winner.winner
                WHEN 'cancelled' THEN 'command.validation_cancelled_on_retire'
                WHEN 'timed_out' THEN 'command.execution_timed_out'
                ELSE 'command.result'
            END END,
            terminal_audit_result = CASE WHEN outbox.terminal_audit_result <> '' THEN outbox.terminal_audit_result ELSE CASE winner.winner WHEN 'succeeded' THEN 'success' ELSE 'failure' END END,
            terminal_audit_detail = CASE WHEN outbox.terminal_audit_dedupe_key <> '' THEN outbox.terminal_audit_detail ELSE CASE winner.winner
                WHEN 'cancelled' THEN jsonb_build_object('reason', 'instance_retired')
                WHEN 'timed_out' THEN jsonb_build_object('reason', 'execution_deadline')
                WHEN 'succeeded' THEN jsonb_build_object('artifact_count', 0, 'state', 'COMMAND_RESULT_STATE_SUCCEEDED')
                ELSE jsonb_build_object('artifact_count', 0, 'state', 'COMMAND_RESULT_STATE_FAILED')
            END END,
            terminal_audit_lease_expires_at = NULL
        FROM dbpilot_retired_validation_winners winner
        WHERE outbox.tenant_id = winner.tenant_id
          AND outbox.project_id = winner.project_id
          AND outbox.job_id = winner.job_id
          AND outbox.id = winner.command_id
    $outbox$;

    EXECUTE $validation$
        UPDATE database_instance_validations validation
        SET status = CASE
                WHEN winner.winner = 'succeeded' THEN 'succeeded'
                WHEN winner.winner = 'failed' AND winner.terminal_target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
                WHEN winner.winner = 'failed' AND winner.terminal_target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
                WHEN winner.winner = 'failed' AND winner.terminal_target_error_summary = 'instance_unreachable' THEN 'unreachable'
                WHEN winner.winner = 'failed' AND winner.terminal_target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
                ELSE 'plugin_failed'
            END,
            error_code = CASE
                WHEN winner.winner = 'succeeded' THEN ''
                WHEN winner.winner = 'failed'
                     AND winner.terminal_target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed')
                    THEN winner.terminal_target_error_summary
                ELSE 'plugin_failed'
            END,
            started_at = COALESCE(validation.started_at, validation.requested_at),
            completed_at = COALESCE(validation.completed_at, winner.terminal_at, CURRENT_TIMESTAMP)
        FROM dbpilot_retired_validation_winners winner
        WHERE validation.tenant_id = winner.tenant_id
          AND validation.project_id = winner.project_id
          AND validation.job_id = winner.job_id
          AND validation.command_id = winner.command_id
    $validation$;

    EXECUTE $instances$
        UPDATE managed_database_instances instance
        SET connection_test_status = CASE
                WHEN winner.winner = 'succeeded' THEN 'succeeded'
                WHEN winner.winner = 'failed' AND winner.terminal_target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
                WHEN winner.winner = 'failed' AND winner.terminal_target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
                WHEN winner.winner = 'failed' AND winner.terminal_target_error_summary = 'instance_unreachable' THEN 'unreachable'
                WHEN winner.winner = 'failed' AND winner.terminal_target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
                ELSE 'plugin_failed'
            END,
            connection_test_error_code = CASE
                WHEN winner.winner = 'succeeded' THEN ''
                WHEN winner.winner = 'failed'
                     AND winner.terminal_target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed')
                    THEN winner.terminal_target_error_summary
                ELSE 'plugin_failed'
            END,
            connection_validation_job_id = '',
            connection_validation_command_id = ''
        FROM dbpilot_retired_validation_winners winner
        WHERE instance.tenant_id = winner.tenant_id
          AND instance.project_id = winner.project_id
          AND instance.instance_id = winner.instance_id
    $instances$;

    IF to_regclass('audit_events') IS NOT NULL THEN
        EXECUTE $audit$
            INSERT INTO audit_events (
                id,tenant_id,project_id,occurred_at,action,actor_type,actor_id,
                resource_type,resource_id,result,request_id,trace_id,job_id,command_id,dedupe_key,detail,created_at
            )
            SELECT 'audit-dbi-validation-history-' || md5(winner.tenant_id || ':' || winner.project_id || ':' || winner.command_id || ':' || winner.winner),
                   winner.tenant_id,
                   winner.project_id,
                   COALESCE(winner.terminal_at, CURRENT_TIMESTAMP),
                   CASE winner.winner WHEN 'succeeded' THEN 'database_instance.connection_test_succeeded' WHEN 'cancelled' THEN 'database_instance.connection_test_cancelled_on_retire' ELSE 'database_instance.connection_test_failed' END,
                   'user',winner.actor_id,'database_instance',winner.instance_id,
                   CASE winner.winner WHEN 'succeeded' THEN 'success' ELSE 'failure' END,
                   winner.request_id,winner.trace_id,winner.job_id,winner.command_id,
                   'database-instance-validation-history:' || winner.command_id || ':' || winner.winner,
                   CASE winner.winner
                       WHEN 'cancelled' THEN jsonb_build_object('reason','instance_retired','error_code','plugin_failed')
                       WHEN 'succeeded' THEN jsonb_build_object('error_code','')
                       ELSE jsonb_build_object('error_code',CASE WHEN winner.terminal_target_error_summary IN ('instance_authentication_failed','instance_tls_failed','instance_unreachable','database_version_unsupported','plugin_failed') THEN winner.terminal_target_error_summary ELSE 'plugin_failed' END)
                   END,
                   COALESCE(winner.terminal_at, CURRENT_TIMESTAMP)
            FROM dbpilot_retired_validation_winners winner
            WHERE NOT EXISTS (
                SELECT 1 FROM audit_events existing
                WHERE existing.tenant_id=winner.tenant_id
                  AND existing.project_id=winner.project_id
                  AND existing.job_id=winner.job_id
                  AND existing.command_id=winner.command_id
                  AND existing.action=CASE winner.winner WHEN 'succeeded' THEN 'database_instance.connection_test_succeeded' WHEN 'cancelled' THEN 'database_instance.connection_test_cancelled_on_retire' ELSE 'database_instance.connection_test_failed' END
            )
            ON CONFLICT (tenant_id,project_id,dedupe_key) WHERE dedupe_key<>'' DO NOTHING
        $audit$;
    END IF;
END
$$;

COMMIT;
