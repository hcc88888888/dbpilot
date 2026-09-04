BEGIN;

-- Repair deployments where 0008/0009 and databaseinstance/0006 were already
-- recorded before the pre-0008 target bridge existed. The independently
-- terminal Job target remains the effective validation outcome. An opposite
-- Audit that has already entered the append-only ledger cannot be rewritten,
-- so startup fails closed instead of projecting a second history.
DO $migration$
DECLARE
    conflict_exists BOOLEAN;
BEGIN
    IF to_regclass('database_instance_validations') IS NULL
       OR to_regclass('managed_database_instances') IS NULL
       OR to_regclass('jobs') IS NULL
       OR to_regclass('job_targets') IS NULL
       OR to_regclass('command_outbox') IS NULL THEN
        RETURN;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'managed_database_instances'
          AND column_name = 'connection_validation_job_id'
    ) OR NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'database_instance_validations'
          AND column_name = 'terminal_reconcile_quarantined_at'
    ) THEN
        RETURN;
    END IF;

    EXECUTE $repair$
        CREATE TEMP TABLE dbpilot_applied_validation_target_repair ON COMMIT DROP AS
        SELECT validation.tenant_id,
               validation.project_id,
               validation.job_id,
               validation.command_id,
               validation.instance_id,
               validation.previous_management_status,
               instance.agent_id,
               target.status AS target_status,
               target.error_summary AS target_error_summary,
               target.result_summary AS target_result_summary,
               target.artifacts AS target_artifacts,
               COALESCE(target.finished_at, outbox.terminal_at, CURRENT_TIMESTAMP) AS terminal_at,
               CASE target.status
                   WHEN 'succeeded' THEN 'succeeded'
                   WHEN 'cancelled' THEN 'cancelled'
                   WHEN 'timed_out' THEN 'timed_out'
                   ELSE CASE WHEN outbox.command_status = 'rejected' THEN 'rejected' ELSE 'failed' END
               END AS expected_command_status,
               CASE target.status
                   WHEN 'succeeded' THEN 'succeeded'
                   WHEN 'cancelled' THEN 'cancelled'
                   WHEN 'timed_out' THEN 'timed_out'
                   ELSE 'failed'
               END AS expected_job_status,
               CASE target.status WHEN 'succeeded' THEN 'complete' ELSE 'none' END AS expected_outcome,
               CASE target.status WHEN 'succeeded' THEN 1 ELSE 0 END AS expected_completed_targets,
               CASE target.status WHEN 'succeeded' THEN 0 ELSE 1 END AS expected_failed_targets,
               CASE
                   WHEN target.status IN ('succeeded', 'failed') THEN 'command.result'
                   WHEN target.status = 'timed_out' THEN 'command.execution_timed_out'
                   ELSE 'command.validation_cancelled_on_retire'
               END AS expected_audit_action,
               CASE target.status WHEN 'succeeded' THEN 'success' ELSE 'failure' END AS expected_audit_result,
               outbox.terminal_audit_recorded_at
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
        JOIN command_outbox outbox
          ON outbox.tenant_id = validation.tenant_id
         AND outbox.project_id = validation.project_id
         AND outbox.job_id = validation.job_id
         AND outbox.id = validation.command_id
        WHERE value.job_type = 'database_instance.validate'
          AND validation.status IN ('queued', 'running')
          AND instance.management_status <> 'retired'
          AND target.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
          AND outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
          AND (
              value.status NOT IN ('succeeded', 'failed', 'cancelled', 'timed_out')
              OR value.status = CASE target.status
                  WHEN 'succeeded' THEN 'succeeded'
                  WHEN 'cancelled' THEN 'cancelled'
                  WHEN 'timed_out' THEN 'timed_out'
                  ELSE 'failed'
                END
          )
          AND (
              CASE outbox.command_status WHEN 'rejected' THEN 'failed' ELSE outbox.command_status END <> target.status
              OR outbox.terminal_target_status IS DISTINCT FROM target.status
              OR outbox.terminal_target_error_summary IS DISTINCT FROM target.error_summary
              OR outbox.terminal_target_result_summary IS DISTINCT FROM target.result_summary
              OR outbox.terminal_target_artifacts IS DISTINCT FROM target.artifacts
              OR outbox.terminal_reconcile_quarantined_at IS NOT NULL
              OR NOT outbox.terminal_reconcile_pending
              OR outbox.terminal_audit_action IS DISTINCT FROM CASE
                    WHEN target.status IN ('succeeded', 'failed') THEN 'command.result'
                    WHEN target.status = 'timed_out' THEN 'command.execution_timed_out'
                    ELSE 'command.validation_cancelled_on_retire'
                 END
              OR outbox.terminal_audit_result IS DISTINCT FROM CASE target.status WHEN 'succeeded' THEN 'success' ELSE 'failure' END
              OR outbox.terminal_audit_detail IS DISTINCT FROM jsonb_build_object(
                    'command_action', 'database_instance.validate',
                    'historical_recovery', TRUE,
                    'terminal_status', target.status
                 )
          )
    $repair$;

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
            JOIN job_targets target
              ON target.tenant_id = validation.tenant_id
             AND target.project_id = validation.project_id
             AND target.job_id = validation.job_id
             AND target.target_id = instance.agent_id
            WHERE value.job_type = 'database_instance.validate'
              AND validation.status IN ('queued', 'running')
              AND instance.management_status <> 'retired'
              AND target.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
              AND value.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
              AND value.status <> CASE target.status
                    WHEN 'succeeded' THEN 'succeeded'
                    WHEN 'cancelled' THEN 'cancelled'
                    WHEN 'timed_out' THEN 'timed_out'
                    ELSE 'failed'
                  END
        )
    $conflict$ INTO conflict_exists;
    IF conflict_exists THEN
        RAISE EXCEPTION 'historical validation Job conflicts with target evidence'
            USING ERRCODE = '23514';
    END IF;

    CREATE TEMP TABLE dbpilot_applied_validation_command_audit (
        tenant_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        job_id TEXT NOT NULL,
        command_id TEXT NOT NULL,
        occurred_at TIMESTAMPTZ NOT NULL,
        action TEXT NOT NULL,
        result TEXT NOT NULL,
        dedupe_key TEXT NOT NULL,
        detail JSONB NOT NULL
    ) ON COMMIT DROP;

    IF to_regclass('audit_events') IS NOT NULL THEN
        EXECUTE $command_audits$
            INSERT INTO dbpilot_applied_validation_command_audit
            SELECT event.tenant_id,event.project_id,event.job_id,event.command_id,
                   event.occurred_at,event.action,event.result,event.dedupe_key,event.detail
            FROM dbpilot_applied_validation_target_repair repair
            JOIN audit_events event
              ON event.tenant_id = repair.tenant_id
             AND event.project_id = repair.project_id
             AND event.job_id = repair.job_id
             AND event.command_id = repair.command_id
             AND event.action IN (
                 'command.result', 'command.acknowledged',
                 'command.undelivered_timed_out', 'command.prepared_timed_out',
                 'command.cancelled_before_start', 'command.cancelled_before_dispatch',
                 'command.delivery_timed_out', 'command.execution_timed_out',
                 'command.prepared_envelope_expired',
                 'command.validation_cancelled_on_retire', 'command.historical_terminal'
             )
        $command_audits$;

        EXECUTE $command_audit_conflict$
            SELECT EXISTS (
                SELECT 1
                FROM dbpilot_applied_validation_target_repair repair
                JOIN dbpilot_applied_validation_command_audit event
                  ON event.tenant_id = repair.tenant_id
                 AND event.project_id = repair.project_id
                 AND event.job_id = repair.job_id
                 AND event.command_id = repair.command_id
                WHERE event.dedupe_key <> event.action || ':' || repair.command_id
                   OR jsonb_typeof(event.detail) <> 'object'
                   OR (CASE event.action
                      WHEN 'command.result' THEN
                          (repair.target_status = 'succeeded' AND event.result = 'success'
                           AND event.detail->>'state' IN ('COMMAND_RESULT_STATE_SUCCEEDED','succeeded')
                           AND jsonb_typeof(event.detail->'artifact_count') = 'number')
                          OR (repair.target_status = 'failed' AND event.result = 'failure'
                              AND event.detail->>'state' IN ('COMMAND_RESULT_STATE_FAILED','failed')
                              AND jsonb_typeof(event.detail->'artifact_count') = 'number')
                          OR (repair.target_status = 'cancelled' AND event.result = 'failure'
                              AND event.detail->>'state' IN ('COMMAND_RESULT_STATE_CANCELLED','cancelled')
                              AND jsonb_typeof(event.detail->'artifact_count') = 'number')
                          OR (repair.target_status = 'timed_out' AND event.result = 'failure'
                              AND event.detail->>'state' IN ('COMMAND_RESULT_STATE_TIMED_OUT','COMMAND_RESULT_STATE_INTERRUPTED','timed_out')
                              AND jsonb_typeof(event.detail->'artifact_count') = 'number')
                          OR (event.detail @> jsonb_build_object('historical_recovery',TRUE,'terminal_status',repair.target_status)
                              AND event.result = CASE repair.target_status WHEN 'succeeded' THEN 'success' ELSE 'failure' END)
                      WHEN 'command.acknowledged' THEN
                          repair.target_status = 'failed'
                          AND repair.expected_command_status = 'rejected'
                          AND event.result = 'failure'
                          AND event.detail->>'state' = 'rejected'
                          AND event.detail->>'reason_code' = repair.target_error_summary
                      WHEN 'command.undelivered_timed_out' THEN
                          repair.target_status = 'timed_out' AND event.result = 'failure' AND event.detail ? 'phase'
                      WHEN 'command.prepared_timed_out' THEN
                          repair.target_status = 'timed_out' AND event.result = 'failure' AND event.detail ? 'phase'
                      WHEN 'command.cancelled_before_start' THEN
                          repair.target_status = 'cancelled' AND event.result = 'success' AND event.detail ? 'phase'
                      WHEN 'command.cancelled_before_dispatch' THEN
                          repair.target_status = 'cancelled' AND event.result = 'success' AND event.detail->>'reason' = 'job_cancellation'
                      WHEN 'command.delivery_timed_out' THEN
                          repair.target_status = 'timed_out' AND event.result = 'failure' AND event.detail->>'reason' = 'delivery_deadline'
                      WHEN 'command.execution_timed_out' THEN
                          repair.target_status = 'timed_out' AND event.result = 'failure' AND event.detail->>'reason' = 'execution_deadline'
                      WHEN 'command.prepared_envelope_expired' THEN
                          repair.target_status = 'timed_out' AND event.result = 'failure'
                          AND event.detail->>'reason' = 'prepare_envelope_expiry' AND event.detail ? 'expires_at'
                      WHEN 'command.validation_cancelled_on_retire' THEN
                          repair.target_status = 'cancelled' AND event.result = 'failure' AND event.detail->>'reason' = 'instance_retired'
                      WHEN 'command.historical_terminal' THEN
                          event.result = CASE repair.target_status WHEN 'succeeded' THEN 'success' ELSE 'failure' END
                          AND event.detail @> jsonb_build_object(
                              'command_action','database_instance.validate',
                              'historical_recovery',TRUE,
                              'terminal_status',repair.target_status
                          )
                      ELSE FALSE
                   END) IS NOT TRUE
            )
        $command_audit_conflict$ INTO conflict_exists;
        IF conflict_exists THEN
            RAISE EXCEPTION 'recorded historical validation Audit conflicts with target evidence'
                USING ERRCODE = '23514';
        END IF;

        EXECUTE $duplicate_command_audit$
            SELECT EXISTS (
                SELECT 1 FROM dbpilot_applied_validation_command_audit
                GROUP BY tenant_id,project_id,job_id,command_id HAVING count(*) > 1
            )
        $duplicate_command_audit$ INTO conflict_exists;
        IF conflict_exists THEN
            RAISE EXCEPTION 'recorded historical validation Audit conflicts with target evidence'
                USING ERRCODE = '23514';
        END IF;

        EXECUTE $validation_audit_conflict$
            SELECT EXISTS (
                SELECT 1
                FROM dbpilot_applied_validation_target_repair repair
                JOIN audit_events event
                  ON event.tenant_id = repair.tenant_id
                 AND event.project_id = repair.project_id
                 AND event.job_id = repair.job_id
                 AND event.command_id = repair.command_id
                 AND event.action IN (
                     'database_instance.connection_test_succeeded',
                     'database_instance.connection_test_failed',
                     'database_instance.connection_test_cancelled_on_retire'
                )
                WHERE event.result <> CASE repair.target_status WHEN 'succeeded' THEN 'success' ELSE 'failure' END
                   OR NOT (
                       (repair.target_status = 'succeeded' AND event.action = 'database_instance.connection_test_succeeded')
                       OR (repair.target_status = 'cancelled' AND event.action IN (
                           'database_instance.connection_test_failed',
                           'database_instance.connection_test_cancelled_on_retire'
                       ))
                       OR (repair.target_status IN ('failed','timed_out') AND event.action = 'database_instance.connection_test_failed')
                   )
                   OR (
                       (event.dedupe_key LIKE 'database-instance-validation-history:%'
                        AND jsonb_typeof(event.detail->'error_code') = 'string')
                       OR (event.dedupe_key LIKE 'database-instance-validation:%'
                           AND jsonb_typeof(event.detail->'job_id') = 'string'
                           AND jsonb_typeof(event.detail->'command_id') = 'string'
                           AND jsonb_typeof(event.detail->'assignment_id') = 'string'
                           AND jsonb_typeof(event.detail->'configuration_revision') = 'number'
                           AND jsonb_typeof(event.detail->'operation_revision') = 'number'
                           AND jsonb_typeof(event.detail->'error_code') = 'string')
                   ) IS NOT TRUE
            )
        $validation_audit_conflict$ INTO conflict_exists;
        IF conflict_exists THEN
            RAISE EXCEPTION 'recorded historical validation Audit conflicts with target evidence'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    EXECUTE $missing_recorded_audit$
        SELECT EXISTS (
            SELECT 1
            FROM dbpilot_applied_validation_target_repair repair
            WHERE repair.terminal_audit_recorded_at IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM dbpilot_applied_validation_command_audit event
                  WHERE event.tenant_id=repair.tenant_id AND event.project_id=repair.project_id
                    AND event.job_id=repair.job_id AND event.command_id=repair.command_id
              )
        )
    $missing_recorded_audit$ INTO conflict_exists;
    IF conflict_exists THEN
        RAISE EXCEPTION 'recorded historical validation Audit conflicts with target evidence'
            USING ERRCODE = '23514';
    END IF;

    EXECUTE $jobs$
        UPDATE jobs value
        SET status = repair.expected_job_status,
            outcome = repair.expected_outcome,
            version = value.version + CASE WHEN
                value.status IS DISTINCT FROM repair.expected_job_status
                OR value.outcome IS DISTINCT FROM repair.expected_outcome
                OR value.completed_targets IS DISTINCT FROM repair.expected_completed_targets
                OR value.failed_targets IS DISTINCT FROM repair.expected_failed_targets
                OR value.skipped_targets IS DISTINCT FROM 0
                OR value.error_summary IS DISTINCT FROM ''
                OR value.result_summary IS DISTINCT FROM 'Agent commands completed'
                OR value.artifacts IS DISTINCT FROM repair.target_artifacts
                OR value.finished_at IS DISTINCT FROM COALESCE(value.finished_at, repair.terminal_at)
                OR (repair.expected_job_status = 'cancelled' AND value.cancel_requested_by = '')
                OR (repair.expected_job_status = 'cancelled' AND value.cancel_requested_at IS NULL)
                THEN 1 ELSE 0 END,
            completed_targets = repair.expected_completed_targets,
            failed_targets = repair.expected_failed_targets,
            skipped_targets = 0,
            error_summary = '',
            result_summary = 'Agent commands completed',
            artifacts = repair.target_artifacts,
            finished_at = COALESCE(value.finished_at, repair.terminal_at),
            cancel_requested_by = CASE
                WHEN repair.expected_job_status = 'cancelled' AND value.cancel_requested_by = ''
                    THEN 'historical-validation-recovery'
                ELSE value.cancel_requested_by
            END,
            cancel_requested_at = CASE
                WHEN repair.expected_job_status = 'cancelled'
                    THEN COALESCE(value.cancel_requested_at, repair.terminal_at)
                ELSE value.cancel_requested_at
            END
        FROM dbpilot_applied_validation_target_repair repair
        WHERE value.tenant_id = repair.tenant_id
          AND value.project_id = repair.project_id
          AND value.id = repair.job_id
    $jobs$;

    EXECUTE $outbox$
        UPDATE command_outbox outbox
        SET command_status = repair.expected_command_status,
            command_phase = repair.expected_command_status,
            terminal_target_status = repair.target_status,
            terminal_target_error_summary = repair.target_error_summary,
            terminal_target_result_summary = repair.target_result_summary,
            terminal_target_artifacts = repair.target_artifacts,
            terminal_reconcile_pending = TRUE,
            terminal_reconcile_available_at = COALESCE(outbox.terminal_at, repair.terminal_at),
            terminal_reconcile_lease_expires_at = NULL,
            terminal_reconcile_claim_token = NULL,
            terminal_reconcile_quarantined_at = NULL,
            terminal_reconcile_quarantine_reason = '',
            terminal_audit_pending = event.command_id IS NULL AND repair.terminal_audit_recorded_at IS NULL,
            terminal_audit_dedupe_key = COALESCE(event.dedupe_key, repair.expected_audit_action || ':' || repair.command_id),
            terminal_audit_action = COALESCE(event.action, repair.expected_audit_action),
            terminal_audit_result = COALESCE(event.result, repair.expected_audit_result),
            terminal_audit_detail = COALESCE(event.detail, jsonb_build_object(
                'command_action', 'database_instance.validate',
                'historical_recovery', TRUE,
                'terminal_status', repair.target_status
            )),
            terminal_audit_lease_expires_at = NULL,
            terminal_audit_attempts = CASE WHEN event.command_id IS NULL THEN 0 ELSE outbox.terminal_audit_attempts END,
            terminal_audit_recorded_at = CASE
                WHEN event.command_id IS NOT NULL THEN COALESCE(repair.terminal_audit_recorded_at,event.occurred_at)
                ELSE repair.terminal_audit_recorded_at
            END
        FROM dbpilot_applied_validation_target_repair repair
        LEFT JOIN dbpilot_applied_validation_command_audit event
          ON event.tenant_id=repair.tenant_id AND event.project_id=repair.project_id
         AND event.job_id=repair.job_id AND event.command_id=repair.command_id
        WHERE outbox.tenant_id = repair.tenant_id
          AND outbox.project_id = repair.project_id
          AND outbox.id = repair.command_id
    $outbox$;

    EXECUTE $validation$
        UPDATE database_instance_validations validation
        SET status = CASE
                WHEN repair.target_status = 'succeeded' THEN 'succeeded'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'instance_unreachable' THEN 'unreachable'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
                ELSE 'plugin_failed'
            END,
            error_code = CASE
                WHEN repair.target_status = 'succeeded' THEN ''
                WHEN repair.target_status = 'failed' AND repair.target_error_summary IN (
                    'instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable',
                    'database_version_unsupported', 'plugin_failed'
                ) THEN repair.target_error_summary
                ELSE 'plugin_failed'
            END,
            started_at = COALESCE(validation.started_at, validation.requested_at),
            completed_at = COALESCE(validation.completed_at, repair.terminal_at)
        FROM dbpilot_applied_validation_target_repair repair
        WHERE validation.tenant_id = repair.tenant_id
          AND validation.project_id = repair.project_id
          AND validation.job_id = repair.job_id
          AND validation.command_id = repair.command_id
    $validation$;

    EXECUTE $instance$
        UPDATE managed_database_instances instance
        SET capability_state = CASE
                WHEN repair.target_status = 'failed' AND repair.target_error_summary NOT IN (
                    'instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable',
                    'database_version_unsupported'
                ) THEN 'plugin_failed'
                ELSE 'plugin_available'
            END,
            connection_test_status = CASE
                WHEN repair.target_status = 'succeeded' THEN 'succeeded'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'instance_unreachable' THEN 'unreachable'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
                ELSE 'plugin_failed'
            END,
            connection_test_error_code = CASE
                WHEN repair.target_status = 'succeeded' THEN ''
                WHEN repair.target_status = 'failed' AND repair.target_error_summary IN (
                    'instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable',
                    'database_version_unsupported', 'plugin_failed'
                ) THEN repair.target_error_summary
                ELSE 'plugin_failed'
            END,
            connection_test_at = repair.terminal_at,
            management_status = CASE
                WHEN repair.target_status = 'succeeded' AND repair.previous_management_status = 'monitoring' THEN 'monitoring'
                WHEN repair.target_status = 'succeeded' THEN 'managed'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'instance_unreachable' THEN 'unreachable'
                WHEN repair.target_status = 'failed' AND repair.target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
                ELSE 'plugin_failed'
            END,
            connection_validation_job_id = '',
            connection_validation_command_id = '',
            revision = instance.revision + 1,
            updated_at = repair.terminal_at
        FROM dbpilot_applied_validation_target_repair repair
        WHERE instance.tenant_id = repair.tenant_id
          AND instance.project_id = repair.project_id
          AND instance.instance_id = repair.instance_id
    $instance$;
END
$migration$;

COMMIT;
