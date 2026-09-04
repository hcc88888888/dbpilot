BEGIN;

ALTER TABLE database_instance_validations
    ADD COLUMN terminal_reconcile_quarantined_at TIMESTAMPTZ,
    ADD COLUMN terminal_reconcile_quarantine_reason TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT database_instance_validations_terminal_quarantine_check CHECK (
        (terminal_reconcile_quarantined_at IS NULL AND terminal_reconcile_quarantine_reason = '')
        OR
        (terminal_reconcile_quarantined_at IS NOT NULL AND terminal_reconcile_quarantine_reason <> '')
    );

DO $migration$
BEGIN
    IF to_regclass('jobs') IS NULL
       OR to_regclass('job_targets') IS NULL
       OR to_regclass('command_outbox') IS NULL
       OR to_regclass('audit_events') IS NULL THEN
        RETURN;
    END IF;

CREATE TEMP TABLE dbpilot_pre_atomic_validation_evidence ON COMMIT DROP AS
SELECT validation.tenant_id,
       validation.project_id,
       validation.job_id,
       validation.command_id,
       validation.instance_id,
       validation.actor_id,
       validation.request_id,
       validation.trace_id,
       validation.previous_management_status,
       instance.agent_id,
       target.status AS target_status,
       target.error_summary AS target_error_summary,
       target.result_summary AS target_result_summary,
       target.artifacts AS target_artifacts,
       COALESCE(target.finished_at, outbox.terminal_at, CURRENT_TIMESTAMP) AS terminal_at,
       outbox.command_status
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
WHERE validation.status IN ('queued', 'running')
  AND instance.management_status <> 'retired'
  AND outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
  AND target.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
  AND target.status = CASE outbox.command_status
        WHEN 'succeeded' THEN 'succeeded'
        WHEN 'cancelled' THEN 'cancelled'
        WHEN 'timed_out' THEN 'timed_out'
        ELSE 'failed'
      END
  AND (
      value.status NOT IN ('succeeded', 'failed', 'cancelled', 'timed_out')
      OR value.status = CASE target.status
          WHEN 'succeeded' THEN 'succeeded'
          WHEN 'cancelled' THEN 'cancelled'
          WHEN 'timed_out' THEN 'timed_out'
          ELSE 'failed'
        END
  );

UPDATE database_instance_validations validation
SET terminal_reconcile_quarantined_at = CURRENT_TIMESTAMP,
    terminal_reconcile_quarantine_reason = CASE
        WHEN target.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
            THEN 'conflicting_effective_outcome_evidence'
        ELSE 'missing_effective_outcome_evidence'
    END
FROM managed_database_instances instance
JOIN jobs value
  ON value.tenant_id = instance.tenant_id
 AND value.project_id = instance.project_id
JOIN command_outbox outbox
  ON outbox.tenant_id = value.tenant_id
 AND outbox.project_id = value.project_id
 AND outbox.job_id = value.id
JOIN job_targets target
  ON target.tenant_id = value.tenant_id
 AND target.project_id = value.project_id
 AND target.job_id = value.id
 AND target.target_id = instance.agent_id
WHERE validation.tenant_id = instance.tenant_id
  AND validation.project_id = instance.project_id
  AND validation.instance_id = instance.instance_id
  AND validation.job_id = value.id
  AND validation.command_id = outbox.id
  AND validation.status IN ('queued', 'running')
  AND instance.management_status <> 'retired'
  AND outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
  AND NOT EXISTS (
      SELECT 1
      FROM dbpilot_pre_atomic_validation_evidence evidence
      WHERE evidence.tenant_id = validation.tenant_id
        AND evidence.project_id = validation.project_id
        AND evidence.job_id = validation.job_id
        AND evidence.command_id = validation.command_id
  );

UPDATE command_outbox outbox
SET terminal_reconcile_quarantined_at = COALESCE(outbox.terminal_reconcile_quarantined_at, validation.terminal_reconcile_quarantined_at),
    terminal_reconcile_quarantine_reason = CASE
        WHEN outbox.terminal_reconcile_quarantine_reason <> '' THEN outbox.terminal_reconcile_quarantine_reason
        ELSE CASE validation.terminal_reconcile_quarantine_reason
            WHEN 'missing_effective_outcome_evidence' THEN 'missing_effective_validation_outcome'
            ELSE 'conflicting_effective_validation_outcome'
        END
    END,
    terminal_reconcile_lease_expires_at = NULL
FROM database_instance_validations validation
WHERE outbox.tenant_id = validation.tenant_id
  AND outbox.project_id = validation.project_id
  AND outbox.job_id = validation.job_id
  AND outbox.id = validation.command_id
  AND validation.terminal_reconcile_quarantined_at IS NOT NULL;

UPDATE jobs value
SET status = desired.job_status,
    outcome = desired.job_outcome,
    version = value.version + CASE WHEN
        value.status IS DISTINCT FROM desired.job_status
        OR value.outcome IS DISTINCT FROM desired.job_outcome
        OR value.completed_targets IS DISTINCT FROM desired.completed_targets
        OR value.failed_targets IS DISTINCT FROM desired.failed_targets
        OR value.skipped_targets IS DISTINCT FROM 0
        OR value.error_summary IS DISTINCT FROM ''
        OR value.result_summary IS DISTINCT FROM 'Agent commands completed'
        OR value.artifacts IS DISTINCT FROM desired.target_artifacts
        OR value.finished_at IS DISTINCT FROM COALESCE(value.finished_at, desired.terminal_at)
        OR (desired.job_status = 'cancelled' AND value.cancel_requested_by = '')
        OR (desired.job_status = 'cancelled' AND value.cancel_requested_at IS NULL)
        THEN 1 ELSE 0 END,
    completed_targets = desired.completed_targets,
    failed_targets = desired.failed_targets,
    skipped_targets = 0,
    error_summary = '',
    result_summary = 'Agent commands completed',
    artifacts = desired.target_artifacts,
    finished_at = COALESCE(value.finished_at, desired.terminal_at),
    cancel_requested_by = CASE WHEN desired.job_status = 'cancelled' AND value.cancel_requested_by = '' THEN 'historical-validation-recovery' ELSE value.cancel_requested_by END,
    cancel_requested_at = CASE WHEN desired.job_status = 'cancelled' THEN COALESCE(value.cancel_requested_at, desired.terminal_at) ELSE value.cancel_requested_at END
FROM (
    SELECT evidence.*,
           CASE evidence.target_status
               WHEN 'succeeded' THEN 'succeeded'
               WHEN 'cancelled' THEN 'cancelled'
               WHEN 'timed_out' THEN 'timed_out'
               ELSE 'failed'
           END AS job_status,
           CASE evidence.target_status WHEN 'succeeded' THEN 'complete' ELSE 'none' END AS job_outcome,
           CASE evidence.target_status WHEN 'succeeded' THEN 1 ELSE 0 END AS completed_targets,
           CASE evidence.target_status WHEN 'succeeded' THEN 0 ELSE 1 END AS failed_targets
    FROM dbpilot_pre_atomic_validation_evidence evidence
) desired
WHERE value.tenant_id = desired.tenant_id
  AND value.project_id = desired.project_id
  AND value.id = desired.job_id;

UPDATE command_outbox outbox
SET terminal_target_status = evidence.target_status,
    terminal_target_error_summary = evidence.target_error_summary,
    terminal_target_result_summary = evidence.target_result_summary,
    terminal_target_artifacts = evidence.target_artifacts,
    terminal_reconcile_pending = FALSE,
    terminal_reconcile_available_at = NULL,
    terminal_reconcile_lease_expires_at = NULL,
    terminal_reconcile_quarantined_at = NULL,
    terminal_reconcile_quarantine_reason = ''
FROM dbpilot_pre_atomic_validation_evidence evidence
WHERE outbox.tenant_id = evidence.tenant_id
  AND outbox.project_id = evidence.project_id
  AND outbox.job_id = evidence.job_id
  AND outbox.id = evidence.command_id;

UPDATE database_instance_validations validation
SET status = CASE
        WHEN evidence.target_status = 'succeeded' THEN 'succeeded'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'instance_unreachable' THEN 'unreachable'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
        ELSE 'plugin_failed'
    END,
    error_code = CASE
        WHEN evidence.target_status = 'succeeded' THEN ''
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed') THEN evidence.target_error_summary
        ELSE 'plugin_failed'
    END,
    started_at = COALESCE(validation.started_at, validation.requested_at),
    completed_at = COALESCE(validation.completed_at, evidence.terminal_at)
FROM dbpilot_pre_atomic_validation_evidence evidence
WHERE validation.tenant_id = evidence.tenant_id
  AND validation.project_id = evidence.project_id
  AND validation.job_id = evidence.job_id
  AND validation.command_id = evidence.command_id;

UPDATE managed_database_instances instance
SET capability_state = CASE WHEN evidence.target_status = 'failed' AND evidence.target_error_summary NOT IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported') THEN 'plugin_failed' ELSE 'plugin_available' END,
    connection_test_status = CASE
        WHEN evidence.target_status = 'succeeded' THEN 'succeeded'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'instance_unreachable' THEN 'unreachable'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
        ELSE 'plugin_failed'
    END,
    connection_test_error_code = CASE
        WHEN evidence.target_status = 'succeeded' THEN ''
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed') THEN evidence.target_error_summary
        ELSE 'plugin_failed'
    END,
    connection_test_at = evidence.terminal_at,
    management_status = CASE
        WHEN evidence.target_status = 'succeeded' AND evidence.previous_management_status = 'monitoring' THEN 'monitoring'
        WHEN evidence.target_status = 'succeeded' THEN 'managed'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'instance_unreachable' THEN 'unreachable'
        WHEN evidence.target_status = 'failed' AND evidence.target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
        ELSE 'plugin_failed'
    END,
    connection_validation_job_id = '',
    connection_validation_command_id = '',
    revision = instance.revision + 1,
    updated_at = evidence.terminal_at
FROM dbpilot_pre_atomic_validation_evidence evidence
WHERE instance.tenant_id = evidence.tenant_id
  AND instance.project_id = evidence.project_id
  AND instance.instance_id = evidence.instance_id;

INSERT INTO audit_events (
    id, tenant_id, project_id, occurred_at, action, actor_type, actor_id,
    resource_type, resource_id, result, request_id, trace_id, job_id, command_id,
    dedupe_key, detail, created_at
)
SELECT 'audit-dbi-pre-atomic-' || md5(evidence.tenant_id || ':' || evidence.project_id || ':' || evidence.command_id),
       evidence.tenant_id,
       evidence.project_id,
       evidence.terminal_at,
       CASE evidence.target_status WHEN 'succeeded' THEN 'database_instance.connection_test_succeeded' ELSE 'database_instance.connection_test_failed' END,
       'user',
       evidence.actor_id,
       'database_instance',
       evidence.instance_id,
       CASE evidence.target_status WHEN 'succeeded' THEN 'success' ELSE 'failure' END,
       evidence.request_id,
       evidence.trace_id,
       evidence.job_id,
       evidence.command_id,
       'database-instance-validation-history:' || evidence.command_id || ':' || evidence.target_status,
       jsonb_build_object('error_code', CASE
           WHEN evidence.target_status = 'failed' AND evidence.target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed') THEN evidence.target_error_summary
           WHEN evidence.target_status = 'succeeded' THEN ''
           ELSE 'plugin_failed'
       END),
       evidence.terminal_at
FROM dbpilot_pre_atomic_validation_evidence evidence
ON CONFLICT (tenant_id, project_id, dedupe_key) WHERE dedupe_key <> '' DO NOTHING;

IF to_regclass('dbpilot_retired_validation_winner_markers') IS NOT NULL THEN

    UPDATE jobs value
    SET status = marker.winner,
        outcome = CASE marker.winner WHEN 'succeeded' THEN 'complete' ELSE 'none' END,
        version = value.version + CASE WHEN value.version <= marker.original_job_version AND (
            value.status IS DISTINCT FROM marker.winner
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
        ) THEN 1 ELSE 0 END,
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
      AND value.id = marker.job_id;

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
      AND target.target_id = marker.agent_id;

    UPDATE command_outbox outbox
    SET command_status = CASE WHEN marker.winner = 'failed' AND outbox.command_status = 'rejected' THEN 'rejected' ELSE marker.winner END,
        command_phase = CASE WHEN marker.winner = 'failed' AND outbox.command_status = 'rejected' THEN 'rejected' ELSE marker.winner END,
        terminal_at = COALESCE(outbox.terminal_at, marker.terminal_at),
        published_at = COALESCE(outbox.published_at, marker.terminal_at),
        terminal_target_status = marker.winner,
        terminal_target_error_summary = marker.target_error_summary,
        terminal_target_result_summary = marker.target_result_summary,
        terminal_target_artifacts = marker.target_artifacts,
        terminal_reconcile_pending = FALSE,
        terminal_reconcile_available_at = NULL,
        terminal_reconcile_lease_expires_at = NULL,
        terminal_reconcile_quarantined_at = NULL,
        terminal_reconcile_quarantine_reason = ''
    FROM dbpilot_retired_validation_winner_markers marker
    WHERE outbox.tenant_id = marker.tenant_id
      AND outbox.project_id = marker.project_id
      AND outbox.job_id = marker.job_id
      AND outbox.id = marker.command_id;

    UPDATE database_instance_validations validation
    SET status = CASE
            WHEN marker.winner = 'succeeded' THEN 'succeeded'
            WHEN marker.winner = 'failed' AND marker.target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
            WHEN marker.winner = 'failed' AND marker.target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
            WHEN marker.winner = 'failed' AND marker.target_error_summary = 'instance_unreachable' THEN 'unreachable'
            WHEN marker.winner = 'failed' AND marker.target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
            ELSE 'plugin_failed'
        END,
        error_code = CASE
            WHEN marker.winner = 'succeeded' THEN ''
            WHEN marker.winner = 'failed' AND marker.target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed') THEN marker.target_error_summary
            ELSE 'plugin_failed'
        END,
        started_at = COALESCE(validation.started_at, validation.requested_at),
        completed_at = COALESCE(validation.completed_at, marker.terminal_at),
        terminal_reconcile_quarantined_at = NULL,
        terminal_reconcile_quarantine_reason = ''
    FROM dbpilot_retired_validation_winner_markers marker
    WHERE validation.tenant_id = marker.tenant_id
      AND validation.project_id = marker.project_id
      AND validation.job_id = marker.job_id
      AND validation.command_id = marker.command_id;

    UPDATE managed_database_instances instance
    SET connection_test_status = CASE
            WHEN marker.winner = 'succeeded' THEN 'succeeded'
            WHEN marker.winner = 'failed' AND marker.target_error_summary = 'instance_authentication_failed' THEN 'authentication_failed'
            WHEN marker.winner = 'failed' AND marker.target_error_summary = 'instance_tls_failed' THEN 'tls_failed'
            WHEN marker.winner = 'failed' AND marker.target_error_summary = 'instance_unreachable' THEN 'unreachable'
            WHEN marker.winner = 'failed' AND marker.target_error_summary = 'database_version_unsupported' THEN 'unsupported_version'
            ELSE 'plugin_failed'
        END,
        connection_test_error_code = CASE
            WHEN marker.winner = 'succeeded' THEN ''
            WHEN marker.winner = 'failed' AND marker.target_error_summary IN ('instance_authentication_failed', 'instance_tls_failed', 'instance_unreachable', 'database_version_unsupported', 'plugin_failed') THEN marker.target_error_summary
            ELSE 'plugin_failed'
        END,
        connection_test_at = COALESCE(instance.connection_test_at, marker.terminal_at),
        connection_validation_job_id = '',
        connection_validation_command_id = ''
    FROM dbpilot_retired_validation_winner_markers marker
    WHERE instance.tenant_id = marker.tenant_id
      AND instance.project_id = marker.project_id
      AND instance.instance_id = marker.instance_id;
END IF;
END
$migration$;

COMMIT;
