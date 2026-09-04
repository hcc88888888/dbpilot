BEGIN;

ALTER TABLE command_outbox
    ADD COLUMN terminal_reconcile_available_at TIMESTAMPTZ,
    ADD COLUMN terminal_reconcile_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN terminal_reconcile_attempts INTEGER NOT NULL DEFAULT 0 CHECK (terminal_reconcile_attempts >= 0),
    ADD COLUMN terminal_reconcile_quarantined_at TIMESTAMPTZ,
    ADD COLUMN terminal_reconcile_quarantine_reason TEXT NOT NULL DEFAULT '';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM command_outbox outbox
        WHERE outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
          AND outbox.terminal_audit_recorded_at IS NULL
          AND (
              outbox.terminal_audit_dedupe_key <> ''
              OR outbox.terminal_audit_action <> ''
              OR outbox.terminal_audit_result <> ''
              OR outbox.terminal_audit_detail <> '{}'::jsonb
          )
          AND (
              outbox.terminal_audit_dedupe_key = ''
              OR outbox.terminal_audit_action = ''
              OR outbox.terminal_audit_result = ''
          )
    ) THEN
        RAISE EXCEPTION 'incomplete historical terminal Audit descriptor'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM command_outbox outbox
        JOIN jobs value
          ON value.tenant_id = outbox.tenant_id
         AND value.project_id = outbox.project_id
         AND value.id = outbox.job_id
        WHERE outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
          AND outbox.terminal_audit_recorded_at IS NULL
          AND outbox.terminal_audit_dedupe_key = ''
          AND value.job_type NOT IN (
              'host.rediscover',
              'database_instance.validate',
              'plugin.reconcile',
              'inspection.collect',
              'metric_template.trial'
          )
    ) THEN
        RAISE EXCEPTION 'unknown historical terminal command action'
            USING ERRCODE = '23514';
    END IF;
END
$$;

UPDATE command_outbox outbox
SET terminal_audit_pending = TRUE,
    terminal_audit_dedupe_key = CASE
        WHEN value.job_type = 'database_instance.validate' AND outbox.command_status IN ('succeeded', 'failed', 'rejected')
            THEN 'command.result:' || outbox.id
        WHEN value.job_type = 'database_instance.validate' AND outbox.command_status = 'timed_out'
            THEN 'command.execution_timed_out:' || outbox.id
        WHEN value.job_type = 'database_instance.validate' AND outbox.command_status = 'cancelled'
            THEN 'command.validation_cancelled_on_retire:' || outbox.id
        ELSE 'command.historical_terminal:' || outbox.id
    END,
    terminal_audit_action = CASE
        WHEN value.job_type = 'database_instance.validate' AND outbox.command_status IN ('succeeded', 'failed', 'rejected')
            THEN 'command.result'
        WHEN value.job_type = 'database_instance.validate' AND outbox.command_status = 'timed_out'
            THEN 'command.execution_timed_out'
        WHEN value.job_type = 'database_instance.validate' AND outbox.command_status = 'cancelled'
            THEN 'command.validation_cancelled_on_retire'
        ELSE 'command.historical_terminal'
    END,
    terminal_audit_result = CASE outbox.command_status WHEN 'succeeded' THEN 'success' ELSE 'failure' END,
    terminal_audit_detail = jsonb_build_object(
        'command_action', value.job_type,
        'historical_recovery', TRUE,
        'terminal_status', CASE outbox.command_status WHEN 'rejected' THEN 'failed' ELSE outbox.command_status END
    ),
    terminal_audit_lease_expires_at = NULL,
    terminal_audit_attempts = 0
FROM jobs value
WHERE value.tenant_id = outbox.tenant_id
  AND value.project_id = outbox.project_id
  AND value.id = outbox.job_id
  AND outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
  AND outbox.terminal_audit_recorded_at IS NULL
  AND outbox.terminal_audit_dedupe_key = '';

UPDATE command_outbox outbox
SET terminal_reconcile_available_at = COALESCE(outbox.terminal_at, outbox.created_at)
FROM jobs value
JOIN job_targets target
  ON target.tenant_id = value.tenant_id
 AND target.project_id = value.project_id
 AND target.job_id = value.id
WHERE value.tenant_id = outbox.tenant_id
  AND value.project_id = outbox.project_id
  AND value.id = outbox.job_id
  AND target.target_id = outbox.target_id
  AND outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
  AND (
      outbox.terminal_reconcile_pending
      OR value.status NOT IN ('succeeded', 'failed', 'cancelled', 'timed_out')
      OR target.status NOT IN ('succeeded', 'failed', 'skipped', 'cancelled', 'timed_out')
  );

DO $$
BEGIN
    IF to_regclass('database_instance_validations') IS NULL
       OR to_regclass('managed_database_instances') IS NULL THEN
        RETURN;
    END IF;

    EXECUTE $quarantine$
        UPDATE command_outbox outbox
        SET terminal_reconcile_quarantined_at = COALESCE(outbox.terminal_reconcile_quarantined_at, CURRENT_TIMESTAMP),
            terminal_reconcile_quarantine_reason = 'missing_effective_validation_outcome',
            terminal_reconcile_lease_expires_at = NULL
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
          AND validation.status IN ('queued', 'running')
          AND instance.management_status <> 'retired'
          AND value.status NOT IN ('succeeded', 'failed', 'cancelled', 'timed_out')
          AND target.status NOT IN ('succeeded', 'failed', 'skipped', 'cancelled', 'timed_out')
          AND outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
    $quarantine$;
END
$$;

ALTER TABLE command_outbox
    ADD CONSTRAINT command_outbox_terminal_reconcile_quarantine_check CHECK (
        (terminal_reconcile_quarantined_at IS NULL AND terminal_reconcile_quarantine_reason = '')
        OR
        (terminal_reconcile_quarantined_at IS NOT NULL AND terminal_reconcile_quarantine_reason <> '')
    );

CREATE INDEX command_outbox_terminal_reconcile_claim_idx
    ON command_outbox (
        terminal_reconcile_available_at,
        terminal_reconcile_lease_expires_at,
        terminal_at,
        created_at,
        id
    )
    WHERE terminal_reconcile_quarantined_at IS NULL
      AND command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected');

COMMIT;
