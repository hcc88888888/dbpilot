BEGIN;

ALTER TABLE command_outbox
    ADD COLUMN terminal_target_status TEXT NOT NULL DEFAULT '',
    ADD COLUMN terminal_target_error_summary TEXT NOT NULL DEFAULT '',
    ADD COLUMN terminal_target_result_summary TEXT NOT NULL DEFAULT '',
    ADD COLUMN terminal_target_artifacts JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN terminal_reconcile_pending BOOLEAN NOT NULL DEFAULT FALSE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM command_outbox outbox
        LEFT JOIN job_targets target
          ON target.tenant_id = outbox.tenant_id
         AND target.project_id = outbox.project_id
         AND target.job_id = outbox.job_id
         AND target.target_id = outbox.target_id
        WHERE outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
          AND target.job_id IS NULL
    ) THEN
        RAISE EXCEPTION 'terminal Command is missing its Job target'
            USING ERRCODE = '23514';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM command_outbox outbox
        JOIN job_targets target
          ON target.tenant_id = outbox.tenant_id
         AND target.project_id = outbox.project_id
         AND target.job_id = outbox.job_id
         AND target.target_id = outbox.target_id
        WHERE outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
          AND target.status IN ('succeeded', 'failed', 'skipped', 'cancelled', 'timed_out')
          AND target.status <> CASE outbox.command_status
                WHEN 'succeeded' THEN 'succeeded'
                WHEN 'cancelled' THEN 'cancelled'
                WHEN 'timed_out' THEN 'timed_out'
                ELSE 'failed'
              END
    ) THEN
        RAISE EXCEPTION 'conflicting terminal Command and Job target winner'
            USING ERRCODE = '23514';
    END IF;
END
$$;

UPDATE command_outbox outbox
SET terminal_target_status = COALESCE(
        (SELECT target.status
         FROM job_targets target
         WHERE target.tenant_id = outbox.tenant_id
           AND target.project_id = outbox.project_id
           AND target.job_id = outbox.job_id
           AND target.target_id = outbox.target_id
           AND target.status IN ('succeeded', 'failed', 'skipped', 'cancelled', 'timed_out')),
        CASE outbox.command_status
            WHEN 'succeeded' THEN 'succeeded'
            WHEN 'cancelled' THEN 'cancelled'
            WHEN 'timed_out' THEN 'timed_out'
            ELSE 'failed'
        END
    ),
    terminal_target_error_summary = COALESCE(
        (SELECT target.error_summary
         FROM job_targets target
         WHERE target.tenant_id = outbox.tenant_id
           AND target.project_id = outbox.project_id
           AND target.job_id = outbox.job_id
           AND target.target_id = outbox.target_id
           AND target.status IN ('succeeded', 'failed', 'skipped', 'cancelled', 'timed_out')),
        CASE outbox.command_status
            WHEN 'failed' THEN 'command_failed'
            WHEN 'rejected' THEN 'command_rejected'
            WHEN 'timed_out' THEN 'command_timed_out'
            ELSE ''
        END
    ),
    terminal_target_result_summary = COALESCE(
        (SELECT target.result_summary
         FROM job_targets target
         WHERE target.tenant_id = outbox.tenant_id
           AND target.project_id = outbox.project_id
           AND target.job_id = outbox.job_id
           AND target.target_id = outbox.target_id
           AND target.status IN ('succeeded', 'failed', 'skipped', 'cancelled', 'timed_out')),
        CASE outbox.command_status
            WHEN 'succeeded' THEN 'Agent command succeeded'
            WHEN 'cancelled' THEN 'Agent command cancelled'
            ELSE 'Agent command failed'
        END
    ),
    terminal_target_artifacts = COALESCE(
        (SELECT target.artifacts
         FROM job_targets target
         WHERE target.tenant_id = outbox.tenant_id
           AND target.project_id = outbox.project_id
           AND target.job_id = outbox.job_id
           AND target.target_id = outbox.target_id
           AND target.status IN ('succeeded', 'failed', 'skipped', 'cancelled', 'timed_out')),
        '[]'::jsonb
    ),
    terminal_reconcile_pending = TRUE
WHERE outbox.command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected');

ALTER TABLE command_outbox
    ADD CONSTRAINT command_outbox_terminal_target_status_check CHECK (
        terminal_target_status IN ('', 'succeeded', 'failed', 'skipped', 'cancelled', 'timed_out')
    ),
    ADD CONSTRAINT command_outbox_terminal_reconcile_check CHECK (
        NOT terminal_reconcile_pending
        OR (
            command_phase IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
            AND terminal_target_status <> ''
            AND terminal_at IS NOT NULL
        )
    );

CREATE INDEX command_outbox_terminal_reconcile_pending_idx
    ON command_outbox (terminal_at, created_at, id)
    WHERE terminal_reconcile_pending;

COMMIT;
