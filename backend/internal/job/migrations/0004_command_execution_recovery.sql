ALTER TABLE command_outbox
    ADD COLUMN IF NOT EXISTS command_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (command_status IN ('pending', 'active', 'succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')),
    ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS execution_deadline_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS execution_last_heartbeat_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS recovery_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cancellation_requested_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cancellation_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS cancellation_available_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cancellation_lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cancellation_attempts INTEGER NOT NULL DEFAULT 0 CHECK (cancellation_attempts >= 0);

CREATE INDEX IF NOT EXISTS command_outbox_execution_deadline_idx
    ON command_outbox (execution_deadline_at, recovery_lease_expires_at, created_at, id)
    WHERE command_status IN ('pending', 'active') AND published_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS command_outbox_cancellation_idx
    ON command_outbox (cancellation_available_at, cancellation_lease_expires_at, created_at, id)
    WHERE cancellation_requested_at IS NOT NULL AND command_status IN ('pending', 'active');
