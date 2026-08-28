ALTER TABLE command_outbox
    ADD COLUMN command_phase TEXT NOT NULL DEFAULT 'pending',
    ADD COLUMN prepare_digest BYTEA,
    ADD COLUMN prepared_at TIMESTAMPTZ,
    ADD COLUMN execution_token_hash BYTEA,
    ADD COLUMN execution_token_ciphertext BYTEA,
    ADD COLUMN execution_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN recovery_revision BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN start_deadline_at TIMESTAMPTZ,
    ADD COLUMN start_enqueued_at TIMESTAMPTZ,
    ADD COLUMN recovery_claim_token BYTEA,
    ADD COLUMN recovery_claimed_deadline TIMESTAMPTZ,
    ADD COLUMN recovery_claimed_revision BIGINT,
    ADD COLUMN terminal_result_digest BYTEA,
    ADD COLUMN terminal_at TIMESTAMPTZ;

-- Commands that were active under the single-phase 0004 schema cannot be
-- safely resumed because no execution token existed. Give them an
-- unforgeable synthetic fence and an immediate recovery deadline so the
-- timeout worker records durable Job/Audit evidence without reexecution.
UPDATE command_outbox
SET command_phase = 'running',
    prepare_digest = decode(repeat('00', 32), 'hex'),
    prepared_at = COALESCE(acknowledged_at, published_at, created_at),
    execution_token_hash = decode(repeat('00', 32), 'hex'),
    execution_token_ciphertext = decode('00', 'hex'),
    execution_revision = 1,
    recovery_revision = 1,
    start_deadline_at = CURRENT_TIMESTAMP,
    start_enqueued_at = published_at,
    execution_deadline_at = LEAST(COALESCE(execution_deadline_at, CURRENT_TIMESTAMP), CURRENT_TIMESTAMP),
    execution_last_heartbeat_at = COALESCE(execution_last_heartbeat_at, acknowledged_at, published_at, created_at)
WHERE command_status = 'active';

UPDATE command_outbox
SET command_phase = command_status,
    terminal_at = COALESCE(acknowledged_at, published_at, created_at)
WHERE command_status IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected');

ALTER TABLE command_outbox
    ADD CONSTRAINT command_outbox_phase_check CHECK (
        command_phase IN ('pending', 'preparing', 'prepared', 'start_authorized', 'running', 'cancelling', 'succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
    ),
    ADD CONSTRAINT command_outbox_prepare_digest_check CHECK (prepare_digest IS NULL OR octet_length(prepare_digest) = 32),
    ADD CONSTRAINT command_outbox_execution_token_hash_check CHECK (execution_token_hash IS NULL OR octet_length(execution_token_hash) = 32),
    ADD CONSTRAINT command_outbox_execution_token_ciphertext_check CHECK (execution_token_ciphertext IS NULL OR octet_length(execution_token_ciphertext) > 0),
    ADD CONSTRAINT command_outbox_terminal_result_digest_check CHECK (terminal_result_digest IS NULL OR octet_length(terminal_result_digest) = 32),
    ADD CONSTRAINT command_outbox_revisions_check CHECK (execution_revision >= 0 AND recovery_revision >= 0),
    ADD CONSTRAINT command_outbox_start_enqueued_check CHECK (start_enqueued_at IS NULL OR execution_revision > 0),
    ADD CONSTRAINT command_outbox_prepare_fields_pair_check CHECK ((prepare_digest IS NULL) = (prepared_at IS NULL)),
    ADD CONSTRAINT command_outbox_execution_fence_fields_check CHECK (
        (
            execution_revision = 0
            AND recovery_revision = 0
            AND execution_token_hash IS NULL
            AND execution_token_ciphertext IS NULL
            AND start_deadline_at IS NULL
        )
        OR (
            execution_revision > 0
            AND recovery_revision > 0
            AND execution_token_hash IS NOT NULL
            AND execution_token_ciphertext IS NOT NULL
            AND start_deadline_at IS NOT NULL
        )
    ),
    ADD CONSTRAINT command_outbox_prepared_fields_check CHECK (
        command_phase NOT IN ('prepared', 'start_authorized', 'running', 'cancelling')
        OR (prepare_digest IS NOT NULL AND prepared_at IS NOT NULL)
    ),
    ADD CONSTRAINT command_outbox_started_fields_check CHECK (
        command_phase NOT IN ('start_authorized', 'running', 'cancelling')
        OR (
            execution_token_hash IS NOT NULL
            AND execution_token_ciphertext IS NOT NULL
            AND execution_revision > 0
            AND recovery_revision > 0
            AND start_deadline_at IS NOT NULL
            AND execution_deadline_at IS NOT NULL
        )
    ),
    ADD CONSTRAINT command_outbox_recovery_claim_check CHECK (
        (recovery_claim_token IS NULL AND recovery_claimed_deadline IS NULL AND recovery_claimed_revision IS NULL)
        OR (
            recovery_claim_token IS NOT NULL
            AND octet_length(recovery_claim_token) = 32
            AND recovery_claimed_deadline IS NOT NULL
            AND recovery_claimed_revision IS NOT NULL
            AND recovery_claimed_revision > 0
            AND command_phase IN ('start_authorized', 'running', 'cancelling')
        )
    ),
    ADD CONSTRAINT command_outbox_terminal_fields_check CHECK (
        command_phase NOT IN ('succeeded', 'failed', 'cancelled', 'timed_out', 'rejected')
        OR terminal_at IS NOT NULL
    ),
    ADD CONSTRAINT command_outbox_terminal_digest_phase_check CHECK (
        terminal_result_digest IS NULL
        OR command_phase IN ('succeeded', 'failed', 'cancelled', 'timed_out')
    );

CREATE INDEX command_outbox_prepared_idx
    ON command_outbox (prepared_at, created_at, id)
    WHERE command_phase = 'prepared' AND cancellation_requested_at IS NULL;

CREATE INDEX command_outbox_prepared_recovery_idx
    ON command_outbox (lease_expires_at, prepared_at, created_at, id)
    WHERE command_phase IN ('prepared', 'start_authorized');

CREATE INDEX command_outbox_pending_cancellation_v2_idx
    ON command_outbox (cancellation_available_at, cancellation_lease_expires_at, created_at, id)
    WHERE cancellation_requested_at IS NOT NULL
      AND command_phase IN ('pending', 'preparing', 'prepared', 'start_authorized', 'running', 'cancelling');

CREATE INDEX command_outbox_expired_execution_v2_idx
    ON command_outbox (execution_deadline_at, recovery_claimed_deadline, recovery_claimed_revision, created_at, id)
    WHERE command_phase IN ('start_authorized', 'running', 'cancelling')
      AND execution_deadline_at IS NOT NULL;
