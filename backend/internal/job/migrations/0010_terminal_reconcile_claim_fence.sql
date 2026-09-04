BEGIN;

ALTER TABLE command_outbox
    ADD COLUMN terminal_reconcile_claim_token BYTEA;

-- A lease written by the pre-fence reconciler has no provable owner. Release
-- it once so the first fenced worker can claim it with a fresh random token.
UPDATE command_outbox
SET terminal_reconcile_lease_expires_at = NULL
WHERE terminal_reconcile_lease_expires_at IS NOT NULL;

ALTER TABLE command_outbox
    ADD CONSTRAINT command_outbox_terminal_reconcile_claim_check CHECK (
        (terminal_reconcile_claim_token IS NULL AND terminal_reconcile_lease_expires_at IS NULL)
        OR
        (
            terminal_reconcile_claim_token IS NOT NULL
            AND octet_length(terminal_reconcile_claim_token) = 32
            AND terminal_reconcile_lease_expires_at IS NOT NULL
        )
    );

COMMIT;
