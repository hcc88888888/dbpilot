ALTER TABLE command_outbox
    ADD COLUMN IF NOT EXISTS prepared_envelope BYTEA;
