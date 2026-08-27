DO $$
DECLARE
    payload_type TEXT;
BEGIN
    SELECT data_type INTO payload_type
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'command_outbox'
      AND column_name = 'payload';

    IF payload_type = 'jsonb' THEN
        ALTER TABLE command_outbox
            ALTER COLUMN payload TYPE BYTEA
            USING convert_to(payload::text, 'UTF8');
    END IF;
END
$$;
