BEGIN;

DO $$
DECLARE
    state_constraint TEXT;
BEGIN
    FOR state_constraint IN
        SELECT DISTINCT constraint_value.conname
        FROM pg_constraint AS constraint_value
        JOIN pg_attribute AS attribute_value
          ON attribute_value.attrelid = constraint_value.conrelid
         AND attribute_value.attnum = ANY (constraint_value.conkey)
        WHERE constraint_value.conrelid = 'idempotency_records'::regclass
          AND constraint_value.contype = 'c'
          AND attribute_value.attname = 'state'
    LOOP
        EXECUTE format('ALTER TABLE idempotency_records DROP CONSTRAINT %I', state_constraint);
    END LOOP;
END
$$;

ALTER TABLE idempotency_records
    ADD CONSTRAINT idempotency_records_state_check
        CHECK (state IN ('processing', 'side_effect_committed', 'audited', 'completed')),
    ADD CONSTRAINT idempotency_records_response_phase_check
        CHECK (
            (state = 'processing' AND response_status = 0 AND response_json IS NULL)
            OR
            (state IN ('side_effect_committed', 'audited', 'completed')
                AND response_status BETWEEN 100 AND 599
                AND response_json IS NOT NULL)
        );

COMMIT;
