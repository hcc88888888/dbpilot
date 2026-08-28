BEGIN;

ALTER TABLE idempotency_records
    DROP CONSTRAINT idempotency_records_response_phase_check,
    ADD CONSTRAINT idempotency_records_response_phase_check
        CHECK (
            (state = 'processing'
                AND response_status = 0
                AND response_json IS NULL)
            OR
            (state IN ('side_effect_committed', 'audited')
                AND response_status BETWEEN 100 AND 599
                AND response_json IS NOT NULL
                AND audit_event_json IS NOT NULL)
            OR
            (state = 'completed'
                AND response_status BETWEEN 100 AND 599
                AND response_json IS NOT NULL)
        );

COMMIT;
