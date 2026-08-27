BEGIN;

-- Only accepted rows were durable acknowledgements in the legacy schema.
-- Rejected rows must remain retryable rather than becoming false duplicates.
DELETE FROM ingest_batch_dedup WHERE NOT accepted;

ALTER TABLE ingest_batch_dedup ADD COLUMN state TEXT;
UPDATE ingest_batch_dedup SET state = 'accepted';
ALTER TABLE ingest_batch_dedup ALTER COLUMN state SET NOT NULL;
ALTER TABLE ingest_batch_dedup ADD CONSTRAINT ingest_batch_dedup_state_check CHECK (state IN ('processing', 'accepted'));
ALTER TABLE ingest_batch_dedup ALTER COLUMN accepted_at DROP NOT NULL;
ALTER TABLE ingest_batch_dedup DROP COLUMN accepted;
ALTER TABLE ingest_batch_dedup DROP COLUMN retryable;
ALTER TABLE ingest_batch_dedup DROP COLUMN error_code;

COMMIT;
