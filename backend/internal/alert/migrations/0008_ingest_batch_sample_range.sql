BEGIN;

ALTER TABLE ingest_batch_dedup ADD COLUMN tenant_id TEXT;
ALTER TABLE ingest_batch_dedup ADD COLUMN project_id TEXT;
ALTER TABLE ingest_batch_dedup ADD COLUMN sampled_from TIMESTAMPTZ;
ALTER TABLE ingest_batch_dedup ADD COLUMN sampled_to TIMESTAMPTZ;

ALTER TABLE ingest_batch_dedup ADD CONSTRAINT ingest_batch_dedup_sample_range_check CHECK (
    (tenant_id IS NULL AND project_id IS NULL AND sampled_from IS NULL AND sampled_to IS NULL)
    OR
    (tenant_id IS NOT NULL AND project_id IS NOT NULL AND sampled_from IS NOT NULL AND sampled_to IS NOT NULL AND sampled_from <= sampled_to)
);

CREATE INDEX ingest_batch_dedup_replay_idx
ON ingest_batch_dedup (tenant_id, project_id, agent_id, sampled_from, sampled_to, accepted_at)
WHERE state = 'accepted' AND sampled_from IS NOT NULL;

COMMIT;
