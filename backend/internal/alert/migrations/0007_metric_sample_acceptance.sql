BEGIN;

ALTER TABLE metric_samples ADD COLUMN accepted_at TIMESTAMPTZ;
UPDATE metric_samples SET accepted_at = NOW() WHERE accepted_at IS NULL;
ALTER TABLE metric_samples ALTER COLUMN accepted_at SET NOT NULL;
ALTER TABLE metric_samples ALTER COLUMN accepted_at SET DEFAULT NOW();

CREATE INDEX metric_samples_inspection_acceptance_idx
ON metric_samples (tenant_id, project_id, agent_id, accepted_at, sampled_at);

COMMIT;
