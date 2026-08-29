BEGIN;

ALTER TABLE jobs
    ADD COLUMN max_concurrency INTEGER,
    ADD COLUMN target_timeout_seconds INTEGER;

UPDATE jobs
SET max_concurrency = 1,
    target_timeout_seconds = GREATEST(
        1,
        LEAST(3600, COALESCE(CEIL(EXTRACT(EPOCH FROM (timeout_at - created_at)))::INTEGER, 60))
    )
WHERE job_type = 'inspection.collect';

ALTER TABLE jobs
    ADD CONSTRAINT jobs_max_concurrency_bounds CHECK (max_concurrency IS NULL OR max_concurrency BETWEEN 1 AND 1000),
    ADD CONSTRAINT jobs_target_timeout_bounds CHECK (target_timeout_seconds IS NULL OR target_timeout_seconds BETWEEN 1 AND 3600),
    ADD CONSTRAINT jobs_inspection_execution_limits CHECK (
        job_type <> 'inspection.collect' OR (max_concurrency IS NOT NULL AND target_timeout_seconds IS NOT NULL)
    );

CREATE INDEX command_outbox_job_phase_idx
    ON command_outbox (tenant_id, project_id, job_id, command_phase);

COMMIT;
