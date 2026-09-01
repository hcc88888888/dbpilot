BEGIN;

ALTER TABLE credential_lease_audits
    ADD COLUMN credential_ref_hash TEXT NOT NULL DEFAULT ''
    CHECK (credential_ref_hash = '' OR credential_ref_hash ~ '^sha256:[0-9a-f]{64}$');

CREATE INDEX credential_lease_audits_renewal_fence_idx
    ON credential_lease_audits
    (tenant_id, project_id, agent_id, assignment_id, instance_id, configuration_revision, operation_revision, instance_revision, credential_ref_hash)
    WHERE result = 'issued';

COMMIT;
