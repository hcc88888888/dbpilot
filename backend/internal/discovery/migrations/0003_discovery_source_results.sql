BEGIN;

CREATE TABLE discovery_scan_sources (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    discovery_source TEXT NOT NULL CHECK (discovery_source IN ('native', 'docker')),
    result_status TEXT NOT NULL CHECK (result_status IN ('completed', 'unavailable', 'not_configured', 'not_requested')),
    reason_code TEXT NOT NULL CHECK (reason_code IN ('healthy', 'helper_unavailable', 'permission_denied', 'detector_error', 'not_configured', 'not_requested')),
    observation_revision BIGINT NOT NULL CHECK (observation_revision >= 1),
    rule_revision BIGINT NOT NULL CHECK (rule_revision >= 1),
    rule_set_digest BYTEA NOT NULL CHECK (octet_length(rule_set_digest) = 32),
    observed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, host_id, discovery_source),
    FOREIGN KEY (tenant_id, project_id, host_id)
        REFERENCES discovery_scan_state (tenant_id, project_id, host_id) ON DELETE CASCADE
);

COMMIT;
