BEGIN;

CREATE TABLE discovery_scan_state (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    observation_revision BIGINT NOT NULL CHECK (observation_revision >= 1),
    rule_revision BIGINT NOT NULL CHECK (rule_revision >= 1),
    report_digest BYTEA NOT NULL CHECK (octet_length(report_digest) = 32),
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, host_id),
    FOREIGN KEY (tenant_id, project_id, host_id, agent_id)
        REFERENCES managed_hosts (tenant_id, project_id, host_id, agent_id)
);

CREATE TABLE discovery_candidates (
    candidate_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    discovery_source TEXT NOT NULL CHECK (discovery_source IN ('native', 'docker')),
    database_family TEXT NOT NULL,
    database_variant TEXT NOT NULL,
    version_hint TEXT NOT NULL DEFAULT '',
    normalized_endpoint TEXT NOT NULL DEFAULT '',
    unix_socket TEXT NOT NULL DEFAULT '',
    process_identity TEXT NOT NULL DEFAULT '',
    service_name TEXT NOT NULL DEFAULT '',
    container_identity TEXT NOT NULL DEFAULT '',
    container_image TEXT NOT NULL DEFAULT '',
    discovered_role TEXT NOT NULL DEFAULT '',
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    evidence_summary JSONB NOT NULL CHECK (jsonb_typeof(evidence_summary) = 'array' AND octet_length(evidence_summary::text) <= 16384),
    fingerprint BYTEA NOT NULL CHECK (octet_length(fingerprint) = 32),
    rule_revision BIGINT NOT NULL CHECK (rule_revision >= 1),
    observation_revision BIGINT NOT NULL CHECK (observation_revision >= 1),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('discovered', 'awaiting_confirmation', 'accepted', 'provisioning', 'ignored', 'duplicate', 'disappeared')),
    ignore_reason TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, project_id, host_id, fingerprint),
    UNIQUE (tenant_id, project_id, candidate_id),
    FOREIGN KEY (tenant_id, project_id, host_id, agent_id)
        REFERENCES managed_hosts (tenant_id, project_id, host_id, agent_id)
);

CREATE INDEX discovery_candidates_scope_page_idx
    ON discovery_candidates (tenant_id, project_id, candidate_id);
CREATE INDEX discovery_candidates_scope_filter_page_idx
    ON discovery_candidates (tenant_id, project_id, host_id, status, discovery_source, database_family, candidate_id);

COMMIT;
