BEGIN;

CREATE TABLE plugin_definitions (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    name TEXT NOT NULL,
    database_family TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    supported_variants JSONB NOT NULL,
    capabilities JSONB NOT NULL,
    latest_available_version TEXT,
    PRIMARY KEY (tenant_id, project_id, plugin_id),
    CHECK (jsonb_typeof(supported_variants) = 'array'),
    CHECK (jsonb_typeof(capabilities) = 'array')
);

CREATE TABLE plugin_versions (
    version_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    plugin_id TEXT NOT NULL,
    semantic_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('uploaded', 'verified', 'approved', 'available', 'deprecated', 'revoked', 'rejected')),
    artifact_id TEXT NOT NULL,
    package_sha256 TEXT NOT NULL CHECK (package_sha256 ~ '^[0-9a-f]{64}$'),
    manifest_digest TEXT NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    publisher_id TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    minimum_agent_protocol_version TEXT NOT NULL,
    maximum_agent_protocol_version TEXT NOT NULL,
    supported_variants JSONB NOT NULL,
    database_version_range TEXT NOT NULL,
    capabilities JSONB NOT NULL,
    metric_template_schema_version INTEGER NOT NULL CHECK (metric_template_schema_version BETWEEN 1 AND 65535),
    platforms JSONB NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    revocation_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, project_id, version_id),
    UNIQUE (tenant_id, project_id, plugin_id, semantic_version),
    FOREIGN KEY (tenant_id, project_id, plugin_id) REFERENCES plugin_definitions (tenant_id, project_id, plugin_id),
    FOREIGN KEY (tenant_id, project_id, artifact_id) REFERENCES artifacts (tenant_id, project_id, id),
    CHECK (jsonb_typeof(supported_variants) = 'array'),
    CHECK (jsonb_typeof(capabilities) = 'array'),
    CHECK (jsonb_typeof(platforms) = 'array')
);

CREATE INDEX plugin_versions_scope_cursor_idx
    ON plugin_versions (tenant_id, project_id, created_at DESC, version_id DESC);
CREATE INDEX plugin_versions_scope_plugin_idx
    ON plugin_versions (tenant_id, project_id, plugin_id, status, created_at DESC);

CREATE OR REPLACE FUNCTION dbpilot_guard_plugin_version_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'plugin_versions history is immutable' USING ERRCODE = '55000';
    END IF;
    IF NEW.version_id <> OLD.version_id
       OR NEW.tenant_id <> OLD.tenant_id
       OR NEW.project_id <> OLD.project_id
       OR NEW.plugin_id <> OLD.plugin_id
       OR NEW.semantic_version <> OLD.semantic_version
       OR NEW.artifact_id <> OLD.artifact_id
       OR NEW.package_sha256 <> OLD.package_sha256
       OR NEW.manifest_digest <> OLD.manifest_digest
       OR NEW.publisher_id <> OLD.publisher_id
       OR NEW.signing_key_id <> OLD.signing_key_id
       OR NEW.protocol_version <> OLD.protocol_version
       OR NEW.minimum_agent_protocol_version <> OLD.minimum_agent_protocol_version
       OR NEW.maximum_agent_protocol_version <> OLD.maximum_agent_protocol_version
       OR NEW.supported_variants <> OLD.supported_variants
       OR NEW.database_version_range <> OLD.database_version_range
       OR NEW.capabilities <> OLD.capabilities
       OR NEW.metric_template_schema_version <> OLD.metric_template_schema_version
       OR NEW.platforms <> OLD.platforms
       OR NEW.created_at <> OLD.created_at
       OR NEW.revision <> OLD.revision + 1 THEN
        RAISE EXCEPTION 'plugin version immutable fields cannot change' USING ERRCODE = '55000';
    END IF;
    IF NOT ((OLD.status = 'verified' AND NEW.status IN ('approved', 'revoked'))
         OR (OLD.status = 'approved' AND NEW.status IN ('available', 'revoked'))
         OR (OLD.status = 'available' AND NEW.status IN ('deprecated', 'revoked'))
         OR (OLD.status = 'deprecated' AND NEW.status = 'revoked')) THEN
        RAISE EXCEPTION 'invalid plugin version lifecycle transition' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS plugin_versions_immutable ON plugin_versions;
CREATE TRIGGER plugin_versions_immutable
    BEFORE UPDATE OR DELETE ON plugin_versions
    FOR EACH ROW EXECUTE FUNCTION dbpilot_guard_plugin_version_mutation();

COMMIT;
