BEGIN;

CREATE TABLE metric_templates (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    database_family TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    builtin BOOLEAN NOT NULL DEFAULT FALSE,
    latest_revision BIGINT NOT NULL DEFAULT 0 CHECK (latest_revision >= 0),
    published_revision BIGINT,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,project_id,template_id),
    CHECK (published_revision IS NULL OR published_revision BETWEEN 1 AND latest_revision)
);

CREATE INDEX metric_templates_scope_cursor_idx
    ON metric_templates (tenant_id,project_id,template_id);

CREATE TABLE metric_template_revisions (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision >= 1),
    database_family TEXT NOT NULL,
    variants JSONB NOT NULL CHECK (jsonb_typeof(variants)='array' AND jsonb_array_length(variants) BETWEEN 1 AND 16),
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    query_kind TEXT NOT NULL CHECK (query_kind='sql'),
    read_only_statement TEXT NOT NULL CHECK (octet_length(read_only_statement) BETWEEN 1 AND 32768),
    collection_interval_seconds INTEGER NOT NULL CHECK (collection_interval_seconds BETWEEN 10 AND 86400),
    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 30),
    max_rows INTEGER NOT NULL CHECK (max_rows BETWEEN 1 AND 100),
    max_columns INTEGER NOT NULL CHECK (max_columns BETWEEN 1 AND 32),
    value_mappings JSONB NOT NULL CHECK (jsonb_typeof(value_mappings)='array' AND jsonb_array_length(value_mappings) BETWEEN 1 AND 32),
    label_mappings JSONB NOT NULL CHECK (jsonb_typeof(label_mappings)='array' AND jsonb_array_length(label_mappings) <= 16),
    database_version_range TEXT NOT NULL DEFAULT '',
    plugin_version_range TEXT NOT NULL DEFAULT '',
    cardinality_limit INTEGER NOT NULL CHECK (cardinality_limit BETWEEN 1 AND 10000),
    query_digest TEXT NOT NULL CHECK (query_digest ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL CHECK (status IN ('draft','validating','validated','validation_failed','trial_running','trial_passed','trial_failed','approval_pending','approved','rejected','published','superseded')),
    created_by TEXT NOT NULL,
    approved_by TEXT NOT NULL DEFAULT '',
    resource_revision BIGINT NOT NULL CHECK (resource_revision >= 1),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,project_id,revision_id),
    UNIQUE (tenant_id,project_id,template_id,revision),
    FOREIGN KEY (tenant_id,project_id,template_id) REFERENCES metric_templates (tenant_id,project_id,template_id),
    CHECK ((status IN ('approved','published','superseded')) = (approved_by <> ''))
);

CREATE INDEX metric_template_revisions_scope_cursor_idx
    ON metric_template_revisions (tenant_id,project_id,template_id,revision DESC,revision_id DESC);
CREATE INDEX metric_template_revisions_digest_idx
    ON metric_template_revisions (tenant_id,project_id,revision_id,query_digest);

CREATE OR REPLACE FUNCTION dbpilot_guard_metric_template_revision()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'metric template revisions are immutable' USING ERRCODE='55000';
    END IF;
    IF NEW.tenant_id<>OLD.tenant_id OR NEW.project_id<>OLD.project_id OR NEW.revision_id<>OLD.revision_id
       OR NEW.template_id<>OLD.template_id OR NEW.revision<>OLD.revision OR NEW.database_family<>OLD.database_family
       OR NEW.variants<>OLD.variants OR NEW.name<>OLD.name OR NEW.description<>OLD.description
       OR NEW.query_kind<>OLD.query_kind OR NEW.read_only_statement<>OLD.read_only_statement
       OR NEW.collection_interval_seconds<>OLD.collection_interval_seconds OR NEW.timeout_seconds<>OLD.timeout_seconds
       OR NEW.max_rows<>OLD.max_rows OR NEW.max_columns<>OLD.max_columns OR NEW.value_mappings<>OLD.value_mappings
       OR NEW.label_mappings<>OLD.label_mappings OR NEW.database_version_range<>OLD.database_version_range
       OR NEW.plugin_version_range<>OLD.plugin_version_range OR NEW.cardinality_limit<>OLD.cardinality_limit
       OR NEW.query_digest<>OLD.query_digest OR NEW.created_by<>OLD.created_by OR NEW.created_at<>OLD.created_at
       OR NEW.resource_revision<>OLD.resource_revision+1 OR NEW.updated_at<OLD.updated_at THEN
        RAISE EXCEPTION 'metric template revision immutable fields cannot change' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER metric_template_revisions_immutable
    BEFORE UPDATE OR DELETE ON metric_template_revisions
    FOR EACH ROW EXECUTE FUNCTION dbpilot_guard_metric_template_revision();

CREATE TABLE metric_template_trials (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    revision_id TEXT NOT NULL,
    query_digest TEXT NOT NULL CHECK (query_digest ~ '^[0-9a-f]{64}$'),
    instance_id TEXT NOT NULL,
    assignment_id TEXT NOT NULL,
    plugin_version_id TEXT NOT NULL,
    configuration_revision BIGINT NOT NULL CHECK (configuration_revision >= 1),
    operation_revision BIGINT NOT NULL CHECK (operation_revision >= 1),
    timeout_seconds INTEGER NOT NULL CHECK (timeout_seconds BETWEEN 1 AND 30),
    max_rows INTEGER NOT NULL CHECK (max_rows BETWEEN 1 AND 100),
    max_columns INTEGER NOT NULL CHECK (max_columns BETWEEN 1 AND 32),
    cardinality_limit INTEGER NOT NULL CHECK (cardinality_limit BETWEEN 1 AND 10000),
    status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed')),
    status_code TEXT NOT NULL DEFAULT '',
    candidate_metrics JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(candidate_metrics)='array' AND jsonb_array_length(candidate_metrics)<=3200),
    row_count INTEGER NOT NULL DEFAULT 0 CHECK (row_count BETWEEN 0 AND 100),
    column_count INTEGER NOT NULL DEFAULT 0 CHECK (column_count BETWEEN 0 AND 32),
    metric_count INTEGER NOT NULL DEFAULT 0 CHECK (metric_count BETWEEN 0 AND 3200),
    duration_millis BIGINT NOT NULL DEFAULT 0 CHECK (duration_millis BETWEEN 0 AND 30000),
    created_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id,project_id,job_id),
    UNIQUE (tenant_id,project_id,command_id),
    FOREIGN KEY (tenant_id,project_id,revision_id) REFERENCES metric_template_revisions (tenant_id,project_id,revision_id),
    FOREIGN KEY (tenant_id,project_id,job_id) REFERENCES jobs (tenant_id,project_id,id),
    FOREIGN KEY (tenant_id,project_id,assignment_id) REFERENCES plugin_assignments (tenant_id,project_id,assignment_id),
    CHECK ((status='running')=(completed_at IS NULL))
);

CREATE UNIQUE INDEX metric_template_trials_one_running_revision_idx
    ON metric_template_trials (tenant_id,project_id,revision_id)
    WHERE status='running';

CREATE TABLE metric_template_publications (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    publication_revision BIGINT NOT NULL CHECK (publication_revision >= 1),
    selected_revision_id TEXT NOT NULL,
    query_digest TEXT NOT NULL CHECK (query_digest ~ '^[0-9a-f]{64}$'),
    rollback BOOLEAN NOT NULL DEFAULT FALSE,
    instance_count INTEGER NOT NULL CHECK (instance_count BETWEEN 0 AND 128),
    assignment_count INTEGER NOT NULL CHECK (assignment_count BETWEEN 0 AND 128),
    published_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,project_id,template_id,publication_revision),
    FOREIGN KEY (tenant_id,project_id,template_id) REFERENCES metric_templates (tenant_id,project_id,template_id),
    FOREIGN KEY (tenant_id,project_id,selected_revision_id) REFERENCES metric_template_revisions (tenant_id,project_id,revision_id)
);

CREATE TABLE metric_template_mutations (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL CHECK (request_fingerprint ~ '^sha256:[0-9a-f]{64}$'),
    action TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_kind TEXT NOT NULL CHECK (response_kind IN ('template','revision','job')),
    response_snapshot JSONB NOT NULL CHECK (jsonb_typeof(response_snapshot)='object'),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id,project_id,actor_id,operation_id,idempotency_key)
);

CREATE OR REPLACE FUNCTION dbpilot_guard_published_template_ids()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE item TEXT;
BEGIN
    FOR item IN SELECT jsonb_array_elements_text(NEW.template_revision_ids) LOOP
        IF NOT EXISTS (
            SELECT 1 FROM metric_template_revisions revision
            WHERE revision.tenant_id=NEW.tenant_id AND revision.project_id=NEW.project_id
              AND revision.revision_id=item AND revision.status IN ('published','superseded')
              AND (EXISTS (
                  SELECT 1 FROM metric_template_publications publication
                  WHERE publication.tenant_id=revision.tenant_id AND publication.project_id=revision.project_id
                    AND publication.selected_revision_id=revision.revision_id
              ) OR EXISTS (
                  SELECT 1 FROM metric_templates template
                  WHERE template.tenant_id=revision.tenant_id AND template.project_id=revision.project_id
                    AND template.template_id=revision.template_id AND template.published_revision=revision.revision
              ))
        ) THEN
            RAISE EXCEPTION 'unpublished metric template revision' USING ERRCODE='23514';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER plugin_assignment_instances_published_templates
    BEFORE INSERT OR UPDATE OF template_revision_ids ON plugin_assignment_instances
    FOR EACH ROW EXECUTE FUNCTION dbpilot_guard_published_template_ids();
CREATE TRIGGER plugin_assignments_published_templates
    BEFORE INSERT OR UPDATE OF template_revision_ids ON plugin_assignments
    FOR EACH ROW EXECUTE FUNCTION dbpilot_guard_published_template_ids();

COMMIT;
