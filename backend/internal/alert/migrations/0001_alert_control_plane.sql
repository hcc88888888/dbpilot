BEGIN;

CREATE TABLE alert_rules (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    metric TEXT NOT NULL,
    aggregation TEXT NOT NULL,
    operator TEXT NOT NULL,
    threshold DOUBLE PRECISION NOT NULL,
    evaluation_every_ns BIGINT NOT NULL CHECK (evaluation_every_ns > 0),
    for_duration_ns BIGINT NOT NULL CHECK (for_duration_ns > 0),
    missing_data TEXT NOT NULL,
    severity TEXT NOT NULL,
    notification_policy_ids TEXT[] NOT NULL DEFAULT '{}',
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, project_id, id)
);
CREATE INDEX alert_rules_scope_created_idx ON alert_rules (tenant_id, project_id, created_at DESC);

CREATE TABLE alert_events (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    state TEXT NOT NULL CHECK (state IN ('pending', 'firing', 'acknowledged', 'resolved')),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    firing_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    last_actor TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, project_id, id),
    UNIQUE (tenant_id, project_id, fingerprint)
);
CREATE INDEX alert_events_scope_state_last_seen_idx ON alert_events (tenant_id, project_id, state, last_seen DESC);

CREATE TABLE notification_policies (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    channel TEXT NOT NULL,
    target TEXT NOT NULL,
    secret_ref TEXT NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, project_id, id)
);
CREATE INDEX notification_policies_scope_name_idx ON notification_policies (tenant_id, project_id, name);

CREATE TABLE notification_templates (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, project_id, id)
);
CREATE INDEX notification_templates_scope_name_idx ON notification_templates (tenant_id, project_id, name);

CREATE TABLE alert_silences (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    matchers JSONB NOT NULL DEFAULT '{}'::jsonb,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, project_id, id)
);
CREATE INDEX alert_silences_scope_window_idx ON alert_silences (tenant_id, project_id, starts_at, ends_at);

CREATE TABLE notification_deliveries (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    status TEXT NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    failure_reason TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (tenant_id, project_id, id)
);
CREATE INDEX notification_deliveries_scope_event_idx ON notification_deliveries (tenant_id, project_id, event_id, attempted_at DESC);

CREATE TABLE alert_audit_log (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, project_id, id)
);
CREATE INDEX alert_audit_log_scope_occurred_idx ON alert_audit_log (tenant_id, project_id, occurred_at DESC);

CREATE TABLE metric_samples (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    series_fingerprint TEXT NOT NULL,
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    value DOUBLE PRECISION NOT NULL,
    sampled_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, agent_id, metric, series_fingerprint, sampled_at)
) PARTITION BY RANGE (sampled_at);

DO $$
DECLARE
    partition_day DATE;
    partition_name TEXT;
    day_offset INTEGER;
BEGIN
    FOR day_offset IN 0..6 LOOP
        partition_day := CURRENT_DATE + day_offset;
        partition_name := format('metric_samples_%s', to_char(partition_day, 'YYYYMMDD'));
        EXECUTE format(
            'CREATE TABLE IF NOT EXISTS %I PARTITION OF metric_samples FOR VALUES FROM (%L) TO (%L)',
            partition_name,
            partition_day,
            partition_day + 1
        );
    END LOOP;
END $$;

COMMIT;
