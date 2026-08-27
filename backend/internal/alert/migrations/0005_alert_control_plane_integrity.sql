BEGIN;

-- Cadence is persisted independently from the metric lookback window. Existing
-- rows retain their previous behavior by backfilling lookback from cadence.
ALTER TABLE alert_rules
    ADD COLUMN lookback_window_ns BIGINT,
    ADD COLUMN next_evaluation_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN last_evaluated_at TIMESTAMPTZ,
    ADD COLUMN evaluation_lease_owner TEXT NOT NULL DEFAULT '',
    ADD COLUMN evaluation_lease_expires_at TIMESTAMPTZ;

UPDATE alert_rules
SET lookback_window_ns = evaluation_every_ns
WHERE lookback_window_ns IS NULL;

ALTER TABLE alert_rules
    ALTER COLUMN lookback_window_ns SET NOT NULL,
    ADD CONSTRAINT alert_rules_lookback_window_check
        CHECK (lookback_window_ns > 0) NOT VALID,
    ADD CONSTRAINT alert_rules_evaluation_lease_check
        CHECK ((evaluation_lease_owner = '') = (evaluation_lease_expires_at IS NULL)) NOT VALID;

CREATE INDEX alert_rules_due_evaluation_idx
    ON alert_rules (tenant_id, project_id, next_evaluation_at, id)
    WHERE enabled;

ALTER TABLE alert_rules VALIDATE CONSTRAINT alert_rules_lookback_window_check;
ALTER TABLE alert_rules VALIDATE CONSTRAINT alert_rules_evaluation_lease_check;

-- New events must always have a live scoped rule. NOT VALID intentionally
-- preserves inspectable pre-migration orphan history; the dispatcher records
-- such rows as abandoned instead of making readiness fail forever.
ALTER TABLE alert_events
    ADD CONSTRAINT alert_events_scoped_rule_fk
        FOREIGN KEY (tenant_id, project_id, rule_id)
        REFERENCES alert_rules (tenant_id, project_id, id)
        NOT VALID;

-- Enforce the same opaque production secret-reference grammar at the storage
-- boundary while permitting legacy rows to remain readable during migration.
WITH scrubbed AS (
    UPDATE notification_policies
    SET enabled = FALSE, secret_ref = '', updated_at = NOW()
    WHERE (channel = 'in_app' AND secret_ref <> '')
       OR (channel IN ('smtp', 'webhook') AND secret_ref !~ '^env://[A-Za-z_][A-Za-z0-9_]*$')
    RETURNING id, tenant_id, project_id, updated_at
)
INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details)
SELECT 'audit-' || substr(md5(tenant_id || ':' || project_id || ':' || id || ':0005-secret-scrub'), 1, 24),
       tenant_id, project_id, 'dbpilot-schema-migration', 'policy.updated', id, updated_at,
       jsonb_build_object('enabled', 'false')
FROM scrubbed
ON CONFLICT (tenant_id, project_id, id) DO NOTHING;

ALTER TABLE notification_policies
    ADD CONSTRAINT notification_policies_channel_check
        CHECK (channel IN ('in_app', 'smtp', 'webhook')) NOT VALID,
    ADD CONSTRAINT notification_policies_secret_reference_check
        CHECK (
            (channel = 'in_app' AND secret_ref = '') OR
            (channel IN ('smtp', 'webhook') AND
                (secret_ref ~ '^env://[A-Za-z_][A-Za-z0-9_]*$' OR (NOT enabled AND secret_ref = '')))
        ) NOT VALID;

UPDATE notification_deliveries
SET request_secret_ref = CASE
        WHEN channel = 'in_app' THEN ''
        ELSE 'env://DBPILOT_MIGRATED_UNAVAILABLE_SECRET'
    END
WHERE (channel = 'in_app' AND request_secret_ref <> '')
   OR (channel IN ('smtp', 'webhook') AND request_secret_ref !~ '^env://[A-Za-z_][A-Za-z0-9_]*$');

ALTER TABLE notification_deliveries
    ADD CONSTRAINT notification_deliveries_channel_check
        CHECK (channel IN ('in_app', 'smtp', 'webhook')) NOT VALID,
    ADD CONSTRAINT notification_deliveries_secret_reference_check
        CHECK (
            (channel = 'in_app' AND request_secret_ref = '') OR
            (channel IN ('smtp', 'webhook') AND request_secret_ref ~ '^env://[A-Za-z_][A-Za-z0-9_]*$')
        ) NOT VALID;

-- This non-unique route identity index supports v1 idempotency lookups while
-- v2 keys include policy/config identity and remain uniquely constrained.
CREATE INDEX notification_deliveries_legacy_route_identity_idx
    ON notification_deliveries (
        tenant_id, project_id, event_id, policy_id, event_state, channel,
        template_id, template_version, request_target, request_secret_ref
    );

CREATE TABLE alert_event_dispositions (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('acknowledgement', 'resolution', 'root_cause')),
    category TEXT NOT NULL CHECK (category ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,127}$'),
    reason TEXT NOT NULL CHECK (btrim(reason) <> '' AND length(reason) <= 1024),
    actor TEXT NOT NULL CHECK (btrim(actor) <> ''),
    occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, project_id, id),
    CONSTRAINT alert_event_dispositions_scoped_event_fk
        FOREIGN KEY (tenant_id, project_id, event_id)
        REFERENCES alert_events (tenant_id, project_id, id)
);

CREATE INDEX alert_event_dispositions_scope_event_time_idx
    ON alert_event_dispositions (tenant_id, project_id, event_id, occurred_at DESC, id DESC);

CREATE FUNCTION dbpilot_reject_event_disposition_mutation() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'alert event dispositions are append-only';
END;
$$;

CREATE TRIGGER alert_event_dispositions_append_only
    BEFORE UPDATE OR DELETE ON alert_event_dispositions
    FOR EACH ROW EXECUTE FUNCTION dbpilot_reject_event_disposition_mutation();

COMMIT;
