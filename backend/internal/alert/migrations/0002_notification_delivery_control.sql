BEGIN;

ALTER TABLE notification_policies
    ADD COLUMN template_id TEXT,
    ADD COLUMN severities TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN match_labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN window_start_utc TIME,
    ADD COLUMN window_end_utc TIME;

ALTER TABLE notification_templates
    ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0);

-- The pre-0002 adapter resolved a template by the policy ID inside the same
-- tenant/project. Preserve that relationship when it is unambiguous.
UPDATE notification_policies AS policy
SET template_id = template.id
FROM notification_templates AS template
WHERE template.tenant_id = policy.tenant_id
  AND template.project_id = policy.project_id
  AND template.id = policy.id;

-- A legacy policy without that scoped template was never safely renderable.
-- Disable it explicitly and leave an immutable, secret-free migration audit.
WITH disabled AS (
    UPDATE notification_policies
    SET enabled = FALSE, updated_at = NOW()
    WHERE template_id IS NULL
    RETURNING id, tenant_id, project_id, channel, updated_at
)
INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details)
SELECT 'audit-' || substr(md5(tenant_id || ':' || project_id || ':' || id || ':0002-policy-disabled'), 1, 24),
       tenant_id, project_id, 'dbpilot-schema-migration', 'policy.updated', id, updated_at,
       jsonb_build_object('enabled', 'false')
FROM disabled;

ALTER TABLE notification_policies
    ADD CONSTRAINT notification_policies_scoped_template_fk
        FOREIGN KEY (tenant_id, project_id, template_id)
        REFERENCES notification_templates (tenant_id, project_id, id)
        NOT VALID,
    ADD CONSTRAINT notification_policies_enabled_template_check
        CHECK (NOT enabled OR template_id IS NOT NULL) NOT VALID,
    ADD CONSTRAINT notification_policies_window_pair_check
        CHECK ((window_start_utc IS NULL) = (window_end_utc IS NULL)) NOT VALID,
    ADD CONSTRAINT notification_policies_severity_check
        CHECK (severities <@ ARRAY['info', 'warning', 'critical']::TEXT[]) NOT VALID,
    ADD CONSTRAINT notification_policies_match_labels_object_check
        CHECK (jsonb_typeof(match_labels) = 'object') NOT VALID;

ALTER TABLE alert_silences
    ADD COLUMN reason TEXT,
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- 0001 did not store a reason. This fixed migration reason is intentionally
-- non-secret and says exactly what information was unavailable.
UPDATE alert_silences
SET reason = 'migrated legacy silence; original reason was not recorded',
    updated_at = created_at;

ALTER TABLE alert_silences
    ALTER COLUMN reason SET NOT NULL,
    ADD CONSTRAINT alert_silences_reason_check CHECK (btrim(reason) <> '') NOT VALID;

CREATE FUNCTION pg_temp.dbpilot_try_jsonb(value TEXT) RETURNS JSONB
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN value::jsonb;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

CREATE FUNCTION pg_temp.dbpilot_try_integer(value TEXT) RETURNS INTEGER
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN value::integer;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

CREATE FUNCTION pg_temp.dbpilot_try_timestamptz(value TEXT) RETURNS TIMESTAMPTZ
LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN value::timestamptz;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

ALTER TABLE notification_deliveries
    ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN event_state TEXT NOT NULL DEFAULT '',
    ADD COLUMN channel TEXT NOT NULL DEFAULT '',
    ADD COLUMN template_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN template_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN next_attempt_at TIMESTAMPTZ,
    ADD COLUMN lease_owner TEXT NOT NULL DEFAULT '',
    ADD COLUMN lease_expires_at TIMESTAMPTZ,
    ADD COLUMN failure_class TEXT NOT NULL DEFAULT '',
    ADD COLUMN request_target TEXT NOT NULL DEFAULT '',
    ADD COLUMN request_subject TEXT NOT NULL DEFAULT '',
    ADD COLUMN request_body TEXT NOT NULL DEFAULT '',
    ADD COLUMN request_labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN request_secret_ref TEXT NOT NULL DEFAULT '',
    ADD COLUMN _legacy_envelope JSONB,
    ADD COLUMN _legacy_recoverable BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE notification_deliveries
SET _legacy_envelope = pg_temp.dbpilot_try_jsonb(failure_reason),
    idempotency_key = id;

UPDATE notification_deliveries
SET _legacy_recoverable = TRUE
WHERE jsonb_typeof(_legacy_envelope) = 'object'
  AND jsonb_typeof(_legacy_envelope -> 'request') = 'object'
  AND pg_temp.dbpilot_try_integer(_legacy_envelope ->> 'attempts') >= 1
  AND _legacy_envelope #>> '{request,scope,tenant_id}' = tenant_id
  AND _legacy_envelope #>> '{request,scope,project_id}' = project_id
  AND _legacy_envelope #>> '{request,event_id}' = event_id
  AND _legacy_envelope #>> '{request,policy_id}' = policy_id
  AND _legacy_envelope #>> '{request,state}' IN ('pending', 'firing', 'acknowledged', 'resolved')
  AND btrim(COALESCE(_legacy_envelope #>> '{request,channel}', '')) <> ''
  AND btrim(COALESCE(_legacy_envelope #>> '{request,template_id}', '')) <> ''
  AND btrim(COALESCE(_legacy_envelope #>> '{request,template_version}', '')) <> ''
  AND jsonb_typeof(COALESCE(_legacy_envelope #> '{request,labels}', '{}'::jsonb)) = 'object'
  AND COALESCE(_legacy_envelope ->> 'failure_class', '') ~ '^[a-z0-9_-]{0,64}$'
  AND (status <> 'retry_scheduled' OR pg_temp.dbpilot_try_timestamptz(_legacy_envelope ->> 'next_attempt_at') IS NOT NULL);

UPDATE notification_deliveries
SET event_state = _legacy_envelope #>> '{request,state}',
    channel = _legacy_envelope #>> '{request,channel}',
    template_id = _legacy_envelope #>> '{request,template_id}',
    template_version = _legacy_envelope #>> '{request,template_version}',
    attempts = pg_temp.dbpilot_try_integer(_legacy_envelope ->> 'attempts'),
    next_attempt_at = CASE WHEN status = 'retry_scheduled'
        THEN pg_temp.dbpilot_try_timestamptz(_legacy_envelope ->> 'next_attempt_at') END,
    lease_owner = CASE WHEN status = 'attempting' THEN 'dbpilot-schema-migration' ELSE '' END,
    lease_expires_at = CASE WHEN status = 'attempting' THEN NOW() - INTERVAL '1 second' END,
    failure_class = CASE WHEN status IN ('delivered', 'suppressed') THEN ''
        ELSE COALESCE(_legacy_envelope ->> 'failure_class', '') END,
    request_target = COALESCE(_legacy_envelope #>> '{request,target}', ''),
    request_subject = COALESCE(_legacy_envelope #>> '{request,subject}', ''),
    request_body = COALESCE(_legacy_envelope #>> '{request,body}', ''),
    request_labels = COALESCE(_legacy_envelope #> '{request,labels}', '{}'::jsonb),
    request_secret_ref = COALESCE(_legacy_envelope #>> '{request,secret_ref}', '')
WHERE _legacy_recoverable;

-- Preserve terminal history even if an old envelope is corrupt. In-flight
-- rows that cannot be reconstructed are abandoned with a transactional audit.
UPDATE notification_deliveries AS delivery
SET event_state = COALESCE((SELECT event.state FROM alert_events AS event
        WHERE event.tenant_id = delivery.tenant_id AND event.project_id = delivery.project_id AND event.id = delivery.event_id), 'firing'),
    channel = COALESCE((SELECT policy.channel FROM notification_policies AS policy
        WHERE policy.tenant_id = delivery.tenant_id AND policy.project_id = delivery.project_id AND policy.id = delivery.policy_id), ''),
    template_id = COALESCE((SELECT policy.template_id FROM notification_policies AS policy
        WHERE policy.tenant_id = delivery.tenant_id AND policy.project_id = delivery.project_id AND policy.id = delivery.policy_id), ''),
    template_version = COALESCE((SELECT template.revision::text
        FROM notification_policies AS policy
        JOIN notification_templates AS template
          ON template.tenant_id = policy.tenant_id AND template.project_id = policy.project_id AND template.id = policy.template_id
        WHERE policy.tenant_id = delivery.tenant_id AND policy.project_id = delivery.project_id AND policy.id = delivery.policy_id), 'legacy-unavailable'),
    attempts = GREATEST(COALESCE(pg_temp.dbpilot_try_integer(delivery._legacy_envelope ->> 'attempts'), 1), 1),
    request_target = COALESCE((SELECT policy.target FROM notification_policies AS policy
        WHERE policy.tenant_id = delivery.tenant_id AND policy.project_id = delivery.project_id AND policy.id = delivery.policy_id), ''),
    request_labels = '{}',
    request_secret_ref = COALESCE((SELECT policy.secret_ref FROM notification_policies AS policy
        WHERE policy.tenant_id = delivery.tenant_id AND policy.project_id = delivery.project_id AND policy.id = delivery.policy_id), ''),
    failure_class = CASE WHEN delivery.status IN ('delivered', 'suppressed') THEN '' ELSE delivery.failure_class END
WHERE NOT delivery._legacy_recoverable;

-- Rows can predate their event/policy through manual legacy imports. Keep
-- constraints valid without inventing a successful external delivery.
UPDATE notification_deliveries
SET event_state = CASE WHEN event_state IN ('pending', 'firing', 'acknowledged', 'resolved') THEN event_state ELSE 'firing' END,
    attempts = GREATEST(attempts, 1),
    template_version = CASE WHEN template_version = '' THEN 'legacy-unavailable' ELSE template_version END,
    request_labels = CASE WHEN jsonb_typeof(request_labels) = 'object' THEN request_labels ELSE '{}'::jsonb END
WHERE NOT _legacy_recoverable;

WITH abandoned AS (
    UPDATE notification_deliveries
    SET status = 'abandoned',
        next_attempt_at = NULL,
        lease_owner = '',
        lease_expires_at = NULL,
        failure_class = 'legacy_delivery_unrecoverable'
    WHERE NOT _legacy_recoverable AND status IN ('attempting', 'retry_scheduled')
    RETURNING id, tenant_id, project_id, channel, attempts
)
INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details)
SELECT 'audit-' || substr(md5(tenant_id || ':' || project_id || ':' || id || ':0002-delivery-abandoned'), 1, 24),
       tenant_id, project_id, 'dbpilot-schema-migration', 'delivery.abandoned', id, NOW(),
       jsonb_build_object('status', 'abandoned', 'channel', 'legacy',
                          'attempt', attempts::text, 'failure_class', 'legacy_delivery_unrecoverable')
FROM abandoned;

ALTER TABLE notification_deliveries
    DROP COLUMN failure_reason,
    DROP COLUMN _legacy_envelope,
    DROP COLUMN _legacy_recoverable,
    ADD CONSTRAINT notification_deliveries_attempts_check CHECK (attempts >= 1) NOT VALID,
    ADD CONSTRAINT notification_deliveries_event_state_check CHECK (event_state IN ('pending', 'firing', 'acknowledged', 'resolved')) NOT VALID,
    ADD CONSTRAINT notification_deliveries_status_check CHECK (status IN ('attempting', 'delivered', 'suppressed', 'retry_scheduled', 'abandoned')) NOT VALID,
    ADD CONSTRAINT notification_deliveries_failure_class_check CHECK (failure_class ~ '^[a-z0-9_-]{0,64}$') NOT VALID,
    ADD CONSTRAINT notification_deliveries_request_labels_object_check CHECK (jsonb_typeof(request_labels) = 'object') NOT VALID,
    ADD CONSTRAINT notification_deliveries_attempting_lease_check CHECK (status <> 'attempting' OR (btrim(lease_owner) <> '' AND lease_expires_at IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT notification_deliveries_retry_due_check CHECK (status <> 'retry_scheduled' OR next_attempt_at IS NOT NULL) NOT VALID;

CREATE UNIQUE INDEX notification_deliveries_scope_idempotency_idx
    ON notification_deliveries (tenant_id, project_id, idempotency_key);
CREATE INDEX notification_deliveries_due_idx
    ON notification_deliveries (status, next_attempt_at, lease_expires_at);

CREATE TABLE in_app_notifications (
    id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_state TEXT NOT NULL,
    recipient TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    read_at TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, project_id, id),
    UNIQUE (tenant_id, project_id, delivery_id, recipient)
);
CREATE INDEX in_app_notifications_scope_recipient_created_idx
    ON in_app_notifications (tenant_id, project_id, recipient, created_at DESC);

ALTER TABLE notification_policies VALIDATE CONSTRAINT notification_policies_scoped_template_fk;
ALTER TABLE notification_policies VALIDATE CONSTRAINT notification_policies_enabled_template_check;
ALTER TABLE notification_policies VALIDATE CONSTRAINT notification_policies_window_pair_check;
ALTER TABLE notification_policies VALIDATE CONSTRAINT notification_policies_severity_check;
ALTER TABLE notification_policies VALIDATE CONSTRAINT notification_policies_match_labels_object_check;
ALTER TABLE alert_silences VALIDATE CONSTRAINT alert_silences_reason_check;
ALTER TABLE notification_deliveries VALIDATE CONSTRAINT notification_deliveries_attempts_check;
ALTER TABLE notification_deliveries VALIDATE CONSTRAINT notification_deliveries_event_state_check;
ALTER TABLE notification_deliveries VALIDATE CONSTRAINT notification_deliveries_status_check;
ALTER TABLE notification_deliveries VALIDATE CONSTRAINT notification_deliveries_failure_class_check;
ALTER TABLE notification_deliveries VALIDATE CONSTRAINT notification_deliveries_request_labels_object_check;
ALTER TABLE notification_deliveries VALIDATE CONSTRAINT notification_deliveries_attempting_lease_check;
ALTER TABLE notification_deliveries VALIDATE CONSTRAINT notification_deliveries_retry_due_check;

COMMIT;
