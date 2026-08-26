BEGIN;

ALTER TABLE notification_policies
    ADD COLUMN template_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN severities TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN match_labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN window_start_utc TIME,
    ADD COLUMN window_end_utc TIME;

ALTER TABLE notification_templates
    ADD COLUMN revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0);

ALTER TABLE notification_policies
    ADD CONSTRAINT notification_policies_scoped_template_fk
    FOREIGN KEY (tenant_id, project_id, template_id)
    REFERENCES notification_templates (tenant_id, project_id, id)
    NOT VALID;

ALTER TABLE alert_silences
    ADD COLUMN reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE notification_policies
    ADD CONSTRAINT notification_policies_window_pair_check CHECK ((window_start_utc IS NULL) = (window_end_utc IS NULL)) NOT VALID,
    ADD CONSTRAINT notification_policies_severity_check CHECK (severities <@ ARRAY['info', 'warning', 'critical']::TEXT[]) NOT VALID,
    ADD CONSTRAINT notification_policies_match_labels_object_check CHECK (jsonb_typeof(match_labels) = 'object') NOT VALID;

ALTER TABLE alert_silences
    ADD CONSTRAINT alert_silences_reason_check CHECK (btrim(reason) <> '') NOT VALID;

ALTER TABLE notification_deliveries
    ADD COLUMN idempotency_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN event_state TEXT NOT NULL DEFAULT '',
    ADD COLUMN channel TEXT NOT NULL DEFAULT '',
    ADD COLUMN template_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN template_version TEXT NOT NULL DEFAULT '',
    ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    ADD COLUMN next_attempt_at TIMESTAMPTZ,
    ADD COLUMN lease_owner TEXT NOT NULL DEFAULT '',
    ADD COLUMN lease_expires_at TIMESTAMPTZ,
    ADD COLUMN failure_class TEXT NOT NULL DEFAULT '',
    ADD COLUMN request_target TEXT NOT NULL DEFAULT '',
    ADD COLUMN request_subject TEXT NOT NULL DEFAULT '',
    ADD COLUMN request_body TEXT NOT NULL DEFAULT '',
    ADD COLUMN request_labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN request_secret_ref TEXT NOT NULL DEFAULT '';

UPDATE notification_deliveries
SET idempotency_key = id,
    failure_class = CASE WHEN failure_reason = '' THEN '' ELSE 'legacy_delivery_failure' END;

UPDATE notification_deliveries
SET status = 'abandoned',
    failure_class = 'legacy_delivery_unrecoverable',
    next_attempt_at = NULL,
    lease_owner = '',
    lease_expires_at = NULL
WHERE status IN ('attempting', 'retry_scheduled');

ALTER TABLE notification_deliveries DROP COLUMN failure_reason;

ALTER TABLE notification_deliveries
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

COMMIT;
