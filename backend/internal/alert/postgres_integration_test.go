package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestNotificationMigrationUpgradesPopulated0001WithoutLosingRoutesOrRetryState(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL notification integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, _ := setupNotificationIntegrationSchemaThrough(t, ctx, dsn, "0001_alert_control_plane.sql")
	scope := Scope{TenantID: "tenant-upgrade", ProjectID: "project-upgrade"}
	attemptedAt := time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)
	nextAttemptAt := attemptedAt.Add(5 * time.Minute)

	_, err := database.ExecContext(ctx, "INSERT INTO notification_templates (id, tenant_id, project_id, name, subject, body) VALUES ('policy-routable', $1, $2, 'legacy same-id', 'subject', 'body')", scope.TenantID, scope.ProjectID)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "INSERT INTO notification_policies (id, tenant_id, project_id, name, channel, target, enabled) VALUES ('policy-routable', $1, $2, 'routable', 'in_app', 'user-7', true), ('policy-no-template', $1, $2, 'missing', 'in_app', 'user-7', true)", scope.TenantID, scope.ProjectID)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "INSERT INTO alert_rules (id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ns, for_duration_ns, missing_data, severity, notification_policy_ids) VALUES ('rule-upgrade', $1, $2, 'upgrade', 'db.cpu', 'avg', '>', 80, 60000000000, 60000000000, 'ignore', 'critical', ARRAY['policy-routable', 'policy-no-template'])", scope.TenantID, scope.ProjectID)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "INSERT INTO alert_silences (id, tenant_id, project_id, matchers, starts_at, ends_at, created_by) VALUES ('silence-legacy', $1, $2, '{\"database\":\"orders\"}', $3, $4, 'operator')", scope.TenantID, scope.ProjectID, attemptedAt, attemptedAt.Add(time.Hour))
	require.NoError(t, err)

	legacyEnvelope := func(status DeliveryStatus, attempts int, next time.Time, failure string) string {
		request := map[string]any{
			"scope":    map[string]string{"tenant_id": scope.TenantID, "project_id": scope.ProjectID},
			"event_id": "event-legacy", "state": "firing", "severity": "critical", "channel": "in_app",
			"policy_id": "policy-routable", "template_id": "policy-routable", "template_version": attemptedAt.Format(time.RFC3339Nano),
			"target": "user-7", "secret_ref": "vault://legacy-reference", "subject": "subject", "body": "body",
			"labels": map[string]string{"database": "orders"},
		}
		envelope := map[string]any{"attempts": attempts, "failure_class": failure, "request": request}
		if !next.IsZero() {
			envelope["next_attempt_at"] = next.Format(time.RFC3339Nano)
		}
		encoded, marshalErr := json.Marshal(envelope)
		require.NoError(t, marshalErr)
		return string(encoded)
	}
	for _, fixture := range []struct {
		id, status, envelope string
		delivered            any
	}{
		{"delivery-delivered", "delivered", legacyEnvelope(DeliveryDelivered, 1, time.Time{}, ""), attemptedAt},
		{"delivery-suppressed", "suppressed", legacyEnvelope(DeliverySuppressed, 1, time.Time{}, ""), nil},
		{"delivery-retry", "retry_scheduled", legacyEnvelope(DeliveryRetryScheduled, 2, nextAttemptAt, "remote_5xx"), nil},
		{"delivery-attempting", "attempting", legacyEnvelope(DeliveryAttempting, 1, time.Time{}, ""), nil},
		{"delivery-malformed", "retry_scheduled", "not-json", nil},
	} {
		_, err = database.ExecContext(ctx, "INSERT INTO notification_deliveries (id, tenant_id, project_id, event_id, policy_id, status, attempted_at, delivered_at, failure_reason) VALUES ($1, $2, $3, 'event-legacy', 'policy-routable', $4, $5, $6, $7)", fixture.id, scope.TenantID, scope.ProjectID, fixture.status, attemptedAt, fixture.delivered, fixture.envelope)
		require.NoError(t, err)
	}

	migration, err := os.ReadFile(filepath.Join("migrations", "0002_notification_delivery_control.sql"))
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, string(migration))
	require.NoError(t, err)
	integrityMigration, err := os.ReadFile(filepath.Join("migrations", "0005_alert_control_plane_integrity.sql"))
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, string(integrityMigration))
	require.NoError(t, err)

	var templateID sql.NullString
	var enabled bool
	require.NoError(t, database.QueryRowContext(ctx, "SELECT template_id, enabled FROM notification_policies WHERE tenant_id = $1 AND project_id = $2 AND id = 'policy-routable'", scope.TenantID, scope.ProjectID).Scan(&templateID, &enabled))
	require.Equal(t, "policy-routable", templateID.String)
	require.True(t, enabled)
	require.NoError(t, database.QueryRowContext(ctx, "SELECT template_id, enabled FROM notification_policies WHERE tenant_id = $1 AND project_id = $2 AND id = 'policy-no-template'", scope.TenantID, scope.ProjectID).Scan(&templateID, &enabled))
	require.False(t, templateID.Valid)
	require.False(t, enabled)
	routes, err := NewPostgresRepository(database).ListNotificationRoutes(ctx, scope, "rule-upgrade")
	require.NoError(t, err)
	require.Len(t, routes, 2)
	require.Equal(t, "policy-no-template", routes[0].Policy.ID)
	require.False(t, routes[0].Policy.Enabled)
	require.Empty(t, routes[0].Policy.TemplateID)

	var reason string
	require.NoError(t, database.QueryRowContext(ctx, "SELECT reason FROM alert_silences WHERE tenant_id = $1 AND project_id = $2 AND id = 'silence-legacy'", scope.TenantID, scope.ProjectID).Scan(&reason))
	require.Equal(t, "migrated legacy silence; original reason was not recorded", reason)

	type migratedDelivery struct {
		status, eventState, channel, templateID, templateVersion, failureClass, target, secretRef string
		attempts                                                                                  int
		nextAttempt, leaseExpiry                                                                  sql.NullTime
	}
	readDelivery := func(id string) migratedDelivery {
		var got migratedDelivery
		require.NoError(t, database.QueryRowContext(ctx, "SELECT status, event_state, channel, template_id, template_version, failure_class, request_target, request_secret_ref, attempts, next_attempt_at, lease_expires_at FROM notification_deliveries WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, id).Scan(&got.status, &got.eventState, &got.channel, &got.templateID, &got.templateVersion, &got.failureClass, &got.target, &got.secretRef, &got.attempts, &got.nextAttempt, &got.leaseExpiry))
		return got
	}
	for _, id := range []string{"delivery-delivered", "delivery-suppressed"} {
		got := readDelivery(id)
		require.Empty(t, got.failureClass, id)
		require.Equal(t, "firing", got.eventState, id)
		require.Equal(t, "policy-routable", got.templateID, id)
	}
	retry := readDelivery("delivery-retry")
	require.Equal(t, "retry_scheduled", retry.status)
	require.Equal(t, 2, retry.attempts)
	require.True(t, retry.nextAttempt.Valid)
	require.True(t, retry.nextAttempt.Time.Equal(nextAttemptAt))
	require.Equal(t, "remote_5xx", retry.failureClass)
	require.Empty(t, retry.secretRef, "unsupported legacy secret material is scrubbed at rest")
	attempting := readDelivery("delivery-attempting")
	require.Equal(t, "attempting", attempting.status)
	require.True(t, attempting.leaseExpiry.Valid)
	require.False(t, attempting.leaseExpiry.Time.After(time.Now().UTC()))
	malformed := readDelivery("delivery-malformed")
	require.Equal(t, "abandoned", malformed.status)
	require.Equal(t, "legacy_delivery_unrecoverable", malformed.failureClass)

	var policyAudit, abandonedAudit int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM alert_audit_log WHERE tenant_id = $1 AND project_id = $2 AND action = 'policy.updated' AND target_id = 'policy-no-template' AND actor = 'dbpilot-schema-migration'", scope.TenantID, scope.ProjectID).Scan(&policyAudit))
	require.Equal(t, 1, policyAudit)
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM alert_audit_log WHERE tenant_id = $1 AND project_id = $2 AND action = 'delivery.abandoned' AND target_id = 'delivery-malformed' AND actor = 'dbpilot-schema-migration'", scope.TenantID, scope.ProjectID).Scan(&abandonedAudit))
	require.Equal(t, 1, abandonedAudit)

	var invalidConstraints int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM pg_constraint WHERE conrelid IN ('notification_policies'::regclass, 'alert_silences'::regclass, 'notification_deliveries'::regclass) AND NOT convalidated").Scan(&invalidConstraints))
	require.Equal(t, 4, invalidConstraints, "forward-only channel and secret checks remain NOT VALID for unknown legacy rows")
}

func TestNotificationMigrationPreservesLegacyTemplateVersionIdempotencyOnReplay(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL notification integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, _ := setupNotificationIntegrationSchemaThrough(t, ctx, dsn, "0001_alert_control_plane.sql")
	scope := Scope{TenantID: "tenant-version", ProjectID: "project-version"}

	var legacyUpdatedAt time.Time
	_, err := database.ExecContext(ctx, "INSERT INTO notification_policies (id, tenant_id, project_id, name, channel, target, enabled) VALUES ('policy-version', $1, $2, 'legacy policy', 'in_app', 'user-7', true)", scope.TenantID, scope.ProjectID)
	require.NoError(t, err)
	require.NoError(t, database.QueryRowContext(ctx, "INSERT INTO notification_templates (id, tenant_id, project_id, name, subject, body) VALUES ('policy-version', $1, $2, 'legacy template', '{{event.id}}', '{{event.state}}') RETURNING updated_at", scope.TenantID, scope.ProjectID).Scan(&legacyUpdatedAt))
	_, err = database.ExecContext(ctx, "INSERT INTO alert_rules (id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ns, for_duration_ns, missing_data, severity, notification_policy_ids) VALUES ('rule-version', $1, $2, 'version replay', 'db.cpu', 'avg', '>', 80, 60000000000, 60000000000, 'ignore', 'critical', ARRAY['policy-version'])", scope.TenantID, scope.ProjectID)
	require.NoError(t, err)

	event := AlertEvent{ID: "event-version", Scope: scope, RuleID: "rule-version", Fingerprint: "version-fingerprint", Labels: map[string]string{"database": "orders"}, Evidence: map[string]string{"aggregate": "91"}, State: EventFiring, FirstSeen: legacyUpdatedAt, LastSeen: legacyUpdatedAt, FiringAt: legacyUpdatedAt, LastActor: "evaluator"}
	legacyVersion := legacyUpdatedAt.UTC().Format(time.RFC3339Nano)
	legacyDeliveryID := legacyDeliveryIdempotencyKey(event.ID, EventFiring, "in_app", legacyVersion)
	envelope, err := json.Marshal(map[string]any{
		"attempts": 1,
		"request": map[string]any{
			"scope":    map[string]string{"tenant_id": scope.TenantID, "project_id": scope.ProjectID},
			"event_id": event.ID, "state": "firing", "severity": "critical", "channel": "in_app",
			"policy_id": "policy-version", "template_id": "policy-version", "template_version": legacyVersion,
			"target": "user-7", "secret_ref": "", "subject": event.ID, "body": "firing", "labels": event.Labels,
		},
	})
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "INSERT INTO notification_deliveries (id, tenant_id, project_id, event_id, policy_id, status, attempted_at, delivered_at, failure_reason) VALUES ($1, $2, $3, $4, 'policy-version', 'delivered', $5, $5, $6)", legacyDeliveryID, scope.TenantID, scope.ProjectID, event.ID, legacyUpdatedAt, string(envelope))
	require.NoError(t, err)

	migration, err := os.ReadFile(filepath.Join("migrations", "0002_notification_delivery_control.sql"))
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, string(migration))
	require.NoError(t, err)
	integrityMigration, err := os.ReadFile(filepath.Join("migrations", "0005_alert_control_plane_integrity.sql"))
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, string(integrityMigration))
	require.NoError(t, err)

	repository := NewPostgresRepository(database)
	routes, err := repository.ListNotificationRoutes(ctx, scope, "rule-version")
	require.NoError(t, err)
	require.Len(t, routes, 1)
	require.Equal(t, legacyVersion, routes[0].Template.Version())
	channel := &recordingChannel{name: "in_app"}
	dispatcher := NewDispatcher(repository, []DeliveryChannel{channel}, func() time.Time { return legacyUpdatedAt.Add(time.Minute) }, nil)
	require.NoError(t, dispatcher.Dispatch(ctx, event, EventFiring))
	require.Empty(t, channel.requests)

	var deliveryCount int
	var storedID, storedKey, storedVersion string
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*), min(id), min(idempotency_key), min(template_version) FROM notification_deliveries WHERE tenant_id = $1 AND project_id = $2 AND event_id = $3", scope.TenantID, scope.ProjectID, event.ID).Scan(&deliveryCount, &storedID, &storedKey, &storedVersion))
	require.Equal(t, 1, deliveryCount)
	require.Equal(t, legacyDeliveryID, storedID)
	require.Equal(t, legacyDeliveryID, storedKey)
	require.Equal(t, legacyVersion, storedVersion)
}

func TestPostgresUpdatingMigratedLegacyTemplateSwitchesToRevisionVersion(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL notification integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, _ := setupNotificationIntegrationSchemaThrough(t, ctx, dsn, "0001_alert_control_plane.sql")
	scope := Scope{TenantID: "tenant-version-update", ProjectID: "project-version-update"}
	var legacyUpdatedAt time.Time
	require.NoError(t, database.QueryRowContext(ctx, "INSERT INTO notification_templates (id, tenant_id, project_id, name, subject, body) VALUES ('template-version', $1, $2, 'legacy template', 'old subject', 'old body') RETURNING updated_at", scope.TenantID, scope.ProjectID).Scan(&legacyUpdatedAt))
	migration, err := os.ReadFile(filepath.Join("migrations", "0002_notification_delivery_control.sql"))
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, string(migration))
	require.NoError(t, err)

	updated, err := NewPostgresRepository(database).UpdateNotificationTemplate(ContextWithAuditActor(ctx, "operator"), NotificationTemplate{ID: "template-version", Scope: scope, Name: "updated template", Subject: "new subject", Body: "new body", Revision: 2})
	require.NoError(t, err)
	require.Equal(t, "2", updated.Version())
	require.NotEqual(t, legacyUpdatedAt.UTC().Format(time.RFC3339Nano), updated.Version())
	encoded, err := json.Marshal(updated)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "legacy_version")

	var legacyVersion bool
	var auditCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT legacy_version_from_updated_at FROM notification_templates WHERE tenant_id = $1 AND project_id = $2 AND id = 'template-version'", scope.TenantID, scope.ProjectID).Scan(&legacyVersion))
	require.False(t, legacyVersion)
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM alert_audit_log WHERE tenant_id = $1 AND project_id = $2 AND action = 'template.updated' AND target_id = 'template-version'", scope.TenantID, scope.ProjectID).Scan(&auditCount))
	require.Equal(t, 1, auditCount)
}

func TestPostgresNotificationRoutingDeliveryLeaseAndInAppRoundTrip(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL notification integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, schema := setupNotificationIntegrationSchema(t, ctx, dsn)
	repository := NewPostgresRepository(database)
	actorCtx := ContextWithAuditActor(ctx, "operator")
	scope := Scope{TenantID: "tenant-route", ProjectID: "project-route"}
	otherScope := Scope{TenantID: "tenant-route", ProjectID: "project-other"}
	now := time.Now().UTC().Add(time.Second)

	template, err := repository.CreateNotificationTemplate(actorCtx, NotificationTemplate{ID: "template-explicit", Scope: scope, Name: "critical", Subject: "{{event.severity}} {{resource.database}}", Body: "{{event.id}} {{event.state}}", Revision: 9})
	require.NoError(t, err)
	_, err = repository.CreateNotificationTemplate(ContextWithAuditActor(ctx, "operator"), NotificationTemplate{ID: "template-other", Scope: otherScope, Name: "other", Subject: "other", Body: "other", Revision: 1})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-wrong-severity", Scope: scope, Name: "wrong severity", Channel: "in_app", Target: "user-7", TemplateID: template.ID, Severities: []string{"warning"}, Enabled: true})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-wrong-label", Scope: scope, Name: "wrong label", Channel: "in_app", Target: "user-7", TemplateID: template.ID, Severities: []string{"critical"}, MatchLabels: map[string]string{"database": "inventory"}, Enabled: true})
	require.NoError(t, err)
	wrongWindowStart := now.Add(time.Hour).Format("15:04")
	wrongWindowEnd := now.Add(2 * time.Hour).Format("15:04")
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-wrong-window", Scope: scope, Name: "wrong window", Channel: "in_app", Target: "user-7", TemplateID: template.ID, Severities: []string{"critical"}, MatchLabels: map[string]string{"database": "orders"}, WindowStartUTC: wrongWindowStart, WindowEndUTC: wrongWindowEnd, Enabled: true})
	require.NoError(t, err)
	matchPolicy, err := repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-match", Scope: scope, Name: "match", Channel: "in_app", Target: "user-7", TemplateID: template.ID, Severities: []string{"critical"}, MatchLabels: map[string]string{"database": "orders"}, Enabled: true})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-match-two", Scope: scope, Name: "match two", Channel: "in_app", Target: "user-8", TemplateID: template.ID, Severities: []string{"critical"}, MatchLabels: map[string]string{"database": "orders"}, Enabled: true})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-cross-scope", Scope: scope, Name: "cross", Channel: "in_app", Target: "user-7", TemplateID: "template-other", Enabled: true})
	require.Error(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-missing", Scope: scope, Name: "missing", Channel: "in_app", Target: "user-7", TemplateID: "does-not-exist", Enabled: true})
	require.Error(t, err)

	rule := AlertRule{ID: "rule-route", Scope: scope, Name: "route", Metric: "db.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", NotificationPolicyIDs: []string{"policy-wrong-severity", "policy-wrong-label", "policy-wrong-window", "policy-match", "policy-match-two"}, Enabled: true}
	_, err = repository.CreateRule(actorCtx, rule)
	require.NoError(t, err)
	event := AlertEvent{ID: "event-route", Scope: scope, RuleID: rule.ID, Fingerprint: "route-fingerprint", Labels: map[string]string{"database": "orders"}, Evidence: map[string]string{"aggregate": "91"}, State: EventFiring, FirstSeen: now.Add(-time.Minute), LastSeen: now, FiringAt: now, LastActor: "evaluator"}
	channel := &recordingChannel{name: "in_app"}
	dispatcher := NewDispatcher(repository, []DeliveryChannel{channel}, func() time.Time { return now }, nil)
	require.NoError(t, dispatcher.Dispatch(ctx, event, EventFiring))
	require.Len(t, channel.requests, 2)
	require.NotEqual(t, channel.requests[0].DeliveryID, channel.requests[1].DeliveryID)
	require.Equal(t, "9", channel.requests[0].TemplateVersion)
	require.Equal(t, "critical orders", channel.requests[0].Subject)

	request := channel.requests[0]
	for _, routed := range channel.requests {
		require.NoError(t, repository.PersistInAppNotification(ctx, routed))
		require.NoError(t, repository.PersistInAppNotification(ctx, routed))
	}
	crossScopeRequest := request
	crossScopeRequest.Scope = otherScope
	require.ErrorIs(t, repository.PersistInAppNotification(ctx, crossScopeRequest), ErrNotificationScopeMismatch)
	notifications, err := repository.ListInAppNotifications(ctx, scope, "user-7", 100)
	require.NoError(t, err)
	require.Len(t, notifications, 1)
	secondNotifications, err := repository.ListInAppNotifications(ctx, scope, "user-8", 100)
	require.NoError(t, err)
	require.Len(t, secondNotifications, 1)
	otherNotifications, err := repository.ListInAppNotifications(ctx, otherScope, "user-7", 100)
	require.NoError(t, err)
	require.Empty(t, otherNotifications)

	previousPolicyDeliveryID := ""
	for _, routed := range channel.requests {
		if routed.PolicyID == matchPolicy.ID {
			previousPolicyDeliveryID = routed.DeliveryID
		}
	}
	require.NotEmpty(t, previousPolicyDeliveryID)
	matchPolicy.Name = "match revised"
	matchPolicy, err = repository.UpdateNotificationPolicy(actorCtx, matchPolicy)
	require.NoError(t, err)
	require.NoError(t, dispatcher.Dispatch(ctx, event, EventFiring))
	require.Len(t, channel.requests, 3, "only the revised policy route should receive a new delivery identity")
	revisedRequest := channel.requests[len(channel.requests)-1]
	require.Equal(t, matchPolicy.ID, revisedRequest.PolicyID)
	require.NotEqual(t, previousPolicyDeliveryID, revisedRequest.DeliveryID)

	// Seed a legacy invalid reference with FK triggers disabled to prove the
	// dispatcher records a permanent configuration failure instead of forging
	// a same-ID or empty template.
	_, err = database.ExecContext(ctx, "ALTER TABLE notification_policies DISABLE TRIGGER ALL")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "INSERT INTO notification_policies (id, tenant_id, project_id, name, channel, target, template_id, enabled) VALUES ('policy-legacy-missing', $1, $2, 'legacy missing', 'in_app', 'user-7', 'template-absent', true)", scope.TenantID, scope.ProjectID)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "ALTER TABLE notification_policies ENABLE TRIGGER ALL")
	require.NoError(t, err)
	rule.NotificationPolicyIDs = []string{"policy-legacy-missing"}
	_, err = repository.UpdateRule(actorCtx, rule)
	require.NoError(t, err)
	event.ID = "event-missing-template"
	event.Fingerprint = "missing-template-fingerprint"
	require.NoError(t, dispatcher.Dispatch(ctx, event, EventFiring))
	var failureClass string
	require.NoError(t, database.QueryRowContext(ctx, "SELECT failure_class FROM notification_deliveries WHERE tenant_id = $1 AND project_id = $2 AND event_id = $3", scope.TenantID, scope.ProjectID, event.ID).Scan(&failureClass))
	require.Equal(t, "template_missing", failureClass)

	leaseScope := Scope{TenantID: "tenant-lease", ProjectID: "project-lease"}
	leaseRequest := DeliveryRequest{Scope: leaseScope, EventID: "event-lease", State: EventFiring, Channel: "in_app", PolicyID: "policy-lease", TemplateID: "template-lease", TemplateVersion: "1", Target: "user-lease", Subject: "subject", Body: "body"}
	leaseEvent := AlertEvent{ID: "event-lease", Scope: leaseScope}
	delivery := newNotificationDelivery(leaseRequest, leaseEvent, now)
	delivery.LeaseOwner = "crashed-initial"
	delivery.LeaseExpiresAt = now.Add(-time.Second)
	delivery.ClaimOwner = "crashed-initial"
	reserved, err := repository.ReserveNotificationDelivery(ctx, delivery, nil)
	require.NoError(t, err)
	require.True(t, reserved)

	databaseTwo := openAlertIntegrationDB(t, alertIntegrationDSN(t, dsn, schema, "notification-claimer-two"), "")
	t.Cleanup(func() { require.NoError(t, databaseTwo.Close()) })
	repositoryTwo := NewPostgresRepository(databaseTwo)
	type claimResult struct {
		owner string
		rows  []NotificationDelivery
		err   error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	for _, claimer := range []struct {
		owner string
		repo  *PostgresRepository
	}{{"worker-one", repository}, {"worker-two", repositoryTwo}} {
		go func(owner string, repo *PostgresRepository) {
			<-start
			rows, claimErr := repo.ClaimDueNotificationDeliveries(ctx, now, owner, now.Add(time.Minute), 10)
			results <- claimResult{owner: owner, rows: rows, err: claimErr}
		}(claimer.owner, claimer.repo)
	}
	close(start)
	first, second := <-results, <-results
	require.NoError(t, first.err)
	require.NoError(t, second.err)
	require.Equal(t, 1, len(first.rows)+len(second.rows))
	claimed := first.rows
	if len(claimed) == 0 {
		claimed = second.rows
	}
	require.Equal(t, 2, claimed[0].Attempts)

	notExpired, err := repository.ClaimDueNotificationDeliveries(ctx, now.Add(30*time.Second), "worker-three", now.Add(2*time.Minute), 10)
	require.NoError(t, err)
	require.Empty(t, notExpired)
	recovered, err := repositoryTwo.ClaimDueNotificationDeliveries(ctx, now.Add(time.Minute), "worker-recovery", now.Add(2*time.Minute), 10)
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	require.Equal(t, 3, recovered[0].Attempts)
}

func TestPostgresRulePolicyReferencesAndDeletionRemainRecoverable(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL referential-integrity tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, _ := setupNotificationIntegrationSchema(t, ctx, dsn)
	repository := NewPostgresRepository(database)
	actorCtx := ContextWithAuditActor(ctx, "operator")
	scope := Scope{TenantID: "tenant-ref", ProjectID: "project-ref"}
	otherScope := Scope{TenantID: "tenant-ref", ProjectID: "project-other"}

	template, err := repository.CreateNotificationTemplate(actorCtx, NotificationTemplate{ID: "template-ref", Scope: scope, Name: "ref", Subject: "subject", Body: "body", Revision: 1})
	require.NoError(t, err)
	policy, err := repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-ref", Scope: scope, Name: "ref", Channel: "in_app", Target: "operator", TemplateID: template.ID, Severities: []string{}, Enabled: true})
	require.NoError(t, err)
	otherTemplate, err := repository.CreateNotificationTemplate(actorCtx, NotificationTemplate{ID: "template-other", Scope: otherScope, Name: "other", Subject: "subject", Body: "body", Revision: 1})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-other", Scope: otherScope, Name: "other", Channel: "in_app", Target: "operator", TemplateID: otherTemplate.ID, Severities: []string{}, Enabled: true})
	require.NoError(t, err)

	base := AlertRule{ID: "rule-ref", Scope: scope, Name: "ref", Metric: "db.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", Enabled: true}
	missing := base
	missing.ID = "rule-missing"
	missing.NotificationPolicyIDs = []string{"policy-missing"}
	_, err = repository.CreateRule(actorCtx, missing)
	require.Error(t, err)
	crossScope := base
	crossScope.ID = "rule-cross-scope"
	crossScope.NotificationPolicyIDs = []string{"policy-other"}
	_, err = repository.CreateRule(actorCtx, crossScope)
	require.Error(t, err)

	base.NotificationPolicyIDs = []string{policy.ID}
	storedRule, err := repository.CreateRule(actorCtx, base)
	require.NoError(t, err)
	require.Error(t, repository.DeleteNotificationPolicy(actorCtx, scope, policy.ID))

	now := time.Now().UTC().Truncate(time.Microsecond)
	event := AlertEvent{ID: "event-ref", Scope: scope, RuleID: storedRule.ID, Fingerprint: "fingerprint-ref", Labels: map[string]string{"host": "db-a"}, Evidence: map[string]string{}, State: EventPending, FirstSeen: now, LastSeen: now, LastActor: "system:evaluator"}
	_, err = repository.PutEvent(ctx, event)
	require.NoError(t, err)
	require.Error(t, repository.DeleteRule(actorCtx, scope, storedRule.ID))
	remaining, err := repository.GetRule(ctx, scope, storedRule.ID)
	require.NoError(t, err)
	require.NoError(t, remaining.Validate())

	evaluationAt := time.Now().UTC().Add(time.Second)
	evaluator := NewEvaluator(repository, repository)
	summary, err := evaluator.EvaluateScope(ctx, scope, evaluationAt)
	require.NoError(t, err)
	require.Zero(t, summary.FailedRules)
	channel := &recordingChannel{name: "in_app"}
	dispatcher := NewDispatcher(repository, []DeliveryChannel{channel}, func() time.Time { return evaluationAt }, nil)
	require.NoError(t, dispatcher.Dispatch(ctx, event, event.State))
	require.Len(t, channel.requests, 1, "rejected deletion preserves the event's notification route")
	history, err := repository.ListEvents(ctx, scope, EventFilter{Limit: 500, OrderByID: true})
	require.NoError(t, err)
	foundHistoricalEvent := false
	for _, stored := range history {
		if stored.ID == event.ID {
			foundHistoricalEvent = true
		}
	}
	require.True(t, foundHistoricalEvent)
	require.Empty(t, evaluator.HealthForScope(scope).LastError)
}

func TestPostgresRuleSchedulingLeasesCadenceAndLookbackAcrossReplicas(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL scheduling integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, _ := setupNotificationIntegrationSchema(t, ctx, dsn)
	repository := NewPostgresRepository(database)
	scope := Scope{TenantID: "tenant-schedule", ProjectID: "project-schedule"}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	rule := AlertRule{ID: "rule-schedule", Scope: scope, Name: "schedule", Metric: "db.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: 5 * time.Minute, LookbackWindow: 15 * time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", Enabled: true}

	stored, err := repository.CreateRule(ContextWithAuditActor(ctx, "operator"), rule)
	require.NoError(t, err)
	require.Equal(t, 15*time.Minute, stored.LookbackWindow)

	first, depth, err := repository.ClaimDueRules(ctx, scope, now, "replica-a", now.Add(time.Minute), 10)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Zero(t, depth)
	require.Equal(t, 15*time.Minute, first[0].Rule.LookbackWindow)

	second, _, err := repository.ClaimDueRules(ctx, scope, now, "replica-b", now.Add(time.Minute), 10)
	require.NoError(t, err)
	require.Empty(t, second, "an unexpired lease prevents duplicate multi-replica evaluation")

	require.NoError(t, repository.CompleteRuleEvaluation(ctx, scope, rule.ID, "replica-a", now, now.Add(rule.EvaluationEvery)))
	second, _, err = repository.ClaimDueRules(ctx, scope, now.Add(4*time.Minute), "replica-b", now.Add(6*time.Minute), 10)
	require.NoError(t, err)
	require.Empty(t, second)
	second, _, err = repository.ClaimDueRules(ctx, scope, now.Add(5*time.Minute), "replica-b", now.Add(6*time.Minute), 10)
	require.NoError(t, err)
	require.Len(t, second, 1)
}

func TestPostgresConcurrentPolicyDeletionCannotRaceRuleEnable(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL policy concurrency integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	databaseOne, schema := setupNotificationIntegrationSchema(t, ctx, dsn)
	databaseTwo := openAlertIntegrationDB(t, alertIntegrationDSN(t, dsn, schema, "policy-enable-racer"), "")
	t.Cleanup(func() { require.NoError(t, databaseTwo.Close()) })
	repositoryOne := NewPostgresRepository(databaseOne)
	repositoryTwo := NewPostgresRepository(databaseTwo)
	scope := Scope{TenantID: "tenant-policy-race", ProjectID: "project-policy-race"}
	actorCtx := ContextWithAuditActor(ctx, "operator")
	template, err := repositoryOne.CreateNotificationTemplate(actorCtx, NotificationTemplate{ID: "template-race", Scope: scope, Name: "race", Subject: "subject", Body: "body", Revision: 1})
	require.NoError(t, err)
	policy, err := repositoryOne.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-race", Scope: scope, Name: "race", Channel: "in_app", Target: "operator", TemplateID: template.ID, Enabled: true})
	require.NoError(t, err)
	rule := AlertRule{ID: "rule-race", Scope: scope, Name: "race", Metric: "db.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", Enabled: false}
	rule, err = repositoryOne.CreateRule(actorCtx, rule)
	require.NoError(t, err)

	deletion, err := databaseOne.BeginTx(ctx, nil)
	require.NoError(t, err)
	var locked string
	require.NoError(t, deletion.QueryRowContext(ctx, "SELECT id FROM notification_policies WHERE tenant_id = $1 AND project_id = $2 AND id = $3 FOR UPDATE", scope.TenantID, scope.ProjectID, policy.ID).Scan(&locked))
	rule.Enabled = true
	rule.NotificationPolicyIDs = []string{policy.ID}
	result := make(chan error, 1)
	go func() {
		_, updateErr := repositoryTwo.UpdateRule(ContextWithAuditActor(ctx, "operator-two"), rule)
		result <- updateErr
	}()
	select {
	case early := <-result:
		t.Fatalf("rule enable did not wait for the policy deletion lock: %v", early)
	case <-time.After(100 * time.Millisecond):
	}
	_, err = deletion.ExecContext(ctx, "DELETE FROM notification_policies WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, policy.ID)
	require.NoError(t, err)
	require.NoError(t, deletion.Commit())
	require.ErrorIs(t, <-result, ErrInvalidPolicyReference)
	stored, err := repositoryOne.GetRule(ctx, scope, rule.ID)
	require.NoError(t, err)
	require.False(t, stored.Enabled)
	require.Empty(t, stored.NotificationPolicyIDs)
}

func TestPostgresEventDispositionIsAtomicScopedAndAppendOnly(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL disposition integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, _ := setupNotificationIntegrationSchema(t, ctx, dsn)
	repository := NewPostgresRepository(database)
	scope := Scope{TenantID: "tenant-disposition", ProjectID: "project-disposition"}
	now := time.Now().UTC().Add(-time.Hour)
	rule := AlertRule{ID: "rule-disposition", Scope: scope, Name: "disposition", Metric: "db.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, LookbackWindow: 5 * time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", Enabled: true}
	_, err := repository.CreateRule(ContextWithAuditActor(ctx, "operator"), rule)
	require.NoError(t, err)
	event := AlertEvent{ID: "event-disposition", Scope: scope, RuleID: rule.ID, Fingerprint: "fingerprint-disposition", State: EventPending, FirstSeen: now, LastSeen: now, LastActor: "system:evaluator"}
	event, err = repository.PutEventAndAudit(ctx, event, AuditRecord{ID: "audit-pending", Scope: scope, Actor: "system:evaluator", Action: "event.pending", TargetID: event.ID, OccurredAt: now, Details: map[string]string{"state": "pending"}})
	require.NoError(t, err)
	event, err = event.Transition(EventFiring, now.Add(time.Minute), "system:evaluator")
	require.NoError(t, err)
	event, err = repository.PutEventAndAudit(ctx, event, AuditRecord{ID: "audit-firing", Scope: scope, Actor: "system:evaluator", Action: "event.firing", TargetID: event.ID, OccurredAt: event.LastSeen, Details: map[string]string{"state": "firing"}})
	require.NoError(t, err)

	_, err = database.ExecContext(ctx, "CREATE FUNCTION fail_forced_disposition() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN IF NEW.category = 'force_failure' THEN RAISE EXCEPTION 'forced disposition failure'; END IF; RETURN NEW; END $$")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "CREATE TRIGGER fail_forced_disposition BEFORE INSERT ON alert_event_dispositions FOR EACH ROW EXECUTE FUNCTION fail_forced_disposition()")
	require.NoError(t, err)
	acknowledged, err := event.Transition(EventAcknowledged, now.Add(2*time.Minute), "operator-1")
	require.NoError(t, err)
	failedDisposition := EventDisposition{ID: "disposition-failed", Scope: scope, EventID: event.ID, Kind: DispositionAcknowledgement, Category: "force_failure", Reason: "force transactional rollback", Actor: "operator-1", OccurredAt: acknowledged.LastSeen}
	failedAudit := AuditRecord{ID: "audit-ack-failed", Scope: scope, Actor: "operator-1", Action: "event.acknowledged", TargetID: event.ID, OccurredAt: acknowledged.LastSeen, Details: map[string]string{"state": "acknowledged", "category": "force_failure", "reason_present": "true"}}
	_, err = repository.PutEventAndDisposition(ctx, acknowledged, failedAudit, failedDisposition)
	require.Error(t, err)
	stored, err := repository.GetEvent(ctx, scope, event.ID)
	require.NoError(t, err)
	require.Equal(t, EventFiring, stored.State, "event and audit roll back when disposition persistence fails")
	var failedAuditCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT COUNT(*) FROM alert_audit_log WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, failedAudit.ID).Scan(&failedAuditCount))
	require.Zero(t, failedAuditCount)

	_, err = database.ExecContext(ctx, "DROP TRIGGER fail_forced_disposition ON alert_event_dispositions")
	require.NoError(t, err)
	validDisposition := failedDisposition
	validDisposition.ID, validDisposition.Category = "disposition-ack", "investigating"
	validAudit := failedAudit
	validAudit.ID = "audit-ack"
	validAudit.Details["category"] = "investigating"
	_, err = repository.PutEventAndDisposition(ctx, acknowledged, validAudit, validDisposition)
	require.NoError(t, err)

	rootAt := now.Add(3 * time.Minute)
	root := EventDisposition{ID: "disposition-root", Scope: scope, EventID: event.ID, Kind: DispositionRootCause, Category: "database_capacity", Reason: "connection pool exhausted", Actor: "operator-2", OccurredAt: rootAt}
	rootAudit := AuditRecord{ID: "audit-root", Scope: scope, Actor: root.Actor, Action: "event.root_cause", TargetID: event.ID, OccurredAt: rootAt, Details: map[string]string{"category": root.Category, "reason_present": "true"}}
	require.NoError(t, repository.AppendEventDisposition(ctx, root, rootAudit))
	values, err := repository.ListEventDispositions(ctx, scope, event.ID, 10, 0)
	require.NoError(t, err)
	require.Len(t, values, 2)
	require.Equal(t, DispositionRootCause, values[0].Kind)

	_, err = database.ExecContext(ctx, "UPDATE alert_event_dispositions SET reason = 'rewritten' WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, root.ID)
	require.ErrorContains(t, err, "append-only")
	otherScope := Scope{TenantID: scope.TenantID, ProjectID: "other-project"}
	values, err = repository.ListEventDispositions(ctx, otherScope, event.ID, 10, 0)
	require.NoError(t, err)
	require.Empty(t, values)
}

func TestPostgresEventCursorAndAggregateCoverMoreThanFiveHundredRows(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL event pagination integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, _ := setupNotificationIntegrationSchema(t, ctx, dsn)
	repository := NewPostgresRepository(database)
	scope := Scope{TenantID: "tenant-pagination", ProjectID: "project-pagination"}
	rule := AlertRule{ID: "rule-pagination", Scope: scope, Name: "pagination", Metric: "db.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", Enabled: true}
	_, err := repository.CreateRule(ContextWithAuditActor(ctx, "operator"), rule)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = database.ExecContext(ctx, `INSERT INTO alert_events (id, tenant_id, project_id, rule_id, fingerprint, state, first_seen, last_seen, firing_at, last_actor)
		SELECT 'event-' || lpad(value::text, 4, '0'), $1, $2, $3, 'fingerprint-' || value::text, 'firing', $4, $4, $4, 'system:evaluator'
		FROM generate_series(0, 500) AS value`, scope.TenantID, scope.ProjectID, rule.ID, now)
	require.NoError(t, err)

	counts, err := repository.CountEventsByState(ctx, scope)
	require.NoError(t, err)
	require.Equal(t, 501, counts[EventFiring])
	first, err := repository.ListEvents(ctx, scope, EventFilter{Limit: 500, OrderByID: true})
	require.NoError(t, err)
	require.Len(t, first, 500)
	require.Equal(t, "event-0499", first[len(first)-1].ID)

	_, err = database.ExecContext(ctx, "UPDATE alert_events SET last_seen = $1, firing_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND id = 'event-0000'", now.Add(time.Minute), scope.TenantID, scope.ProjectID)
	require.NoError(t, err)
	second, err := repository.ListEvents(ctx, scope, EventFilter{Limit: 500, OrderByID: true, AfterID: first[len(first)-1].ID})
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, "event-0500", second[0].ID, "last_seen changes cannot reorder the dispatch cursor")
}

func TestPostgresRejectsRawSecretsBeforeAnyControlPlaneTableWrite(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL secret-boundary integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, _ := setupNotificationIntegrationSchema(t, ctx, dsn)
	repository := NewPostgresRepository(database)
	scope := Scope{TenantID: "tenant-secret", ProjectID: "project-secret"}
	actorCtx := ContextWithAuditActor(ctx, "operator")
	now := time.Now().UTC()

	_, err := repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-secret", Scope: scope, Name: "unsafe", Channel: "webhook", Target: "https://allowed.example/hook", SecretRef: "password=hunter2", TemplateID: "template-secret", Enabled: true})
	require.Error(t, err)
	_, err = repository.CreateRule(actorCtx, AlertRule{ID: "rule-secret", Scope: scope, Name: "unsafe", Metric: "db.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", Labels: map[string]string{"api_token": "hunter2"}, Enabled: true})
	require.Error(t, err)
	_, err = repository.CreateSilence(actorCtx, Silence{ID: "silence-secret", Scope: scope, Matchers: map[string]string{"label.host": "password=hunter2"}, StartsAt: now, EndsAt: now.Add(time.Hour), CreatedBy: "operator", Reason: "maintenance"})
	require.Error(t, err)
	err = repository.Append(ctx, []MetricSample{{Scope: scope, AgentID: "agent-secret", Name: "db.cpu", Labels: map[string]string{"instance": "db-1", "component": "postgres", "role": "db", "host": "db-1", "password": "hunter2"}, Value: 1, SampledAt: now}})
	require.Error(t, err)
	delivery := NotificationDelivery{ID: "delivery-secret", IdempotencyKey: "delivery-secret", Scope: scope, EventID: "event-secret", PolicyID: "policy-secret", EventState: EventFiring, Status: DeliveryAttempting, Attempts: 1, AttemptedAt: now, LeaseOwner: "worker", LeaseExpiresAt: now.Add(time.Minute), Request: DeliveryRequest{Scope: scope, EventID: "event-secret", PolicyID: "policy-secret", State: EventFiring, Channel: "webhook", TemplateID: "template-secret", TemplateVersion: "1", Target: "https://allowed.example/hook", SecretRef: "hunter2"}}
	reserved, err := repository.ReserveNotificationDelivery(ctx, delivery, nil)
	require.False(t, reserved)
	require.Error(t, err)
	err = repository.AppendAudit(ctx, AuditRecord{ID: "audit-secret", Scope: scope, Actor: "operator", Action: "evaluation.failed", TargetID: "rule-secret", OccurredAt: now, Details: map[string]string{"failure_kind": "password=hunter2"}})
	require.Error(t, err)

	for _, assertion := range []string{
		"SELECT COUNT(*) FROM notification_policies WHERE tenant_id = $1 AND project_id = $2",
		"SELECT COUNT(*) FROM alert_rules WHERE tenant_id = $1 AND project_id = $2",
		"SELECT COUNT(*) FROM alert_silences WHERE tenant_id = $1 AND project_id = $2",
		"SELECT COUNT(*) FROM metric_samples WHERE tenant_id = $1 AND project_id = $2",
		"SELECT COUNT(*) FROM notification_deliveries WHERE tenant_id = $1 AND project_id = $2",
		"SELECT COUNT(*) FROM alert_audit_log WHERE tenant_id = $1 AND project_id = $2",
	} {
		var count int
		require.NoError(t, database.QueryRowContext(ctx, assertion, scope.TenantID, scope.ProjectID).Scan(&count))
		require.Zero(t, count, assertion)
	}
}

func TestPostgresRetryClaimsEachSlowDeliveryJustInTime(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run PostgreSQL notification integration tests")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, schema := setupNotificationIntegrationSchema(t, ctx, dsn)
	databaseTwo := openAlertIntegrationDB(t, alertIntegrationDSN(t, dsn, schema, "notification-jit-worker-two"), "")
	t.Cleanup(func() { require.NoError(t, databaseTwo.Close()) })

	scope := Scope{TenantID: "tenant-jit", ProjectID: "project-jit"}
	dueAt := time.Now().UTC().Add(-time.Second)
	repositoryOne := NewPostgresRepository(database)
	for index := 1; index <= 3; index++ {
		eventID := fmt.Sprintf("event-jit-%d", index)
		request := DeliveryRequest{Scope: scope, EventID: eventID, State: EventFiring, Channel: "in_app", PolicyID: "policy-jit", TemplateID: "template-jit", TemplateVersion: "1", Target: "recipient", Subject: "subject", Body: "body"}
		delivery := newNotificationDelivery(request, AlertEvent{ID: eventID, Scope: scope}, dueAt)
		delivery.LeaseOwner = "seed-owner"
		delivery.LeaseExpiresAt = dueAt
		delivery.ClaimOwner = "seed-owner"
		reserved, err := repositoryOne.ReserveNotificationDelivery(ctx, delivery, nil)
		require.NoError(t, err)
		require.True(t, reserved)
		_, err = database.ExecContext(ctx, "UPDATE notification_deliveries SET status = 'retry_scheduled', next_attempt_at = $1, lease_owner = '', lease_expires_at = NULL, failure_class = 'remote_5xx' WHERE tenant_id = $2 AND project_id = $3 AND id = $4", dueAt, scope.TenantID, scope.ProjectID, delivery.ID)
		require.NoError(t, err)
	}

	channel := &slowCountingChannel{name: "in_app", delay: 40 * time.Millisecond, started: make(chan string, 8), counts: make(map[string]int)}
	workerOne := NewDispatcher(repositoryOne, []DeliveryChannel{channel}, time.Now, nil)
	workerTwo := NewDispatcher(NewPostgresRepository(databaseTwo), []DeliveryChannel{channel}, time.Now, nil)
	workerOne.lease, workerTwo.lease = 50*time.Millisecond, 50*time.Millisecond
	workerOne.batchSize, workerTwo.batchSize = 3, 3

	workerOneResult := make(chan error, 1)
	go func() { workerOneResult <- workerOne.RetryDue(ctx, time.Now().UTC()) }()
	for index := 0; index < 3; index++ {
		select {
		case <-channel.started:
		case err := <-workerOneResult:
			t.Fatalf("worker one stopped after %d deliveries: %v", index, err)
		case <-ctx.Done():
			t.Fatal("worker one did not start all slow deliveries")
		}
	}
	require.NoError(t, workerTwo.RetryDue(ctx, time.Now().UTC()))
	require.NoError(t, <-workerOneResult)

	channel.mu.Lock()
	defer channel.mu.Unlock()
	require.Len(t, channel.counts, 3)
	for deliveryID, count := range channel.counts {
		require.Equal(t, 1, count, deliveryID)
	}
}

type slowCountingChannel struct {
	name    string
	delay   time.Duration
	started chan string
	mu      sync.Mutex
	counts  map[string]int
}

func (channel *slowCountingChannel) Name() string { return channel.name }

func (channel *slowCountingChannel) Deliver(ctx context.Context, request DeliveryRequest) error {
	channel.mu.Lock()
	channel.counts[request.DeliveryID]++
	channel.mu.Unlock()
	channel.started <- request.DeliveryID
	timer := time.NewTimer(channel.delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func setupNotificationIntegrationSchema(t *testing.T, ctx context.Context, dsn string) (*sql.DB, string) {
	return setupNotificationIntegrationSchemaThrough(t, ctx, dsn, "0001_alert_control_plane.sql", "0002_notification_delivery_control.sql", "0005_alert_control_plane_integrity.sql", "0006_monitoring_instance_state.sql")
}

func setupNotificationIntegrationSchemaThrough(t *testing.T, ctx context.Context, dsn string, migrations ...string) (*sql.DB, string) {
	t.Helper()
	admin := openAlertIntegrationDB(t, dsn, "notification-admin")
	schema := fmt.Sprintf("alert_notification_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})
	database := openAlertIntegrationDB(t, alertIntegrationDSN(t, dsn, schema, "notification-primary"), "")
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	for _, name := range migrations {
		migration, readErr := os.ReadFile(filepath.Join("migrations", name))
		require.NoError(t, readErr)
		_, execErr := database.ExecContext(ctx, string(migration))
		require.NoError(t, execErr, name)
	}
	return database, schema
}

// Run with a disposable PostgreSQL database, for example:
//
//	DBPILOT_ALERT_POSTGRES_INTEGRATION=1 \
//	  DBPILOT_ALERT_POSTGRES_DSN=postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable \
//	  go test ./internal/alert -run TestPostgresConcurrentFirstEventWritesAreSerialized -count=1
func TestPostgresConcurrentFirstEventWritesAreSerialized(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run the PostgreSQL concurrency integration test")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin := openAlertIntegrationDB(t, dsn, "alert-race-admin")
	schema := fmt.Sprintf("alert_race_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})

	setupAlertConcurrencySchema(t, ctx, admin, quotedSchema)
	writerOneDB := openAlertIntegrationDB(t, alertIntegrationDSN(t, dsn, schema, "alert-race-writer-1"), "")
	writerTwoDB := openAlertIntegrationDB(t, alertIntegrationDSN(t, dsn, schema, "alert-race-writer-2"), "")
	writerOneDB.SetMaxOpenConns(1)
	writerTwoDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		require.NoError(t, writerOneDB.Close())
		require.NoError(t, writerTwoDB.Close())
	})

	gate, err := admin.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gate.Close()) })
	_, err = gate.ExecContext(ctx, "SELECT pg_advisory_lock($1, $2)", int32(2147483647), int32(2147483646))
	require.NoError(t, err)

	at := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	scope := Scope{TenantID: "tenant-concurrent", ProjectID: "project-concurrent"}
	first := AlertEvent{ID: "event-first", Scope: scope, RuleID: "rule-1", Fingerprint: "shared-fingerprint", Labels: map[string]string{"host": "db-a"}, Evidence: map[string]string{}, State: EventPending, FirstSeen: at, LastSeen: at, LastActor: "system:evaluator"}
	second := first
	second.ID = "event-second"
	second.FirstSeen = at.Add(-time.Minute)
	second.LastSeen = second.FirstSeen

	type writeResult struct {
		writer int
		err    error
	}
	results := make(chan writeResult, 2)
	go func() {
		_, writeErr := NewPostgresRepository(writerOneDB).PutEvent(ctx, first)
		results <- writeResult{writer: 1, err: writeErr}
	}()
	waitForAdvisoryWait(t, ctx, admin, "alert-race-writer-1")
	go func() {
		_, writeErr := NewPostgresRepository(writerTwoDB).PutEvent(ctx, second)
		results <- writeResult{writer: 2, err: writeErr}
	}()
	waitForAdvisoryWait(t, ctx, admin, "alert-race-writer-2")

	_, err = gate.ExecContext(ctx, "SELECT pg_advisory_unlock($1, $2)", int32(2147483647), int32(2147483646))
	require.NoError(t, err)
	one, two := <-results, <-results
	byWriter := map[int]error{one.writer: one.err, two.writer: two.err}
	require.NoError(t, byWriter[1])
	require.ErrorIs(t, byWriter[2], ErrInvalidEventTransition)

	var eventID string
	var firstSeen time.Time
	require.NoError(t, writerOneDB.QueryRowContext(ctx, "SELECT id, first_seen FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND fingerprint = $3", scope.TenantID, scope.ProjectID, first.Fingerprint).Scan(&eventID, &firstSeen))
	require.Equal(t, first.ID, eventID)
	require.True(t, first.FirstSeen.Equal(firstSeen))
	var auditCount int
	require.NoError(t, writerOneDB.QueryRowContext(ctx, "SELECT count(*) FROM alert_audit_log WHERE tenant_id = $1 AND project_id = $2", scope.TenantID, scope.ProjectID).Scan(&auditCount))
	require.Equal(t, 1, auditCount)
}

// TestPostgresMetricBatchDedupIsAtomicAcrossInstances exercises two genuinely
// independent pools against the same unique reservation. Exactly one instance
// may commit the authenticated batch and its metric samples.
func TestPostgresMetricBatchDedupIsAtomicAcrossInstances(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run the PostgreSQL concurrency integration test")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	databaseOne, schema := setupNotificationIntegrationSchemaThrough(t, ctx, dsn, "0001_alert_control_plane.sql", "0003_ingest_dedup.sql", "0004_atomic_ingest_batch.sql", "0006_monitoring_instance_state.sql", "0007_metric_sample_acceptance.sql")
	databaseTwo := openAlertIntegrationDB(t, alertIntegrationDSN(t, dsn, schema, "metric-batch-writer-2"), "")
	t.Cleanup(func() { require.NoError(t, databaseTwo.Close()) })

	sample := MetricSample{Scope: Scope{TenantID: "tenant-a", ProjectID: "project-a"}, AgentID: "agent-a", Name: "db.connections", Labels: map[string]string{"instance": "db-a", "component": "postgres", "role": "db", "host": "db-a"}, Value: 12, SampledAt: time.Now().UTC()}
	type result struct {
		first bool
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for _, repository := range []*PostgresRepository{NewPostgresRepository(databaseOne), NewPostgresRepository(databaseTwo)} {
		go func(repository *PostgresRepository) {
			<-start
			first, err := repository.AppendBatch(ctx, "agent-a", "batch-a", []MetricSample{sample})
			results <- result{first: first, err: err}
		}(repository)
	}
	close(start)
	one, two := <-results, <-results
	require.NoError(t, one.err)
	require.NoError(t, two.err)
	require.NotEqual(t, one.first, two.first)

	var dedupCount, metricCount int
	require.NoError(t, databaseOne.QueryRowContext(ctx, "SELECT count(*) FROM ingest_batch_dedup WHERE agent_id = $1 AND batch_id = $2 AND state = 'accepted'", "agent-a", "batch-a").Scan(&dedupCount))
	require.NoError(t, databaseOne.QueryRowContext(ctx, "SELECT count(*) FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND agent_id = $3", "tenant-a", "project-a", "agent-a").Scan(&metricCount))
	require.Equal(t, 1, dedupCount)
	require.Equal(t, 1, metricCount)

	_, err := databaseOne.ExecContext(ctx, "CREATE FUNCTION fail_metric_batch_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected metric failure'; END $$")
	require.NoError(t, err)
	_, err = databaseOne.ExecContext(ctx, "CREATE TRIGGER fail_metric_batch BEFORE INSERT ON metric_samples FOR EACH ROW EXECUTE FUNCTION fail_metric_batch_insert()")
	require.NoError(t, err)
	failedSample := sample
	failedSample.SampledAt = failedSample.SampledAt.Add(time.Second)
	first, err := NewPostgresRepository(databaseOne).AppendBatch(ctx, "agent-a", "batch-retry", []MetricSample{failedSample})
	require.Error(t, err)
	require.False(t, first)
	require.NoError(t, databaseOne.QueryRowContext(ctx, "SELECT count(*) FROM ingest_batch_dedup WHERE agent_id = $1 AND batch_id = $2", "agent-a", "batch-retry").Scan(&dedupCount))
	require.Zero(t, dedupCount, "failed payload transaction must roll back its reservation")
	_, err = databaseOne.ExecContext(ctx, "DROP TRIGGER fail_metric_batch ON metric_samples")
	require.NoError(t, err)
	first, err = NewPostgresRepository(databaseTwo).AppendBatch(ctx, "agent-a", "batch-retry", []MetricSample{failedSample})
	require.NoError(t, err)
	require.True(t, first, "another instance must be able to retry after rollback")
}

func setupAlertConcurrencySchema(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()
	statements := []string{
		"CREATE TABLE " + schema + ".alert_events (id TEXT NOT NULL, tenant_id TEXT NOT NULL, project_id TEXT NOT NULL, rule_id TEXT NOT NULL, fingerprint TEXT NOT NULL, labels JSONB NOT NULL DEFAULT '{}'::jsonb, evidence JSONB NOT NULL DEFAULT '{}'::jsonb, state TEXT NOT NULL, first_seen TIMESTAMPTZ NOT NULL, last_seen TIMESTAMPTZ NOT NULL, firing_at TIMESTAMPTZ, acknowledged_at TIMESTAMPTZ, resolved_at TIMESTAMPTZ, last_actor TEXT NOT NULL DEFAULT '', PRIMARY KEY (tenant_id, project_id, id), UNIQUE (tenant_id, project_id, fingerprint))",
		"CREATE TABLE " + schema + ".alert_audit_log (id TEXT NOT NULL, tenant_id TEXT NOT NULL, project_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target_id TEXT NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, details JSONB NOT NULL DEFAULT '{}'::jsonb, PRIMARY KEY (tenant_id, project_id, id))",
		"CREATE FUNCTION " + schema + ".hold_first_event_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2147483647, 2147483646); RETURN NEW; END $$",
		"CREATE TRIGGER hold_first_event_insert BEFORE INSERT ON " + schema + ".alert_events FOR EACH ROW EXECUTE FUNCTION " + schema + ".hold_first_event_insert()",
	}
	for _, statement := range statements {
		_, err := db.ExecContext(ctx, statement)
		require.NoError(t, err)
	}
}

func openAlertIntegrationDB(t *testing.T, dsn, applicationName string) *sql.DB {
	t.Helper()
	if applicationName != "" {
		dsn = alertIntegrationDSN(t, dsn, "", applicationName)
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, db.PingContext(ctx))
	return db
}

func alertIntegrationDSN(t *testing.T, dsn, schema, applicationName string) string {
	t.Helper()
	if strings.Contains(dsn, "://") {
		parsed, err := url.Parse(dsn)
		require.NoError(t, err)
		query := parsed.Query()
		if schema != "" {
			query.Set("search_path", schema)
		}
		if applicationName != "" {
			query.Set("application_name", applicationName)
		}
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	if schema != "" {
		dsn += " search_path=" + schema
	}
	if applicationName != "" {
		dsn += " application_name=" + applicationName
	}
	return dsn
}

func waitForAdvisoryWait(t *testing.T, ctx context.Context, db *sql.DB, applicationName string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		err := db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = $1 AND wait_event_type = 'Lock' AND lower(wait_event) = 'advisory')", applicationName).Scan(&waiting)
		require.NoError(t, err)
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("writer %s did not reach an advisory-lock wait: %v", applicationName, ctx.Err())
		case <-ticker.C:
		}
	}
}
