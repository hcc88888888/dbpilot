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
	require.Equal(t, "vault://legacy-reference", retry.secretRef)
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
	require.Zero(t, invalidConstraints)
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
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

	template, err := repository.CreateNotificationTemplate(actorCtx, NotificationTemplate{ID: "template-explicit", Scope: scope, Name: "critical", Subject: "{{event.severity}} {{resource.database}}", Body: "{{event.id}} {{event.state}}", Revision: 9})
	require.NoError(t, err)
	_, err = repository.CreateNotificationTemplate(ContextWithAuditActor(ctx, "operator"), NotificationTemplate{ID: "template-other", Scope: otherScope, Name: "other", Subject: "other", Body: "other", Revision: 1})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-wrong-severity", Scope: scope, Name: "wrong severity", Channel: "in_app", Target: "user-7", TemplateID: template.ID, Severities: []string{"warning"}, Enabled: true})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-wrong-label", Scope: scope, Name: "wrong label", Channel: "in_app", Target: "user-7", TemplateID: template.ID, Severities: []string{"critical"}, MatchLabels: map[string]string{"database": "inventory"}, Enabled: true})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-wrong-window", Scope: scope, Name: "wrong window", Channel: "in_app", Target: "user-7", TemplateID: template.ID, Severities: []string{"critical"}, MatchLabels: map[string]string{"database": "orders"}, WindowStartUTC: "11:00", WindowEndUTC: "12:00", Enabled: true})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-match", Scope: scope, Name: "match", Channel: "in_app", Target: "user-7", TemplateID: template.ID, Severities: []string{"critical"}, MatchLabels: map[string]string{"database": "orders"}, WindowStartUTC: "09:00", WindowEndUTC: "11:00", Enabled: true})
	require.NoError(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-cross-scope", Scope: scope, Name: "cross", Channel: "in_app", Target: "user-7", TemplateID: "template-other", Enabled: true})
	require.Error(t, err)
	_, err = repository.CreateNotificationPolicy(actorCtx, NotificationPolicy{ID: "policy-missing", Scope: scope, Name: "missing", Channel: "in_app", Target: "user-7", TemplateID: "does-not-exist", Enabled: true})
	require.Error(t, err)

	rule := AlertRule{ID: "rule-route", Scope: scope, Name: "route", Metric: "db.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", NotificationPolicyIDs: []string{"policy-wrong-severity", "policy-wrong-label", "policy-wrong-window", "policy-match"}, Enabled: true}
	_, err = repository.CreateRule(actorCtx, rule)
	require.NoError(t, err)
	event := AlertEvent{ID: "event-route", Scope: scope, RuleID: rule.ID, Fingerprint: "route-fingerprint", Labels: map[string]string{"database": "orders"}, Evidence: map[string]string{"aggregate": "91"}, State: EventFiring, FirstSeen: now.Add(-time.Minute), LastSeen: now, FiringAt: now, LastActor: "evaluator"}
	channel := &recordingChannel{name: "in_app"}
	dispatcher := NewDispatcher(repository, []DeliveryChannel{channel}, func() time.Time { return now }, nil)
	require.NoError(t, dispatcher.Dispatch(ctx, event, EventFiring))
	require.Len(t, channel.requests, 1)
	require.Equal(t, "9", channel.requests[0].TemplateVersion)
	require.Equal(t, "critical orders", channel.requests[0].Subject)

	request := channel.requests[0]
	require.NoError(t, repository.PersistInAppNotification(ctx, request))
	require.NoError(t, repository.PersistInAppNotification(ctx, request))
	crossScopeRequest := request
	crossScopeRequest.Scope = otherScope
	require.ErrorIs(t, repository.PersistInAppNotification(ctx, crossScopeRequest), ErrNotificationScopeMismatch)
	notifications, err := repository.ListInAppNotifications(ctx, scope, "user-7", 100)
	require.NoError(t, err)
	require.Len(t, notifications, 1)
	otherNotifications, err := repository.ListInAppNotifications(ctx, otherScope, "user-7", 100)
	require.NoError(t, err)
	require.Empty(t, otherNotifications)

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
		request := DeliveryRequest{Scope: scope, EventID: eventID, State: EventFiring, Channel: "slow", PolicyID: "policy-jit", TemplateID: "template-jit", TemplateVersion: "1", Target: "recipient", Subject: "subject", Body: "body"}
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

	channel := &slowCountingChannel{name: "slow", delay: 40 * time.Millisecond, started: make(chan string, 8), counts: make(map[string]int)}
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
	return setupNotificationIntegrationSchemaThrough(t, ctx, dsn, "0001_alert_control_plane.sql", "0002_notification_delivery_control.sql")
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
