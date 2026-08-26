package alert

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestDispatcherSilenceSuppressesDeliveryButWritesAudit(t *testing.T) {
	fx := newDispatchFixture(t)
	fx.repository.silences = []Silence{{
		ID: "silence-1", Scope: fx.event.Scope,
		Matchers: map[string]string{"fingerprint": fx.event.Fingerprint},
		StartsAt: fx.now.Add(-time.Minute), EndsAt: fx.now.Add(time.Minute), CreatedBy: "operator", CreatedAt: fx.now.Add(-time.Hour),
	}}

	require.NoError(t, fx.dispatcher.Dispatch(context.Background(), fx.event, EventFiring))
	require.Empty(t, fx.channel.requests)
	require.Equal(t, DeliverySuppressed, fx.repository.deliveries[0].Status)
	require.Equal(t, "delivery.suppressed", fx.repository.audits[0].Action)
}

func TestDispatcherUsesEventStateChannelAndTemplateVersionIdempotencyKey(t *testing.T) {
	fx := newDispatchFixture(t)

	require.NoError(t, fx.dispatcher.Dispatch(context.Background(), fx.event, EventFiring))
	require.NoError(t, fx.dispatcher.Dispatch(context.Background(), fx.event, EventFiring))

	require.Len(t, fx.channel.requests, 1)
	require.Len(t, fx.repository.deliveries, 1)
	require.Equal(t, deliveryIdempotencyKey(fx.event.ID, EventFiring, "test", fx.repository.routes[0].Template.Version()), fx.repository.deliveries[0].IdempotencyKey)
}

func TestDispatcherMatchesSeverityLabelsAndUTCWindowAndRendersAllowedFields(t *testing.T) {
	fx := newDispatchFixture(t)
	fx.repository.routes[0].Policy.Severities = []string{"critical"}
	fx.repository.routes[0].Policy.MatchLabels = map[string]string{"database": "orders"}
	fx.repository.routes[0].Policy.WindowStartUTC = "09:00"
	fx.repository.routes[0].Policy.WindowEndUTC = "11:00"
	fx.repository.routes[0].Template.Subject = "{{event.severity}} {{resource.database}}"
	fx.repository.routes[0].Template.Body = "{{event.id}} {{event.state}} {{evidence.aggregate}} {{event.url}}"

	require.NoError(t, fx.dispatcher.Dispatch(context.Background(), fx.event, EventFiring))
	require.Len(t, fx.channel.requests, 1)
	require.Equal(t, "critical orders", fx.channel.requests[0].Subject)
	require.Equal(t, "event-1 firing 93.5 https://dbpilot.example/alerts/event-1", fx.channel.requests[0].Body)
}

func TestDispatcherSilencePrecedesChannelAndTemplateValidation(t *testing.T) {
	fx := newDispatchFixture(t)
	fx.repository.routes[0].Policy.Channel = "missing-channel"
	fx.repository.routes[0].Template.Body = "{{unknown.value}}"
	fx.repository.silences = []Silence{{
		ID: "silence-1", Scope: fx.event.Scope, Reason: "planned maintenance",
		Matchers: map[string]string{"fingerprint": fx.event.Fingerprint},
		StartsAt: fx.now.Add(-time.Minute), EndsAt: fx.now.Add(time.Minute), CreatedBy: "operator", CreatedAt: fx.now.Add(-time.Hour), UpdatedAt: fx.now.Add(-time.Hour),
	}}

	require.NoError(t, fx.dispatcher.Dispatch(context.Background(), fx.event, EventFiring))
	require.Empty(t, fx.channel.requests)
	require.Equal(t, DeliverySuppressed, fx.repository.deliveries[0].Status)
	require.Equal(t, "delivery.suppressed", fx.repository.audits[0].Action)
}

func TestDispatcherMissingReferencedTemplateIsPermanentConfigurationFailure(t *testing.T) {
	fx := newDispatchFixture(t)
	fx.repository.routes[0].Policy.TemplateID = "template-missing"
	fx.repository.routes[0].Template = NotificationTemplate{}

	require.NoError(t, fx.dispatcher.Dispatch(context.Background(), fx.event, EventFiring))
	require.Empty(t, fx.channel.requests)
	require.Equal(t, DeliveryAbandoned, fx.repository.deliveries[0].Status)
	require.Equal(t, "template_missing", fx.repository.deliveries[0].FailureClass)
}

func TestDispatcherRejectsUnknownTemplatePlaceholderWithoutCallingChannel(t *testing.T) {
	fx := newDispatchFixture(t)
	fx.repository.routes[0].Template.Body = "{{secret.value}}"

	require.NoError(t, fx.dispatcher.Dispatch(context.Background(), fx.event, EventFiring))
	require.Empty(t, fx.channel.requests)
	require.Equal(t, DeliveryAbandoned, fx.repository.deliveries[0].Status)
	require.Equal(t, "template_validation", fx.repository.deliveries[0].FailureClass)
	require.Equal(t, "delivery.abandoned", fx.repository.audits[len(fx.repository.audits)-1].Action)
}

func TestDispatcherRetriesAtBoundedScheduleAndEventuallyAbandons(t *testing.T) {
	fx := newDispatchFixture(t)
	fx.channel.err = RetryableDeliveryError("remote_5xx", errors.New("response body must not survive"))

	require.NoError(t, fx.dispatcher.Dispatch(context.Background(), fx.event, EventFiring))
	require.Equal(t, fx.now.Add(time.Minute), fx.repository.deliveries[0].NextAttemptAt)

	for _, at := range []time.Time{fx.now.Add(time.Minute), fx.now.Add(6 * time.Minute), fx.now.Add(36 * time.Minute)} {
		fx.clock = at
		require.NoError(t, fx.dispatcher.RetryDue(context.Background(), at))
	}

	delivery := fx.repository.deliveries[0]
	require.Equal(t, 4, delivery.Attempts)
	require.Equal(t, DeliveryAbandoned, delivery.Status)
	require.Equal(t, "remote_5xx", delivery.FailureClass)
	require.NotContains(t, delivery.FailureClass, "response body")
	require.Equal(t, "delivery.abandoned", fx.repository.audits[len(fx.repository.audits)-1].Action)
}

func TestDispatcherRetryDueDoesNotLetBadDeliveryBlockOtherTenants(t *testing.T) {
	fx := newDispatchFixture(t)
	firstRequest, err := fx.dispatcher.deliveryRequest(fx.repository.routes[0], fx.repository.rule, fx.event, EventFiring)
	require.NoError(t, err)
	firstRequest.Channel = "missing-channel"
	first := newNotificationDelivery(firstRequest, fx.event, fx.now)
	first.Status = DeliveryRetryScheduled
	first.NextAttemptAt = fx.now
	first.LeaseOwner, first.LeaseExpiresAt, first.ClaimOwner = "", time.Time{}, ""

	secondEvent := fx.event
	secondEvent.ID = "event-2"
	secondEvent.Scope = Scope{TenantID: "tenant-b", ProjectID: "project-b"}
	secondRequest := firstRequest
	secondRequest.Scope = secondEvent.Scope
	secondRequest.EventID = secondEvent.ID
	secondRequest.Channel = "test"
	second := newNotificationDelivery(secondRequest, secondEvent, fx.now)
	second.Status = DeliveryRetryScheduled
	second.NextAttemptAt = fx.now
	second.LeaseOwner, second.LeaseExpiresAt, second.ClaimOwner = "", time.Time{}, ""
	fx.repository.deliveries = []NotificationDelivery{first, second}

	require.NoError(t, fx.dispatcher.RetryDue(context.Background(), fx.now))
	require.Len(t, fx.channel.requests, 1)
	require.Equal(t, "event-2", fx.channel.requests[0].EventID)
	require.Equal(t, DeliveryAbandoned, fx.repository.deliveries[0].Status)
	require.Equal(t, DeliveryDelivered, fx.repository.deliveries[1].Status)
}

func TestClaimDueRecoversExpiredAttemptingDelivery(t *testing.T) {
	fx := newDispatchFixture(t)
	request, err := fx.dispatcher.deliveryRequest(fx.repository.routes[0], fx.repository.rule, fx.event, EventFiring)
	require.NoError(t, err)
	delivery := newNotificationDelivery(request, fx.event, fx.now)
	delivery.LeaseOwner = "crashed-worker"
	delivery.LeaseExpiresAt = fx.now.Add(-time.Second)
	delivery.ClaimOwner = "crashed-worker"
	fx.repository.deliveries = []NotificationDelivery{delivery}

	claimed, err := fx.repository.ClaimDueNotificationDeliveries(context.Background(), fx.now, "recovery-worker", fx.now.Add(time.Minute), 10)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, 2, claimed[0].Attempts)
	require.Equal(t, "recovery-worker", claimed[0].LeaseOwner)
}

func TestNotificationPolicyJSONOnlyExposesSecretPresence(t *testing.T) {
	encoded, err := json.Marshal(NotificationPolicy{ID: "policy-1", Scope: Scope{TenantID: "tenant-a", ProjectID: "project-a"}, SecretRef: "vault://notifications/webhook"})
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "vault://")
	require.NotContains(t, string(encoded), "secret_ref")
	require.Contains(t, string(encoded), `"has_secret":true`)
}

func TestPostgresNotificationRepositoryLoadsOnlyAssignedScopedRoutes(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, database.Close())
	})
	at := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	mock.ExpectQuery("FROM alert_rules r JOIN notification_policies p").
		WithArgs("tenant-a", "project-a", "rule-1").
		WillReturnRows(sqlmock.NewRows(notificationRouteColumns()).AddRow(
			"policy-1", "tenant-a", "project-a", "primary", "webhook", "https://allowed.example/hook", "vault://hook", "template-7", "{critical}", []byte(`{"database":"orders"}`), "09:00", "11:00", true, at, at,
			"template-7", "tenant-a", "project-a", "default", "subject", "body", int64(7), false, at, at,
		))

	routes, err := NewPostgresRepository(database).ListNotificationRoutes(context.Background(), Scope{TenantID: "tenant-a", ProjectID: "project-a"}, "rule-1")
	require.NoError(t, err)
	require.Len(t, routes, 1)
	require.Equal(t, "vault://hook", routes[0].Policy.SecretRef)
	require.Equal(t, "template-7", routes[0].Policy.TemplateID)
	require.Equal(t, []string{"critical"}, routes[0].Policy.Severities)
	require.Equal(t, map[string]string{"database": "orders"}, routes[0].Policy.MatchLabels)
	require.Equal(t, "09:00", routes[0].Policy.WindowStartUTC)
	require.Equal(t, int64(7), routes[0].Template.Revision)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresNotificationRepositoryReservesDeliveryAndAuditAtomically(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, database.Close())
	})
	fx := newDispatchFixture(t)
	request, err := fx.dispatcher.deliveryRequest(fx.repository.routes[0], fx.repository.rule, fx.event, EventFiring)
	require.NoError(t, err)
	delivery := newNotificationDelivery(request, fx.event, fx.now)
	delivery.Status = DeliverySuppressed
	audit := notificationAudit(delivery, "delivery.suppressed", fx.now)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO notification_deliveries").WithArgs(
		delivery.ID, "tenant-a", "project-a", "event-1", "policy-1", delivery.IdempotencyKey, "firing", "test", "template-1", "3",
		"suppressed", 1, fx.now, nil, nil, "", nil, "", "recipient", "Alert event-1", "firing", sqlmock.AnyArg(), "secret-ref",
	).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO alert_audit_log").WithArgs(
		audit.ID, "tenant-a", "project-a", audit.Actor, audit.Action, delivery.ID, fx.now, sqlmock.AnyArg(),
	).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	reserved, err := NewPostgresRepository(database).ReserveNotificationDelivery(context.Background(), delivery, &audit)
	require.NoError(t, err)
	require.True(t, reserved)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresNotificationRepositoryAtomicallyClaimsDueAndExpiredAttempting(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, database.Close())
	})
	fx := newDispatchFixture(t)
	request, err := fx.dispatcher.deliveryRequest(fx.repository.routes[0], fx.repository.rule, fx.event, EventFiring)
	require.NoError(t, err)
	delivery := newNotificationDelivery(request, fx.event, fx.now)
	delivery.Status = DeliveryRetryScheduled
	delivery.NextAttemptAt = fx.now.Add(time.Minute)
	delivery.FailureClass = "remote_5xx"
	leaseUntil := fx.now.Add(2 * time.Minute)
	mock.ExpectQuery(regexp.QuoteMeta(claimDeliveriesSQL)).WithArgs(fx.now.Add(time.Minute), 10, "worker-b", leaseUntil).WillReturnRows(
		sqlmock.NewRows(notificationDeliveryColumns()).AddRow(
			delivery.ID, "tenant-a", "project-a", "event-1", "policy-1", delivery.ID, "firing", "test", "template-1", "3",
			"attempting", 2, fx.now.Add(time.Minute), nil, nil, "worker-b", leaseUntil, "remote_5xx", "recipient", "Alert event-1", "firing", []byte(`{"database":"orders"}`), "secret-ref",
		),
	)

	due, err := NewPostgresRepository(database).ClaimDueNotificationDeliveries(context.Background(), fx.now.Add(time.Minute), "worker-b", leaseUntil, 10)
	require.NoError(t, err)
	require.Len(t, due, 1)
	require.Equal(t, "secret-ref", due[0].Request.SecretRef)
	require.Equal(t, "worker-b", due[0].LeaseOwner)
	require.Equal(t, 2, due[0].Attempts)
	require.NoError(t, mock.ExpectationsWereMet())
}

func notificationRouteColumns() []string {
	return []string{"policy_id", "policy_tenant_id", "policy_project_id", "policy_name", "channel", "target", "secret_ref", "template_id", "severities", "match_labels", "window_start_utc", "window_end_utc", "enabled", "policy_created_at", "policy_updated_at", "resolved_template_id", "template_tenant_id", "template_project_id", "template_name", "subject", "body", "template_revision", "template_legacy_version", "template_created_at", "template_updated_at"}
}

func notificationDeliveryColumns() []string {
	return []string{"id", "tenant_id", "project_id", "event_id", "policy_id", "idempotency_key", "event_state", "channel", "template_id", "template_version", "status", "attempts", "attempted_at", "next_attempt_at", "delivered_at", "lease_owner", "lease_expires_at", "failure_class", "request_target", "request_subject", "request_body", "request_labels", "request_secret_ref"}
}

type dispatchFixture struct {
	now        time.Time
	clock      time.Time
	event      AlertEvent
	repository *memoryNotificationRepository
	channel    *recordingChannel
	dispatcher *Dispatcher
}

func newDispatchFixture(t *testing.T) *dispatchFixture {
	t.Helper()
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	scope := Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	event := AlertEvent{ID: "event-1", Scope: scope, RuleID: "rule-1", Fingerprint: "fingerprint-1", Labels: map[string]string{"database": "orders"}, Evidence: map[string]string{"aggregate": "93.5"}, State: EventFiring, FirstSeen: now.Add(-time.Hour), LastSeen: now, FiringAt: now, LastActor: "evaluator"}
	template := NotificationTemplate{ID: "template-1", Scope: scope, Name: "default", Subject: "Alert {{event.id}}", Body: "{{event.state}}", Revision: 3, UpdatedAt: now.Add(-time.Hour)}
	policy := NotificationPolicy{ID: "policy-1", Scope: scope, Name: "test", Channel: "test", Target: "recipient", SecretRef: "secret-ref", TemplateID: "template-1", Enabled: true}
	repository := &memoryNotificationRepository{
		rule:   AlertRule{ID: "rule-1", Scope: scope, Name: "CPU", Metric: "cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", NotificationPolicyIDs: []string{"policy-1"}, Enabled: true},
		routes: []NotificationRoute{{Policy: policy, Template: template}},
	}
	channel := &recordingChannel{name: "test"}
	fx := &dispatchFixture{now: now, clock: now, event: event, repository: repository, channel: channel}
	fx.dispatcher = NewDispatcher(repository, []DeliveryChannel{channel}, func() time.Time { return fx.clock }, func(event AlertEvent) string { return "https://dbpilot.example/alerts/" + event.ID })
	return fx
}

func TestNotificationForwardMigrationAddsTypedRoutingDeliveryLeaseAndInAppFields(t *testing.T) {
	migration, err := os.ReadFile(filepath.Join("migrations", "0002_notification_delivery_control.sql"))
	require.NoError(t, err)
	content := string(migration)
	for _, required := range []string{
		"template_id", "severities", "match_labels", "window_start_utc", "window_end_utc", "revision",
		"idempotency_key", "event_state", "channel", "template_version", "attempts", "next_attempt_at", "lease_owner", "lease_expires_at", "failure_class",
		"request_target", "request_subject", "request_body", "request_labels", "request_secret_ref", "CREATE TABLE in_app_notifications", "reason",
	} {
		require.Contains(t, content, required)
	}
	require.NotContains(t, content, "failure_reason::jsonb")
}

func TestPostgresInAppNotificationIsScopedIdempotentAndReadable(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, database.Close())
	})
	repository := NewPostgresRepository(database)
	scope := Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	request := DeliveryRequest{DeliveryID: "delivery-1", Scope: scope, EventID: "event-1", State: EventFiring, Target: "user-7", Subject: "critical", Body: "database down"}
	mock.ExpectQuery("INSERT INTO in_app_notifications").WithArgs(sqlmock.AnyArg(), "tenant-a", "project-a", "delivery-1", "event-1", "firing", "user-7", "critical", "database down").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("notice-1"))
	require.NoError(t, repository.PersistInAppNotification(context.Background(), request))
	crossScope := request
	crossScope.Scope.ProjectID = "project-other"
	mock.ExpectQuery("INSERT INTO in_app_notifications").WithArgs(sqlmock.AnyArg(), "tenant-a", "project-other", "delivery-1", "event-1", "firing", "user-7", "critical", "database down").WillReturnError(sql.ErrNoRows)
	require.ErrorIs(t, repository.PersistInAppNotification(context.Background(), crossScope), ErrNotificationScopeMismatch)

	at := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	mock.ExpectQuery("FROM in_app_notifications WHERE tenant_id = \\$1 AND project_id = \\$2 AND recipient = \\$3").WithArgs("tenant-a", "project-a", "user-7", 50).WillReturnRows(
		sqlmock.NewRows([]string{"id", "tenant_id", "project_id", "delivery_id", "event_id", "event_state", "recipient", "subject", "body", "created_at", "read_at"}).AddRow("notice-1", "tenant-a", "project-a", "delivery-1", "event-1", "firing", "user-7", "critical", "database down", at, nil),
	)
	notifications, err := repository.ListInAppNotifications(context.Background(), scope, "user-7", 50)
	require.NoError(t, err)
	require.Len(t, notifications, 1)
	require.Equal(t, scope, notifications[0].Scope)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresCreateSilencePersistsReasonAndLifecycleAudit(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, database.Close())
	})
	at := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	silence := Silence{ID: "silence-1", Scope: Scope{TenantID: "tenant-a", ProjectID: "project-a"}, Matchers: map[string]string{"database": "orders"}, StartsAt: at, EndsAt: at.Add(time.Hour), CreatedBy: "operator", Reason: "planned maintenance", CreatedAt: at, UpdatedAt: at}
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO alert_silences").WithArgs("silence-1", "tenant-a", "project-a", sqlmock.AnyArg(), at, at.Add(time.Hour), "operator", "planned maintenance").WillReturnRows(
		sqlmock.NewRows([]string{"id", "tenant_id", "project_id", "matchers", "starts_at", "ends_at", "created_by", "reason", "created_at", "updated_at"}).AddRow("silence-1", "tenant-a", "project-a", []byte(`{"database":"orders"}`), at, at.Add(time.Hour), "operator", "planned maintenance", at, at),
	)
	mock.ExpectExec("INSERT INTO alert_audit_log").WithArgs(sqlmock.AnyArg(), "tenant-a", "project-a", "operator", "silence.created", "silence-1", at, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	stored, err := NewPostgresRepository(database).CreateSilence(ContextWithAuditActor(context.Background(), "operator"), silence)
	require.NoError(t, err)
	require.Equal(t, "planned maintenance", stored.Reason)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresCreatesExplicitVersionedTemplateAndRoutedPolicy(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, database.Close())
	})
	repository := NewPostgresRepository(database)
	ctx := ContextWithAuditActor(context.Background(), "operator")
	scope := Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	at := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	template := NotificationTemplate{ID: "template-7", Scope: scope, Name: "critical", Subject: "{{event.id}}", Body: "{{event.state}}", Revision: 7}
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO notification_templates").WithArgs("template-7", "tenant-a", "project-a", "critical", "{{event.id}}", "{{event.state}}", int64(7)).WillReturnRows(
		sqlmock.NewRows([]string{"id", "tenant_id", "project_id", "name", "subject", "body", "revision", "legacy_version_from_updated_at", "created_at", "updated_at"}).AddRow("template-7", "tenant-a", "project-a", "critical", "{{event.id}}", "{{event.state}}", int64(7), false, at, at),
	)
	mock.ExpectExec("INSERT INTO alert_audit_log").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	_, err = repository.CreateNotificationTemplate(ctx, template)
	require.NoError(t, err)

	policy := NotificationPolicy{ID: "policy-1", Scope: scope, Name: "route", Channel: "webhook", Target: "https://allowed.example/hook", SecretRef: "vault://hook", TemplateID: "template-7", Severities: []string{"critical"}, MatchLabels: map[string]string{"database": "orders"}, WindowStartUTC: "09:00", WindowEndUTC: "11:00", Enabled: true}
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO notification_policies").WithArgs("policy-1", "tenant-a", "project-a", "route", "webhook", "https://allowed.example/hook", "vault://hook", "template-7", sqlmock.AnyArg(), sqlmock.AnyArg(), "09:00", "11:00", true).WillReturnRows(
		sqlmock.NewRows(notificationPolicyColumns()).AddRow("policy-1", "tenant-a", "project-a", "route", "webhook", "https://allowed.example/hook", "vault://hook", "template-7", "{critical}", []byte(`{"database":"orders"}`), "09:00", "11:00", true, at, at),
	)
	mock.ExpectExec("INSERT INTO alert_audit_log").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	stored, err := repository.CreateNotificationPolicy(ctx, policy)
	require.NoError(t, err)
	require.Equal(t, "template-7", stored.TemplateID)
	require.Equal(t, []string{"critical"}, stored.Severities)
	require.NoError(t, mock.ExpectationsWereMet())
}

func notificationPolicyColumns() []string {
	return []string{"id", "tenant_id", "project_id", "name", "channel", "target", "secret_ref", "template_id", "severities", "match_labels", "window_start_utc", "window_end_utc", "enabled", "created_at", "updated_at"}
}

type recordingChannel struct {
	name     string
	requests []DeliveryRequest
	err      error
}

func (channel *recordingChannel) Name() string { return channel.name }
func (channel *recordingChannel) Deliver(_ context.Context, request DeliveryRequest) error {
	channel.requests = append(channel.requests, request)
	return channel.err
}

type memoryNotificationRepository struct {
	rule       AlertRule
	routes     []NotificationRoute
	silences   []Silence
	deliveries []NotificationDelivery
	audits     []AuditRecord
}

func (repository *memoryNotificationRepository) GetRule(_ context.Context, scope Scope, id string) (AlertRule, error) {
	if repository.rule.Scope != scope || repository.rule.ID != id {
		return AlertRule{}, ErrNotFound
	}
	return repository.rule, nil
}

func (repository *memoryNotificationRepository) ListNotificationRoutes(_ context.Context, scope Scope, ruleID string) ([]NotificationRoute, error) {
	if repository.rule.Scope != scope || repository.rule.ID != ruleID {
		return nil, ErrNotFound
	}
	return append([]NotificationRoute(nil), repository.routes...), nil
}

func (repository *memoryNotificationRepository) ListActiveSilences(_ context.Context, scope Scope, at time.Time) ([]Silence, error) {
	var matches []Silence
	for _, silence := range repository.silences {
		if silence.Scope == scope && !at.Before(silence.StartsAt) && at.Before(silence.EndsAt) {
			matches = append(matches, silence)
		}
	}
	return matches, nil
}

func (repository *memoryNotificationRepository) ReserveNotificationDelivery(_ context.Context, delivery NotificationDelivery, audit *AuditRecord) (bool, error) {
	for _, existing := range repository.deliveries {
		if existing.Scope == delivery.Scope && existing.IdempotencyKey == delivery.IdempotencyKey {
			return false, nil
		}
	}
	repository.deliveries = append(repository.deliveries, delivery)
	if audit != nil {
		repository.audits = append(repository.audits, *audit)
	}
	return true, nil
}

func (repository *memoryNotificationRepository) UpdateNotificationDelivery(_ context.Context, delivery NotificationDelivery, audit AuditRecord) error {
	for index := range repository.deliveries {
		if repository.deliveries[index].Scope == delivery.Scope && repository.deliveries[index].ID == delivery.ID {
			repository.deliveries[index] = delivery
			repository.audits = append(repository.audits, audit)
			return nil
		}
	}
	return ErrNotFound
}

func (repository *memoryNotificationRepository) ClaimDueNotificationDeliveries(_ context.Context, at time.Time, owner string, leaseUntil time.Time, limit int) ([]NotificationDelivery, error) {
	var due []NotificationDelivery
	for index := range repository.deliveries {
		delivery := &repository.deliveries[index]
		isDue := delivery.Status == DeliveryRetryScheduled && !delivery.NextAttemptAt.After(at)
		isExpired := delivery.Status == DeliveryAttempting && !delivery.LeaseExpiresAt.After(at)
		if isDue || isExpired {
			delivery.Status = DeliveryAttempting
			delivery.Attempts++
			delivery.AttemptedAt = at
			delivery.NextAttemptAt = time.Time{}
			delivery.LeaseOwner = owner
			delivery.LeaseExpiresAt = leaseUntil
			delivery.ClaimOwner = owner
			due = append(due, *delivery)
			if len(due) >= limit {
				break
			}
		}
	}
	return due, nil
}
