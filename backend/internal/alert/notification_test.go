package alert

import (
	"context"
	"encoding/json"
	"errors"
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
	fx.repository.routes[0].Severities = []string{"critical"}
	fx.repository.routes[0].MatchLabels = map[string]string{"database": "orders"}
	fx.repository.routes[0].WindowStartUTC = "09:00"
	fx.repository.routes[0].WindowEndUTC = "11:00"
	fx.repository.routes[0].Template.Subject = "{{event.severity}} {{resource.database}}"
	fx.repository.routes[0].Template.Body = "{{event.id}} {{event.state}} {{evidence.aggregate}} {{event.url}}"

	require.NoError(t, fx.dispatcher.Dispatch(context.Background(), fx.event, EventFiring))
	require.Len(t, fx.channel.requests, 1)
	require.Equal(t, "critical orders", fx.channel.requests[0].Subject)
	require.Equal(t, "event-1 firing 93.5 https://dbpilot.example/alerts/event-1", fx.channel.requests[0].Body)
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
			"policy-1", "tenant-a", "project-a", "primary", "webhook", "https://allowed.example/hook", "vault://hook", true, at, at,
			"policy-1", "tenant-a", "project-a", "default", "subject", "body", at, at,
		))

	routes, err := NewPostgresRepository(database).ListNotificationRoutes(context.Background(), Scope{TenantID: "tenant-a", ProjectID: "project-a"}, "rule-1")
	require.NoError(t, err)
	require.Len(t, routes, 1)
	require.Equal(t, "vault://hook", routes[0].Policy.SecretRef)
	require.Equal(t, "policy-1", routes[0].Template.ID)
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
		delivery.ID, "tenant-a", "project-a", "event-1", "policy-1", "suppressed", fx.now, nil, sqlmock.AnyArg(),
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

func TestPostgresNotificationRepositoryRestoresDueRetryEnvelope(t *testing.T) {
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
	envelope, err := marshalDeliveryEnvelope(delivery)
	require.NoError(t, err)
	mock.ExpectQuery(regexp.QuoteMeta(dueDeliveriesSQL)).WithArgs(fx.now.Add(time.Minute)).WillReturnRows(
		sqlmock.NewRows(notificationDeliveryColumns()).AddRow(delivery.ID, "tenant-a", "project-a", "event-1", "policy-1", "retry_scheduled", fx.now, nil, envelope),
	)

	due, err := NewPostgresRepository(database).ListDueNotificationDeliveries(context.Background(), fx.now.Add(time.Minute))
	require.NoError(t, err)
	require.Len(t, due, 1)
	require.Equal(t, "secret-ref", due[0].Request.SecretRef)
	require.Equal(t, fx.now.Add(time.Minute), due[0].NextAttemptAt)
	require.NoError(t, mock.ExpectationsWereMet())
}

func notificationRouteColumns() []string {
	return []string{"policy_id", "policy_tenant_id", "policy_project_id", "policy_name", "channel", "target", "secret_ref", "enabled", "policy_created_at", "policy_updated_at", "template_id", "template_tenant_id", "template_project_id", "template_name", "subject", "body", "template_created_at", "template_updated_at"}
}

func notificationDeliveryColumns() []string {
	return []string{"id", "tenant_id", "project_id", "event_id", "policy_id", "status", "attempted_at", "delivered_at", "failure_reason"}
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
	template := NotificationTemplate{ID: "template-1", Scope: scope, Name: "default", Subject: "Alert {{event.id}}", Body: "{{event.state}}", UpdatedAt: now.Add(-time.Hour)}
	policy := NotificationPolicy{ID: "policy-1", Scope: scope, Name: "test", Channel: "test", Target: "recipient", SecretRef: "secret-ref", Enabled: true}
	repository := &memoryNotificationRepository{
		rule:   AlertRule{ID: "rule-1", Scope: scope, Name: "CPU", Metric: "cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", NotificationPolicyIDs: []string{"policy-1"}, Enabled: true},
		routes: []NotificationRoute{{Policy: policy, Template: template}},
	}
	channel := &recordingChannel{name: "test"}
	fx := &dispatchFixture{now: now, clock: now, event: event, repository: repository, channel: channel}
	fx.dispatcher = NewDispatcher(repository, []DeliveryChannel{channel}, func() time.Time { return fx.clock }, func(event AlertEvent) string { return "https://dbpilot.example/alerts/" + event.ID })
	return fx
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

func (repository *memoryNotificationRepository) ListDueNotificationDeliveries(_ context.Context, at time.Time) ([]NotificationDelivery, error) {
	var due []NotificationDelivery
	for _, delivery := range repository.deliveries {
		if delivery.Status == DeliveryRetryScheduled && !delivery.NextAttemptAt.After(at) {
			due = append(due, delivery)
		}
	}
	return due, nil
}
