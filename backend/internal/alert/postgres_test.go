package alert_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPostgresRepositoryScopesEventLookup(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND fingerprint = $3")).
		WithArgs("t1", "p1", "fp").
		WillReturnRows(sqlmock.NewRows(eventColumns()).AddRow("event-1", "t1", "p1", "rule-1", "fp", []byte(`{"host":"a"}`), []byte(`{"value":"80"}`), "firing", time.Now(), time.Now(), time.Now(), nil, nil, "system"))

	event, found, err := alert.NewPostgresRepository(db).FindEventByFingerprint(context.Background(), alert.Scope{TenantID: "t1", ProjectID: "p1"}, "fp")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "event-1", event.ID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRepositoryPagesEventsWithinScopeAndRule(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	at := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND rule_id = $3 ORDER BY id ASC LIMIT $4 OFFSET $5")).
		WithArgs("t1", "p1", "rule-1", 500, 500).
		WillReturnRows(sqlmock.NewRows(eventColumns()).AddRow("event-501", "t1", "p1", "rule-1", "fp-501", []byte(`{"host":"a"}`), []byte(`{}`), "pending", at, at, nil, nil, nil, "system:evaluator"))

	events, err := alert.NewPostgresRepository(db).ListRuleEvents(context.Background(), alert.Scope{TenantID: "t1", ProjectID: "p1"}, "rule-1", alert.EventFilter{Limit: 500, Offset: 500})
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "event-501", events[0].ID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRepositoryScopesEveryRuleOperation(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	repository := alert.NewPostgresRepository(db)
	ctx := context.Background()
	rule := testRule()

	mock.ExpectQuery("INSERT INTO alert_rules").WithArgs(
		"rule-1", "t1", "p1", "cpu", "host.cpu", "avg", ">", 80.0, int64(time.Minute), int64(time.Minute), "ignore", "critical", sqlmock.AnyArg(), sqlmock.AnyArg(), true, "operator-a",
	).WillReturnRows(sqlmock.NewRows(ruleColumns()).AddRow(ruleRowValues(rule)...))
	_, err = repository.CreateRule(alert.ContextWithAuditActor(ctx, "operator-a"), rule)
	require.NoError(t, err)

	mock.ExpectQuery("UPDATE alert_rules").WithArgs(
		"cpu", "host.cpu", "avg", ">", 80.0, int64(time.Minute), int64(time.Minute), "ignore", "critical", sqlmock.AnyArg(), sqlmock.AnyArg(), true, "t1", "p1", "rule-1", "operator-b",
	).WillReturnRows(sqlmock.NewRows(ruleColumns()).AddRow(ruleRowValues(rule)...))
	_, err = repository.UpdateRule(alert.ContextWithAuditActor(ctx, "operator-b"), rule)
	require.NoError(t, err)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ns, for_duration_ns, missing_data, severity, notification_policy_ids, labels, enabled, created_at, updated_at FROM alert_rules WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC")).
		WithArgs("t1", "p1").
		WillReturnRows(sqlmock.NewRows(ruleColumns()).AddRow(ruleRowValues(rule)...))
	_, err = repository.ListRules(ctx, rule.Scope)
	require.NoError(t, err)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ns, for_duration_ns, missing_data, severity, notification_policy_ids, labels, enabled, created_at, updated_at FROM alert_rules WHERE tenant_id = $1 AND project_id = $2 AND id = $3")).
		WithArgs("t1", "p1", "rule-1").
		WillReturnRows(sqlmock.NewRows(ruleColumns()).AddRow(ruleRowValues(rule)...))
	_, err = repository.GetRule(ctx, rule.Scope, "rule-1")
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRepositoryScopesEveryEventAndAuditWrite(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	repository := alert.NewPostgresRepository(db)
	ctx := context.Background()
	firstSeen := time.Now()
	event := alert.AlertEvent{ID: "event-1", Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, RuleID: "rule-1", Fingerprint: "fp", Labels: map[string]string{"host": "a"}, Evidence: map[string]string{"value": "80"}, State: alert.EventPending, FirstSeen: firstSeen, LastSeen: firstSeen, LastActor: "system"}

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock($1)")).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("FOR UPDATE").WithArgs("t1", "p1", "fp").WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery("INSERT INTO alert_events").WithArgs(
		"event-1", "t1", "p1", "rule-1", "fp", sqlmock.AnyArg(), sqlmock.AnyArg(), "pending", event.FirstSeen, event.LastSeen, nil, nil, nil, "system",
	).WillReturnRows(sqlmock.NewRows(eventColumns()).AddRow(eventRowValues(event)...))
	mock.ExpectExec("INSERT INTO alert_audit_log").WithArgs(sqlmock.AnyArg(), "t1", "p1", "system", "event.pending", "event-1", event.LastSeen, []byte(`{"state":"pending"}`)).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	_, err = repository.PutEvent(ctx, event)
	require.NoError(t, err)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor FROM alert_events WHERE tenant_id = $1 AND project_id = $2 ORDER BY last_seen DESC LIMIT $3 OFFSET $4")).
		WithArgs("t1", "p1", 25, 0).
		WillReturnRows(sqlmock.NewRows(eventColumns()).AddRow(eventRowValues(event)...))
	_, err = repository.ListEvents(ctx, event.Scope, alert.EventFilter{Limit: 25})
	require.NoError(t, err)

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at, details) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")).
		WithArgs("audit-1", "t1", "p1", "operator", "event.acknowledged", "event-1", sqlmock.AnyArg(), []byte(`{"state":"acknowledged"}`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	err = repository.AppendAudit(ctx, alert.AuditRecord{ID: "audit-1", Scope: event.Scope, Actor: "operator", Action: "event.acknowledged", TargetID: "event-1", OccurredAt: time.Now(), Details: map[string]string{"state": "acknowledged"}})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAlertControlPlaneMigrationHasScopedIndexesAndDailyMetricPartitions(t *testing.T) {
	migration, err := os.ReadFile(filepath.Join("migrations", "0001_alert_control_plane.sql"))
	require.NoError(t, err)
	content := string(migration)
	for _, table := range []string{"alert_rules", "alert_events", "notification_policies", "notification_templates", "alert_silences", "notification_deliveries", "alert_audit_log", "metric_samples"} {
		require.Contains(t, content, "CREATE TABLE "+table)
	}
	require.Contains(t, content, "PARTITION BY RANGE (sampled_at)")
	require.Contains(t, content, "FOR day_offset IN 0..6 LOOP")
	require.Contains(t, content, "(tenant_id, project_id")
	require.Contains(t, content, "series_fingerprint TEXT NOT NULL")
	require.Contains(t, content, "agent_id TEXT NOT NULL")
	require.Contains(t, content, "PRIMARY KEY (tenant_id, project_id, agent_id, metric, series_fingerprint, sampled_at)")
	require.Contains(t, content, "CHECK (state IN ('pending', 'firing', 'acknowledged', 'resolved'))")
	require.NotContains(t, content, "secret_value")
	require.NotContains(t, content, "id TEXT PRIMARY KEY")
	require.NotEqual(t, alert.SeriesFingerprint(map[string]string{"host": "db-a"}), alert.SeriesFingerprint(map[string]string{"host": "db-b"}))
}

func TestPostgresRepositoryRejectsInvalidEventsBeforeWriting(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})

	firstSeen := time.Now()
	for _, event := range []alert.AlertEvent{
		{Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, RuleID: "rule-1", Fingerprint: "fp", State: alert.EventState("unknown"), FirstSeen: firstSeen, LastSeen: firstSeen},
		{Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, RuleID: "rule-1", Fingerprint: "fp", State: alert.EventFiring, FirstSeen: firstSeen, LastSeen: firstSeen, FiringAt: firstSeen.Add(time.Nanosecond)},
	} {
		_, err = alert.NewPostgresRepository(db).PutEvent(context.Background(), event)
		require.Error(t, err)
	}
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRepositoryPreservesNanosecondRuleDurations(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	rule := testRule()
	rule.EvaluationEvery = time.Nanosecond
	rule.For = 999999 * time.Nanosecond
	mock.ExpectQuery("INSERT INTO alert_rules").WithArgs(
		"rule-1", "t1", "p1", "cpu", "host.cpu", "avg", ">", 80.0, int64(time.Nanosecond), int64(999999*time.Nanosecond), "ignore", "critical", sqlmock.AnyArg(), sqlmock.AnyArg(), true, "operator",
	).WillReturnRows(sqlmock.NewRows(ruleColumns()).AddRow(ruleRowValues(rule)...))

	stored, err := alert.NewPostgresRepository(db).CreateRule(alert.ContextWithAuditActor(context.Background(), "operator"), rule)
	require.NoError(t, err)
	require.Equal(t, time.Nanosecond, stored.EvaluationEvery)
	require.Equal(t, 999999*time.Nanosecond, stored.For)
	require.NoError(t, mock.ExpectationsWereMet())
}

func testRule() alert.AlertRule {
	return alert.AlertRule{ID: "rule-1", Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, Name: "cpu", Metric: "host.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", NotificationPolicyIDs: []string{"policy-1"}, Labels: map[string]string{"host": "a"}, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
}

func ruleColumns() []string {
	return []string{"id", "tenant_id", "project_id", "name", "metric", "aggregation", "operator", "threshold", "evaluation_every_ns", "for_duration_ns", "missing_data", "severity", "notification_policy_ids", "labels", "enabled", "created_at", "updated_at"}
}

func ruleRowValues(rule alert.AlertRule) []driver.Value {
	return []driver.Value{rule.ID, rule.Scope.TenantID, rule.Scope.ProjectID, rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, int64(rule.EvaluationEvery), int64(rule.For), rule.MissingData, rule.Severity, "{policy-1}", []byte(`{"host":"a"}`), rule.Enabled, rule.CreatedAt, rule.UpdatedAt}
}

func eventColumns() []string {
	return []string{"id", "tenant_id", "project_id", "rule_id", "fingerprint", "labels", "evidence", "state", "first_seen", "last_seen", "firing_at", "acknowledged_at", "resolved_at", "last_actor"}
}

func eventRowValues(event alert.AlertEvent) []driver.Value {
	return []driver.Value{event.ID, event.Scope.TenantID, event.Scope.ProjectID, event.RuleID, event.Fingerprint, []byte(`{"host":"a"}`), []byte(`{"value":"80"}`), string(event.State), event.FirstSeen, event.LastSeen, nullableTime(event.FiringAt), nullableTime(event.AcknowledgedAt), nullableTime(event.ResolvedAt), event.LastActor}
}

func nullableTime(value time.Time) driver.Value {
	if value.IsZero() {
		return nil
	}
	return value
}
