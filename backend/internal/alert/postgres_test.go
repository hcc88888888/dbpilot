package alert_test

import (
	"context"
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
		"rule-1", "t1", "p1", "cpu", "host.cpu", "avg", ">", 80.0, int64(time.Minute/time.Millisecond), int64(time.Minute/time.Millisecond), "ignore", "critical", sqlmock.AnyArg(), sqlmock.AnyArg(), true,
	).WillReturnRows(sqlmock.NewRows(ruleColumns()).AddRow(ruleRowValues(rule)...))
	_, err = repository.CreateRule(ctx, rule)
	require.NoError(t, err)

	mock.ExpectQuery("UPDATE alert_rules").WithArgs(
		"cpu", "host.cpu", "avg", ">", 80.0, int64(time.Minute/time.Millisecond), int64(time.Minute/time.Millisecond), "ignore", "critical", sqlmock.AnyArg(), sqlmock.AnyArg(), true, "t1", "p1", "rule-1",
	).WillReturnRows(sqlmock.NewRows(ruleColumns()).AddRow(ruleRowValues(rule)...))
	_, err = repository.UpdateRule(ctx, rule)
	require.NoError(t, err)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ms, for_duration_ms, missing_data, severity, notification_policy_ids, labels, enabled, created_at, updated_at FROM alert_rules WHERE tenant_id = $1 AND project_id = $2 ORDER BY created_at DESC")).
		WithArgs("t1", "p1").
		WillReturnRows(sqlmock.NewRows(ruleColumns()).AddRow(ruleRowValues(rule)...))
	_, err = repository.ListRules(ctx, rule.Scope)
	require.NoError(t, err)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, project_id, name, metric, aggregation, operator, threshold, evaluation_every_ms, for_duration_ms, missing_data, severity, notification_policy_ids, labels, enabled, created_at, updated_at FROM alert_rules WHERE tenant_id = $1 AND project_id = $2 AND id = $3")).
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
	event := alert.AlertEvent{ID: "event-1", Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, RuleID: "rule-1", Fingerprint: "fp", Labels: map[string]string{"host": "a"}, Evidence: map[string]string{"value": "80"}, State: alert.EventFiring, FirstSeen: time.Now(), LastSeen: time.Now(), FiringAt: time.Now(), LastActor: "system"}

	mock.ExpectQuery("INSERT INTO alert_events").WithArgs(
		"event-1", "t1", "p1", "rule-1", "fp", sqlmock.AnyArg(), sqlmock.AnyArg(), "firing", event.FirstSeen, event.LastSeen, event.FiringAt, nil, nil, "system",
	).WillReturnRows(sqlmock.NewRows(eventColumns()).AddRow(eventRowValues(event)...))
	_, err = repository.PutEvent(ctx, event)
	require.NoError(t, err)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, tenant_id, project_id, rule_id, fingerprint, labels, evidence, state, first_seen, last_seen, firing_at, acknowledged_at, resolved_at, last_actor FROM alert_events WHERE tenant_id = $1 AND project_id = $2 ORDER BY last_seen DESC LIMIT $3 OFFSET $4")).
		WithArgs("t1", "p1", 25, 0).
		WillReturnRows(sqlmock.NewRows(eventColumns()).AddRow(eventRowValues(event)...))
	_, err = repository.ListEvents(ctx, event.Scope, alert.EventFilter{Limit: 25})
	require.NoError(t, err)

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO alert_audit_log (id, tenant_id, project_id, actor, action, target_id, occurred_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")).
		WithArgs("audit-1", "t1", "p1", "operator", "acknowledge", "event-1", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	err = repository.AppendAudit(ctx, alert.AuditRecord{ID: "audit-1", Scope: event.Scope, Actor: "operator", Action: "acknowledge", TargetID: "event-1", OccurredAt: time.Now()})
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
	require.NotContains(t, content, "secret_value")
	require.NotContains(t, content, "id TEXT PRIMARY KEY")
}

func testRule() alert.AlertRule {
	return alert.AlertRule{ID: "rule-1", Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, Name: "cpu", Metric: "host.cpu", Aggregation: "avg", Operator: ">", Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute, MissingData: "ignore", Severity: "critical", NotificationPolicyIDs: []string{"policy-1"}, Labels: map[string]string{"host": "a"}, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
}

func ruleColumns() []string {
	return []string{"id", "tenant_id", "project_id", "name", "metric", "aggregation", "operator", "threshold", "evaluation_every_ms", "for_duration_ms", "missing_data", "severity", "notification_policy_ids", "labels", "enabled", "created_at", "updated_at"}
}

func ruleRowValues(rule alert.AlertRule) []driver.Value {
	return []driver.Value{rule.ID, rule.Scope.TenantID, rule.Scope.ProjectID, rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, int64(rule.EvaluationEvery / time.Millisecond), int64(rule.For / time.Millisecond), rule.MissingData, rule.Severity, "{policy-1}", []byte(`{"host":"a"}`), rule.Enabled, rule.CreatedAt, rule.UpdatedAt}
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
