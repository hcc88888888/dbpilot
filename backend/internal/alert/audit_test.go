package alert

import (
	"context"
	"database/sql/driver"
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

func TestSanitizeDetailsRedactsSecretLikeFields(t *testing.T) {
	details := map[string]string{
		"host":          "db-a",
		"password":      "unsafe",
		"api-token":     "unsafe",
		"credential_id": "unsafe",
	}

	sanitized := sanitizeDetails(details)
	require.Equal(t, "db-a", sanitized["host"])
	require.Equal(t, RedactedValue, sanitized["password"])
	require.Equal(t, RedactedValue, sanitized["api-token"])
	require.Equal(t, RedactedValue, sanitized["credential_id"])
	require.Equal(t, "unsafe", details["password"], "sanitization must not mutate caller-owned evidence")
}

func TestPostgresPutEventAndAuditCommitsTogether(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	repository := NewPostgresRepository(db)
	event, record := transactionalEventAndAudit()

	mock.ExpectBegin()
	expectEventWrite(mock, event)
	mock.ExpectExec(regexp.QuoteMeta(auditInsertSQL)).
		WithArgs(record.ID, "t1", "p1", record.Actor, record.Action, record.TargetID, record.OccurredAt, []byte(`{"aggregate":"91"}`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	stored, err := repository.PutEventAndAudit(context.Background(), event, record)
	require.NoError(t, err)
	require.Equal(t, event.ID, stored.ID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresPutEventIncludesAtomicStateAudit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	event, _ := transactionalEventAndAudit()

	mock.ExpectQuery(`(?s)WITH previous AS.*INSERT INTO alert_events.*INSERT INTO alert_audit_log.*'event\.' \|\| state`).
		WillReturnRows(sqlmock.NewRows(eventColumnNames()).AddRow(event.ID, "t1", "p1", event.RuleID, event.Fingerprint, []byte(`{"host":"a"}`), []byte(`{"aggregate":"91"}`), string(event.State), event.FirstSeen, event.LastSeen, nil, nil, nil, event.LastActor))

	_, err = NewPostgresRepository(db).PutEvent(context.Background(), event)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresPutEventAndAuditRollsBackBothWritesWhenAuditFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	repository := NewPostgresRepository(db)
	event, record := transactionalEventAndAudit()

	mock.ExpectBegin()
	expectEventWrite(mock, event)
	mock.ExpectExec(regexp.QuoteMeta(auditInsertSQL)).
		WithArgs(record.ID, "t1", "p1", record.Actor, record.Action, record.TargetID, record.OccurredAt, []byte(`{"aggregate":"91"}`)).
		WillReturnError(errors.New("audit unavailable"))
	mock.ExpectRollback()

	_, err = repository.PutEventAndAudit(context.Background(), event, record)
	require.ErrorContains(t, err, "audit unavailable")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRuleWritesIncludeImmutableAuditActions(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	repository := NewPostgresRepository(db)
	rule := ruleWithScope()

	mock.ExpectQuery(`(?s)INSERT INTO alert_rules.*INSERT INTO alert_audit_log.*rule\.created`).
		WillReturnRows(sqlmock.NewRows(ruleColumnNames()).AddRow(ruleColumnValues(rule)...))
	_, err = repository.CreateRule(context.Background(), rule)
	require.NoError(t, err)

	mock.ExpectQuery(`(?s)UPDATE alert_rules.*INSERT INTO alert_audit_log.*rule\.updated`).
		WillReturnRows(sqlmock.NewRows(ruleColumnNames()).AddRow(ruleColumnValues(rule)...))
	_, err = repository.UpdateRule(context.Background(), rule)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAuditRecordValidationRequiresImmutableIdentityAndActor(t *testing.T) {
	record := AuditRecord{ID: "audit-1", Scope: Scope{TenantID: "t1", ProjectID: "p1"}, Actor: "operator", Action: "event.acknowledged", TargetID: "event-1", OccurredAt: time.Now(), Details: map[string]string{"state": "acknowledged"}}
	require.NoError(t, record.Validate())

	record.Actor = ""
	require.ErrorIs(t, record.Validate(), ErrInvalidAuditRecord)
}

func TestAuditRecordValidationRejectsUnsanitizedSecretDetails(t *testing.T) {
	record := AuditRecord{ID: "audit-1", Scope: Scope{TenantID: "t1", ProjectID: "p1"}, Actor: "operator", Action: "event.acknowledged", TargetID: "event-1", OccurredAt: time.Now(), Details: map[string]string{"api_token": "unsafe"}}
	require.ErrorIs(t, record.Validate(), ErrInvalidAuditRecord)
}

func TestAuditRecordJSONNeverLeaksUnsanitizedSecretDetails(t *testing.T) {
	record := AuditRecord{ID: "audit-1", Scope: Scope{TenantID: "t1", ProjectID: "p1"}, Actor: "operator", Action: "event.acknowledged", TargetID: "event-1", OccurredAt: time.Now(), Details: map[string]string{"host": "db-a", "api_token": "unsafe-value"}}

	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"host":"db-a"`)
	require.NotContains(t, string(encoded), "api_token")
	require.NotContains(t, string(encoded), "unsafe-value")
}

func TestAuditMigrationStoresSanitizedDetailsAsJSONB(t *testing.T) {
	migration, err := os.ReadFile(filepath.Join("migrations", "0001_alert_control_plane.sql"))
	require.NoError(t, err)
	require.Contains(t, string(migration), "details JSONB NOT NULL DEFAULT '{}'::jsonb")
}

func transactionalEventAndAudit() (AlertEvent, AuditRecord) {
	at := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	scope := Scope{TenantID: "t1", ProjectID: "p1"}
	event := AlertEvent{ID: "event-1", Scope: scope, RuleID: "rule-1", Fingerprint: "fp", Labels: map[string]string{"host": "a"}, Evidence: map[string]string{"aggregate": "91"}, State: EventPending, FirstSeen: at, LastSeen: at, LastActor: "system:evaluator"}
	record := AuditRecord{ID: "audit-1", Scope: scope, Actor: "system:evaluator", Action: "event.pending", TargetID: event.ID, OccurredAt: at, Details: map[string]string{"aggregate": "91", "api_token": "must-not-be-persisted"}}
	return event, record
}

func expectEventWrite(mock sqlmock.Sqlmock, event AlertEvent) {
	mock.ExpectQuery("INSERT INTO alert_events").
		WithArgs(event.ID, "t1", "p1", event.RuleID, event.Fingerprint, sqlmock.AnyArg(), sqlmock.AnyArg(), event.State, event.FirstSeen, event.LastSeen, nil, nil, nil, event.LastActor).
		WillReturnRows(sqlmock.NewRows(eventColumnNames()).AddRow(event.ID, "t1", "p1", event.RuleID, event.Fingerprint, []byte(`{"host":"a"}`), []byte(`{"aggregate":"91"}`), string(event.State), event.FirstSeen, event.LastSeen, nil, nil, nil, event.LastActor))
}

func ruleWithScope() AlertRule {
	rule := defaultRule()
	rule.Scope = Scope{TenantID: "t1", ProjectID: "p1"}
	rule.CreatedAt = time.Date(2026, time.August, 26, 9, 0, 0, 0, time.UTC)
	rule.UpdatedAt = rule.CreatedAt
	return rule
}

func ruleColumnNames() []string {
	return []string{"id", "tenant_id", "project_id", "name", "metric", "aggregation", "operator", "threshold", "evaluation_every_ns", "for_duration_ns", "missing_data", "severity", "notification_policy_ids", "labels", "enabled", "created_at", "updated_at"}
}

func ruleColumnValues(rule AlertRule) []driver.Value {
	return []driver.Value{rule.ID, rule.Scope.TenantID, rule.Scope.ProjectID, rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, int64(rule.EvaluationEvery), int64(rule.For), rule.MissingData, rule.Severity, "{}", []byte(`{}`), rule.Enabled, rule.CreatedAt, rule.UpdatedAt}
}

func eventColumnNames() []string {
	return []string{"id", "tenant_id", "project_id", "rule_id", "fingerprint", "labels", "evidence", "state", "first_seen", "last_seen", "firing_at", "acknowledged_at", "resolved_at", "last_actor"}
}
