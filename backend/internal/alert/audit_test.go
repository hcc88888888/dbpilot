package alert

import (
	"context"
	"database/sql"
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
	expectNoLockedEvent(mock, event)
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

	mock.ExpectBegin()
	expectNoLockedEvent(mock, event)
	expectEventWrite(mock, event)
	mock.ExpectExec(regexp.QuoteMeta(auditInsertSQL)).
		WithArgs(sqlmock.AnyArg(), "t1", "p1", event.LastActor, "event.pending", event.ID, event.LastSeen, []byte(`{"aggregate":"91","state":"pending"}`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

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
	expectNoLockedEvent(mock, event)
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
	_, err = repository.CreateRule(ContextWithAuditActor(context.Background(), "operator-a"), rule)
	require.NoError(t, err)

	mock.ExpectQuery(`(?s)UPDATE alert_rules.*INSERT INTO alert_audit_log.*rule\.updated`).
		WillReturnRows(sqlmock.NewRows(ruleColumnNames()).AddRow(ruleColumnValues(rule)...))
	_, err = repository.UpdateRule(ContextWithAuditActor(context.Background(), "operator-b"), rule)
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
	record := AuditRecord{ID: "audit-1", Scope: Scope{TenantID: "t1", ProjectID: "p1"}, Actor: "operator", Action: "event.acknowledged", TargetID: "event-1", OccurredAt: time.Now(), Details: map[string]string{"state": "acknowledged", "host": "db-a", "api_token": "unsafe-value"}}

	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"state":"acknowledged"`)
	require.NotContains(t, string(encoded), "db-a")
	require.NotContains(t, string(encoded), "api_token")
	require.NotContains(t, string(encoded), "unsafe-value")
}

func TestAuditMigrationStoresSanitizedDetailsAsJSONB(t *testing.T) {
	migration, err := os.ReadFile(filepath.Join("migrations", "0001_alert_control_plane.sql"))
	require.NoError(t, err)
	require.Contains(t, string(migration), "details JSONB NOT NULL DEFAULT '{}'::jsonb")
}

func TestPostgresRejectsIllegalStoredEventTransition(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	previous, _ := transactionalEventAndAudit()
	acknowledged := previous
	acknowledged.State = EventAcknowledged
	acknowledged.FiringAt = previous.LastSeen.Add(time.Minute)
	acknowledged.AcknowledgedAt = previous.LastSeen.Add(2 * time.Minute)
	acknowledged.LastSeen = acknowledged.AcknowledgedAt
	acknowledged.LastActor = "operator-a"
	record := AuditRecord{ID: "audit-ack", Scope: acknowledged.Scope, Actor: acknowledged.LastActor, Action: "event.acknowledged", TargetID: acknowledged.ID, OccurredAt: acknowledged.LastSeen, Details: map[string]string{"state": "acknowledged"}}

	mock.ExpectBegin()
	expectLockedEvent(mock, previous)
	mock.ExpectRollback()
	_, err = NewPostgresRepository(db).PutEventAndAudit(context.Background(), acknowledged, record)
	require.ErrorIs(t, err, ErrInvalidEventTransition)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresCommitsLegalStoredEventTransitionWithMatchingAudit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	previous, _ := transactionalEventAndAudit()
	firing, err := previous.Transition(EventFiring, previous.LastSeen.Add(time.Minute), "system:evaluator")
	require.NoError(t, err)
	firing.Scope = previous.Scope
	firing.RuleID = previous.RuleID
	firing.Fingerprint = previous.Fingerprint
	firing.ID = previous.ID
	firing.Labels = previous.Labels
	firing.Evidence = map[string]string{"aggregate": "91"}
	record := AuditRecord{ID: "audit-fire", Scope: firing.Scope, Actor: firing.LastActor, Action: "event.firing", TargetID: firing.ID, OccurredAt: firing.LastSeen, Details: map[string]string{"state": "firing", "aggregate": "91"}}

	mock.ExpectBegin()
	expectLockedEvent(mock, previous)
	expectEventWrite(mock, firing)
	mock.ExpectExec(regexp.QuoteMeta(auditInsertSQL)).
		WithArgs(record.ID, "t1", "p1", record.Actor, record.Action, record.TargetID, record.OccurredAt, []byte(`{"aggregate":"91","state":"firing"}`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	stored, err := NewPostgresRepository(db).PutEventAndAudit(context.Background(), firing, record)
	require.NoError(t, err)
	require.Equal(t, EventFiring, stored.State)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRejectsLifecycleAuditMismatch(t *testing.T) {
	event, record := transactionalEventAndAudit()
	tests := []struct {
		name   string
		mutate func(*AuditRecord)
	}{
		{name: "action", mutate: func(record *AuditRecord) { record.Action = "event.firing" }},
		{name: "actor", mutate: func(record *AuditRecord) { record.Actor = "other" }},
		{name: "time", mutate: func(record *AuditRecord) { record.OccurredAt = record.OccurredAt.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			t.Cleanup(func() {
				mock.ExpectClose()
				require.NoError(t, db.Close())
			})
			mismatched := record
			test.mutate(&mismatched)
			_, err = NewPostgresRepository(db).PutEventAndAudit(context.Background(), event, mismatched)
			require.ErrorIs(t, err, ErrInvalidAuditRecord)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestAuditDetailsStrictAllowlistScrubsFreeTextValues(t *testing.T) {
	record := AuditRecord{ID: "audit-1", Scope: Scope{TenantID: "t1", ProjectID: "p1"}, Actor: "operator", Action: "event.acknowledged", TargetID: "event-1", OccurredAt: time.Now(), Details: map[string]string{"state": "acknowledged", "reason": "password=hunter2", "note": "Bearer abc.def.ghi"}}

	encoded, err := json.Marshal(record)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"state":"acknowledged"`)
	for _, forbidden := range []string{"reason", "note", "hunter2", "Bearer", "abc.def.ghi"} {
		require.NotContains(t, string(encoded), forbidden)
	}
}

func TestPostgresAuditPersistenceUsesStrictDetailsAllowlist(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	record := AuditRecord{ID: "audit-1", Scope: Scope{TenantID: "t1", ProjectID: "p1"}, Actor: "operator", Action: "event.acknowledged", TargetID: "event-1", OccurredAt: time.Now(), Details: map[string]string{"state": "acknowledged", "reason": "postgres://user:password@db"}}
	mock.ExpectExec(regexp.QuoteMeta(auditInsertSQL)).
		WithArgs(record.ID, "t1", "p1", record.Actor, record.Action, record.TargetID, record.OccurredAt, []byte(`{"state":"acknowledged"}`)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	require.NoError(t, NewPostgresRepository(db).AppendAudit(context.Background(), record))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditRejectsInvalidTypedAllowedDetail(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	record := AuditRecord{ID: "audit-1", Scope: Scope{TenantID: "t1", ProjectID: "p1"}, Actor: "operator", Action: "event.pending", TargetID: "event-1", OccurredAt: time.Now(), Details: map[string]string{"state": "pending", "samples": "not-a-number"}}

	require.ErrorIs(t, NewPostgresRepository(db).AppendAudit(context.Background(), record), ErrInvalidAuditRecord)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRuleAuditUsesTrustedContextActor(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	rule := ruleWithScope()
	mock.ExpectQuery(`(?s)INSERT INTO alert_rules.*rule\.created`).
		WithArgs(rule.ID, "t1", "p1", rule.Name, rule.Metric, rule.Aggregation, rule.Operator, rule.Threshold, int64(rule.EvaluationEvery), int64(rule.For), rule.MissingData, rule.Severity, sqlmock.AnyArg(), sqlmock.AnyArg(), rule.Enabled, "alice").
		WillReturnRows(sqlmock.NewRows(ruleColumnNames()).AddRow(ruleColumnValues(rule)...))

	_, err = NewPostgresRepository(db).CreateRule(ContextWithAuditActor(context.Background(), "alice"), rule)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresRuleAuditRejectsMissingTrustedActor(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})

	_, err = NewPostgresRepository(db).CreateRule(context.Background(), ruleWithScope())
	require.ErrorIs(t, err, ErrMissingAuditActor)
	require.NoError(t, mock.ExpectationsWereMet())
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
		WithArgs(event.ID, "t1", "p1", event.RuleID, event.Fingerprint, sqlmock.AnyArg(), sqlmock.AnyArg(), event.State, event.FirstSeen, event.LastSeen, nullableTimestamp(event.FiringAt), nullableTimestamp(event.AcknowledgedAt), nullableTimestamp(event.ResolvedAt), event.LastActor).
		WillReturnRows(sqlmock.NewRows(eventColumnNames()).AddRow(event.ID, "t1", "p1", event.RuleID, event.Fingerprint, []byte(`{"host":"a"}`), []byte(`{"aggregate":"91"}`), string(event.State), event.FirstSeen, event.LastSeen, nullableTimestamp(event.FiringAt), nullableTimestamp(event.AcknowledgedAt), nullableTimestamp(event.ResolvedAt), event.LastActor))
}

func expectLockedEvent(mock sqlmock.Sqlmock, event AlertEvent) {
	mock.ExpectQuery(regexp.QuoteMeta(eventLockSQL)).
		WithArgs(event.Scope.TenantID, event.Scope.ProjectID, event.Fingerprint).
		WillReturnRows(sqlmock.NewRows(eventColumnNames()).AddRow(event.ID, event.Scope.TenantID, event.Scope.ProjectID, event.RuleID, event.Fingerprint, []byte(`{"host":"a"}`), []byte(`{"aggregate":"91"}`), string(event.State), event.FirstSeen, event.LastSeen, nil, nil, nil, event.LastActor))
}

func expectNoLockedEvent(mock sqlmock.Sqlmock, event AlertEvent) {
	mock.ExpectQuery(regexp.QuoteMeta(eventLockSQL)).
		WithArgs(event.Scope.TenantID, event.Scope.ProjectID, event.Fingerprint).
		WillReturnError(sql.ErrNoRows)
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
