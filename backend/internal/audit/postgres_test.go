package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPostgresStoreAppendPersistsAppendOnlyEvent(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	value := validEvent()
	value.ID = "audit-1"
	value.OccurredAt = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	value.CreatedAt = value.OccurredAt
	value.Detail = map[string]any{"count": float64(2)}
	mock.ExpectExec("INSERT INTO audit_events").WithArgs(
		value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.OccurredAt, value.Action,
		value.Actor.Type, value.Actor.ID, value.Resource.Type, value.Resource.ID, value.Result,
		value.RequestID, value.TraceID, value.JobID, value.CommandID, []byte(`{"count":2}`), value.CreatedAt,
	).WillReturnResult(sqlmock.NewResult(0, 1))

	require.NoError(t, NewPostgresStore(database).Append(context.Background(), value))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestServiceRecordPersistsSystemSQLEvidenceThroughPostgresStore(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	value := validEvent()
	value.Detail = map[string]any{"sql_text": "select 1"}
	service := NewService(NewPostgresStore(database))
	service.now = func() time.Time { return now }
	service.newID = func() (string, error) { return "audit-sql", nil }
	expectedDetail := []byte(`{"sql_evidence":[{"digest":"sha256:822ae07d4783158bc1912bb623e5107cc9002d519e1143a9c200ed6ee18b6d0f","source_field":"sql_text","summary":"SELECT statement"}]}`)
	mock.ExpectExec("INSERT INTO audit_events").WithArgs(
		"audit-sql", value.Scope.TenantID, value.Scope.ProjectID, now, value.Action,
		value.Actor.Type, value.Actor.ID, value.Resource.Type, value.Resource.ID, value.Result,
		value.RequestID, value.TraceID, value.JobID, value.CommandID, expectedDetail, now,
	).WillReturnResult(sqlmock.NewResult(0, 1))

	_, err = service.Record(context.Background(), value)
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreRejectsEveryRawSQLFieldShapeBeforeExec(t *testing.T) {
	values := map[string]struct {
		key   string
		value any
	}{
		"typed slice": {key: "query", value: []string{"select password from users"}},
		"object":      {key: "sql", value: map[string]any{"text": "select password from users"}},
		"number":      {key: "statement", value: 7},
		"boolean":     {key: "sql_text", value: true},
		"null":        {key: "query", value: nil},
	}
	for name, fixture := range values {
		for _, nested := range []bool{false, true} {
			depth := "root"
			detail := map[string]any{fixture.key: fixture.value}
			if nested {
				depth = "nested"
				detail = map[string]any{"operation": detail}
			}
			t.Run(name+"/"+depth, func(t *testing.T) {
				database, _, err := sqlmock.New()
				require.NoError(t, err)
				t.Cleanup(func() { _ = database.Close() })
				value := validEvent()
				value.ID = "audit-invalid-sql"
				value.OccurredAt = time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
				value.CreatedAt = value.OccurredAt
				value.Detail = detail

				err = NewPostgresStore(database).Append(context.Background(), value)
				require.ErrorIs(t, err, ErrInvalidEvent)
			})
		}
	}
}

func TestPostgresStoreListUsesScopeAndTupleCursor(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	after := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT .* FROM audit_events WHERE tenant_id = \\$1 AND project_id = \\$2 AND \\(created_at, id\\) > \\(\\$3, \\$4\\) ORDER BY created_at ASC, id ASC LIMIT \\$5").
		WithArgs(scope.TenantID, scope.ProjectID, after, "audit-1", 11).
		WillReturnRows(sqlmock.NewRows(auditColumnNames()).AddRow("audit-2", scope.TenantID, scope.ProjectID, after.Add(time.Second), "inspection.finished", "user", "operator-1", "inspection", "inspection-1", "succeeded", "request-1", "trace-1", "job-1", "command-1", []byte(`{"rows":3}`), after.Add(time.Second)))

	items, err := NewPostgresStore(database).List(context.Background(), scope, StoreListQuery{After: after, AfterID: "audit-1", Limit: 11})
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, scope, items[0].Scope)
	require.Equal(t, time.UTC, items[0].OccurredAt.Location())
	require.Equal(t, json.Number("3"), items[0].Detail["rows"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreListWithoutCursorStillRequiresExactScope(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	mock.ExpectQuery("SELECT .* FROM audit_events WHERE tenant_id = \\$1 AND project_id = \\$2 ORDER BY created_at ASC, id ASC LIMIT \\$3").WithArgs(scope.TenantID, scope.ProjectID, 10).WillReturnRows(sqlmock.NewRows(auditColumnNames()))

	items, err := NewPostgresStore(database).List(context.Background(), scope, StoreListQuery{Limit: 10})
	require.NoError(t, err)
	require.Empty(t, items)
	require.NoError(t, mock.ExpectationsWereMet())
}
