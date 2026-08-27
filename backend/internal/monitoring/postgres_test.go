package monitoring

import (
	"context"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPostgresStoreBuildsScopedInstanceFromMetricSamples(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	scope := alert.Scope{TenantID: "t1", ProjectID: "p1"}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT agent_id, metric, labels, value, sampled_at FROM metric_samples").
		WithArgs(scope.TenantID, scope.ProjectID, now.Add(-time.Hour), now).
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "metric", "labels", "value", "sampled_at"}).
			AddRow("agent-1", "host.cpu", []byte(`{"instance":"db-1","host":"db-1","component":"database","role":"primary","engine":"mysql"}`), 42.0, now.Add(-time.Minute)))

	store := NewPostgresStore(db, nil)
	store.SetNow(func() time.Time { return now })
	value, err := store.GetInstance(context.Background(), scope, "db-1", RangeQuery{From: now.Add(-time.Hour), To: now})
	require.NoError(t, err)
	require.Equal(t, "db-1", value.Instance.ID)
	require.Equal(t, "mysql", string(value.Instance.Engine))
	require.NotEmpty(t, value.Metrics)
	require.NoError(t, mock.ExpectationsWereMet())
}
