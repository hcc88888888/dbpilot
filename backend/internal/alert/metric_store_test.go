package alert_test

import (
	"context"
	"database/sql/driver"
	"regexp"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestMetricStoreQueryFiltersScopeMetricLabelsAndWindow(t *testing.T) {
	// A query that omits any of these filters could return a different
	// tenant's data or an unrelated metric series.
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})

	from := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT tenant_id, project_id, metric, labels, value, sampled_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND metric = $3 AND sampled_at >= $4 AND sampled_at <= $5 ORDER BY sampled_at ASC")).
		WithArgs("t1", "p1", "db.connections", from, to).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "project_id", "metric", "labels", "value", "sampled_at"}).
			AddRow("t1", "p1", "db.connections", []byte(`{"instance":"db-1","role":"primary"}`), 12.0, from.Add(time.Minute)).
			AddRow("t1", "p1", "db.connections", []byte(`{"instance":"db-2"}`), 20.0, from.Add(2*time.Minute)))

	samples, err := alert.NewPostgresRepository(db).Query(context.Background(), alert.MetricQuery{
		Scope:  alert.Scope{TenantID: "t1", ProjectID: "p1"},
		Name:   "db.connections",
		From:   from,
		To:     to,
		Labels: map[string]string{"instance": "db-1"},
	})
	require.NoError(t, err)
	require.Len(t, samples, 1)
	require.Equal(t, "db-1", samples[0].InstanceID)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMetricStoreAppendUsesScopedSeriesIdentityAndCanonicalLabels(t *testing.T) {
	// Removing series identity or scope from the insert would collide unrelated
	// samples; serializing labels without canonical JSON breaks stable writes.
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})

	sampledAt := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	sample := alert.MetricSample{
		Scope:     alert.Scope{TenantID: "t1", ProjectID: "p1"},
		Name:      "db.connections",
		Labels:    map[string]string{"role": "primary", "instance": "db-1"},
		Value:     12,
		SampledAt: sampledAt,
	}
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO metric_samples (tenant_id, project_id, metric, series_fingerprint, labels, value, sampled_at) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING")).
		WithArgs("t1", "p1", "db.connections", alert.SeriesFingerprint(sample.Labels), canonicalJSON(`{"instance":"db-1","role":"primary"}`), 12.0, sampledAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = alert.NewPostgresRepository(db).Append(context.Background(), []alert.MetricSample{sample})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func canonicalJSON(value string) driver.Value { return []byte(value) }
