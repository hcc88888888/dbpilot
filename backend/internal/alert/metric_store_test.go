package alert_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
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
	mock.ExpectQuery(regexp.QuoteMeta("SELECT tenant_id, project_id, agent_id, metric, labels, value, sampled_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND metric = $3 AND sampled_at >= $4 AND sampled_at <= $5 ORDER BY sampled_at ASC, agent_id ASC")).
		WithArgs("t1", "p1", "db.connections", from, to).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "project_id", "agent_id", "metric", "labels", "value", "sampled_at"}).
			AddRow("t1", "p1", "agent-a", "db.connections", []byte(`{"instance":"db-1","role":"primary"}`), 12.0, from.Add(time.Minute)).
			AddRow("t1", "p1", "agent-b", "db.connections", []byte(`{"instance":"db-1","role":"primary"}`), 13.0, from.Add(time.Minute)).
			AddRow("t1", "p1", "agent-a", "db.connections", []byte(`{"instance":"db-2"}`), 20.0, from.Add(2*time.Minute)))

	samples, err := alert.NewPostgresRepository(db).Query(context.Background(), alert.MetricQuery{
		Scope:  alert.Scope{TenantID: "t1", ProjectID: "p1"},
		Name:   "db.connections",
		From:   from,
		To:     to,
		Labels: map[string]string{"instance": "db-1"},
	})
	require.NoError(t, err)
	require.Len(t, samples, 2)
	require.Equal(t, "db-1", samples[0].InstanceID)
	require.Equal(t, []string{"agent-a", "agent-b"}, []string{samples[0].AgentID, samples[1].AgentID})
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
		AgentID:   "agent-a",
		Name:      "db.connections",
		Labels:    canonicalMetricLabels(),
		Value:     12,
		SampledAt: sampledAt,
	}
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO metric_samples (tenant_id, project_id, agent_id, metric, series_fingerprint, labels, value, sampled_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING")).
		WithArgs("t1", "p1", "agent-a", "db.connections", agentSeriesFingerprint("agent-a", sample.Labels), canonicalJSON(`{"component":"postgres","host":"db-a","instance":"db-1","role":"primary"}`), 12.0, sampledAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO monitoring_instances").
		WithArgs("t1", "p1", "db-1", "agent-a", "", "db-a", canonicalJSON(`{"component":"postgres","host":"db-a","instance":"db-1","role":"primary"}`), int64(time.Minute), sampledAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO metric_samples (tenant_id, project_id, agent_id, metric, series_fingerprint, labels, value, sampled_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING")).
		WithArgs("t1", "p1", "agent-b", "db.connections", agentSeriesFingerprint("agent-b", sample.Labels), canonicalJSON(`{"component":"postgres","host":"db-a","instance":"db-1","role":"primary"}`), 12.0, sampledAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO monitoring_instances").
		WithArgs("t1", "p1", "db-1", "agent-b", "", "db-a", canonicalJSON(`{"component":"postgres","host":"db-a","instance":"db-1","role":"primary"}`), int64(time.Minute), sampledAt).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	otherAgent := sample
	otherAgent.AgentID = "agent-b"
	err = alert.NewPostgresRepository(db).Append(context.Background(), []alert.MetricSample{sample, otherAgent})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMetricStoreAppendBatchCommitsReservationAndSamplesAtomically(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { mock.ExpectClose(); require.NoError(t, db.Close()) })
	sampledAt := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	sample := alert.MetricSample{Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, AgentID: "agent-a", Name: "db.connections", Labels: canonicalMetricLabels(), Value: 12, SampledAt: sampledAt}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO ingest_batch_dedup").WithArgs("agent-a", "batch-a").WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("processing"))
	mock.ExpectExec("INSERT INTO metric_samples").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO monitoring_instances").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE ingest_batch_dedup").WithArgs("agent-a", "batch-a").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	first, err := alert.NewPostgresRepository(db).AppendBatch(context.Background(), "agent-a", "batch-a", []alert.MetricSample{sample})
	require.NoError(t, err)
	require.True(t, first)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMetricStoreAppendBatchRollsBackFailureWithoutAcknowledging(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { mock.ExpectClose(); require.NoError(t, db.Close()) })
	sample := alert.MetricSample{Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, AgentID: "agent-a", Name: "db.connections", Labels: canonicalMetricLabels(), Value: 12, SampledAt: time.Now().UTC()}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO ingest_batch_dedup").WithArgs("agent-a", "batch-a").WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("processing"))
	mock.ExpectExec("INSERT INTO metric_samples").WillReturnError(errors.New("write failed"))
	mock.ExpectRollback()

	first, err := alert.NewPostgresRepository(db).AppendBatch(context.Background(), "agent-a", "batch-a", []alert.MetricSample{sample})
	require.Error(t, err)
	require.False(t, first)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMetricStoreAppendBatchFailsClosedWhenReservationCommitIsLost(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { mock.ExpectClose(); require.NoError(t, db.Close()) })
	sample := alert.MetricSample{Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, AgentID: "agent-a", Name: "db.connections", Labels: canonicalMetricLabels(), Value: 12, SampledAt: time.Now().UTC()}

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO ingest_batch_dedup").WithArgs("agent-a", "batch-a").WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("processing"))
	mock.ExpectExec("INSERT INTO metric_samples").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("INSERT INTO monitoring_instances").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE ingest_batch_dedup").WithArgs("agent-a", "batch-a").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()

	first, err := alert.NewPostgresRepository(db).AppendBatch(context.Background(), "agent-a", "batch-a", []alert.MetricSample{sample})
	require.Error(t, err)
	require.False(t, first)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMetricStoreAppendBatchTreatsCommittedReservationAsDuplicate(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { mock.ExpectClose(); require.NoError(t, db.Close()) })

	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO ingest_batch_dedup").WithArgs("agent-a", "batch-a").WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()

	first, err := alert.NewPostgresRepository(db).AppendBatch(context.Background(), "agent-a", "batch-a", nil)
	require.NoError(t, err)
	require.False(t, first)
	require.NoError(t, mock.ExpectationsWereMet())
}

func canonicalJSON(value string) driver.Value { return []byte(value) }

func agentSeriesFingerprint(agentID string, labels map[string]string) string {
	values := make(map[string]string, len(labels)+1)
	for key, value := range labels {
		values[key] = value
	}
	values["agent_id"] = agentID
	return alert.SeriesFingerprint(values)
}

func canonicalMetricLabels() map[string]string {
	return map[string]string{"instance": "db-1", "component": "postgres", "role": "primary", "host": "db-a"}
}

func TestMetricStoreQueryDoesNotTreatMissingLabelAsEmptyValue(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() {
		mock.ExpectClose()
		require.NoError(t, db.Close())
	})
	from := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	to := from.Add(time.Hour)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT tenant_id, project_id, agent_id, metric, labels, value, sampled_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND metric = $3 AND sampled_at >= $4 AND sampled_at <= $5 ORDER BY sampled_at ASC, agent_id ASC")).
		WithArgs("t1", "p1", "db.connections", from, to).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "project_id", "agent_id", "metric", "labels", "value", "sampled_at"}).
			AddRow("t1", "p1", "agent-a", "db.connections", []byte(`{"instance":""}`), 12.0, from.Add(time.Minute)).
			AddRow("t1", "p1", "agent-b", "db.connections", []byte(`{"role":"primary"}`), 13.0, from.Add(time.Minute)))

	samples, err := alert.NewPostgresRepository(db).Query(context.Background(), alert.MetricQuery{Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"}, Name: "db.connections", Labels: map[string]string{"instance": ""}, From: from, To: to})
	require.NoError(t, err)
	require.Len(t, samples, 1)
	require.Equal(t, "agent-a", samples[0].AgentID)
	require.NoError(t, mock.ExpectationsWereMet())
}
