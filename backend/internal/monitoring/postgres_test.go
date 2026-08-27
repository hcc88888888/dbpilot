package monitoring

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestProductionPostgresMetricBatchHandsOffToMonitoringStoreForCoreEngines(t *testing.T) {
	for _, engine := range []database.EngineFamily{database.MySQLFamily, database.PostgresFamily, database.OracleFamily} {
		t.Run(string(engine), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			require.NoError(t, err)
			t.Cleanup(func() { _ = db.Close() })

			scope := alert.Scope{TenantID: "t1", ProjectID: "p1"}
			now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
			instanceID := string(engine) + "-1"
			labels := []byte(fmt.Sprintf(`{"component":%q,"engine":%q,"host":%q,"instance":%q,"role":"primary"}`, engine, engine, instanceID+".internal", instanceID))
			sample := alert.MetricSample{Scope: scope, AgentID: "agent-a", InstanceID: instanceID, Component: string(engine), Role: "primary", Host: instanceID + ".internal", Name: "host.cpu", Labels: map[string]string{"instance": instanceID, "engine": string(engine), "component": string(engine), "role": "primary", "host": instanceID + ".internal"}, Value: 42, SampledAt: now.Add(-time.Minute)}

			mock.ExpectBegin()
			mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO ingest_batch_dedup (agent_id, batch_id, state) VALUES ($1, $2, 'processing') ON CONFLICT DO NOTHING RETURNING state")).
				WithArgs("agent-a", "batch-"+string(engine)).
				WillReturnRows(sqlmock.NewRows([]string{"state"}).AddRow("processing"))
			mock.ExpectExec(regexp.QuoteMeta("INSERT INTO metric_samples (tenant_id, project_id, agent_id, metric, series_fingerprint, labels, value, sampled_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING")).
				WithArgs(scope.TenantID, scope.ProjectID, "agent-a", "host.cpu", sqlmock.AnyArg(), labels, 42.0, sample.SampledAt).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectExec(regexp.QuoteMeta("INSERT INTO monitoring_instances (tenant_id, project_id, instance_id, agent_id, engine, host, labels, collect_every_ns, last_sample_at, last_heartbeat_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) ON CONFLICT (tenant_id, project_id, instance_id) DO UPDATE SET agent_id = EXCLUDED.agent_id, engine = EXCLUDED.engine, host = EXCLUDED.host, labels = EXCLUDED.labels, collect_every_ns = EXCLUDED.collect_every_ns, last_sample_at = GREATEST(monitoring_instances.last_sample_at, EXCLUDED.last_sample_at), last_heartbeat_at = NOW()")).
				WithArgs(scope.TenantID, scope.ProjectID, instanceID, "agent-a", string(engine), instanceID+".internal", labels, int64(time.Minute), sample.SampledAt).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectExec(regexp.QuoteMeta("UPDATE ingest_batch_dedup SET state = 'accepted', accepted_at = NOW() WHERE agent_id = $1 AND batch_id = $2")).
				WithArgs("agent-a", "batch-"+string(engine)).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()
			first, err := alert.NewPostgresRepository(db).AppendBatch(context.Background(), "agent-a", "batch-"+string(engine), []alert.MetricSample{sample})
			require.NoError(t, err)
			require.True(t, first)

			mock.ExpectQuery(regexp.QuoteMeta(instancesSQL)).
				WithArgs(scope.TenantID, scope.ProjectID, 201).
				WillReturnRows(instanceRows().AddRow(instanceID, "agent-a", string(engine), instanceID+".internal", labels, int64(time.Minute), sample.SampledAt, now))
			mock.ExpectQuery(regexp.QuoteMeta(scopeSamplesSQL)).
				WithArgs(scope.TenantID, scope.ProjectID, now.Add(-MaximumRange), now, 10001).
				WillReturnRows(sqlmock.NewRows([]string{"agent_id", "metric", "labels", "value", "sampled_at"}).AddRow("agent-a", "host.cpu", labels, 42.0, sample.SampledAt))
			store := NewPostgresStore(db, DefaultCapabilities())
			store.SetNow(func() time.Time { return now })
			page, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 20})
			require.NoError(t, err)
			require.Len(t, page.Items, 1)
			require.Equal(t, engine, page.Items[0].Engine)
			require.NotNil(t, page.Items[0].Latest["host.cpu"])
			require.Equal(t, 42.0, *page.Items[0].Latest["host.cpu"])
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPostgresStoreBuildsScopedInstanceFromMetricSamples(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	scope := alert.Scope{TenantID: "t1", ProjectID: "p1"}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT instance_id, agent_id, engine, host, labels, collect_every_ns, last_sample_at, last_heartbeat_at FROM monitoring_instances").
		WithArgs(scope.TenantID, scope.ProjectID, "db-1").
		WillReturnRows(instanceRows().AddRow("db-1", "agent-1", "mysql", "db-1", []byte(`{"instance":"db-1","host":"db-1","component":"database","role":"primary","engine":"mysql"}`), int64(time.Minute), now.Add(-time.Minute), now.Add(-time.Minute)))
	mock.ExpectQuery("SELECT agent_id, metric, labels, value, sampled_at FROM metric_samples").
		WithArgs(scope.TenantID, scope.ProjectID, "db-1", now.Add(-time.Hour), now, 10001).
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

func TestPostgresStoreKeepsKnownInstanceWhenRangeHasNoSamples(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	scope := alert.Scope{TenantID: "t1", ProjectID: "p1"}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT instance_id, agent_id, engine, host, labels, collect_every_ns, last_sample_at, last_heartbeat_at FROM monitoring_instances WHERE tenant_id = $1 AND project_id = $2 AND instance_id = $3")).
		WithArgs(scope.TenantID, scope.ProjectID, "db-1").
		WillReturnRows(instanceRows().AddRow("db-1", "agent-1", "mysql", "db-1", []byte(`{"instance":"db-1","host":"db-1","component":"database","role":"primary"}`), int64(time.Minute), now.Add(-5*time.Minute), now.Add(-time.Minute)))
	mock.ExpectQuery("SELECT agent_id, metric, labels, value, sampled_at FROM metric_samples").
		WithArgs(scope.TenantID, scope.ProjectID, "db-1", now.Add(-time.Hour), now, 10001).
		WillReturnRows(sqlmock.NewRows([]string{"agent_id", "metric", "labels", "value", "sampled_at"}))

	store := NewPostgresStore(db, nil)
	store.SetNow(func() time.Time { return now })
	value, err := store.GetInstance(context.Background(), scope, "db-1", RangeQuery{From: now.Add(-time.Hour), To: now})
	require.NoError(t, err)
	require.Equal(t, "db-1", value.Instance.ID)
	require.Equal(t, StatusStale, value.Instance.Status)
	require.Empty(t, value.Metrics)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreRejectsOverflowBeforeAccumulatingInstances(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	scope := alert.Scope{TenantID: "t1", ProjectID: "p1"}
	rows := instanceRows()
	for index := 0; index <= 200; index++ {
		rows.AddRow(fmt.Sprintf("db-%03d", index), "agent-1", "mysql", "db-1", []byte(`{"instance":"db-1","host":"db-1","component":"database","role":"primary"}`), int64(time.Minute), time.Now().UTC(), time.Now().UTC())
	}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT instance_id, agent_id, engine, host, labels, collect_every_ns, last_sample_at, last_heartbeat_at FROM monitoring_instances WHERE tenant_id = $1 AND project_id = $2 ORDER BY instance_id ASC LIMIT $3")).
		WithArgs(scope.TenantID, scope.ProjectID, 201).WillReturnRows(rows)

	_, err = NewPostgresStore(db, nil).ListInstances(context.Background(), scope, InstanceQuery{Limit: 10})
	require.ErrorIs(t, err, ErrQueryLimit)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresStoreOverviewAndListIncludeBoundedSamples(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	scope := alert.Scope{TenantID: "t1", ProjectID: "p1"}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	state := instanceRows().AddRow("db-1", "agent-1", "mysql", "db-1", []byte(`{"instance":"db-1","host":"db-1","component":"database","role":"primary"}`), int64(time.Minute), now.Add(-time.Minute), now.Add(-time.Minute))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT instance_id, agent_id, engine, host, labels, collect_every_ns, last_sample_at, last_heartbeat_at FROM monitoring_instances WHERE tenant_id = $1 AND project_id = $2 ORDER BY instance_id ASC LIMIT $3")).WithArgs(scope.TenantID, scope.ProjectID, 201).WillReturnRows(state)
	mock.ExpectQuery("SELECT agent_id, metric, labels, value, sampled_at FROM metric_samples").WithArgs(scope.TenantID, scope.ProjectID, now.Add(-time.Hour), now, 10001).WillReturnRows(metricRows(now))

	store := NewPostgresStore(db, nil)
	store.SetNow(func() time.Time { return now })
	overview, err := store.Overview(context.Background(), scope, RangeQuery{From: now.Add(-time.Hour), To: now})
	require.NoError(t, err)
	require.NotEmpty(t, overview.Trend.Buckets)

	state = instanceRows().AddRow("db-1", "agent-1", "mysql", "db-1", []byte(`{"instance":"db-1","host":"db-1","component":"database","role":"primary"}`), int64(time.Minute), now.Add(-time.Minute), now.Add(-time.Minute))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT instance_id, agent_id, engine, host, labels, collect_every_ns, last_sample_at, last_heartbeat_at FROM monitoring_instances WHERE tenant_id = $1 AND project_id = $2 ORDER BY instance_id ASC LIMIT $3")).WithArgs(scope.TenantID, scope.ProjectID, 201).WillReturnRows(state)
	mock.ExpectQuery("SELECT agent_id, metric, labels, value, sampled_at FROM metric_samples").WithArgs(scope.TenantID, scope.ProjectID, now.Add(-MaximumRange), now, 10001).WillReturnRows(metricRows(now))
	page, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 10})
	require.NoError(t, err)
	require.NotNil(t, page.Items[0].Latest["host.cpu"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestDefaultCapabilitiesIncludeCoreSQLAdapters(t *testing.T) {
	capabilities := DefaultCapabilities()
	byEngine := make(map[string]Capability, len(capabilities))
	for _, capability := range capabilities {
		byEngine[string(capability.Engine)] = capability
	}
	for _, engine := range []string{"mysql", "postgres", "oracle"} {
		require.True(t, byEngine[engine].Metrics, engine)
	}
}

func TestPostgresStoreResponseLimitCountsEncodedNewline(t *testing.T) {
	store := NewPostgresStoreWithLimits(nil, nil, QueryLimits{MaximumResponseBytes: 12})
	require.ErrorIs(t, store.ValidateResponse(map[string]string{"value": "123"}), ErrQueryLimit)
}

func instanceRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"instance_id", "agent_id", "engine", "host", "labels", "collect_every_ns", "last_sample_at", "last_heartbeat_at"})
}

func metricRows(now time.Time) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"agent_id", "metric", "labels", "value", "sampled_at"}).AddRow("agent-1", "host.cpu", []byte(`{"instance":"db-1","host":"db-1","component":"database","role":"primary"}`), 42.0, now.Add(-time.Minute))
}
