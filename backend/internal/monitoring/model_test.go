package monitoring

import (
	"context"
	"slices"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
	"github.com/stretchr/testify/require"
)

func TestRangeQueryValidateDefaultsAndRejectsMoreThanSevenDays(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	query := RangeQuery{To: now}
	require.NoError(t, query.Validate(now))
	require.Equal(t, now.Add(-time.Hour), query.From)
	require.Equal(t, time.Minute, query.Step)
	require.ErrorIs(t, (&RangeQuery{From: now.Add(-8 * 24 * time.Hour), To: now}).Validate(now), ErrRangeTooLarge)
}

func TestRangeQueryValidateRejectsTooManyBuckets(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	query := RangeQuery{From: now.Add(-time.Hour), To: now, Step: time.Second}

	require.ErrorIs(t, query.Validate(now), ErrTooManyBuckets)
}

func TestClassifySampleMarksTwoIntervalsWithoutUpdateAsStale(t *testing.T) {
	status := ClassifySample(
		time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 8, 27, 9, 29, 0, 0, time.UTC),
		15*time.Minute,
	)
	require.Equal(t, StatusStale, status)
}

func TestClassifyInstanceReturnsOfflineWhenHeartbeatIsStale(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	require.Equal(t, StatusOffline, ClassifyInstance(now, now.Add(-time.Minute), now.Add(-31*time.Minute), 15*time.Minute))
}

func TestBuildSeriesPreservesMissingBucketsAsNull(t *testing.T) {
	series := BuildSeries("host.cpu", time.Unix(0, 0).UTC(), time.Unix(120, 0).UTC(), time.Minute, []SamplePoint{{At: time.Unix(0, 0).UTC(), Value: 12}})
	require.Len(t, series.Buckets, 3)
	require.Nil(t, series.Buckets[1].Value)
}

func TestMemoryStoreOverviewDistinguishesMetricScopeSourceAndStaleWithoutZeros(t *testing.T) {
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	lastSample := now.Add(-15 * time.Minute)
	labels := map[string]string{
		"instance": "mysql-1", "host": "host-1", "engine": "mysql", "component": "dbpilot-plugin-mysql",
		"plugin_id": "mysql", "assignment_id": "assignment-1", "dbpilot_source_id": "plugin-metrics-v1:assignment-1",
	}
	samples := []alert.MetricSample{
		{Scope: scope, AgentID: "agent-1", InstanceID: "mysql-1", Host: "host-1", Name: "system.cpu.utilization", Value: 42, SampledAt: lastSample, Labels: map[string]string{"instance": "mysql-1", "host": "host-1", "component": "host"}},
		{Scope: scope, AgentID: "agent-1", InstanceID: "mysql-1", Host: "host-1", Name: "system.memory.utilization", Value: 61, SampledAt: lastSample, Labels: map[string]string{"instance": "mysql-1", "host": "host-1", "component": "host"}},
		{Scope: scope, AgentID: "agent-1", InstanceID: "mysql-1", Host: "host-1", Name: "dbpilot.plugin.collection.status", Value: 1, SampledAt: lastSample, Labels: labels},
	}
	for index, name := range MySQLBuiltinMetricIDs() {
		samples = append(samples, alert.MetricSample{Scope: scope, AgentID: "agent-1", InstanceID: "mysql-1", Host: "host-1", Name: name, Value: float64(index + 1), SampledAt: lastSample, Labels: labels})
	}
	store := NewMemoryStore([]Instance{{
		ID: "mysql-1", Scope: scope, AgentID: "agent-1", Engine: "mysql", Host: "host-1", LastSampleAt: lastSample,
		LastHeartbeatAt: now.Add(-time.Minute), CollectEvery: 5 * time.Minute,
	}}, samples, nil)
	store.SetNow(func() time.Time { return now })

	overview, err := store.Overview(context.Background(), scope, RangeQuery{From: now.Add(-time.Hour), To: now, Step: 5 * time.Minute})
	require.NoError(t, err)
	require.Len(t, overview.Metrics, 8)
	byName := make(map[string]Series, len(overview.Metrics))
	for _, series := range overview.Metrics {
		byName[series.Name] = series
		require.Equal(t, StatusStale, series.Status)
		require.Nil(t, series.Buckets[len(series.Buckets)-1].Value, "stale series must preserve a missing bucket rather than synthesize zero")
	}
	require.Equal(t, MetricScopeHost, byName["system.cpu.utilization"].Scope)
	require.Equal(t, "agent-core", byName["system.cpu.utilization"].Source)
	require.Equal(t, "host-1", byName["system.cpu.utilization"].HostID)
	require.Equal(t, MetricScopeHost, byName["system.memory.utilization"].Scope)
	require.Equal(t, MetricScopePlugin, byName["dbpilot.plugin.collection.status"].Scope)
	require.Equal(t, "assignment-1", byName["dbpilot.plugin.collection.status"].PluginAssignmentID)
	for _, name := range MySQLBuiltinMetricIDs() {
		require.Equal(t, MetricScopeDatabase, byName[name].Scope, name)
		require.Equal(t, "mysql", byName[name].Source, name)
		require.Equal(t, "mysql-1", byName[name].InstanceID, name)
	}
	require.True(t, slices.Equal(MySQLBuiltinMetricIDs(), []string{
		"mysql.connections.current", "mysql.queries.total", "mysql.threads.running", "mysql.up", "mysql.uptime.seconds",
	}))
}

func TestMemoryStoreKeepsExpectedMySQLSeriesWhenLastSamplePrecedesWindow(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	scope := alert.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	labels := map[string]string{"instance": "mysql-1", "host": "host-1", "engine": "mysql", "component": "dbpilot-plugin-mysql", "plugin_id": "mysql", "assignment_id": "assignment-1"}
	instance := Instance{ID: "mysql-1", Scope: scope, Engine: database.MySQLFamily, Host: "host-1", AgentID: "agent-1", Labels: labels, CollectEvery: time.Minute, LastSampleAt: now.Add(-2 * time.Hour), LastHeartbeatAt: now}
	samples := []alert.MetricSample{{Scope: scope, AgentID: "agent-1", InstanceID: "mysql-1", Host: "host-1", Name: "mysql.up", Value: 1, SampledAt: now.Add(-2 * time.Hour), Labels: labels}}
	store := NewMemoryStore([]Instance{instance}, samples, nil)
	store.SetNow(func() time.Time { return now })

	overview, err := store.Overview(context.Background(), scope, RangeQuery{From: now.Add(-time.Hour), To: now, Step: 15 * time.Minute})
	require.NoError(t, err)
	require.Len(t, overview.Metrics, len(MySQLBuiltinMetricIDs()))
	byName := make(map[string]Series, len(overview.Metrics))
	for _, series := range overview.Metrics {
		byName[series.Name] = series
		require.Equal(t, StatusStale, series.Status)
		require.Equal(t, MetricScopeDatabase, series.Scope)
		require.Equal(t, "mysql", series.Source)
		require.Equal(t, "assignment-1", series.PluginAssignmentID)
		require.Equal(t, "mysql-1", series.InstanceID)
		for _, bucket := range series.Buckets {
			require.Nil(t, bucket.Value)
		}
	}
	for _, name := range MySQLBuiltinMetricIDs() {
		require.Contains(t, byName, name)
	}
}

func TestInstanceDTONeverCarriesRawPayloadOrSecret(t *testing.T) {
	got := RedactInstance(Instance{Labels: map[string]string{"password": "hidden", "engine": "mysql"}, RawPayload: "secret"})
	require.NotContains(t, got.Labels, "password")
	require.Empty(t, got.RawPayload)
	require.Equal(t, "mysql", got.Labels["engine"])
}

func TestInstanceDTORedactsCommonCredentialLabelsAndInlineSecrets(t *testing.T) {
	got := RedactInstance(Instance{
		Labels:       map[string]string{"api_key": "key-1", "access_key": "key-2", "client_secret": "key-3", "engine": "mysql"},
		ErrorSummary: "collector rejected request: password=hunter2",
	})

	require.Equal(t, map[string]string{"engine": "mysql"}, got.Labels)
	require.Empty(t, got.ErrorSummary)
}

func TestInstanceDTORedactsWhitespaceSeparatedInlineSecrets(t *testing.T) {
	got := RedactInstance(Instance{
		Labels:       map[string]string{"engine": "mysql", "diagnostic": "ToKeN : abc"},
		ErrorSummary: "collector rejected request: PASSWORD = hunter2",
	})

	require.Equal(t, map[string]string{"engine": "mysql"}, got.Labels)
	require.Empty(t, got.ErrorSummary)
}

func TestMemoryStoreRejectsCrossScopeInstanceAndReturnsCopies(t *testing.T) {
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore(
		[]Instance{{ID: "db-1", Scope: scope, Labels: map[string]string{"engine": "mysql"}}},
		nil,
		nil,
	)

	page, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 10})
	require.NoError(t, err)
	page.Items[0].Labels["engine"] = "mutated"

	again, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 10})
	require.NoError(t, err)
	require.Equal(t, "mysql", again.Items[0].Labels["engine"])

	_, err = store.GetInstance(context.Background(), alert.Scope{TenantID: "tenant-b", ProjectID: "project-a"}, "db-1", validRange())
	require.ErrorIs(t, err, ErrInstanceNotFound)
}

func TestMemoryStoreDetailBuildsNullBucketsWithoutMutatingStoredDTO(t *testing.T) {
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore(
		[]Instance{{
			ID: "db-1", Scope: scope, Labels: map[string]string{"engine": "mysql", "password": "hidden"}, RawPayload: "raw",
			LastSampleAt: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC), LastHeartbeatAt: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), CollectEvery: time.Hour,
		}},
		[]alert.MetricSample{{Scope: scope, InstanceID: "db-1", Name: "host.cpu", Value: 12, SampledAt: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)}},
		nil,
	)
	store.SetNow(func() time.Time { return time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC) })

	detail, err := store.GetInstance(context.Background(), scope, "db-1", RangeQuery{From: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), Step: time.Hour})
	require.NoError(t, err)
	require.Len(t, detail.Metrics, 1)
	require.Nil(t, detail.Metrics[0].Buckets[1].Value)
	require.NotContains(t, detail.Instance.Labels, "password")
	require.Empty(t, detail.Instance.RawPayload)
}

func TestMemoryStoreDetailUsesNewestNonNilBucketForLatest(t *testing.T) {
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore(
		[]Instance{{ID: "db-1", Scope: scope, LastSampleAt: time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC), LastHeartbeatAt: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), CollectEvery: time.Hour}},
		[]alert.MetricSample{{Scope: scope, InstanceID: "db-1", Name: "host.cpu", Value: 12, SampledAt: time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC)}},
		nil,
	)
	store.SetNow(func() time.Time { return time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC) })

	detail, err := store.GetInstance(context.Background(), scope, "db-1", RangeQuery{From: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), Step: time.Hour})
	require.NoError(t, err)
	require.Nil(t, detail.Metrics[0].Buckets[1].Value)
	require.NotNil(t, detail.Instance.Latest["host.cpu"])
	require.Equal(t, 12.0, *detail.Instance.Latest["host.cpu"])
}

func TestMemoryStoreOverviewReturnsClassifiedRedactedInstances(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore([]Instance{{
		ID: "db-1", Scope: scope, Labels: map[string]string{"password": "hidden"},
		LastSampleAt: now.Add(-31 * time.Minute), LastHeartbeatAt: now, CollectEvery: 15 * time.Minute,
	}}, nil, nil)
	store.SetNow(func() time.Time { return now })

	overview, err := store.Overview(context.Background(), scope, RangeQuery{To: now})
	require.NoError(t, err)
	require.Equal(t, 1, overview.Stale)
	require.Equal(t, StatusStale, overview.Instances[0].Status)
	require.NotContains(t, overview.Instances[0].Labels, "password")
}

func TestMemoryStorePagesInStableIDOrderAndCopiesCapabilities(t *testing.T) {
	scope := alert.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	store := NewMemoryStore(
		[]Instance{{ID: "db-2", Scope: scope}, {ID: "db-1", Scope: scope}, {ID: "db-3", Scope: scope}},
		nil,
		[]Capability{{Engine: "mysql", MetricIDs: []string{"host.cpu"}}},
	)

	first, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 2})
	require.NoError(t, err)
	require.Equal(t, []string{"db-1", "db-2"}, []string{first.Items[0].ID, first.Items[1].ID})
	require.Equal(t, 2, first.NextOffset)
	second, err := store.ListInstances(context.Background(), scope, InstanceQuery{Limit: 2, Offset: first.NextOffset})
	require.NoError(t, err)
	require.Equal(t, []string{"db-3"}, []string{second.Items[0].ID})
	require.Zero(t, second.NextOffset)

	capabilities, err := store.Capabilities(context.Background(), scope)
	require.NoError(t, err)
	capabilities[0].MetricIDs[0] = "mutated"
	again, err := store.Capabilities(context.Background(), scope)
	require.NoError(t, err)
	require.Equal(t, "host.cpu", again[0].MetricIDs[0])
}

func validRange() RangeQuery {
	return RangeQuery{From: time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), Step: time.Minute}
}
