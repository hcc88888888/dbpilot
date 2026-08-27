package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/monitoring"
	"github.com/stretchr/testify/require"
)

func TestMetricIngestFeedsMonitoringQueriesWithResolvedScope(t *testing.T) {
	fixture := newMonitoringIngestFixture(t)
	err := fixture.consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(`{"samples":[{"name":"host.cpu","value":42,"sampled_at":"2026-08-27T09:59:00Z","labels":{"instance":"mysql-1","engine":"mysql","component":"mysql","role":"primary","host":"mysql-1.internal"}}]}`), fixture.now)
	require.NoError(t, err)
	require.Len(t, fixture.store.samples, 1)
	require.Equal(t, fixture.scope, fixture.store.samples[0].Scope)

	result, err := fixture.store.ListInstances(context.Background(), fixture.scope, monitoring.InstanceQuery{Limit: 20})
	require.NoError(t, err)
	require.Len(t, result.Items, 1)
	require.Equal(t, "mysql-1", result.Items[0].ID)
	require.Equal(t, database.MySQLFamily, result.Items[0].Engine)

	detail, err := fixture.store.GetInstance(context.Background(), fixture.scope, "mysql-1", monitoring.RangeQuery{From: fixture.now.Add(-time.Hour), To: fixture.now, Step: time.Minute})
	require.NoError(t, err)
	require.Len(t, detail.Metrics, 1)
	require.Equal(t, "host.cpu", detail.Metrics[0].Name)
	require.Equal(t, 42.0, *detail.Metrics[0].Buckets[len(detail.Metrics[0].Buckets)-2].Value)
}

type monitoringIngestFixture struct {
	scope    alert.Scope
	now      time.Time
	store    *ingestMonitoringStore
	consumer *MetricConsumer
}

func newMonitoringIngestFixture(t *testing.T) *monitoringIngestFixture {
	t.Helper()
	scope := alert.Scope{TenantID: "t1", ProjectID: "p1"}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	store := &ingestMonitoringStore{now: now}
	return &monitoringIngestFixture{
		scope:    scope,
		now:      now,
		store:    store,
		consumer: NewMetricConsumer(staticAgentScopeResolver{"agent-a": scope}, store),
	}
}

type staticAgentScopeResolver map[string]alert.Scope

func (r staticAgentScopeResolver) ScopeForAgent(_ context.Context, agentID string) (alert.Scope, error) {
	scope, ok := r[agentID]
	if !ok {
		return alert.Scope{}, alert.ErrNotFound
	}
	return scope, nil
}

// ingestMonitoringStore is a test-only bridge proving that the consumer's
// resolved samples are the records supplied to the monitoring query contract.
type ingestMonitoringStore struct {
	mu      sync.RWMutex
	now     time.Time
	samples []alert.MetricSample
}

func (s *ingestMonitoringStore) Append(_ context.Context, samples []alert.MetricSample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples = append(s.samples, samples...)
	return nil
}

func (s *ingestMonitoringStore) Query(_ context.Context, query alert.MetricQuery) ([]alert.MetricSample, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]alert.MetricSample, 0)
	for _, sample := range s.samples {
		if sample.Scope != query.Scope || sample.Name != query.Name || sample.SampledAt.Before(query.From) || sample.SampledAt.After(query.To) {
			continue
		}
		result = append(result, sample)
	}
	return result, nil
}

func (s *ingestMonitoringStore) monitoringStore() *monitoring.MemoryStore {
	s.mu.RLock()
	samples := append([]alert.MetricSample(nil), s.samples...)
	s.mu.RUnlock()
	instances := make(map[string]monitoring.Instance)
	for _, sample := range samples {
		key := sample.Scope.TenantID + "/" + sample.Scope.ProjectID + "/" + sample.InstanceID
		instance := instances[key]
		if instance.ID == "" {
			instance = monitoring.Instance{ID: sample.InstanceID, Scope: sample.Scope, Engine: database.EngineFamily(sample.Labels["engine"]), Host: sample.Host, AgentID: sample.AgentID, Labels: sample.Labels, CollectEvery: time.Minute}
		}
		if sample.SampledAt.After(instance.LastSampleAt) {
			instance.LastSampleAt = sample.SampledAt
		}
		instance.LastHeartbeatAt = s.now
		instances[key] = instance
	}
	values := make([]monitoring.Instance, 0, len(instances))
	for _, instance := range instances {
		values = append(values, instance)
	}
	store := monitoring.NewMemoryStore(values, samples, nil)
	store.SetNow(func() time.Time { return s.now })
	return store
}

func (s *ingestMonitoringStore) Overview(ctx context.Context, scope alert.Scope, query monitoring.RangeQuery) (monitoring.Overview, error) {
	return s.monitoringStore().Overview(ctx, scope, query)
}

func (s *ingestMonitoringStore) ListInstances(ctx context.Context, scope alert.Scope, query monitoring.InstanceQuery) (monitoring.InstancePage, error) {
	return s.monitoringStore().ListInstances(ctx, scope, query)
}

func (s *ingestMonitoringStore) GetInstance(ctx context.Context, scope alert.Scope, instanceID string, query monitoring.RangeQuery) (monitoring.InstanceDetail, error) {
	return s.monitoringStore().GetInstance(ctx, scope, instanceID, query)
}

func (s *ingestMonitoringStore) Series(ctx context.Context, scope alert.Scope, query monitoring.SeriesQuery) (monitoring.Series, error) {
	return s.monitoringStore().Series(ctx, scope, query)
}

func (s *ingestMonitoringStore) Capabilities(ctx context.Context, scope alert.Scope) ([]monitoring.Capability, error) {
	return s.monitoringStore().Capabilities(ctx, scope)
}

func TestMonitoringRoutesUseScopeAndRejectCrossProjectInstance(t *testing.T) {
	fixture := monitoringFixture(t)
	response := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/monitoring/overview?from=2026-08-27T09:00:00Z&to=2026-08-27T10:00:00Z", memberFor("t1", "p1"))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var overview struct {
		Source string      `json:"source"`
		Scope  alert.Scope `json:"scope"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &overview))
	require.Equal(t, "control-plane", overview.Source)
	require.Equal(t, fixture.scope, overview.Scope)

	response = fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/monitoring/instances/other?from=2026-08-27T09:00:00Z&to=2026-08-27T10:00:00Z", memberFor("t1", "p1"))
	require.Equal(t, http.StatusNotFound, response.Code)
	require.Contains(t, response.Body.String(), `"code":"not_found"`)

	response = fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/monitoring/overview", memberFor("t1", "p2"))
	require.Equal(t, http.StatusForbidden, response.Code)
	require.Contains(t, response.Body.String(), `"code":"forbidden"`)
}

func TestMonitoringRoutesRejectRangeAndQueryOverflow(t *testing.T) {
	fixture := monitoringFixture(t)
	for _, path := range []string{
		"/api/v1/tenants/t1/projects/p1/monitoring/series?instance_id=db-1&metric=host.cpu&from=2026-08-01T00:00:00Z&to=2026-08-10T00:00:00Z",
		"/api/v1/tenants/t1/projects/p1/monitoring/overview?from=not-a-time&to=2026-08-27T10:00:00Z",
		"/api/v1/tenants/t1/projects/p1/monitoring/series?instance_id=db-1&metric=host.cpu&from=2026-08-27T09:00:00Z&to=2026-08-27T10:00:00Z&step=0s",
		"/api/v1/tenants/t1/projects/p1/monitoring/instances?limit=201",
		"/api/v1/tenants/t1/projects/p1/monitoring/instances?offset=-1",
		"/api/v1/tenants/t1/projects/p1/monitoring/instances?status=unknown",
		"/api/v1/tenants/t1/projects/p1/monitoring/instances?engine=untrusted",
	} {
		response := fixture.request(http.MethodGet, path, memberFor("t1", "p1"))
		require.Equal(t, http.StatusBadRequest, response.Code, path+": "+response.Body.String())
		require.Contains(t, response.Body.String(), `"code":"invalid_request"`)
	}
}

func TestMonitoringResponseMarksMissingValueNullAndStaleInstance(t *testing.T) {
	fixture := monitoringFixture(t)
	response := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/monitoring/instances/db-1?from=2026-08-27T09:00:00Z&to=2026-08-27T10:00:00Z", memberFor("t1", "p1"))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), `"status":"stale"`)
	require.Contains(t, response.Body.String(), `"value":null`)
	require.NotContains(t, response.Body.String(), "raw-payload")
	require.NotContains(t, response.Body.String(), "secret-token")
}

func TestMonitoringRoutesReturnInstancesSeriesAndCapabilities(t *testing.T) {
	fixture := monitoringFixture(t)
	cases := []string{
		"/api/v1/tenants/t1/projects/p1/monitoring/instances?status=stale&engine=mysql&limit=1&offset=0",
		"/api/v1/tenants/t1/projects/p1/monitoring/series?instance_id=db-1&metric=host.cpu&from=2026-08-27T09:00:00Z&to=2026-08-27T10:00:00Z&step=30m",
		"/api/v1/tenants/t1/projects/p1/monitoring/capabilities",
	}
	for _, path := range cases {
		response := fixture.request(http.MethodGet, path, memberFor("t1", "p1"))
		require.Equal(t, http.StatusOK, response.Code, path+": "+response.Body.String())
		require.Contains(t, response.Body.String(), `"source":"control-plane"`)
		require.Contains(t, response.Body.String(), `"scope":{"tenant_id":"t1","project_id":"p1"}`)
	}
}

func TestMonitoringQueryLimitErrorIsStableAndRedacted(t *testing.T) {
	response := httptest.NewRecorder()
	monitoringAPIError(response, monitoring.ErrQueryLimit)
	require.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
	require.JSONEq(t, `{"error":{"code":"query_limit_exceeded","message":"monitoring query exceeds configured limit"}}`, response.Body.String())
}

func TestMonitoringHTTPResponseLimitAppliesToMemoryStoreEnvelopeAndNewline(t *testing.T) {
	fixture := monitoringFixture(t)
	value := monitoringCapabilitiesResponse{Source: monitoringSource, Scope: fixture.scope, Items: []monitoring.Capability{{Engine: database.MySQLFamily, Metrics: true, MetricIDs: []string{"host.cpu"}}}}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	handler := NewHTTPHandler(Services{Repository: newHTTPFixture().repository, Evaluator: healthyEvaluator{}, Monitoring: fixture.store, MonitoringResponseBytes: len(encoded), Now: func() time.Time { return fixture.now }}, memberFor("t1", "p1"))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/tenants/t1/projects/p1/monitoring/capabilities", nil))
	require.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
	require.Contains(t, response.Body.String(), `"code":"query_limit_exceeded"`)
}

type monitoringHTTPFixture struct {
	scope   alert.Scope
	now     time.Time
	store   monitoring.QueryStore
	handler http.Handler
}

func monitoringFixture(t *testing.T) *monitoringHTTPFixture {
	t.Helper()
	scope := alert.Scope{TenantID: "t1", ProjectID: "p1"}
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	store := monitoring.NewMemoryStore([]monitoring.Instance{
		{ID: "db-1", Scope: scope, Engine: database.MySQLFamily, Labels: map[string]string{"engine": "mysql", "token": "secret-token"}, LastSampleAt: now.Add(-15 * time.Minute), LastHeartbeatAt: now.Add(-time.Minute), CollectEvery: 5 * time.Minute, RawPayload: "raw-payload", Secret: "secret-token"},
		{ID: "other", Scope: alert.Scope{TenantID: "t1", ProjectID: "p2"}, Engine: database.PostgresFamily, LastSampleAt: now, LastHeartbeatAt: now, CollectEvery: time.Minute},
	}, []alert.MetricSample{
		{Scope: scope, AgentID: "agent-1", InstanceID: "db-1", Name: "host.cpu", Value: 42, SampledAt: now.Add(-15 * time.Minute), Labels: map[string]string{"instance": "db-1", "host": "db-1", "component": "database", "role": "primary"}},
	}, []monitoring.Capability{{Engine: database.MySQLFamily, Metrics: true, MetricIDs: []string{"host.cpu"}}})
	store.SetNow(func() time.Time { return now })
	return &monitoringHTTPFixture{scope: scope, now: now, store: store, handler: NewHTTPHandler(Services{Repository: newHTTPFixture().repository, Evaluator: healthyEvaluator{}, Monitoring: store, Now: func() time.Time { return now }}, memberFor("t1", "p1"))}
}

func (fixture *monitoringHTTPFixture) request(method, path string, resolver PrincipalResolver) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(method, path, bytes.NewReader(nil))
	NewHTTPHandler(Services{Repository: newHTTPFixture().repository, Evaluator: healthyEvaluator{}, Monitoring: fixture.store, Now: func() time.Time { return fixture.now }}, resolver).ServeHTTP(response, request)
	return response
}
