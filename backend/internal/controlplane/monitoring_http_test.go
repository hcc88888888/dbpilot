package controlplane

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/monitoring"
	"github.com/stretchr/testify/require"
)

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
