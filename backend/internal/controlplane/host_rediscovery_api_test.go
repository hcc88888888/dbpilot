package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/rediscovery"
	"github.com/stretchr/testify/require"
)

func TestRediscoverHostCreatesOneRecoverableAuditedJobWithExactETag(t *testing.T) {
	now := time.Date(2026, 9, 4, 4, 0, 0, 0, time.UTC)
	value := job.Job{ID: "job-rediscover-a", Type: "host.rediscover", Scope: platformTestScope, Status: job.StatusQueued, Outcome: job.OutcomeNone, TargetResourceIDs: []string{"agent-1"}, InitiatedBy: "operator", SourceResource: job.ResourceReference{ResourceType: "host", ResourceID: "host-1"}, IdempotencyKey: "internal-a", Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, RequestID: "request-a", TraceID: "trace-a"}
	service := &recordingHostRediscovery{value: value}
	audits := &recordingAuditService{}
	services := Services{HostRediscovery: service, Idempotency: idempotency.NewService(newHTTPIdempotencyStore()), Audit: audits}
	principal := principalWith(platformTestScope, openapi.PermissionRediscoverHost)

	first := servePlatformRequest(services, principal, newRediscoverHostRequest("rediscover-a"))
	second := servePlatformRequest(services, principal, newRediscoverHostRequest("rediscover-a"))

	for _, response := range []*httptest.ResponseRecorder{first, second} {
		require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
		require.Equal(t, `"1"`, response.Header().Get("ETag"))
		require.Equal(t, platformBasePath+"/jobs/job-rediscover-a", response.Header().Get("Location"))
		var body openapi.Job
		require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &body))
		require.Equal(t, "job-rediscover-a", body.Id)
		require.Equal(t, 1, body.Version)
	}
	require.Equal(t, 1, service.calls)
	require.Equal(t, platformTestScope, service.scope)
	require.Equal(t, "host-1", service.hostID)
	require.Equal(t, "trusted-user", service.request.Actor)
	require.Equal(t, 1, audits.recordCalls)
	require.Equal(t, "host.rediscovery_requested", audits.records[0].Action)
}

func TestRediscoverHostAcceptsGlobalOIDCSubjectAndOpenAPIIdempotencyKey(t *testing.T) {
	now := time.Date(2026, 9, 4, 4, 0, 0, 0, time.UTC)
	value := job.Job{ID: "job-rediscover-global", Type: "host.rediscover", Scope: platformTestScope, Status: job.StatusQueued, Outcome: job.OutcomeNone, TargetResourceIDs: []string{"agent-1"}, InitiatedBy: "https://issuer.example/subjects/user|tenant@example.com", SourceResource: job.ResourceReference{ResourceType: "host", ResourceID: "host-1"}, IdempotencyKey: "internal-global", Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, RequestID: "request-global", TraceID: "trace-global"}
	service := &recordingHostRediscovery{value: value}
	services := Services{HostRediscovery: service, Idempotency: idempotency.NewService(newHTTPIdempotencyStore()), Audit: &recordingAuditService{}}
	principal := principalWith(platformTestScope, openapi.PermissionRediscoverHost)
	principal.Subject = value.InitiatedBy
	key := "rediscover /?=+_"
	for len(key) < 128 {
		key += "x"
	}

	response := servePlatformRequest(services, principal, newRediscoverHostRequest(key))

	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	require.Equal(t, principal.Subject, service.request.Actor)
	require.Equal(t, key, service.request.IdempotencyKey)
}

func TestRediscoverHostPermissionAndCapabilityFailureDoNotCreateJob(t *testing.T) {
	service := &recordingHostRediscovery{err: rediscovery.ErrRediscoveryUnavailable}
	services := Services{HostRediscovery: service, Idempotency: idempotency.NewService(newHTTPIdempotencyStore()), Audit: &recordingAuditService{}}

	denied := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionGetHost), newRediscoverHostRequest("rediscover-denied"))
	requireProblem(t, denied, http.StatusForbidden, "forbidden", denied.Header().Get("X-Request-ID"))
	require.Zero(t, service.calls)

	unavailable := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionRediscoverHost), newRediscoverHostRequest("rediscover-unavailable"))
	requireProblem(t, unavailable, http.StatusUnprocessableEntity, "discovery_unavailable", unavailable.Header().Get("X-Request-ID"))
	require.Equal(t, 1, service.calls)
}

func newRediscoverHostRequest(key string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/hosts/host-1/actions/rediscover", nil)
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("X-Request-ID", "request-rediscover")
	return request
}

type recordingHostRediscovery struct {
	value   job.Job
	err     error
	calls   int
	scope   platformscope.Scope
	hostID  string
	request rediscovery.RediscoveryRequest
}

func (service *recordingHostRediscovery) Start(_ context.Context, scope platformscope.Scope, hostID string, request rediscovery.RediscoveryRequest) (job.Job, error) {
	service.calls++
	service.scope, service.hostID, service.request = scope, hostID, request
	return service.value, service.err
}
