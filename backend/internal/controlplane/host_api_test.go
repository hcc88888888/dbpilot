package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestManagedHostListUsesGeneratedPermissionExactScopeAndPagination(t *testing.T) {
	hosts := &recordingHostService{listValue: hostinventory.Page{Items: []hostinventory.Host{validManagedHost()}, NextCursor: "host-1"}}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/hosts?status=stale&cursor=host-0&limit=1", nil)
	response := servePlatformRequest(Services{Hosts: hosts}, principalWith(platformTestScope, openapi.PermissionListHosts), request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, platformTestScope, hosts.listScope)
	require.Equal(t, hostinventory.HostStale, hosts.listFilter.Status)
	require.Equal(t, "host-0", hosts.listFilter.Cursor)
	require.Equal(t, 1, hosts.listFilter.Limit)
	var body openapi.ManagedHostPage
	require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &body))
	require.Len(t, body.Items, 1)
	require.Equal(t, "host-1", body.Items[0].HostId)
	require.Equal(t, openapi.HostStatusOnline, body.Items[0].Status)
	require.Equal(t, `"2"`, body.Items[0].Etag)
	require.True(t, body.Page.HasMore)
	require.Equal(t, 1, body.Page.Limit)
	require.NotNil(t, body.Page.NextCursor)
	require.Equal(t, "host-1", *body.Page.NextCursor)
	requireOpenAPIResponse(t, request, response)

	denied := servePlatformRequest(Services{Hosts: hosts}, principalWith(platformTestScope, openapi.PermissionGetJob), httptest.NewRequest(http.MethodGet, platformBasePath+"/hosts", nil))
	requireProblem(t, denied, http.StatusForbidden, "forbidden", denied.Header().Get("X-Request-ID"))
	require.Equal(t, 1, hosts.listCalls)
}

func TestManagedHostGetReturnsGeneratedDTOAndETag(t *testing.T) {
	hosts := &recordingHostService{getValue: validManagedHost()}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/hosts/host-1", nil)
	response := servePlatformRequest(Services{Hosts: hosts}, principalWith(platformTestScope, openapi.PermissionGetHost), request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, `"2"`, response.Header().Get("ETag"))
	require.Equal(t, platformTestScope, hosts.getScope)
	require.Equal(t, "host-1", hosts.getID)
	var body openapi.ManagedHost
	require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &body))
	require.Equal(t, "agent-1", body.AgentId)
	require.Equal(t, int64(1), body.EnrollmentRevision)
	require.NotNil(t, body.LastHeartbeatAt)
	requireOpenAPIResponse(t, request, response)
}

func TestManagedHostDecommissionUsesETagIdempotencyAndAuditOnce(t *testing.T) {
	host := validManagedHost()
	host.Status, host.Version = hostinventory.HostDecommissioned, 3
	hosts := &recordingHostService{decommissionValue: host}
	audits := &recordingAuditService{}
	services := Services{Hosts: hosts, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
	principal := principalWith(platformTestScope, openapi.PermissionDecommissionHost)
	request := newDecommissionHostRequest(`"2"`, "decommission-host-1")
	request.Header.Set("X-Request-ID", "request-host-decommission")

	first := servePlatformRequest(services, principal, request)
	second := servePlatformRequest(services, principal, newDecommissionHostRequest(`"2"`, "decommission-host-1"))

	for _, response := range []*httptest.ResponseRecorder{first, second} {
		require.Equal(t, http.StatusOK, response.Code, response.Body.String())
		require.Equal(t, `"3"`, response.Header().Get("ETag"))
		var body openapi.ManagedHost
		require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &body))
		require.Equal(t, openapi.HostStatusDecommissioned, body.Status)
	}
	require.Equal(t, 1, hosts.decommissionCalls)
	require.Equal(t, platformTestScope, hosts.decommissionScope)
	require.Equal(t, "host-1", hosts.decommissionID)
	require.Equal(t, uint64(2), hosts.decommissionVersion)
	require.Equal(t, 1, audits.recordCalls)
	require.Len(t, audits.records, 1)
	require.Equal(t, "host.decommissioned", audits.records[0].Action)
	require.Equal(t, "host", audits.records[0].Resource.Type)
	require.Equal(t, "host-1", audits.records[0].Resource.ID)
}

func TestManagedHostDecommissionMapsVersionConflictToPreconditionAndAbortsClaim(t *testing.T) {
	hosts := &recordingHostService{decommissionErr: hostinventory.ErrConflict}
	store := newHTTPIdempotencyStore()
	request := newDecommissionHostRequest(`"2"`, "decommission-conflict")
	response := servePlatformRequest(
		Services{Hosts: hosts, Idempotency: idempotency.NewService(store)},
		principalWith(platformTestScope, openapi.PermissionDecommissionHost),
		request,
	)

	requireProblem(t, response, http.StatusPreconditionFailed, "precondition_failed", response.Header().Get("X-Request-ID"))
	require.Equal(t, 1, store.abortCalls)
}

func TestManagedHostDecommissionRetryRecoversCommittedSideEffectAndAudit(t *testing.T) {
	host := validManagedHost()
	host.Status, host.Version = hostinventory.HostDecommissioned, 3
	hosts := &recordingHostService{getValue: host, decommissionValue: host}
	audits := &recordingAuditService{}
	store := newHTTPIdempotencyStore()
	store.completeErr = errors.New("simulated crash gap")
	services := Services{Hosts: hosts, Audit: audits, Idempotency: idempotency.NewService(store)}
	principal := principalWith(platformTestScope, openapi.PermissionDecommissionHost)

	first := servePlatformRequest(services, principal, newDecommissionHostRequest(`"2"`, "decommission-recover"))
	requireProblem(t, first, http.StatusInternalServerError, "internal_error", first.Header().Get("X-Request-ID"))
	require.Equal(t, 1, hosts.decommissionCalls)
	require.Zero(t, audits.recordCalls)

	store.completeErr = nil
	retry := servePlatformRequest(services, principal, newDecommissionHostRequest(`"2"`, "decommission-recover"))
	require.Equal(t, http.StatusOK, retry.Code, retry.Body.String())
	require.Equal(t, `"3"`, retry.Header().Get("ETag"))
	require.Equal(t, 1, hosts.decommissionCalls, "processing recovery must not repeat the CAS side effect")
	require.Equal(t, 1, audits.recordCalls)
}

func TestManagedHostDecommissionRecoveryRejectsCompetingActorTransition(t *testing.T) {
	host := validManagedHost()
	hosts := &competingHostService{host: host, failNext: errors.New("request A stopped before CAS")}
	audits := &recordingAuditService{}
	services := Services{Hosts: hosts, Audit: audits, Idempotency: idempotency.NewService(newHTTPIdempotencyStore())}
	actorA := principalWith(platformTestScope, openapi.PermissionDecommissionHost)
	actorA.Subject = "operator-a"
	actorB := principalWith(platformTestScope, openapi.PermissionDecommissionHost)
	actorB.Subject = "operator-b"

	firstA := servePlatformRequest(services, actorA, newDecommissionHostRequest(`"2"`, "request-a"))
	requireProblem(t, firstA, http.StatusInternalServerError, "internal_error", firstA.Header().Get("X-Request-ID"))

	requestB := servePlatformRequest(services, actorB, newDecommissionHostRequest(`"2"`, "request-b"))
	require.Equal(t, http.StatusOK, requestB.Code, requestB.Body.String())
	require.Equal(t, `"3"`, requestB.Header().Get("ETag"))
	require.Len(t, audits.records, 1)
	require.Equal(t, "operator-b", audits.records[0].Actor.ID)

	retryA := servePlatformRequest(services, actorA, newDecommissionHostRequest(`"2"`, "request-a"))
	requireProblem(t, retryA, http.StatusConflict, "idempotency_in_progress", retryA.Header().Get("X-Request-ID"))
	require.Equal(t, 2, hosts.decommissionCalls, "A retry must not repeat CAS after B owns the transition")
	require.Len(t, audits.records, 1, "A must not Audit B's transition")
}

func TestManagedHostHandlersRejectOutOfScopeServiceValues(t *testing.T) {
	host := validManagedHost()
	host.Scope.ProjectID = "other-project"
	hosts := &recordingHostService{getValue: host}
	response := servePlatformRequest(
		Services{Hosts: hosts},
		principalWith(platformTestScope, openapi.PermissionGetHost),
		httptest.NewRequest(http.MethodGet, platformBasePath+"/hosts/host-1", nil),
	)
	requireProblem(t, response, http.StatusInternalServerError, "internal_error", response.Header().Get("X-Request-ID"))
}

func newDecommissionHostRequest(ifMatch, idempotencyKey string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/hosts/host-1/actions/decommission", nil)
	request.Header.Set("If-Match", ifMatch)
	request.Header.Set("Idempotency-Key", idempotencyKey)
	return request
}

func validManagedHost() hostinventory.Host {
	now := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	return hostinventory.Host{
		Scope: platformTestScope, ID: "host-1", AgentID: "agent-1", DisplayName: "DB host", Hostname: "db-1.example",
		OperatingSystem: "linux", OperatingSystemVersion: "kylin-v10", KernelVersion: "5.10", Architecture: "amd64",
		CPU: hostinventory.ResourceSummary{Capacity: 8, Available: 2}, Memory: hostinventory.ResourceSummary{Capacity: 1024, Available: 512},
		Filesystems:      []hostinventory.FilesystemSummary{{MountPoint: "/", CapacityBytes: 1024, AvailableBytes: 512}},
		NetworkAddresses: []string{"10.0.0.1"}, Labels: map[string]string{"role": "database"}, ContainerRuntime: hostinventory.ContainerRuntimeNone,
		Capabilities: []hostinventory.Capability{{Name: "host.collect", Available: true}}, AgentVersion: "1.0.0",
		EnrollmentRevision: 1, ObservationRevision: 2, EnrolledAt: now.Add(-time.Hour), LastHeartbeatAt: now.Add(-time.Minute),
		Status: hostinventory.HostOnline, Version: 2,
	}
}

type recordingHostService struct {
	listValue              hostinventory.Page
	listErr                error
	listScope              platformscope.Scope
	listFilter             hostinventory.Filter
	listCalls              int
	getValue               hostinventory.Host
	getErr                 error
	getScope               platformscope.Scope
	getID                  string
	decommissionValue      hostinventory.Host
	decommissionErr        error
	decommissionScope      platformscope.Scope
	decommissionID         string
	decommissionVersion    uint64
	decommissionTransition hostinventory.DecommissionTransition
	decommissionCalls      int
}

func (service *recordingHostService) RecordObservation(context.Context, hostinventory.Observation) (hostinventory.Host, error) {
	return hostinventory.Host{}, errors.New("unexpected observation")
}

func (service *recordingHostService) List(_ context.Context, scope platformscope.Scope, filter hostinventory.Filter) (hostinventory.Page, error) {
	service.listCalls++
	service.listScope, service.listFilter = scope, filter
	return service.listValue, service.listErr
}

func (service *recordingHostService) Get(_ context.Context, scope platformscope.Scope, id string) (hostinventory.Host, error) {
	service.getScope, service.getID = scope, id
	return service.getValue, service.getErr
}

func (service *recordingHostService) Decommission(ctx context.Context, scope platformscope.Scope, id string, version uint64) (hostinventory.Host, error) {
	service.decommissionCalls++
	service.decommissionScope, service.decommissionID, service.decommissionVersion = scope, id, version
	transition, ok := hostinventory.DecommissionTransitionFromContext(ctx)
	if !ok {
		return hostinventory.Host{}, hostinventory.ErrInvalid
	}
	service.decommissionTransition = transition
	value := service.decommissionValue
	if service.decommissionErr == nil {
		value.DecommissionTransition = &transition
		service.getValue = value
	}
	return value, service.decommissionErr
}

var _ hostinventory.Service = (*recordingHostService)(nil)

type competingHostService struct {
	host              hostinventory.Host
	failNext          error
	decommissionCalls int
}

func (*competingHostService) RecordObservation(context.Context, hostinventory.Observation) (hostinventory.Host, error) {
	return hostinventory.Host{}, errors.New("unexpected observation")
}

func (service *competingHostService) List(context.Context, platformscope.Scope, hostinventory.Filter) (hostinventory.Page, error) {
	return hostinventory.Page{}, nil
}

func (service *competingHostService) Get(_ context.Context, scope platformscope.Scope, id string) (hostinventory.Host, error) {
	if service.host.Scope != scope || service.host.ID != id {
		return hostinventory.Host{}, hostinventory.ErrNotFound
	}
	return service.host, nil
}

func (service *competingHostService) Decommission(ctx context.Context, scope platformscope.Scope, id string, version uint64) (hostinventory.Host, error) {
	service.decommissionCalls++
	if service.failNext != nil {
		err := service.failNext
		service.failNext = nil
		return hostinventory.Host{}, err
	}
	transition, ok := hostinventory.DecommissionTransitionFromContext(ctx)
	if !ok {
		return hostinventory.Host{}, hostinventory.ErrInvalid
	}
	if service.host.Scope != scope || service.host.ID != id {
		return hostinventory.Host{}, hostinventory.ErrNotFound
	}
	if service.host.Status == hostinventory.HostDecommissioned || service.host.Version != version {
		return hostinventory.Host{}, hostinventory.ErrConflict
	}
	service.host.Status = hostinventory.HostDecommissioned
	service.host.Version++
	service.host.DecommissionTransition = &transition
	return service.host, nil
}

var _ hostinventory.Service = (*competingHostService)(nil)
