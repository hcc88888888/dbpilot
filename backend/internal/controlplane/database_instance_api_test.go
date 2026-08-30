package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestDatabaseInstanceAPIAcceptsCurrentCandidateWithCASAndScope(t *testing.T) {
	candidate := discoveryAPICandidate(platformTestScope)
	candidate.ObservationRevision = 7
	instances := &databaseInstanceAPIService{instance: controlplaneDatabaseInstance()}
	services := Services{Discovery: &discoveryAPIService{candidate: candidate}, DatabaseInstances: instances}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/discovery-candidates/candidate-1/actions/accept", strings.NewReader(`{"display_name":"Orders MySQL","database_family":"mysql","database_variant":"mysql","normalized_endpoint":"127.0.0.1:3306","credential_ref":"secret://vault/database/mysql/orders","labels":{"service":"orders"}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "accept-1")
	request.Header.Set("If-Match", `"7"`)

	response := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionAcceptDiscoveryCandidate), request)

	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	require.Equal(t, `"1"`, response.Header().Get("ETag"))
	require.Equal(t, platformTestScope, instances.acceptScope)
	require.Equal(t, "candidate-1", instances.acceptCandidateID)
	require.Equal(t, uint64(7), instances.acceptRequest.ExpectedCandidateRevision)
	require.Equal(t, candidateFingerprintHex(candidate), instances.acceptRequest.CandidateFingerprint)
	require.Equal(t, "trusted-user", instances.acceptRequest.Audit.Actor)
	require.NotEmpty(t, instances.acceptRequest.Audit.RequestFingerprint)
}

func TestDatabaseInstanceAPIListsUpdatesRetiresAndReturnsFixedPluginMissingProblem(t *testing.T) {
	instances := &databaseInstanceAPIService{instance: controlplaneDatabaseInstance()}
	services := Services{DatabaseInstances: instances}
	list := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionListDatabaseInstances), httptest.NewRequest(http.MethodGet, platformBasePath+"/database-instances?database_family=mysql&limit=1", nil))
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	var page openapi.ManagedDatabaseInstancePage
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &page))
	require.Len(t, page.Items, 1)
	require.Equal(t, "plugin_not_installed", page.Items[0].Capabilities[0])

	update := httptest.NewRequest(http.MethodPatch, platformBasePath+"/database-instances/instance-1", strings.NewReader(`{"display_name":"Updated MySQL"}`))
	update.Header.Set("Content-Type", "application/json")
	update.Header.Set("Idempotency-Key", "update-1")
	update.Header.Set("If-Match", `"1"`)
	updated := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionUpdateDatabaseInstance), update)
	require.Equal(t, http.StatusOK, updated.Code, updated.Body.String())
	require.Equal(t, `"2"`, updated.Header().Get("ETag"))

	testConnection := httptest.NewRequest(http.MethodPost, platformBasePath+"/database-instances/instance-1/actions/test-connection", nil)
	testConnection.Header.Set("Idempotency-Key", "test-1")
	tested := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionTestDatabaseInstanceConnection), testConnection)
	require.Equal(t, http.StatusUnprocessableEntity, tested.Code, tested.Body.String())
	var problem openapi.Problem
	require.NoError(t, json.Unmarshal(tested.Body.Bytes(), &problem))
	require.Equal(t, "plugin_not_installed", problem.Code)

	retire := httptest.NewRequest(http.MethodPost, platformBasePath+"/database-instances/instance-1/actions/retire", nil)
	retire.Header.Set("Idempotency-Key", "retire-1")
	retire.Header.Set("If-Match", `"2"`)
	retired := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionRetireDatabaseInstance), retire)
	require.Equal(t, http.StatusOK, retired.Code, retired.Body.String())
	require.Equal(t, `"3"`, retired.Header().Get("ETag"))
}

type databaseInstanceAPIService struct {
	instance          databaseinstance.Instance
	acceptScope       platformscope.Scope
	acceptCandidateID string
	acceptRequest     databaseinstance.AcceptCandidateRequest
}

func (service *databaseInstanceAPIService) AcceptCandidate(_ context.Context, scope platformscope.Scope, candidateID string, request databaseinstance.AcceptCandidateRequest) (databaseinstance.Instance, error) {
	service.acceptScope, service.acceptCandidateID, service.acceptRequest = scope, candidateID, request
	return service.instance, nil
}
func (service *databaseInstanceAPIService) List(_ context.Context, scope platformscope.Scope, _ databaseinstance.Filter) (databaseinstance.Page, error) {
	value := service.instance
	value.Scope = scope
	return databaseinstance.Page{Items: []databaseinstance.Instance{value}}, nil
}
func (service *databaseInstanceAPIService) Get(_ context.Context, scope platformscope.Scope, id string) (databaseinstance.Instance, error) {
	value := service.instance
	value.Scope, value.ID = scope, id
	return value, nil
}
func (service *databaseInstanceAPIService) Update(_ context.Context, scope platformscope.Scope, id string, revision uint64, update databaseinstance.Update) (databaseinstance.Instance, error) {
	value := service.instance
	value.Scope, value.ID = scope, id
	value.Revision, value.UpdatedAt = revision+1, value.UpdatedAt.Add(time.Second)
	if update.DisplayName != nil { value.DisplayName = *update.DisplayName }
	service.instance = value
	return value, nil
}
func (service *databaseInstanceAPIService) Retire(_ context.Context, scope platformscope.Scope, id string, revision uint64, _ databaseinstance.MutationAudit) (databaseinstance.Instance, error) {
	value := service.instance
	value.Scope, value.ID = scope, id
	value.Revision, value.UpdatedAt, value.ManagementStatus = revision+1, value.UpdatedAt.Add(time.Second), databaseinstance.StatusRetired
	retired := value.UpdatedAt
	value.RetiredAt = &retired
	service.instance = value
	return value, nil
}

func controlplaneDatabaseInstance() databaseinstance.Instance {
	now := time.Date(2026, 8, 31, 1, 2, 3, 0, time.UTC)
	return databaseinstance.Instance{
		ID: "instance-1", Scope: platformTestScope, HostID: "host-1", AgentID: "agent-1", CandidateID: "candidate-1",
		DiscoverySource: discovery.SourceNative, SourceFingerprint: strings.Repeat("a", 64), SourceIdentity: "native-service:mysqld.service",
		DatabaseFamily: "mysql", DatabaseVariant: "mysql", DisplayName: "Orders MySQL", Endpoint: "127.0.0.1:3306",
		CredentialRef: "secret://vault/database/mysql/orders", Labels: map[string]string{"service": "orders"},
		Capabilities: []string{}, CapabilityState: databaseinstance.CapabilityPluginNotInstalled, ConnectionTestStatus: databaseinstance.ConnectionNotTested,
		ManagementStatus: databaseinstance.StatusAccepted, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}

var _ databaseinstance.Service = (*databaseInstanceAPIService)(nil)
