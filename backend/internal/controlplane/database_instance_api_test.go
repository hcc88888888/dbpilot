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
	"dbpilot.local/platform/internal/job"
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

func TestDatabaseInstanceAPIStaleAcceptanceReturnsContractValidPrecondition(t *testing.T) {
	spec, err := openapi.GetSpec()
	require.NoError(t, err)
	pathItem := spec.Paths.Find("/discovery-candidates/{candidate_id}/actions/accept")
	require.NotNil(t, pathItem)
	operation := pathItem.Post
	_, declared := operation.Responses.Map()["412"]
	require.True(t, declared, "accept contract must declare its runtime precondition response")
	candidate := discoveryAPICandidate(platformTestScope)
	candidate.ObservationRevision = 8
	service := &databaseInstanceAPIService{instance: controlplaneDatabaseInstance()}
	request := databaseInstanceAcceptHTTPRequest(`"7"`, "accept-stale-read")
	response := servePlatformRequest(Services{Discovery: &discoveryAPIService{candidate: candidate}, DatabaseInstances: service}, principalWith(platformTestScope, openapi.PermissionAcceptDiscoveryCandidate), request)
	requireProblem(t, response, http.StatusPreconditionFailed, "precondition_failed", response.Header().Get("X-Request-ID"))
	requireOpenAPIResponse(t, request, response)

	candidate.ObservationRevision = 7
	service.acceptErrors = map[string]error{"accept-raced": databaseinstance.ErrPrecondition}
	request = databaseInstanceAcceptHTTPRequest(`"7"`, "accept-raced")
	response = servePlatformRequest(Services{Discovery: &discoveryAPIService{candidate: candidate}, DatabaseInstances: service}, principalWith(platformTestScope, openapi.PermissionAcceptDiscoveryCandidate), request)
	requireProblem(t, response, http.StatusPreconditionFailed, "precondition_failed", response.Header().Get("X-Request-ID"))
	requireOpenAPIResponse(t, request, response)
	require.NotContains(t, response.Body.String(), "response validation")
}

func TestDatabaseInstanceAPIRetiredCandidateOnlyReplaysOriginalHistoricalResponse(t *testing.T) {
	candidate := discoveryAPICandidate(platformTestScope)
	candidate.ObservationRevision = 7
	accepted := controlplaneDatabaseInstance()
	retired := accepted
	retired.ManagementStatus, retired.Revision = databaseinstance.StatusRetired, 2
	retired.UpdatedAt = retired.UpdatedAt.Add(time.Second)
	retiredAt := retired.UpdatedAt
	retired.RetiredAt = &retiredAt
	service := &databaseInstanceAPIService{instance: retired, acceptResponses: map[string]databaseinstance.Instance{"accept-original": accepted}, acceptErrors: map[string]error{"accept-new": databaseinstance.ErrConflict}}
	services := Services{Discovery: &discoveryAPIService{candidate: candidate}, DatabaseInstances: service}

	historical := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionAcceptDiscoveryCandidate), databaseInstanceAcceptHTTPRequest(`"7"`, "accept-original"))
	require.Equal(t, http.StatusAccepted, historical.Code, historical.Body.String())
	var historicalBody openapi.ManagedDatabaseInstance
	require.NoError(t, json.Unmarshal(historical.Body.Bytes(), &historicalBody))
	require.Equal(t, openapi.DatabaseManagementStatusAccepted, historicalBody.ManagementStatus)
	newKey := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionAcceptDiscoveryCandidate), databaseInstanceAcceptHTTPRequest(`"7"`, "accept-new"))
	require.Equal(t, http.StatusConflict, newKey.Code, newKey.Body.String())
	current := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionGetDatabaseInstance), httptest.NewRequest(http.MethodGet, platformBasePath+"/database-instances/instance-1", nil))
	require.Equal(t, http.StatusOK, current.Code, current.Body.String())
	var currentBody openapi.ManagedDatabaseInstance
	require.NoError(t, json.Unmarshal(current.Body.Bytes(), &currentBody))
	require.Equal(t, openapi.DatabaseManagementStatusRetired, currentBody.ManagementStatus)
}

func TestDatabaseInstanceAPIListsUpdatesRetiresAndReturnsFixedPluginMissingProblem(t *testing.T) {
	instances := &databaseInstanceAPIService{instance: controlplaneDatabaseInstance(), validationErr: databaseinstance.ErrPluginMissing}
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

func TestDatabaseInstanceConnectionTestReturnsDurableJobAndMapsInternalRunningState(t *testing.T) {
	now := time.Date(2026, 9, 4, 5, 0, 0, 0, time.UTC)
	instance := controlplaneDatabaseInstance()
	instance.PluginID, instance.PluginAssignmentRevision = "mysql", 7
	instance.CapabilityState = databaseinstance.CapabilityPluginAvailable
	service := &databaseInstanceAPIService{instance: instance, validationJob: job.Job{ID: "job-validate-a", Type: "database_instance.validate", Scope: platformTestScope, Status: job.StatusQueued, Outcome: job.OutcomeNone, InstanceID: instance.ID, TargetResourceIDs: []string{instance.AgentID}, InitiatedBy: "trusted-user", SourceResource: job.ResourceReference{ResourceType: "database_instance", ResourceID: instance.ID}, IdempotencyKey: "internal-a", Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, RequestID: "request-a", TraceID: "trace-a"}}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/database-instances/instance-1/actions/test-connection", nil)
	request.Header.Set("Idempotency-Key", "validate-a")

	response := servePlatformRequest(Services{DatabaseInstances: service}, principalWith(platformTestScope, openapi.PermissionTestDatabaseInstanceConnection), request)

	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	require.Equal(t, `"1"`, response.Header().Get("ETag"))
	require.Equal(t, platformBasePath+"/jobs/job-validate-a", response.Header().Get("Location"))
	require.Equal(t, "trusted-user", service.validationRequest.Audit.Actor)
	require.Equal(t, "testDatabaseInstanceConnection", service.validationRequest.Audit.OperationID)
	require.NotEmpty(t, service.validationRequest.Audit.RequestFingerprint)

	running := instance
	running.ConnectionTestStatus = databaseinstance.ConnectionRunning
	running.ConnectionTestAt = &now
	running.ManagementStatus = databaseinstance.StatusConnectionTesting
	service.instance = running
	get := servePlatformRequest(Services{DatabaseInstances: service}, principalWith(platformTestScope, openapi.PermissionGetDatabaseInstance), httptest.NewRequest(http.MethodGet, platformBasePath+"/database-instances/instance-1", nil))
	require.Equal(t, http.StatusOK, get.Code, get.Body.String())
	var body openapi.ManagedDatabaseInstance
	require.NoError(t, json.Unmarshal(get.Body.Bytes(), &body))
	require.Equal(t, openapi.ConnectionTestStatusPending, body.ConnectionTestStatus)

	pluginFailed := instance
	pluginFailed.ConnectionTestStatus = databaseinstance.ConnectionPluginFailed
	pluginFailed.ConnectionTestErrorCode = databaseinstance.ConnectionErrorPlugin
	pluginFailed.ConnectionTestAt = &now
	pluginFailed.CapabilityState = databaseinstance.CapabilityPluginFailed
	pluginFailed.ManagementStatus = databaseinstance.StatusPluginFailed
	service.instance = pluginFailed
	get = servePlatformRequest(Services{DatabaseInstances: service}, principalWith(platformTestScope, openapi.PermissionGetDatabaseInstance), httptest.NewRequest(http.MethodGet, platformBasePath+"/database-instances/instance-1", nil))
	require.Equal(t, http.StatusOK, get.Code, get.Body.String())
	require.NoError(t, json.Unmarshal(get.Body.Bytes(), &body))
	require.Equal(t, openapi.ConnectionTestStatusUnreachable, body.ConnectionTestStatus, "the attempted validation was unavailable and must never be serialized as not_tested")
	require.Contains(t, body.Capabilities, "plugin_failed")
	require.Contains(t, body.Capabilities, "connection_error:plugin_failed")
}

type databaseInstanceAPIService struct {
	instance          databaseinstance.Instance
	acceptScope       platformscope.Scope
	acceptCandidateID string
	acceptRequest     databaseinstance.AcceptCandidateRequest
	acceptResponses   map[string]databaseinstance.Instance
	acceptErrors      map[string]error
	validationJob     job.Job
	validationErr     error
	validationRequest databaseinstance.ValidationRequest
}

func (service *databaseInstanceAPIService) AcceptCandidate(_ context.Context, scope platformscope.Scope, candidateID string, request databaseinstance.AcceptCandidateRequest) (databaseinstance.Instance, error) {
	service.acceptScope, service.acceptCandidateID, service.acceptRequest = scope, candidateID, request
	if err := service.acceptErrors[request.Audit.IdempotencyKey]; err != nil {
		return databaseinstance.Instance{}, err
	}
	if value, ok := service.acceptResponses[request.Audit.IdempotencyKey]; ok {
		return value, nil
	}
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
	if update.DisplayName != nil {
		value.DisplayName = *update.DisplayName
	}
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
func (service *databaseInstanceAPIService) StartValidation(_ context.Context, _ platformscope.Scope, _ string, request databaseinstance.ValidationRequest) (job.Job, error) {
	service.validationRequest = request
	return service.validationJob, service.validationErr
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

func databaseInstanceAcceptHTTPRequest(ifMatch, key string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/discovery-candidates/candidate-1/actions/accept", strings.NewReader(`{"display_name":"Orders MySQL","database_family":"mysql","database_variant":"mysql","normalized_endpoint":"127.0.0.1:3306","credential_ref":"secret://vault/database/mysql/orders","labels":{"service":"orders"}}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", key)
	request.Header.Set("If-Match", ifMatch)
	return request
}

var _ databaseinstance.Service = (*databaseInstanceAPIService)(nil)
