package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/capability"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/stretchr/testify/require"
)

const platformBasePath = "/api/v1/tenants/tenant-a/projects/project-a"

var platformTestScope = platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}

func TestGeneratedGetJobReturnsScopedContractEntityWithETag(t *testing.T) {
	jobs := &recordingJobService{getValue: validPlatformJob()}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/jobs/job-1", nil)
	request.Header.Set("X-Request-ID", "request-http-1")
	response := servePlatformRequest(Services{Jobs: jobs}, principalWith(platformTestScope, openapi.PermissionGetJob), request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, `"7"`, response.Header().Get("ETag"))
	require.Equal(t, "request-http-1", response.Header().Get("X-Request-ID"))
	require.Equal(t, platformTestScope, jobs.getScope)
	require.Equal(t, "job-1", jobs.getID)
	require.JSONEq(t, `{
		"id":"job-1","type":"inspection.run","status":"running","outcome":"none",
		"tenant_id":"tenant-a","project_id":"project-a","instance_id":"instance-1",
		"target_resource_ids":["instance-1"],"initiated_by":"trusted-user",
		"source_resource":{"resource_type":"inspection","resource_id":"inspection-1"},
		"idempotency_key":"create-job-1","version":7,
		"progress":{"total_targets":1,"completed_targets":0,"failed_targets":0,"skipped_targets":0},
		"artifacts":[],"created_at":"2026-08-28T04:00:00Z","request_id":"request-job-1","trace_id":"trace-job-1"
	}`, response.Body.String())
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedCancelUsesURLScopeAuthenticatedActorAndConditionalVersion(t *testing.T) {
	jobs := &recordingJobService{transitionValue: func() job.Job {
		value := validPlatformJob()
		value.Status = job.StatusCancelling
		value.Version = 8
		return value
	}()}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/jobs/job-1/actions/cancel", strings.NewReader(`{"actor":"attacker","tenant_id":"tenant-b","project_id":"project-b"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "cancel-job-1")
	request.Header.Set("If-Match", `"7"`)
	response := servePlatformRequest(Services{Jobs: jobs, Now: func() time.Time { return time.Date(2026, 8, 28, 5, 0, 0, 0, time.UTC) }}, principalWith(platformTestScope, openapi.PermissionCancelJob), request)

	require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
	require.Equal(t, `"8"`, response.Header().Get("ETag"))
	require.Equal(t, platformBasePath+"/jobs/job-1", response.Header().Get("Location"))
	require.Len(t, jobs.transitions, 1)
	require.Equal(t, platformTestScope, jobs.transitions[0].Scope)
	require.Equal(t, "job-1", jobs.transitions[0].JobID)
	require.Equal(t, int64(7), jobs.transitions[0].CurrentVersion)
	require.Equal(t, job.StatusCancelling, jobs.transitions[0].To)
	require.Equal(t, "trusted-user", jobs.transitions[0].Actor)
	require.Equal(t, time.Date(2026, 8, 28, 5, 0, 0, 0, time.UTC), jobs.transitions[0].At)
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedCancelRequiresIdempotencyKeyAndIfMatch(t *testing.T) {
	tests := map[string]func(*http.Request){
		"missing idempotency key": func(request *http.Request) { request.Header.Set("If-Match", `"7"`) },
		"missing if match":        func(request *http.Request) { request.Header.Set("Idempotency-Key", "cancel-job-1") },
		"invalid if match": func(request *http.Request) {
			request.Header.Set("Idempotency-Key", "cancel-job-1")
			request.Header.Set("If-Match", "W/\"7\"")
		},
	}
	for name, configure := range tests {
		t.Run(name, func(t *testing.T) {
			jobs := &recordingJobService{}
			request := httptest.NewRequest(http.MethodPost, platformBasePath+"/jobs/job-1/actions/cancel", nil)
			request.Header.Set("X-Request-ID", "request-invalid-1")
			configure(request)

			response := servePlatformRequest(Services{Jobs: jobs}, principalWith(platformTestScope, openapi.PermissionCancelJob), request)

			requireProblem(t, response, http.StatusBadRequest, "invalid_request", "request-invalid-1")
			require.Empty(t, jobs.transitions)
			requireOpenAPIResponse(t, request, response)
		})
	}
}

func TestGeneratedCancelReturnsPreconditionFailedForStaleETag(t *testing.T) {
	jobs := &recordingJobService{transitionErr: job.ErrConflict}
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/jobs/job-1/actions/cancel", nil)
	request.Header.Set("Idempotency-Key", "cancel-job-1")
	request.Header.Set("If-Match", `"6"`)
	response := servePlatformRequest(Services{Jobs: jobs}, principalWith(platformTestScope, openapi.PermissionCancelJob), request)

	requireProblem(t, response, http.StatusPreconditionFailed, "precondition_failed", response.Header().Get("X-Request-ID"))
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedArtifactMetadataAndDownloadDescriptor(t *testing.T) {
	created := time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC)
	expires := created.Add(time.Hour)
	artifacts := &recordingArtifactService{
		getValue:      artifact.Artifact{ID: "artifact-1", Scope: platformTestScope, Kind: "inspection-report", ContentType: "application/json", SizeBytes: 37, Checksum: "sha256:abc", CreatedBy: "trusted-user", CreatedAt: created, ExpiresAt: &expires},
		downloadValue: artifact.Download{URL: "https://downloads.example/artifact-1?signature=safe", ExpiresAt: created.Add(5 * time.Minute)},
	}

	metadataRequest := httptest.NewRequest(http.MethodGet, platformBasePath+"/artifacts/artifact-1", nil)
	metadataResponse := servePlatformRequest(Services{Artifacts: artifacts}, principalWith(platformTestScope, openapi.PermissionGetArtifact), metadataRequest)
	require.Equal(t, http.StatusOK, metadataResponse.Code, metadataResponse.Body.String())
	require.Equal(t, platformTestScope, artifacts.getScope)
	require.NotContains(t, metadataResponse.Body.String(), "storage_reference")
	requireOpenAPIResponse(t, metadataRequest, metadataResponse)

	downloadRequest := httptest.NewRequest(http.MethodPost, platformBasePath+"/artifacts/artifact-1/actions/download", nil)
	downloadRequest.Header.Set("Idempotency-Key", "download-artifact-1")
	downloadResponse := servePlatformRequest(Services{Artifacts: artifacts}, principalWith(platformTestScope, openapi.PermissionCreateArtifactDownload), downloadRequest)
	require.Equal(t, http.StatusOK, downloadResponse.Code, downloadResponse.Body.String())
	require.Equal(t, platformTestScope, artifacts.downloadScope)
	require.Equal(t, "artifact-1", artifacts.downloadID)
	require.Equal(t, artifact.MaximumDownloadTTL, artifacts.downloadTTL)
	requireOpenAPIResponse(t, downloadRequest, downloadResponse)
}

func TestGeneratedAuditListUsesOnlyURLScopeAndOpaqueCursor(t *testing.T) {
	occurred := time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC)
	audits := &recordingAuditService{page: audit.Page{Items: []audit.Event{{
		ID: "audit-1", Scope: platformTestScope, OccurredAt: occurred, Action: "inspection.started",
		Actor: audit.Actor{Type: "user", ID: "trusted-user"}, RequestID: "request-job-1", Detail: map[string]any{"result": "accepted"},
	}}, NextCursor: "next-cursor"}}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/audit-events?cursor=opaque-cursor&limit=1", nil)
	response := servePlatformRequest(Services{Audit: audits}, principalWith(platformTestScope, openapi.PermissionListAuditEvents), request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, platformTestScope, audits.scope)
	require.Equal(t, audit.ListQuery{Cursor: "opaque-cursor", Limit: 1}, audits.query)
	require.JSONEq(t, `{"items":[{"id":"audit-1","occurred_at":"2026-08-28T04:00:00Z","action":"inspection.started","tenant_id":"tenant-a","project_id":"project-a","actor":{"type":"user","id":"trusted-user"},"request_id":"request-job-1","detail":{"result":"accepted"}}],"page":{"limit":1,"next_cursor":"next-cursor","has_more":true}}`, response.Body.String())
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedCapabilitiesIntersectAuthenticatedPermissions(t *testing.T) {
	capabilities := &recordingCapabilityService{values: []capability.Capability{{Name: "job.read", Enabled: true, RequiredPermission: openapi.PermissionGetJob, DatabaseTypes: []string{"postgresql"}, AgentCapabilities: []string{"inspect_instance"}}}}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/capabilities", nil)
	principal := principalWith(platformTestScope, openapi.PermissionGetCapabilities, openapi.PermissionGetJob)
	response := servePlatformRequest(Services{
		Capabilities: capabilities,
		CapabilityInput: func(context.Context, platformscope.Scope) capability.Input {
			return capability.Input{DatabaseType: "postgresql", AgentCapabilities: map[string]bool{"inspect_instance": true}}
		},
	}, principal, request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.True(t, capabilities.input.Permissions[openapi.PermissionGetCapabilities])
	require.True(t, capabilities.input.Permissions[openapi.PermissionGetJob])
	require.Equal(t, "postgresql", capabilities.input.DatabaseType)
	requireOpenAPIResponse(t, request, response)
}

func TestGeneratedRoutesRejectMissingOrWrongActionBeforeServiceExecution(t *testing.T) {
	tests := []struct {
		name      string
		principal Principal
		status    int
		code      string
	}{
		{name: "unauthenticated", status: http.StatusUnauthorized, code: "unauthenticated"},
		{name: "wrong action", principal: principalWith(platformTestScope, openapi.PermissionCancelJob), status: http.StatusForbidden, code: "forbidden"},
		{name: "wrong scope", principal: principalWith(platformscope.Scope{TenantID: "tenant-b", ProjectID: "project-b"}, openapi.PermissionGetJob), status: http.StatusForbidden, code: "forbidden"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jobs := &recordingJobService{getValue: validPlatformJob()}
			request := httptest.NewRequest(http.MethodGet, platformBasePath+"/jobs/job-1", nil)
			var resolver PrincipalResolver = platformStaticPrincipalResolver{principal: test.principal}
			if test.status == http.StatusUnauthorized {
				resolver = platformStaticPrincipalResolver{err: ErrUnauthenticated}
			}
			response := httptest.NewRecorder()

			NewHTTPHandler(Services{Jobs: jobs}, resolver).ServeHTTP(response, request)

			requireProblem(t, response, test.status, test.code, response.Header().Get("X-Request-ID"))
			require.Zero(t, jobs.getCalls)
			requireOpenAPIResponse(t, request, response)
		})
	}
}

func TestProblemMappingsAreStableAndNeverExposeInternalErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "validation", err: artifact.ErrInvalid, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "not found", err: job.ErrNotFound, status: http.StatusNotFound, code: "not_found"},
		{name: "conflict", err: job.ErrInvalidTransition, status: http.StatusConflict, code: "conflict"},
		{name: "precondition", err: ErrPreconditionFailed, status: http.StatusPreconditionFailed, code: "precondition_failed"},
		{name: "forbidden", err: ErrForbidden, status: http.StatusForbidden, code: "forbidden"},
		{name: "timeout", err: context.DeadlineExceeded, status: http.StatusGatewayTimeout, code: "timeout"},
		{name: "internal", err: errors.New("postgres password=top-secret"), status: http.StatusInternalServerError, code: "internal_error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			problem := problemForError(test.err, "request-problem-1", "/safe-instance")
			require.Equal(t, test.status, problem.Status)
			require.Equal(t, test.code, problem.Code)
			require.NotContains(t, problem.Title, "top-secret")
			if problem.Detail != nil {
				require.NotContains(t, *problem.Detail, "top-secret")
			}
			requireProblemSchema(t, problem)
		})
	}
}

func servePlatformRequest(services Services, principal Principal, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	NewHTTPHandler(services, platformStaticPrincipalResolver{principal: principal}).ServeHTTP(response, request)
	return response
}

func requireProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code, requestID string) openapi.Problem {
	t.Helper()
	require.Equal(t, status, response.Code, response.Body.String())
	require.Equal(t, "application/problem+json", response.Header().Get("Content-Type"))
	var problem openapi.Problem
	require.NoError(t, decodeJSONBytes(response.Body.Bytes(), &problem))
	require.Equal(t, code, problem.Code)
	require.NotEmpty(t, problem.Type)
	require.NotEmpty(t, problem.Title)
	require.Equal(t, requestID, problem.RequestId)
	requireProblemSchema(t, problem)
	return problem
}

func requireProblemSchema(t *testing.T, problem openapi.Problem) {
	t.Helper()
	spec, err := openapi.GetSpec()
	require.NoError(t, err)
	encoded := new(bytes.Buffer)
	require.NoError(t, json.NewEncoder(encoded).Encode(problem))
	var value any
	require.NoError(t, decodeJSONBytes(encoded.Bytes(), &value))
	require.NoError(t, spec.Components.Schemas["Problem"].Value.VisitJSON(value))
}

func requireOpenAPIResponse(t *testing.T, request *http.Request, response *httptest.ResponseRecorder) {
	t.Helper()
	spec, err := openapi.GetSpec()
	require.NoError(t, err)
	router, err := legacy.NewRouter(spec)
	require.NoError(t, err)
	route, pathParams, err := router.FindRoute(request)
	require.NoError(t, err)
	input := &openapi3filter.RequestValidationInput{Request: request, PathParams: pathParams, Route: route}
	validation := (&openapi3filter.ResponseValidationInput{RequestValidationInput: input, Status: response.Code, Header: response.Header()}).SetBodyBytes(response.Body.Bytes())
	require.NoError(t, openapi3filter.ValidateResponse(context.Background(), validation))
}

func decodeJSONBytes(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

type platformStaticPrincipalResolver struct {
	principal Principal
	err       error
}

func (resolver platformStaticPrincipalResolver) ResolvePrincipal(*http.Request) (Principal, error) {
	return resolver.principal, resolver.err
}

func principalWith(scope platformscope.Scope, permissions ...string) Principal {
	return Principal{Subject: "trusted-user", Projects: map[string]struct{}{scope.Key(): {}}, Grants: scopedGrants(scope, permissions...)}
}

func validPlatformJob() job.Job {
	return job.Job{
		ID: "job-1", Type: "inspection.run", Scope: platformTestScope, Status: job.StatusRunning, Outcome: job.OutcomeNone,
		InstanceID: "instance-1", TargetResourceIDs: []string{"instance-1"}, InitiatedBy: "trusted-user",
		SourceResource: job.ResourceReference{ResourceType: "inspection", ResourceID: "inspection-1"}, IdempotencyKey: "create-job-1", Version: 7,
		Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC),
		RequestID: "request-job-1", TraceID: "trace-job-1",
	}
}

type recordingJobService struct {
	getValue        job.Job
	getErr          error
	getScope        platformscope.Scope
	getID           string
	getCalls        int
	transitionValue job.Job
	transitionErr   error
	transitions     []job.Transition
}

func (service *recordingJobService) Get(_ context.Context, scope platformscope.Scope, id string) (job.Job, error) {
	service.getCalls++
	service.getScope, service.getID = scope, id
	return service.getValue, service.getErr
}

func (service *recordingJobService) Transition(_ context.Context, transition job.Transition) (job.Job, error) {
	service.transitions = append(service.transitions, transition)
	return service.transitionValue, service.transitionErr
}

type recordingArtifactService struct {
	getValue      artifact.Artifact
	getErr        error
	getScope      platformscope.Scope
	downloadValue artifact.Download
	downloadErr   error
	downloadScope platformscope.Scope
	downloadID    string
	downloadTTL   time.Duration
}

func (service *recordingArtifactService) Get(_ context.Context, scope platformscope.Scope, _ string) (artifact.Artifact, error) {
	service.getScope = scope
	return service.getValue, service.getErr
}

func (service *recordingArtifactService) CreateDownload(_ context.Context, scope platformscope.Scope, id string, ttl time.Duration) (artifact.Download, error) {
	service.downloadScope, service.downloadID, service.downloadTTL = scope, id, ttl
	return service.downloadValue, service.downloadErr
}

type recordingAuditService struct {
	page  audit.Page
	err   error
	scope platformscope.Scope
	query audit.ListQuery
}

func (service *recordingAuditService) List(_ context.Context, scope platformscope.Scope, query audit.ListQuery) (audit.Page, error) {
	service.scope, service.query = scope, query
	return service.page, service.err
}

type recordingCapabilityService struct {
	values []capability.Capability
	input  capability.Input
}

func (service *recordingCapabilityService) Resolve(input capability.Input) []capability.Capability {
	service.input = input
	return service.values
}
