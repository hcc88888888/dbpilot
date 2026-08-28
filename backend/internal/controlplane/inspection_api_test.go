package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestInspectionStrictHandlersCoverGeneratedOperationsWithURLScope(t *testing.T) {
	now := time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC)
	service := &recordingInspectionService{now: now}
	tests := []struct {
		name, method, path, body, permission string
		status                               int
		headers                              map[string]string
	}{
		{name: "list items", method: http.MethodGet, path: "/inspection-items?cursor=item-cursor&limit=20", permission: openapi.PermissionListInspectionItems, status: http.StatusOK},
		{name: "create item", method: http.MethodPost, path: "/inspection-items", body: validInspectionItemBody(), permission: openapi.PermissionCreateInspectionItem, status: http.StatusCreated, headers: map[string]string{"Idempotency-Key": "create-item-1"}},
		{name: "overview", method: http.MethodGet, path: "/inspection-overview", permission: openapi.PermissionGetInspectionOverview, status: http.StatusOK},
		{name: "list policies", method: http.MethodGet, path: "/inspection-policies?cursor=policy-cursor&limit=20", permission: openapi.PermissionListInspectionPolicies, status: http.StatusOK},
		{name: "create policy", method: http.MethodPost, path: "/inspection-policies", body: validInspectionPolicyBody(), permission: openapi.PermissionCreateInspectionPolicy, status: http.StatusCreated, headers: map[string]string{"Idempotency-Key": "create-policy-1"}},
		{name: "get policy", method: http.MethodGet, path: "/inspection-policies/policy-1", permission: openapi.PermissionGetInspectionPolicy, status: http.StatusOK},
		{name: "update policy", method: http.MethodPatch, path: "/inspection-policies/policy-1", body: validInspectionPolicyBody(), permission: openapi.PermissionUpdateInspectionPolicy, status: http.StatusOK, headers: map[string]string{"Idempotency-Key": "update-policy-1", "If-Match": `"3"`}},
		{name: "run policy", method: http.MethodPost, path: "/inspection-policies/policy-1/run", permission: openapi.PermissionRunInspectionPolicy, status: http.StatusAccepted, headers: map[string]string{"Idempotency-Key": "run-policy-1"}},
		{name: "list reports", method: http.MethodGet, path: "/inspection-reports?cursor=report-cursor&limit=20", permission: openapi.PermissionListInspectionReports, status: http.StatusOK},
		{name: "get report", method: http.MethodGet, path: "/inspection-reports/report-1", permission: openapi.PermissionGetInspectionReport, status: http.StatusOK},
		{name: "download report", method: http.MethodPost, path: "/inspection-reports/report-1/download", permission: openapi.PermissionCreateInspectionReportDownload, status: http.StatusOK, headers: map[string]string{"Idempotency-Key": "download-report-1"}},
		{name: "list runs", method: http.MethodGet, path: "/inspection-runs?cursor=run-cursor&limit=20", permission: openapi.PermissionListInspectionRuns, status: http.StatusOK},
		{name: "create run", method: http.MethodPost, path: "/inspection-runs", body: validInspectionRunBody(), permission: openapi.PermissionCreateInspectionRun, status: http.StatusAccepted, headers: map[string]string{"Idempotency-Key": "create-run-1"}},
		{name: "get run", method: http.MethodGet, path: "/inspection-runs/run-1", permission: openapi.PermissionGetInspectionRun, status: http.StatusOK},
		{name: "cancel run", method: http.MethodPost, path: "/inspection-runs/run-1/cancel", permission: openapi.PermissionCancelInspectionRun, status: http.StatusAccepted, headers: map[string]string{"Idempotency-Key": "cancel-run-1"}},
		{name: "retry run", method: http.MethodPost, path: "/inspection-runs/run-1/retry", permission: openapi.PermissionRetryInspectionRun, status: http.StatusAccepted, headers: map[string]string{"Idempotency-Key": "retry-run-1"}},
		{name: "list targets", method: http.MethodGet, path: "/inspection-targets?cursor=target-cursor&limit=20", permission: openapi.PermissionListInspectionTargets, status: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := len(service.calls)
			request := httptest.NewRequest(test.method, platformBasePath+test.path, strings.NewReader(test.body))
			if test.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}

			response := servePlatformRequest(Services{Inspection: service}, principalWith(platformTestScope, test.permission), request)

			require.Equal(t, test.status, response.Code, response.Body.String())
			require.Len(t, service.calls, before+1)
			require.Equal(t, platformTestScope, service.calls[before].scope, "only the authenticated URL scope may reach the service")
			requireOpenAPIResponse(t, request, response)
		})
	}
}

func TestInspectionPermissionsUseEveryGeneratedConstantAndFailClosed(t *testing.T) {
	want := map[string]string{
		"ListInspectionItems": openapi.PermissionListInspectionItems, "CreateInspectionItem": openapi.PermissionCreateInspectionItem,
		"GetInspectionOverview": openapi.PermissionGetInspectionOverview, "ListInspectionPolicies": openapi.PermissionListInspectionPolicies,
		"CreateInspectionPolicy": openapi.PermissionCreateInspectionPolicy, "GetInspectionPolicy": openapi.PermissionGetInspectionPolicy,
		"UpdateInspectionPolicy": openapi.PermissionUpdateInspectionPolicy, "RunInspectionPolicy": openapi.PermissionRunInspectionPolicy,
		"ListInspectionReports": openapi.PermissionListInspectionReports, "GetInspectionReport": openapi.PermissionGetInspectionReport,
		"CreateInspectionReportDownload": openapi.PermissionCreateInspectionReportDownload, "ListInspectionRuns": openapi.PermissionListInspectionRuns,
		"CreateInspectionRun": openapi.PermissionCreateInspectionRun, "GetInspectionRun": openapi.PermissionGetInspectionRun,
		"CancelInspectionRun": openapi.PermissionCancelInspectionRun, "RetryInspectionRun": openapi.PermissionRetryInspectionRun,
		"ListInspectionTargets": openapi.PermissionListInspectionTargets,
	}
	for operation, permission := range want {
		got, ok := permissionForStrictOperation(operation)
		require.True(t, ok, operation)
		require.Equal(t, permission, got, operation)
	}
}

func TestInspectionRunCancelRetryRequireIdempotencyKeyBeforeService(t *testing.T) {
	tests := []struct{ name, path string }{
		{name: "run policy", path: "/inspection-policies/policy-1/run"},
		{name: "create run", path: "/inspection-runs"},
		{name: "cancel run", path: "/inspection-runs/run-1/cancel"},
		{name: "retry run", path: "/inspection-runs/run-1/retry"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &recordingInspectionService{now: time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC)}
			body := ""
			if test.name == "create run" {
				body = validInspectionRunBody()
			}
			request := httptest.NewRequest(http.MethodPost, platformBasePath+test.path, strings.NewReader(body))
			if body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			response := servePlatformRequest(Services{Inspection: service}, Principal{Subject: "trusted-user", PlatformAdmin: true}, request)
			requireProblem(t, response, http.StatusBadRequest, "invalid_request", response.Header().Get("X-Request-ID"))
			require.Empty(t, service.calls)
		})
	}
}

func TestInspectionRequestBodyCannotOverrideURLScopeOrActor(t *testing.T) {
	service := &recordingInspectionService{now: time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC)}
	body := strings.TrimSuffix(validInspectionPolicyBody(), "}") + `,"tenant_id":"tenant-b","project_id":"project-b","actor":"attacker"}`
	request := httptest.NewRequest(http.MethodPost, platformBasePath+"/inspection-policies", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "scope-override")
	response := servePlatformRequest(Services{Inspection: service}, principalWith(platformTestScope, openapi.PermissionCreateInspectionPolicy), request)
	requireProblem(t, response, http.StatusBadRequest, "invalid_request", response.Header().Get("X-Request-ID"))
	require.Empty(t, service.calls)
}

func TestInspectionPolicyETagAndStaleIfMatch(t *testing.T) {
	service := &recordingInspectionService{now: time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC)}
	getRequest := httptest.NewRequest(http.MethodGet, platformBasePath+"/inspection-policies/policy-1", nil)
	getResponse := servePlatformRequest(Services{Inspection: service}, principalWith(platformTestScope, openapi.PermissionGetInspectionPolicy), getRequest)
	require.Equal(t, `"3"`, getResponse.Header().Get("ETag"))

	service.err = inspection.ErrConflict
	updateRequest := httptest.NewRequest(http.MethodPatch, platformBasePath+"/inspection-policies/policy-1", strings.NewReader(validInspectionPolicyBody()))
	updateRequest.Header.Set("Content-Type", "application/json")
	updateRequest.Header.Set("Idempotency-Key", "update-policy-stale")
	updateRequest.Header.Set("If-Match", `"2"`)
	updateResponse := servePlatformRequest(Services{Inspection: service}, principalWith(platformTestScope, openapi.PermissionUpdateInspectionPolicy), updateRequest)
	requireProblem(t, updateResponse, http.StatusPreconditionFailed, "precondition_failed", updateResponse.Header().Get("X-Request-ID"))
}

func TestInspectionListCursorAndScopeArePassedTogether(t *testing.T) {
	service := &recordingInspectionService{now: time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC)}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/inspection-runs?cursor=opaque-scope-bound&limit=7", nil)
	response := servePlatformRequest(Services{Inspection: service}, principalWith(platformTestScope, openapi.PermissionListInspectionRuns), request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, inspection.CursorFilter{Cursor: "opaque-scope-bound", Limit: 7}, service.calls[0].filter)
	require.Equal(t, platformTestScope, service.calls[0].scope)
}

func TestInspectionInternalFailureUsesStableProblemWithoutRawDetails(t *testing.T) {
	service := &recordingInspectionService{err: errors.New("postgres password=do-not-leak")}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/inspection-overview", nil)
	response := servePlatformRequest(Services{Inspection: service}, principalWith(platformTestScope, openapi.PermissionGetInspectionOverview), request)
	requireProblem(t, response, http.StatusInternalServerError, "internal_error", response.Header().Get("X-Request-ID"))
	require.NotContains(t, response.Body.String(), "do-not-leak")
}

func TestInspectionCreateItemIdempotencyReplaysOneDeterministicResourceAndAudit(t *testing.T) {
	now := time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC)
	repository := &applicationInspectionRepository{items: map[string]inspection.Item{}}
	audits := &recordingAuditService{}
	application := &inspectionApplicationService{repository: repository, audit: audits, idempotency: idempotency.NewService(newHTTPIdempotencyStore()), now: func() time.Time { return now }}
	services := Services{Inspection: application}
	principal := principalWith(platformTestScope, openapi.PermissionCreateInspectionItem)
	request := func(body string) *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/inspection-items", strings.NewReader(body))
		value.Header.Set("Content-Type", "application/json")
		value.Header.Set("Idempotency-Key", "create-item-deterministic")
		value.Header.Set("X-Request-ID", "request-create-item")
		return value
	}

	first := servePlatformRequest(services, principal, request(validInspectionItemBody()))
	second := servePlatformRequest(services, principal, request(validInspectionItemBody()))

	require.Equal(t, http.StatusCreated, first.Code, first.Body.String())
	require.Equal(t, first.Body.String(), second.Body.String())
	require.Equal(t, 1, repository.creates)
	require.Len(t, repository.items, 1)
	require.Equal(t, 1, audits.recordCalls)
	for _, item := range repository.items {
		require.Equal(t, deterministicInspectionID("inspection-item", platformTestScope, "trusted-user", "CreateInspectionItem", "create-item-deterministic"), item.ID)
		require.Equal(t, platformTestScope, item.Scope)
	}

	collisionBody := strings.Replace(validInspectionItemBody(), `"name":"CPU"`, `"name":"Different"`, 1)
	collision := servePlatformRequest(services, principal, request(collisionBody))
	requireProblem(t, collision, http.StatusConflict, "idempotency_conflict", collision.Header().Get("X-Request-ID"))
	require.Equal(t, 1, repository.creates)
}

func TestInspectionCancelCrashRetryUsesImmutableSnapshotCorrelation(t *testing.T) {
	now := time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC)
	run := inspection.Run{Scope: platformTestScope, ID: "run-1", JobID: "job-1", Status: inspection.RunCollecting, Trigger: inspection.RunTriggerManual, ItemSnapshot: []inspection.Item{}, TargetCount: 1, AuditCorrelation: "inspection-run:run-1", InitiatedBy: "trusted-user", RequestID: "request-run-1", CreatedAt: now.Add(-time.Minute)}
	repository := &applicationInspectionRepository{items: map[string]inspection.Item{}, runDetail: inspection.RunDetail{Run: run}}
	current := validPlatformJob()
	current.ID, current.Scope, current.Status, current.Version = "job-1", platformTestScope, job.StatusRunning, 7
	cancelled := current
	cancelled.Status, cancelled.Version = job.StatusCancelling, 8
	jobs := &inspectionCancellationJobService{current: current, cancelled: cancelled}
	audits := &recordingAuditService{}
	store := newHTTPIdempotencyStore()
	store.completeErr = errors.New("crash after cancellation transaction")
	application := &inspectionApplicationService{repository: repository, jobs: jobs, audit: audits, idempotency: idempotency.NewService(store), now: func() time.Time { return now }}
	services := Services{Inspection: application}
	principal := principalWith(platformTestScope, openapi.PermissionCancelInspectionRun)
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/inspection-runs/run-1/cancel", nil)
		value.Header.Set("Idempotency-Key", "cancel-run-crash")
		value.Header.Set("X-Request-ID", "request-cancel-run")
		return value
	}

	first := servePlatformRequest(services, principal, request())
	requireProblem(t, first, http.StatusInternalServerError, "internal_error", "request-cancel-run")
	require.Equal(t, 1, jobs.cancelCalls)
	require.Zero(t, audits.recordCalls)

	store.completeErr = nil
	retry := servePlatformRequest(services, principal, request())
	require.Equal(t, http.StatusAccepted, retry.Code, retry.Body.String())
	require.Equal(t, 1, jobs.cancelCalls, "exact crash retry must recover without a second cancellation")
	require.Equal(t, 1, jobs.findCalls)
	require.Equal(t, 1, audits.recordCalls)
	replay := servePlatformRequest(services, principal, request())
	require.Equal(t, retry.Body.Bytes(), replay.Body.Bytes())
	require.Equal(t, 1, jobs.cancelCalls)
	require.Equal(t, 1, audits.recordCalls)
}

type inspectionServiceCall struct {
	operation, actor, key, id string
	scope                     platformscope.Scope
	filter                    inspection.CursorFilter
}

type recordingInspectionService struct {
	now   time.Time
	err   error
	calls []inspectionServiceCall
}

func (service *recordingInspectionService) record(operation string, scope platformscope.Scope, actor, key, id string, filter inspection.CursorFilter) error {
	service.calls = append(service.calls, inspectionServiceCall{operation: operation, scope: scope, actor: actor, key: key, id: id, filter: filter})
	return service.err
}

func (service *recordingInspectionService) ListItems(_ context.Context, scope platformscope.Scope, filter inspection.ItemFilter) (inspection.ItemPage, error) {
	err := service.record("list-items", scope, "", "", "", filter.CursorFilter)
	return inspection.ItemPage{Items: []inspection.Item{service.item()}, More: false}, err
}
func (service *recordingInspectionService) CreateItem(_ context.Context, scope platformscope.Scope, actor, key string, value inspection.Item) (inspection.Item, error) {
	err := service.record("create-item", scope, actor, key, value.ID, inspection.CursorFilter{})
	return service.item(), err
}
func (service *recordingInspectionService) GetOverview(_ context.Context, scope platformscope.Scope) (InspectionOverview, error) {
	err := service.record("overview", scope, "", "", "", inspection.CursorFilter{})
	return InspectionOverview{TargetCount: 1, OnlineTargetCount: 1, RunStatusCounts: map[inspection.RunStatus]int{inspection.RunCompleted: 1}, FindingLevelCounts: map[inspection.FindingLevel]int{inspection.LevelHealthy: 1}}, err
}
func (service *recordingInspectionService) ListPolicies(_ context.Context, scope platformscope.Scope, filter inspection.PolicyFilter) (inspection.PolicyPage, error) {
	err := service.record("list-policies", scope, "", "", "", filter.CursorFilter)
	return inspection.PolicyPage{Items: []inspection.Policy{service.policy()}}, err
}
func (service *recordingInspectionService) CreatePolicy(_ context.Context, scope platformscope.Scope, actor, key string, value inspection.Policy) (inspection.Policy, error) {
	err := service.record("create-policy", scope, actor, key, value.ID, inspection.CursorFilter{})
	return service.policy(), err
}
func (service *recordingInspectionService) GetPolicy(_ context.Context, scope platformscope.Scope, id string) (inspection.Policy, error) {
	err := service.record("get-policy", scope, "", "", id, inspection.CursorFilter{})
	return service.policy(), err
}
func (service *recordingInspectionService) UpdatePolicy(_ context.Context, scope platformscope.Scope, actor, key, id string, current int64, value inspection.Policy) (inspection.Policy, error) {
	err := service.record("update-policy", scope, actor, key, id, inspection.CursorFilter{})
	policy := service.policy()
	policy.Version = current + 1
	return policy, err
}
func (service *recordingInspectionService) RunPolicy(_ context.Context, scope platformscope.Scope, actor, key, id string) (inspection.Run, error) {
	err := service.record("run-policy", scope, actor, key, id, inspection.CursorFilter{})
	return service.run(), err
}
func (service *recordingInspectionService) ListReports(_ context.Context, scope platformscope.Scope, filter inspection.ReportFilter) (inspection.ReportPage, error) {
	err := service.record("list-reports", scope, "", "", "", filter.CursorFilter)
	return inspection.ReportPage{Items: []inspection.ReportSnapshot{service.report()}}, err
}
func (service *recordingInspectionService) GetReport(_ context.Context, scope platformscope.Scope, id string) (inspection.ReportSnapshot, error) {
	err := service.record("get-report", scope, "", "", id, inspection.CursorFilter{})
	return service.report(), err
}
func (service *recordingInspectionService) CreateReportDownload(_ context.Context, scope platformscope.Scope, actor, key, id string) (artifact.Download, error) {
	err := service.record("download-report", scope, actor, key, id, inspection.CursorFilter{})
	return artifact.Download{URL: "https://control.example/download", ExpiresAt: service.time().Add(time.Minute)}, err
}
func (service *recordingInspectionService) ListRuns(_ context.Context, scope platformscope.Scope, filter inspection.RunFilter) (inspection.RunPage, error) {
	err := service.record("list-runs", scope, "", "", "", filter.CursorFilter)
	return inspection.RunPage{Items: []inspection.Run{service.run()}}, err
}
func (service *recordingInspectionService) CreateRun(_ context.Context, request inspection.CreateRunRequest) (inspection.Run, error) {
	err := service.record("create-run", request.Scope, request.InitiatedBy, request.IdempotencyKey, "", inspection.CursorFilter{})
	return service.run(), err
}
func (service *recordingInspectionService) GetRun(_ context.Context, scope platformscope.Scope, id string) (inspection.RunDetail, error) {
	err := service.record("get-run", scope, "", "", id, inspection.CursorFilter{})
	return inspection.RunDetail{Run: service.run(), Targets: []inspection.TargetRun{{TargetID: "agent-1", AgentID: "agent-1", CommandID: "command-1", Status: inspection.TargetSucceeded, ObservedAt: service.time()}}}, err
}
func (service *recordingInspectionService) CancelRun(_ context.Context, scope platformscope.Scope, actor, key, id string) (inspection.Run, error) {
	err := service.record("cancel-run", scope, actor, key, id, inspection.CursorFilter{})
	return service.run(), err
}
func (service *recordingInspectionService) RetryRun(_ context.Context, scope platformscope.Scope, actor, key, id string) (inspection.Run, error) {
	err := service.record("retry-run", scope, actor, key, id, inspection.CursorFilter{})
	return service.run(), err
}
func (service *recordingInspectionService) ListTargets(_ context.Context, scope platformscope.Scope, filter inspection.CursorFilter) (InspectionTargetPage, error) {
	err := service.record("list-targets", scope, "", "", "", filter)
	return InspectionTargetPage{Items: []inspection.HostTarget{{Scope: scope, AgentID: "agent-1", DisplayName: "DB host", Host: "db-1.example", Labels: map[string]string{"role": "db"}, Connectivity: "online", Capabilities: []string{"host.inspect"}}}}, err
}

func (service *recordingInspectionService) time() time.Time {
	if service.now.IsZero() {
		return time.Date(2026, 8, 29, 8, 0, 0, 0, time.UTC)
	}
	return service.now
}
func (service *recordingInspectionService) item() inspection.Item {
	return inspection.Item{Scope: platformTestScope, ID: "custom.cpu", Version: 1, Name: "CPU", Description: "CPU usage", Category: "host", ScopeType: inspection.ScopeHost, SourceType: inspection.SourceMetric, MetricRule: &inspection.MetricRule{MetricName: "system.cpu.utilization", Labels: map[string]string{}, Window: 5 * time.Minute, Aggregation: inspection.AggregationLatest, Operator: inspection.OperatorGTE, WarningThreshold: 80, CriticalThreshold: 90}, EvidenceSelector: []string{"value"}, RecommendationTemplate: "Reduce load", Enabled: true, CreatedAt: service.time(), UpdatedAt: service.time()}
}
func (service *recordingInspectionService) policy() inspection.Policy {
	return inspection.Policy{Scope: platformTestScope, ID: "policy-1", Name: "Daily", Enabled: true, Version: 3, Items: []inspection.PolicyItem{{ItemID: "custom.cpu", Version: 1}}, Selector: inspection.TargetSelector{AgentIDs: []string{"agent-1"}, Labels: map[string]string{}}, TargetTimeout: time.Minute, MaxConcurrency: 1, CreatedAt: service.time(), UpdatedAt: service.time()}
}
func (service *recordingInspectionService) run() inspection.Run {
	return inspection.Run{Scope: platformTestScope, ID: "run-1", JobID: "job-1", Status: inspection.RunCompleted, Trigger: inspection.RunTriggerManual, ItemSnapshot: []inspection.Item{service.item()}, TargetCount: 1, CompletedTargetCount: 1, ReportID: "report-1", AuditCorrelation: "inspection-run:run-1", InitiatedBy: "trusted-user", RequestID: "request-1", CreatedAt: service.time(), FinishedAt: timePointer(service.time())}
}
func (service *recordingInspectionService) report() inspection.ReportSnapshot {
	return inspection.ReportSnapshot{Scope: platformTestScope, ID: "report-1", RunID: "run-1", Status: inspection.ReportCompleted, Summary: "healthy=1", Artifacts: []job.ArtifactReference{{ArtifactID: "report-1.json", Kind: "inspection-report"}}, GeneratedAt: service.time(), Document: &inspection.ReportDocument{ReportID: "report-1", RunID: "run-1", Status: inspection.RunCompleted, Summary: "healthy=1", GeneratedAt: service.time()}}
}

func validInspectionItemBody() string {
	return `{"name":"CPU","description":"CPU usage","category":"host","scope_type":"host","source_type":"metric","metric_rule":{"metric_name":"system.cpu.utilization","labels":{},"window":"5m","aggregation":"latest","operator":"gte","warning_threshold":80,"critical_threshold":90},"evidence_selector":{"fields":["value"]},"required_capabilities":[],"recommendation_template":"Reduce load"}`
}
func validInspectionPolicyBody() string {
	return `{"name":"Daily","enabled":true,"target_ids":["agent-1"],"labels":{},"item_versions":[{"item_id":"custom.cpu","version":1}],"target_timeout_seconds":60,"max_concurrency":1}`
}
func validInspectionRunBody() string {
	return `{"target_ids":["agent-1"],"item_versions":[{"item_id":"custom.cpu","version":1}],"target_timeout_seconds":60,"max_concurrency":1}`
}

func timePointer(value time.Time) *time.Time { return &value }

type applicationInspectionRepository struct {
	items     map[string]inspection.Item
	creates   int
	runDetail inspection.RunDetail
}

func (repository *applicationInspectionRepository) CreateItem(_ context.Context, value inspection.Item) error {
	key := value.Scope.Key() + "\x00" + value.ID + "\x00" + strconv.Itoa(value.Version)
	if _, exists := repository.items[key]; exists {
		return inspection.ErrDuplicate
	}
	repository.creates++
	repository.items[key] = value
	return nil
}
func (repository *applicationInspectionRepository) ListItems(_ context.Context, scope platformscope.Scope, filter inspection.ItemFilter) (inspection.ItemPage, error) {
	page := inspection.ItemPage{}
	for _, version := range filter.Versions {
		if value, ok := repository.items[scope.Key()+"\x00"+version.ItemID+"\x00"+strconv.Itoa(version.Version)]; ok {
			page.Items = append(page.Items, value)
		}
	}
	return page, nil
}
func (*applicationInspectionRepository) CreatePolicy(context.Context, inspection.Policy) error {
	return nil
}
func (*applicationInspectionRepository) ListPolicies(context.Context, platformscope.Scope, inspection.PolicyFilter) (inspection.PolicyPage, error) {
	return inspection.PolicyPage{}, nil
}
func (*applicationInspectionRepository) GetPolicy(context.Context, platformscope.Scope, string) (inspection.Policy, error) {
	return inspection.Policy{}, inspection.ErrNotFound
}
func (*applicationInspectionRepository) UpdatePolicy(context.Context, inspection.Policy, int64) (inspection.Policy, error) {
	return inspection.Policy{}, inspection.ErrNotFound
}
func (*applicationInspectionRepository) ClaimDuePolicies(context.Context, time.Time, int, time.Duration) ([]inspection.Policy, error) {
	return nil, nil
}
func (*applicationInspectionRepository) CreateRunWithJob(context.Context, inspection.Run, []inspection.TargetRun, job.Job, []job.OutboxMessage) error {
	return nil
}
func (*applicationInspectionRepository) CreateClaimedRunWithJob(context.Context, inspection.Policy, inspection.Run, []inspection.TargetRun, job.Job, []job.OutboxMessage) (inspection.Run, error) {
	return inspection.Run{}, nil
}
func (repository *applicationInspectionRepository) GetRun(_ context.Context, scope platformscope.Scope, id string) (inspection.RunDetail, error) {
	if repository.runDetail.Run.Scope != scope || repository.runDetail.Run.ID != id {
		return inspection.RunDetail{}, inspection.ErrNotFound
	}
	return repository.runDetail, nil
}
func (*applicationInspectionRepository) GetRunByIdempotencyKey(context.Context, platformscope.Scope, string) (inspection.Run, error) {
	return inspection.Run{}, inspection.ErrNotFound
}
func (*applicationInspectionRepository) ListRuns(context.Context, platformscope.Scope, inspection.RunFilter) (inspection.RunPage, error) {
	return inspection.RunPage{}, nil
}
func (*applicationInspectionRepository) GetReport(context.Context, platformscope.Scope, string) (inspection.ReportSnapshot, error) {
	return inspection.ReportSnapshot{}, inspection.ErrNotFound
}
func (*applicationInspectionRepository) ListReports(context.Context, platformscope.Scope, inspection.ReportFilter) (inspection.ReportPage, error) {
	return inspection.ReportPage{}, nil
}

type inspectionCancellationJobService struct {
	current     job.Job
	cancelled   job.Job
	snapshot    *job.CancellationSnapshot
	cancelCalls int
	findCalls   int
}

func (service *inspectionCancellationJobService) Get(context.Context, platformscope.Scope, string) (job.Job, error) {
	return service.current, nil
}
func (service *inspectionCancellationJobService) RequestCancelWithSnapshot(_ context.Context, scope platformscope.Scope, id, _ string, version int64, at time.Time, input job.CancellationSnapshotInput) (job.Job, error) {
	service.cancelCalls++
	service.snapshot = &job.CancellationSnapshot{Scope: scope, JobID: id, Key: input.Key, OwnerToken: input.OwnerToken, CurrentVersion: version, Job: service.cancelled, AuditEventJSON: append([]byte(nil), input.AuditEventJSON...), CreatedAt: at.UTC()}
	service.current = service.cancelled
	return service.cancelled, nil
}
func (service *inspectionCancellationJobService) GetCancellationSnapshot(_ context.Context, scope platformscope.Scope, id string, key job.CancellationSnapshotKey) (job.CancellationSnapshot, error) {
	if service.snapshot == nil || service.snapshot.Scope != scope || service.snapshot.JobID != id || service.snapshot.Key != key {
		return job.CancellationSnapshot{}, job.ErrNotFound
	}
	return *service.snapshot, nil
}
func (service *inspectionCancellationJobService) FindCancellationSnapshot(_ context.Context, scope platformscope.Scope, id string, correlation job.CancellationSnapshotCorrelation) (job.CancellationSnapshot, error) {
	service.findCalls++
	if service.snapshot == nil || service.snapshot.Scope != scope || service.snapshot.JobID != id || service.snapshot.Key.Actor != correlation.Actor || service.snapshot.Key.OperationID != correlation.OperationID || service.snapshot.Key.IdempotencyKey != correlation.IdempotencyKey || service.snapshot.Key.RequestFingerprint != correlation.RequestFingerprint {
		return job.CancellationSnapshot{}, job.ErrNotFound
	}
	return *service.snapshot, nil
}
