package controlplane

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"github.com/stretchr/testify/require"
)

func TestPluginAssignmentReconcileConcurrentExactRetriesUsePostgresResponse(t *testing.T) {
	if os.Getenv("DBPILOT_HTTP_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_HTTP_POSTGRES_INTEGRATION=1")
	}
	ctx := context.Background()
	database := openHTTPIntegrationDatabase(t, ctx, os.Getenv("DBPILOT_HTTP_POSTGRES_DSN"), "plugin_reconcile_concurrent")
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	assignment := validControlPlaneAssignment(now)
	service := &recordingPluginAssignmentService{value: assignment}
	timeout := now.Add(time.Hour)
	authoritative := job.Job{ID: "job-plugin-pg", Type: "plugin.reconcile", Scope: platformTestScope, Status: job.StatusQueued, Outcome: job.OutcomeNone, TargetResourceIDs: []string{"agent-a"}, InitiatedBy: "plugin-reconciler", SourceResource: job.ResourceReference{ResourceType: "plugin_assignment", ResourceID: assignment.ID}, IdempotencyKey: "plugin-reconcile:pg", Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: time.Minute, RequestID: "request-job-pg", TraceID: "trace-job-pg"}
	reconciler := &recordingPluginAssignmentReconciler{value: authoritative}
	gap := &commitSideEffectGapStore{inner: idempotency.NewPostgresStore(database), fail: true, commitThenFail: true}
	services := Services{PluginAssignments: service, PluginReconciler: reconciler, Idempotency: idempotency.NewService(gap), Now: func() time.Time { return now }}
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-assignments/assignment-a/actions/reconcile", nil)
		value.Header.Set("Idempotency-Key", "reconcile-pg")
		return value
	}
	failed := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
	require.Equal(t, http.StatusInternalServerError, failed.Code)
	gap.fail = false
	const consumers = 24
	responses := make(chan *httptest.ResponseRecorder, consumers)
	var wait sync.WaitGroup
	for index := 0; index < consumers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
		}()
	}
	wait.Wait()
	close(responses)
	var body string
	for response := range responses {
		require.Equal(t, http.StatusAccepted, response.Code, response.Body.String())
		if body == "" {
			body = response.Body.String()
		} else {
			require.JSONEq(t, body, response.Body.String())
		}
	}
}

func TestPluginAssignmentReconcileLostResponseRecoversExactAuthoritativeJob(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	assignment := validControlPlaneAssignment(now)
	service := &recordingPluginAssignmentService{value: assignment}
	timeout := now.Add(time.Hour)
	authoritative := job.Job{ID: "job-plugin-a", Type: "plugin.reconcile", Scope: platformTestScope, Status: job.StatusQueued, Outcome: job.OutcomeNone, TargetResourceIDs: []string{"agent-a"}, InitiatedBy: "plugin-reconciler", SourceResource: job.ResourceReference{ResourceType: "plugin_assignment", ResourceID: assignment.ID}, IdempotencyKey: "plugin-reconcile:a", Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: time.Minute, RequestID: "request-job", TraceID: "trace-job"}
	reconciler := &recordingPluginAssignmentReconciler{value: authoritative}
	store := newHTTPIdempotencyStore()
	store.completeErr = errors.New("lost HTTP response after durable Job")
	services := Services{PluginAssignments: service, PluginReconciler: reconciler, Idempotency: idempotency.NewService(store), Now: func() time.Time { return now }}
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, platformBasePath+"/plugin-assignments/assignment-a/actions/reconcile", bytes.NewReader(nil))
		value.Header.Set("Idempotency-Key", "reconcile-lost")
		return value
	}
	first := servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
	require.Equal(t, http.StatusInternalServerError, first.Code)
	store.completeErr = nil
	services.Now = func() time.Time { return now.Add(8 * time.Hour) }
	var wait sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 2)
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			responses <- servePlatformRequest(services, principalWith(platformTestScope, openapi.PermissionReconcilePluginAssignment), request())
		}()
	}
	wait.Wait()
	close(responses)
	var body string
	for retry := range responses {
		require.Equal(t, http.StatusAccepted, retry.Code, retry.Body.String())
		require.Contains(t, retry.Body.String(), now.Format(time.RFC3339))
		if body == "" {
			body = retry.Body.String()
		} else {
			require.JSONEq(t, body, retry.Body.String())
		}
	}
	require.Equal(t, authoritative.ID, reconciler.value.ID)
	require.GreaterOrEqual(t, reconciler.callCount(), 2)
}

type recordingPluginAssignmentReconciler struct {
	value job.Job
	calls int
	mu    sync.Mutex
}

func (value *recordingPluginAssignmentReconciler) ReconcileAssignment(context.Context, pluginassignment.Assignment, time.Time) (job.Job, error) {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.calls++
	return value.value, nil
}
func (value *recordingPluginAssignmentReconciler) callCount() int {
	value.mu.Lock()
	defer value.mu.Unlock()
	return value.calls
}

func validControlPlaneAssignment(now time.Time) pluginassignment.Assignment {
	return pluginassignment.Assignment{ID: "assignment-a", Scope: platformTestScope, HostID: "host-a", AgentID: "agent-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersionID: "mysql-version-1", DesiredVersion: "1.2.3", ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DesiredState: pluginassignment.DesiredRunning, ConfigurationRevision: 2, OperationRevision: 3, RolloutPercentage: 100, InstanceIDs: []string{"instance-a"}, TemplateRevisionIDs: []string{}, ReconcileState: pluginassignment.ReconcilePending, Revision: 4, CreatedAt: now, UpdatedAt: now}
}

func TestPluginAssignmentProblemsAreStableAndRedacted(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{{pluginassignment.ErrInvalid, http.StatusBadRequest, "invalid_request"}, {pluginassignment.ErrNotFound, http.StatusNotFound, "not_found"}, {pluginassignment.ErrConflict, http.StatusConflict, "conflict"}, {pluginassignment.ErrPrecondition, http.StatusPreconditionFailed, "state_revision_conflict"}, {pluginassignment.ErrVersionUnavailable, http.StatusUnprocessableEntity, "plugin_version_unavailable"}, {pluginassignment.ErrVersionRevoked, http.StatusConflict, "plugin_version_revoked"}}
	for _, test := range tests {
		problem := problemForError(test.err, "request-a", "/plugin-assignments/assignment-a")
		require.Equal(t, test.status, problem.Status)
		require.Equal(t, test.code, problem.Code)
		require.NotContains(t, problem.Title, test.err.Error())
	}
}

func TestPluginAssignmentGetUsesGeneratedPermissionScopeAndETag(t *testing.T) {
	now := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	value := pluginassignment.Assignment{ID: "assignment-a", Scope: platformTestScope, HostID: "host-a", AgentID: "agent-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersionID: "mysql-version-1", DesiredVersion: "1.2.3", ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DesiredState: pluginassignment.DesiredRunning, ConfigurationRevision: 2, OperationRevision: 3, RolloutPercentage: 100, InstanceIDs: []string{"instance-a"}, TemplateRevisionIDs: []string{}, ReconcileState: pluginassignment.ReconcilePending, Revision: 4, CreatedAt: now, UpdatedAt: now}
	service := &recordingPluginAssignmentService{value: value}
	request := httptest.NewRequest(http.MethodGet, platformBasePath+"/plugin-assignments/assignment-a", nil)
	response := servePlatformRequest(Services{PluginAssignments: service}, principalWith(platformTestScope, openapi.PermissionGetPluginAssignment), request)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Equal(t, `"4"`, response.Header().Get("ETag"))
	require.Contains(t, response.Body.String(), `"assignment_id":"assignment-a"`)
	require.Equal(t, platformTestScope, service.scope)
	requireOpenAPIResponse(t, request, response)
}

type recordingPluginAssignmentService struct {
	value      pluginassignment.Assignment
	scope      platformscope.Scope
	forceCalls int
}

func (service *recordingPluginAssignmentService) EnsureForInstance(context.Context, databaseinstance.Instance) (pluginassignment.Assignment, error) {
	return service.value, nil
}
func (service *recordingPluginAssignmentService) List(_ context.Context, scope platformscope.Scope, _ pluginassignment.Filter) (pluginassignment.Page, error) {
	service.scope = scope
	return pluginassignment.Page{Items: []pluginassignment.Assignment{service.value}}, nil
}
func (service *recordingPluginAssignmentService) Get(_ context.Context, scope platformscope.Scope, _ string) (pluginassignment.Assignment, error) {
	service.scope = scope
	return service.value, nil
}
func (service *recordingPluginAssignmentService) SetDesiredState(context.Context, platformscope.Scope, string, uint64, pluginassignment.DesiredUpdate) (pluginassignment.Assignment, error) {
	return service.value, nil
}
func (service *recordingPluginAssignmentService) RecordObservation(context.Context, pluginassignment.ObservationReport) error {
	return nil
}
func (service *recordingPluginAssignmentService) ForceReconcile(context.Context, platformscope.Scope, string, pluginassignment.MutationAudit) (pluginassignment.Assignment, error) {
	service.forceCalls++
	return service.value, nil
}
