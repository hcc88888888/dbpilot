package controlplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"github.com/stretchr/testify/require"
)

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
	value pluginassignment.Assignment
	scope platformscope.Scope
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
	return service.value, nil
}
