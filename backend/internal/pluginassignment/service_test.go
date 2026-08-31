package pluginassignment

import (
	"context"
	"testing"
	"time"

	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestServiceReusesAssignmentForTwoInstancesAndFencesDesiredRevision(t *testing.T) {
	now := time.Date(2026, 8, 31, 2, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	repository := &memoryRepository{assignment: validAssignmentFixture(scope, now)}
	service := NewService(repository)

	first, err := service.EnsureForInstance(context.Background(), databaseinstance.Instance{ID: "instance-a", Scope: scope, HostID: "host-a", AgentID: "agent-a", DatabaseFamily: "mysql", DatabaseVariant: "mysql"})
	require.NoError(t, err)
	second, err := service.EnsureForInstance(context.Background(), databaseinstance.Instance{ID: "instance-b", Scope: scope, HostID: "host-a", AgentID: "agent-a", DatabaseFamily: "mysql", DatabaseVariant: "mysql"})
	require.NoError(t, err)
	require.Equal(t, first.ID, second.ID)
	require.Equal(t, []string{"instance-a", "instance-b"}, second.InstanceIDs)

	state := DesiredStopped
	update := DesiredUpdate{DesiredState: &state, Audit: validAssignmentAudit("stop")}
	updated, err := service.SetDesiredState(context.Background(), scope, second.ID, second.Revision, update)
	require.NoError(t, err)
	require.Equal(t, second.ConfigurationRevision, updated.ConfigurationRevision, "state-only change does not rewrite plugin configuration")
	require.Equal(t, second.OperationRevision+1, updated.OperationRevision)
	_, err = service.SetDesiredState(context.Background(), scope, second.ID, second.Revision, update)
	require.ErrorIs(t, err, ErrPrecondition)
}

type memoryRepository struct{ assignment Assignment }

func (repository *memoryRepository) EnsureForInstance(_ context.Context, instance databaseinstance.Instance) (Assignment, error) {
	if repository.assignment.Scope != instance.Scope || repository.assignment.AgentID != instance.AgentID || repository.assignment.DatabaseFamily != instance.DatabaseFamily {
		return Assignment{}, ErrConflict
	}
	repository.assignment.InstanceIDs = sortedUnique(append(repository.assignment.InstanceIDs, instance.ID))
	repository.assignment.ConfigurationRevision++
	repository.assignment.Revision++
	return repository.assignment, nil
}
func (repository *memoryRepository) List(context.Context, platformscope.Scope, Filter) (Page, error) {
	return Page{Items: []Assignment{repository.assignment}}, nil
}
func (repository *memoryRepository) Get(context.Context, platformscope.Scope, string) (Assignment, error) {
	return repository.assignment, nil
}
func (repository *memoryRepository) SetDesiredState(_ context.Context, _ platformscope.Scope, _ string, revision uint64, update DesiredUpdate) (Assignment, error) {
	if revision != repository.assignment.Revision {
		return Assignment{}, ErrPrecondition
	}
	if update.DesiredState != nil && *update.DesiredState != repository.assignment.DesiredState {
		repository.assignment.DesiredState = *update.DesiredState
		repository.assignment.OperationRevision++
	}
	if update.DesiredVersion != nil && *update.DesiredVersion != repository.assignment.DesiredVersion {
		repository.assignment.DesiredVersion = *update.DesiredVersion
		repository.assignment.ConfigurationRevision++
		repository.assignment.OperationRevision++
	}
	if update.RolloutPercentage != nil {
		repository.assignment.RolloutPercentage = *update.RolloutPercentage
		repository.assignment.OperationRevision++
	}
	repository.assignment.Revision++
	return repository.assignment, nil
}
func (repository *memoryRepository) RecordObservation(context.Context, ObservationReport) error {
	return nil
}
func (repository *memoryRepository) ForceReconcile(context.Context, platformscope.Scope, string, MutationAudit) (Assignment, error) {
	return repository.assignment, nil
}

func validAssignmentFixture(scope platformscope.Scope, now time.Time) Assignment {
	return Assignment{ID: "assignment-a", Scope: scope, HostID: "host-a", AgentID: "agent-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersionID: "mysql-version-1", DesiredVersion: "1.2.3", ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DesiredState: DesiredRunning, ConfigurationRevision: 1, OperationRevision: 1, RolloutPercentage: 100, InstanceIDs: []string{}, ReconcileState: ReconcilePending, Revision: 1, CreatedAt: now, UpdatedAt: now}
}

func validAssignmentAudit(key string) MutationAudit {
	return MutationAudit{Actor: "operator-a", OperationID: "updatePluginAssignment", IdempotencyKey: key, RequestFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RequestID: "request-a"}
}
