package reconciliation

import (
	"context"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPluginReconcilerCreatesOneExactSecretFreeTypedJobOnlyForDrift(t *testing.T) {
	now := time.Date(2026, 8, 31, 3, 0, 0, 0, time.UTC)
	drift := reconcileAssignmentFixture(now)
	repository := &memoryReconcileRepository{claims: []pluginassignment.ReconcileClaim{{Assignment: drift, Token: "claim-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", LeasedUntil: now.Add(time.Minute)}}}
	reconciler := NewPluginReconciler(repository)

	result, err := reconciler.Reconcile(context.Background(), now, 10)
	require.NoError(t, err)
	require.Equal(t, ReconcileResult{Claimed: 1, Enqueued: 1}, result)
	require.Len(t, repository.jobs, 1)
	require.Len(t, repository.messages, 1)
	require.Equal(t, "plugin.reconcile", repository.jobs[0].Type)
	require.Equal(t, []string{"agent-a"}, repository.jobs[0].TargetResourceIDs)

	envelope := new(agentv1.CommandEnvelope)
	require.NoError(t, proto.Unmarshal(repository.messages[0].Payload, envelope))
	require.Equal(t, "agent-a", envelope.GetAgentId())
	require.Equal(t, uint32(900), envelope.GetLeaseSeconds())
	command := envelope.GetReconcilePlugin()
	require.NotNil(t, command)
	require.Equal(t, "assignment-a", command.GetAssignmentId())
	require.Equal(t, []string{"instance-a", "instance-b"}, command.GetInstanceIds())
	require.Equal(t, []string{"template-a:3"}, command.GetTemplateIds())
	require.Len(t, command.GetArtifactSha256(), 32)
	require.Len(t, command.GetManifestDigest(), 32)
	require.NotContains(t, string(repository.messages[0].Payload), "secret://")

	matching := drift
	matching.Observed = &pluginassignment.ObservedState{AssignmentID: matching.ID, PluginID: matching.PluginID, DatabaseFamily: matching.DatabaseFamily, InstalledVersion: matching.DesiredVersion, ActiveSlot: pluginassignment.SlotA, ProcessState: pluginassignment.ProcessRunning, Health: pluginassignment.HealthHealthy, CircuitState: pluginassignment.CircuitClosed, BoundInstanceCount: 2, ActiveConfigurationRevision: matching.ConfigurationRevision, ObservedOperationRevision: matching.OperationRevision, ObservationRevision: 3, ObservedAt: now}
	repository = &memoryReconcileRepository{claims: []pluginassignment.ReconcileClaim{{Assignment: matching, Token: "claim-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", LeasedUntil: now.Add(time.Minute)}}}
	result, err = NewPluginReconciler(repository).Reconcile(context.Background(), now, 10)
	require.NoError(t, err)
	require.Equal(t, ReconcileResult{Claimed: 1, Converged: 1}, result)
	require.Empty(t, repository.jobs)
}

type memoryReconcileRepository struct {
	claims   []pluginassignment.ReconcileClaim
	jobs     []job.Job
	messages []job.OutboxMessage
}

func (repository *memoryReconcileRepository) ClaimDue(context.Context, time.Time, int, time.Duration) ([]pluginassignment.ReconcileClaim, error) {
	return repository.claims, nil
}
func (repository *memoryReconcileRepository) ClaimOne(_ context.Context, assignment pluginassignment.Assignment, _ time.Time, _ time.Duration) (pluginassignment.ReconcileClaim, error) {
	if len(repository.claims) > 0 {
		return repository.claims[0], nil
	}
	return pluginassignment.ReconcileClaim{Assignment: assignment, Token: "claim-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", LeasedUntil: time.Now().UTC().Add(time.Minute)}, nil
}
func (repository *memoryReconcileRepository) MarkConverged(context.Context, pluginassignment.ReconcileClaim) error {
	return nil
}
func (repository *memoryReconcileRepository) MarkConflict(context.Context, pluginassignment.ReconcileClaim) error {
	return nil
}
func (repository *memoryReconcileRepository) Schedule(_ context.Context, _ pluginassignment.ReconcileClaim, value job.Job, message job.OutboxMessage) (bool, error) {
	repository.jobs = append(repository.jobs, value)
	repository.messages = append(repository.messages, message)
	return true, nil
}

func reconcileAssignmentFixture(now time.Time) pluginassignment.Assignment {
	return pluginassignment.Assignment{ID: "assignment-a", Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, HostID: "host-a", AgentID: "agent-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersionID: "mysql-version-1", DesiredVersion: "1.2.3", ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DesiredState: pluginassignment.DesiredRunning, ConfigurationRevision: 7, OperationRevision: 9, RolloutPercentage: 100, InstanceIDs: []string{"instance-a", "instance-b"}, TemplateRevisionIDs: []string{"template-a:3"}, ReconcileState: pluginassignment.ReconcilePending, Revision: 3, CreatedAt: now, UpdatedAt: now}
}
