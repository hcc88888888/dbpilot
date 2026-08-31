package reconciliation

import (
	"context"
	"fmt"
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
	waiting  int
	stored   *job.Job
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
func (repository *memoryReconcileRepository) MarkWaiting(context.Context, pluginassignment.ReconcileClaim, string) error {
	repository.waiting++
	return nil
}
func (repository *memoryReconcileRepository) FindScheduledJob(context.Context, pluginassignment.Assignment) (job.Job, bool, error) {
	if repository.stored != nil {
		return *repository.stored, true, nil
	}
	return job.Job{}, false, nil
}

func TestReconcileAssignmentReturnsAuthoritativeStoredJobAtAdvancedClock(t *testing.T) {
	now := time.Date(2026, 8, 31, 3, 0, 0, 0, time.UTC)
	assignment := reconcileAssignmentFixture(now)
	stored, _, err := buildPluginJob(assignment, now)
	require.NoError(t, err)
	repository := &memoryReconcileRepository{stored: &stored}
	got, err := NewPluginReconciler(repository).ReconcileAssignment(context.Background(), assignment, now.Add(8*time.Hour))
	require.NoError(t, err)
	require.Equal(t, stored, got)
	require.Equal(t, now, got.CreatedAt)
}

func TestRolloutUsesStableAssignmentBucketAndSafetyBypassesDelay(t *testing.T) {
	now := time.Date(2026, 8, 31, 3, 0, 0, 0, time.UTC)
	eligible, ineligible := reconcileAssignmentFixture(now), reconcileAssignmentFixture(now)
	eligible.RolloutPercentage, ineligible.RolloutPercentage = 50, 50
	for index := 0; index < 10000 && rolloutEligible(eligible) == rolloutEligible(ineligible); index++ {
		ineligible.ID = fmt.Sprintf("assignment-%d", index)
	}
	require.NotEqual(t, rolloutEligible(eligible), rolloutEligible(ineligible))
	claims := []pluginassignment.ReconcileClaim{{Assignment: eligible, Token: "claim-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", LeasedUntil: now.Add(time.Minute)}, {Assignment: ineligible, Token: "claim-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", LeasedUntil: now.Add(time.Minute)}}
	repository := &memoryReconcileRepository{claims: claims}
	result, err := NewPluginReconciler(repository).Reconcile(context.Background(), now, 10)
	require.NoError(t, err)
	require.Equal(t, 1, result.Enqueued)
	require.Equal(t, 1, result.Waiting)
	safety := ineligible
	safety.DesiredState = pluginassignment.DesiredStopped
	require.True(t, rolloutEligible(safety))
	safety.DesiredState = pluginassignment.DesiredAbsent
	safety.InstanceIDs = []string{}
	require.True(t, rolloutEligible(safety))
}
func (repository *memoryReconcileRepository) Schedule(_ context.Context, _ pluginassignment.ReconcileClaim, value job.Job, message job.OutboxMessage) (job.Job, bool, error) {
	repository.jobs = append(repository.jobs, value)
	repository.messages = append(repository.messages, message)
	return value, true, nil
}

func reconcileAssignmentFixture(now time.Time) pluginassignment.Assignment {
	return pluginassignment.Assignment{ID: "assignment-a", Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, HostID: "host-a", AgentID: "agent-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersionID: "mysql-version-1", DesiredVersion: "1.2.3", ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DesiredState: pluginassignment.DesiredRunning, ConfigurationRevision: 7, OperationRevision: 9, RolloutPercentage: 100, InstanceIDs: []string{"instance-a", "instance-b"}, TemplateRevisionIDs: []string{"template-a:3"}, ReconcileState: pluginassignment.ReconcilePending, Revision: 3, CreatedAt: now, UpdatedAt: now}
}
