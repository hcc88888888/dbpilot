package agent

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"github.com/stretchr/testify/require"
)

func TestReconcilePluginExecutorConsumesTypedCommandOnlyAfterExecutionFence(t *testing.T) {
	supervisor := &recordingPluginSupervisor{}
	executor, err := NewReconcilePluginExecutor(supervisor)
	require.NoError(t, err)
	reporter := fencedProgressReporter{fence: pluginsupervisor.ExecutionFence{CommandID: "command-1", ExecutionToken: bytesOfAgent(7, sha256.Size), LeaseRevision: 9, StartedAt: time.Now().UTC()}}
	envelope := &agentv1.CommandEnvelope{CommandId: "command-1", Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{AssignmentId: "assignment-1", PluginId: "mysql", DatabaseFamily: "mysql", DesiredVersion: "1.0.0", DesiredState: agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING, ArtifactId: "artifact-1", ArtifactSha256: bytesOfAgent(1, sha256.Size), ManifestDigest: bytesOfAgent(2, sha256.Size), ConfigurationRevision: 3, OperationRevision: 4, InstanceIds: []string{"mysql-1", "mysql-2"}, TemplateIds: []string{"template-1"}}}}

	result, err := executor.Execute(context.Background(), envelope, &reporter)
	require.NoError(t, err)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, result.GetState())
	require.Equal(t, 1, supervisor.prepareCalls)
	require.Equal(t, 1, supervisor.startCalls)
	require.Equal(t, uint64(9), supervisor.fence.LeaseRevision)
	require.Equal(t, []string{"mysql-1", "mysql-2"}, supervisor.request.InstanceIDs)
	require.Equal(t, []uint32{10, 100}, reporter.percents)
}

func TestReconcilePluginExecutorAdvertisesExactDescriptorProtocolCapability(t *testing.T) {
	executor, err := NewReconcilePluginExecutor(&recordingPluginSupervisor{})
	require.NoError(t, err)
	require.Equal(t, []string{PluginReconcileInstanceDescriptorsCapability}, executor.AdditionalCapabilities())
}

func TestReconcilePluginExecutorRejectsMissingFenceAndNonTypedEnvelope(t *testing.T) {
	supervisor := &recordingPluginSupervisor{}
	executor, err := NewReconcilePluginExecutor(supervisor)
	require.NoError(t, err)
	_, err = executor.Execute(context.Background(), &agentv1.CommandEnvelope{CommandId: "command-1", Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}}}, unfencedReporter{})
	require.Error(t, err)
	require.Zero(t, supervisor.prepareCalls)

	typed := &agentv1.CommandEnvelope{CommandId: "command-1", Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{}}}
	_, err = executor.Execute(context.Background(), typed, unfencedReporter{})
	require.Error(t, err)
	require.Zero(t, supervisor.startCalls)
}

func TestReconcilePluginExecutorAcceptsTask8AbsentCommandWithArtifactMetadata(t *testing.T) {
	supervisor := &recordingPluginSupervisor{}
	executor, err := NewReconcilePluginExecutor(supervisor)
	require.NoError(t, err)
	reporter := fencedProgressReporter{fence: pluginsupervisor.ExecutionFence{CommandID: "command-absent", ExecutionToken: bytesOfAgent(7, sha256.Size), LeaseRevision: 1, StartedAt: time.Now().UTC()}}
	envelope := &agentv1.CommandEnvelope{CommandId: "command-absent", Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{AssignmentId: "assignment-1", PluginId: "mysql", DatabaseFamily: "mysql", DesiredVersion: "1.0.0", DesiredState: agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_ABSENT, ArtifactId: "artifact-1", ArtifactSha256: bytesOfAgent(1, 32), ManifestDigest: bytesOfAgent(2, 32), ConfigurationRevision: 3, OperationRevision: 4}}}
	_, err = executor.Execute(context.Background(), envelope, &reporter)
	require.NoError(t, err)
	require.Equal(t, pluginsupervisor.DesiredAbsent, supervisor.request.DesiredState)
	require.NoError(t, supervisor.request.Validate())
}

type recordingPluginSupervisor struct {
	prepareCalls int
	startCalls   int
	request      pluginsupervisor.ReconcileRequest
	fence        pluginsupervisor.ExecutionFence
}

func (supervisor *recordingPluginSupervisor) Prepare(_ context.Context, request pluginsupervisor.ReconcileRequest) (pluginsupervisor.PreparedChange, error) {
	supervisor.prepareCalls++
	supervisor.request = request
	return pluginsupervisor.PreparedChange{Request: request, PreparedAt: time.Now().UTC()}, nil
}
func (supervisor *recordingPluginSupervisor) Start(_ context.Context, prepared pluginsupervisor.PreparedChange, fence pluginsupervisor.ExecutionFence) (pluginsupervisor.ObservedState, error) {
	supervisor.startCalls++
	supervisor.fence = fence
	return pluginsupervisor.ObservedState{}, nil
}
func (*recordingPluginSupervisor) Stop(context.Context) error                    { return nil }
func (*recordingPluginSupervisor) Observe() []pluginsupervisor.PluginObservation { return nil }

type fencedProgressReporter struct {
	fence    pluginsupervisor.ExecutionFence
	percents []uint32
}

func (reporter *fencedProgressReporter) Report(progress *agentv1.CommandProgress) error {
	reporter.percents = append(reporter.percents, progress.GetPercent())
	return nil
}
func (reporter *fencedProgressReporter) ExecutionFence() pluginsupervisor.ExecutionFence {
	return reporter.fence
}

type unfencedReporter struct{}

func (unfencedReporter) Report(*agentv1.CommandProgress) error { return nil }

func bytesOfAgent(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}
