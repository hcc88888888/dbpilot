package agent

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"github.com/stretchr/testify/require"
)

func TestPluginRuntimeExecutorRoutesAllThreeTypedCommandsBehindExecutionFence(t *testing.T) {
	runtime := &recordingTypedPluginRuntime{validation: plugingateway.ValidationResult{InstanceID: "instance-a", Valid: true}}
	executor, err := NewPluginRuntimeExecutor(runtime)
	require.NoError(t, err)
	fence := pluginsupervisor.ExecutionFence{CommandID: "command-a", ExecutionToken: bytesOfAgent(7, sha256.Size), LeaseRevision: 2, StartedAt: time.Now().UTC()}

	commands := []*agentv1.CommandEnvelope{
		{CommandId: "command-a", Command: &agentv1.CommandEnvelope_ApplyPluginConfiguration{ApplyPluginConfiguration: &agentv1.ApplyPluginConfiguration{AssignmentId: "assignment-a", ConfigurationRevision: 8, Instances: []*agentv1.PluginInstanceConfiguration{{InstanceId: "instance-a", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", CredentialRevision: 3}}}}},
		{CommandId: "command-a", Command: &agentv1.CommandEnvelope_ValidateDatabaseInstance{ValidateDatabaseInstance: &agentv1.ValidateDatabaseInstance{AssignmentId: "assignment-a", InstanceId: "instance-a", ConfigurationRevision: 8}}},
		{CommandId: "command-a", Command: &agentv1.CommandEnvelope_DrainPlugin{DrainPlugin: &agentv1.DrainPlugin{AssignmentId: "assignment-a", OperationRevision: 9, TimeoutSeconds: 30}}},
	}
	for _, command := range commands {
		result, executeErr := executor.Execute(context.Background(), command, &fencedProgressReporter{fence: fence})
		require.NoError(t, executeErr)
		require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, result.GetState())
	}
	require.Equal(t, 1, runtime.applyCalls)
	require.Equal(t, 1, runtime.validateCalls)
	require.Equal(t, 1, runtime.drainCalls)
	require.Equal(t, uint64(2), runtime.fence.LeaseRevision)
}

func TestPluginRuntimeExecutorPreservesFixedValidationFailureWithoutRawError(t *testing.T) {
	runtime := &recordingTypedPluginRuntime{validation: plugingateway.ValidationResult{InstanceID: "instance-a", ErrorCode: "authentication_failed"}}
	executor, err := NewPluginRuntimeExecutor(runtime)
	require.NoError(t, err)
	fence := pluginsupervisor.ExecutionFence{CommandID: "command-a", ExecutionToken: bytesOfAgent(7, sha256.Size), LeaseRevision: 2, StartedAt: time.Now().UTC()}
	envelope := &agentv1.CommandEnvelope{CommandId: "command-a", Command: &agentv1.CommandEnvelope_ValidateDatabaseInstance{ValidateDatabaseInstance: &agentv1.ValidateDatabaseInstance{AssignmentId: "assignment-a", InstanceId: "instance-a", ConfigurationRevision: 8}}}
	reporter := &fencedProgressReporter{fence: fence}

	result, err := executor.Execute(context.Background(), envelope, reporter)

	require.NoError(t, err)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, result.GetState())
	require.Equal(t, "instance_authentication_failed", result.GetErrorCode())
	require.NotContains(t, result.GetSummary(), "password")
	require.Equal(t, []uint32{10, 100}, reporter.percents)
}

func TestPluginRuntimeExecutorRejectsUnknownCommandAndMissingFence(t *testing.T) {
	runtime := &recordingTypedPluginRuntime{}
	executor, err := NewPluginRuntimeExecutor(runtime)
	require.NoError(t, err)
	_, err = executor.Execute(context.Background(), &agentv1.CommandEnvelope{CommandId: "command-a", Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}}}, &fencedProgressReporter{})
	require.Error(t, err)
	_, err = executor.Execute(context.Background(), &agentv1.CommandEnvelope{CommandId: "command-a", Command: &agentv1.CommandEnvelope_DrainPlugin{DrainPlugin: &agentv1.DrainPlugin{AssignmentId: "assignment-a", OperationRevision: 1, TimeoutSeconds: 1}}}, unfencedReporter{})
	require.Error(t, err)
	require.Zero(t, runtime.drainCalls)
}

func TestTypedPluginRuntimeInventoryAdvertisesSixOfSixExecutableCommands(t *testing.T) {
	registry := NewExecutorRegistry()
	executor, err := NewPluginRuntimeExecutor(&recordingTypedPluginRuntime{})
	require.NoError(t, err)
	for kind, implementation := range map[CommandKind]CommandExecutor{
		CommandKindDiscoverDatabases:        immediateExecutor{},
		CommandKindReconcilePlugin:          immediateExecutor{},
		CommandKindApplyPluginConfiguration: executor,
		CommandKindValidateDatabaseInstance: executor,
		CommandKindDrainPlugin:              executor,
		CommandKindCollectDatabaseMetrics:   immediateExecutor{},
	} {
		require.NoError(t, registry.Register(kind, implementation))
	}
	require.ElementsMatch(t, []string{
		"discover_databases", "plugin.reconcile.v1", "plugin.configuration.apply.v1",
		"plugin.instance.validate.v1", "plugin.drain.v1", "plugin.metrics.collect.v1",
	}, registry.Capabilities())
}

type recordingTypedPluginRuntime struct {
	applyCalls, validateCalls, drainCalls int
	validation                            plugingateway.ValidationResult
	err                                   error
	fence                                 pluginsupervisor.ExecutionFence
}

func (runtime *recordingTypedPluginRuntime) ApplyPluginConfiguration(_ context.Context, _ *agentv1.ApplyPluginConfiguration, fence pluginsupervisor.ExecutionFence) error {
	runtime.applyCalls++
	runtime.fence = fence
	return runtime.err
}
func (runtime *recordingTypedPluginRuntime) ValidateDatabaseInstance(_ context.Context, _ *agentv1.ValidateDatabaseInstance, fence pluginsupervisor.ExecutionFence) (plugingateway.ValidationResult, error) {
	runtime.validateCalls++
	runtime.fence = fence
	return runtime.validation, runtime.err
}
func (runtime *recordingTypedPluginRuntime) DrainPlugin(_ context.Context, _ *agentv1.DrainPlugin, fence pluginsupervisor.ExecutionFence) error {
	runtime.drainCalls++
	runtime.fence = fence
	return runtime.err
}

var _ PluginCommandRuntime = (*recordingTypedPluginRuntime)(nil)
