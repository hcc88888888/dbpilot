package agent

import (
	"context"
	"errors"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
)

type ReconcilePluginExecutor struct{ supervisor pluginsupervisor.Supervisor }

const PluginReconcileInstanceDescriptorsCapability = "plugin_reconcile.instance_descriptors.v1"

func NewReconcilePluginExecutor(supervisor pluginsupervisor.Supervisor) (*ReconcilePluginExecutor, error) {
	if supervisor == nil {
		return nil, errors.New("plugin supervisor is required")
	}
	return &ReconcilePluginExecutor{supervisor: supervisor}, nil
}

func (*ReconcilePluginExecutor) AdditionalCapabilities() []string {
	return []string{PluginReconcileInstanceDescriptorsCapability}
}

func (executor *ReconcilePluginExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, reporter ProgressReporter) (*agentv1.CommandResult, error) {
	if executor == nil || executor.supervisor == nil || envelope == nil || envelope.GetReconcilePlugin() == nil || reporter == nil {
		return nil, pluginsupervisor.ErrInvalidRequest
	}
	command := envelope.GetReconcilePlugin()
	descriptors := make([]pluginsupervisor.InstanceDescriptor, 0, len(command.GetInstanceDescriptors()))
	for _, descriptor := range command.GetInstanceDescriptors() {
		if descriptor == nil {
			return nil, pluginsupervisor.ErrInvalidRequest
		}
		descriptors = append(descriptors, pluginsupervisor.InstanceDescriptor{InstanceID: descriptor.GetInstanceId(), DatabaseVariant: descriptor.GetDatabaseVariant(), Endpoint: descriptor.GetEndpoint(), UnixSocket: descriptor.GetUnixSocket()})
	}
	request := pluginsupervisor.ReconcileRequest{AssignmentID: command.GetAssignmentId(), PluginID: command.GetPluginId(), DatabaseFamily: command.GetDatabaseFamily(), DesiredVersion: command.GetDesiredVersion(), DesiredState: desiredPluginState(command.GetDesiredState()), ArtifactID: command.GetArtifactId(), ArtifactSHA256: append([]byte(nil), command.GetArtifactSha256()...), ManifestDigest: append([]byte(nil), command.GetManifestDigest()...), ConfigurationRevision: command.GetConfigurationRevision(), OperationRevision: command.GetOperationRevision(), InstanceIDs: append([]string(nil), command.GetInstanceIds()...), InstanceDescriptors: descriptors, TemplateIDs: append([]string(nil), command.GetTemplateIds()...)}
	prepared, err := executor.supervisor.Prepare(ctx, request)
	if err != nil {
		return nil, err
	}
	fenced, ok := reporter.(interface {
		ExecutionFence() pluginsupervisor.ExecutionFence
	})
	if !ok {
		return nil, pluginsupervisor.ErrInvalidFence
	}
	fence := fenced.ExecutionFence()
	if err := fence.Validate(); err != nil || fence.CommandID != envelope.GetCommandId() {
		return nil, pluginsupervisor.ErrInvalidFence
	}
	if err := reporter.Report(&agentv1.CommandProgress{CommandId: envelope.GetCommandId(), Percent: 10, Stage: "plugin_prepared", Message: "plugin reconciliation prepared"}); err != nil {
		return nil, err
	}
	if _, err := executor.supervisor.Start(ctx, prepared, fence); err != nil {
		return nil, err
	}
	if err := reporter.Report(&agentv1.CommandProgress{CommandId: envelope.GetCommandId(), Percent: 100, Stage: "plugin_reconciled", Message: "plugin reconciliation completed"}); err != nil {
		return nil, err
	}
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "plugin reconciliation completed"}, nil
}

func desiredPluginState(value agentv1.PluginDesiredState) pluginsupervisor.DesiredState {
	switch value {
	case agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_ABSENT:
		return pluginsupervisor.DesiredAbsent
	case agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_INSTALLED:
		return pluginsupervisor.DesiredInstalled
	case agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING:
		return pluginsupervisor.DesiredRunning
	case agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_STOPPED:
		return pluginsupervisor.DesiredStopped
	default:
		return pluginsupervisor.DesiredUnspecified
	}
}

var _ CommandExecutor = (*ReconcilePluginExecutor)(nil)
