package agent

import (
	"context"
	"errors"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
)

// PluginCommandRuntime is the narrow, process-fenced Agent boundary used by
// the three dedicated plugin runtime commands. It never accepts executable or
// shell input and never returns driver errors to the control plane.
type PluginCommandRuntime interface {
	ApplyPluginConfiguration(context.Context, *agentv1.ApplyPluginConfiguration, pluginsupervisor.ExecutionFence) error
	ValidateDatabaseInstance(context.Context, *agentv1.ValidateDatabaseInstance, pluginsupervisor.ExecutionFence) (plugingateway.ValidationResult, error)
	DrainPlugin(context.Context, *agentv1.DrainPlugin, pluginsupervisor.ExecutionFence) error
}

type PluginRuntimeExecutor struct{ runtime PluginCommandRuntime }

func NewPluginRuntimeExecutor(runtime PluginCommandRuntime) (*PluginRuntimeExecutor, error) {
	if runtime == nil {
		return nil, errors.New("typed plugin runtime is required")
	}
	return &PluginRuntimeExecutor{runtime: runtime}, nil
}

func (executor *PluginRuntimeExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, reporter ProgressReporter) (*agentv1.CommandResult, error) {
	if executor == nil || executor.runtime == nil || ctx == nil || envelope == nil || reporter == nil {
		return nil, errors.New("typed plugin command is invalid")
	}
	fenced, ok := reporter.(interface {
		ExecutionFence() pluginsupervisor.ExecutionFence
	})
	if !ok {
		return nil, errors.New("typed plugin execution fence is required")
	}
	fence := fenced.ExecutionFence()
	if fence.Validate() != nil || fence.CommandID != envelope.GetCommandId() {
		return nil, errors.New("typed plugin execution fence is invalid")
	}
	switch command := envelope.GetCommand().(type) {
	case *agentv1.CommandEnvelope_ApplyPluginConfiguration:
		if command.ApplyPluginConfiguration == nil {
			return nil, errors.New("plugin configuration command is invalid")
		}
		if err := executor.runtime.ApplyPluginConfiguration(ctx, command.ApplyPluginConfiguration, fence); err != nil {
			return failedPluginRuntimeResult(envelope.GetCommandId(), "plugin_failed", "plugin configuration was not applied"), nil
		}
		return succeededPluginRuntimeResult(envelope.GetCommandId(), "plugin configuration applied"), nil
	case *agentv1.CommandEnvelope_ValidateDatabaseInstance:
		if command.ValidateDatabaseInstance == nil {
			return nil, errors.New("database instance validation command is invalid")
		}
		result, err := executor.runtime.ValidateDatabaseInstance(ctx, command.ValidateDatabaseInstance, fence)
		if err != nil {
			return failedPluginRuntimeResult(envelope.GetCommandId(), "plugin_failed", "database instance validation failed"), nil
		}
		if !result.Valid {
			return failedPluginRuntimeResult(envelope.GetCommandId(), canonicalValidationErrorCode(result.ErrorCode), "database instance validation failed"), nil
		}
		if result.InstanceID != command.ValidateDatabaseInstance.GetInstanceId() || result.ErrorCode != "" {
			return failedPluginRuntimeResult(envelope.GetCommandId(), "plugin_failed", "database instance validation failed"), nil
		}
		return succeededPluginRuntimeResult(envelope.GetCommandId(), "database instance validation succeeded"), nil
	case *agentv1.CommandEnvelope_DrainPlugin:
		if command.DrainPlugin == nil {
			return nil, errors.New("plugin drain command is invalid")
		}
		if err := executor.runtime.DrainPlugin(ctx, command.DrainPlugin, fence); err != nil {
			return failedPluginRuntimeResult(envelope.GetCommandId(), "plugin_failed", "plugin drain failed"), nil
		}
		return succeededPluginRuntimeResult(envelope.GetCommandId(), "plugin drained"), nil
	default:
		return nil, errors.New("unsupported typed plugin command")
	}
}

func canonicalValidationErrorCode(value string) string {
	switch value {
	case "authentication_failed", "instance_authentication_failed":
		return "instance_authentication_failed"
	case "tls_failed", "instance_tls_failed":
		return "instance_tls_failed"
	case "instance_unreachable", "connection_unavailable", "timeout":
		return "instance_unreachable"
	case "unsupported", "unsupported_database", "unsupported_version", "database_version_unsupported":
		return "database_version_unsupported"
	default:
		return "plugin_failed"
	}
}

func succeededPluginRuntimeResult(commandID, summary string) *agentv1.CommandResult {
	return &agentv1.CommandResult{CommandId: commandID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: summary}
}

func failedPluginRuntimeResult(commandID, code, summary string) *agentv1.CommandResult {
	return &agentv1.CommandResult{CommandId: commandID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, ErrorCode: code, Summary: summary}
}

var _ CommandExecutor = (*PluginRuntimeExecutor)(nil)
