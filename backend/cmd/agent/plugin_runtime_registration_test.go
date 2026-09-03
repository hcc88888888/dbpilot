package main

import (
	"context"
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"github.com/stretchr/testify/require"
)

func TestRegisterPluginRuntimeExecutorsAdvertisesEveryDedicatedRuntimeRoute(t *testing.T) {
	registry := agent.NewExecutorRegistry()
	require.NoError(t, registerPluginRuntimeExecutors(registry, noopPluginRuntime{}))
	require.ElementsMatch(t, []string{"plugin.configuration.apply.v1", "plugin.instance.validate.v1", "plugin.drain.v1"}, registry.Capabilities())
}

type noopPluginRuntime struct{}

func (noopPluginRuntime) ApplyPluginConfiguration(context.Context, *agentv1.ApplyPluginConfiguration, pluginsupervisor.ExecutionFence) error {
	return nil
}
func (noopPluginRuntime) ValidateDatabaseInstance(context.Context, *agentv1.ValidateDatabaseInstance, pluginsupervisor.ExecutionFence) (plugingateway.ValidationResult, error) {
	return plugingateway.ValidationResult{}, nil
}
func (noopPluginRuntime) DrainPlugin(context.Context, *agentv1.DrainPlugin, pluginsupervisor.ExecutionFence) error {
	return nil
}
