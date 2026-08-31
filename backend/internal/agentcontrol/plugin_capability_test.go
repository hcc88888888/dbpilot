package agentcontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestReconcilePluginNegotiatesExactCapabilityName(t *testing.T) {
	running := &agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{DesiredState: agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_RUNNING}}}
	capability, ok := commandCapability(running)
	require.True(t, ok)
	require.Equal(t, "plugin.reconcile.v1", capability)
	require.Equal(t, []string{"plugin.reconcile.v1", "plugin_reconcile.instance_descriptors.v1"}, commandCapabilities(running))
}

func TestRegistryDoesNotDispatchField20CommandToOldAgent(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	envelope := &agentv1.CommandEnvelope{CommandId: "command-1", AgentId: "agent-1", ExpiresAt: timestamppb.New(now.Add(time.Minute)), Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{InstanceDescriptors: []*agentv1.PluginInstanceDescriptor{{InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}}}}}
	registry := NewRegistry(1)
	registry.now = func() time.Time { return now }
	require.NoError(t, registry.register("agent-1", []string{"plugin.reconcile.v1"}, nil, func() {}))
	err := registry.Dispatch(context.Background(), "agent-1", envelope)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrCapabilityNotAdvertised))
	session, _ := registry.liveSession("agent-1")
	require.Empty(t, session.send)

	registry = NewRegistry(1)
	registry.now = func() time.Time { return now }
	require.NoError(t, registry.register("agent-1", []string{"plugin.reconcile.v1", "plugin_reconcile.instance_descriptors.v1"}, nil, func() {}))
	require.NoError(t, registry.Dispatch(context.Background(), "agent-1", envelope))
	session, _ = registry.liveSession("agent-1")
	require.Len(t, session.send, 1)
}

func TestRegistryDispatchesDescriptorFreeSafetyCommandsToOldAgent(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, desired := range []agentv1.PluginDesiredState{agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_STOPPED, agentv1.PluginDesiredState_PLUGIN_DESIRED_STATE_ABSENT} {
		t.Run(desired.String(), func(t *testing.T) {
			registry := NewRegistry(1)
			registry.now = func() time.Time { return now }
			require.NoError(t, registry.register("agent-1", []string{"plugin.reconcile.v1"}, nil, func() {}))
			envelope := &agentv1.CommandEnvelope{CommandId: "command-safety", AgentId: "agent-1", ExpiresAt: timestamppb.New(now.Add(time.Minute)), Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{DesiredState: desired}}}
			require.Equal(t, []string{"plugin.reconcile.v1"}, commandCapabilities(envelope))
			require.NoError(t, registry.Dispatch(context.Background(), "agent-1", envelope))
			session, _ := registry.liveSession("agent-1")
			require.Len(t, session.send, 1)
		})
	}
}
