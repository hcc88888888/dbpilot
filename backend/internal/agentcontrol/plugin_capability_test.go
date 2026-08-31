package agentcontrol

import (
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
)

func TestReconcilePluginNegotiatesExactCapabilityName(t *testing.T) {
	capability, ok := commandCapability(&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{}}})
	require.True(t, ok)
	require.Equal(t, "plugin.reconcile.v1", capability)
}
