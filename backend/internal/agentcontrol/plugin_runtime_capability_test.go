package agentcontrol

import (
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
)

func TestServerNegotiatesAllSixTypedPluginRuntimeCommands(t *testing.T) {
	tests := []struct {
		envelope *agentv1.CommandEnvelope
		want     string
	}{
		{&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_DiscoverDatabases{DiscoverDatabases: &agentv1.DiscoverDatabases{}}}, "discover_databases"},
		{&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{}}}, "plugin.reconcile.v1"},
		{&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_ApplyPluginConfiguration{ApplyPluginConfiguration: &agentv1.ApplyPluginConfiguration{}}}, "plugin.configuration.apply.v1"},
		{&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_ValidateDatabaseInstance{ValidateDatabaseInstance: &agentv1.ValidateDatabaseInstance{}}}, "plugin.instance.validate.v1"},
		{&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_DrainPlugin{DrainPlugin: &agentv1.DrainPlugin{}}}, "plugin.drain.v1"},
		{&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{}}}, "plugin.metrics.collect.v1"},
	}
	for _, test := range tests {
		capability, ok := commandCapability(test.envelope)
		require.True(t, ok)
		require.Equal(t, test.want, capability)
	}
	require.Empty(t, commandCapabilities(&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: nil}})[1:], "unknown capability expansion is forbidden")
}
