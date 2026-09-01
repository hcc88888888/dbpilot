package agent

import (
	"crypto/ed25519"
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
)

func TestReconcilePluginVerifierUsesExactAdvertisedCapability(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	verifier, err := NewCommandVerifier("agent-a", private.Public().(ed25519.PublicKey), []string{"plugin.reconcile.v1"})
	require.NoError(t, err)
	require.Contains(t, verifier.capabilities, CommandKind("plugin.reconcile.v1"))

	kind, ok := envelopeCommandKind(&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_ReconcilePlugin{ReconcilePlugin: &agentv1.ReconcilePlugin{}}})
	require.True(t, ok)
	require.Equal(t, CommandKind("plugin.reconcile.v1"), kind)
}

func TestCollectDatabaseMetricsVerifierUsesExactAdvertisedCapability(t *testing.T) {
	_, private, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	verifier, err := NewCommandVerifier("agent-a", private.Public().(ed25519.PublicKey), []string{"plugin.metrics.collect.v1"})
	require.NoError(t, err)
	require.Contains(t, verifier.capabilities, CommandKind("plugin.metrics.collect.v1"))
	kind, ok := envelopeCommandKind(&agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{}}})
	require.True(t, ok)
	require.Equal(t, CommandKind("plugin.metrics.collect.v1"), kind)
}
