package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
)

type capabilityDiscoveryRunner struct{}

func (capabilityDiscoveryRunner) Execute(context.Context, *agentv1.CommandEnvelope, interface {
	Report(*agentv1.CommandProgress) error
}) (*agentv1.CommandResult, error) {
	return nil, nil
}

func (capabilityDiscoveryRunner) AdditionalCapabilities() []string {
	return []string{"discovery_source_results_v1", "docker_discovery_configured"}
}

func TestDiscoveryCommandExecutorForwardsProtocolCapabilities(t *testing.T) {
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindDiscoverDatabases, DiscoveryCommandExecutor{Runner: capabilityDiscoveryRunner{}}))
	require.ElementsMatch(t, []string{"discover_databases", "discovery_source_results_v1", "docker_discovery_configured"}, registry.Capabilities())
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, err = NewCommandVerifier("agent-a", public, append(registry.Capabilities(), "docker_discovery_v1", "native_discovery_v1"))
	require.NoError(t, err, "protocol metadata must not be treated as executable command kinds")
}
