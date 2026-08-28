package inspection

import (
	"context"
	"testing"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestConfiguredTargetResolverReturnsSortedUniqueExactScopeMatches(t *testing.T) {
	// Break caught: unioning explicit IDs and label matches without deduping or
	// scope checks can duplicate commands or target another project.
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	resolver, err := NewConfiguredTargetResolver([]HostTarget{
		{Scope: scope, AgentID: "agent-b", DisplayName: "B", Host: "b.example", Labels: map[string]string{"role": "db", "zone": "2"}},
		{Scope: scope, AgentID: "agent-a", DisplayName: "A", Host: "a.example", Labels: map[string]string{"role": "db", "zone": "1"}},
		{Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-2"}, AgentID: "agent-c", DisplayName: "C", Host: "c.example", Labels: map[string]string{"role": "db"}},
	})
	require.NoError(t, err)

	targets, err := resolver.Resolve(context.Background(), scope, TargetSelector{AgentIDs: []string{"agent-b", "agent-b"}, Labels: map[string]string{"role": "db"}})
	require.NoError(t, err)
	require.Equal(t, []string{"agent-a", "agent-b"}, []string{targets[0].AgentID, targets[1].AgentID})
}

func TestConfiguredTargetResolverRejectsUnknownAndEmptySelections(t *testing.T) {
	// Break caught: silently ignoring an unknown explicit Agent or accepting an
	// empty selector can create a misleading zero-target inspection run.
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	resolver, err := NewConfiguredTargetResolver([]HostTarget{{Scope: scope, AgentID: "agent-a", DisplayName: "A", Host: "a.example"}})
	require.NoError(t, err)
	_, err = resolver.Resolve(context.Background(), scope, TargetSelector{AgentIDs: []string{"agent-missing"}})
	require.ErrorIs(t, err, ErrUnknownTarget)
	_, err = resolver.Resolve(context.Background(), scope, TargetSelector{Labels: map[string]string{"role": "missing"}})
	require.ErrorIs(t, err, ErrNoTargets)
}

func TestConfiguredTargetResolverOwnsImmutableInventory(t *testing.T) {
	// Break caught: caller mutation after injection must not rewrite later run
	// target identity, labels, or advertised capabilities.
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	inventory := []HostTarget{{Scope: scope, AgentID: "agent-a", DisplayName: "A", Host: "a.example", Labels: map[string]string{"role": "db"}, Capabilities: []string{"host.metrics"}}}
	resolver, err := NewConfiguredTargetResolver(inventory)
	require.NoError(t, err)
	inventory[0].Labels["role"] = "changed"
	inventory[0].Capabilities[0] = "changed"

	listed, err := resolver.List(context.Background(), scope)
	require.NoError(t, err)
	require.Equal(t, "db", listed[0].Labels["role"])
	require.Equal(t, "host.metrics", listed[0].Capabilities[0])
	listed[0].Labels["role"] = "again"
	again, err := resolver.List(context.Background(), scope)
	require.NoError(t, err)
	require.Equal(t, "db", again[0].Labels["role"])
}
