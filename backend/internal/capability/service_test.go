package capability

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveRequiresDeploymentDatabaseAgentAndPermissionIntersection(t *testing.T) {
	definition := Definition{
		Name: "inspection.run", DeploymentFlags: []string{"inspections_enabled"},
		DatabaseTypes: []string{"postgresql", "mysql"}, RequiredDatabaseCapabilities: []string{"read_only_sql"},
		AgentCapabilities: []string{"inspect_instance"}, RequiredPermission: "inspections.run",
	}
	base := Input{
		DeploymentFlags: map[string]bool{"inspections_enabled": true}, DatabaseType: "postgresql",
		DatabaseCapabilities: map[string]bool{"read_only_sql": true}, AgentCapabilities: map[string]bool{"inspect_instance": true},
		Permissions: map[string]bool{"inspections.run": true},
	}

	tests := []struct {
		name   string
		mutate func(*Input)
		reason ReasonCode
	}{
		{"deployment disabled", func(input *Input) { input.DeploymentFlags["inspections_enabled"] = false }, DeploymentDisabled},
		{"database type unsupported", func(input *Input) { input.DatabaseType = "oracle" }, DatabaseUnsupported},
		{"database operation unsupported", func(input *Input) { input.DatabaseCapabilities["read_only_sql"] = false }, DatabaseUnsupported},
		{"agent unsupported", func(input *Input) { input.AgentCapabilities["inspect_instance"] = false }, AgentUnsupported},
		{"permission denied", func(input *Input) { input.Permissions["inspections.run"] = false }, PermissionDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneInput(base)
			test.mutate(&input)
			got := Resolve([]Definition{definition}, input)
			require.Equal(t, []Capability{{
				Name: definition.Name, Enabled: false, ReasonCode: test.reason,
				DatabaseTypes: []string{"mysql", "postgresql"}, AgentCapabilities: []string{"inspect_instance"}, RequiredPermission: "inspections.run",
			}}, got)
		})
	}

	got := Resolve([]Definition{definition}, base)
	require.True(t, got[0].Enabled)
	require.Empty(t, got[0].ReasonCode)
}

func TestResolveUsesStableReasonPrecedence(t *testing.T) {
	definition := Definition{Name: "backup.restore", DeploymentFlags: []string{"backup_enabled"}, DatabaseTypes: []string{"postgresql"}, AgentCapabilities: []string{"restore_backup"}, RequiredPermission: "backups.restore"}
	got := Resolve([]Definition{definition}, Input{DatabaseType: "mysql"})
	require.Equal(t, DeploymentDisabled, got[0].ReasonCode)
}

func TestResolveSortsCapabilitiesAndAdvertisedSetsWithoutFrontendBranching(t *testing.T) {
	catalog := []Definition{
		{Name: "z.operation", DatabaseTypes: []string{"postgresql", "mysql", "mysql"}, AgentCapabilities: []string{"zeta", "alpha"}},
		{Name: "a.operation", DatabaseTypes: []string{"dameng", "oracle"}},
	}
	service := NewService(catalog)
	got := service.Resolve(Input{DatabaseType: "oracle"})

	require.Equal(t, []string{"a.operation", "z.operation"}, []string{got[0].Name, got[1].Name})
	require.Equal(t, []string{"mysql", "postgresql"}, got[1].DatabaseTypes)
	require.Equal(t, []string{"alpha", "zeta"}, got[1].AgentCapabilities)
	require.Equal(t, DatabaseUnsupported, got[1].ReasonCode)
	require.Equal(t, []string{"postgresql", "mysql", "mysql"}, catalog[0].DatabaseTypes, "resolver must be pure")
}

func TestFoundationCatalogIsNonemptyAndExplainsMissingAgentCapability(t *testing.T) {
	catalog := FoundationCatalog()
	require.NotEmpty(t, catalog)
	input := Input{DeploymentFlags: FoundationDeploymentFlags(), Permissions: map[string]bool{
		"platform.jobs.read": true, "platform.jobs.cancel": true, "platform.audit.read": true,
		"platform.artifacts.read": true, "platform.capabilities.read": true,
	}}
	resolved := Resolve(catalog, input)
	require.Len(t, resolved, len(catalog))
	require.True(t, findCapability(resolved, "platform.jobs").Enabled)
	require.True(t, findCapability(resolved, "platform.audit").Enabled)
	require.True(t, findCapability(resolved, "platform.artifacts").Enabled)
	require.False(t, findCapability(resolved, "agent.control").Enabled)
	require.Equal(t, AgentUnsupported, findCapability(resolved, "agent.control").ReasonCode)

	input.AgentCapabilities = map[string]bool{"collect_now": true}
	require.True(t, findCapability(Resolve(catalog, input), "agent.control").Enabled)
}

func findCapability(values []Capability, name string) Capability {
	for _, value := range values {
		if value.Name == name {
			return value
		}
	}
	return Capability{}
}

func cloneInput(input Input) Input {
	result := input
	result.DeploymentFlags = cloneSet(input.DeploymentFlags)
	result.DatabaseCapabilities = cloneSet(input.DatabaseCapabilities)
	result.AgentCapabilities = cloneSet(input.AgentCapabilities)
	result.Permissions = cloneSet(input.Permissions)
	return result
}

func cloneSet(input map[string]bool) map[string]bool {
	result := make(map[string]bool, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
