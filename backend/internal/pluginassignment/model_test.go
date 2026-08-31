package pluginassignment

import (
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestAssignmentNormalizesOneAgentFamilyInstanceSetWithoutSecrets(t *testing.T) {
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	value := Assignment{
		ID: "assignment-a", Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"},
		HostID: "host-a", AgentID: "agent-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql",
		DesiredVersionID: "mysql-version-1", DesiredVersion: "1.2.3", DesiredState: DesiredRunning,
		ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ConfigurationRevision: 2, OperationRevision: 3, RolloutPercentage: 100,
		InstanceIDs: []string{"instance-b", "instance-a", "instance-a"}, TemplateRevisionIDs: []string{"template-z:7", "template-a:3", "template-a:3"},
		ReconcileState: ReconcilePending, Revision: 4, CreatedAt: now, UpdatedAt: now,
	}

	normalized, err := NormalizeAssignment(value)
	require.NoError(t, err)
	require.Equal(t, []string{"instance-a", "instance-b"}, normalized.InstanceIDs)
	require.Equal(t, []string{"template-a:3", "template-z:7"}, normalized.TemplateRevisionIDs)
	require.Equal(t, `"4"`, normalized.ETag())

	secret := value
	secret.InstanceIDs = []string{"secret://vault/password"}
	_, err = NormalizeAssignment(secret)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestAssignmentNeedsReconcileOnlyForDesiredObservedDrift(t *testing.T) {
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	value := Assignment{
		ID: "assignment-a", Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, HostID: "host-a", AgentID: "agent-a",
		PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersionID: "mysql-version-1", DesiredVersion: "1.2.3", DesiredState: DesiredRunning,
		ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ConfigurationRevision: 7, OperationRevision: 9, RolloutPercentage: 100, InstanceIDs: []string{"instance-a"},
		ReconcileState: ReconcileConverged, Revision: 3, CreatedAt: now, UpdatedAt: now,
		Observed: &ObservedState{AssignmentID: "assignment-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", InstalledVersion: "1.2.3", ActiveSlot: SlotA, ProcessState: ProcessRunning, Health: HealthHealthy, CircuitState: CircuitClosed, BoundInstanceCount: 1, ActiveConfigurationRevision: 7, ObservedOperationRevision: 9, ObservationRevision: 12, ObservedAt: now},
	}
	require.NoError(t, value.Validate())
	require.False(t, value.NeedsReconcile())

	configurationDrift := value
	configurationDrift.Observed = cloneObserved(value.Observed)
	configurationDrift.Observed.ActiveConfigurationRevision--
	require.True(t, configurationDrift.NeedsReconcile())

	stateDrift := value
	stateDrift.Observed = cloneObserved(value.Observed)
	stateDrift.Observed.ProcessState = ProcessStopped
	require.True(t, stateDrift.NeedsReconcile())

	conflict := value
	conflict.Observed = cloneObserved(value.Observed)
	conflict.Observed.ObservedOperationRevision++
	require.True(t, conflict.HasObservedRevisionConflict())
	require.False(t, conflict.NeedsReconcile(), "Server must not roll an Agent back from a future observed revision")
	futureConfiguration := value
	futureConfiguration.Observed = cloneObserved(value.Observed)
	futureConfiguration.Observed.ActiveConfigurationRevision++
	require.True(t, futureConfiguration.HasObservedRevisionConflict())
	require.False(t, futureConfiguration.NeedsReconcile(), "Server must not roll an Agent back from a future configuration revision")
}

func cloneObserved(value *ObservedState) *ObservedState {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func TestAssignmentCursorCannotBeReusedAcrossScopeOrFilter(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	filter := Filter{HostID: "host-a", PluginID: "dbpilot.mysql", Limit: 25}
	cursor, err := encodeAssignmentCursor(scope, filter, "assignment-a")
	require.NoError(t, err)
	filter.Cursor = cursor
	after, err := decodeAssignmentCursor(scope, filter)
	require.NoError(t, err)
	require.Equal(t, "assignment-a", after)
	_, err = decodeAssignmentCursor(platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-b"}, filter)
	require.ErrorIs(t, err, ErrInvalid)
	filter.PluginID = "dbpilot.postgres"
	_, err = decodeAssignmentCursor(scope, filter)
	require.ErrorIs(t, err, ErrInvalid)
}
