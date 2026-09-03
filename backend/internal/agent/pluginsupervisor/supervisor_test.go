package pluginsupervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginstate"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSupervisorRunsOneFamilyProcessForTwoInstancesAndDuplicateIsIdempotent(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	observed, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.ProcessRunning, observed.State.ProcessState)
	require.Equal(t, uint32(2), observed.State.BoundInstanceCount)
	require.Equal(t, 1, fixture.runner.startCount())
	require.Equal(t, 2, len(fixture.runner.configurations[0].InstanceIDs))
	require.Equal(t, 1, fixture.lease.calls)

	duplicate, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), duplicate, validFence())
	require.NoError(t, err)
	require.Equal(t, 1, fixture.runner.startCount())
	require.Equal(t, 1, fixture.lease.calls)
}

func TestSupervisorFailedUpgradeRollsBackOldSlotProcessAndConfiguration(t *testing.T) {
	fixture := newSupervisorFixture(t)
	first := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), first)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.SlotA, fixture.installer.active)

	upgrade := first
	upgrade.DesiredVersion = "1.1.0"
	upgrade.OperationRevision = 2
	upgrade.ConfigurationRevision = 2
	upgrade.InstanceIDs = []string{"mysql-3"}
	upgrade.InstanceDescriptors = []InstanceDescriptor{{InstanceID: "mysql-3", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3307"}}
	upgrade.TemplateIDs = []string{"template-2"}
	upgrade.TemplateConfigurations = []*pluginv1.MetricTemplateConfiguration{testTemplateConfiguration("template-2")}
	upgrade.ArtifactID = "artifact-2"
	upgrade.ArtifactSHA256 = bytesOf(4, sha256.Size)
	upgrade.ManifestDigest = bytesOf(5, sha256.Size)
	fixture.health.failVersion = "1.1.0"
	prepared, err = fixture.supervisor.Prepare(context.Background(), upgrade)
	require.NoError(t, err)
	observed, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.ErrorIs(t, err, ErrHealthHandshake)
	require.Equal(t, pluginstate.SlotA, fixture.installer.active)
	require.Equal(t, "1.0.0", observed.State.InstalledVersion)
	require.Equal(t, pluginstate.ProcessRunning, observed.State.ProcessState)
	require.Equal(t, "plugin_upgrade_rolled_back", observed.State.LastErrorCode)
	require.Equal(t, 3, fixture.runner.startCount(), "old, failed new, restored old")
	require.Equal(t, "1.0.0", fixture.runner.configurations[2].Version)
	require.Equal(t, []string{"mysql-1", "mysql-2"}, fixture.runner.configurations[2].InstanceIDs)
	require.Equal(t, first.InstanceDescriptors, fixture.runner.configurations[2].InstanceDescriptors)
	require.True(t, proto.Equal(first.TemplateConfigurations[0], fixture.health.requests[2].TemplateConfigurations[0]))
	require.Equal(t, []string{"template-1"}, fixture.runner.configurations[2].TemplateIDs)
	require.Equal(t, upgrade.OperationRevision, fixture.runner.configurations[2].OperationRevision, "the restored binary must run under the current rollback operation fence")
	require.Equal(t, upgrade.OperationRevision, fixture.health.requests[2].OperationRevision)
	require.Equal(t, upgrade.ConfigurationRevision, fixture.runner.configurations[2].ConfigurationRevision, "the restored binary must lease credentials under the current configuration fence")
	require.Equal(t, upgrade.ConfigurationRevision, observed.State.ActiveConfigurationRevision)
}

func TestSupervisorHigherConfigurationRevisionAppliesAtomicallyToSameProcess(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	first, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)

	request.OperationRevision = 2
	request.ConfigurationRevision = 2
	request.InstanceIDs = append(request.InstanceIDs, "mysql-3")
	request.InstanceDescriptors = append(request.InstanceDescriptors, InstanceDescriptor{InstanceID: "mysql-3", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3308"})
	prepared, err = fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	observed, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, 1, fixture.runner.startCount())
	require.Equal(t, first.State.ProcessID, observed.State.ProcessID)
	require.Len(t, fixture.health.applied, 1)
	require.Equal(t, []string{"mysql-1", "mysql-2", "mysql-3"}, fixture.health.applied[0].InstanceIDs)
	require.Equal(t, uint64(2), observed.State.ActiveConfigurationRevision)
	require.Equal(t, uint32(3), observed.State.BoundInstanceCount)
}

func TestSupervisorTypedRuntimeUsesExactRunningProcessAndRevisionFences(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	observed, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	processID := observed.State.ProcessID

	apply := &agentv1.ApplyPluginConfiguration{AssignmentId: request.AssignmentID, ConfigurationRevision: 2, Instances: []*agentv1.PluginInstanceConfiguration{
		{InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", CredentialRevision: 2, Templates: []*agentv1.PluginTemplateRevision{{TemplateId: "template-1", Revision: 1, QueryDigest: bytesOf(4, sha256.Size)}}},
		{InstanceId: "mysql-2", DatabaseVariant: "mysql", UnixSocket: "/run/mysql-2.sock", CredentialRevision: 2, Templates: []*agentv1.PluginTemplateRevision{{TemplateId: "template-1", Revision: 1, QueryDigest: bytesOf(4, sha256.Size)}}},
	}}
	require.NoError(t, fixture.supervisor.ApplyPluginConfiguration(context.Background(), apply, validFence()))
	state, ok := fixture.store.Get("mysql")
	require.True(t, ok)
	require.Equal(t, processID, state.ProcessID)
	require.Equal(t, uint64(2), state.ActiveConfigurationRevision)
	require.Equal(t, 1, fixture.health.typedApplyCalls)

	fixture.health.validation = plugingateway.ValidationResult{InstanceID: "mysql-1", Valid: true, DatabaseVersion: "8.4.0"}
	result, err := fixture.supervisor.ValidateDatabaseInstance(context.Background(), &agentv1.ValidateDatabaseInstance{AssignmentId: request.AssignmentID, InstanceId: "mysql-1", ConfigurationRevision: 2}, validFence())
	require.NoError(t, err)
	require.True(t, result.Valid)
	require.Equal(t, 1, fixture.health.typedValidateCalls)

	require.NoError(t, fixture.supervisor.DrainPlugin(context.Background(), &agentv1.DrainPlugin{AssignmentId: request.AssignmentID, OperationRevision: request.OperationRevision, TimeoutSeconds: 1}, validFence()))
	state, ok = fixture.store.Get("mysql")
	require.True(t, ok)
	require.Equal(t, pluginstate.ProcessStopped, state.ProcessState)
	require.Zero(t, state.ProcessID)
	require.True(t, fixture.runner.processes[0].stopped)
}

func TestSupervisorTypedRuntimeRejectsStaleOrCrossAssignmentCommands(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)

	wrong := &agentv1.ValidateDatabaseInstance{AssignmentId: "assignment-other", InstanceId: "mysql-1", ConfigurationRevision: 1}
	_, err = fixture.supervisor.ValidateDatabaseInstance(context.Background(), wrong, validFence())
	require.ErrorIs(t, err, ErrInvalidFence)
	stale := &agentv1.ValidateDatabaseInstance{AssignmentId: request.AssignmentID, InstanceId: "mysql-1", ConfigurationRevision: 2}
	_, err = fixture.supervisor.ValidateDatabaseInstance(context.Background(), stale, validFence())
	require.ErrorIs(t, err, ErrInvalidFence)
	drain := &agentv1.DrainPlugin{AssignmentId: request.AssignmentID, OperationRevision: 2, TimeoutSeconds: 1}
	require.ErrorIs(t, fixture.supervisor.DrainPlugin(context.Background(), drain, validFence()), ErrInvalidFence)
	require.Zero(t, fixture.health.typedValidateCalls)
	require.False(t, fixture.runner.processes[0].stopped)
}

func TestSupervisorFailedSameVersionConfigurationKeepsOldProcessAndConfiguration(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	first, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)

	fixture.health.applyErr = ErrHealthHandshake
	request.OperationRevision = 2
	request.ConfigurationRevision = 2
	request.InstanceIDs = append(request.InstanceIDs, "mysql-3")
	request.InstanceDescriptors = append(request.InstanceDescriptors, InstanceDescriptor{InstanceID: "mysql-3", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3308"})
	prepared, err = fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	observed, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.ErrorIs(t, err, ErrHealthHandshake)
	require.Equal(t, 1, fixture.runner.startCount())
	require.Equal(t, first.State.ProcessID, observed.State.ProcessID)
	require.Equal(t, pluginstate.ProcessRunning, observed.State.ProcessState)
	require.Equal(t, uint64(1), observed.State.ActiveConfigurationRevision)
	require.Equal(t, uint32(2), observed.State.BoundInstanceCount)
	require.Equal(t, "plugin_configuration_apply_failed", observed.State.LastErrorCode)
	require.NotEqual(t, "plugin_upgrade_rolled_back", observed.State.LastErrorCode)
}

func TestSupervisorOpensCircuitAfterFiveFailuresAndOnlyHigherOperationResets(t *testing.T) {
	fixture := newSupervisorFixture(t)
	fixture.runner.alwaysFail = true
	request := validReconcileRequest()
	for attempt := 0; attempt < 5; attempt++ {
		prepared, err := fixture.supervisor.Prepare(context.Background(), request)
		require.NoError(t, err)
		_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
		require.Error(t, err)
	}
	state, ok := fixture.store.Get("mysql")
	require.True(t, ok)
	require.Equal(t, pluginstate.CircuitOpen, state.CircuitState)
	require.Equal(t, pluginstate.ProcessCircuitOpen, state.ProcessState)

	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.ErrorIs(t, err, ErrCircuitOpen)
	require.Equal(t, 5, fixture.runner.startCount())

	fixture.runner.alwaysFail = false
	request.OperationRevision = 2
	prepared, err = fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	stateAfter, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.CircuitClosed, stateAfter.State.CircuitState)
	require.Equal(t, pluginstate.ProcessRunning, stateAfter.State.ProcessState)
}

func TestSupervisorRejectsStaleOperationAndSafelyStopsOrRemovesFamily(t *testing.T) {
	fixture := newSupervisorFixture(t)
	running := validReconcileRequest()
	running.OperationRevision = 3
	prepared, err := fixture.supervisor.Prepare(context.Background(), running)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)

	stale := running
	stale.OperationRevision = 2
	_, err = fixture.supervisor.Prepare(context.Background(), stale)
	require.ErrorIs(t, err, ErrStaleOperation)

	stopped := running
	stopped.OperationRevision = 4
	stopped.DesiredState = DesiredStopped
	prepared, err = fixture.supervisor.Prepare(context.Background(), stopped)
	require.NoError(t, err)
	state, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.ProcessStopped, state.State.ProcessState)
	require.Equal(t, 1, fixture.lease.calls, "safe stop must not request a revoked or missing artifact")

	absent := running
	absent.OperationRevision = 5
	absent.DesiredState = DesiredAbsent
	absent.DesiredVersion, absent.ArtifactID = "", ""
	absent.ArtifactSHA256, absent.ManifestDigest = nil, nil
	prepared, err = fixture.supervisor.Prepare(context.Background(), absent)
	require.NoError(t, err)
	state, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.ProcessAbsent, state.State.ProcessState)
	require.True(t, fixture.installer.removed)
	require.Equal(t, 1, fixture.lease.calls, "absent must not download")
}

func TestSupervisorGatewayShutdownFailureStillDrainsAndJoinsProcess(t *testing.T) {
	fixture := newSupervisorFixture(t)
	running := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), running)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	fixture.health.shutdownErr = ErrHealthHandshake

	stopped := running
	stopped.OperationRevision++
	stopped.DesiredState = DesiredStopped
	prepared, err = fixture.supervisor.Prepare(context.Background(), stopped)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err, "gateway shutdown is best effort before mandatory OS cleanup")
	require.True(t, fixture.runner.processes[0].stopped)
	require.Equal(t, 1, fixture.health.shutdownCalls)
}

func TestSupervisorPersistsWaitingTemplatesWithoutFalseHealthyMetrics(t *testing.T) {
	fixture := newSupervisorFixture(t)
	fixture.health.activationHealth = pluginstate.HealthDegraded
	fixture.health.activationCode = "waiting_templates"
	request := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	observed, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.ProcessRunning, observed.State.ProcessState)
	require.Equal(t, pluginstate.HealthDegraded, observed.State.HealthState)
	require.Equal(t, "waiting_templates", observed.State.LastErrorCode)
	require.Empty(t, observed.State.Failures)
}

func TestSupervisorPreSessionHandshakeFailureStillTerminatesRejectedProcess(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	fixture.health.failVersion = request.DesiredVersion
	fixture.health.shutdownErr = ErrHealthHandshake
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.Error(t, err)
	require.True(t, fixture.runner.processes[0].stopped)
	require.Equal(t, 1, fixture.health.shutdownCalls)
}

func TestSupervisorRejectsEqualRevisionSemanticConflictAcrossRestart(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	conflict := request
	conflict.InstanceIDs = []string{"mysql-other"}
	conflict.InstanceDescriptors = []InstanceDescriptor{{InstanceID: "mysql-other", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3308"}}
	_, err = fixture.supervisor.Prepare(context.Background(), conflict)
	require.ErrorIs(t, err, ErrOperationConflict)
	restarted, err := NewPluginSupervisor(PluginSupervisorConfig{AgentID: "agent-1", HostID: "host-1", RuntimeRoot: t.TempDir(), Store: fixture.store, Installer: fixture.installer, Leases: fixture.lease, Downloader: fakeDownloader{}, Processes: fixture.runner, Health: fixture.health, DrainTimeout: time.Second, FailureWindow: 10 * time.Minute, FailureThreshold: 5, RestartBase: time.Millisecond, RestartMaximum: 10 * time.Millisecond})
	require.NoError(t, err)
	_, err = restarted.Prepare(context.Background(), conflict)
	require.ErrorIs(t, err, ErrOperationConflict)
}

func TestSupervisorUnexpectedExitRestartsAndFiveCrashesOpenCircuit(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	for crash := 1; crash <= 5; crash++ {
		fixture.runner.mu.Lock()
		process := fixture.runner.processes[len(fixture.runner.processes)-1]
		fixture.runner.mu.Unlock()
		process.finish()
		if crash < 5 {
			require.Eventually(t, func() bool { return fixture.runner.startCount() >= crash+1 }, time.Second, time.Millisecond)
			fixture.runner.mu.Lock()
			restarted := fixture.runner.configurations[len(fixture.runner.configurations)-1]
			fixture.runner.mu.Unlock()
			require.Equal(t, request.InstanceDescriptors, restarted.InstanceDescriptors)
			require.True(t, proto.Equal(request.TemplateConfigurations[0], fixture.health.requests[len(fixture.health.requests)-1].TemplateConfigurations[0]))
		}
	}
	require.Eventually(t, func() bool {
		state, ok := fixture.store.Get("mysql")
		return ok && state.CircuitState == pluginstate.CircuitOpen && state.ProcessState == pluginstate.ProcessCircuitOpen
	}, time.Second, time.Millisecond)
	count := fixture.runner.startCount()
	time.Sleep(30 * time.Millisecond)
	require.Equal(t, count, fixture.runner.startCount())
}

func TestPluginObservationIsByteIdenticalUntilPersistedStateChanges(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	request.DesiredState = DesiredStopped
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	first, _ := proto.MarshalOptions{Deterministic: true}.Marshal(fixture.supervisor.Observation())
	second, _ := proto.MarshalOptions{Deterministic: true}.Marshal(fixture.supervisor.Observation())
	require.Equal(t, first, second)
	restarted, err := NewPluginSupervisor(PluginSupervisorConfig{AgentID: "agent-1", HostID: "host-1", RuntimeRoot: t.TempDir(), Store: fixture.store, Installer: fixture.installer, Leases: fixture.lease, Downloader: fakeDownloader{}, Processes: fixture.runner, Health: fixture.health, DrainTimeout: time.Second, FailureWindow: 10 * time.Minute, FailureThreshold: 5})
	require.NoError(t, err)
	replayed, _ := proto.MarshalOptions{Deterministic: true}.Marshal(restarted.Observation())
	require.Equal(t, first, replayed)
}

func TestSupervisorPluginObservationRevisionAdvancesWhenAnotherFamilyChanges(t *testing.T) {
	fixture := newSupervisorFixture(t)
	mysql := pluginstate.FamilyState{AssignmentID: "assignment-mysql", PluginID: "mysql", DatabaseFamily: "mysql", InstalledVersion: "1.0.0", ActiveSlot: pluginstate.SlotA, DesiredState: pluginstate.DesiredRunning, RequestFingerprint: strings.Repeat("a", 64), ProcessState: pluginstate.ProcessRunning, HealthState: pluginstate.HealthHealthy, CircuitState: pluginstate.CircuitClosed, ActiveConfigurationRevision: 1, DesiredConfigurationRevision: 1, ObservedOperationRevision: 1, ObservationRevision: 5, BoundInstanceCount: 1, ActiveInstanceIDs: []string{"mysql-1"}}
	for index := 0; index < 5; index++ {
		_, err := fixture.store.Put(context.Background(), mysql)
		require.NoError(t, err)
	}
	first := fixture.supervisor.Observation()
	postgres := mysql
	postgres.AssignmentID, postgres.PluginID, postgres.DatabaseFamily, postgres.ObservationRevision = "assignment-postgres", "postgres", "postgres", 1
	_, err := fixture.store.Put(context.Background(), postgres)
	require.NoError(t, err)
	second := fixture.supervisor.Observation()
	require.Greater(t, second.GetObservationRevision(), first.GetObservationRevision())
}

func TestSupervisorRefreshesEquivalentObservationAfterControlReconnect(t *testing.T) {
	fixture := newSupervisorFixture(t)
	state := pluginstate.FamilyState{AssignmentID: "assignment-mysql", PluginID: "mysql", DatabaseFamily: "mysql", InstalledVersion: "1.0.0", ActiveSlot: pluginstate.SlotA, DesiredState: pluginstate.DesiredRunning, RequestFingerprint: strings.Repeat("a", 64), ProcessState: pluginstate.ProcessRunning, HealthState: pluginstate.HealthHealthy, CircuitState: pluginstate.CircuitClosed, ActiveConfigurationRevision: 1, DesiredConfigurationRevision: 1, ObservedOperationRevision: 1, ObservationRevision: 5, BoundInstanceCount: 1, ActiveInstanceIDs: []string{"mysql-1"}}
	stored, err := fixture.store.Put(context.Background(), state)
	require.NoError(t, err)
	before := fixture.supervisor.Observation()
	require.NoError(t, fixture.supervisor.RefreshObservation(context.Background()))
	require.Eventually(t, func() bool {
		after := fixture.supervisor.Observation()
		return after.GetObservationRevision() > before.GetObservationRevision() && after.GetObservedAt().AsTime().After(before.GetObservedAt().AsTime())
	}, time.Second, time.Millisecond)
	require.Equal(t, stored.ProcessID, fixture.store.families["mysql"].ProcessID)
}

func TestSupervisorCoalescesReconnectRefreshAndFlushesAfterMutationUnlock(t *testing.T) {
	fixture := newSupervisorFixture(t)
	state := pluginstate.FamilyState{AssignmentID: "assignment-mysql", PluginID: "mysql", DatabaseFamily: "mysql", InstalledVersion: "1.0.0", ActiveSlot: pluginstate.SlotA, DesiredState: pluginstate.DesiredRunning, RequestFingerprint: strings.Repeat("a", 64), ProcessState: pluginstate.ProcessRunning, HealthState: pluginstate.HealthHealthy, CircuitState: pluginstate.CircuitClosed, ActiveConfigurationRevision: 1, DesiredConfigurationRevision: 1, ObservedOperationRevision: 1, ObservationRevision: 5, BoundInstanceCount: 1, ActiveInstanceIDs: []string{"mysql-1"}}
	_, err := fixture.store.Put(context.Background(), state)
	require.NoError(t, err)
	before, _ := fixture.store.Get("mysql")
	fixture.supervisor.mu.Lock()
	require.NoError(t, fixture.supervisor.RefreshObservation(context.Background()))
	require.NoError(t, fixture.supervisor.RefreshObservation(context.Background()))
	during, _ := fixture.store.Get("mysql")
	require.Equal(t, before.ObservationRevision, during.ObservationRevision)
	fixture.supervisor.mu.Unlock()
	require.Eventually(t, func() bool {
		after, ok := fixture.store.Get("mysql")
		return ok && after.ObservationRevision == before.ObservationRevision+1
	}, time.Second, time.Millisecond)
}

func TestNewSupervisorRecoversPersistedFamilySlotsBeforeAcceptingCommands(t *testing.T) {
	fixture := newSupervisorFixture(t)
	state := pluginstate.FamilyState{AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", InstalledVersion: "1.0.0", ActiveSlot: pluginstate.SlotA, DesiredState: pluginstate.DesiredStopped, RequestFingerprint: strings.Repeat("a", 64), ProcessState: pluginstate.ProcessRunning, HealthState: pluginstate.HealthHealthy, CircuitState: pluginstate.CircuitClosed, ActiveConfigurationRevision: 1, DesiredConfigurationRevision: 1, ObservedOperationRevision: 1, ObservationRevision: 1, BoundInstanceCount: 1, ActiveInstanceIDs: []string{"mysql-1"}}
	state.ProcessID, state.ProcessStartTicks, state.StartedAt = 999999, 1, time.Now().UTC()
	_, err := fixture.store.Put(context.Background(), state)
	require.NoError(t, err)
	installer := &fakeInstaller{slots: map[pluginstate.Slot]InstalledSlot{}}
	_, err = NewPluginSupervisor(PluginSupervisorConfig{AgentID: "agent-1", HostID: "host-1", RuntimeRoot: t.TempDir(), Store: fixture.store, Installer: installer, Leases: fixture.lease, Downloader: fakeDownloader{}, Processes: fixture.runner, Health: fixture.health, DrainTimeout: time.Second, FailureWindow: 10 * time.Minute, FailureThreshold: 5})
	require.NoError(t, err)
	require.Equal(t, []string{"mysql"}, installer.recovered)
	reconciled, ok := fixture.store.Get("mysql")
	require.True(t, ok)
	require.Zero(t, reconciled.ProcessID)
	require.Equal(t, pluginstate.ProcessStopped, reconciled.ProcessState)
}

func validFence() ExecutionFence {
	return ExecutionFence{CommandID: "command-1", ExecutionToken: bytesOf(9, sha256.Size), LeaseRevision: 1, StartedAt: time.Now().UTC()}
}

type supervisorFixture struct {
	supervisor *PluginSupervisor
	store      *memoryStateStore
	installer  *fakeInstaller
	lease      *fakeLeaseClient
	runner     *fakeProcessRunner
	health     *fakeHealthChecker
}

func newSupervisorFixture(t *testing.T) supervisorFixture {
	t.Helper()
	store := &memoryStateStore{families: map[string]pluginstate.FamilyState{}}
	installer := &fakeInstaller{slots: map[pluginstate.Slot]InstalledSlot{}}
	lease := &fakeLeaseClient{}
	downloader := fakeDownloader{}
	runner := &fakeProcessRunner{}
	health := &fakeHealthChecker{}
	supervisor, err := NewPluginSupervisor(PluginSupervisorConfig{AgentID: "agent-1", HostID: "host-1", RuntimeRoot: t.TempDir(), Store: store, Installer: installer, Leases: lease, Downloader: downloader, Processes: runner, Health: health, DrainTimeout: 50 * time.Millisecond, FailureWindow: 10 * time.Minute, FailureThreshold: 5, RestartBase: time.Millisecond, RestartMaximum: 10 * time.Millisecond, Now: time.Now})
	require.NoError(t, err)
	return supervisorFixture{supervisor: supervisor, store: store, installer: installer, lease: lease, runner: runner, health: health}
}

type memoryStateStore struct {
	mu         sync.Mutex
	revision   uint64
	families   map[string]pluginstate.FamilyState
	observedAt time.Time
}

func (store *memoryStateStore) Get(family string) (pluginstate.FamilyState, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, ok := store.families[family]
	return state, ok
}
func (store *memoryStateStore) List() []pluginstate.FamilyState {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]pluginstate.FamilyState, 0, len(store.families))
	for _, state := range store.families {
		result = append(result, state)
	}
	return result
}
func (store *memoryStateStore) Snapshot() (uint64, time.Time, []pluginstate.FamilyState) {
	store.mu.Lock()
	defer store.mu.Unlock()
	result := make([]pluginstate.FamilyState, 0, len(store.families))
	for _, state := range store.families {
		result = append(result, state)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DatabaseFamily < result[j].DatabaseFamily })
	return store.revision, store.observedAt, result
}
func (store *memoryStateStore) Put(_ context.Context, state pluginstate.FamilyState) (pluginstate.FamilyState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if current, ok := store.families[state.DatabaseFamily]; ok && state.ObservedOperationRevision < current.ObservedOperationRevision {
		return pluginstate.FamilyState{}, pluginstate.ErrStaleOperation
	}
	store.revision++
	store.observedAt = time.Unix(int64(store.revision), 0).UTC()
	state.StateRevision = store.revision
	store.families[state.DatabaseFamily] = state
	return state, nil
}
func (store *memoryStateStore) Delete(_ context.Context, family string, _ uint64) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.families, family)
	return nil
}

type fakeInstaller struct {
	active    pluginstate.Slot
	slots     map[pluginstate.Slot]InstalledSlot
	removed   bool
	recovered []string
}

func (installer *fakeInstaller) InstallInactive(_ context.Context, request InstallRequest, slot pluginstate.Slot) (InstalledSlot, error) {
	installed := InstalledSlot{Slot: slot, Version: request.Version, ExecutablePath: "/plugins/" + request.DatabaseFamily + "/" + string(slot) + "/plugin", ExecutableSHA256: hexBytes(request.ArtifactSHA256), ManifestPath: "/plugins/manifest", ArtifactSHA256: hexBytes(request.ArtifactSHA256), ManifestDigest: hexBytes(request.ManifestDigest), SupportedVariants: []string{"mysql"}, Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1}
	installer.slots[slot] = installed
	return installed, nil
}
func (installer *fakeInstaller) Activate(_ context.Context, _ SlotIdentity, slot pluginstate.Slot) error {
	installer.active = slot
	return nil
}
func (installer *fakeInstaller) RemoveInactive(_ context.Context, _ string, slot pluginstate.Slot) error {
	if installer.active == slot {
		return ErrInstallFailed
	}
	delete(installer.slots, slot)
	return nil
}
func (installer *fakeInstaller) RemoveFamily(context.Context, string) error {
	installer.active = pluginstate.SlotNone
	installer.slots = map[pluginstate.Slot]InstalledSlot{}
	installer.removed = true
	return nil
}
func (installer *fakeInstaller) Recover(_ context.Context, family string) error {
	installer.recovered = append(installer.recovered, family)
	return nil
}
func (installer *fakeInstaller) Installed(_ context.Context, _ SlotIdentity, slot pluginstate.Slot) (InstalledSlot, error) {
	value, ok := installer.slots[slot]
	if !ok {
		return InstalledSlot{}, ErrInstallFailed
	}
	return value, nil
}

type fakeLeaseClient struct{ calls int }

func (client *fakeLeaseClient) LeasePluginArtifact(_ context.Context, request ArtifactLeaseRequest) (ArtifactLease, error) {
	client.calls++
	return ArtifactLease{LeaseID: "lease-1", AssignmentID: request.AssignmentID, ArtifactID: request.ArtifactID, OperationRevision: request.OperationRevision, ExpiresAt: time.Now().Add(time.Minute), DownloadURL: "https://server/plugin"}, nil
}

type fakeDownloader struct{}

func (fakeDownloader) Download(context.Context, ArtifactLease) (DownloadedArtifact, error) {
	return DownloadedArtifact{Body: io.NopCloser(bytes.NewReader([]byte("archive"))), Size: 7}, nil
}

type fakeProcessRunner struct {
	mu             sync.Mutex
	configurations []LaunchConfiguration
	processes      []*fakeProcess
	alwaysFail     bool
}

func (runner *fakeProcessRunner) Start(_ context.Context, _ Executable, config LaunchConfiguration) (Process, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.configurations = append(runner.configurations, config)
	if runner.alwaysFail {
		return nil, ErrProcessStart
	}
	process := &fakeProcess{pid: 100 + len(runner.processes), started: time.Now().UTC(), done: make(chan struct{})}
	runner.processes = append(runner.processes, process)
	return process, nil
}
func (runner *fakeProcessRunner) startCount() int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return len(runner.configurations)
}

type fakeProcess struct {
	pid     int
	started time.Time
	stopped bool
	done    chan struct{}
	once    sync.Once
}

func (process *fakeProcess) PID() int             { return process.pid }
func (process *fakeProcess) StartTicks() uint64   { return uint64(process.pid) }
func (process *fakeProcess) StartedAt() time.Time { return process.started }
func (process *fakeProcess) finish() {
	process.once.Do(func() {
		process.stopped = true
		if process.done != nil {
			close(process.done)
		}
	})
}
func (process *fakeProcess) Drain(context.Context) error { process.finish(); return nil }
func (process *fakeProcess) Stop(context.Context) error  { process.finish(); return nil }
func (process *fakeProcess) Kill() error                 { process.finish(); return nil }
func (process *fakeProcess) Wait() error {
	if process.done == nil {
		return errors.New("missing done")
	}
	<-process.done
	return nil
}

type fakeHealthChecker struct {
	failVersion        string
	shutdownErr        error
	shutdownCalls      int
	activationHealth   pluginstate.HealthState
	activationCode     string
	requests           []HealthRequest
	applied            []HealthRequest
	applyErr           error
	typedApplyCalls    int
	typedValidateCalls int
	validation         plugingateway.ValidationResult
}

func (checker *fakeHealthChecker) ApplyTypedConfiguration(context.Context, Process, HealthRequest, *agentv1.ApplyPluginConfiguration) error {
	checker.typedApplyCalls++
	return checker.applyErr
}

func (checker *fakeHealthChecker) ValidateTypedInstance(context.Context, Process, HealthRequest, string) (plugingateway.ValidationResult, error) {
	checker.typedValidateCalls++
	return checker.validation, nil
}

func (checker *fakeHealthChecker) ApplyConfiguration(_ context.Context, _ Process, request HealthRequest) error {
	checker.applied = append(checker.applied, request)
	return checker.applyErr
}

func (checker *fakeHealthChecker) ActivationState(Process) (pluginstate.HealthState, string) {
	return checker.activationHealth, checker.activationCode
}

func (checker *fakeHealthChecker) Handshake(_ context.Context, _ Process, request HealthRequest) error {
	checker.requests = append(checker.requests, request)
	if request.Version == checker.failVersion {
		return ErrHealthHandshake
	}
	return nil
}

func (checker *fakeHealthChecker) Shutdown(context.Context, Process, time.Duration) error {
	checker.shutdownCalls++
	return checker.shutdownErr
}

func hexBytes(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, b := range value {
		result[index*2], result[index*2+1] = digits[b>>4], digits[b&15]
	}
	return string(result)
}
