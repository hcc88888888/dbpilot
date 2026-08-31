package pluginsupervisor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/agent/pluginstate"
	"github.com/stretchr/testify/require"
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
	require.Equal(t, 3, fixture.runner.startCount(), "old, failed new, restored old")
	require.Equal(t, "1.0.0", fixture.runner.configurations[2].Version)
}

func TestSupervisorHigherConfigurationRevisionRestartsSameVersion(t *testing.T) {
	fixture := newSupervisorFixture(t)
	request := validReconcileRequest()
	prepared, err := fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	_, err = fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)

	request.OperationRevision = 2
	request.ConfigurationRevision = 2
	prepared, err = fixture.supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	observed, err := fixture.supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, 2, fixture.runner.startCount())
	require.Equal(t, uint64(2), observed.State.ActiveConfigurationRevision)
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
}

func TestSupervisorPluginObservationRevisionAdvancesWhenAnotherFamilyChanges(t *testing.T) {
	fixture := newSupervisorFixture(t)
	mysql := pluginstate.FamilyState{AssignmentID: "assignment-mysql", PluginID: "mysql", DatabaseFamily: "mysql", InstalledVersion: "1.0.0", ActiveSlot: pluginstate.SlotA, DesiredState: pluginstate.DesiredRunning, ProcessState: pluginstate.ProcessRunning, HealthState: pluginstate.HealthHealthy, CircuitState: pluginstate.CircuitClosed, ActiveConfigurationRevision: 1, ObservedOperationRevision: 1, ObservationRevision: 5, BoundInstanceCount: 1}
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

func TestNewSupervisorRecoversPersistedFamilySlotsBeforeAcceptingCommands(t *testing.T) {
	fixture := newSupervisorFixture(t)
	state := pluginstate.FamilyState{AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", InstalledVersion: "1.0.0", ActiveSlot: pluginstate.SlotA, DesiredState: pluginstate.DesiredRunning, ProcessState: pluginstate.ProcessRunning, HealthState: pluginstate.HealthHealthy, CircuitState: pluginstate.CircuitClosed, ActiveConfigurationRevision: 1, ObservedOperationRevision: 1, ObservationRevision: 1, BoundInstanceCount: 1}
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
	supervisor, err := NewPluginSupervisor(PluginSupervisorConfig{AgentID: "agent-1", HostID: "host-1", RuntimeRoot: t.TempDir(), Store: store, Installer: installer, Leases: lease, Downloader: downloader, Processes: runner, Health: health, DrainTimeout: 50 * time.Millisecond, FailureWindow: 10 * time.Minute, FailureThreshold: 5, Now: time.Now})
	require.NoError(t, err)
	return supervisorFixture{supervisor: supervisor, store: store, installer: installer, lease: lease, runner: runner, health: health}
}

type memoryStateStore struct {
	mu       sync.Mutex
	revision uint64
	families map[string]pluginstate.FamilyState
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
func (store *memoryStateStore) Put(_ context.Context, state pluginstate.FamilyState) (pluginstate.FamilyState, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if current, ok := store.families[state.DatabaseFamily]; ok && state.ObservedOperationRevision < current.ObservedOperationRevision {
		return pluginstate.FamilyState{}, pluginstate.ErrStaleOperation
	}
	store.revision++
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
	installed := InstalledSlot{Slot: slot, Version: request.Version, ExecutablePath: "/plugins/" + request.DatabaseFamily + "/" + string(slot) + "/plugin", ExecutableSHA256: hexBytes(request.ArtifactSHA256), ManifestPath: "/plugins/manifest", ArtifactSHA256: hexBytes(request.ArtifactSHA256), ManifestDigest: hexBytes(request.ManifestDigest)}
	installer.slots[slot] = installed
	return installed, nil
}
func (installer *fakeInstaller) Activate(_ context.Context, _ string, slot pluginstate.Slot) error {
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
func (installer *fakeInstaller) Installed(_ string, slot pluginstate.Slot) (InstalledSlot, error) {
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
	process := &fakeProcess{pid: 100 + len(runner.processes), started: time.Now().UTC()}
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
}

func (process *fakeProcess) PID() int                    { return process.pid }
func (process *fakeProcess) StartTicks() uint64          { return uint64(process.pid) }
func (process *fakeProcess) StartedAt() time.Time        { return process.started }
func (process *fakeProcess) Drain(context.Context) error { process.stopped = true; return nil }
func (process *fakeProcess) Stop(context.Context) error  { process.stopped = true; return nil }
func (process *fakeProcess) Kill() error                 { process.stopped = true; return nil }
func (process *fakeProcess) Wait() error {
	if !process.stopped {
		return errors.New("running")
	}
	return nil
}

type fakeHealthChecker struct{ failVersion string }

func (checker *fakeHealthChecker) Handshake(_ context.Context, _ Process, request HealthRequest) error {
	if request.Version == checker.failVersion {
		return ErrHealthHandshake
	}
	return nil
}

func hexBytes(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, b := range value {
		result[index*2], result[index*2+1] = digits[b>>4], digits[b&15]
	}
	return string(result)
}
