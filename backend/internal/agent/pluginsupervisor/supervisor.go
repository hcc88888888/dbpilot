package pluginsupervisor

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/pluginstate"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type PluginSupervisorConfig struct {
	AgentID          string
	HostID           string
	RuntimeRoot      string
	Store            StateStore
	Installer        SlotInstaller
	Leases           LeaseClient
	Downloader       ArtifactDownloader
	Processes        ProcessRunner
	Health           HealthChecker
	UserID           uint32
	GroupID          uint32
	DrainTimeout     time.Duration
	FailureWindow    time.Duration
	FailureThreshold int
	Now              func() time.Time
}

type PluginSupervisor struct {
	mu               sync.Mutex
	agentID          string
	hostID           string
	runtimeRoot      string
	store            StateStore
	installer        SlotInstaller
	leases           LeaseClient
	downloader       ArtifactDownloader
	processes        ProcessRunner
	health           HealthChecker
	userID           uint32
	groupID          uint32
	drainTimeout     time.Duration
	failureWindow    time.Duration
	failureThreshold int
	now              func() time.Time
	running          map[string]Process
}

func NewPluginSupervisor(config PluginSupervisorConfig) (*PluginSupervisor, error) {
	if !resourceIdentifier.MatchString(config.AgentID) || !resourceIdentifier.MatchString(config.HostID) || !filepath.IsAbs(config.RuntimeRoot) || filepath.Clean(config.RuntimeRoot) != config.RuntimeRoot || config.Store == nil || config.Installer == nil || config.Leases == nil || config.Downloader == nil || config.Processes == nil || config.Health == nil || config.DrainTimeout <= 0 || config.DrainTimeout > time.Minute || config.FailureWindow <= 0 || config.FailureWindow > time.Hour || config.FailureThreshold < 1 || config.FailureThreshold > 20 {
		return nil, ErrInvalidRequest
	}
	if info, err := os.Lstat(config.RuntimeRoot); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidRequest
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	for _, state := range config.Store.List() {
		if state.Validate() != nil || config.Installer.Recover(context.Background(), state.DatabaseFamily) != nil {
			return nil, ErrInstallFailed
		}
		if reconciled, changed := reconcilePersistedProcess(state); changed {
			reconciled.ObservationRevision++
			if _, err := config.Store.Put(context.Background(), reconciled); err != nil {
				return nil, ErrInstallFailed
			}
		}
	}
	return &PluginSupervisor{agentID: config.AgentID, hostID: config.HostID, runtimeRoot: config.RuntimeRoot, store: config.Store, installer: config.Installer, leases: config.Leases, downloader: config.Downloader, processes: config.Processes, health: config.Health, userID: config.UserID, groupID: config.GroupID, drainTimeout: config.DrainTimeout, failureWindow: config.FailureWindow, failureThreshold: config.FailureThreshold, now: config.Now, running: map[string]Process{}}, nil
}

func (supervisor *PluginSupervisor) Prepare(ctx context.Context, request ReconcileRequest) (PreparedChange, error) {
	if supervisor == nil || ctx == nil || ctx.Err() != nil || request.Validate() != nil {
		return PreparedChange{}, ErrInvalidRequest
	}
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	current, exists := supervisor.store.Get(request.DatabaseFamily)
	if exists {
		if current.AssignmentID != request.AssignmentID || current.PluginID != request.PluginID {
			return PreparedChange{}, ErrInvalidRequest
		}
		if request.OperationRevision < current.ObservedOperationRevision {
			return PreparedChange{}, ErrStaleOperation
		}
		if request.OperationRevision > current.ObservedOperationRevision {
			current.Failures = nil
			current.CircuitState = pluginstate.CircuitClosed
			if current.ProcessState == pluginstate.ProcessCircuitOpen {
				current.ProcessState = pluginstate.ProcessStopped
			}
		}
	}
	return PreparedChange{Request: cloneRequest(request), CurrentState: current, HasCurrent: exists, PreparedAt: supervisor.now().UTC()}, nil
}

func (supervisor *PluginSupervisor) Start(ctx context.Context, prepared PreparedChange, fence ExecutionFence) (ObservedState, error) {
	if supervisor == nil || ctx == nil || ctx.Err() != nil || prepared.Request.Validate() != nil || fence.Validate() != nil {
		return ObservedState{}, ErrInvalidFence
	}
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	request := prepared.Request
	current, exists := supervisor.store.Get(request.DatabaseFamily)
	if exists && request.OperationRevision < current.ObservedOperationRevision {
		return ObservedState{State: current}, ErrStaleOperation
	}
	if exists && request.OperationRevision == current.ObservedOperationRevision && current.CircuitState == pluginstate.CircuitOpen {
		return ObservedState{State: current}, ErrCircuitOpen
	}
	if exists && request.OperationRevision > current.ObservedOperationRevision {
		current.Failures = nil
		current.CircuitState = pluginstate.CircuitClosed
	}
	if !exists {
		current = baseState(request)
	}
	previous := current
	current.AssignmentID = request.AssignmentID
	current.PluginID = request.PluginID
	current.DatabaseFamily = request.DatabaseFamily
	current.DesiredState = stateForDesired(request.DesiredState)
	current.ActiveConfigurationRevision = request.ConfigurationRevision
	current.ObservedOperationRevision = request.OperationRevision
	current.BoundInstanceCount = uint32(len(request.InstanceIDs))
	current.ObservationRevision++
	if current.ObservationRevision == 0 {
		return ObservedState{}, ErrInvalidRequest
	}

	switch request.DesiredState {
	case DesiredAbsent:
		return supervisor.makeAbsent(ctx, request, current)
	case DesiredStopped:
		return supervisor.makeStopped(ctx, request, current)
	case DesiredInstalled:
		return supervisor.makeInstalled(ctx, request, current)
	case DesiredRunning:
		return supervisor.makeRunning(ctx, request, current, previous)
	default:
		return ObservedState{}, ErrInvalidRequest
	}
}

func (supervisor *PluginSupervisor) makeAbsent(ctx context.Context, request ReconcileRequest, state pluginstate.FamilyState) (ObservedState, error) {
	if err := supervisor.stopFamily(ctx, request.DatabaseFamily); err != nil {
		return supervisor.fail(ctx, state, pluginstate.ProcessStartFailed, "plugin_stop_failed", err)
	}
	state.ProcessState, state.HealthState, state.CircuitState = pluginstate.ProcessUninstalling, pluginstate.HealthUnknown, pluginstate.CircuitClosed
	if _, err := supervisor.store.Put(ctx, state); err != nil {
		return ObservedState{}, err
	}
	if err := supervisor.installer.RemoveFamily(ctx, request.DatabaseFamily); err != nil {
		return supervisor.fail(ctx, state, pluginstate.ProcessUninstalling, "plugin_uninstall_failed", err)
	}
	state.ProcessState, state.ActiveSlot, state.InstalledVersion, state.Slots = pluginstate.ProcessAbsent, pluginstate.SlotNone, "", nil
	state.ProcessID, state.ProcessStartTicks, state.RestartCount = 0, 0, 0
	state.StartedAt, state.Failures, state.LastErrorCode = time.Time{}, nil, ""
	saved, err := supervisor.store.Put(ctx, state)
	return ObservedState{State: saved}, err
}

func (supervisor *PluginSupervisor) makeStopped(ctx context.Context, request ReconcileRequest, state pluginstate.FamilyState) (ObservedState, error) {
	if state.InstalledVersion != request.DesiredVersion || state.ActiveSlot == pluginstate.SlotNone {
		return supervisor.installOnly(ctx, request, state, pluginstate.ProcessStopped)
	}
	if err := supervisor.stopFamily(ctx, request.DatabaseFamily); err != nil {
		return supervisor.fail(ctx, state, pluginstate.ProcessStartFailed, "plugin_stop_failed", err)
	}
	state.ProcessState, state.HealthState = pluginstate.ProcessStopped, pluginstate.HealthUnknown
	state.ProcessID, state.ProcessStartTicks, state.StartedAt = 0, 0, time.Time{}
	state.LastErrorCode = ""
	saved, err := supervisor.store.Put(ctx, state)
	return ObservedState{State: saved}, err
}

func (supervisor *PluginSupervisor) makeInstalled(ctx context.Context, request ReconcileRequest, state pluginstate.FamilyState) (ObservedState, error) {
	if err := supervisor.stopFamily(ctx, request.DatabaseFamily); err != nil {
		return supervisor.fail(ctx, state, pluginstate.ProcessStartFailed, "plugin_stop_failed", err)
	}
	if state.InstalledVersion == request.DesiredVersion && state.ActiveSlot != pluginstate.SlotNone {
		state.ProcessState, state.HealthState, state.LastErrorCode = pluginstate.ProcessInstalled, pluginstate.HealthUnknown, ""
		state.ProcessID, state.ProcessStartTicks, state.StartedAt = 0, 0, time.Time{}
		saved, err := supervisor.store.Put(ctx, state)
		return ObservedState{State: saved}, err
	}
	return supervisor.installOnly(ctx, request, state, pluginstate.ProcessInstalled)
}

func (supervisor *PluginSupervisor) installOnly(ctx context.Context, request ReconcileRequest, state pluginstate.FamilyState, final pluginstate.ProcessState) (ObservedState, error) {
	installed, next, err := supervisor.install(ctx, request, state)
	if err != nil {
		return supervisor.fail(ctx, next, processStateForError(err), errorCode(err), err)
	}
	if err := supervisor.installer.Activate(ctx, request.DatabaseFamily, installed.Slot); err != nil {
		return supervisor.fail(ctx, next, pluginstate.ProcessManifestRejected, "plugin_activate_failed", err)
	}
	next.ActiveSlot, next.InstalledVersion = installed.Slot, installed.Version
	next.ProcessState, next.HealthState, next.CircuitState = final, pluginstate.HealthUnknown, pluginstate.CircuitClosed
	next.LastErrorCode, next.Failures = "", nil
	next.ProcessID, next.ProcessStartTicks, next.StartedAt = 0, 0, time.Time{}
	saved, saveErr := supervisor.store.Put(ctx, next)
	return ObservedState{State: saved}, saveErr
}

func (supervisor *PluginSupervisor) makeRunning(ctx context.Context, request ReconcileRequest, state, previous pluginstate.FamilyState) (ObservedState, error) {
	if process, ok := supervisor.running[request.DatabaseFamily]; ok && previous.InstalledVersion == request.DesiredVersion && previous.ActiveConfigurationRevision == request.ConfigurationRevision && previous.ObservedOperationRevision == request.OperationRevision && previous.ProcessState == pluginstate.ProcessRunning {
		_ = process
		return ObservedState{State: previous}, nil
	}
	oldState := previous
	oldProcess := supervisor.running[request.DatabaseFamily]
	var installed InstalledSlot
	var err error
	if state.InstalledVersion == request.DesiredVersion && state.ActiveSlot != pluginstate.SlotNone {
		installed, err = supervisor.installer.Installed(request.DatabaseFamily, state.ActiveSlot)
	} else {
		installed, state, err = supervisor.install(ctx, request, state)
	}
	if err != nil {
		return supervisor.fail(ctx, state, processStateForError(err), errorCode(err), err)
	}
	if oldProcess != nil {
		state.ProcessState = pluginstate.ProcessDraining
		if _, persistErr := supervisor.store.Put(ctx, state); persistErr != nil {
			return ObservedState{}, persistErr
		}
		if stopErr := supervisor.drainProcess(ctx, oldProcess); stopErr != nil {
			return supervisor.fail(ctx, state, pluginstate.ProcessStartFailed, "plugin_drain_failed", stopErr)
		}
		delete(supervisor.running, request.DatabaseFamily)
	}
	state.ProcessState = pluginstate.ProcessStarting
	if _, persistErr := supervisor.store.Put(ctx, state); persistErr != nil {
		return ObservedState{}, persistErr
	}
	process, startErr := supervisor.startProcess(ctx, request, installed, request.ConfigurationRevision)
	if startErr != nil {
		return supervisor.rollback(ctx, request, oldState, oldProcess != nil, state, startErr)
	}
	state.ProcessState = pluginstate.ProcessHandshaking
	if _, persistErr := supervisor.store.Put(ctx, state); persistErr != nil {
		_ = process.Kill()
		return ObservedState{}, persistErr
	}
	if healthErr := supervisor.health.Handshake(ctx, process, healthRequest(request, installed, request.ConfigurationRevision, filepath.Join(supervisor.runtimeRoot, request.DatabaseFamily))); healthErr != nil {
		_ = supervisor.drainProcess(ctx, process)
		return supervisor.rollback(ctx, request, oldState, oldProcess != nil, state, ErrHealthHandshake)
	}
	if activateErr := supervisor.installer.Activate(ctx, request.DatabaseFamily, installed.Slot); activateErr != nil {
		_ = supervisor.drainProcess(ctx, process)
		return supervisor.rollback(ctx, request, oldState, oldProcess != nil, state, activateErr)
	}
	supervisor.running[request.DatabaseFamily] = process
	state.ActiveSlot, state.InstalledVersion = installed.Slot, installed.Version
	state.ProcessState, state.HealthState, state.CircuitState = pluginstate.ProcessRunning, pluginstate.HealthHealthy, pluginstate.CircuitClosed
	state.ProcessID, state.ProcessStartTicks, state.StartedAt = process.PID(), process.StartTicks(), process.StartedAt()
	state.LastErrorCode, state.Failures = "", nil
	saved, saveErr := supervisor.store.Put(ctx, state)
	return ObservedState{State: saved}, saveErr
}

func (supervisor *PluginSupervisor) install(ctx context.Context, request ReconcileRequest, state pluginstate.FamilyState) (InstalledSlot, pluginstate.FamilyState, error) {
	state.ProcessState, state.HealthState = pluginstate.ProcessDownloading, pluginstate.HealthUnknown
	if _, err := supervisor.store.Put(ctx, state); err != nil {
		return InstalledSlot{}, state, err
	}
	lease, err := supervisor.leases.LeasePluginArtifact(ctx, ArtifactLeaseRequest{AssignmentID: request.AssignmentID, ArtifactID: request.ArtifactID, OperationRevision: request.OperationRevision})
	if err != nil || lease.AssignmentID != request.AssignmentID || lease.ArtifactID != request.ArtifactID || lease.OperationRevision != request.OperationRevision {
		return InstalledSlot{}, state, ErrArtifactLease
	}
	download, err := supervisor.downloader.Download(ctx, lease)
	if err != nil {
		return InstalledSlot{}, state, ErrArtifactDownload
	}
	defer download.Body.Close()
	active := state.ActiveSlot
	inactive := pluginstate.SlotA
	if active == pluginstate.SlotA {
		inactive = pluginstate.SlotB
	}
	if err := supervisor.installer.RemoveInactive(ctx, request.DatabaseFamily, inactive); err != nil {
		return InstalledSlot{}, state, err
	}
	state.ProcessState = pluginstate.ProcessVerifying
	if _, err := supervisor.store.Put(ctx, state); err != nil {
		return InstalledSlot{}, state, err
	}
	installed, err := supervisor.installer.InstallInactive(ctx, InstallRequest{DatabaseFamily: request.DatabaseFamily, PluginID: request.PluginID, Version: request.DesiredVersion, ArtifactSHA256: request.ArtifactSHA256, ManifestDigest: request.ManifestDigest, Archive: download.Body, ArchiveSize: download.Size}, inactive)
	if err != nil {
		return InstalledSlot{}, state, err
	}
	if state.Slots == nil {
		state.Slots = map[pluginstate.Slot]pluginstate.SlotState{}
	}
	state.Slots[inactive] = pluginstate.SlotState{Version: installed.Version, ArtifactSHA256: installed.ArtifactSHA256, ManifestDigest: installed.ManifestDigest, CompletedAt: supervisor.now().UTC()}
	return installed, state, nil
}

func (supervisor *PluginSupervisor) rollback(ctx context.Context, request ReconcileRequest, old pluginstate.FamilyState, hadOldProcess bool, failed pluginstate.FamilyState, cause error) (ObservedState, error) {
	if !hadOldProcess || old.ActiveSlot == pluginstate.SlotNone || old.InstalledVersion == "" {
		return supervisor.fail(ctx, failed, processStateForError(cause), errorCode(cause), cause)
	}
	oldInstalled, err := supervisor.installer.Installed(request.DatabaseFamily, old.ActiveSlot)
	if err != nil {
		return supervisor.fail(ctx, failed, pluginstate.ProcessRollback, "plugin_rollback_failed", ErrRollbackFailed)
	}
	rollbackRequest := request
	rollbackRequest.DesiredVersion = old.InstalledVersion
	rollbackProcess, err := supervisor.startProcess(ctx, rollbackRequest, oldInstalled, old.ActiveConfigurationRevision)
	if err != nil || supervisor.health.Handshake(ctx, rollbackProcess, healthRequest(rollbackRequest, oldInstalled, old.ActiveConfigurationRevision, filepath.Join(supervisor.runtimeRoot, request.DatabaseFamily))) != nil {
		if rollbackProcess != nil {
			_ = rollbackProcess.Kill()
		}
		return supervisor.fail(ctx, failed, pluginstate.ProcessRollback, "plugin_rollback_failed", ErrRollbackFailed)
	}
	supervisor.running[request.DatabaseFamily] = rollbackProcess
	old.ObservedOperationRevision = request.OperationRevision
	old.DesiredState = stateForDesired(request.DesiredState)
	old.ProcessState, old.HealthState = pluginstate.ProcessRunning, pluginstate.HealthHealthy
	old.ProcessID, old.ProcessStartTicks, old.StartedAt = rollbackProcess.PID(), rollbackProcess.StartTicks(), rollbackProcess.StartedAt()
	old.BoundInstanceCount = uint32(len(request.InstanceIDs))
	old.ObservationRevision++
	old = supervisor.recordFailure(old, "plugin_rollback_"+errorCode(cause))
	saved, saveErr := supervisor.store.Put(ctx, old)
	if saveErr != nil {
		return ObservedState{}, saveErr
	}
	return ObservedState{State: saved}, cause
}

func (supervisor *PluginSupervisor) startProcess(ctx context.Context, request ReconcileRequest, installed InstalledSlot, configurationRevision uint64) (Process, error) {
	runtimeDirectory := filepath.Join(supervisor.runtimeRoot, request.DatabaseFamily)
	if err := secureMkdir(supervisor.runtimeRoot, runtimeDirectory); err != nil {
		return nil, ErrProcessStart
	}
	config := LaunchConfiguration{AssignmentID: request.AssignmentID, PluginID: request.PluginID, DatabaseFamily: request.DatabaseFamily, Version: installed.Version, Slot: installed.Slot, ConfigurationRevision: configurationRevision, OperationRevision: request.OperationRevision, InstanceIDs: append([]string(nil), request.InstanceIDs...), TemplateIDs: append([]string(nil), request.TemplateIDs...), RuntimeDirectory: runtimeDirectory, UserID: supervisor.userID, GroupID: supervisor.groupID}
	process, err := supervisor.processes.Start(ctx, Executable{Path: installed.ExecutablePath, SHA256: slotExecutableDigest(installed)}, config)
	if err != nil {
		return nil, ErrProcessStart
	}
	return process, nil
}

func slotExecutableDigest(installed InstalledSlot) string {
	return installed.ExecutableSHA256
}

func (supervisor *PluginSupervisor) drainProcess(ctx context.Context, process Process) error {
	drainContext, cancel := context.WithTimeout(ctx, supervisor.drainTimeout)
	defer cancel()
	if err := process.Drain(drainContext); err != nil {
		if killErr := process.Kill(); killErr != nil {
			return killErr
		}
	}
	return nil
}

func (supervisor *PluginSupervisor) stopFamily(ctx context.Context, family string) error {
	process := supervisor.running[family]
	if process == nil {
		return nil
	}
	if err := supervisor.drainProcess(ctx, process); err != nil {
		return err
	}
	delete(supervisor.running, family)
	return nil
}

func (supervisor *PluginSupervisor) fail(ctx context.Context, state pluginstate.FamilyState, processState pluginstate.ProcessState, code string, cause error) (ObservedState, error) {
	state.ProcessState, state.HealthState = processState, pluginstate.HealthUnhealthy
	state.ProcessID, state.ProcessStartTicks, state.StartedAt = 0, 0, time.Time{}
	state = supervisor.recordFailure(state, code)
	saved, err := supervisor.store.Put(ctx, state)
	if err != nil {
		return ObservedState{}, err
	}
	return ObservedState{State: saved}, cause
}

func (supervisor *PluginSupervisor) recordFailure(state pluginstate.FamilyState, code string) pluginstate.FamilyState {
	now := supervisor.now().UTC()
	cutoff := now.Add(-supervisor.failureWindow)
	failures := make([]time.Time, 0, len(state.Failures)+1)
	for _, failure := range state.Failures {
		if failure.After(cutoff) {
			failures = append(failures, failure)
		}
	}
	failures = append(failures, now)
	state.Failures, state.RestartCount, state.LastErrorCode = failures, state.RestartCount+1, code
	if len(failures) >= supervisor.failureThreshold {
		state.CircuitState, state.ProcessState = pluginstate.CircuitOpen, pluginstate.ProcessCircuitOpen
	}
	return state
}

func (supervisor *PluginSupervisor) Stop(ctx context.Context) error {
	if supervisor == nil || ctx == nil {
		return nil
	}
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	families := make([]string, 0, len(supervisor.running))
	for family := range supervisor.running {
		families = append(families, family)
	}
	sort.Strings(families)
	var result error
	for _, family := range families {
		result = errors.Join(result, supervisor.stopFamily(ctx, family))
	}
	return result
}

func (supervisor *PluginSupervisor) Observe() []PluginObservation {
	if supervisor == nil {
		return nil
	}
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	states := supervisor.store.List()
	sort.Slice(states, func(left, right int) bool { return states[left].DatabaseFamily < states[right].DatabaseFamily })
	result := make([]PluginObservation, 0, len(states))
	for _, state := range states {
		result = append(result, *assignmentObservation(state, supervisor.now().UTC()))
	}
	return result
}

func (supervisor *PluginSupervisor) Observation() *agentv1.PluginObservation {
	if supervisor == nil {
		return nil
	}
	states := supervisor.store.List()
	sort.Slice(states, func(left, right int) bool { return states[left].DatabaseFamily < states[right].DatabaseFamily })
	revision := uint64(1)
	assignments := make([]*agentv1.PluginAssignmentObservation, 0, len(states))
	for _, state := range states {
		if state.StateRevision >= revision {
			revision = state.StateRevision
		}
		assignments = append(assignments, assignmentObservation(state, supervisor.now().UTC()))
	}
	observedAt := supervisor.now().UTC()
	return &agentv1.PluginObservation{HostId: supervisor.hostID, AgentId: supervisor.agentID, ObservationRevision: revision, Assignments: assignments, ObservedAt: timestamppb.New(observedAt)}
}

func assignmentObservation(state pluginstate.FamilyState, at time.Time) *agentv1.PluginAssignmentObservation {
	result := &agentv1.PluginAssignmentObservation{AssignmentId: state.AssignmentID, PluginId: state.PluginID, DatabaseFamily: state.DatabaseFamily, InstalledVersion: state.InstalledVersion, ActiveSlot: protoSlot(state.ActiveSlot), ProcessState: protoProcess(state.ProcessState), Health: protoHealth(state.HealthState), RestartCount: state.RestartCount, BoundInstanceCount: state.BoundInstanceCount, ActiveConfigurationRevision: state.ActiveConfigurationRevision, ObservedOperationRevision: state.ObservedOperationRevision, LastErrorCode: state.LastErrorCode, CircuitState: protoCircuit(state.CircuitState), ObservedAt: timestamppb.New(at)}
	if state.ProcessID > 0 {
		result.ProcessId = uint32(state.ProcessID)
		result.StartedAt = timestamppb.New(state.StartedAt)
	}
	return result
}

func baseState(request ReconcileRequest) pluginstate.FamilyState {
	return pluginstate.FamilyState{AssignmentID: request.AssignmentID, PluginID: request.PluginID, DatabaseFamily: request.DatabaseFamily, ActiveSlot: pluginstate.SlotNone, DesiredState: stateForDesired(request.DesiredState), ProcessState: pluginstate.ProcessAbsent, HealthState: pluginstate.HealthUnknown, CircuitState: pluginstate.CircuitClosed, ActiveConfigurationRevision: request.ConfigurationRevision, ObservedOperationRevision: request.OperationRevision, BoundInstanceCount: uint32(len(request.InstanceIDs))}
}

func cloneRequest(request ReconcileRequest) ReconcileRequest {
	request.ArtifactSHA256 = append([]byte(nil), request.ArtifactSHA256...)
	request.ManifestDigest = append([]byte(nil), request.ManifestDigest...)
	request.InstanceIDs = append([]string(nil), request.InstanceIDs...)
	request.TemplateIDs = append([]string(nil), request.TemplateIDs...)
	return request
}

func healthRequest(request ReconcileRequest, installed InstalledSlot, configurationRevision uint64, runtimeDirectory string) HealthRequest {
	digest, _ := hex.DecodeString(installed.ExecutableSHA256)
	return HealthRequest{AssignmentID: request.AssignmentID, PluginID: request.PluginID, DatabaseFamily: request.DatabaseFamily, Version: installed.Version, ProtocolVersion: "v1", ExecutableSHA256: digest, ConfigurationRevision: configurationRevision, OperationRevision: request.OperationRevision, InstanceIDs: append([]string(nil), request.InstanceIDs...), RuntimeDirectory: runtimeDirectory}
}

func processStateForError(err error) pluginstate.ProcessState {
	switch {
	case errors.Is(err, ErrArtifactDownload), errors.Is(err, ErrArtifactLease):
		return pluginstate.ProcessDownloadFailed
	case errors.Is(err, ErrSignatureRejected):
		return pluginstate.ProcessSignatureRejected
	case errors.Is(err, ErrPlatformMismatch):
		return pluginstate.ProcessPlatformMismatch
	case errors.Is(err, ErrManifestRejected), errors.Is(err, ErrArtifactDigest):
		return pluginstate.ProcessManifestRejected
	case errors.Is(err, ErrHealthHandshake):
		return pluginstate.ProcessHandshakeFailed
	default:
		return pluginstate.ProcessStartFailed
	}
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, ErrArtifactLease):
		return "artifact_lease_rejected"
	case errors.Is(err, ErrArtifactDownload):
		return "artifact_download_failed"
	case errors.Is(err, ErrArtifactDigest):
		return "artifact_digest_rejected"
	case errors.Is(err, ErrSignatureRejected):
		return "signature_rejected"
	case errors.Is(err, ErrPlatformMismatch):
		return "platform_mismatch"
	case errors.Is(err, ErrManifestRejected):
		return "manifest_rejected"
	case errors.Is(err, ErrHealthHandshake):
		return "handshake_failed"
	default:
		return "plugin_start_failed"
	}
}

func protoSlot(value pluginstate.Slot) agentv1.PluginActiveSlot {
	switch value {
	case pluginstate.SlotA:
		return agentv1.PluginActiveSlot_PLUGIN_ACTIVE_SLOT_A
	case pluginstate.SlotB:
		return agentv1.PluginActiveSlot_PLUGIN_ACTIVE_SLOT_B
	default:
		return agentv1.PluginActiveSlot_PLUGIN_ACTIVE_SLOT_NONE
	}
}
func protoHealth(value pluginstate.HealthState) agentv1.PluginHealthState {
	switch value {
	case pluginstate.HealthHealthy:
		return agentv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY
	case pluginstate.HealthDegraded:
		return agentv1.PluginHealthState_PLUGIN_HEALTH_STATE_DEGRADED
	default:
		return agentv1.PluginHealthState_PLUGIN_HEALTH_STATE_UNHEALTHY
	}
}
func protoCircuit(value pluginstate.CircuitState) agentv1.PluginCircuitState {
	switch value {
	case pluginstate.CircuitOpen:
		return agentv1.PluginCircuitState_PLUGIN_CIRCUIT_STATE_OPEN
	case pluginstate.CircuitHalfOpen:
		return agentv1.PluginCircuitState_PLUGIN_CIRCUIT_STATE_HALF_OPEN
	default:
		return agentv1.PluginCircuitState_PLUGIN_CIRCUIT_STATE_CLOSED
	}
}
func protoProcess(value pluginstate.ProcessState) agentv1.PluginProcessState {
	mapping := map[pluginstate.ProcessState]agentv1.PluginProcessState{pluginstate.ProcessAbsent: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_ABSENT, pluginstate.ProcessDownloading: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_DOWNLOADING, pluginstate.ProcessVerifying: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_VERIFYING, pluginstate.ProcessInstalled: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_INSTALLED, pluginstate.ProcessStarting: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_STARTING, pluginstate.ProcessHandshaking: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_HANDSHAKING, pluginstate.ProcessRunning: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_RUNNING, pluginstate.ProcessDegraded: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_DEGRADED, pluginstate.ProcessRestarting: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_RESTARTING, pluginstate.ProcessDraining: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_DRAINING, pluginstate.ProcessStopped: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_STOPPED, pluginstate.ProcessUninstalling: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_UNINSTALLING, pluginstate.ProcessDownloadFailed: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_DOWNLOAD_FAILED, pluginstate.ProcessSignatureRejected: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_SIGNATURE_REJECTED, pluginstate.ProcessManifestRejected: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_MANIFEST_REJECTED, pluginstate.ProcessPlatformMismatch: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_PLATFORM_MISMATCH, pluginstate.ProcessStartFailed: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_START_FAILED, pluginstate.ProcessHandshakeFailed: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_HANDSHAKE_FAILED, pluginstate.ProcessUpgrading: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_UPGRADING, pluginstate.ProcessRollback: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_ROLLBACK, pluginstate.ProcessCircuitOpen: agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_CIRCUIT_OPEN}
	if result, ok := mapping[value]; ok {
		return result
	}
	return agentv1.PluginProcessState_PLUGIN_PROCESS_STATE_UNSPECIFIED
}

var _ Supervisor = (*PluginSupervisor)(nil)
