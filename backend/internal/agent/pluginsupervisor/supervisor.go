package pluginsupervisor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/pluginstate"
	"google.golang.org/protobuf/proto"
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
	RestartBase      time.Duration
	RestartMaximum   time.Duration
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
	restartBase      time.Duration
	restartMaximum   time.Duration
	now              func() time.Time
	running          map[string]*managedProcess
	shuttingDown     atomic.Bool
	refreshPending   atomic.Bool
	refreshWorker    atomic.Bool
}

type managedProcess struct {
	process     Process
	cancel      context.CancelFunc
	launchNonce []byte
	expected    atomic.Bool
	request     ReconcileRequest
	installed   InstalledSlot
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
	if config.RestartBase <= 0 {
		config.RestartBase = time.Second
	}
	if config.RestartMaximum <= 0 {
		config.RestartMaximum = 30 * time.Second
	}
	if config.RestartBase > config.RestartMaximum || config.RestartMaximum > 5*time.Minute {
		return nil, ErrInvalidRequest
	}
	for _, state := range config.Store.List() {
		if state.Validate() != nil || config.Installer.Recover(context.Background(), state.DatabaseFamily) != nil {
			return nil, ErrInstallFailed
		}
		for slot, slotState := range state.Slots {
			identity := SlotIdentity{DatabaseFamily: state.DatabaseFamily, PluginID: state.PluginID, Version: slotState.Version, ArtifactSHA256: slotState.ArtifactSHA256, ManifestDigest: slotState.ManifestDigest}
			if _, err := config.Installer.Installed(context.Background(), identity, slot); err != nil {
				return nil, ErrInstallFailed
			}
		}
		if reconciled, changed := reconcilePersistedProcess(state); changed {
			reconciled.ObservationRevision++
			if _, err := config.Store.Put(context.Background(), reconciled); err != nil {
				return nil, ErrInstallFailed
			}
		}
	}
	supervisor := &PluginSupervisor{agentID: config.AgentID, hostID: config.HostID, runtimeRoot: config.RuntimeRoot, store: config.Store, installer: config.Installer, leases: config.Leases, downloader: config.Downloader, processes: config.Processes, health: config.Health, userID: config.UserID, groupID: config.GroupID, drainTimeout: config.DrainTimeout, failureWindow: config.FailureWindow, failureThreshold: config.FailureThreshold, restartBase: config.RestartBase, restartMaximum: config.RestartMaximum, now: config.Now, running: map[string]*managedProcess{}}
	for _, state := range config.Store.List() {
		if state.DesiredState == pluginstate.DesiredRunning && state.ActiveSlot != pluginstate.SlotNone && state.CircuitState != pluginstate.CircuitOpen {
			go supervisor.restartPersisted(state.DatabaseFamily, state.RequestFingerprint, 0)
		}
	}
	return supervisor, nil
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
		if request.OperationRevision == current.ObservedOperationRevision && current.RequestFingerprint != request.Fingerprint() {
			return PreparedChange{}, ErrOperationConflict
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
	if exists && request.OperationRevision == current.ObservedOperationRevision && current.RequestFingerprint != request.Fingerprint() {
		return ObservedState{State: current}, ErrOperationConflict
	}
	if exists && request.OperationRevision == current.ObservedOperationRevision && current.CircuitState == pluginstate.CircuitOpen {
		return ObservedState{State: current}, ErrCircuitOpen
	}
	if exists && request.OperationRevision == current.ObservedOperationRevision && current.RequestFingerprint == request.Fingerprint() {
		if stateConverged(current, request.DesiredState, supervisor.running[request.DatabaseFamily] != nil) {
			return ObservedState{State: current}, nil
		}
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
	current.DesiredVersion = request.DesiredVersion
	current.DesiredArtifactID = request.ArtifactID
	current.DesiredArtifactSHA256 = hex.EncodeToString(request.ArtifactSHA256)
	current.DesiredManifestDigest = hex.EncodeToString(request.ManifestDigest)
	current.DesiredConfigurationRevision = request.ConfigurationRevision
	current.DesiredInstanceIDs = append([]string(nil), request.InstanceIDs...)
	current.DesiredInstanceDescriptors = stateDescriptors(request.InstanceDescriptors)
	current.DesiredTemplateIDs = append([]string(nil), request.TemplateIDs...)
	current.DesiredTemplateConfigurations = cloneTemplateConfigurations(request.TemplateConfigurations)
	current.DesiredTemplateLeaseCommandID = request.TemplateLeaseCommandID
	current.DesiredTemplateReferences = stateTemplateReferences(request.TemplateReferences)
	current.DesiredInstanceTemplateRefs = stateInstanceTemplateReferences(request.InstanceTemplateRefs)
	current.DesiredCredentialsComplete = request.CredentialsComplete
	sort.Strings(current.DesiredInstanceIDs)
	sort.Strings(current.DesiredTemplateIDs)
	current.RequestFingerprint = request.Fingerprint()
	current.ObservedOperationRevision = request.OperationRevision
	current.ObservationRevision++
	if current.ObservationRevision == 0 {
		return ObservedState{}, ErrInvalidRequest
	}
	intent, err := supervisor.store.Put(ctx, current)
	if err != nil {
		return ObservedState{}, err
	}
	current = intent

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

func stateConverged(state pluginstate.FamilyState, desired DesiredState, hasProcess bool) bool {
	switch desired {
	case DesiredAbsent:
		return state.ProcessState == pluginstate.ProcessAbsent
	case DesiredStopped:
		return state.ProcessState == pluginstate.ProcessStopped && !hasProcess
	case DesiredInstalled:
		return (state.ProcessState == pluginstate.ProcessInstalled || state.ProcessState == pluginstate.ProcessStopped) && state.ActiveSlot != pluginstate.SlotNone
	case DesiredRunning:
		return state.ProcessState == pluginstate.ProcessRunning && hasProcess
	default:
		return false
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
	state.ActiveArtifactID, state.ActiveArtifactSHA256, state.ActiveManifestDigest = "", "", ""
	state.ActiveInstanceIDs, state.ActiveInstanceDescriptors, state.ActiveTemplateIDs, state.ActiveTemplateConfigurations, state.BoundInstanceCount = nil, nil, nil, nil, 0
	state.ActiveTemplateLeaseCommandID, state.ActiveTemplateReferences, state.ActiveInstanceTemplateRefs = "", nil, nil
	state.ActiveCredentialsComplete = false
	state.ProcessID, state.ProcessStartTicks, state.RestartCount = 0, 0, 0
	state.StartedAt, state.Failures, state.LastErrorCode = time.Time{}, nil, ""
	saved, err := supervisor.store.Put(ctx, state)
	return ObservedState{State: saved}, err
}

func (supervisor *PluginSupervisor) makeStopped(ctx context.Context, request ReconcileRequest, state pluginstate.FamilyState) (ObservedState, error) {
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
	if err := supervisor.installer.Activate(ctx, identityFromRequest(request), installed.Slot); err != nil {
		return supervisor.fail(ctx, next, pluginstate.ProcessManifestRejected, "plugin_activate_failed", err)
	}
	next.ActiveSlot, next.InstalledVersion = installed.Slot, installed.Version
	applyActiveConfiguration(&next, request, installed)
	next.ProcessState, next.HealthState, next.CircuitState = final, pluginstate.HealthUnknown, pluginstate.CircuitClosed
	next.LastErrorCode, next.Failures = "", nil
	next.ProcessID, next.ProcessStartTicks, next.StartedAt = 0, 0, time.Time{}
	saved, saveErr := supervisor.store.Put(ctx, next)
	return ObservedState{State: saved}, saveErr
}

func (supervisor *PluginSupervisor) makeRunning(ctx context.Context, request ReconcileRequest, state, previous pluginstate.FamilyState) (ObservedState, error) {
	if process, ok := supervisor.running[request.DatabaseFamily]; ok && previous.RequestFingerprint == request.Fingerprint() && previous.ProcessState == pluginstate.ProcessRunning {
		_ = process
		return ObservedState{State: previous}, nil
	}
	oldState := previous
	oldProcess := supervisor.running[request.DatabaseFamily]
	var installed InstalledSlot
	var err error
	if state.InstalledVersion == request.DesiredVersion && state.ActiveSlot != pluginstate.SlotNone {
		installed, err = supervisor.installer.Installed(ctx, identityFromRequest(request), state.ActiveSlot)
	} else {
		installed, state, err = supervisor.install(ctx, request, state)
	}
	if err != nil {
		return supervisor.fail(ctx, state, processStateForError(err), errorCode(err), err)
	}
	if oldProcess != nil && oldState.ProcessState == pluginstate.ProcessRunning && oldState.InstalledVersion == request.DesiredVersion && oldState.ActiveSlot != pluginstate.SlotNone {
		applier, ok := supervisor.health.(ConfigurationApplier)
		if !ok {
			state.ProcessState, state.HealthState = oldState.ProcessState, oldState.HealthState
			state.ProcessID, state.ProcessStartTicks, state.StartedAt = oldState.ProcessID, oldState.ProcessStartTicks, oldState.StartedAt
			state.LastErrorCode = "plugin_configuration_apply_failed"
			saved, saveErr := supervisor.store.Put(ctx, state)
			if saveErr != nil {
				return ObservedState{}, saveErr
			}
			return ObservedState{State: saved}, ErrHealthHandshake
		}
		applyRequest := healthRequest(request, installed, request.ConfigurationRevision, filepath.Join(supervisor.runtimeRoot, request.DatabaseFamily), oldProcess.launchNonce, supervisor.userID, supervisor.groupID)
		if applyErr := applier.ApplyConfiguration(ctx, oldProcess.process, applyRequest); applyErr != nil {
			state.ProcessState, state.HealthState = oldState.ProcessState, oldState.HealthState
			state.ProcessID, state.ProcessStartTicks, state.StartedAt = oldState.ProcessID, oldState.ProcessStartTicks, oldState.StartedAt
			state.LastErrorCode = "plugin_configuration_apply_failed"
			saved, saveErr := supervisor.store.Put(ctx, state)
			if saveErr != nil {
				return ObservedState{}, saveErr
			}
			return ObservedState{State: saved}, applyErr
		}
		applyActiveConfiguration(&state, request, installed)
		healthState, activationCode := supervisor.activationState(oldProcess.process)
		state.ProcessState, state.HealthState, state.CircuitState = pluginstate.ProcessRunning, healthState, pluginstate.CircuitClosed
		state.ProcessID, state.ProcessStartTicks, state.StartedAt = oldState.ProcessID, oldState.ProcessStartTicks, oldState.StartedAt
		state.LastErrorCode, state.Failures = activationCode, nil
		oldProcess.request = cloneRequest(request)
		oldProcess.installed = installed
		saved, saveErr := supervisor.store.Put(ctx, state)
		return ObservedState{State: saved}, saveErr
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
	process, startErr := supervisor.startProcess(request, installed, request.ConfigurationRevision)
	if startErr != nil {
		return supervisor.rollback(ctx, request, oldState, oldProcess != nil, state, startErr)
	}
	state.ProcessState = pluginstate.ProcessHandshaking
	if _, persistErr := supervisor.store.Put(ctx, state); persistErr != nil {
		_ = supervisor.drainProcess(ctx, process)
		return ObservedState{}, persistErr
	}
	if healthErr := supervisor.health.Handshake(ctx, process.process, healthRequest(request, installed, request.ConfigurationRevision, filepath.Join(supervisor.runtimeRoot, request.DatabaseFamily), process.launchNonce, supervisor.userID, supervisor.groupID)); healthErr != nil {
		_ = supervisor.drainProcess(ctx, process)
		return supervisor.rollback(ctx, request, oldState, oldProcess != nil, state, ErrHealthHandshake)
	}
	if activateErr := supervisor.installer.Activate(ctx, identityFromRequest(request), installed.Slot); activateErr != nil {
		_ = supervisor.drainProcess(ctx, process)
		return supervisor.rollback(ctx, request, oldState, oldProcess != nil, state, activateErr)
	}
	supervisor.running[request.DatabaseFamily] = process
	state.ActiveSlot, state.InstalledVersion = installed.Slot, installed.Version
	applyActiveConfiguration(&state, request, installed)
	healthState, activationCode := supervisor.activationState(process.process)
	state.ProcessState, state.HealthState, state.CircuitState = pluginstate.ProcessRunning, healthState, pluginstate.CircuitClosed
	state.ProcessID, state.ProcessStartTicks, state.StartedAt = process.process.PID(), process.process.StartTicks(), process.process.StartedAt()
	state.LastErrorCode, state.Failures = activationCode, nil
	saved, saveErr := supervisor.store.Put(ctx, state)
	if saveErr == nil {
		go supervisor.monitorProcess(request.DatabaseFamily, process)
	}
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
	installed, err = supervisor.installer.Installed(ctx, identityFromRequest(request), inactive)
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
	oldInstalled, err := supervisor.installer.Installed(ctx, identityFromActiveState(old), old.ActiveSlot)
	if err != nil {
		return supervisor.fail(ctx, failed, pluginstate.ProcessRollback, "plugin_rollback_failed", ErrRollbackFailed)
	}
	rollbackRequest := requestFromActiveState(old)
	rollbackRequest.ConfigurationRevision = request.ConfigurationRevision
	rollbackRequest.OperationRevision = request.OperationRevision
	if request.TemplateLeaseCommandID != "" {
		rollbackRequest.TemplateLeaseCommandID = request.TemplateLeaseCommandID
	}
	rollbackProcess, err := supervisor.startProcess(rollbackRequest, oldInstalled, rollbackRequest.ConfigurationRevision)
	if err != nil || supervisor.health.Handshake(ctx, rollbackProcess.process, healthRequest(rollbackRequest, oldInstalled, rollbackRequest.ConfigurationRevision, filepath.Join(supervisor.runtimeRoot, request.DatabaseFamily), rollbackProcess.launchNonce, supervisor.userID, supervisor.groupID)) != nil {
		if rollbackProcess != nil {
			_ = supervisor.drainProcess(ctx, rollbackProcess)
		}
		return supervisor.fail(ctx, failed, pluginstate.ProcessRollback, "plugin_rollback_failed", ErrRollbackFailed)
	}
	supervisor.running[request.DatabaseFamily] = rollbackProcess
	old.ObservedOperationRevision = request.OperationRevision
	old.ActiveConfigurationRevision = request.ConfigurationRevision
	if request.TemplateLeaseCommandID != "" {
		old.ActiveTemplateLeaseCommandID = request.TemplateLeaseCommandID
	}
	old.DesiredState = stateForDesired(request.DesiredState)
	rollbackHealth, _ := supervisor.activationState(rollbackProcess.process)
	old.ProcessState, old.HealthState = pluginstate.ProcessRunning, rollbackHealth
	old.ProcessID, old.ProcessStartTicks, old.StartedAt = rollbackProcess.process.PID(), rollbackProcess.process.StartTicks(), rollbackProcess.process.StartedAt()
	old.ObservationRevision++
	old.DesiredState = stateForDesired(request.DesiredState)
	old.DesiredVersion, old.DesiredArtifactID = request.DesiredVersion, request.ArtifactID
	old.DesiredArtifactSHA256, old.DesiredManifestDigest, old.RequestFingerprint = hex.EncodeToString(request.ArtifactSHA256), hex.EncodeToString(request.ManifestDigest), request.Fingerprint()
	old.DesiredConfigurationRevision = request.ConfigurationRevision
	old.DesiredInstanceIDs, old.DesiredTemplateIDs = append([]string(nil), request.InstanceIDs...), append([]string(nil), request.TemplateIDs...)
	old.DesiredInstanceDescriptors = stateDescriptors(request.InstanceDescriptors)
	old.DesiredTemplateConfigurations = cloneTemplateConfigurations(request.TemplateConfigurations)
	old.DesiredTemplateLeaseCommandID = request.TemplateLeaseCommandID
	old.DesiredTemplateReferences = stateTemplateReferences(request.TemplateReferences)
	old.DesiredInstanceTemplateRefs = stateInstanceTemplateReferences(request.InstanceTemplateRefs)
	old.DesiredCredentialsComplete = request.CredentialsComplete
	sort.Strings(old.DesiredInstanceIDs)
	sort.Strings(old.DesiredTemplateIDs)
	old = supervisor.recordFailure(old, "plugin_upgrade_rolled_back")
	saved, saveErr := supervisor.store.Put(ctx, old)
	if saveErr != nil {
		return ObservedState{}, saveErr
	}
	go supervisor.monitorProcess(request.DatabaseFamily, rollbackProcess)
	return ObservedState{State: saved}, cause
}

func (supervisor *PluginSupervisor) startProcess(request ReconcileRequest, installed InstalledSlot, configurationRevision uint64) (*managedProcess, error) {
	runtimeDirectory := filepath.Join(supervisor.runtimeRoot, request.DatabaseFamily)
	if err := secureMkdir(supervisor.runtimeRoot, runtimeDirectory); err != nil {
		return nil, ErrProcessStart
	}
	if err := prepareRuntimeSocket(runtimeDirectory); err != nil {
		return nil, ErrProcessStart
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrProcessStart
	}
	lifetime, cancel := context.WithCancel(context.Background())
	config := LaunchConfiguration{AssignmentID: request.AssignmentID, PluginID: request.PluginID, DatabaseFamily: request.DatabaseFamily, Version: installed.Version, Slot: installed.Slot, ConfigurationRevision: configurationRevision, OperationRevision: request.OperationRevision, InstanceIDs: append([]string(nil), request.InstanceIDs...), InstanceDescriptors: append([]InstanceDescriptor(nil), request.InstanceDescriptors...), TemplateIDs: append([]string(nil), request.TemplateIDs...), RuntimeDirectory: runtimeDirectory, UserID: supervisor.userID, GroupID: supervisor.groupID, LaunchNonce: nonce}
	process, err := supervisor.processes.Start(lifetime, Executable{Path: installed.ExecutablePath, SHA256: slotExecutableDigest(installed)}, config)
	if err != nil {
		cancel()
		return nil, ErrProcessStart
	}
	return &managedProcess{process: process, cancel: cancel, launchNonce: nonce, request: cloneRequest(request), installed: installed}, nil
}

func slotExecutableDigest(installed InstalledSlot) string {
	return installed.ExecutableSHA256
}

func (supervisor *PluginSupervisor) drainProcess(ctx context.Context, process *managedProcess) error {
	if process == nil || process.process == nil {
		return nil
	}
	process.expected.Store(true)
	defer process.cancel()
	drainContext, cancel := context.WithTimeout(ctx, supervisor.drainTimeout)
	defer cancel()
	if gateway, ok := supervisor.health.(interface {
		Shutdown(context.Context, Process, time.Duration) error
	}); ok {
		// Gateway shutdown is advisory. The Supervisor always continues through
		// the OS-owned bounded termination and join path, including when no
		// Session was registered or the plugin RPC is unresponsive.
		_ = gateway.Shutdown(drainContext, process.process, supervisor.drainTimeout)
	}
	if err := process.process.Drain(drainContext); err != nil {
		if killErr := process.process.Kill(); killErr != nil {
			return killErr
		}
	}
	process.cancel()
	joined := make(chan error, 1)
	go func() { joined <- process.process.Wait() }()
	select {
	case <-joined:
		return nil
	case <-drainContext.Done():
		if err := process.process.Kill(); err != nil {
			return err
		}
	}
	joinTimer := time.NewTimer(supervisor.drainTimeout)
	defer joinTimer.Stop()
	select {
	case <-joined:
		return nil
	case <-joinTimer.C:
		return ErrProcessExited
	}
}

func (supervisor *PluginSupervisor) activationState(process Process) (pluginstate.HealthState, string) {
	if provider, ok := supervisor.health.(interface {
		ActivationState(Process) (pluginstate.HealthState, string)
	}); ok {
		health, code := provider.ActivationState(process)
		if health == pluginstate.HealthDegraded && (code == "waiting_templates" || code == "waiting_credentials" || code == "plugin_reconcile_unavailable") {
			return health, code
		}
	}
	return pluginstate.HealthHealthy, ""
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

func (supervisor *PluginSupervisor) monitorProcess(family string, managed *managedProcess) {
	err := managed.process.Wait()
	managed.cancel()
	if managed.expected.Load() || supervisor.shuttingDown.Load() {
		return
	}
	if cleaner, ok := supervisor.health.(UnexpectedExitCleaner); ok {
		cleaner.CleanupUnexpectedExit(managed.process)
	}
	supervisor.mu.Lock()
	if supervisor.running[family] != managed {
		supervisor.mu.Unlock()
		return
	}
	delete(supervisor.running, family)
	state, ok := supervisor.store.Get(family)
	if !ok || state.DesiredState != pluginstate.DesiredRunning {
		supervisor.mu.Unlock()
		return
	}
	state.ProcessID, state.ProcessStartTicks, state.StartedAt = 0, 0, time.Time{}
	state.ProcessState, state.HealthState = pluginstate.ProcessRestarting, pluginstate.HealthUnhealthy
	state = supervisor.recordFailure(state, "plugin_process_exited")
	_, _ = supervisor.store.Put(context.Background(), state)
	delay := supervisor.restartDelay(len(state.Failures))
	if state.CircuitState == pluginstate.CircuitOpen {
		supervisor.mu.Unlock()
		return
	}
	fingerprint := state.RequestFingerprint
	supervisor.mu.Unlock()
	_ = err
	go supervisor.restartPersisted(family, fingerprint, delay)
}

func (supervisor *PluginSupervisor) restartDelay(failures int) time.Duration {
	delay := supervisor.restartBase
	for index := 1; index < failures && delay < supervisor.restartMaximum; index++ {
		delay *= 2
		if delay > supervisor.restartMaximum {
			delay = supervisor.restartMaximum
		}
	}
	return delay
}

func (supervisor *PluginSupervisor) restartPersisted(family, fingerprint string, delay time.Duration) {
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		<-timer.C
	}
	if supervisor.shuttingDown.Load() {
		return
	}
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.shuttingDown.Load() || supervisor.running[family] != nil {
		return
	}
	state, ok := supervisor.store.Get(family)
	if !ok || state.RequestFingerprint != fingerprint || state.DesiredState != pluginstate.DesiredRunning || state.CircuitState == pluginstate.CircuitOpen || state.ActiveSlot == pluginstate.SlotNone {
		return
	}
	identity := identityFromActiveState(state)
	installed, err := supervisor.installer.Installed(context.Background(), identity, state.ActiveSlot)
	if err != nil {
		state = supervisor.recordFailure(state, "plugin_slot_rejected")
		state.ProcessState = pluginstate.ProcessStartFailed
		_, _ = supervisor.store.Put(context.Background(), state)
		if state.CircuitState != pluginstate.CircuitOpen {
			go supervisor.restartPersisted(family, fingerprint, supervisor.restartDelay(len(state.Failures)))
		}
		return
	}
	request := requestFromActiveState(state)
	managed, err := supervisor.startProcess(request, installed, state.ActiveConfigurationRevision)
	if err == nil {
		healthCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = supervisor.health.Handshake(healthCtx, managed.process, healthRequest(request, installed, state.ActiveConfigurationRevision, filepath.Join(supervisor.runtimeRoot, family), managed.launchNonce, supervisor.userID, supervisor.groupID))
		cancel()
	}
	if err != nil {
		if managed != nil {
			_ = supervisor.drainProcess(context.Background(), managed)
		}
		state = supervisor.recordFailure(state, "plugin_restart_failed")
		state.ProcessState = pluginstate.ProcessRestarting
		_, _ = supervisor.store.Put(context.Background(), state)
		if state.CircuitState != pluginstate.CircuitOpen {
			go supervisor.restartPersisted(family, fingerprint, supervisor.restartDelay(len(state.Failures)))
		}
		return
	}
	supervisor.running[family] = managed
	healthState, activationCode := supervisor.activationState(managed.process)
	state.ProcessState, state.HealthState = pluginstate.ProcessRunning, healthState
	state.ProcessID, state.ProcessStartTicks, state.StartedAt = managed.process.PID(), managed.process.StartTicks(), managed.process.StartedAt()
	state.LastErrorCode = activationCode
	_, _ = supervisor.store.Put(context.Background(), state)
	go supervisor.monitorProcess(family, managed)
}

func (supervisor *PluginSupervisor) Stop(ctx context.Context) error {
	if supervisor == nil || ctx == nil {
		return nil
	}
	supervisor.shuttingDown.Store(true)
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
	_, observedAt, states := supervisor.store.Snapshot()
	result := make([]PluginObservation, 0, len(states))
	for _, state := range states {
		result = append(result, *assignmentObservation(state, observedAt))
	}
	return result
}

func (supervisor *PluginSupervisor) Observation() *agentv1.PluginObservation {
	if supervisor == nil {
		return nil
	}
	revision, observedAt, states := supervisor.store.Snapshot()
	if revision == 0 || observedAt.IsZero() {
		return nil
	}
	assignments := make([]*agentv1.PluginAssignmentObservation, 0, len(states))
	for _, state := range states {
		assignments = append(assignments, assignmentObservation(state, observedAt))
	}
	return &agentv1.PluginObservation{HostId: supervisor.hostID, AgentId: supervisor.agentID, ObservationRevision: revision, Assignments: assignments, ObservedAt: timestamppb.New(observedAt)}
}

// RefreshObservation persists an equivalent, higher-revision snapshot when a
// new authenticated control session is established. This lets a restarted
// Server distinguish fresh Agent convergence from replay of an old snapshot.
func (supervisor *PluginSupervisor) RefreshObservation(ctx context.Context) error {
	if supervisor == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalidRequest
	}
	supervisor.refreshPending.Store(true)
	if supervisor.mu.TryLock() {
		supervisor.refreshPending.Store(false)
		err := supervisor.refreshObservationLocked(ctx)
		supervisor.mu.Unlock()
		if supervisor.refreshPending.Load() {
			supervisor.startObservationRefreshWorker()
		}
		return err
	}
	supervisor.startObservationRefreshWorker()
	return nil
}

func (supervisor *PluginSupervisor) refreshObservationLocked(ctx context.Context) error {
	states := supervisor.store.List()
	sort.Slice(states, func(i, j int) bool { return states[i].DatabaseFamily < states[j].DatabaseFamily })
	for _, state := range states {
		state.ObservationRevision++
		if state.ObservationRevision == 0 {
			return ErrInvalidRequest
		}
		if _, err := supervisor.store.Put(ctx, state); err != nil {
			return err
		}
	}
	return nil
}

func (supervisor *PluginSupervisor) startObservationRefreshWorker() {
	if supervisor == nil || supervisor.shuttingDown.Load() || !supervisor.refreshWorker.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer func() {
			supervisor.refreshWorker.Store(false)
			if supervisor.refreshPending.Load() && !supervisor.shuttingDown.Load() {
				supervisor.startObservationRefreshWorker()
			}
		}()
		for supervisor.refreshPending.Load() && !supervisor.shuttingDown.Load() {
			if !supervisor.mu.TryLock() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			if !supervisor.refreshPending.Swap(false) {
				supervisor.mu.Unlock()
				continue
			}
			err := supervisor.refreshObservationLocked(context.Background())
			supervisor.mu.Unlock()
			if err != nil {
				supervisor.refreshPending.Store(true)
				time.Sleep(25 * time.Millisecond)
			}
		}
	}()
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
	state := pluginstate.FamilyState{AssignmentID: request.AssignmentID, PluginID: request.PluginID, DatabaseFamily: request.DatabaseFamily, ActiveSlot: pluginstate.SlotNone, DesiredState: stateForDesired(request.DesiredState), DesiredVersion: request.DesiredVersion, DesiredArtifactID: request.ArtifactID, DesiredArtifactSHA256: hex.EncodeToString(request.ArtifactSHA256), DesiredManifestDigest: hex.EncodeToString(request.ManifestDigest), DesiredConfigurationRevision: request.ConfigurationRevision, DesiredInstanceIDs: append([]string(nil), request.InstanceIDs...), DesiredInstanceDescriptors: stateDescriptors(request.InstanceDescriptors), DesiredTemplateIDs: append([]string(nil), request.TemplateIDs...), DesiredTemplateConfigurations: cloneTemplateConfigurations(request.TemplateConfigurations), DesiredTemplateLeaseCommandID: request.TemplateLeaseCommandID, DesiredTemplateReferences: stateTemplateReferences(request.TemplateReferences), DesiredInstanceTemplateRefs: stateInstanceTemplateReferences(request.InstanceTemplateRefs), DesiredCredentialsComplete: request.CredentialsComplete, RequestFingerprint: request.Fingerprint(), ProcessState: pluginstate.ProcessAbsent, HealthState: pluginstate.HealthUnknown, CircuitState: pluginstate.CircuitClosed, ActiveConfigurationRevision: request.ConfigurationRevision, ObservedOperationRevision: request.OperationRevision}
	sort.Strings(state.DesiredInstanceIDs)
	sort.Strings(state.DesiredTemplateIDs)
	return state
}

func applyActiveConfiguration(state *pluginstate.FamilyState, request ReconcileRequest, installed InstalledSlot) {
	state.ActiveConfigurationRevision = request.ConfigurationRevision
	state.ActiveArtifactID, state.ActiveArtifactSHA256, state.ActiveManifestDigest = request.ArtifactID, installed.ArtifactSHA256, installed.ManifestDigest
	state.ActiveInstanceIDs = append([]string(nil), request.InstanceIDs...)
	state.ActiveInstanceDescriptors = stateDescriptors(request.InstanceDescriptors)
	state.ActiveTemplateIDs = append([]string(nil), request.TemplateIDs...)
	state.ActiveTemplateConfigurations = cloneTemplateConfigurations(request.TemplateConfigurations)
	state.ActiveTemplateLeaseCommandID = request.TemplateLeaseCommandID
	state.ActiveTemplateReferences = stateTemplateReferences(request.TemplateReferences)
	state.ActiveInstanceTemplateRefs = stateInstanceTemplateReferences(request.InstanceTemplateRefs)
	state.ActiveCredentialsComplete = request.CredentialsComplete
	sort.Strings(state.ActiveInstanceIDs)
	sort.Strings(state.ActiveTemplateIDs)
	state.BoundInstanceCount = uint32(len(state.ActiveInstanceIDs))
}

func requestFromActiveState(state pluginstate.FamilyState) ReconcileRequest {
	artifactDigest, _ := hex.DecodeString(state.ActiveArtifactSHA256)
	manifestDigest, _ := hex.DecodeString(state.ActiveManifestDigest)
	return ReconcileRequest{AssignmentID: state.AssignmentID, PluginID: state.PluginID, DatabaseFamily: state.DatabaseFamily, DesiredVersion: state.InstalledVersion, DesiredState: DesiredRunning, ArtifactID: state.ActiveArtifactID, ArtifactSHA256: artifactDigest, ManifestDigest: manifestDigest, ConfigurationRevision: state.ActiveConfigurationRevision, OperationRevision: state.ObservedOperationRevision, InstanceIDs: append([]string(nil), state.ActiveInstanceIDs...), InstanceDescriptors: supervisorDescriptors(state.ActiveInstanceDescriptors), TemplateIDs: append([]string(nil), state.ActiveTemplateIDs...), TemplateConfigurations: cloneTemplateConfigurations(state.ActiveTemplateConfigurations), TemplateLeaseCommandID: state.ActiveTemplateLeaseCommandID, TemplateReferences: supervisorTemplateReferences(state.ActiveTemplateReferences), InstanceTemplateRefs: supervisorInstanceTemplateReferences(state.ActiveInstanceTemplateRefs), CredentialsComplete: state.ActiveCredentialsComplete}
}

func stateDescriptors(values []InstanceDescriptor) []pluginstate.InstanceDescriptor {
	result := make([]pluginstate.InstanceDescriptor, len(values))
	for index, value := range values {
		result[index] = pluginstate.InstanceDescriptor{InstanceID: value.InstanceID, DatabaseVariant: value.DatabaseVariant, Endpoint: value.Endpoint, UnixSocket: value.UnixSocket}
	}
	return result
}

func stateTemplateReferences(values []TemplateReference) []pluginstate.TemplateReference {
	result := make([]pluginstate.TemplateReference, len(values))
	for index, value := range values {
		result[index] = pluginstate.TemplateReference{TemplateID: value.TemplateID, RevisionID: value.RevisionID, QueryDigest: hex.EncodeToString(value.QueryDigest), TimeoutSeconds: value.TimeoutSeconds, MaxRows: value.MaxRows, MaxColumns: value.MaxColumns, CardinalityLimit: value.CardinalityLimit}
	}
	return result
}
func stateInstanceTemplateReferences(values []InstanceTemplateReferences) []pluginstate.InstanceTemplateReferences {
	result := make([]pluginstate.InstanceTemplateReferences, len(values))
	for index, value := range values {
		result[index].InstanceID = value.InstanceID
		result[index].Templates = stateTemplateReferences(value.Templates)
	}
	return result
}
func supervisorTemplateReferences(values []pluginstate.TemplateReference) []TemplateReference {
	result := make([]TemplateReference, len(values))
	for index, value := range values {
		digest, _ := hex.DecodeString(value.QueryDigest)
		result[index] = TemplateReference{TemplateID: value.TemplateID, RevisionID: value.RevisionID, QueryDigest: digest, TimeoutSeconds: value.TimeoutSeconds, MaxRows: value.MaxRows, MaxColumns: value.MaxColumns, CardinalityLimit: value.CardinalityLimit}
	}
	return result
}
func supervisorInstanceTemplateReferences(values []pluginstate.InstanceTemplateReferences) []InstanceTemplateReferences {
	result := make([]InstanceTemplateReferences, len(values))
	for index, value := range values {
		result[index].InstanceID = value.InstanceID
		result[index].Templates = supervisorTemplateReferences(value.Templates)
	}
	return result
}
func cloneTemplateReferences(values []TemplateReference) []TemplateReference {
	result := make([]TemplateReference, len(values))
	for index, value := range values {
		result[index] = value
		result[index].QueryDigest = append([]byte(nil), value.QueryDigest...)
	}
	return result
}
func cloneInstanceTemplateReferences(values []InstanceTemplateReferences) []InstanceTemplateReferences {
	result := make([]InstanceTemplateReferences, len(values))
	for index, value := range values {
		result[index].InstanceID = value.InstanceID
		result[index].Templates = cloneTemplateReferences(value.Templates)
	}
	return result
}

func supervisorDescriptors(values []pluginstate.InstanceDescriptor) []InstanceDescriptor {
	result := make([]InstanceDescriptor, len(values))
	for index, value := range values {
		result[index] = InstanceDescriptor{InstanceID: value.InstanceID, DatabaseVariant: value.DatabaseVariant, Endpoint: value.Endpoint, UnixSocket: value.UnixSocket}
	}
	return result
}

func identityFromRequest(request ReconcileRequest) SlotIdentity {
	return SlotIdentity{DatabaseFamily: request.DatabaseFamily, PluginID: request.PluginID, Version: request.DesiredVersion, ArtifactSHA256: hex.EncodeToString(request.ArtifactSHA256), ManifestDigest: hex.EncodeToString(request.ManifestDigest)}
}

func identityFromActiveState(state pluginstate.FamilyState) SlotIdentity {
	return SlotIdentity{DatabaseFamily: state.DatabaseFamily, PluginID: state.PluginID, Version: state.InstalledVersion, ArtifactSHA256: state.ActiveArtifactSHA256, ManifestDigest: state.ActiveManifestDigest}
}

func cloneRequest(request ReconcileRequest) ReconcileRequest {
	request.ArtifactSHA256 = append([]byte(nil), request.ArtifactSHA256...)
	request.ManifestDigest = append([]byte(nil), request.ManifestDigest...)
	request.InstanceIDs = append([]string(nil), request.InstanceIDs...)
	request.InstanceDescriptors = append([]InstanceDescriptor(nil), request.InstanceDescriptors...)
	request.TemplateIDs = append([]string(nil), request.TemplateIDs...)
	request.TemplateConfigurations = cloneTemplateConfigurations(request.TemplateConfigurations)
	request.TemplateReferences = cloneTemplateReferences(request.TemplateReferences)
	request.InstanceTemplateRefs = cloneInstanceTemplateReferences(request.InstanceTemplateRefs)
	return request
}

func healthRequest(request ReconcileRequest, installed InstalledSlot, configurationRevision uint64, runtimeDirectory string, nonce []byte, uid, gid uint32) HealthRequest {
	digest, _ := hex.DecodeString(installed.ExecutableSHA256)
	return HealthRequest{AssignmentID: request.AssignmentID, PluginID: request.PluginID, DatabaseFamily: request.DatabaseFamily, Version: installed.Version, ProtocolVersion: "v1", ExecutableSHA256: digest, ExecutablePath: installed.ExecutablePath, ConfigurationRevision: configurationRevision, OperationRevision: request.OperationRevision, InstanceIDs: append([]string(nil), request.InstanceIDs...), InstanceDescriptors: append([]InstanceDescriptor(nil), request.InstanceDescriptors...), TemplateIDs: append([]string(nil), request.TemplateIDs...), SupportedVariants: append([]string(nil), installed.SupportedVariants...), SignedCapabilities: append([]string(nil), installed.Capabilities...), MetricTemplateSchemaVersion: installed.MetricTemplateSchemaVersion, TemplateConfigurations: cloneTemplateConfigurations(request.TemplateConfigurations), TemplateLeaseCommandID: request.TemplateLeaseCommandID, TemplateReferences: cloneTemplateReferences(request.TemplateReferences), InstanceTemplateRefs: cloneInstanceTemplateReferences(request.InstanceTemplateRefs), CredentialsComplete: request.CredentialsComplete, RuntimeDirectory: runtimeDirectory, LaunchNonce: append([]byte(nil), nonce...), ExpectedUserID: uid, ExpectedGroupID: gid}
}

func cloneTemplateConfigurations(values []*pluginv1.MetricTemplateConfiguration) []*pluginv1.MetricTemplateConfiguration {
	result := make([]*pluginv1.MetricTemplateConfiguration, len(values))
	for index, value := range values {
		if value != nil {
			result[index] = proto.Clone(value).(*pluginv1.MetricTemplateConfiguration)
		}
	}
	return result
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
