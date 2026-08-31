package pluginstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"sync"
	"time"
)

const stateFileName = "plugin-state.json"

var (
	ErrInvalidState   = errors.New("plugin state is invalid")
	ErrStaleOperation = errors.New("plugin operation revision is stale")
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	resourcePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
)

type Slot string

const (
	SlotNone Slot = "none"
	SlotA    Slot = "A"
	SlotB    Slot = "B"
)

type DesiredState string

const (
	DesiredAbsent    DesiredState = "absent"
	DesiredInstalled DesiredState = "installed"
	DesiredRunning   DesiredState = "running"
	DesiredStopped   DesiredState = "stopped"
)

type ProcessState string

const (
	ProcessAbsent            ProcessState = "absent"
	ProcessDownloading       ProcessState = "downloading"
	ProcessVerifying         ProcessState = "verifying"
	ProcessInstalled         ProcessState = "installed"
	ProcessStarting          ProcessState = "starting"
	ProcessHandshaking       ProcessState = "handshaking"
	ProcessRunning           ProcessState = "running"
	ProcessDegraded          ProcessState = "degraded"
	ProcessRestarting        ProcessState = "restarting"
	ProcessDraining          ProcessState = "draining"
	ProcessStopped           ProcessState = "stopped"
	ProcessUninstalling      ProcessState = "uninstalling"
	ProcessDownloadFailed    ProcessState = "download_failed"
	ProcessSignatureRejected ProcessState = "signature_rejected"
	ProcessManifestRejected  ProcessState = "manifest_rejected"
	ProcessPlatformMismatch  ProcessState = "platform_mismatch"
	ProcessStartFailed       ProcessState = "start_failed"
	ProcessHandshakeFailed   ProcessState = "handshake_failed"
	ProcessUpgrading         ProcessState = "upgrading"
	ProcessRollback          ProcessState = "rollback"
	ProcessCircuitOpen       ProcessState = "circuit_open"
)

type HealthState string

const (
	HealthUnknown   HealthState = "unknown"
	HealthHealthy   HealthState = "healthy"
	HealthDegraded  HealthState = "degraded"
	HealthUnhealthy HealthState = "unhealthy"
)

type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

type SlotState struct {
	Version        string    `json:"version"`
	ArtifactSHA256 string    `json:"artifact_sha256"`
	ManifestDigest string    `json:"manifest_digest"`
	CompletedAt    time.Time `json:"completed_at"`
}

// FamilyState contains only durable, non-secret reconciliation facts. Lease
// URLs, request headers, credentials, command tokens and plugin output never
// cross this persistence boundary.
type FamilyState struct {
	StateRevision               uint64             `json:"state_revision"`
	AssignmentID                string             `json:"assignment_id"`
	PluginID                    string             `json:"plugin_id"`
	DatabaseFamily              string             `json:"database_family"`
	InstalledVersion            string             `json:"installed_version,omitempty"`
	ActiveSlot                  Slot               `json:"active_slot"`
	Slots                       map[Slot]SlotState `json:"slots,omitempty"`
	DesiredState                DesiredState       `json:"desired_state"`
	ProcessState                ProcessState       `json:"process_state"`
	ProcessID                   int                `json:"process_id,omitempty"`
	ProcessStartTicks           uint64             `json:"process_start_ticks,omitempty"`
	StartedAt                   time.Time          `json:"started_at,omitempty"`
	RestartCount                uint32             `json:"restart_count"`
	Failures                    []time.Time        `json:"failures,omitempty"`
	CircuitState                CircuitState       `json:"circuit_state"`
	HealthState                 HealthState        `json:"health_state"`
	ActiveConfigurationRevision uint64             `json:"active_configuration_revision"`
	ObservedOperationRevision   uint64             `json:"observed_operation_revision"`
	ObservationRevision         uint64             `json:"observation_revision"`
	BoundInstanceCount          uint32             `json:"bound_instance_count"`
	LastErrorCode               string             `json:"last_error_code,omitempty"`
}

func (state FamilyState) Validate() error {
	if !resourcePattern.MatchString(state.AssignmentID) || !identifierPattern.MatchString(state.PluginID) || !identifierPattern.MatchString(state.DatabaseFamily) ||
		state.ObservedOperationRevision == 0 || state.ActiveConfigurationRevision == 0 || state.BoundInstanceCount > 4096 || len(state.Failures) > 32 {
		return ErrInvalidState
	}
	if state.ActiveSlot != SlotNone && state.ActiveSlot != SlotA && state.ActiveSlot != SlotB {
		return ErrInvalidState
	}
	if !validDesired(state.DesiredState) || !validProcess(state.ProcessState) || !validHealth(state.HealthState) || !validCircuit(state.CircuitState) {
		return ErrInvalidState
	}
	if state.ProcessID < 0 || state.ProcessID == 0 && state.ProcessStartTicks != 0 || state.ProcessID != 0 && state.ProcessStartTicks == 0 {
		return ErrInvalidState
	}
	if state.InstalledVersion != "" && !boundedText(state.InstalledVersion, 64) || state.LastErrorCode != "" && !identifierPattern.MatchString(state.LastErrorCode) {
		return ErrInvalidState
	}
	for slot, value := range state.Slots {
		if slot != SlotA && slot != SlotB || !boundedText(value.Version, 64) || !hexDigest(value.ArtifactSHA256) || !hexDigest(value.ManifestDigest) || value.CompletedAt.IsZero() {
			return ErrInvalidState
		}
	}
	for _, failure := range state.Failures {
		if failure.IsZero() {
			return ErrInvalidState
		}
	}
	return nil
}

type diskSnapshot struct {
	Revision uint64                 `json:"revision"`
	Families map[string]FamilyState `json:"families"`
}

type FileStore struct {
	mu       sync.RWMutex
	root     string
	revision uint64
	families map[string]FamilyState
}

func NewFileStore(root string) (*FileStore, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrInvalidState
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidState
	}
	store := &FileStore{root: root, families: map[string]FamilyState{}}
	valid := 0
	var invalid error
	for _, suffix := range []string{".a", ".b"} {
		snapshot, exists, readErr := readSnapshot(filepath.Join(root, stateFileName+suffix))
		if readErr != nil {
			invalid = readErr
			continue
		}
		if exists {
			valid++
			if snapshot.Revision > store.revision {
				store.revision = snapshot.Revision
				store.families = cloneFamilies(snapshot.Families)
			}
		}
	}
	if valid == 0 && invalid != nil {
		return nil, invalid
	}
	return store, nil
}

func (store *FileStore) Get(family string) (FamilyState, bool) {
	if store == nil {
		return FamilyState{}, false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	state, ok := store.families[family]
	return cloneFamily(state), ok
}

func (store *FileStore) List() []FamilyState {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	keys := make([]string, 0, len(store.families))
	for key := range store.families {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]FamilyState, 0, len(keys))
	for _, key := range keys {
		result = append(result, cloneFamily(store.families[key]))
	}
	return result
}

func (store *FileStore) Put(ctx context.Context, state FamilyState) (FamilyState, error) {
	if store == nil || ctx == nil || ctx.Err() != nil || state.Validate() != nil {
		return FamilyState{}, ErrInvalidState
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if current, ok := store.families[state.DatabaseFamily]; ok && state.ObservedOperationRevision < current.ObservedOperationRevision {
		return FamilyState{}, ErrStaleOperation
	}
	state.StateRevision = store.revision + 1
	if state.StateRevision == 0 {
		return FamilyState{}, ErrInvalidState
	}
	next := cloneFamilies(store.families)
	next[state.DatabaseFamily] = cloneFamily(state)
	snapshot := diskSnapshot{Revision: state.StateRevision, Families: next}
	if err := store.writeSnapshot(ctx, snapshot); err != nil {
		return FamilyState{}, err
	}
	store.revision = snapshot.Revision
	store.families = next
	return cloneFamily(state), nil
}

func (store *FileStore) Delete(ctx context.Context, family string, operationRevision uint64) error {
	if store == nil || ctx == nil || ctx.Err() != nil || !identifierPattern.MatchString(family) || operationRevision == 0 {
		return ErrInvalidState
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, ok := store.families[family]
	if !ok {
		return nil
	}
	if operationRevision < current.ObservedOperationRevision {
		return ErrStaleOperation
	}
	next := cloneFamilies(store.families)
	delete(next, family)
	snapshot := diskSnapshot{Revision: store.revision + 1, Families: next}
	if snapshot.Revision == 0 {
		return ErrInvalidState
	}
	if err := store.writeSnapshot(ctx, snapshot); err != nil {
		return err
	}
	store.revision = snapshot.Revision
	store.families = next
	return nil
}

func (store *FileStore) writeSnapshot(ctx context.Context, snapshot diskSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > 1<<20 {
		return ErrInvalidState
	}
	suffix := ".a"
	if snapshot.Revision%2 == 0 {
		suffix = ".b"
	}
	target := filepath.Join(store.root, stateFileName+suffix)
	temporary := target + ".tmp"
	if err := removeRegularIfExists(temporary); err != nil {
		return err
	}
	handle, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := handle.Write(encoded)
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := removeRegularIfExists(target); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, target); err != nil {
		return err
	}
	return syncDirectory(store.root)
}

func readSnapshot(path string) (diskSnapshot, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return diskSnapshot{}, false, nil
	}
	if err != nil {
		return diskSnapshot{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 1<<20 {
		return diskSnapshot{}, false, ErrInvalidState
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return diskSnapshot{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var snapshot diskSnapshot
	if decoder.Decode(&snapshot) != nil || ensureEOF(decoder) != nil || snapshot.Revision == 0 || snapshot.Families == nil {
		return diskSnapshot{}, false, ErrInvalidState
	}
	for family, state := range snapshot.Families {
		if family != state.DatabaseFamily || state.StateRevision == 0 || state.StateRevision > snapshot.Revision || state.Validate() != nil {
			return diskSnapshot{}, false, ErrInvalidState
		}
	}
	return snapshot, true, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidState
	}
	return nil
}

func cloneFamily(state FamilyState) FamilyState {
	state.Failures = append([]time.Time(nil), state.Failures...)
	if state.Slots != nil {
		state.Slots = make(map[Slot]SlotState, len(state.Slots))
		for slot, value := range state.Slots {
			state.Slots[slot] = value
		}
	}
	return state
}

func cloneFamilies(values map[string]FamilyState) map[string]FamilyState {
	result := make(map[string]FamilyState, len(values))
	for key, value := range values {
		result[key] = cloneFamily(value)
	}
	return result
}

func removeRegularIfExists(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidState
	}
	return os.Remove(path)
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func validDesired(value DesiredState) bool {
	return value == DesiredAbsent || value == DesiredInstalled || value == DesiredRunning || value == DesiredStopped
}

func validProcess(value ProcessState) bool {
	switch value {
	case ProcessAbsent, ProcessDownloading, ProcessVerifying, ProcessInstalled, ProcessStarting, ProcessHandshaking, ProcessRunning, ProcessDegraded, ProcessRestarting, ProcessDraining, ProcessStopped, ProcessUninstalling, ProcessDownloadFailed, ProcessSignatureRejected, ProcessManifestRejected, ProcessPlatformMismatch, ProcessStartFailed, ProcessHandshakeFailed, ProcessUpgrading, ProcessRollback, ProcessCircuitOpen:
		return true
	default:
		return false
	}
}

func validHealth(value HealthState) bool {
	return value == HealthUnknown || value == HealthHealthy || value == HealthDegraded || value == HealthUnhealthy
}

func validCircuit(value CircuitState) bool {
	return value == CircuitClosed || value == CircuitOpen || value == CircuitHalfOpen
}

func boundedText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && value == filepath.Base(value) && !bytes.ContainsAny([]byte(value), "\x00\r\n\t")
}

func hexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}
