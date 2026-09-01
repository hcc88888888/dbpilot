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
	"strings"
	"sync"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"google.golang.org/protobuf/proto"
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

type InstanceDescriptor struct {
	InstanceID      string `json:"instance_id"`
	DatabaseVariant string `json:"database_variant"`
	Endpoint        string `json:"endpoint,omitempty"`
	UnixSocket      string `json:"unix_socket,omitempty"`
}

type TemplateReference struct {
	TemplateID       string `json:"template_id"`
	RevisionID       string `json:"revision_id"`
	QueryDigest      string `json:"query_digest"`
	TimeoutSeconds   uint32 `json:"timeout_seconds"`
	MaxRows          uint32 `json:"max_rows"`
	MaxColumns       uint32 `json:"max_columns"`
	CardinalityLimit uint32 `json:"cardinality_limit"`
}

type InstanceTemplateReferences struct {
	InstanceID string              `json:"instance_id"`
	Templates  []TemplateReference `json:"templates"`
}

// FamilyState contains only durable, non-secret reconciliation facts. Lease
// URLs, request headers, credentials, command tokens and plugin output never
// cross this persistence boundary.
type FamilyState struct {
	StateRevision                 uint64                                  `json:"state_revision"`
	AssignmentID                  string                                  `json:"assignment_id"`
	PluginID                      string                                  `json:"plugin_id"`
	DatabaseFamily                string                                  `json:"database_family"`
	InstalledVersion              string                                  `json:"installed_version,omitempty"`
	ActiveArtifactID              string                                  `json:"active_artifact_id,omitempty"`
	ActiveArtifactSHA256          string                                  `json:"active_artifact_sha256,omitempty"`
	ActiveManifestDigest          string                                  `json:"active_manifest_digest,omitempty"`
	ActiveInstanceIDs             []string                                `json:"active_instance_ids,omitempty"`
	ActiveInstanceDescriptors     []InstanceDescriptor                    `json:"active_instance_descriptors,omitempty"`
	ActiveTemplateIDs             []string                                `json:"active_template_ids,omitempty"`
	ActiveTemplateConfigurations  []*pluginv1.MetricTemplateConfiguration `json:"active_template_configurations,omitempty"`
	ActiveTemplateLeaseCommandID  string                                  `json:"active_template_lease_command_id,omitempty"`
	ActiveTemplateReferences      []TemplateReference                     `json:"active_template_references,omitempty"`
	ActiveInstanceTemplateRefs    []InstanceTemplateReferences            `json:"active_instance_template_refs,omitempty"`
	ActiveCredentialsComplete     bool                                    `json:"active_credentials_complete,omitempty"`
	DesiredVersion                string                                  `json:"desired_version,omitempty"`
	DesiredArtifactID             string                                  `json:"desired_artifact_id,omitempty"`
	DesiredArtifactSHA256         string                                  `json:"desired_artifact_sha256,omitempty"`
	DesiredManifestDigest         string                                  `json:"desired_manifest_digest,omitempty"`
	DesiredConfigurationRevision  uint64                                  `json:"desired_configuration_revision"`
	DesiredInstanceIDs            []string                                `json:"desired_instance_ids,omitempty"`
	DesiredInstanceDescriptors    []InstanceDescriptor                    `json:"desired_instance_descriptors,omitempty"`
	DesiredTemplateIDs            []string                                `json:"desired_template_ids,omitempty"`
	DesiredTemplateConfigurations []*pluginv1.MetricTemplateConfiguration `json:"desired_template_configurations,omitempty"`
	DesiredTemplateLeaseCommandID string                                  `json:"desired_template_lease_command_id,omitempty"`
	DesiredTemplateReferences     []TemplateReference                     `json:"desired_template_references,omitempty"`
	DesiredInstanceTemplateRefs   []InstanceTemplateReferences            `json:"desired_instance_template_refs,omitempty"`
	DesiredCredentialsComplete    bool                                    `json:"desired_credentials_complete,omitempty"`
	RequestFingerprint            string                                  `json:"request_fingerprint"`
	ActiveSlot                    Slot                                    `json:"active_slot"`
	Slots                         map[Slot]SlotState                      `json:"slots,omitempty"`
	DesiredState                  DesiredState                            `json:"desired_state"`
	ProcessState                  ProcessState                            `json:"process_state"`
	ProcessID                     int                                     `json:"process_id,omitempty"`
	ProcessStartTicks             uint64                                  `json:"process_start_ticks,omitempty"`
	StartedAt                     time.Time                               `json:"started_at,omitempty"`
	RestartCount                  uint32                                  `json:"restart_count"`
	Failures                      []time.Time                             `json:"failures,omitempty"`
	CircuitState                  CircuitState                            `json:"circuit_state"`
	HealthState                   HealthState                             `json:"health_state"`
	ActiveConfigurationRevision   uint64                                  `json:"active_configuration_revision"`
	ObservedOperationRevision     uint64                                  `json:"observed_operation_revision"`
	ObservationRevision           uint64                                  `json:"observation_revision"`
	BoundInstanceCount            uint32                                  `json:"bound_instance_count"`
	LastErrorCode                 string                                  `json:"last_error_code,omitempty"`
}

func (state FamilyState) Validate() error {
	if !resourcePattern.MatchString(state.AssignmentID) || !identifierPattern.MatchString(state.PluginID) || !identifierPattern.MatchString(state.DatabaseFamily) ||
		state.ObservedOperationRevision == 0 || state.ActiveConfigurationRevision == 0 || state.DesiredConfigurationRevision == 0 || state.BoundInstanceCount > 128 || len(state.Failures) > 32 || !hexDigest(state.RequestFingerprint) || len(state.ActiveInstanceIDs) > 128 || len(state.ActiveTemplateIDs) > 128 || len(state.DesiredInstanceIDs) > 128 || len(state.DesiredTemplateIDs) > 128 {
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
	if state.InstalledVersion != "" && !boundedText(state.InstalledVersion, 64) || state.DesiredVersion != "" && !boundedText(state.DesiredVersion, 64) || state.LastErrorCode != "" && !identifierPattern.MatchString(state.LastErrorCode) || int(state.BoundInstanceCount) != len(state.ActiveInstanceIDs) {
		return ErrInvalidState
	}
	if !validOptionalArtifact(state.ActiveArtifactID, state.ActiveArtifactSHA256, state.ActiveManifestDigest) || !validOptionalArtifact(state.DesiredArtifactID, state.DesiredArtifactSHA256, state.DesiredManifestDigest) || !validIDs(state.ActiveInstanceIDs) || !validIDs(state.ActiveTemplateIDs) || !validIDs(state.DesiredInstanceIDs) || !validIDs(state.DesiredTemplateIDs) || !validDescriptors(state.ActiveInstanceIDs, state.ActiveInstanceDescriptors) || !validDescriptors(state.DesiredInstanceIDs, state.DesiredInstanceDescriptors) || !validTemplateProjection(state.ActiveTemplateIDs, state.ActiveTemplateConfigurations) || !validTemplateProjection(state.DesiredTemplateIDs, state.DesiredTemplateConfigurations) || !validPublicTemplateReferences(state.ActiveTemplateIDs, state.ActiveInstanceIDs, state.ActiveTemplateLeaseCommandID, state.ActiveTemplateReferences, state.ActiveInstanceTemplateRefs) || !validPublicTemplateReferences(state.DesiredTemplateIDs, state.DesiredInstanceIDs, state.DesiredTemplateLeaseCommandID, state.DesiredTemplateReferences, state.DesiredInstanceTemplateRefs) || len(state.ActiveTemplateReferences) > 0 && len(state.ActiveTemplateConfigurations) > 0 || len(state.DesiredTemplateReferences) > 0 && len(state.DesiredTemplateConfigurations) > 0 {
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
	Revision   uint64                 `json:"revision"`
	ObservedAt time.Time              `json:"observed_at"`
	Families   map[string]FamilyState `json:"families"`
}

type FileStore struct {
	mu         sync.RWMutex
	root       string
	revision   uint64
	observedAt time.Time
	families   map[string]FamilyState
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
				store.observedAt = snapshot.ObservedAt
				store.families = cloneFamilies(snapshot.Families)
			}
		}
	}
	if valid == 0 && invalid != nil {
		return nil, invalid
	}
	return store, nil
}

func (store *FileStore) Snapshot() (uint64, time.Time, []FamilyState) {
	if store == nil {
		return 0, time.Time{}, nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.revision, store.observedAt, sortedFamilies(store.families)
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
	snapshot := diskSnapshot{Revision: state.StateRevision, ObservedAt: time.Now().UTC(), Families: next}
	if err := store.writeSnapshot(ctx, snapshot); err != nil {
		return FamilyState{}, err
	}
	store.revision = snapshot.Revision
	store.observedAt = snapshot.ObservedAt
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
	snapshot := diskSnapshot{Revision: store.revision + 1, ObservedAt: time.Now().UTC(), Families: next}
	if snapshot.Revision == 0 {
		return ErrInvalidState
	}
	if err := store.writeSnapshot(ctx, snapshot); err != nil {
		return err
	}
	store.revision = snapshot.Revision
	store.observedAt = snapshot.ObservedAt
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
	if decoder.Decode(&snapshot) != nil || ensureEOF(decoder) != nil || snapshot.Revision == 0 || snapshot.Families == nil || snapshot.ObservedAt.IsZero() {
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
	state.ActiveInstanceIDs = append([]string(nil), state.ActiveInstanceIDs...)
	state.ActiveInstanceDescriptors = append([]InstanceDescriptor(nil), state.ActiveInstanceDescriptors...)
	state.ActiveTemplateIDs = append([]string(nil), state.ActiveTemplateIDs...)
	state.ActiveTemplateConfigurations = cloneTemplates(state.ActiveTemplateConfigurations)
	state.ActiveTemplateReferences = append([]TemplateReference(nil), state.ActiveTemplateReferences...)
	state.ActiveInstanceTemplateRefs = cloneInstanceTemplateRefs(state.ActiveInstanceTemplateRefs)
	state.DesiredInstanceIDs = append([]string(nil), state.DesiredInstanceIDs...)
	state.DesiredInstanceDescriptors = append([]InstanceDescriptor(nil), state.DesiredInstanceDescriptors...)
	state.DesiredTemplateIDs = append([]string(nil), state.DesiredTemplateIDs...)
	state.DesiredTemplateConfigurations = cloneTemplates(state.DesiredTemplateConfigurations)
	state.DesiredTemplateReferences = append([]TemplateReference(nil), state.DesiredTemplateReferences...)
	state.DesiredInstanceTemplateRefs = cloneInstanceTemplateRefs(state.DesiredInstanceTemplateRefs)
	if state.Slots != nil {
		state.Slots = make(map[Slot]SlotState, len(state.Slots))
		for slot, value := range state.Slots {
			state.Slots[slot] = value
		}
	}
	return state
}

func sortedFamilies(values map[string]FamilyState) []FamilyState {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]FamilyState, 0, len(keys))
	for _, key := range keys {
		result = append(result, cloneFamily(values[key]))
	}
	return result
}

func validOptionalArtifact(id, artifactDigest, manifestDigest string) bool {
	return id == "" && artifactDigest == "" && manifestDigest == "" || resourcePattern.MatchString(id) && hexDigest(artifactDigest) && hexDigest(manifestDigest)
}

func validIDs(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if !resourcePattern.MatchString(value) {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validDescriptors(instanceIDs []string, values []InstanceDescriptor) bool {
	// Empty is retained as an explicit legacy/unavailable projection. New
	// reconciliations persist the complete set and can therefore restart
	// without a Server replay.
	if len(values) == 0 {
		return true
	}
	if len(values) != len(instanceIDs) || len(values) > 128 {
		return false
	}
	allowed, seen := map[string]struct{}{}, map[string]struct{}{}
	for _, id := range instanceIDs {
		allowed[id] = struct{}{}
	}
	for _, value := range values {
		if _, ok := allowed[value.InstanceID]; !ok || !resourcePattern.MatchString(value.InstanceID) || !identifierPattern.MatchString(value.DatabaseVariant) || (value.Endpoint == "") == (value.UnixSocket == "") || len(value.Endpoint) > 512 || len(value.UnixSocket) > 512 {
			return false
		}
		if _, duplicate := seen[value.InstanceID]; duplicate {
			return false
		}
		seen[value.InstanceID] = struct{}{}
	}
	return true
}

func validPublicTemplateReferences(templateIDs, instanceIDs []string, commandID string, references []TemplateReference, instances []InstanceTemplateReferences) bool {
	if len(references) == 0 {
		return commandID == "" && len(instances) == 0
	}
	if !resourcePattern.MatchString(commandID) || len(references) != len(templateIDs) || len(references) > 128 || len(instances) != len(instanceIDs) {
		return false
	}
	byRevision, byTemplate := map[string]TemplateReference{}, map[string]struct{}{}
	for _, reference := range references {
		if !resourcePattern.MatchString(reference.TemplateID) || !resourcePattern.MatchString(reference.RevisionID) || !hexDigest(reference.QueryDigest) || reference.TimeoutSeconds == 0 || reference.TimeoutSeconds > 30 || reference.MaxRows == 0 || reference.MaxRows > 100 || reference.MaxColumns == 0 || reference.MaxColumns > 32 || reference.CardinalityLimit == 0 || reference.CardinalityLimit > 10000 {
			return false
		}
		if _, duplicate := byRevision[reference.RevisionID]; duplicate {
			return false
		}
		if _, duplicate := byTemplate[reference.TemplateID]; duplicate {
			return false
		}
		byRevision[reference.RevisionID], byTemplate[reference.TemplateID] = reference, struct{}{}
	}
	for _, templateID := range templateIDs {
		if _, ok := byTemplate[templateID]; !ok {
			return false
		}
	}
	allowedInstances, seenInstances, used := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, instanceID := range instanceIDs {
		allowedInstances[instanceID] = struct{}{}
	}
	for _, instance := range instances {
		if _, ok := allowedInstances[instance.InstanceID]; !ok {
			return false
		}
		if _, duplicate := seenInstances[instance.InstanceID]; duplicate {
			return false
		}
		seenInstances[instance.InstanceID] = struct{}{}
		seenTemplates := map[string]struct{}{}
		for _, reference := range instance.Templates {
			authoritative, ok := byRevision[reference.RevisionID]
			if !ok || !samePublicTemplateReference(authoritative, reference) {
				return false
			}
			if _, duplicate := seenTemplates[reference.TemplateID]; duplicate {
				return false
			}
			seenTemplates[reference.TemplateID], used[reference.RevisionID] = struct{}{}, struct{}{}
		}
	}
	return len(used) == len(byRevision)
}

func samePublicTemplateReference(left, right TemplateReference) bool {
	return left.TemplateID == right.TemplateID && left.RevisionID == right.RevisionID && left.QueryDigest == right.QueryDigest && left.TimeoutSeconds == right.TimeoutSeconds && left.MaxRows == right.MaxRows && left.MaxColumns == right.MaxColumns && left.CardinalityLimit == right.CardinalityLimit
}

func cloneInstanceTemplateRefs(values []InstanceTemplateReferences) []InstanceTemplateReferences {
	result := make([]InstanceTemplateReferences, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Templates = append([]TemplateReference(nil), value.Templates...)
	}
	return result
}

func validTemplateProjection(templateIDs []string, values []*pluginv1.MetricTemplateConfiguration) bool {
	if len(values) == 0 {
		return true
	}
	if len(values) != len(templateIDs) || len(values) > 128 {
		return false
	}
	allowed, seen := map[string]struct{}{}, map[string]struct{}{}
	totalBytes := 0
	for _, id := range templateIDs {
		allowed[id] = struct{}{}
	}
	for _, value := range values {
		totalBytes += proto.Size(value)
		if value == nil || value.GetRevision() == 0 || len(value.GetQueryDigest()) != 32 || value.GetQueryKind() != "sql" || value.GetReadOnlyStatement() == "" || len(value.GetReadOnlyStatement()) > 64<<10 || strings.ContainsAny(value.GetReadOnlyStatement(), "\x00\r") || value.GetCollectionIntervalSeconds() < 10 || value.GetTimeoutSeconds() == 0 || value.GetTimeoutSeconds() > 30 || value.GetMaxRows() == 0 || value.GetMaxRows() > 100 || value.GetMaxColumns() == 0 || value.GetMaxColumns() > 32 || len(value.GetValueMappings()) == 0 || len(value.GetValueMappings()) > 32 || len(value.GetLabelMappings()) > 16 {
			return false
		}
		if totalBytes > 256<<10 {
			return false
		}
		if _, ok := allowed[value.GetTemplateId()]; !ok {
			return false
		}
		if _, duplicate := seen[value.GetTemplateId()]; duplicate {
			return false
		}
		seen[value.GetTemplateId()] = struct{}{}
	}
	return true
}

func cloneTemplates(values []*pluginv1.MetricTemplateConfiguration) []*pluginv1.MetricTemplateConfiguration {
	result := make([]*pluginv1.MetricTemplateConfiguration, len(values))
	for index, value := range values {
		if value != nil {
			result[index] = proto.Clone(value).(*pluginv1.MetricTemplateConfiguration)
		}
	}
	return result
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
