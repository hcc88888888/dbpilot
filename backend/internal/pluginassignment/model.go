// Package pluginassignment owns the desired and observed state for one
// database-plugin process per Agent and database family.
package pluginassignment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"dbpilot.local/platform/internal/platformscope"
)

var (
	ErrInvalid            = errors.New("invalid plugin assignment")
	ErrNotFound           = errors.New("plugin assignment not found")
	ErrConflict           = errors.New("plugin assignment conflict")
	ErrPrecondition       = errors.New("plugin assignment precondition failed")
	ErrVersionUnavailable = errors.New("plugin version is not available")
	ErrVersionRevoked     = errors.New("plugin version is revoked")
	ErrStaleObservation   = errors.New("plugin observation is stale")
	ErrClaimLost          = errors.New("plugin reconciliation claim was lost")
)

const DefaultListLimit = 50

var (
	idPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	familyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	pluginIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
	digestPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	fingerprintPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	cursorPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{1,512}$`)
)

type DesiredState string

const (
	DesiredAbsent    DesiredState = "absent"
	DesiredInstalled DesiredState = "installed"
	DesiredRunning   DesiredState = "running"
	DesiredStopped   DesiredState = "stopped"
)

func (value DesiredState) Valid() bool {
	return value == DesiredAbsent || value == DesiredInstalled || value == DesiredRunning || value == DesiredStopped
}

type ReconcileState string

const (
	ReconcilePending   ReconcileState = "pending"
	ReconcileConverged ReconcileState = "converged"
	ReconcileBlocked   ReconcileState = "blocked"
	ReconcileConflict  ReconcileState = "state_conflict"
)

func (value ReconcileState) Valid() bool {
	return value == ReconcilePending || value == ReconcileConverged || value == ReconcileBlocked || value == ReconcileConflict
}

type ProcessState string

const (
	ProcessAbsent      ProcessState = "absent"
	ProcessInstalled   ProcessState = "installed"
	ProcessRunning     ProcessState = "running"
	ProcessDegraded    ProcessState = "degraded"
	ProcessStopped     ProcessState = "stopped"
	ProcessCircuitOpen ProcessState = "circuit_open"
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

type ActiveSlot string

const (
	SlotNone ActiveSlot = "none"
	SlotA    ActiveSlot = "a"
	SlotB    ActiveSlot = "b"
)

type ObservedState struct {
	AssignmentID                string
	PluginID                    string
	DatabaseFamily              string
	InstalledVersion            string
	ActiveSlot                  ActiveSlot
	ProcessState                ProcessState
	PID                         uint32
	StartedAt                   *time.Time
	Health                      HealthState
	RestartCount                uint32
	CircuitState                CircuitState
	BoundInstanceCount          uint32
	ActiveConfigurationRevision uint64
	ObservedOperationRevision   uint64
	LastErrorCode               string
	ObservationRevision         uint64
	ObservedAt                  time.Time
	Digest                      string
}

func (value ObservedState) Validate() error {
	if !idPattern.MatchString(value.AssignmentID) || !pluginIDPattern.MatchString(value.PluginID) || !familyPattern.MatchString(value.DatabaseFamily) || value.InstalledVersion != "" && !versionPattern.MatchString(value.InstalledVersion) || !validProcessState(value.ProcessState) || !validHealth(value.Health) || !validCircuit(value.CircuitState) || !validSlot(value.ActiveSlot) || value.BoundInstanceCount > 1000 || value.ObservationRevision == 0 || !validUTC(value.ObservedAt) || value.Digest != "" && !digestPattern.MatchString(value.Digest) || value.LastErrorCode != "" && !pluginIDPattern.MatchString(value.LastErrorCode) {
		return ErrInvalid
	}
	if value.StartedAt != nil && !validUTC(*value.StartedAt) {
		return ErrInvalid
	}
	return nil
}

type Assignment struct {
	ID                    string
	Scope                 platformscope.Scope
	HostID                string
	AgentID               string
	PluginID              string
	DatabaseFamily        string
	DesiredVersionID      string
	DesiredVersion        string
	ArtifactID            string
	ArtifactSHA256        string
	ManifestDigest        string
	DesiredState          DesiredState
	ConfigurationRevision uint64
	OperationRevision     uint64
	RolloutPercentage     int
	InstanceIDs           []string
	TemplateRevisionIDs   []string
	ReconcileState        ReconcileState
	BlockedReason         string
	Revision              uint64
	CreatedAt             time.Time
	UpdatedAt             time.Time
	Observed              *ObservedState
}

func NormalizeAssignment(value Assignment) (Assignment, error) {
	value.InstanceIDs = sortedUnique(value.InstanceIDs)
	value.TemplateRevisionIDs = sortedUnique(value.TemplateRevisionIDs)
	if value.Validate() != nil {
		return Assignment{}, ErrInvalid
	}
	return value, nil
}

func (value Assignment) Validate() error {
	if !idPattern.MatchString(value.ID) || value.Scope.Validate() != nil || !idPattern.MatchString(value.HostID) || !idPattern.MatchString(value.AgentID) || !pluginIDPattern.MatchString(value.PluginID) || !familyPattern.MatchString(value.DatabaseFamily) || !idPattern.MatchString(value.DesiredVersionID) || !versionPattern.MatchString(value.DesiredVersion) || !idPattern.MatchString(value.ArtifactID) || !digestPattern.MatchString(value.ArtifactSHA256) || !digestPattern.MatchString(value.ManifestDigest) || !value.DesiredState.Valid() || value.ConfigurationRevision == 0 || value.OperationRevision == 0 || value.RolloutPercentage < 1 || value.RolloutPercentage > 100 || len(value.InstanceIDs) > 1000 || (len(value.InstanceIDs) == 0 && value.DesiredState != DesiredAbsent) || len(value.TemplateRevisionIDs) > 1000 || !value.ReconcileState.Valid() || value.BlockedReason != "" && !pluginIDPattern.MatchString(value.BlockedReason) || value.Revision == 0 || !validUTC(value.CreatedAt) || !validUTC(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return ErrInvalid
	}
	if !strictSortedIdentifiers(value.InstanceIDs) || !strictSortedIdentifiers(value.TemplateRevisionIDs) {
		return ErrInvalid
	}
	if value.ReconcileState == ReconcileBlocked && value.BlockedReason == "" || value.ReconcileState != ReconcileBlocked && value.BlockedReason != "" {
		return ErrInvalid
	}
	if value.Observed != nil {
		if value.Observed.Validate() != nil || value.Observed.AssignmentID != value.ID || value.Observed.PluginID != value.PluginID || value.Observed.DatabaseFamily != value.DatabaseFamily {
			return ErrInvalid
		}
	}
	return nil
}

func (value Assignment) ETag() string {
	if value.Revision == 0 {
		return ""
	}
	return `"` + strconv.FormatUint(value.Revision, 10) + `"`
}

func (value Assignment) HasObservedRevisionConflict() bool {
	return value.Observed != nil && (value.Observed.ObservedOperationRevision > value.OperationRevision || value.Observed.ActiveConfigurationRevision > value.ConfigurationRevision)
}

func (value Assignment) NeedsReconcile() bool {
	if value.ReconcileState == ReconcileBlocked || value.HasObservedRevisionConflict() {
		return false
	}
	if value.Observed == nil || value.Observed.ObservedOperationRevision < value.OperationRevision || value.Observed.ActiveConfigurationRevision < value.ConfigurationRevision {
		return true
	}
	if value.Observed.ObservedOperationRevision != value.OperationRevision || value.Observed.ActiveConfigurationRevision != value.ConfigurationRevision || value.Observed.InstalledVersion != value.DesiredVersion || int(value.Observed.BoundInstanceCount) != len(value.InstanceIDs) {
		return true
	}
	switch value.DesiredState {
	case DesiredAbsent:
		return value.Observed.ProcessState != ProcessAbsent
	case DesiredInstalled:
		return value.Observed.ProcessState != ProcessInstalled && value.Observed.ProcessState != ProcessStopped && value.Observed.ProcessState != ProcessRunning && value.Observed.ProcessState != ProcessDegraded
	case DesiredRunning:
		return value.Observed.ProcessState != ProcessRunning && value.Observed.ProcessState != ProcessDegraded
	case DesiredStopped:
		return value.Observed.ProcessState != ProcessStopped && value.Observed.ProcessState != ProcessInstalled
	default:
		return false
	}
}

type MutationAudit struct {
	Actor              string
	OperationID        string
	IdempotencyKey     string
	RequestFingerprint string
	RequestID          string
	TraceID            string
}

func (value MutationAudit) Validate() error {
	if !bounded(value.Actor, 256, true) || !bounded(value.OperationID, 128, true) || !bounded(value.IdempotencyKey, 128, true) || !fingerprintPattern.MatchString(value.RequestFingerprint) || !bounded(value.RequestID, 256, true) || !bounded(value.TraceID, 256, false) {
		return ErrInvalid
	}
	return nil
}

type DesiredUpdate struct {
	DesiredVersion    *string
	DesiredState      *DesiredState
	RolloutPercentage *int
	Audit             MutationAudit
}

func (value DesiredUpdate) Validate() error {
	if value.DesiredVersion == nil && value.DesiredState == nil && value.RolloutPercentage == nil || value.Audit.Validate() != nil {
		return ErrInvalid
	}
	if value.DesiredVersion != nil && !versionPattern.MatchString(*value.DesiredVersion) || value.DesiredState != nil && !value.DesiredState.Valid() || value.RolloutPercentage != nil && (*value.RolloutPercentage < 1 || *value.RolloutPercentage > 100) {
		return ErrInvalid
	}
	return nil
}

type Filter struct {
	HostID         string
	PluginID       string
	AgentID        string
	DatabaseFamily string
	Cursor         string
	Limit          int
}

func (value Filter) Validate() error {
	if value.HostID != "" && !idPattern.MatchString(value.HostID) || value.PluginID != "" && !pluginIDPattern.MatchString(value.PluginID) || value.AgentID != "" && !idPattern.MatchString(value.AgentID) || value.DatabaseFamily != "" && !familyPattern.MatchString(value.DatabaseFamily) || value.Cursor != "" && !cursorPattern.MatchString(value.Cursor) || value.Limit < 0 || value.Limit > 100 {
		return ErrInvalid
	}
	return nil
}

type Page struct {
	Items      []Assignment
	NextCursor string
}

type ObservationReport struct {
	Scope               platformscope.Scope
	HostID              string
	AgentID             string
	ObservationRevision uint64
	Assignments         []ObservedState
	ObservedAt          time.Time
}

func (value ObservationReport) Validate() error {
	if value.Scope.Validate() != nil || !idPattern.MatchString(value.HostID) || !idPattern.MatchString(value.AgentID) || value.ObservationRevision == 0 || len(value.Assignments) > 128 || !validUTC(value.ObservedAt) {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(value.Assignments))
	for _, observed := range value.Assignments {
		if observed.Validate() != nil || observed.ObservationRevision != value.ObservationRevision || observed.ObservedAt.After(value.ObservedAt.Add(time.Minute)) {
			return ErrInvalid
		}
		if _, duplicate := seen[observed.AssignmentID]; duplicate {
			return ErrInvalid
		}
		seen[observed.AssignmentID] = struct{}{}
	}
	return nil
}

type ReconcileClaim struct {
	Assignment  Assignment
	Token       string
	LeasedUntil time.Time
}

func (value ReconcileClaim) Validate() error {
	if value.Assignment.Validate() != nil || !strings.HasPrefix(value.Token, "claim-") || len(value.Token) != len("claim-")+64 || !validUTC(value.LeasedUntil) {
		return ErrInvalid
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(value.Token, "claim-")); err != nil {
		return ErrInvalid
	}
	return nil
}

func DeterministicID(prefix string, values ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return prefix + hex.EncodeToString(digest[:16])
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if write == 0 || result[write-1] != value {
			result[write] = value
			write++
		}
	}
	return result[:write]
}

func strictSortedIdentifiers(values []string) bool {
	for index, value := range values {
		if !idPattern.MatchString(value) || index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func bounded(value string, maximum int, required bool) bool {
	if value == "" {
		return !required
	}
	return value == strings.TrimSpace(value) && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n\t")
}

func validUTC(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func validProcessState(value ProcessState) bool {
	switch value {
	case "absent", "downloading", "verifying", "installed", "starting", "handshaking", "running", "degraded", "restarting", "circuit_open", "draining", "stopped", "uninstalling", "download_failed", "signature_rejected", "manifest_rejected", "platform_mismatch", "start_failed", "handshake_failed", "upgrading", "rollback":
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
func validSlot(value ActiveSlot) bool { return value == SlotNone || value == SlotA || value == SlotB }
