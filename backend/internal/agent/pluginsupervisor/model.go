package pluginsupervisor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/pluginstate"
)

const (
	MaxAssignedInstances = 1024
	MaxAssignedTemplates = 1024
	MaxPluginOutputBytes = 64 << 10
)

var (
	ErrInvalidRequest     = errors.New("PLUGIN_RECONCILE_INVALID")
	ErrInvalidFence       = errors.New("PLUGIN_EXECUTION_FENCE_INVALID")
	ErrStaleOperation     = errors.New("PLUGIN_OPERATION_STALE")
	ErrOperationConflict  = errors.New("PLUGIN_OPERATION_CONFLICT")
	ErrCircuitOpen        = errors.New("PLUGIN_CIRCUIT_OPEN")
	ErrArtifactLease      = errors.New("PLUGIN_ARTIFACT_LEASE_REJECTED")
	ErrArtifactDownload   = errors.New("PLUGIN_ARTIFACT_DOWNLOAD_FAILED")
	ErrArtifactDigest     = errors.New("PLUGIN_ARTIFACT_DIGEST_REJECTED")
	ErrManifestRejected   = errors.New("PLUGIN_MANIFEST_REJECTED")
	ErrSignatureRejected  = errors.New("PLUGIN_SIGNATURE_REJECTED")
	ErrPlatformMismatch   = errors.New("PLUGIN_PLATFORM_MISMATCH")
	ErrInstallFailed      = errors.New("PLUGIN_INSTALL_FAILED")
	ErrProcessStart       = errors.New("PLUGIN_START_FAILED")
	ErrHealthHandshake    = errors.New("PLUGIN_HANDSHAKE_FAILED")
	ErrRollbackFailed     = errors.New("PLUGIN_ROLLBACK_FAILED")
	ErrProcessUnsupported = errors.New("PLUGIN_PROCESS_UNSUPPORTED")
	ErrProcessExited      = errors.New("PLUGIN_PROCESS_EXITED")
	resourceIdentifier    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	familyIdentifier      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

type DesiredState uint8

const (
	DesiredUnspecified DesiredState = iota
	DesiredAbsent
	DesiredInstalled
	DesiredRunning
	DesiredStopped
)

type ReconcileRequest struct {
	AssignmentID          string
	PluginID              string
	DatabaseFamily        string
	DesiredVersion        string
	DesiredState          DesiredState
	ArtifactID            string
	ArtifactSHA256        []byte
	ManifestDigest        []byte
	ConfigurationRevision uint64
	OperationRevision     uint64
	InstanceIDs           []string
	TemplateIDs           []string
}

func (request ReconcileRequest) Validate() error {
	if !resourceIdentifier.MatchString(request.AssignmentID) || !familyIdentifier.MatchString(request.PluginID) || !familyIdentifier.MatchString(request.DatabaseFamily) ||
		request.ConfigurationRevision == 0 || request.OperationRevision == 0 || len(request.InstanceIDs) > MaxAssignedInstances || len(request.TemplateIDs) > MaxAssignedTemplates ||
		!uniqueResources(request.InstanceIDs) || !uniqueResources(request.TemplateIDs) {
		return ErrInvalidRequest
	}
	switch request.DesiredState {
	case DesiredAbsent:
		if !optionalArtifactIdentity(request) {
			return ErrInvalidRequest
		}
	case DesiredStopped:
		if !optionalArtifactIdentity(request) {
			return ErrInvalidRequest
		}
	case DesiredInstalled, DesiredRunning:
		if !boundedVersion(request.DesiredVersion) || !resourceIdentifier.MatchString(request.ArtifactID) || len(request.ArtifactSHA256) != sha256.Size || len(request.ManifestDigest) != sha256.Size {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func optionalArtifactIdentity(request ReconcileRequest) bool {
	empty := request.DesiredVersion == "" && request.ArtifactID == "" && len(request.ArtifactSHA256) == 0 && len(request.ManifestDigest) == 0
	complete := boundedVersion(request.DesiredVersion) && resourceIdentifier.MatchString(request.ArtifactID) && len(request.ArtifactSHA256) == sha256.Size && len(request.ManifestDigest) == sha256.Size
	return empty || complete
}

func (request ReconcileRequest) Fingerprint() string {
	instances := append([]string(nil), request.InstanceIDs...)
	templates := append([]string(nil), request.TemplateIDs...)
	sort.Strings(instances)
	sort.Strings(templates)
	values := []string{request.AssignmentID, request.PluginID, request.DatabaseFamily, request.DesiredVersion, strconv.Itoa(int(request.DesiredState)), request.ArtifactID, hex.EncodeToString(request.ArtifactSHA256), hex.EncodeToString(request.ManifestDigest), strconv.FormatUint(request.ConfigurationRevision, 10), strconv.FormatUint(request.OperationRevision, 10)}
	values = append(values, "instances", strconv.Itoa(len(instances)))
	values = append(values, instances...)
	values = append(values, "templates", strconv.Itoa(len(templates)))
	values = append(values, templates...)
	hash := sha256.New()
	for _, value := range values {
		_, _ = io.WriteString(hash, strconv.Itoa(len(value))+":"+value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func LaunchProof(nonce, challenge []byte, assignmentID, version string, configurationRevision, operationRevision uint64, instanceIDs []string) []byte {
	if len(nonce) != sha256.Size || len(challenge) != sha256.Size {
		return nil
	}
	instances := append([]string(nil), instanceIDs...)
	sort.Strings(instances)
	values := []string{hex.EncodeToString(challenge), assignmentID, version, strconv.FormatUint(configurationRevision, 10), strconv.FormatUint(operationRevision, 10)}
	values = append(values, instances...)
	mac := hmac.New(sha256.New, nonce)
	_, _ = io.WriteString(mac, "dbpilot-plugin-launch-proof-v1\n")
	for _, value := range values {
		_, _ = io.WriteString(mac, strconv.Itoa(len(value))+":"+value)
	}
	return mac.Sum(nil)
}

type PreparedChange struct {
	Request      ReconcileRequest
	CurrentState pluginstate.FamilyState
	HasCurrent   bool
	PreparedAt   time.Time
}

type ExecutionFence struct {
	CommandID      string
	ExecutionToken []byte
	LeaseRevision  uint64
	StartedAt      time.Time
}

func (fence ExecutionFence) Validate() error {
	if !resourceIdentifier.MatchString(fence.CommandID) || len(fence.ExecutionToken) != sha256.Size || fence.LeaseRevision == 0 || fence.StartedAt.IsZero() {
		return ErrInvalidFence
	}
	return nil
}

type ArtifactLeaseRequest struct {
	AssignmentID      string
	ArtifactID        string
	OperationRevision uint64
}

type ArtifactLease struct {
	LeaseID           string
	AssignmentID      string
	ArtifactID        string
	OperationRevision uint64
	ExpiresAt         time.Time
	DownloadURL       string
	RequestHeaders    map[string]string
}

type LeaseClient interface {
	LeasePluginArtifact(context.Context, ArtifactLeaseRequest) (ArtifactLease, error)
}

type DownloadedArtifact struct {
	Body io.ReadCloser
	Size int64
}

type ArtifactDownloader interface {
	Download(context.Context, ArtifactLease) (DownloadedArtifact, error)
}

type InstalledSlot struct {
	Slot             pluginstate.Slot
	Version          string
	ExecutablePath   string
	ExecutableSHA256 string
	ManifestPath     string
	ArtifactSHA256   string
	ManifestDigest   string
}

type InstallRequest struct {
	DatabaseFamily string
	PluginID       string
	Version        string
	ArtifactSHA256 []byte
	ManifestDigest []byte
	Archive        io.Reader
	ArchiveSize    int64
}

type SlotIdentity struct {
	DatabaseFamily string
	PluginID       string
	Version        string
	ArtifactSHA256 string
	ManifestDigest string
}

type SlotInstaller interface {
	InstallInactive(context.Context, InstallRequest, pluginstate.Slot) (InstalledSlot, error)
	Installed(context.Context, SlotIdentity, pluginstate.Slot) (InstalledSlot, error)
	Activate(context.Context, SlotIdentity, pluginstate.Slot) error
	RemoveInactive(context.Context, string, pluginstate.Slot) error
	RemoveFamily(context.Context, string) error
	Recover(context.Context, string) error
}

type Executable struct {
	Path   string
	SHA256 string
}

type LaunchConfiguration struct {
	AssignmentID          string
	PluginID              string
	DatabaseFamily        string
	Version               string
	Slot                  pluginstate.Slot
	ConfigurationRevision uint64
	OperationRevision     uint64
	InstanceIDs           []string
	TemplateIDs           []string
	RuntimeDirectory      string
	ExecutablePath        string
	UserID                uint32
	GroupID               uint32
	LaunchNonce           []byte
}

type Process interface {
	PID() int
	StartTicks() uint64
	StartedAt() time.Time
	Drain(context.Context) error
	Stop(context.Context) error
	Kill() error
	Wait() error
}

type ProcessRunner interface {
	Start(context.Context, Executable, LaunchConfiguration) (Process, error)
}

type HealthRequest struct {
	AssignmentID          string
	PluginID              string
	DatabaseFamily        string
	Version               string
	ProtocolVersion       string
	ExecutableSHA256      []byte
	ExecutablePath        string
	ConfigurationRevision uint64
	OperationRevision     uint64
	InstanceIDs           []string
	RuntimeDirectory      string
	LaunchNonce           []byte
	ExpectedUserID        uint32
	ExpectedGroupID       uint32
}

type HealthChecker interface {
	Handshake(context.Context, Process, HealthRequest) error
}

type StateStore interface {
	Get(string) (pluginstate.FamilyState, bool)
	List() []pluginstate.FamilyState
	Put(context.Context, pluginstate.FamilyState) (pluginstate.FamilyState, error)
	Delete(context.Context, string, uint64) error
	Snapshot() (uint64, time.Time, []pluginstate.FamilyState)
}

type ObservedState struct {
	State pluginstate.FamilyState
}

type Supervisor interface {
	Prepare(context.Context, ReconcileRequest) (PreparedChange, error)
	Start(context.Context, PreparedChange, ExecutionFence) (ObservedState, error)
	Stop(context.Context) error
	Observe() []PluginObservation
}

type PluginObservation = agentv1.PluginAssignmentObservation

func uniqueResources(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !resourceIdentifier.MatchString(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func boundedVersion(value string) bool {
	return value != "" && len(value) <= 64 && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n\t/\\:")
}

func stateForDesired(value DesiredState) pluginstate.DesiredState {
	switch value {
	case DesiredAbsent:
		return pluginstate.DesiredAbsent
	case DesiredInstalled:
		return pluginstate.DesiredInstalled
	case DesiredRunning:
		return pluginstate.DesiredRunning
	case DesiredStopped:
		return pluginstate.DesiredStopped
	default:
		return ""
	}
}
