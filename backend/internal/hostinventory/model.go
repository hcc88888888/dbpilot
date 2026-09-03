// Package hostinventory owns the framework-neutral managed-host domain.
package hostinventory

import (
	"context"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"dbpilot.local/platform/internal/platformscope"
)

const (
	DefaultListLimit = 50
	MaximumListLimit = 100
)

var (
	ErrInvalid        = errors.New("invalid host inventory value")
	ErrNotFound       = errors.New("managed host not found")
	ErrConflict       = errors.New("managed host version conflict")
	ErrStaleRevision  = errors.New("host observation revision is stale")
	ErrDecommissioned = errors.New("managed host is decommissioned")
)

type HostStatus string

const (
	HostPending        HostStatus = "pending"
	HostEnrolling      HostStatus = "enrolling"
	HostOnline         HostStatus = "online"
	HostStale          HostStatus = "stale"
	HostOffline        HostStatus = "offline"
	HostDecommissioned HostStatus = "decommissioned"
)

type ContainerRuntime string

const (
	ContainerRuntimeNone   ContainerRuntime = "none"
	ContainerRuntimeDocker ContainerRuntime = "docker"
)

type Capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

type ResourceSummary struct {
	Capacity  uint64 `json:"capacity"`
	Available uint64 `json:"available"`
}

type FilesystemSummary struct {
	MountPoint     string `json:"mount_point"`
	CapacityBytes  uint64 `json:"capacity_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
}

type DecommissionTransition struct {
	Actor          string
	OperationID    string
	IdempotencyKey string
	Fingerprint    string
	OwnerToken     string
}

type decommissionTransitionContextKey struct{}

func WithDecommissionTransition(ctx context.Context, transition DecommissionTransition) context.Context {
	return context.WithValue(ctx, decommissionTransitionContextKey{}, transition)
}

func DecommissionTransitionFromContext(ctx context.Context) (DecommissionTransition, bool) {
	if ctx == nil {
		return DecommissionTransition{}, false
	}
	transition, ok := ctx.Value(decommissionTransitionContextKey{}).(DecommissionTransition)
	return transition, ok && transition.Validate() == nil
}

func (transition DecommissionTransition) Validate() error {
	if !boundedRequired(transition.Actor, 256) || transition.OperationID != "decommissionHost" ||
		!boundedRequired(transition.IdempotencyKey, 256) || !fingerprintPattern.MatchString(transition.Fingerprint) ||
		!ownerTokenPattern.MatchString(transition.OwnerToken) {
		return ErrInvalid
	}
	return nil
}

func (transition DecommissionTransition) Matches(expected DecommissionTransition) bool {
	return transition.Validate() == nil && expected.Validate() == nil && transition == expected
}

type Host struct {
	Scope                  platformscope.Scope     `json:"scope"`
	ID                     string                  `json:"host_id"`
	AgentID                string                  `json:"agent_id"`
	DisplayName            string                  `json:"display_name"`
	Hostname               string                  `json:"hostname"`
	OperatingSystem        string                  `json:"operating_system"`
	OperatingSystemVersion string                  `json:"operating_system_version,omitempty"`
	KernelVersion          string                  `json:"kernel_version,omitempty"`
	Architecture           string                  `json:"architecture"`
	CPU                    ResourceSummary         `json:"cpu_summary,omitempty"`
	Memory                 ResourceSummary         `json:"memory_summary,omitempty"`
	Filesystems            []FilesystemSummary     `json:"filesystem_summary,omitempty"`
	NetworkAddresses       []string                `json:"network_addresses"`
	Labels                 map[string]string       `json:"labels"`
	ContainerRuntime       ContainerRuntime        `json:"container_runtime"`
	Capabilities           []Capability            `json:"capabilities"`
	AgentVersion           string                  `json:"agent_version,omitempty"`
	EnrollmentRevision     uint64                  `json:"enrollment_revision"`
	CredentialGeneration   uint64                  `json:"credential_generation"`
	CertificateFingerprint string                  `json:"-"`
	CertificateSerial      string                  `json:"-"`
	CredentialRevokedAt    *time.Time              `json:"-"`
	ObservationRevision    uint64                  `json:"observation_revision"`
	EnrolledAt             time.Time               `json:"enrolled_at"`
	LastHelloAt            time.Time               `json:"last_hello_at,omitempty"`
	LastHeartbeatAt        time.Time               `json:"last_heartbeat_at,omitempty"`
	Status                 HostStatus              `json:"status"`
	Version                uint64                  `json:"version"`
	DecommissionTransition *DecommissionTransition `json:"-"`
}

// Observation contains only inventory reported by an authenticated Agent.
// Tenant/project ownership is resolved by the service and is never trusted
// from this payload.
type Observation struct {
	HostID              string
	AgentID             string
	Revision            uint64
	AgentVersion        string
	Hostname            string
	OS                  string
	OSVersion           string
	Kernel              string
	Architecture        string
	LogicalCPUCount     uint32
	MemoryCapacityBytes uint64
	Filesystems         []FilesystemSummary
	NetworkAddresses    []string
	Capabilities        []string
	ObservedAt          time.Time
}

// Enrollment contains only trusted control-plane metadata bound to a consumed
// one-time token. Agent observations never populate these fields.
type Enrollment struct {
	HostID      string
	AgentID     string
	DisplayName string
	Labels      map[string]string
	Revision    uint64
	EnrolledAt  time.Time
}

func (enrollment Enrollment) Validate() error {
	if !identifierPattern.MatchString(enrollment.HostID) || !identifierPattern.MatchString(enrollment.AgentID) ||
		!boundedRequired(enrollment.DisplayName, 120) || !validLabels(enrollment.Labels) ||
		!validPostgresRevision(enrollment.Revision, false) || !validUTC(enrollment.EnrolledAt) {
		return ErrInvalid
	}
	return nil
}

type Filter struct {
	Status       HostStatus
	Cursor       string
	Limit        int
	now          time.Time
	staleAfter   time.Duration
	offlineAfter time.Duration
}

type Page struct {
	Items      []Host
	NextCursor string
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var capabilityPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
var labelNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
var fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var ownerTokenPattern = regexp.MustCompile(`^owner-[0-9a-f]{64}$`)
var fingerprintHexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var serialPattern = regexp.MustCompile(`^[0-9a-f]+$`)

func (host Host) Validate() error {
	if host.Scope.Validate() != nil || !identifierPattern.MatchString(host.ID) || !identifierPattern.MatchString(host.AgentID) ||
		!boundedRequired(host.DisplayName, 120) || !boundedRequired(host.Hostname, 253) ||
		!boundedRequired(host.OperatingSystem, 64) || !boundedOptional(host.OperatingSystemVersion, 128) ||
		!boundedOptional(host.KernelVersion, 128) || !boundedRequired(host.Architecture, 32) ||
		!boundedOptional(host.AgentVersion, 64) || !validPostgresRevision(host.EnrollmentRevision, false) || !validPostgresRevision(host.CredentialGeneration, true) || !validCredentialState(host) ||
		!validPostgresRevision(host.ObservationRevision, true) || !validPostgresRevision(host.Version, false) ||
		!validUTC(host.EnrolledAt) || !validOptionalUTC(host.LastHelloAt) || !validOptionalUTC(host.LastHeartbeatAt) ||
		!validHostStatus(host.Status) || !validContainerRuntime(host.ContainerRuntime) ||
		!validResource(host.CPU) || !validResource(host.Memory) || !validFilesystems(host.Filesystems) ||
		!validUniqueStrings(host.NetworkAddresses, 32, 64, false) || !validLabels(host.Labels) || !validCapabilities(host.Capabilities) ||
		(host.DecommissionTransition != nil && (host.Status != HostDecommissioned || host.DecommissionTransition.Validate() != nil)) {
		return ErrInvalid
	}
	return nil
}

func validCredentialState(host Host) bool {
	active := host.CredentialGeneration > 0 && fingerprintHexPattern.MatchString(host.CertificateFingerprint) && serialPattern.MatchString(host.CertificateSerial) && host.CredentialRevokedAt == nil && host.Status != HostDecommissioned
	legacy := host.CredentialGeneration == 0 && host.CertificateFingerprint == "" && host.CertificateSerial == "" && host.CredentialRevokedAt == nil
	revoked := host.CredentialGeneration > 0 && host.CertificateFingerprint == "" && host.CertificateSerial == "" && host.CredentialRevokedAt != nil && validUTC(*host.CredentialRevokedAt) && host.Status == HostDecommissioned
	return active || legacy || revoked
}

func (observation Observation) Validate() error {
	if !identifierPattern.MatchString(observation.HostID) || !identifierPattern.MatchString(observation.AgentID) || !validPostgresRevision(observation.Revision, false) ||
		!boundedRequired(observation.Hostname, 253) || !boundedRequired(observation.OS, 64) ||
		!boundedOptional(observation.OSVersion, 128) || !boundedOptional(observation.Kernel, 128) ||
		!boundedRequired(observation.Architecture, 32) || !boundedOptional(observation.AgentVersion, 64) ||
		observation.LogicalCPUCount == 0 || observation.MemoryCapacityBytes == 0 || observation.MemoryCapacityBytes > math.MaxInt64 || !validFilesystems(observation.Filesystems) ||
		!validUniqueStrings(observation.NetworkAddresses, 32, 64, false) || !validUniqueStrings(observation.Capabilities, 64, 128, true) || !validUTC(observation.ObservedAt) {
		return ErrInvalid
	}
	return nil
}

func (filter Filter) Validate() error {
	if filter.Limit < 0 || filter.Limit > MaximumListLimit || (filter.Status != "" && !validHostStatus(filter.Status)) ||
		(filter.Cursor != "" && (filter.Cursor != strings.TrimSpace(filter.Cursor) || utf8.RuneCountInString(filter.Cursor) > 512)) {
		return ErrInvalid
	}
	return nil
}

func ClassifyHost(now time.Time, host Host, staleAfter, offlineAfter time.Duration) HostStatus {
	if host.Status == HostDecommissioned {
		return HostDecommissioned
	}
	if host.Status == HostPending || host.Status == HostEnrolling {
		return host.Status
	}
	if now.IsZero() || staleAfter <= 0 || offlineAfter <= staleAfter || host.LastHeartbeatAt.IsZero() {
		return HostOffline
	}
	age := now.Sub(host.LastHeartbeatAt)
	if age <= staleAfter {
		return HostOnline
	}
	if age <= offlineAfter {
		return HostStale
	}
	return HostOffline
}

func CanTransitionHostStatus(from, to HostStatus) bool {
	if from == to {
		return validHostStatus(from)
	}
	if to == HostDecommissioned {
		return validHostStatus(from) && from != HostDecommissioned
	}
	switch from {
	case HostPending:
		return to == HostEnrolling
	case HostEnrolling:
		return to == HostOnline
	case HostOnline:
		return to == HostStale || to == HostOffline
	case HostStale:
		return to == HostOnline || to == HostOffline
	case HostOffline:
		return to == HostOnline
	default:
		return false
	}
}

func validHostStatus(value HostStatus) bool {
	switch value {
	case HostPending, HostEnrolling, HostOnline, HostStale, HostOffline, HostDecommissioned:
		return true
	default:
		return false
	}
}

func validContainerRuntime(value ContainerRuntime) bool {
	return value == ContainerRuntimeNone || value == ContainerRuntimeDocker
}

func boundedRequired(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maximum
}

func boundedOptional(value string, maximum int) bool {
	return value == "" || boundedRequired(value, maximum)
}

func validUTC(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }

func validOptionalUTC(value time.Time) bool { return value.IsZero() || validUTC(value) }

func validResource(value ResourceSummary) bool {
	return value.Capacity <= math.MaxInt64 && value.Available <= value.Capacity
}

func validFilesystems(values []FilesystemSummary) bool {
	if len(values) > 128 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !boundedRequired(value.MountPoint, 512) || value.CapacityBytes > math.MaxInt64 || value.AvailableBytes > value.CapacityBytes {
			return false
		}
		if _, duplicate := seen[value.MountPoint]; duplicate {
			return false
		}
		seen[value.MountPoint] = struct{}{}
	}
	return true
}

func validPostgresRevision(value uint64, zeroAllowed bool) bool {
	return value <= math.MaxInt64 && (zeroAllowed || value > 0)
}

func validUniqueStrings(values []string, maximumItems, maximumLength int, capabilityNames bool) bool {
	if len(values) > maximumItems {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		valid := boundedRequired(value, maximumLength)
		if capabilityNames {
			valid = valid && capabilityPattern.MatchString(value)
		}
		if !valid {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validLabels(values map[string]string) bool {
	if len(values) > 32 {
		return false
	}
	for name, value := range values {
		if !labelNamePattern.MatchString(name) || !boundedOptional(value, 128) {
			return false
		}
	}
	return true
}

func validCapabilities(values []Capability) bool {
	if len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !capabilityPattern.MatchString(value.Name) || (value.Reason != "" && !validCapabilityReason(value.Reason)) || (value.Available && value.Reason != "") {
			return false
		}
		if _, duplicate := seen[value.Name]; duplicate {
			return false
		}
		seen[value.Name] = struct{}{}
	}
	return true
}

func validCapabilityReason(value string) bool {
	switch value {
	case "agent_unsupported", "docker_discovery_unavailable", "plugin_not_installed", "plugin_version_incompatible", "permission_denied":
		return true
	default:
		return false
	}
}
