// Package discovery owns database discovery rules, observations and candidates.
package discovery

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const (
	MaximumEvidenceItems = 32
	MaximumEvidenceBytes = 256
	DefaultListLimit     = 50
)

var (
	ErrInvalid              = errors.New("invalid discovery value")
	ErrInvalidRule          = errors.New("invalid discovery rule")
	ErrInvalidRuleSet       = errors.New("invalid discovery rule set")
	ErrInvalidSignature     = errors.New("invalid discovery rule signature")
	ErrRuleRevisionRollback = errors.New("discovery rule revision rollback")
	ErrSecretEvidence       = errors.New("secret-bearing discovery evidence")
	ErrNotFound             = errors.New("discovery candidate not found")
	ErrConflict             = errors.New("discovery candidate conflict")
	ErrStaleRevision        = errors.New("stale discovery observation revision")
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var familyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
var variantPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
var secretEvidencePattern = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|credential|authorization)(=|:|%3[dD])|[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@`)

type Source string

const (
	SourceNative Source = "native"
	SourceDocker Source = "docker"
)

type Status string

const (
	StatusDiscovered           Status = "discovered"
	StatusAwaitingConfirmation Status = "awaiting_confirmation"
	StatusAccepted             Status = "accepted"
	StatusProvisioning         Status = "provisioning"
	StatusIgnored              Status = "ignored"
	StatusDuplicate            Status = "duplicate"
	StatusDisappeared          Status = "disappeared"
)

type EvidenceKind string

const (
	EvidenceProcessName    EvidenceKind = "process_name"
	EvidenceExecutablePath EvidenceKind = "executable_path"
	EvidenceSystemdUnit    EvidenceKind = "systemd_unit"
	EvidenceListenEndpoint EvidenceKind = "listen_endpoint"
	EvidenceUnixSocket     EvidenceKind = "unix_socket"
	EvidenceContainerImage EvidenceKind = "container_image"
	EvidenceContainerLabel EvidenceKind = "container_label"
	EvidenceContainerPort  EvidenceKind = "container_port"
	EvidenceVersionHint    EvidenceKind = "version_hint"
)

type Evidence struct {
	Kind  EvidenceKind `json:"kind"`
	Value string       `json:"value"`
}

func (e Evidence) Validate() error {
	if !validEvidenceKind(e.Kind) || strings.TrimSpace(e.Value) != e.Value || e.Value == "" || len(e.Value) > MaximumEvidenceBytes || strings.ContainsAny(e.Value, "\x00\r\n") {
		return ErrInvalid
	}
	if secretEvidencePattern.MatchString(e.Value) {
		return ErrSecretEvidence
	}
	return nil
}

type CandidateObservation struct {
	ObservationID      string     `json:"observation_id"`
	Source             Source     `json:"source"`
	DatabaseFamily     string     `json:"database_family"`
	DatabaseVariant    string     `json:"database_variant"`
	VersionHint        string     `json:"version_hint,omitempty"`
	NormalizedEndpoint string     `json:"normalized_endpoint,omitempty"`
	UnixSocket         string     `json:"unix_socket,omitempty"`
	ProcessIdentity    string     `json:"process_identity,omitempty"`
	ServiceName        string     `json:"service_name,omitempty"`
	ContainerIdentity  string     `json:"container_identity,omitempty"`
	ContainerImage     string     `json:"container_image,omitempty"`
	DiscoveredRole     string     `json:"discovered_role,omitempty"`
	Confidence         float64    `json:"confidence"`
	Evidence           []Evidence `json:"evidence"`
	Fingerprint        [32]byte   `json:"-"`
	ObservedAt         time.Time  `json:"observed_at"`
}

func (observation CandidateObservation) Validate() error {
	if !identifierPattern.MatchString(observation.ObservationID) || (observation.Source != SourceNative && observation.Source != SourceDocker) || !familyPattern.MatchString(observation.DatabaseFamily) || !variantPattern.MatchString(observation.DatabaseVariant) || observation.Confidence < 0 || observation.Confidence > 1 || len(observation.Evidence) > MaximumEvidenceItems || (!observation.ObservedAt.IsZero() && !validUTC(observation.ObservedAt)) {
		return ErrInvalid
	}
	if len(observation.VersionHint) > 128 || len(observation.NormalizedEndpoint) > 512 || len(observation.UnixSocket) > 512 || len(observation.ProcessIdentity) > 256 || len(observation.ServiceName) > 256 || len(observation.ContainerIdentity) > 128 || len(observation.ContainerImage) > 512 || len(observation.DiscoveredRole) > 64 {
		return ErrInvalid
	}
	seen := make(map[Evidence]struct{}, len(observation.Evidence))
	for _, evidence := range observation.Evidence {
		if err := evidence.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[evidence]; duplicate {
			return ErrInvalid
		}
		seen[evidence] = struct{}{}
	}
	return nil
}

type Report struct {
	Scope               platformscope.Scope
	HostID              string
	AgentID             string
	ObservationRevision uint64
	RuleRevision        uint64
	Candidates          []CandidateObservation
	ObservedAt          time.Time
}

func (report Report) Validate() error {
	if report.Scope.Validate() != nil || !identifierPattern.MatchString(report.HostID) || !identifierPattern.MatchString(report.AgentID) || report.ObservationRevision == 0 || report.RuleRevision == 0 || !validUTC(report.ObservedAt) || len(report.Candidates) > 1024 {
		return ErrInvalid
	}
	seen := make(map[[32]byte]struct{}, len(report.Candidates))
	for _, candidate := range report.Candidates {
		if candidate.Validate() != nil || candidate.Fingerprint == ([32]byte{}) {
			return ErrInvalid
		}
		if _, duplicate := seen[candidate.Fingerprint]; duplicate {
			return ErrInvalid
		}
		seen[candidate.Fingerprint] = struct{}{}
	}
	return nil
}

type Candidate struct {
	ID      string
	Scope   platformscope.Scope
	HostID  string
	AgentID string
	CandidateObservation
	RuleRevision        uint64
	ObservationRevision uint64
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
	Status              Status
	IgnoreReason        string
}

func (candidate Candidate) Validate() error {
	if !identifierPattern.MatchString(candidate.ID) || candidate.Scope.Validate() != nil || !identifierPattern.MatchString(candidate.HostID) || !identifierPattern.MatchString(candidate.AgentID) || candidate.CandidateObservation.Validate() != nil || candidate.Fingerprint == ([32]byte{}) || candidate.RuleRevision == 0 || candidate.ObservationRevision == 0 || !validUTC(candidate.FirstSeenAt) || !validUTC(candidate.LastSeenAt) || candidate.LastSeenAt.Before(candidate.FirstSeenAt) || !validStatus(candidate.Status) {
		return ErrInvalid
	}
	return nil
}

type Filter struct {
	HostID         string
	Status         Status
	Source         Source
	DatabaseFamily string
	Cursor         string
	Limit          int
}

func (filter Filter) Validate() error {
	if filter.HostID != "" && !identifierPattern.MatchString(filter.HostID) || filter.Cursor != "" && !identifierPattern.MatchString(filter.Cursor) || filter.Status != "" && !validStatus(filter.Status) || filter.Source != "" && filter.Source != SourceNative && filter.Source != SourceDocker || filter.DatabaseFamily != "" && !familyPattern.MatchString(filter.DatabaseFamily) || filter.Limit < 0 || filter.Limit > 100 {
		return ErrInvalid
	}
	return nil
}

type Page struct {
	Items      []Candidate
	NextCursor string
}

func validEvidenceKind(kind EvidenceKind) bool {
	switch kind {
	case EvidenceProcessName, EvidenceExecutablePath, EvidenceSystemdUnit, EvidenceListenEndpoint, EvidenceUnixSocket, EvidenceContainerImage, EvidenceContainerLabel, EvidenceContainerPort, EvidenceVersionHint:
		return true
	default:
		return false
	}
}

func validStatus(status Status) bool {
	switch status {
	case StatusDiscovered, StatusAwaitingConfirmation, StatusAccepted, StatusProvisioning, StatusIgnored, StatusDuplicate, StatusDisappeared:
		return true
	default:
		return false
	}
}

func validUTC(value time.Time) bool { return !value.IsZero() && value.Location() == time.UTC }
