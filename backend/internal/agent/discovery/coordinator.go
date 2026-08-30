package discovery

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	domain "dbpilot.local/platform/internal/discovery"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Detector interface {
	Discover(context.Context, []domain.Rule) ([]domain.CandidateObservation, error)
}

type ScanReason string

const (
	ScanEnrollment ScanReason = "enrollment"
	ScanPeriodic   ScanReason = "periodic"
	ScanCommand    ScanReason = "command"
)

type Reporter func(context.Context, *agentv1.DiscoveryReport) error
type CompatibilityState uint8

const (
	CompatibilityUnknown CompatibilityState = iota
	CompatibilityCompatible
	CompatibilityIncompatible
)

var controlIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type CoordinatorConfig struct {
	HostID             string
	AgentID            string
	Detector           Detector
	DockerDetector     Detector
	RuleSet            domain.RuleSet
	Attestation        domain.RuleAttestation
	Reporter           Reporter
	Now                func() time.Time
	RetryBackoff       time.Duration
	RevisionStore      RevisionStore
	ReportStore        ReportStore
	InitialUnavailable bool
	Compatibility      func() CompatibilityState
}

type Coordinator struct {
	hostID         string
	agentID        string
	detector       Detector
	dockerDetector Detector
	rules          domain.RuleSet
	attestation    domain.RuleAttestation
	reporter       Reporter
	now            func() time.Time
	retryBackoff   time.Duration

	mu                sync.Mutex
	revisionStore     RevisionStore
	pendingRevision   uint64
	reports           ReportStore
	pendingReport     *agentv1.DiscoveryReport
	unavailable       bool
	dockerUnavailable bool
	compatibility     func() CompatibilityState
}

func NewCoordinator(config CoordinatorConfig) (*Coordinator, error) {
	if !controlIdentifier.MatchString(config.HostID) || !controlIdentifier.MatchString(config.AgentID) || config.Detector == nil || config.Reporter == nil || config.RuleSet.Validate() != nil {
		return nil, domain.ErrInvalid
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	if config.RetryBackoff == 0 {
		config.RetryBackoff = time.Second
	}
	if config.RetryBackoff < time.Millisecond || config.RetryBackoff > time.Minute {
		return nil, domain.ErrInvalid
	}
	if config.RevisionStore == nil {
		config.RevisionStore = &memoryRevisionStore{}
	}
	if config.ReportStore == nil {
		config.ReportStore = &memoryReportStore{}
	}
	if config.Compatibility == nil {
		config.Compatibility = func() CompatibilityState { return CompatibilityCompatible }
	}
	if config.Attestation.Revision != config.RuleSet.Revision || config.Attestation.Digest == ([32]byte{}) || config.Attestation.IssuedAt != config.RuleSet.IssuedAt || config.Attestation.ExpiresAt != config.RuleSet.ExpiresAt || config.Attestation.DisappearanceGrace != config.RuleSet.DisappearanceGrace {
		return nil, domain.ErrInvalid
	}
	return &Coordinator{hostID: config.HostID, agentID: config.AgentID, detector: config.Detector, dockerDetector: config.DockerDetector, rules: config.RuleSet, attestation: config.Attestation, reporter: config.Reporter, now: config.Now, retryBackoff: config.RetryBackoff, revisionStore: config.RevisionStore, reports: config.ReportStore, unavailable: config.InitialUnavailable, dockerUnavailable: config.DockerDetector == nil, compatibility: config.Compatibility}, nil
}

// Run performs the enrollment scan before starting the bounded periodic scan.
func (coordinator *Coordinator) Run(ctx context.Context) error {
	if ctx == nil {
		return domain.ErrInvalid
	}
	if err := coordinator.scanUntilDelivered(ctx, ScanEnrollment); err != nil {
		return nil
	}
	ticker := time.NewTicker(coordinator.rules.ScanInterval)
	defer ticker.Stop()
	dockerEvents := make(chan struct{}, 1)
	if watcher, ok := coordinator.dockerDetector.(interface{ Watch(context.Context, func()) }); ok {
		go watcher.Watch(ctx, func() {
			select {
			case dockerEvents <- struct{}{}:
			default:
			}
		})
	}
	for {
		select {
		case <-ticker.C:
			if err := coordinator.scanUntilDelivered(ctx, ScanPeriodic); err != nil {
				return nil
			}
		case <-ctx.Done():
			return nil
		case <-dockerEvents:
			if err := coordinator.scanUntilDelivered(ctx, ScanPeriodic); err != nil {
				return nil
			}
		}
	}
}

func (coordinator *Coordinator) scanUntilDelivered(ctx context.Context, reason ScanReason) error {
	for {
		if err := coordinator.Scan(ctx, reason); err == nil {
			return nil
		} else if errors.Is(err, ErrDiscoveryUnavailable) {
			return err
		}
		timer := time.NewTimer(coordinator.retryBackoff)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

func (coordinator *Coordinator) Scan(ctx context.Context, _ ScanReason) error {
	return coordinator.scanSelected(ctx, true, true)
}

func (coordinator *Coordinator) scanSelected(ctx context.Context, includeNative, includeDocker bool) error {
	if ctx == nil {
		return domain.ErrInvalid
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.unavailable {
		return ErrDiscoveryUnavailable
	}
	switch coordinator.compatibility() {
	case CompatibilityUnknown:
		return ErrDiscoveryCompatibilityUnknown
	case CompatibilityIncompatible:
		return ErrDiscoveryCompatibilityPaused
	}
	if coordinator.pendingReport == nil {
		pending, err := coordinator.reports.Load(ctx)
		if err != nil {
			return err
		}
		coordinator.pendingReport = pending
	}
	if coordinator.pendingReport != nil {
		return coordinator.deliverPending(ctx)
	}
	observedAt := coordinator.now().UTC()
	if coordinator.rules.Active(observedAt) != nil {
		return domain.ErrInvalid
	}
	candidates := make([]domain.CandidateObservation, 0)
	if includeNative {
		native, err := coordinator.detector.Discover(ctx, coordinator.rules.Rules)
		if err != nil {
			return err
		}
		candidates = append(candidates, native...)
	}
	if includeDocker {
		if coordinator.dockerDetector == nil {
			coordinator.dockerUnavailable = true
			if !includeNative {
				return ErrDockerDiscoveryUnavailable
			}
		} else {
			dockerCandidates, err := coordinator.dockerDetector.Discover(ctx, coordinator.rules.Rules)
			if err != nil {
				coordinator.dockerUnavailable = true
				if !includeNative {
					return err
				}
			} else {
				coordinator.dockerUnavailable = false
				candidates = append(candidates, dockerCandidates...)
			}
		}
	}
	protobufCandidates := make([]*agentv1.DiscoveryCandidateObservation, 0, len(candidates))
	seen := make(map[[32]byte]struct{}, len(candidates))
	for index := range candidates {
		candidate := candidates[index]
		candidate.ObservedAt = observedAt
		fingerprint, err := domain.Fingerprint(coordinator.hostID, candidate)
		if err != nil {
			return fmt.Errorf("fingerprint native discovery candidate: %w", err)
		}
		if _, duplicate := seen[fingerprint]; duplicate {
			continue
		}
		seen[fingerprint] = struct{}{}
		candidate.Fingerprint = fingerprint
		if candidate.ObservationID == "" {
			candidate.ObservationID = "native-" + hex.EncodeToString(fingerprint[:8])
		}
		if err := candidate.Validate(); err != nil {
			return err
		}
		protobufCandidate, err := protobufCandidate(candidate)
		if err != nil {
			return err
		}
		protobufCandidates = append(protobufCandidates, protobufCandidate)
	}
	sort.Slice(protobufCandidates, func(left, right int) bool {
		return string(protobufCandidates[left].GetFingerprint()) < string(protobufCandidates[right].GetFingerprint())
	})
	report := &agentv1.DiscoveryReport{HostId: coordinator.hostID, AgentId: coordinator.agentID, ObservationRevision: math.MaxUint64, RuleRevision: coordinator.rules.Revision, Candidates: protobufCandidates, ObservedAt: timestamppb.New(observedAt), RuleSetDigest: append([]byte(nil), coordinator.attestation.Digest[:]...), DisappearanceGraceSeconds: uint64(coordinator.attestation.DisappearanceGrace / time.Second), RuleIssuedAt: timestamppb.New(coordinator.attestation.IssuedAt), RuleExpiresAt: timestamppb.New(coordinator.attestation.ExpiresAt), RuleAttestationSignature: append([]byte(nil), coordinator.attestation.Signature...), RuleAttestationVersion: coordinator.attestation.Version, RuleAttestationAlgorithm: coordinator.attestation.Algorithm, RuleAttestationKeyId: coordinator.attestation.KeyID}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil || len(encoded) > domain.MaximumDiscoveryReportBytes {
		coordinator.unavailable = true
		return ErrDiscoveryUnavailable
	}
	if coordinator.pendingRevision == 0 {
		revision, err := coordinator.revisionStore.Next(ctx)
		if err != nil {
			return err
		}
		coordinator.pendingRevision = revision
	}
	report.ObservationRevision = coordinator.pendingRevision
	if err := coordinator.reports.Save(ctx, report); err != nil {
		return err
	}
	coordinator.pendingReport = report
	return coordinator.deliverPending(ctx)
}

func (coordinator *Coordinator) deliverPending(ctx context.Context) error {
	report := coordinator.pendingReport
	if report == nil {
		return nil
	}
	if err := coordinator.reporter(ctx, proto.Clone(report).(*agentv1.DiscoveryReport)); err != nil {
		var terminal interface{ NonRetryableDiscovery() bool }
		if errors.As(err, &terminal) && terminal.NonRetryableDiscovery() {
			if clearErr := coordinator.reports.Clear(ctx, report); clearErr != nil {
				return clearErr
			}
			coordinator.pendingReport = nil
			coordinator.pendingRevision = 0
			coordinator.unavailable = true
		}
		return err
	}
	if err := coordinator.reports.Clear(ctx, report); err != nil {
		return err
	}
	coordinator.pendingReport = nil
	coordinator.pendingRevision = 0
	return nil
}

var ErrDiscoveryUnavailable = errors.New("native discovery unavailable until restart or policy reload")
var ErrDiscoveryCompatibilityUnknown = errors.New("native discovery waiting for control compatibility")
var ErrDiscoveryCompatibilityPaused = errors.New("native discovery paused for incompatible control plane")

func (coordinator *Coordinator) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, _ interface {
	Report(*agentv1.CommandProgress) error
}) (*agentv1.CommandResult, error) {
	command := envelope.GetDiscoverDatabases()
	if command == nil || command.GetHostId() != coordinator.hostID || command.GetRuleRevision() != coordinator.rules.Revision || (!command.GetIncludeNative() && !command.GetIncludeDocker()) {
		return nil, domain.ErrInvalid
	}
	if err := coordinator.scanSelected(ctx, command.GetIncludeNative(), command.GetIncludeDocker()); err != nil {
		return nil, err
	}
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "database discovery completed"}, nil
}

func (coordinator *Coordinator) AdditionalCapabilities() []string {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.dockerUnavailable {
		return []string{"docker_discovery_unavailable", "native_discovery_v1"}
	}
	return []string{"docker_discovery_v1", "native_discovery_v1"}
}

func protobufCandidate(candidate domain.CandidateObservation) (*agentv1.DiscoveryCandidateObservation, error) {
	source := agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE
	if candidate.Source == domain.SourceDocker {
		source = agentv1.DiscoverySource_DISCOVERY_SOURCE_DOCKER
	}
	evidence := make([]*agentv1.DiscoveryEvidence, 0, len(candidate.Evidence))
	for _, value := range candidate.Evidence {
		kind, ok := protobufEvidenceKind(value.Kind)
		if !ok {
			return nil, domain.ErrInvalid
		}
		evidence = append(evidence, &agentv1.DiscoveryEvidence{Kind: kind, RedactedValue: value.Value})
	}
	return &agentv1.DiscoveryCandidateObservation{
		ObservationId: candidate.ObservationID, Source: source, DatabaseFamily: candidate.DatabaseFamily, DatabaseVariant: candidate.DatabaseVariant,
		VersionHint: candidate.VersionHint, NormalizedEndpoint: candidate.NormalizedEndpoint, UnixSocket: candidate.UnixSocket,
		ProcessIdentity: candidate.ProcessIdentity, ServiceName: candidate.ServiceName, ContainerIdentity: candidate.ContainerIdentity,
		ContainerImage: candidate.ContainerImage, DiscoveredRole: candidate.DiscoveredRole, Confidence: candidate.Confidence,
		Evidence: evidence, Fingerprint: append([]byte(nil), candidate.Fingerprint[:]...), ObservedAt: timestamppb.New(candidate.ObservedAt),
	}, nil
}

func protobufEvidenceKind(kind domain.EvidenceKind) (agentv1.DiscoveryEvidenceKind, bool) {
	values := map[domain.EvidenceKind]agentv1.DiscoveryEvidenceKind{
		domain.EvidenceProcessName:    agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_PROCESS_NAME,
		domain.EvidenceExecutablePath: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_EXECUTABLE_PATH,
		domain.EvidenceSystemdUnit:    agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_SYSTEMD_UNIT,
		domain.EvidenceListenEndpoint: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_LISTEN_ENDPOINT,
		domain.EvidenceUnixSocket:     agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_UNIX_SOCKET,
		domain.EvidenceContainerImage: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_IMAGE,
		domain.EvidenceContainerLabel: agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_LABEL,
		domain.EvidenceContainerPort:  agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_CONTAINER_PORT,
		domain.EvidenceVersionHint:    agentv1.DiscoveryEvidenceKind_DISCOVERY_EVIDENCE_KIND_VERSION_HINT,
	}
	value, ok := values[kind]
	return value, ok
}

var _ = errors.Is
