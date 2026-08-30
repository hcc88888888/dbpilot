package agentcontrol

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	discoverydomain "dbpilot.local/platform/internal/discovery"
	"google.golang.org/protobuf/proto"
)

var (
	ErrDiscoveryObservationCapacity = errors.New("DISCOVERY_OBSERVATION_PENDING_AGENT_CAPACITY")
	ErrDiscoveryObservationClosed   = errors.New("DISCOVERY_OBSERVATION_DISPATCHER_CLOSED")
	ErrDiscoveryObservationInvalid  = errors.New("DISCOVERY_OBSERVATION_INVALID")
)

type DiscoveryReportSink interface {
	RecordDiscoveryReport(context.Context, string, *agentv1.DiscoveryReport) error
}
type DiscoveryObserver interface {
	SubmitDiscovery(string, *agentv1.DiscoveryReport) error
}
type DiscoveryAcknowledger func(string, *agentv1.DiscoveryReportAcknowledgement) error

type DiscoveryDispatcherConfig struct {
	MaximumPendingAgents   int
	DeliveryTimeout        time.Duration
	RetryBackoff           time.Duration
	OnError                func(error)
	Acknowledge            DiscoveryAcknowledger
	SourceResultsSupported func(string) bool
}
type discoveryLane struct {
	agentID        string
	dispatcher     *DiscoveryDispatcher
	wake           chan struct{}
	pending        *agentv1.DiscoveryReport
	pendingDigest  [sha256.Size]byte
	activeRevision uint64
	activeDigest   [sha256.Size]byte
	quarantined    bool
}
type DiscoveryDispatcher struct {
	sink      DiscoveryReportSink
	config    DiscoveryDispatcherConfig
	mu        sync.Mutex
	lanes     map[string]*discoveryLane
	last      map[string]discoveryRevisionDigest
	lastOrder []string
	closed    bool
	stop      chan struct{}
}
type discoveryRevisionDigest struct {
	revision uint64
	digest   [sha256.Size]byte
}

func NewDiscoveryDispatcher(sink DiscoveryReportSink, config DiscoveryDispatcherConfig) (*DiscoveryDispatcher, error) {
	if sink == nil || config.Acknowledge == nil {
		return nil, ErrDiscoveryObservationInvalid
	}
	if config.MaximumPendingAgents == 0 {
		config.MaximumPendingAgents = 1024
	}
	if config.DeliveryTimeout == 0 {
		config.DeliveryTimeout = 10 * time.Second
	}
	if config.RetryBackoff == 0 {
		config.RetryBackoff = time.Second
	}
	if config.MaximumPendingAgents < 1 || config.DeliveryTimeout <= 0 || config.RetryBackoff <= 0 {
		return nil, ErrDiscoveryObservationInvalid
	}
	return &DiscoveryDispatcher{sink: sink, config: config, lanes: make(map[string]*discoveryLane), last: make(map[string]discoveryRevisionDigest), stop: make(chan struct{})}, nil
}
func (dispatcher *DiscoveryDispatcher) SubmitDiscovery(agentID string, report *agentv1.DiscoveryReport) error {
	requiresSourceResults := true
	if dispatcher.config.SourceResultsSupported != nil {
		requiresSourceResults = dispatcher.config.SourceResultsSupported(agentID)
	}
	if !validDiscoveryReport(agentID, report, requiresSourceResults) {
		return ErrDiscoveryObservationInvalid
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil || len(encoded) > discoverydomain.MaximumDiscoveryReportBytes {
		return ErrDiscoveryObservationInvalid
	}
	digest := sha256.Sum256(encoded)
	clone := proto.Clone(report).(*agentv1.DiscoveryReport)
	if !requiresSourceResults {
		clone = normalizeLegacyDiscoveryReport(clone)
	}
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.closed {
		return ErrDiscoveryObservationClosed
	}
	if previous, ok := dispatcher.last[agentID]; ok {
		if report.GetObservationRevision() < previous.revision {
			return ErrDiscoveryObservationInvalid
		}
		if report.GetObservationRevision() == previous.revision && digest != previous.digest {
			return ErrDiscoveryObservationInvalid
		}
	}
	lane := dispatcher.lanes[agentID]
	if lane == nil {
		if len(dispatcher.lanes) >= dispatcher.config.MaximumPendingAgents {
			return ErrDiscoveryObservationCapacity
		}
		lane = &discoveryLane{agentID: agentID, dispatcher: dispatcher, wake: make(chan struct{}, 1)}
		dispatcher.lanes[agentID] = lane
		go lane.run()
	}
	if lane.quarantined {
		return ErrDiscoveryObservationCapacity
	}
	highest := lane.activeRevision
	highestDigest := lane.activeDigest
	if lane.pending != nil && lane.pending.GetObservationRevision() >= highest {
		highest = lane.pending.GetObservationRevision()
		highestDigest = lane.pendingDigest
	}
	if report.GetObservationRevision() < highest {
		return ErrDiscoveryObservationInvalid
	}
	if report.GetObservationRevision() == highest && highest != 0 {
		if digest != highestDigest {
			return ErrDiscoveryObservationInvalid
		}
		return nil
	}
	lane.pending = clone
	lane.pendingDigest = digest
	select {
	case lane.wake <- struct{}{}:
	default:
	}
	return nil
}
func (dispatcher *DiscoveryDispatcher) Close() {
	dispatcher.mu.Lock()
	if !dispatcher.closed {
		dispatcher.closed = true
		close(dispatcher.stop)
	}
	dispatcher.mu.Unlock()
}
func (lane *discoveryLane) run() {
	for {
		select {
		case <-lane.wake:
		case <-lane.dispatcher.stop:
			return
		}
		for {
			report, digest, ok := lane.take()
			if !ok {
				if lane.retire() {
					return
				}
				break
			}
			if !lane.deliver(report, digest) {
				return
			}
		}
	}
}
func (lane *discoveryLane) take() (*agentv1.DiscoveryReport, [sha256.Size]byte, bool) {
	lane.dispatcher.mu.Lock()
	defer lane.dispatcher.mu.Unlock()
	if lane.pending == nil {
		return nil, [sha256.Size]byte{}, false
	}
	report, digest := lane.pending, lane.pendingDigest
	lane.pending = nil
	lane.pendingDigest = [sha256.Size]byte{}
	lane.activeRevision = report.GetObservationRevision()
	lane.activeDigest = digest
	return report, digest, true
}
func (lane *discoveryLane) deliver(report *agentv1.DiscoveryReport, digest [sha256.Size]byte) bool {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), lane.dispatcher.config.DeliveryTimeout)
		result := make(chan error, 1)
		go func() { result <- lane.dispatcher.sink.RecordDiscoveryReport(ctx, lane.agentID, report) }()
		select {
		case err := <-result:
			cancel()
			if err == nil {
				lane.ack(report, digest, true, false, "PERSISTED")
				lane.clearActive()
				return true
			}
			if errors.Is(err, discoverydomain.ErrConflict) || errors.Is(err, discoverydomain.ErrStaleRevision) || errors.Is(err, discoverydomain.ErrInvalidSignature) || errors.Is(err, discoverydomain.ErrInvalid) {
				lane.ack(report, digest, false, false, "REPORT_REJECTED")
				lane.clearActive()
				return true
			}
			if lane.dispatcher.config.OnError != nil {
				lane.dispatcher.config.OnError(err)
			}
			timer := time.NewTimer(lane.dispatcher.config.RetryBackoff)
			select {
			case <-timer.C:
				continue
			case <-lane.dispatcher.stop:
				timer.Stop()
				return false
			}
		case <-ctx.Done():
			cancel()
			lane.dispatcher.mu.Lock()
			lane.quarantined = true
			lane.dispatcher.mu.Unlock()
			go lane.awaitQuarantined(result, report, digest)
			return false
		case <-lane.dispatcher.stop:
			cancel()
			return false
		}
	}
}
func (lane *discoveryLane) awaitQuarantined(result <-chan error, report *agentv1.DiscoveryReport, digest [sha256.Size]byte) {
	err := <-result
	if err == nil {
		lane.ack(report, digest, true, false, "PERSISTED")
	} else {
		lane.ack(report, digest, false, true, "PERSISTENCE_RETRY")
	}
	lane.dispatcher.mu.Lock()
	lane.activeRevision = 0
	lane.activeDigest = [sha256.Size]byte{}
	lane.quarantined = false
	if lane.pending == nil && !lane.dispatcher.closed {
		delete(lane.dispatcher.lanes, lane.agentID)
	}
	lane.dispatcher.mu.Unlock()
}
func (lane *discoveryLane) ack(report *agentv1.DiscoveryReport, digest [sha256.Size]byte, persisted, retryable bool, reason string) {
	ack := &agentv1.DiscoveryReportAcknowledgement{HostId: report.GetHostId(), AgentId: lane.agentID, ObservationRevision: report.GetObservationRevision(), ReportDigest: digest[:], Persisted: persisted, Retryable: retryable, ReasonCode: reason}
	if persisted {
		lane.dispatcher.remember(lane.agentID, report.GetObservationRevision(), digest)
	}
	for {
		err := lane.dispatcher.config.Acknowledge(lane.agentID, ack)
		if err == nil {
			return
		}
		if lane.dispatcher.config.OnError != nil {
			lane.dispatcher.config.OnError(err)
		}
		timer := time.NewTimer(lane.dispatcher.config.RetryBackoff)
		select {
		case <-timer.C:
		case <-lane.dispatcher.stop:
			timer.Stop()
			return
		}
	}
}

func (dispatcher *DiscoveryDispatcher) remember(agentID string, revision uint64, digest [sha256.Size]byte) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if current, ok := dispatcher.last[agentID]; ok && current.revision >= revision {
		return
	}
	if _, exists := dispatcher.last[agentID]; !exists {
		dispatcher.lastOrder = append(dispatcher.lastOrder, agentID)
	}
	dispatcher.last[agentID] = discoveryRevisionDigest{revision: revision, digest: digest}
	for len(dispatcher.lastOrder) > dispatcher.config.MaximumPendingAgents {
		oldest := dispatcher.lastOrder[0]
		dispatcher.lastOrder = dispatcher.lastOrder[1:]
		delete(dispatcher.last, oldest)
	}
}
func (lane *discoveryLane) clearActive() {
	lane.dispatcher.mu.Lock()
	lane.activeRevision = 0
	lane.activeDigest = [sha256.Size]byte{}
	lane.dispatcher.mu.Unlock()
}
func (lane *discoveryLane) retire() bool {
	lane.dispatcher.mu.Lock()
	defer lane.dispatcher.mu.Unlock()
	if lane.pending != nil || lane.activeRevision != 0 || lane.quarantined {
		return false
	}
	delete(lane.dispatcher.lanes, lane.agentID)
	return true
}
func validDiscoveryReport(agentID string, report *agentv1.DiscoveryReport, requiresSourceResults bool) bool {
	if !hostObservationAgentID.MatchString(agentID) || report == nil || report.GetAgentId() != agentID || !hostObservationAgentID.MatchString(report.GetHostId()) || report.GetObservationRevision() == 0 || report.GetRuleRevision() == 0 || report.GetObservedAt() == nil || !report.GetObservedAt().IsValid() || len(report.GetCandidates()) > 1024 || len(report.GetRuleSetDigest()) != sha256.Size || report.GetDisappearanceGraceSeconds() == 0 || report.GetRuleIssuedAt() == nil || !report.GetRuleIssuedAt().IsValid() || report.GetRuleExpiresAt() == nil || !report.GetRuleExpiresAt().IsValid() || len(report.GetRuleAttestationSignature()) != 64 || report.GetRuleAttestationVersion() == 0 || report.GetRuleAttestationAlgorithm() == "" || report.GetRuleAttestationKeyId() == "" {
		return false
	}
	if requiresSourceResults && len(report.GetSourceResults()) != 2 || !requiresSourceResults && len(report.GetSourceResults()) != 0 {
		return false
	}
	if !requiresSourceResults {
		for _, candidate := range report.GetCandidates() {
			if candidate.GetSource() != agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE {
				return false
			}
		}
		return validDiscoveryCandidates(report.GetCandidates(), map[agentv1.DiscoverySource]bool{agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE: true})
	}
	completed := map[agentv1.DiscoverySource]bool{}
	for _, result := range report.GetSourceResults() {
		if result == nil || result.GetSource() == agentv1.DiscoverySource_DISCOVERY_SOURCE_UNSPECIFIED || result.GetStatus() == agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_UNSPECIFIED || result.GetReason() == agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_UNSPECIFIED || result.GetObservedAt() == nil || !result.GetObservedAt().IsValid() || !result.GetObservedAt().AsTime().Equal(report.GetObservedAt().AsTime()) {
			return false
		}
		if _, duplicate := completed[result.GetSource()]; duplicate || !validSourceOutcome(result.GetStatus(), result.GetReason()) {
			return false
		}
		completed[result.GetSource()] = result.GetStatus() == agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_COMPLETED
	}
	if _, ok := completed[agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE]; !ok {
		return false
	}
	if _, ok := completed[agentv1.DiscoverySource_DISCOVERY_SOURCE_DOCKER]; !ok {
		return false
	}
	return validDiscoveryCandidates(report.GetCandidates(), completed)
}

func validDiscoveryCandidates(candidates []*agentv1.DiscoveryCandidateObservation, completed map[agentv1.DiscoverySource]bool) bool {
	for _, candidate := range candidates {
		if candidate == nil || candidate.GetSource() == agentv1.DiscoverySource_DISCOVERY_SOURCE_UNSPECIFIED || !completed[candidate.GetSource()] || candidate.GetDatabaseFamily() == "" || candidate.GetDatabaseVariant() == "" || len(candidate.GetFingerprint()) != 32 || candidate.GetObservedAt() == nil || !candidate.GetObservedAt().IsValid() || len(candidate.GetEvidence()) > 32 {
			return false
		}
	}
	return true
}

func normalizeLegacyDiscoveryReport(report *agentv1.DiscoveryReport) *agentv1.DiscoveryReport {
	report.SourceResults = []*agentv1.DiscoverySourceResult{
		{Source: agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE, Status: agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_COMPLETED, Reason: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_HEALTHY, ObservedAt: report.GetObservedAt()},
		{Source: agentv1.DiscoverySource_DISCOVERY_SOURCE_DOCKER, Status: agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_NOT_REQUESTED, Reason: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_NOT_REQUESTED, ObservedAt: report.GetObservedAt()},
	}
	return report
}

func validSourceOutcome(statusValue agentv1.DiscoverySourceResultStatus, reason agentv1.DiscoverySourceReason) bool {
	switch statusValue {
	case agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_COMPLETED:
		return reason == agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_HEALTHY
	case agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_UNAVAILABLE:
		return reason == agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_HELPER_UNAVAILABLE || reason == agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_PERMISSION_DENIED || reason == agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_DETECTOR_ERROR
	case agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_NOT_CONFIGURED:
		return reason == agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_NOT_CONFIGURED
	case agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_NOT_REQUESTED:
		return reason == agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_NOT_REQUESTED
	default:
		return false
	}
}

type noopDiscoveryObserver struct{}

func (noopDiscoveryObserver) SubmitDiscovery(string, *agentv1.DiscoveryReport) error { return nil }

var _ DiscoveryObserver = (*DiscoveryDispatcher)(nil)
