package agentcontrol

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
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

type DiscoveryDispatcherConfig struct {
	MaximumPendingAgents int
	DeliveryTimeout      time.Duration
	RetryBackoff         time.Duration
	OnError              func(error)
}

type DiscoveryDispatcher struct {
	sink    DiscoveryReportSink
	config  DiscoveryDispatcherConfig
	mu      sync.Mutex
	pending map[string]*agentv1.DiscoveryReport
	notify  chan struct{}
	stop    chan struct{}
	done    chan struct{}
	closed  bool
}

func NewDiscoveryDispatcher(sink DiscoveryReportSink, config DiscoveryDispatcherConfig) (*DiscoveryDispatcher, error) {
	if sink == nil {
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
	dispatcher := &DiscoveryDispatcher{sink: sink, config: config, pending: make(map[string]*agentv1.DiscoveryReport), notify: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go dispatcher.run()
	return dispatcher, nil
}

func (dispatcher *DiscoveryDispatcher) SubmitDiscovery(agentID string, report *agentv1.DiscoveryReport) error {
	if !validDiscoveryReport(agentID, report) {
		return ErrDiscoveryObservationInvalid
	}
	clone := proto.Clone(report).(*agentv1.DiscoveryReport)
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.closed {
		return ErrDiscoveryObservationClosed
	}
	if current, exists := dispatcher.pending[agentID]; exists && current.GetObservationRevision() > clone.GetObservationRevision() {
		return ErrDiscoveryObservationInvalid
	}
	if _, exists := dispatcher.pending[agentID]; !exists && len(dispatcher.pending) >= dispatcher.config.MaximumPendingAgents {
		return ErrDiscoveryObservationCapacity
	}
	dispatcher.pending[agentID] = clone
	select {
	case dispatcher.notify <- struct{}{}:
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
	<-dispatcher.done
}

func (dispatcher *DiscoveryDispatcher) run() {
	defer close(dispatcher.done)
	for {
		select {
		case <-dispatcher.notify:
			for {
				agentID, report, ok := dispatcher.take()
				if !ok {
					break
				}
				ctx, cancel := context.WithTimeout(context.Background(), dispatcher.config.DeliveryTimeout)
				err := dispatcher.sink.RecordDiscoveryReport(ctx, agentID, report)
				cancel()
				if err != nil {
					if dispatcher.config.OnError != nil {
						dispatcher.config.OnError(err)
					}
					dispatcher.requeue(agentID, report)
					timer := time.NewTimer(dispatcher.config.RetryBackoff)
					select {
					case <-timer.C:
					case <-dispatcher.stop:
						timer.Stop()
						return
					}
					break
				}
			}
		case <-dispatcher.stop:
			return
		}
	}
}

func (dispatcher *DiscoveryDispatcher) take() (string, *agentv1.DiscoveryReport, bool) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if len(dispatcher.pending) == 0 {
		return "", nil, false
	}
	keys := make([]string, 0, len(dispatcher.pending))
	for key := range dispatcher.pending {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	key := keys[0]
	value := dispatcher.pending[key]
	delete(dispatcher.pending, key)
	return key, value, true
}
func (dispatcher *DiscoveryDispatcher) requeue(agentID string, report *agentv1.DiscoveryReport) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.closed {
		return
	}
	if current := dispatcher.pending[agentID]; current == nil || current.GetObservationRevision() < report.GetObservationRevision() {
		dispatcher.pending[agentID] = report
	}
	select {
	case dispatcher.notify <- struct{}{}:
	default:
	}
}

func validDiscoveryReport(agentID string, report *agentv1.DiscoveryReport) bool {
	if !hostObservationAgentID.MatchString(agentID) || report == nil || report.GetAgentId() != agentID || !hostObservationAgentID.MatchString(report.GetHostId()) || report.GetObservationRevision() == 0 || report.GetRuleRevision() == 0 || report.GetObservedAt() == nil || !report.GetObservedAt().IsValid() || len(report.GetCandidates()) > 1024 {
		return false
	}
	for _, candidate := range report.GetCandidates() {
		if candidate == nil || candidate.GetSource() == agentv1.DiscoverySource_DISCOVERY_SOURCE_UNSPECIFIED || candidate.GetDatabaseFamily() == "" || candidate.GetDatabaseVariant() == "" || len(candidate.GetFingerprint()) != 32 || candidate.GetObservedAt() == nil || !candidate.GetObservedAt().IsValid() || len(candidate.GetEvidence()) > 32 {
			return false
		}
	}
	return true
}

type noopDiscoveryObserver struct{}

func (noopDiscoveryObserver) SubmitDiscovery(string, *agentv1.DiscoveryReport) error { return nil }

var _ DiscoveryObserver = (*DiscoveryDispatcher)(nil)
