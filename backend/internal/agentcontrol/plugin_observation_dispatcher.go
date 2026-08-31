package agentcontrol

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"google.golang.org/protobuf/proto"
)

var (
	ErrPluginObservationCapacity = errors.New("PLUGIN_OBSERVATION_PENDING_AGENT_CAPACITY")
	ErrPluginObservationClosed   = errors.New("PLUGIN_OBSERVATION_DISPATCHER_CLOSED")
	ErrPluginObservationInvalid  = errors.New("PLUGIN_OBSERVATION_INVALID")
)

const maximumPluginObservationBytes = 1 << 20

type PluginObservationSink interface {
	RecordPluginObservation(context.Context, string, *agentv1.PluginObservation) error
}
type PluginObservationDispatcherConfig struct {
	MaximumPendingAgents          int
	DeliveryTimeout, RetryBackoff time.Duration
	OnError                       func(error)
}
type pluginObservationRevision struct {
	revision uint64
	digest   [sha256.Size]byte
}
type pluginObservationLane struct {
	agentID        string
	dispatcher     *PluginObservationDispatcher
	wake           chan struct{}
	pending        *agentv1.PluginObservation
	pendingDigest  [sha256.Size]byte
	activeRevision uint64
	activeDigest   [sha256.Size]byte
	quarantined    bool
}
type PluginObservationDispatcher struct {
	sink      PluginObservationSink
	config    PluginObservationDispatcherConfig
	mu        sync.Mutex
	lanes     map[string]*pluginObservationLane
	last      map[string]pluginObservationRevision
	lastOrder []string
	closed    bool
	stop      chan struct{}
}

func NewPluginObservationDispatcher(sink PluginObservationSink, config PluginObservationDispatcherConfig) (*PluginObservationDispatcher, error) {
	if sink == nil {
		return nil, ErrPluginObservationInvalid
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
		return nil, ErrPluginObservationInvalid
	}
	return &PluginObservationDispatcher{sink: sink, config: config, lanes: map[string]*pluginObservationLane{}, last: map[string]pluginObservationRevision{}, stop: make(chan struct{})}, nil
}

func (dispatcher *PluginObservationDispatcher) SubmitPlugin(agentID string, report *agentv1.PluginObservation) error {
	if dispatcher == nil || !validPluginObservation(agentID, report) {
		return ErrPluginObservationInvalid
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil || len(encoded) > maximumPluginObservationBytes {
		return ErrPluginObservationInvalid
	}
	digest := sha256.Sum256(encoded)
	clone := proto.Clone(report).(*agentv1.PluginObservation)
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.closed {
		return ErrPluginObservationClosed
	}
	if previous, ok := dispatcher.last[agentID]; ok {
		if report.GetObservationRevision() < previous.revision {
			return ErrPluginObservationInvalid
		}
		if report.GetObservationRevision() == previous.revision {
			if digest != previous.digest {
				return ErrPluginObservationInvalid
			}
			return nil
		}
	}
	lane := dispatcher.lanes[agentID]
	if lane == nil {
		if len(dispatcher.lanes) >= dispatcher.config.MaximumPendingAgents {
			return ErrPluginObservationCapacity
		}
		lane = &pluginObservationLane{agentID: agentID, dispatcher: dispatcher, wake: make(chan struct{}, 1)}
		dispatcher.lanes[agentID] = lane
		go lane.run()
	}
	if lane.quarantined {
		return ErrPluginObservationCapacity
	}
	highest, highestDigest := lane.activeRevision, lane.activeDigest
	if lane.pending != nil && lane.pending.GetObservationRevision() >= highest {
		highest, highestDigest = lane.pending.GetObservationRevision(), lane.pendingDigest
	}
	if report.GetObservationRevision() < highest {
		return ErrPluginObservationInvalid
	}
	if report.GetObservationRevision() == highest && highest != 0 {
		if digest != highestDigest {
			return ErrPluginObservationInvalid
		}
		return nil
	}
	lane.pending, lane.pendingDigest = clone, digest
	select {
	case lane.wake <- struct{}{}:
	default:
	}
	return nil
}

func (dispatcher *PluginObservationDispatcher) Close() {
	if dispatcher == nil {
		return
	}
	dispatcher.mu.Lock()
	if !dispatcher.closed {
		dispatcher.closed = true
		close(dispatcher.stop)
	}
	dispatcher.mu.Unlock()
}

func (lane *pluginObservationLane) run() {
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
func (lane *pluginObservationLane) take() (*agentv1.PluginObservation, [sha256.Size]byte, bool) {
	lane.dispatcher.mu.Lock()
	defer lane.dispatcher.mu.Unlock()
	if lane.pending == nil {
		return nil, [sha256.Size]byte{}, false
	}
	report, digest := lane.pending, lane.pendingDigest
	lane.pending = nil
	lane.pendingDigest = [sha256.Size]byte{}
	lane.activeRevision, lane.activeDigest = report.GetObservationRevision(), digest
	return report, digest, true
}
func (lane *pluginObservationLane) deliver(report *agentv1.PluginObservation, digest [sha256.Size]byte) bool {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), lane.dispatcher.config.DeliveryTimeout)
		result := make(chan error, 1)
		go func() { result <- lane.dispatcher.sink.RecordPluginObservation(ctx, lane.agentID, report) }()
		select {
		case err := <-result:
			cancel()
			if err == nil {
				lane.persisted(report, digest)
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
func (lane *pluginObservationLane) awaitQuarantined(result <-chan error, report *agentv1.PluginObservation, digest [sha256.Size]byte) {
	err := <-result
	if err == nil {
		lane.persisted(report, digest)
	} else if lane.dispatcher.config.OnError != nil {
		lane.dispatcher.config.OnError(err)
	}
	lane.dispatcher.mu.Lock()
	lane.activeRevision = 0
	lane.activeDigest = [sha256.Size]byte{}
	lane.quarantined = false
	closed := lane.dispatcher.closed
	hasPending := lane.pending != nil
	if !hasPending {
		delete(lane.dispatcher.lanes, lane.agentID)
	}
	lane.dispatcher.mu.Unlock()
	if !closed && hasPending {
		select {
		case lane.wake <- struct{}{}:
		default:
		}
		go lane.run()
	}
}
func (lane *pluginObservationLane) persisted(report *agentv1.PluginObservation, digest [sha256.Size]byte) {
	lane.dispatcher.mu.Lock()
	defer lane.dispatcher.mu.Unlock()
	lane.dispatcher.last[lane.agentID] = pluginObservationRevision{revision: report.GetObservationRevision(), digest: digest}
	for index, value := range lane.dispatcher.lastOrder {
		if value == lane.agentID {
			lane.dispatcher.lastOrder = append(lane.dispatcher.lastOrder[:index], lane.dispatcher.lastOrder[index+1:]...)
			break
		}
	}
	lane.dispatcher.lastOrder = append(lane.dispatcher.lastOrder, lane.agentID)
	maximum := lane.dispatcher.config.MaximumPendingAgents * 4
	for len(lane.dispatcher.lastOrder) > maximum {
		old := lane.dispatcher.lastOrder[0]
		lane.dispatcher.lastOrder = lane.dispatcher.lastOrder[1:]
		if _, active := lane.dispatcher.lanes[old]; !active {
			delete(lane.dispatcher.last, old)
		}
	}
}
func (lane *pluginObservationLane) clearActive() {
	lane.dispatcher.mu.Lock()
	lane.activeRevision = 0
	lane.activeDigest = [sha256.Size]byte{}
	lane.dispatcher.mu.Unlock()
}
func (lane *pluginObservationLane) retire() bool {
	lane.dispatcher.mu.Lock()
	defer lane.dispatcher.mu.Unlock()
	if lane.pending != nil || lane.activeRevision != 0 || lane.quarantined {
		return false
	}
	delete(lane.dispatcher.lanes, lane.agentID)
	return true
}

func validPluginObservation(agentID string, report *agentv1.PluginObservation) bool {
	if report == nil || agentID == "" || report.GetAgentId() != agentID || report.GetHostId() == "" || report.GetObservationRevision() == 0 || report.GetObservedAt() == nil || !report.GetObservedAt().IsValid() || len(report.GetAssignments()) > 128 {
		return false
	}
	seen := map[string]struct{}{}
	for _, assignment := range report.GetAssignments() {
		if assignment == nil || assignment.GetAssignmentId() == "" || assignment.GetPluginId() == "" || assignment.GetDatabaseFamily() == "" || assignment.GetObservedAt() == nil || !assignment.GetObservedAt().IsValid() {
			return false
		}
		if _, duplicate := seen[assignment.GetAssignmentId()]; duplicate {
			return false
		}
		seen[assignment.GetAssignmentId()] = struct{}{}
	}
	return true
}

var _ PluginObserver = (*PluginObservationDispatcher)(nil)
