package agentcontrol

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"google.golang.org/protobuf/proto"
)

var (
	ErrHostObservationCapacity = errors.New("HOST_OBSERVATION_PENDING_HOST_CAPACITY")
	ErrHostObservationClosed   = errors.New("HOST_OBSERVATION_DISPATCHER_CLOSED")
	ErrHostObservationInvalid  = errors.New("HOST_OBSERVATION_INVALID")
)

var hostObservationAgentID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type HostObservationSink interface {
	RecordHello(context.Context, string, time.Time) error
	RecordHeartbeat(context.Context, string, time.Time) error
	RecordObservation(context.Context, string, *agentv1.HostObservation) error
}

type HostObserver interface {
	SubmitHello(string, time.Time) error
	SubmitHeartbeat(string, time.Time) error
	SubmitObservation(string, *agentv1.HostObservation) error
}

type HostObservationDispatcherConfig struct {
	MaximumPendingHosts int
	DeliveryTimeout     time.Duration
	RetryBackoff        time.Duration
	OnError             func(error)
}

type HostObservationLaneStats struct {
	Accepted        uint64
	Coalesced       uint64
	RejectedNewKeys uint64
	Delivered       uint64
	Failed          uint64
	Retried         uint64
	Discarded       uint64
}

type HostObservationDispatcherStats struct {
	Accepted        uint64
	Coalesced       uint64
	RejectedNewKeys uint64
	Delivered       uint64
	Failed          uint64
	Retried         uint64
	Discarded       uint64
	Observation     HostObservationLaneStats
	Hello           HostObservationLaneStats
	Heartbeat       HostObservationLaneStats
}

type HostObservationCloseReport struct {
	ObservationDiscarded uint64
	HelloDiscarded       uint64
	HeartbeatDiscarded   uint64
}

func (report HostObservationCloseReport) TotalDiscarded() uint64 {
	return report.ObservationDiscarded + report.HelloDiscarded + report.HeartbeatDiscarded
}

type hostLaneKind uint8

const (
	hostLaneObservation hostLaneKind = iota + 1
	hostLaneHello
	hostLaneHeartbeat
)

type hostLaneEvent struct {
	agentID     string
	at          time.Time
	observation *agentv1.HostObservation
}

type pendingHostLaneEvent struct {
	event   hostLaneEvent
	retryAt time.Time
}

type hostLaneAttempt struct {
	event    hostLaneEvent
	timedOut bool
}

type hostLaneDeliveryResult struct {
	agentID string
	err     error
}

type hostObservationLane struct {
	kind            hostLaneKind
	sink            HostObservationSink
	maximumPending  int
	deliveryTimeout time.Duration
	retryBackoff    time.Duration
	onError         func(error)

	mu        sync.Mutex
	pending   map[string]pendingHostLaneEvent
	queue     []string
	queued    map[string]bool
	active    map[string]hostLaneAttempt
	started   bool
	accepting bool
	closing   bool
	aborted   bool
	wake      chan struct{}
	results   chan hostLaneDeliveryResult
	done      chan struct{}
	doneOnce  sync.Once
	cancel    context.CancelFunc

	accepted        atomic.Uint64
	coalesced       atomic.Uint64
	rejectedNewKeys atomic.Uint64
	delivered       atomic.Uint64
	failed          atomic.Uint64
	retried         atomic.Uint64
	discarded       atomic.Uint64
}

type HostObservationDispatcher struct {
	observation *hostObservationLane
	hello       *hostObservationLane
	heartbeat   *hostObservationLane
	mu          sync.Mutex
	started     bool
	closed      bool
}

func NewHostObservationDispatcher(sink HostObservationSink, config HostObservationDispatcherConfig) (*HostObservationDispatcher, error) {
	if sink == nil || config.MaximumPendingHosts < 1 || config.MaximumPendingHosts > 100000 || config.DeliveryTimeout <= 0 || config.RetryBackoff < 0 {
		return nil, ErrHostObservationInvalid
	}
	retryBackoff := config.RetryBackoff
	if retryBackoff == 0 {
		retryBackoff = 100 * time.Millisecond
	}
	newLane := func(kind hostLaneKind) *hostObservationLane {
		return &hostObservationLane{
			kind: kind, sink: sink, maximumPending: config.MaximumPendingHosts, deliveryTimeout: config.DeliveryTimeout,
			retryBackoff: retryBackoff, onError: config.OnError, pending: make(map[string]pendingHostLaneEvent),
			queued: make(map[string]bool), active: make(map[string]hostLaneAttempt), queue: make([]string, 0, config.MaximumPendingHosts),
			wake: make(chan struct{}, 1), results: make(chan hostLaneDeliveryResult, config.MaximumPendingHosts), done: make(chan struct{}),
		}
	}
	return &HostObservationDispatcher{
		observation: newLane(hostLaneObservation), hello: newLane(hostLaneHello), heartbeat: newLane(hostLaneHeartbeat),
	}, nil
}

func (dispatcher *HostObservationDispatcher) Start(ctx context.Context) error {
	if dispatcher == nil || ctx == nil {
		return ErrHostObservationInvalid
	}
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.started || dispatcher.closed {
		return ErrHostObservationInvalid
	}
	for _, lane := range dispatcher.lanes() {
		lane.start(ctx)
	}
	dispatcher.started = true
	return nil
}

func (dispatcher *HostObservationDispatcher) SubmitHello(agentID string, at time.Time) error {
	if dispatcher == nil || !validHostLaneTime(agentID, at) {
		return ErrHostObservationInvalid
	}
	return dispatcher.hello.submit(hostLaneEvent{agentID: agentID, at: at})
}

func (dispatcher *HostObservationDispatcher) SubmitHeartbeat(agentID string, at time.Time) error {
	if dispatcher == nil || !validHostLaneTime(agentID, at) {
		return ErrHostObservationInvalid
	}
	return dispatcher.heartbeat.submit(hostLaneEvent{agentID: agentID, at: at})
}

func (dispatcher *HostObservationDispatcher) SubmitObservation(agentID string, observation *agentv1.HostObservation) error {
	if dispatcher == nil || observation == nil || observation.GetAgentId() != agentID || !hostObservationAgentID.MatchString(agentID) ||
		!hostObservationAgentID.MatchString(observation.GetHostId()) || observation.GetObservationRevision() == 0 {
		return ErrHostObservationInvalid
	}
	return dispatcher.observation.submit(hostLaneEvent{agentID: agentID, observation: proto.Clone(observation).(*agentv1.HostObservation)})
}

func (dispatcher *HostObservationDispatcher) Close(ctx context.Context) (HostObservationCloseReport, error) {
	if dispatcher == nil || ctx == nil {
		return HostObservationCloseReport{}, ErrHostObservationInvalid
	}
	dispatcher.mu.Lock()
	if !dispatcher.started {
		dispatcher.closed = true
		dispatcher.mu.Unlock()
		return HostObservationCloseReport{}, nil
	}
	if !dispatcher.closed {
		dispatcher.closed = true
		for _, lane := range dispatcher.lanes() {
			lane.beginClose()
		}
	}
	dispatcher.mu.Unlock()

	allDone := make(chan struct{})
	go func() {
		for _, lane := range dispatcher.lanes() {
			<-lane.done
		}
		close(allDone)
	}()
	var closeErr error
	select {
	case <-allDone:
	case <-ctx.Done():
		closeErr = ctx.Err()
		for _, lane := range dispatcher.lanes() {
			lane.abort()
		}
		<-allDone
	}
	report := HostObservationCloseReport{
		ObservationDiscarded: dispatcher.observation.discarded.Load(),
		HelloDiscarded:       dispatcher.hello.discarded.Load(),
		HeartbeatDiscarded:   dispatcher.heartbeat.discarded.Load(),
	}
	return report, closeErr
}

func (dispatcher *HostObservationDispatcher) Stats() HostObservationDispatcherStats {
	if dispatcher == nil {
		return HostObservationDispatcherStats{}
	}
	observation := dispatcher.observation.stats()
	hello := dispatcher.hello.stats()
	heartbeat := dispatcher.heartbeat.stats()
	return HostObservationDispatcherStats{
		Accepted:        observation.Accepted + hello.Accepted + heartbeat.Accepted,
		Coalesced:       observation.Coalesced + hello.Coalesced + heartbeat.Coalesced,
		RejectedNewKeys: observation.RejectedNewKeys + hello.RejectedNewKeys + heartbeat.RejectedNewKeys,
		Delivered:       observation.Delivered + hello.Delivered + heartbeat.Delivered,
		Failed:          observation.Failed + hello.Failed + heartbeat.Failed,
		Retried:         observation.Retried + hello.Retried + heartbeat.Retried,
		Discarded:       observation.Discarded + hello.Discarded + heartbeat.Discarded,
		Observation:     observation, Hello: hello, Heartbeat: heartbeat,
	}
}

func (dispatcher *HostObservationDispatcher) lanes() []*hostObservationLane {
	return []*hostObservationLane{dispatcher.observation, dispatcher.hello, dispatcher.heartbeat}
}

func (lane *hostObservationLane) start(parent context.Context) {
	lane.mu.Lock()
	workerContext, cancel := context.WithCancel(parent)
	lane.started, lane.accepting, lane.cancel = true, true, cancel
	lane.mu.Unlock()
	go lane.run(workerContext)
}

func (lane *hostObservationLane) submit(event hostLaneEvent) error {
	lane.mu.Lock()
	defer lane.mu.Unlock()
	if !lane.started || !lane.accepting {
		return ErrHostObservationClosed
	}
	pending, pendingExists := lane.pending[event.agentID]
	active, activeSameKey := lane.active[event.agentID]
	if !pendingExists && !activeSameKey && lane.distinctKeysLocked() >= lane.maximumPending {
		lane.rejectedNewKeys.Add(1)
		return ErrHostObservationCapacity
	}
	if pendingExists || activeSameKey {
		lane.coalesced.Add(1)
	}
	if pendingExists {
		event = mergeHostLaneEvent(lane.kind, pending.event, event)
	} else if activeSameKey {
		event = mergeHostLaneEvent(lane.kind, active.event, event)
	}
	lane.pending[event.agentID] = pendingHostLaneEvent{event: cloneHostLaneEvent(event)}
	if !activeSameKey {
		lane.enqueueLocked(event.agentID)
	}
	lane.accepted.Add(1)
	lane.signalLocked()
	return nil
}

func (lane *hostObservationLane) run(ctx context.Context) {
	for {
		event, wait, ok, finish := lane.next(time.Now())
		if finish {
			lane.finish()
			return
		}
		if !ok {
			if !lane.wait(ctx, wait) {
				lane.abort()
				return
			}
			continue
		}
		if !lane.deliver(ctx, event) {
			lane.abort()
			return
		}
	}
}

func (lane *hostObservationLane) next(now time.Time) (hostLaneEvent, time.Duration, bool, bool) {
	lane.mu.Lock()
	defer lane.mu.Unlock()
	if lane.aborted {
		return hostLaneEvent{}, 0, false, true
	}
	var selected string
	var earliest time.Time
	queueLength := len(lane.queue)
	for index := 0; index < queueLength; index++ {
		agentID := lane.queue[0]
		lane.queue = lane.queue[1:]
		lane.queued[agentID] = false
		pending, exists := lane.pending[agentID]
		if !exists {
			continue
		}
		if _, active := lane.active[agentID]; active {
			continue
		}
		if !pending.retryAt.IsZero() && pending.retryAt.After(now) {
			lane.enqueueLocked(agentID)
			if earliest.IsZero() || pending.retryAt.Before(earliest) {
				earliest = pending.retryAt
			}
			continue
		}
		selected = agentID
		break
	}
	if selected != "" {
		pending := lane.pending[selected]
		delete(lane.pending, selected)
		event := cloneHostLaneEvent(pending.event)
		lane.active[selected] = hostLaneAttempt{event: event}
		return event, 0, true, false
	}
	if lane.closing && len(lane.pending) == 0 && len(lane.active) == 0 {
		return hostLaneEvent{}, 0, false, true
	}
	if !earliest.IsZero() {
		return hostLaneEvent{}, time.Until(earliest), false, false
	}
	return hostLaneEvent{}, 0, false, false
}

func (lane *hostObservationLane) wait(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		select {
		case <-lane.wake:
			return true
		case result := <-lane.results:
			lane.completeDelivery(result)
			return true
		case <-ctx.Done():
			return false
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-lane.wake:
		return true
	case result := <-lane.results:
		lane.completeDelivery(result)
		return true
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (lane *hostObservationLane) deliver(parent context.Context, event hostLaneEvent) bool {
	deliveryContext, cancel := context.WithTimeout(parent, lane.deliveryTimeout)
	go func() {
		lane.results <- hostLaneDeliveryResult{agentID: event.agentID, err: lane.callSink(deliveryContext, event)}
	}()
	defer cancel()
	for {
		select {
		case result := <-lane.results:
			if result.agentID == event.agentID {
				lane.completeDelivery(result)
				return true
			}
			lane.completeDelivery(result)
		case <-deliveryContext.Done():
			if parent.Err() != nil {
				return false
			}
			lane.timeoutDelivery(event, deliveryContext.Err())
			return true
		}
	}
}

func (lane *hostObservationLane) callSink(ctx context.Context, event hostLaneEvent) error {
	switch lane.kind {
	case hostLaneObservation:
		return lane.sink.RecordObservation(ctx, event.agentID, proto.Clone(event.observation).(*agentv1.HostObservation))
	case hostLaneHello:
		return lane.sink.RecordHello(ctx, event.agentID, event.at)
	case hostLaneHeartbeat:
		return lane.sink.RecordHeartbeat(ctx, event.agentID, event.at)
	default:
		return ErrHostObservationInvalid
	}
}

func (lane *hostObservationLane) timeoutDelivery(event hostLaneEvent, deliveryErr error) {
	var reportErr error
	lane.mu.Lock()
	if lane.aborted {
		lane.mu.Unlock()
		return
	}
	attempt, exists := lane.active[event.agentID]
	if !exists || attempt.timedOut {
		lane.mu.Unlock()
		return
	}
	attempt.timedOut = true
	lane.active[event.agentID] = attempt
	pending, pendingExists := lane.pending[event.agentID]
	if pendingExists {
		event = mergeHostLaneEvent(lane.kind, event, pending.event)
	}
	lane.pending[event.agentID] = pendingHostLaneEvent{event: cloneHostLaneEvent(event), retryAt: time.Now().Add(lane.retryBackoff)}
	lane.failed.Add(1)
	lane.retried.Add(1)
	reportErr = deliveryErr
	lane.signalLocked()
	lane.mu.Unlock()
	if reportErr != nil && lane.onError != nil {
		lane.onError(reportErr)
	}
}

func (lane *hostObservationLane) completeDelivery(result hostLaneDeliveryResult) {
	var reportErr error
	lane.mu.Lock()
	if lane.aborted {
		lane.mu.Unlock()
		return
	}
	attempt, exists := lane.active[result.agentID]
	if !exists {
		lane.mu.Unlock()
		return
	}
	delete(lane.active, result.agentID)
	if attempt.timedOut {
		if _, pending := lane.pending[result.agentID]; pending {
			lane.enqueueLocked(result.agentID)
		}
		lane.signalLocked()
		lane.mu.Unlock()
		return
	}
	if result.err == nil {
		lane.delivered.Add(1)
		if _, pending := lane.pending[result.agentID]; pending {
			lane.enqueueLocked(result.agentID)
		}
	} else {
		lane.failed.Add(1)
		lane.retried.Add(1)
		event := attempt.event
		if pending, pendingExists := lane.pending[result.agentID]; pendingExists {
			event = mergeHostLaneEvent(lane.kind, event, pending.event)
		}
		lane.pending[result.agentID] = pendingHostLaneEvent{event: cloneHostLaneEvent(event), retryAt: time.Now().Add(lane.retryBackoff)}
		lane.enqueueLocked(result.agentID)
		reportErr = result.err
	}
	lane.signalLocked()
	lane.mu.Unlock()
	if reportErr != nil && lane.onError != nil {
		lane.onError(reportErr)
	}
}

func (lane *hostObservationLane) beginClose() {
	lane.mu.Lock()
	lane.accepting = false
	lane.closing = true
	lane.signalLocked()
	lane.mu.Unlock()
}

func (lane *hostObservationLane) abort() {
	lane.mu.Lock()
	if lane.aborted {
		lane.mu.Unlock()
		return
	}
	lane.accepting, lane.aborted = false, true
	keys := make(map[string]struct{}, len(lane.pending)+len(lane.active))
	for agentID := range lane.pending {
		keys[agentID] = struct{}{}
	}
	for agentID := range lane.active {
		keys[agentID] = struct{}{}
	}
	lane.discarded.Add(uint64(len(keys)))
	lane.pending = make(map[string]pendingHostLaneEvent)
	lane.active = make(map[string]hostLaneAttempt)
	lane.queue = nil
	lane.queued = make(map[string]bool)
	cancel := lane.cancel
	lane.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	lane.finish()
}

func (lane *hostObservationLane) finish() {
	lane.doneOnce.Do(func() { close(lane.done) })
}

func (lane *hostObservationLane) signalLocked() {
	select {
	case lane.wake <- struct{}{}:
	default:
	}
}

func (lane *hostObservationLane) enqueueLocked(agentID string) {
	if lane.queued[agentID] {
		return
	}
	lane.queue = append(lane.queue, agentID)
	lane.queued[agentID] = true
}

func (lane *hostObservationLane) distinctKeysLocked() int {
	count := len(lane.pending)
	for agentID := range lane.active {
		if _, pending := lane.pending[agentID]; !pending {
			count++
		}
	}
	return count
}

func (lane *hostObservationLane) stats() HostObservationLaneStats {
	return HostObservationLaneStats{
		Accepted: lane.accepted.Load(), Coalesced: lane.coalesced.Load(), RejectedNewKeys: lane.rejectedNewKeys.Load(),
		Delivered: lane.delivered.Load(), Failed: lane.failed.Load(), Retried: lane.retried.Load(), Discarded: lane.discarded.Load(),
	}
}

func mergeHostLaneEvent(kind hostLaneKind, first, second hostLaneEvent) hostLaneEvent {
	if kind == hostLaneObservation {
		if first.observation == nil || (second.observation != nil && second.observation.GetObservationRevision() > first.observation.GetObservationRevision()) {
			return cloneHostLaneEvent(second)
		}
		return cloneHostLaneEvent(first)
	}
	if second.at.After(first.at) {
		return cloneHostLaneEvent(second)
	}
	return cloneHostLaneEvent(first)
}

func cloneHostLaneEvent(event hostLaneEvent) hostLaneEvent {
	clone := event
	if event.observation != nil {
		clone.observation = proto.Clone(event.observation).(*agentv1.HostObservation)
	}
	return clone
}

func validHostLaneTime(agentID string, at time.Time) bool {
	return hostObservationAgentID.MatchString(agentID) && !at.IsZero() && at.Location() == time.UTC
}

type noopHostObserver struct{}

func (noopHostObserver) SubmitHello(string, time.Time) error                      { return nil }
func (noopHostObserver) SubmitHeartbeat(string, time.Time) error                  { return nil }
func (noopHostObserver) SubmitObservation(string, *agentv1.HostObservation) error { return nil }

var _ HostObserver = (*HostObservationDispatcher)(nil)
