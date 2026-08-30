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
	OnError             func(error)
}

type HostObservationDispatcherStats struct {
	Accepted        uint64
	Coalesced       uint64
	RejectedNewKeys uint64
	Delivered       uint64
	Failed          uint64
}

type hostObservationEvent struct {
	agentID     string
	helloAt     time.Time
	heartbeatAt time.Time
	observation *agentv1.HostObservation
}

type HostObservationDispatcher struct {
	sink            HostObservationSink
	maximumPending  int
	deliveryTimeout time.Duration
	onError         func(error)

	mu        sync.Mutex
	pending   map[string]hostObservationEvent
	started   bool
	accepting bool
	closing   bool
	finished  bool
	wake      chan struct{}
	done      chan struct{}
	cancel    context.CancelFunc

	accepted        atomic.Uint64
	coalesced       atomic.Uint64
	rejectedNewKeys atomic.Uint64
	delivered       atomic.Uint64
	failed          atomic.Uint64
}

func NewHostObservationDispatcher(sink HostObservationSink, config HostObservationDispatcherConfig) (*HostObservationDispatcher, error) {
	if sink == nil || config.MaximumPendingHosts < 1 || config.MaximumPendingHosts > 100000 || config.DeliveryTimeout <= 0 {
		return nil, ErrHostObservationInvalid
	}
	return &HostObservationDispatcher{
		sink: sink, maximumPending: config.MaximumPendingHosts, deliveryTimeout: config.DeliveryTimeout, onError: config.OnError,
		pending: make(map[string]hostObservationEvent), wake: make(chan struct{}, 1), done: make(chan struct{}),
	}, nil
}

func (dispatcher *HostObservationDispatcher) Start(ctx context.Context) error {
	if dispatcher == nil || ctx == nil {
		return ErrHostObservationInvalid
	}
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.started {
		return ErrHostObservationInvalid
	}
	workerContext, cancel := context.WithCancel(ctx)
	dispatcher.started, dispatcher.accepting, dispatcher.cancel = true, true, cancel
	go dispatcher.run(workerContext)
	return nil
}

func (dispatcher *HostObservationDispatcher) SubmitHello(agentID string, at time.Time) error {
	return dispatcher.submit(hostObservationEvent{agentID: agentID, helloAt: at})
}

func (dispatcher *HostObservationDispatcher) SubmitHeartbeat(agentID string, at time.Time) error {
	return dispatcher.submit(hostObservationEvent{agentID: agentID, heartbeatAt: at})
}

func (dispatcher *HostObservationDispatcher) SubmitObservation(agentID string, observation *agentv1.HostObservation) error {
	if observation == nil || observation.GetAgentId() != agentID || !hostObservationAgentID.MatchString(observation.GetHostId()) || observation.GetObservationRevision() == 0 {
		return ErrHostObservationInvalid
	}
	return dispatcher.submit(hostObservationEvent{agentID: agentID, observation: proto.Clone(observation).(*agentv1.HostObservation)})
}

func (dispatcher *HostObservationDispatcher) submit(event hostObservationEvent) error {
	if dispatcher == nil || !hostObservationAgentID.MatchString(event.agentID) ||
		(event.helloAt.IsZero() && event.heartbeatAt.IsZero() && event.observation == nil) ||
		(!event.helloAt.IsZero() && event.helloAt.Location() != time.UTC) ||
		(!event.heartbeatAt.IsZero() && event.heartbeatAt.Location() != time.UTC) {
		return ErrHostObservationInvalid
	}
	dispatcher.mu.Lock()
	if !dispatcher.started || !dispatcher.accepting {
		dispatcher.mu.Unlock()
		return ErrHostObservationClosed
	}
	pending, exists := dispatcher.pending[event.agentID]
	if !exists && len(dispatcher.pending) >= dispatcher.maximumPending {
		dispatcher.rejectedNewKeys.Add(1)
		dispatcher.mu.Unlock()
		return ErrHostObservationCapacity
	}
	if exists {
		dispatcher.coalesced.Add(1)
	}
	pending.agentID = event.agentID
	if event.helloAt.After(pending.helloAt) {
		pending.helloAt = event.helloAt
	}
	if event.heartbeatAt.After(pending.heartbeatAt) {
		pending.heartbeatAt = event.heartbeatAt
	}
	if event.observation != nil && (pending.observation == nil || event.observation.GetObservationRevision() > pending.observation.GetObservationRevision()) {
		pending.observation = proto.Clone(event.observation).(*agentv1.HostObservation)
	}
	dispatcher.pending[event.agentID] = pending
	dispatcher.accepted.Add(1)
	dispatcher.signalLocked()
	dispatcher.mu.Unlock()
	return nil
}

func (dispatcher *HostObservationDispatcher) Close(ctx context.Context) error {
	if dispatcher == nil || ctx == nil {
		return ErrHostObservationInvalid
	}
	dispatcher.mu.Lock()
	if !dispatcher.started {
		dispatcher.accepting = false
		dispatcher.mu.Unlock()
		return nil
	}
	dispatcher.accepting = false
	dispatcher.closing = true
	dispatcher.signalLocked()
	done := dispatcher.done
	cancelWorker := dispatcher.cancel
	dispatcher.mu.Unlock()
	select {
	case <-done:
		cancelWorker()
		return nil
	case <-ctx.Done():
		cancelWorker()
		return ctx.Err()
	}
}

func (dispatcher *HostObservationDispatcher) Stats() HostObservationDispatcherStats {
	if dispatcher == nil {
		return HostObservationDispatcherStats{}
	}
	return HostObservationDispatcherStats{
		Accepted: dispatcher.accepted.Load(), Coalesced: dispatcher.coalesced.Load(), RejectedNewKeys: dispatcher.rejectedNewKeys.Load(),
		Delivered: dispatcher.delivered.Load(), Failed: dispatcher.failed.Load(),
	}
}

func (dispatcher *HostObservationDispatcher) run(ctx context.Context) {
	for {
		select {
		case <-dispatcher.wake:
		case <-ctx.Done():
			dispatcher.finish()
			return
		}
		for {
			event, ok, shouldFinish := dispatcher.take()
			if shouldFinish {
				dispatcher.finish()
				return
			}
			if !ok {
				break
			}
			deliveryContext, cancel := context.WithTimeout(ctx, dispatcher.deliveryTimeout)
			err := dispatcher.deliver(deliveryContext, event)
			cancel()
			if err != nil {
				dispatcher.failed.Add(1)
				if dispatcher.onError != nil {
					dispatcher.onError(err)
				}
			} else {
				dispatcher.delivered.Add(1)
			}
		}
	}
}

func (dispatcher *HostObservationDispatcher) take() (hostObservationEvent, bool, bool) {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	for agentID, event := range dispatcher.pending {
		delete(dispatcher.pending, agentID)
		return event, true, false
	}
	return hostObservationEvent{}, false, dispatcher.closing
}

func (dispatcher *HostObservationDispatcher) deliver(ctx context.Context, event hostObservationEvent) error {
	var deliveryErrors []error
	if event.observation != nil {
		if err := dispatcher.sink.RecordObservation(ctx, event.agentID, proto.Clone(event.observation).(*agentv1.HostObservation)); err != nil {
			deliveryErrors = append(deliveryErrors, err)
		}
	}
	if !event.helloAt.IsZero() {
		if err := dispatcher.sink.RecordHello(ctx, event.agentID, event.helloAt); err != nil {
			deliveryErrors = append(deliveryErrors, err)
		}
	}
	if !event.heartbeatAt.IsZero() {
		if err := dispatcher.sink.RecordHeartbeat(ctx, event.agentID, event.heartbeatAt); err != nil {
			deliveryErrors = append(deliveryErrors, err)
		}
	}
	return errors.Join(deliveryErrors...)
}

func (dispatcher *HostObservationDispatcher) signalLocked() {
	select {
	case dispatcher.wake <- struct{}{}:
	default:
	}
}

func (dispatcher *HostObservationDispatcher) finish() {
	dispatcher.mu.Lock()
	defer dispatcher.mu.Unlock()
	if dispatcher.finished {
		return
	}
	dispatcher.finished, dispatcher.accepting = true, false
	close(dispatcher.done)
}

type noopHostObserver struct{}

func (noopHostObserver) SubmitHello(string, time.Time) error                      { return nil }
func (noopHostObserver) SubmitHeartbeat(string, time.Time) error                  { return nil }
func (noopHostObserver) SubmitObservation(string, *agentv1.HostObservation) error { return nil }

var _ HostObserver = (*HostObservationDispatcher)(nil)
