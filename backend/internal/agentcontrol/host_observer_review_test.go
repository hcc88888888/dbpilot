package agentcontrol

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHostDeliveryLanesAreIndependent(t *testing.T) {
	base := time.Date(2026, 8, 30, 11, 0, 0, 0, time.UTC)
	sink := newReviewHostSink()
	sink.blockObservation = make(chan struct{})
	dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 2, DeliveryTimeout: 20 * time.Millisecond, RetryBackoff: 5 * time.Millisecond})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	require.NoError(t, dispatcher.SubmitObservation("agent-a", reviewObservation("agent-a", 1, base)))
	requireReceive(t, sink.observationEntered, "observation lane did not enter persistence")

	require.NoError(t, dispatcher.SubmitHeartbeat("agent-a", base.Add(time.Second)))
	select {
	case got := <-sink.heartbeats:
		require.Equal(t, base.Add(time.Second), got.at)
	case <-time.After(250 * time.Millisecond):
		t.Fatal("blocked observation lane blocked the independent Heartbeat lane")
	}
	close(sink.blockObservation)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = dispatcher.Close(ctx)
	require.NoError(t, err)
}

func TestFailedHostDeliveryRequeuesAndMergesNewestPendingState(t *testing.T) {
	base := time.Date(2026, 8, 30, 11, 0, 0, 0, time.UTC)
	sink := newReviewHostSink()
	sink.failObservationAttempts.Store(1)
	sink.firstObservationRelease = make(chan struct{})
	dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 1, DeliveryTimeout: time.Second, RetryBackoff: 5 * time.Millisecond})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	require.NoError(t, dispatcher.SubmitObservation("agent-a", reviewObservation("agent-a", 1, base)))
	requireReceive(t, sink.observationEntered, "first observation attempt did not start")
	require.NoError(t, dispatcher.SubmitObservation("agent-a", reviewObservation("agent-a", 2, base.Add(time.Second))))
	close(sink.firstObservationRelease)

	select {
	case got := <-sink.observations:
		require.Equal(t, uint64(2), got.revision, "failed state must merge with and retry the highest accepted revision")
	case <-time.After(time.Second):
		t.Fatal("newest observation was dropped after transient persistence failure")
	}
	stats := dispatcher.Stats()
	require.GreaterOrEqual(t, stats.Observation.Retried, uint64(1))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = dispatcher.Close(ctx)
	require.NoError(t, err)
}

func TestLaneCapacityIncludesInFlightKey(t *testing.T) {
	base := time.Date(2026, 8, 30, 11, 0, 0, 0, time.UTC)
	sink := newReviewHostSink()
	sink.blockHeartbeat = make(chan struct{})
	dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 1, DeliveryTimeout: time.Second, RetryBackoff: time.Millisecond})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	require.NoError(t, dispatcher.SubmitHeartbeat("agent-a", base))
	requireReceive(t, sink.heartbeatEntered, "Heartbeat did not become in flight")
	require.ErrorIs(t, dispatcher.SubmitHeartbeat("agent-b", base), ErrHostObservationCapacity)
	close(sink.blockHeartbeat)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = dispatcher.Close(ctx)
	require.NoError(t, err)
}

func TestCloseReportsExactDiscardedStateAcrossLanes(t *testing.T) {
	base := time.Date(2026, 8, 30, 11, 0, 0, 0, time.UTC)
	sink := newReviewHostSink()
	sink.blockObservation = make(chan struct{})
	sink.blockHello = make(chan struct{})
	sink.blockHeartbeat = make(chan struct{})
	dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 2, DeliveryTimeout: time.Minute, RetryBackoff: time.Second})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	require.NoError(t, dispatcher.SubmitObservation("agent-a", reviewObservation("agent-a", 1, base)))
	require.NoError(t, dispatcher.SubmitHello("agent-a", base))
	require.NoError(t, dispatcher.SubmitHeartbeat("agent-a", base))
	requireReceive(t, sink.observationEntered, "observation not in flight")
	requireReceive(t, sink.helloEntered, "Hello not in flight")
	requireReceive(t, sink.heartbeatEntered, "Heartbeat not in flight")
	require.NoError(t, dispatcher.SubmitObservation("agent-b", reviewObservation("agent-b", 1, base)))
	require.NoError(t, dispatcher.SubmitHello("agent-b", base))
	require.NoError(t, dispatcher.SubmitHeartbeat("agent-b", base))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	report, closeErr := dispatcher.Close(ctx)
	require.ErrorIs(t, closeErr, context.DeadlineExceeded)
	require.Equal(t, uint64(2), report.ObservationDiscarded)
	require.Equal(t, uint64(2), report.HelloDiscarded)
	require.Equal(t, uint64(2), report.HeartbeatDiscarded)
	require.Equal(t, uint64(6), report.TotalDiscarded())
	require.ErrorIs(t, dispatcher.SubmitHeartbeat("agent-c", base), ErrHostObservationClosed)
	close(sink.blockObservation)
	close(sink.blockHello)
	close(sink.blockHeartbeat)
}

func TestHostDeliveryLanesServeDistinctKeysInFIFOOrderAndReturnHotKeyToTail(t *testing.T) {
	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for _, kind := range []hostLaneKind{hostLaneObservation, hostLaneHello, hostLaneHeartbeat} {
		t.Run(hostLaneName(kind), func(t *testing.T) {
			sink := newOrderedHostSink(kind, "agent-a")
			dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 8, DeliveryTimeout: time.Second, RetryBackoff: time.Millisecond})
			require.NoError(t, err)
			require.NoError(t, dispatcher.Start(context.Background()))
			require.NoError(t, submitLaneEvent(dispatcher, kind, "agent-a", 1, base))
			requireReceive(t, sink.blocked, "hot key did not enter persistence")
			for index, agentID := range []string{"agent-b", "agent-c", "agent-d", "agent-e", "agent-f", "agent-g", "agent-h"} {
				require.NoError(t, submitLaneEvent(dispatcher, kind, agentID, uint64(index+1), base.Add(time.Duration(index+1)*time.Second)))
			}
			require.NoError(t, submitLaneEvent(dispatcher, kind, "agent-a", 2, base.Add(20*time.Second)))
			close(sink.release)

			want := []string{"agent-a", "agent-b", "agent-c", "agent-d", "agent-e", "agent-f", "agent-g", "agent-h", "agent-a"}
			for _, agentID := range want {
				select {
				case got := <-sink.delivered:
					require.Equal(t, agentID, got.agentID)
				case <-time.After(time.Second):
					t.Fatalf("%s lane did not deliver %s in FIFO order", hostLaneName(kind), agentID)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err = dispatcher.Close(ctx)
			require.NoError(t, err)
		})
	}
}

func TestTimedOutNeverReturningKeyIsQuarantinedWithoutBlockingColdKeysInEveryLane(t *testing.T) {
	base := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	for _, kind := range []hostLaneKind{hostLaneObservation, hostLaneHello, hostLaneHeartbeat} {
		t.Run(hostLaneName(kind), func(t *testing.T) {
			sink := newOrderedHostSink(kind, "agent-a")
			dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 2, DeliveryTimeout: 15 * time.Millisecond, RetryBackoff: time.Millisecond})
			require.NoError(t, err)
			require.NoError(t, dispatcher.Start(context.Background()))
			require.NoError(t, submitLaneEvent(dispatcher, kind, "agent-a", 1, base))
			requireReceive(t, sink.blocked, "never-returning key did not enter persistence")
			require.NoError(t, submitLaneEvent(dispatcher, kind, "agent-a", 2, base.Add(time.Second)))
			require.NoError(t, submitLaneEvent(dispatcher, kind, "agent-b", 1, base.Add(2*time.Second)))

			select {
			case got := <-sink.delivered:
				require.Equal(t, "agent-b", got.agentID)
			case <-time.After(250 * time.Millisecond):
				t.Fatalf("%s lane let a timed-out sink call block a cold key", hostLaneName(kind))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			report, closeErr := dispatcher.Close(ctx)
			cancel()
			require.ErrorIs(t, closeErr, context.DeadlineExceeded)
			switch kind {
			case hostLaneObservation:
				require.Equal(t, uint64(1), report.ObservationDiscarded)
			case hostLaneHello:
				require.Equal(t, uint64(1), report.HelloDiscarded)
			case hostLaneHeartbeat:
				require.Equal(t, uint64(1), report.HeartbeatDiscarded)
			}
			close(sink.release)
		})
	}
}

type orderedHostSink struct {
	kind      hostLaneKind
	blockKey  string
	blocked   chan struct{}
	release   chan struct{}
	delivered chan reviewHostEvent
	once      sync.Once
}

func newOrderedHostSink(kind hostLaneKind, blockKey string) *orderedHostSink {
	return &orderedHostSink{kind: kind, blockKey: blockKey, blocked: make(chan struct{}), release: make(chan struct{}), delivered: make(chan reviewHostEvent, 32)}
}

func (sink *orderedHostSink) record(agentID string, revision uint64, at time.Time) error {
	if agentID == sink.blockKey {
		sink.once.Do(func() { close(sink.blocked) })
		<-sink.release
	}
	sink.delivered <- reviewHostEvent{agentID: agentID, revision: revision, at: at}
	return nil
}

func (sink *orderedHostSink) RecordObservation(_ context.Context, agentID string, observation *agentv1.HostObservation) error {
	return sink.record(agentID, observation.GetObservationRevision(), observation.GetObservedAt().AsTime())
}

func (sink *orderedHostSink) RecordHello(_ context.Context, agentID string, at time.Time) error {
	return sink.record(agentID, 0, at)
}

func (sink *orderedHostSink) RecordHeartbeat(_ context.Context, agentID string, at time.Time) error {
	return sink.record(agentID, 0, at)
}

func submitLaneEvent(dispatcher *HostObservationDispatcher, kind hostLaneKind, agentID string, revision uint64, at time.Time) error {
	switch kind {
	case hostLaneObservation:
		return dispatcher.SubmitObservation(agentID, reviewObservation(agentID, revision, at))
	case hostLaneHello:
		return dispatcher.SubmitHello(agentID, at)
	case hostLaneHeartbeat:
		return dispatcher.SubmitHeartbeat(agentID, at)
	default:
		return ErrHostObservationInvalid
	}
}

func hostLaneName(kind hostLaneKind) string {
	switch kind {
	case hostLaneObservation:
		return "observation"
	case hostLaneHello:
		return "hello"
	case hostLaneHeartbeat:
		return "heartbeat"
	default:
		return "unknown"
	}
}

type reviewHostEvent struct {
	agentID  string
	revision uint64
	at       time.Time
}

type reviewHostSink struct {
	observationEntered      chan struct{}
	helloEntered            chan struct{}
	heartbeatEntered        chan struct{}
	observations            chan reviewHostEvent
	hellos                  chan reviewHostEvent
	heartbeats              chan reviewHostEvent
	blockObservation        chan struct{}
	blockHello              chan struct{}
	blockHeartbeat          chan struct{}
	firstObservationRelease chan struct{}
	failObservationAttempts atomic.Int32
	observationCalls        atomic.Int32
	once                    sync.Once
}

func newReviewHostSink() *reviewHostSink {
	return &reviewHostSink{
		observationEntered: make(chan struct{}, 8), helloEntered: make(chan struct{}, 8), heartbeatEntered: make(chan struct{}, 8),
		observations: make(chan reviewHostEvent, 8), hellos: make(chan reviewHostEvent, 8), heartbeats: make(chan reviewHostEvent, 8),
	}
}

func (sink *reviewHostSink) RecordObservation(_ context.Context, agentID string, observation *agentv1.HostObservation) error {
	sink.observationEntered <- struct{}{}
	call := sink.observationCalls.Add(1)
	if call == 1 && sink.firstObservationRelease != nil {
		<-sink.firstObservationRelease
	}
	if sink.blockObservation != nil {
		<-sink.blockObservation
	}
	if sink.failObservationAttempts.Add(-1) >= 0 {
		return errors.New("transient observation persistence failure")
	}
	sink.observations <- reviewHostEvent{agentID: agentID, revision: observation.GetObservationRevision()}
	return nil
}

func (sink *reviewHostSink) RecordHello(_ context.Context, agentID string, at time.Time) error {
	sink.helloEntered <- struct{}{}
	if sink.blockHello != nil {
		<-sink.blockHello
	}
	sink.hellos <- reviewHostEvent{agentID: agentID, at: at}
	return nil
}

func (sink *reviewHostSink) RecordHeartbeat(_ context.Context, agentID string, at time.Time) error {
	sink.heartbeatEntered <- struct{}{}
	if sink.blockHeartbeat != nil {
		<-sink.blockHeartbeat
	}
	sink.heartbeats <- reviewHostEvent{agentID: agentID, at: at}
	return nil
}

func reviewObservation(agentID string, revision uint64, at time.Time) *agentv1.HostObservation {
	return &agentv1.HostObservation{HostId: "host-" + agentID, AgentId: agentID, ObservationRevision: revision, ObservedAt: timestamppb.New(at)}
}

func requireReceive(t *testing.T, channel <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-channel:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}
