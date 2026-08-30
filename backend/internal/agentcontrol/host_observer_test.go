package agentcontrol

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
)

func TestHostObservationDispatcherCoalescesNewestHeartbeatWhilePersistenceIsBlocked(t *testing.T) {
	base := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	sink := &blockingHostObservationSink{helloEntered: make(chan struct{}, 1), releaseHello: make(chan struct{}), observations: make(chan uint64, 4), heartbeats: make(chan time.Time, 4)}
	dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 1, DeliveryTimeout: time.Minute})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, _ = dispatcher.Close(ctx)
	})
	require.NoError(t, dispatcher.SubmitHello("agent-a", base))
	select {
	case <-sink.helloEntered:
	case <-time.After(time.Second):
		t.Fatal("Hello persistence did not block")
	}
	latest := base
	for index := 1; index <= 100; index++ {
		latest = base.Add(time.Duration(index) * time.Second)
		require.NoError(t, dispatcher.SubmitObservation("agent-a", &agentv1.HostObservation{HostId: "host-a", AgentId: "agent-a", ObservationRevision: uint64(index)}))
		require.NoError(t, dispatcher.SubmitHeartbeat("agent-a", latest))
	}
	require.ErrorIs(t, dispatcher.SubmitHeartbeat("agent-b", latest), ErrHostObservationCapacity)
	stats := dispatcher.Stats()
	require.Equal(t, uint64(1), stats.RejectedNewKeys)

	close(sink.releaseHello)
	requireEventuallyRevision(t, sink.observations, 100)
	requireEventuallyTime(t, sink.heartbeats, latest)
}

func TestHostObservationDispatcherClosePerformsOneBoundedDrainThenStopsIntake(t *testing.T) {
	base := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	sink := &blockingHostObservationSink{heartbeats: make(chan time.Time, 1)}
	dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 2, DeliveryTimeout: time.Second})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	require.NoError(t, dispatcher.SubmitHeartbeat("agent-a", base))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	report, err := dispatcher.Close(ctx)
	require.NoError(t, err)
	require.Zero(t, report.TotalDiscarded())
	require.Equal(t, base, <-sink.heartbeats)
	require.ErrorIs(t, dispatcher.SubmitHeartbeat("agent-a", base.Add(time.Second)), ErrHostObservationClosed)
}

func TestHostObservationFailureDoesNotSuppressRealHeartbeat(t *testing.T) {
	base := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	sink := &blockingHostObservationSink{observations: make(chan uint64, 1), observationErr: errors.New("stale inventory"), heartbeats: make(chan time.Time, 1)}
	dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 1, DeliveryTimeout: time.Second})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	require.NoError(t, dispatcher.SubmitObservation("agent-a", &agentv1.HostObservation{HostId: "host-a", AgentId: "agent-a", ObservationRevision: 1}))
	require.NoError(t, dispatcher.SubmitHeartbeat("agent-a", base))
	select {
	case persisted := <-sink.heartbeats:
		require.Equal(t, base, persisted)
	case <-time.After(time.Second):
		t.Fatal("a failed inventory observation suppressed real Heartbeat liveness")
	}
	require.Eventually(t, func() bool { return dispatcher.Stats().Failed == 1 }, time.Second, time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	report, err := dispatcher.Close(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, uint64(1), report.ObservationDiscarded)
}

type blockingHostObservationSink struct {
	helloEntered   chan struct{}
	releaseHello   chan struct{}
	observations   chan uint64
	observationErr error
	heartbeats     chan time.Time
	mu             sync.Mutex
}

func (sink *blockingHostObservationSink) RecordObservation(ctx context.Context, _ string, observation *agentv1.HostObservation) error {
	if sink.observationErr != nil {
		return sink.observationErr
	}
	select {
	case sink.observations <- observation.GetObservationRevision():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (sink *blockingHostObservationSink) RecordHello(ctx context.Context, _ string, _ time.Time) error {
	if sink.helloEntered != nil {
		sink.helloEntered <- struct{}{}
	}
	if sink.releaseHello != nil {
		select {
		case <-sink.releaseHello:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (sink *blockingHostObservationSink) RecordHeartbeat(ctx context.Context, _ string, at time.Time) error {
	select {
	case sink.heartbeats <- at:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func requireEventuallyRevision(t *testing.T, values <-chan uint64, want uint64) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case got := <-values:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("revision %d was not persisted", want)
		}
	}
}

func requireEventuallyTime(t *testing.T, values <-chan time.Time, want time.Time) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case got := <-values:
			if got.Equal(want) {
				return
			}
		case <-deadline:
			t.Fatalf("timestamp %s was not persisted", want)
		}
	}
}

var _ HostObservationSink = (*blockingHostObservationSink)(nil)

func TestHostObservationDispatcherRejectsInvalidConfiguration(t *testing.T) {
	_, err := NewHostObservationDispatcher(nil, HostObservationDispatcherConfig{})
	require.Error(t, err)
	require.False(t, errors.Is(err, ErrHostObservationCapacity))
}
