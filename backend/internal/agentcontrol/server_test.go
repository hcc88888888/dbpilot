package agentcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	agentruntime "dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestConnectRejectsUnverifiedOrInvalidSPIFFEIdentity(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "missing peer certificate", ctx: context.Background()},
		{name: "unverified peer certificate", ctx: tlsPeerContext(t, false, "spiffe://dbpilot.local/agent/agent-a")},
		{name: "non SPIFFE URI", ctx: tlsPeerContext(t, true, "https://dbpilot.local/agent/agent-a")},
		{name: "wrong trust domain", ctx: tlsPeerContext(t, true, "spiffe://other.local/agent/agent-a")},
		{name: "multiple SPIFFE URIs", ctx: tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a", "spiffe://dbpilot.local/agent/agent-b")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := NewServer(NewRegistry(2), nil)
			stream := newTestConnectStream(test.ctx, helloMessage("agent-a", ProtocolVersion, "collect_now"))
			stream.closeReceive()

			err := server.Connect(stream)

			require.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

func TestConnectRequiresValidMatchingHello(t *testing.T) {
	tests := []struct {
		name  string
		hello *agentv1.AgentMessage
		code  codes.Code
	}{
		{name: "first message is not hello", hello: &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: "agent-a"}}}, code: codes.InvalidArgument},
		{name: "missing agent ID", hello: helloMessage("", ProtocolVersion, "collect_now"), code: codes.InvalidArgument},
		{name: "certificate identity mismatch", hello: helloMessage("agent-b", ProtocolVersion, "collect_now"), code: codes.PermissionDenied},
		{name: "unsupported protocol version", hello: helloMessage("agent-a", "2", "collect_now"), code: codes.FailedPrecondition},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := NewServer(NewRegistry(2), nil)
			stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), test.hello)
			stream.closeReceive()

			err := server.Connect(stream)

			require.Equal(t, test.code, status.Code(err))
		})
	}
}

func TestConnectRegistersCapabilitiesSendsHelloAckAndRejectsDuplicateSession(t *testing.T) {
	registry := NewRegistry(2)
	observer := &recordingObserver{connected: make(chan SessionInfo, 1)}
	server := NewServer(registry, observer)
	first := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	firstDone := make(chan error, 1)
	go func() { firstDone <- server.Connect(first) }()

	ack := first.nextSent(t)
	require.Equal(t, ProtocolVersion, ack.GetHelloAck().GetProtocolVersion())
	require.Equal(t, []string{CapabilityDiscoveryPolicyAttestationV1, CapabilityDiscoveryReportACKV1}, ack.GetHelloAck().GetCapabilities())
	connected := <-observer.connected
	require.Equal(t, "agent-a", connected.AgentID)
	require.Equal(t, []string{"collect_now"}, connected.Capabilities)
	snapshot, ok := registry.Session("agent-a")
	require.True(t, ok)
	require.Equal(t, []string{"collect_now"}, snapshot.Capabilities)

	duplicate := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	duplicate.closeReceive()
	require.Equal(t, codes.AlreadyExists, status.Code(server.Connect(duplicate)))

	first.closeReceive()
	require.NoError(t, <-firstDone)
	require.Eventually(t, func() bool { _, exists := registry.Session("agent-a"); return !exists }, time.Second, time.Millisecond)
}

func TestConnectRecordsRealHeartbeatWhileConnectedObserverIsBlocked(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	registry := NewRegistry(2)
	observer := &blockingObserver{connectedEntered: make(chan struct{}), connectedRelease: make(chan struct{}), resultEntered: make(chan struct{}), resultRelease: make(chan struct{})}
	server := NewServer(registry, observer)
	server.now = func() time.Time { return now }
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	done := make(chan error, 1)
	go func() { done <- server.Connect(stream) }()
	_ = stream.nextSent(t)
	<-observer.connectedEntered

	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: "agent-a"}}})
	require.Eventually(t, func() bool {
		session, ok := registry.Session("agent-a")
		return ok && session.LastHeartbeat.Equal(now)
	}, 200*time.Millisecond, time.Millisecond)

	close(observer.connectedRelease)
	stream.closeReceive()
	require.NoError(t, <-done)
}

func TestConnectRecordsRealHeartbeatWhileCommandResultObserverIsBlocked(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	registry := NewRegistry(2)
	observer := &blockingObserver{connectedEntered: make(chan struct{}), connectedRelease: make(chan struct{}), resultEntered: make(chan struct{}), resultRelease: make(chan struct{})}
	server := NewServer(registry, observer)
	server.now = func() time.Time { return now }
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	done := make(chan error, 1)
	go func() { done <- server.Connect(stream) }()
	_ = stream.nextSent(t)
	<-observer.connectedEntered
	close(observer.connectedRelease)

	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: &agentv1.CommandResult{CommandId: "command-replay", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, ExecutionToken: testServerExecutionToken(0x41), LeaseRevision: 1}}})
	<-observer.resultEntered
	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: "agent-a"}}})
	require.Eventually(t, func() bool {
		session, ok := registry.Session("agent-a")
		return ok && session.LastHeartbeat.Equal(now)
	}, 200*time.Millisecond, time.Millisecond)

	close(observer.resultRelease)
	stream.closeReceive()
	require.NoError(t, <-done)
}

func TestBlockedHostPersistenceDoesNotBlockCommandEventsAndKeepsNewestHeartbeat(t *testing.T) {
	base := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	sink := &blockingHostObservationSink{helloEntered: make(chan struct{}, 1), releaseHello: make(chan struct{}), observations: make(chan uint64, 4), heartbeats: make(chan time.Time, 4)}
	dispatcher, err := NewHostObservationDispatcher(sink, HostObservationDispatcherConfig{MaximumPendingHosts: 1, DeliveryTimeout: time.Minute})
	require.NoError(t, err)
	require.NoError(t, dispatcher.Start(context.Background()))
	observer := &recordingObserver{connected: make(chan SessionInfo, 1)}
	server := NewServer(NewRegistry(8), observer, WithHostObserver(dispatcher))
	var tick atomic.Int64
	server.now = func() time.Time { return base.Add(time.Duration(tick.Add(1)) * time.Second) }
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	done := make(chan error, 1)
	go func() { done <- server.Connect(stream) }()
	_ = stream.nextSent(t)
	<-observer.connected
	select {
	case <-sink.helloEntered:
	case <-time.After(time.Second):
		t.Fatal("Host Hello persistence did not block")
	}
	token := testServerExecutionToken(0x45)
	go func() {
		for index := 0; index < 64; index++ {
			stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: "agent-a"}}})
			stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_HostObservation{HostObservation: &agentv1.HostObservation{HostId: "host-a", AgentId: "agent-a", ObservationRevision: uint64(index + 1)}}})
		}
		stream.push(
			&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandAcknowledgement{CommandAcknowledgement: &agentv1.CommandAcknowledgement{CommandId: "command-a"}}},
			&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: "command-a", Percent: 50, ExecutionToken: token, LeaseRevision: 1}}},
			&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, ExecutionToken: token, LeaseRevision: 1}}},
		)
	}()
	require.Eventually(t, func() bool { return observer.counts() == [3]int{1, 1, 1} }, time.Second, time.Millisecond)
	require.NotNil(t, stream.nextSent(t).GetCommandResultAcknowledgement(), "result ACK must not wait for Host PostgreSQL")
	require.Greater(t, dispatcher.Stats().Coalesced, uint64(0))
	close(sink.releaseHello)
	requireEventuallyRevision(t, sink.observations, 64)
	requireEventuallyTime(t, sink.heartbeats, base.Add(68*time.Second))
	stream.closeReceive()
	require.NoError(t, <-done)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = dispatcher.Close(ctx)
	require.NoError(t, err)
}

func TestRegistryDispatchValidatesAgentCapabilityExpiryAndQueueBound(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	registry := NewRegistry(1)
	registry.now = func() time.Time { return now }
	sessionContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, registry.register("agent-a", []string{"collect_now"}, nil, cancel))

	valid := collectNowEnvelope("command-a", "agent-a", now.Add(time.Minute))
	require.NoError(t, registry.Dispatch(context.Background(), "agent-a", valid))
	require.ErrorIs(t, registry.Dispatch(context.Background(), "agent-a", collectNowEnvelope("command-b", "agent-a", now.Add(time.Minute))), ErrSessionQueueFull)
	require.True(t, IsRetryableDispatchError(registry.Dispatch(context.Background(), "missing", collectNowEnvelope("command-offline", "missing", now.Add(time.Minute)))))
	require.ErrorIs(t, registry.Dispatch(context.Background(), "agent-a", inspectEnvelope("command-c", "agent-a", now.Add(time.Minute))), ErrCapabilityNotAdvertised)
	require.ErrorIs(t, registry.Dispatch(context.Background(), "agent-a", collectNowEnvelope("command-d", "agent-a", now.Add(-time.Second))), ErrCommandExpired)
	require.ErrorIs(t, registry.Dispatch(context.Background(), "agent-a", collectNowEnvelope("command-e", "agent-b", now.Add(time.Minute))), ErrAgentMismatch)
	require.NotNil(t, sessionContext)
}

func TestRegistryCancelFlowsThroughStreamToPreparedAndRunningAgent(t *testing.T) {
	t.Run("prepared command is durably cancelled without execution", func(t *testing.T) {
		fixture := newAgentRegistryIntegrationFixture(t, NoopObserver{})
		envelope := fixture.signedEnvelope(t, "command-prepared-cancel")
		require.NoError(t, fixture.registry.Dispatch(context.Background(), "agent-a", envelope))
		require.Eventually(t, func() bool {
			entry, err := fixture.journal.Get(context.Background(), envelope.GetCommandId())
			return err == nil && entry.State == commandjournal.StatePrepared
		}, time.Second, time.Millisecond)

		require.NoError(t, fixture.registry.Cancel(context.Background(), "agent-a", envelope.GetCommandId()))
		require.Eventually(t, func() bool {
			entry, err := fixture.journal.Get(context.Background(), envelope.GetCommandId())
			return err == nil && entry.State == commandjournal.StateCancelled
		}, time.Second, time.Millisecond)
		require.Zero(t, fixture.executor.calls.Load())

		lateStart := &agentv1.CommandStart{CommandId: envelope.GetCommandId(), ExecutionToken: testServerExecutionToken(0x61), LeaseRevision: 1, LeaseSeconds: 30, StartDeadline: timestamppb.New(time.Now().Add(time.Minute))}
		require.NoError(t, fixture.registry.Start(context.Background(), "agent-a", lateStart))
		time.Sleep(20 * time.Millisecond)
		require.Zero(t, fixture.executor.calls.Load(), "durably cancelled Prepare must reject a later Start")
	})

	t.Run("running command receives exact fence and cancels executor", func(t *testing.T) {
		token := testServerExecutionToken(0x62)
		observer := &recordingObserver{connected: make(chan SessionInfo, 1), start: &agentv1.CommandStart{CommandId: "command-running-cancel", ExecutionToken: token, LeaseRevision: 7, LeaseSeconds: 30, StartDeadline: timestamppb.New(time.Now().Add(time.Minute))}}
		fixture := newAgentRegistryIntegrationFixture(t, observer)
		envelope := fixture.signedEnvelope(t, "command-running-cancel")
		require.NoError(t, fixture.registry.Dispatch(context.Background(), "agent-a", envelope))
		select {
		case <-fixture.executor.started:
		case <-time.After(time.Second):
			t.Fatal("executor did not start")
		}

		require.NoError(t, fixture.registry.Cancel(context.Background(), "agent-a", envelope.GetCommandId()))
		select {
		case <-fixture.executor.cancelled:
		case <-time.After(time.Second):
			t.Fatal("fenced Registry cancellation did not reach executor")
		}
		require.Eventually(t, func() bool {
			for _, message := range fixture.clientStream.receivedMessages() {
				cancellation := message.GetCommandCancellation()
				if cancellation != nil && cancellation.GetCommandId() == envelope.GetCommandId() {
					return bytes.Equal(token, cancellation.GetExecutionToken()) && cancellation.GetLeaseRevision() == 7
				}
			}
			return false
		}, time.Second, time.Millisecond)
		require.Equal(t, int32(1), fixture.executor.calls.Load())
	})
}

func TestPreparedObserverPersistsBeforeServerSendsStart(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	token := bytes.Repeat([]byte{0x41}, sha256.Size)
	registry := NewRegistry(4)
	registry.now = func() time.Time { return now }
	observer := &recordingObserver{connected: make(chan SessionInfo, 1), prepared: make(chan *agentv1.CommandPrepared, 1)}
	observer.start = &agentv1.CommandStart{CommandId: "command-a", ExecutionToken: token, LeaseRevision: 3, LeaseSeconds: 30, StartDeadline: timestamppb.New(now.Add(time.Minute))}
	server := NewServer(registry, observer)
	server.now = func() time.Time { return now }
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	done := make(chan error, 1)
	go func() { done <- server.Connect(stream) }()
	_ = stream.nextSent(t)
	<-observer.connected

	digest := sha256.Sum256([]byte("envelope"))
	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandPrepared{CommandPrepared: &agentv1.CommandPrepared{CommandId: "command-a", EnvelopeDigest: digest[:]}}})
	prepared := <-observer.prepared
	require.Equal(t, digest[:], prepared.GetEnvelopeDigest())
	var start *agentv1.CommandStart
	select {
	case message := <-stream.sent:
		start = message.GetCommandStart()
	case connectErr := <-done:
		t.Fatalf("server ended before CommandStart: %v", connectErr)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for CommandStart")
	}
	require.NotNil(t, start)
	require.Equal(t, token, start.GetExecutionToken())
	require.Equal(t, uint64(3), start.GetLeaseRevision())

	stream.closeReceive()
	require.NoError(t, <-done)
}

func TestReplayStartAllowsExactExpiredPersistedFence(t *testing.T) {
	registry := NewRegistry(2)
	now := time.Date(2026, 8, 28, 13, 0, 0, 0, time.UTC)
	registry.now = func() time.Time { return now }
	require.NoError(t, registry.register("agent-a", []string{"collect_now"}, nil, func() {}))
	start := &agentv1.CommandStart{
		CommandId: "command-replay", ExecutionToken: bytes.Repeat([]byte{0x71}, sha256.Size), LeaseRevision: 1,
		LeaseSeconds: 30, StartDeadline: timestamppb.New(now.Add(-time.Second)),
	}
	require.Error(t, registry.Start(context.Background(), "agent-a", start), "fresh Start must retain deadline validation")
	require.NoError(t, registry.ReplayStart(context.Background(), "agent-a", start))
	session, ok := registry.liveSession("agent-a")
	require.True(t, ok)
	require.True(t, proto.Equal(start, (<-session.send).GetCommandStart()))
}

func TestResultAckIsPersistedOnlyForMatchingObserverDigest(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	registry := NewRegistry(4)
	observer := &recordingObserver{connected: make(chan SessionInfo, 1)}
	server := NewServer(registry, observer)
	server.now = func() time.Time { return now }
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	done := make(chan error, 1)
	go func() { done <- server.Connect(stream) }()
	_ = stream.nextSent(t)
	<-observer.connected

	result := &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, ExecutionToken: bytes.Repeat([]byte{0x42}, sha256.Size), LeaseRevision: 5}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	require.NoError(t, err)
	digest := sha256.Sum256(encoded)
	observer.resultDigest = digest[:]
	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: result}})
	ack := stream.nextSent(t).GetCommandResultAcknowledgement()
	require.True(t, ack.GetPersisted())
	require.Equal(t, digest[:], ack.GetResultDigest())
	require.False(t, ack.GetRetryable())

	observer.resultDigest = bytes.Repeat([]byte{0xff}, sha256.Size)
	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: result}})
	ack = stream.nextSent(t).GetCommandResultAcknowledgement()
	require.False(t, ack.GetPersisted())
	require.Equal(t, "RESULT_DIGEST_MISMATCH", ack.GetReasonCode())

	stream.closeReceive()
	require.NoError(t, <-done)
}

func TestConnectRoutesAgentEventsAndRenewsCommandLease(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	token := testServerExecutionToken(0x31)
	registry := NewRegistry(2)
	registry.now = func() time.Time { return now }
	observer := &recordingObserver{connected: make(chan SessionInfo, 1)}
	observer.start = &agentv1.CommandStart{CommandId: "command-a", ExecutionToken: token, LeaseRevision: 1, LeaseSeconds: 30, StartDeadline: timestamppb.New(now.Add(time.Minute))}
	server := NewServer(registry, observer)
	server.now = func() time.Time { return now }
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	done := make(chan error, 1)
	go func() { done <- server.Connect(stream) }()
	_ = stream.nextSent(t)
	<-observer.connected

	require.NoError(t, registry.Dispatch(context.Background(), "agent-a", &agentv1.CommandEnvelope{
		CommandId: "command-a", AgentId: "agent-a", LeaseSeconds: 30,
		ExpiresAt: timestamppb.New(now.Add(time.Minute)), Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}},
	}))
	require.Equal(t, "command-a", stream.nextSent(t).GetCommand().GetCommandId())
	prepareDigest := sha256.Sum256([]byte("command-a-envelope"))
	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandPrepared{CommandPrepared: &agentv1.CommandPrepared{CommandId: "command-a", EnvelopeDigest: prepareDigest[:]}}})
	require.Equal(t, "command-a", stream.nextSent(t).GetCommandStart().GetCommandId())
	stream.push(
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: "agent-a", ActiveCommandIds: []string{"command-a"}, ActiveCommands: []*agentv1.ActiveCommand{{CommandId: "command-a", ExecutionToken: token, LeaseRevision: 1}}}}},
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandAcknowledgement{CommandAcknowledgement: &agentv1.CommandAcknowledgement{CommandId: "command-a"}}},
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: "command-a", Percent: 50, ExecutionToken: token, LeaseRevision: 1}}},
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, ExecutionToken: token, LeaseRevision: 1}}},
	)
	require.Eventually(t, func() bool { return observer.counts() == [3]int{1, 1, 1} }, time.Second, time.Millisecond)
	resultAck := stream.nextSent(t).GetCommandResultAcknowledgement()
	require.NotNil(t, resultAck)
	require.Equal(t, "command-a", resultAck.GetCommandId())
	require.True(t, resultAck.GetPersisted())
	snapshot, ok := registry.Session("agent-a")
	require.True(t, ok)
	require.Equal(t, now.Add(30*time.Second), snapshot.Leases["command-a"])

	stream.closeReceive()
	require.NoError(t, <-done)
}

func TestRegistrySessionSnapshotCopiesLeaseStateUnderLock(t *testing.T) {
	now := time.Now().UTC()
	registry := NewRegistry(2048)
	registry.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, registry.register("agent-a", []string{"collect_now"}, nil, cancel))
	current, ok := registry.liveSession("agent-a")
	require.True(t, ok)
	require.NoError(t, registry.Start(ctx, "agent-a", &agentv1.CommandStart{CommandId: "command-seed", ExecutionToken: testServerExecutionToken(0x51), LeaseRevision: 1, LeaseSeconds: 30, StartDeadline: timestamppb.New(now.Add(time.Hour))}))

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for index := 0; index < 1000; index++ {
			commandID := fmt.Sprintf("command-%d", index)
			_ = registry.Dispatch(ctx, "agent-a", &agentv1.CommandEnvelope{CommandId: commandID, AgentId: "agent-a", LeaseSeconds: 30, ExpiresAt: timestamppb.New(now.Add(time.Hour)), Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}}})
			registry.renew("agent-a", &agentv1.Heartbeat{AgentId: "agent-a", ActiveCommandIds: []string{commandID}}, now)
		}
	}()
	go func() {
		defer wait.Done()
		for index := 0; index < 1000; index++ {
			snapshot, exists := registry.snapshot("agent-a", current)
			require.True(t, exists)
			for commandID := range snapshot.Leases {
				delete(snapshot.Leases, commandID)
			}
			for commandID := range snapshot.LeaseRevisions {
				delete(snapshot.LeaseRevisions, commandID)
			}
		}
	}()
	wait.Wait()
}

func helloMessage(agentID, protocol string, capabilities ...string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentId: agentID, ProtocolVersion: protocol, Capabilities: capabilities}}}
}

func collectNowEnvelope(commandID, agentID string, expiresAt time.Time) *agentv1.CommandEnvelope {
	return &agentv1.CommandEnvelope{CommandId: commandID, AgentId: agentID, ExpiresAt: timestamppb.New(expiresAt), Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}}}
}

func inspectEnvelope(commandID, agentID string, expiresAt time.Time) *agentv1.CommandEnvelope {
	return &agentv1.CommandEnvelope{CommandId: commandID, AgentId: agentID, ExpiresAt: timestamppb.New(expiresAt), Command: &agentv1.CommandEnvelope_InspectInstance{InspectInstance: &agentv1.InspectInstance{}}}
}

func tlsPeerContext(t *testing.T, verified bool, rawURIs ...string) context.Context {
	t.Helper()
	certificate := &x509.Certificate{}
	for _, rawURI := range rawURIs {
		identityURI, err := url.Parse(rawURI)
		require.NoError(t, err)
		certificate.URIs = append(certificate.URIs, identityURI)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	if verified {
		state.VerifiedChains = [][]*x509.Certificate{{certificate}}
	}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
}

type testConnectStream struct {
	ctx      context.Context
	receive  chan *agentv1.AgentMessage
	sent     chan *agentv1.ServerMessage
	closeOne sync.Once
}

func newTestConnectStream(ctx context.Context, messages ...*agentv1.AgentMessage) *testConnectStream {
	stream := &testConnectStream{ctx: ctx, receive: make(chan *agentv1.AgentMessage, 16), sent: make(chan *agentv1.ServerMessage, 16)}
	stream.push(messages...)
	return stream
}

func (s *testConnectStream) push(messages ...*agentv1.AgentMessage) {
	for _, message := range messages {
		s.receive <- message
	}
}

func (s *testConnectStream) closeReceive() { s.closeOne.Do(func() { close(s.receive) }) }
func (s *testConnectStream) nextSent(t *testing.T) *agentv1.ServerMessage {
	t.Helper()
	select {
	case message := <-s.sent:
		return message
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server message")
		return nil
	}
}
func (s *testConnectStream) Send(message *agentv1.ServerMessage) error { s.sent <- message; return nil }
func (s *testConnectStream) Recv() (*agentv1.AgentMessage, error) {
	message, ok := <-s.receive
	if !ok {
		return nil, io.EOF
	}
	return message, nil
}
func (s *testConnectStream) SetHeader(metadata.MD) error  { return nil }
func (s *testConnectStream) SendHeader(metadata.MD) error { return nil }
func (s *testConnectStream) SetTrailer(metadata.MD)       {}
func (s *testConnectStream) Context() context.Context     { return s.ctx }
func (s *testConnectStream) SendMsg(message any) error {
	typed, ok := message.(*agentv1.ServerMessage)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	return s.Send(typed)
}
func (s *testConnectStream) RecvMsg(message any) error {
	typed, ok := message.(*agentv1.AgentMessage)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	received, err := s.Recv()
	if err != nil {
		return err
	}
	proto.Reset(typed)
	proto.Merge(typed, received)
	return nil
}

var _ grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage] = (*testConnectStream)(nil)

type recordingObserver struct {
	connected    chan SessionInfo
	mu           sync.Mutex
	acks         int
	progress     int
	results      int
	prepared     chan *agentv1.CommandPrepared
	start        *agentv1.CommandStart
	resultDigest []byte
}

type blockingObserver struct {
	NoopObserver
	connectedEntered chan struct{}
	connectedRelease chan struct{}
	resultEntered    chan struct{}
	resultRelease    chan struct{}
}

func (o *blockingObserver) Connected(ctx context.Context, _ SessionInfo) {
	o.connectedEntered <- struct{}{}
	select {
	case <-o.connectedRelease:
	case <-ctx.Done():
	}
}

func (o *blockingObserver) Result(ctx context.Context, _ string, result *agentv1.CommandResult) (ResultPersistence, error) {
	o.resultEntered <- struct{}{}
	select {
	case <-o.resultRelease:
	case <-ctx.Done():
	}
	encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	digest := sha256.Sum256(encoded)
	return ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: digest[:], Persisted: true}, nil
}

func (o *recordingObserver) Connected(_ context.Context, session SessionInfo)      { o.connected <- session }
func (o *recordingObserver) Heartbeat(context.Context, string, *agentv1.Heartbeat) {}
func (o *recordingObserver) Prepared(_ context.Context, _ string, prepared *agentv1.CommandPrepared) (*agentv1.CommandStart, error) {
	if o.prepared != nil {
		o.prepared <- proto.Clone(prepared).(*agentv1.CommandPrepared)
	}
	if o.start == nil {
		return nil, nil
	}
	return proto.Clone(o.start).(*agentv1.CommandStart), nil
}
func (o *recordingObserver) Acknowledged(context.Context, string, *agentv1.CommandAcknowledgement) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.acks++
}
func (o *recordingObserver) Progress(context.Context, string, *agentv1.CommandProgress) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.progress++
}
func (o *recordingObserver) Result(_ context.Context, _ string, result *agentv1.CommandResult) (ResultPersistence, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.results++
	digest := append([]byte(nil), o.resultDigest...)
	if len(digest) == 0 {
		encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(result)
		value := sha256.Sum256(encoded)
		digest = value[:]
	}
	return ResultPersistence{CommandID: result.GetCommandId(), ResultDigest: digest, Persisted: true}, nil
}
func (o *recordingObserver) counts() [3]int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return [3]int{o.acks, o.progress, o.results}
}

func testServerExecutionToken(value byte) []byte {
	return bytes.Repeat([]byte{value}, sha256.Size)
}

type agentRegistryIntegrationFixture struct {
	registry     *Registry
	journal      *commandjournal.BoltJournal
	executor     *integrationCancellationExecutor
	privateKey   ed25519.PrivateKey
	clientStream *loopbackControlClientStream
}

func TestNewServerIgnoresOldDiscoveryShapeWithoutTearingControlSession(t *testing.T) {
	server := NewServer(NewRegistry(2), NoopObserver{}, WithDiscoveryObserver(rejectingDiscoveryObserver{}))
	message := &agentv1.AgentMessage{Message: &agentv1.AgentMessage_DiscoveryReport{DiscoveryReport: &agentv1.DiscoveryReport{HostId: "host-1", AgentId: "agent-1", ObservationRevision: 1, RuleRevision: 1, ObservedAt: timestamppb.Now()}}}
	require.NoError(t, server.handleAgentMessage(context.Background(), "agent-1", message))
}

type rejectingDiscoveryObserver struct{}

func (rejectingDiscoveryObserver) SubmitDiscovery(string, *agentv1.DiscoveryReport) error {
	return ErrDiscoveryObservationInvalid
}

func newAgentRegistryIntegrationFixture(t *testing.T, observer Observer) *agentRegistryIntegrationFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	executor := &integrationCancellationExecutor{started: make(chan struct{}, 1), cancelled: make(chan struct{}, 1)}
	executors := agentruntime.NewExecutorRegistry()
	require.NoError(t, executors.Register(agentruntime.CommandKindCollectNow, executor))
	verifier, err := agentruntime.NewCommandVerifier("agent-a", publicKey, executors.Capabilities())
	require.NoError(t, err)
	registry := NewRegistry(16)
	serverStream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"))
	serverDone := make(chan error, 1)
	go func() { serverDone <- NewServer(registry, observer).Connect(serverStream) }()
	var clientStream *loopbackControlClientStream
	client, err := agentruntime.NewControlClient(agentruntime.ControlClientConfig{
		AgentID: "agent-a",
		StreamOpener: func(ctx context.Context) (agentruntime.ControlStream, error) {
			clientStream = &loopbackControlClientStream{ctx: ctx, server: serverStream}
			return clientStream, nil
		},
		Journal: journal, Verifier: verifier, Executors: executors,
		HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour,
	})
	require.NoError(t, err)
	clientContext, cancelClient := context.WithCancel(context.Background())
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(clientContext) }()
	require.Eventually(t, func() bool { _, connected := registry.Session("agent-a"); return connected }, time.Second, time.Millisecond)
	t.Cleanup(func() {
		cancelClient()
		require.NoError(t, <-clientDone)
		require.NoError(t, <-serverDone)
		require.NoError(t, journal.Close())
	})
	return &agentRegistryIntegrationFixture{registry: registry, journal: journal, executor: executor, privateKey: privateKey, clientStream: clientStream}
}

func (fixture *agentRegistryIntegrationFixture) signedEnvelope(t *testing.T, commandID string) *agentv1.CommandEnvelope {
	t.Helper()
	now := time.Now().UTC()
	envelope := &agentv1.CommandEnvelope{
		CommandId: commandID, JobId: "job-" + commandID, AgentId: "agent-a", Nonce: []byte("nonce-" + commandID), LeaseSeconds: 30,
		IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"host"}}},
	}
	payload, err := agentruntime.CommandSigningBytes(envelope)
	require.NoError(t, err)
	envelope.Signature = ed25519.Sign(fixture.privateKey, payload)
	return envelope
}

type loopbackControlClientStream struct {
	ctx      context.Context
	server   *testConnectStream
	mu       sync.Mutex
	received []*agentv1.ServerMessage
}

func (stream *loopbackControlClientStream) Send(message *agentv1.AgentMessage) error {
	select {
	case stream.server.receive <- proto.Clone(message).(*agentv1.AgentMessage):
		return nil
	case <-stream.ctx.Done():
		return stream.ctx.Err()
	}
}

func (stream *loopbackControlClientStream) Recv() (*agentv1.ServerMessage, error) {
	select {
	case message := <-stream.server.sent:
		cloned := proto.Clone(message).(*agentv1.ServerMessage)
		stream.mu.Lock()
		stream.received = append(stream.received, cloned)
		stream.mu.Unlock()
		return cloned, nil
	case <-stream.ctx.Done():
		return nil, stream.ctx.Err()
	}
}

func (stream *loopbackControlClientStream) CloseSend() error {
	stream.server.closeReceive()
	return nil
}

func (stream *loopbackControlClientStream) receivedMessages() []*agentv1.ServerMessage {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	result := make([]*agentv1.ServerMessage, 0, len(stream.received))
	for _, message := range stream.received {
		result = append(result, proto.Clone(message).(*agentv1.ServerMessage))
	}
	return result
}

type integrationCancellationExecutor struct {
	calls     atomic.Int32
	started   chan struct{}
	cancelled chan struct{}
}

func (executor *integrationCancellationExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, _ agentruntime.ProgressReporter) (*agentv1.CommandResult, error) {
	executor.calls.Add(1)
	select {
	case executor.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	select {
	case executor.cancelled <- struct{}{}:
	default:
	}
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED}, nil
}
