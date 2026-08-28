package agentcontrol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/url"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
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
	require.Equal(t, []string{"collect_now"}, ack.GetHelloAck().GetCapabilities())
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

func TestConnectRoutesAgentEventsAndRenewsCommandLease(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	registry := NewRegistry(2)
	registry.now = func() time.Time { return now }
	observer := &recordingObserver{connected: make(chan SessionInfo, 1)}
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
	stream.push(
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: "agent-a", ActiveCommandIds: []string{"command-a"}}}},
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandAcknowledgement{CommandAcknowledgement: &agentv1.CommandAcknowledgement{CommandId: "command-a"}}},
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: "command-a", Percent: 50}}},
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED}}},
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
	connected chan SessionInfo
	mu        sync.Mutex
	acks      int
	progress  int
	results   int
}

func (o *recordingObserver) Connected(_ context.Context, session SessionInfo)      { o.connected <- session }
func (o *recordingObserver) Heartbeat(context.Context, string, *agentv1.Heartbeat) {}
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
	return ResultPersistence{CommandID: result.GetCommandId(), Persisted: true}, nil
}
func (o *recordingObserver) counts() [3]int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return [3]int{o.acks, o.progress, o.results}
}
