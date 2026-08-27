package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestControlClientReconnectReportsActiveCommands(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	now := time.Now().UTC()
	accepted, err := journal.Accept(context.Background(), &agentv1.CommandEnvelope{
		CommandId: "recover-me", AgentId: "agent-a", ExpiresAt: timestamp(now.Add(time.Hour)),
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}},
	})
	require.NoError(t, err)
	require.True(t, accepted)

	first := newFakeControlStream()
	second := newFakeControlStream()
	first.receive <- helloAckMessage()
	first.receiveErrors <- io.EOF
	second.receive <- helloAckMessage()
	opener := &sequenceStreamOpener{streams: []ControlStream{first, second}}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, immediateExecutor{}))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: opener.Open, Journal: journal, Verifier: verifier, Executors: registry,
		HeartbeatInterval: time.Hour, ReconnectBackoff: time.Millisecond,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	firstHello := first.nextSent(t).GetHello()
	require.Len(t, firstHello.GetActiveCommands(), 1)
	require.Equal(t, "recover-me", firstHello.GetActiveCommands()[0].GetCommandId())
	secondHello := second.nextSent(t).GetHello()
	require.Len(t, secondHello.GetActiveCommands(), 1)
	require.Equal(t, "recover-me", secondHello.GetActiveCommands()[0].GetCommandId())
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientDurablyAcknowledgesExecutesReportsAndDeduplicates(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	realJournal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = realJournal.Close() })
	events := &orderedEvents{}
	journal := &recordingCommandJournal{Journal: realJournal, events: events}
	executor := &progressExecutor{events: events, calls: make(chan struct{}, 2)}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, executor))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	stream := newFakeControlStream()
	stream.events = events
	stream.receive <- helloAckMessage()
	command := signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: command}}
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: command}}
	opener := &sequenceStreamOpener{streams: []ControlStream{stream}}
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: opener.Open, Journal: journal, Verifier: verifier, Executors: registry,
		HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	require.Eventually(t, func() bool {
		messages := stream.sentMessages()
		return countAcknowledgements(messages, agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED) == 1 &&
			countAcknowledgements(messages, agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE) == 1 &&
			countProgress(messages) == 1 && countResults(messages) == 1
	}, 2*time.Second, time.Millisecond)
	require.Equal(t, 1, len(executor.calls), "a replayed command ID must not execute twice")
	require.Less(t, events.index("accept:command-a"), events.index("ack:accepted"))
	entry, err := realJournal.Get(context.Background(), "command-a")
	require.NoError(t, err)
	require.Equal(t, commandjournal.StateCompleted, entry.State)
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientRejectsInvalidCommandBeforeJournal(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, immediateExecutor{}))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	invalid := signedCollectNowEnvelope(t, privateKey, "invalid", "agent-a", []byte("nonce-invalid"), now, now.Add(time.Minute))
	invalid.Signature[0] ^= 0xff
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: invalid}}
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	require.Eventually(t, func() bool {
		return countAcknowledgements(stream.sentMessages(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED) == 1
	}, time.Second, time.Millisecond)
	_, err = journal.Get(context.Background(), "invalid")
	require.ErrorIs(t, err, commandjournal.ErrCommandNotFound)
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientCancellationCancelsExecutorContext(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	executor := &cancellationExecutor{started: make(chan struct{}), cancelled: make(chan struct{})}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, executor))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))}}
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	select {
	case <-executor.started:
	case <-time.After(time.Second):
		t.Fatal("executor did not start")
	}
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_CommandCancellation{CommandCancellation: &agentv1.CommandCancellation{CommandId: "command-a"}}}
	select {
	case <-executor.cancelled:
	case <-time.After(time.Second):
		t.Fatal("executor context was not cancelled")
	}
	require.Eventually(t, func() bool { return countResults(stream.sentMessages()) == 1 }, time.Second, time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientReleasesExecutorContextAfterCompletion(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	executor := &contextObservingExecutor{contexts: make(chan context.Context, 1)}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, executor))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))}}
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	executionContext := <-executor.contexts
	require.Eventually(t, func() bool { return countResults(stream.sentMessages()) == 1 }, time.Second, time.Millisecond)

	select {
	case <-executionContext.Done():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("completed executor context was not released")
	}
	cancel()
	require.NoError(t, <-done)
}

func timestamp(value time.Time) *timestamppb.Timestamp { return timestamppb.New(value) }

type sequenceStreamOpener struct {
	mu      sync.Mutex
	streams []ControlStream
	index   int
}

func (o *sequenceStreamOpener) Open(context.Context) (ControlStream, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.index >= len(o.streams) {
		return nil, errors.New("no fake stream available")
	}
	stream := o.streams[o.index]
	o.index++
	return stream, nil
}

type fakeControlStream struct {
	mu            sync.Mutex
	receive       chan *agentv1.ServerMessage
	receiveErrors chan error
	sent          []*agentv1.AgentMessage
	events        *orderedEvents
}

func newFakeControlStream() *fakeControlStream {
	return &fakeControlStream{receive: make(chan *agentv1.ServerMessage, 16), receiveErrors: make(chan error, 4)}
}

func (s *fakeControlStream) Send(message *agentv1.AgentMessage) error {
	s.mu.Lock()
	s.sent = append(s.sent, message)
	s.mu.Unlock()
	if acknowledgement := message.GetCommandAcknowledgement(); acknowledgement != nil && s.events != nil {
		if acknowledgement.GetState() == agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED {
			s.events.add("ack:accepted")
		}
	}
	return nil
}
func (s *fakeControlStream) Recv() (*agentv1.ServerMessage, error) {
	select {
	case message := <-s.receive:
		return message, nil
	default:
	}
	select {
	case message := <-s.receive:
		return message, nil
	case err := <-s.receiveErrors:
		return nil, err
	}
}
func (s *fakeControlStream) CloseSend() error { return nil }
func (s *fakeControlStream) sentMessages() []*agentv1.AgentMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*agentv1.AgentMessage(nil), s.sent...)
}
func (s *fakeControlStream) nextSent(t *testing.T) *agentv1.AgentMessage {
	t.Helper()
	require.Eventually(t, func() bool { return len(s.sentMessages()) > 0 }, time.Second, time.Millisecond)
	return s.sentMessages()[0]
}

func helloAckMessage() *agentv1.ServerMessage {
	return &agentv1.ServerMessage{Message: &agentv1.ServerMessage_HelloAck{HelloAck: &agentv1.HelloAck{ProtocolVersion: ControlProtocolVersion}}}
}

type recordingCommandJournal struct {
	commandjournal.Journal
	events *orderedEvents
}

func (j *recordingCommandJournal) Accept(ctx context.Context, envelope *agentv1.CommandEnvelope) (bool, error) {
	accepted, err := j.Journal.Accept(ctx, envelope)
	if accepted && err == nil {
		j.events.add("accept:" + envelope.GetCommandId())
	}
	return accepted, err
}

type orderedEvents struct {
	mu     sync.Mutex
	values []string
}

func (e *orderedEvents) add(value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.values = append(e.values, value)
}
func (e *orderedEvents) index(value string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	for index, candidate := range e.values {
		if candidate == value {
			return index
		}
	}
	return len(e.values)
}

type progressExecutor struct {
	events *orderedEvents
	calls  chan struct{}
}

func (e *progressExecutor) Execute(_ context.Context, envelope *agentv1.CommandEnvelope, reporter ProgressReporter) (*agentv1.CommandResult, error) {
	e.calls <- struct{}{}
	if err := reporter.Report(&agentv1.CommandProgress{CommandId: envelope.GetCommandId(), Percent: 50, Stage: "collecting"}); err != nil {
		return nil, err
	}
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "done"}, nil
}

type immediateExecutor struct{}

func (immediateExecutor) Execute(_ context.Context, envelope *agentv1.CommandEnvelope, _ ProgressReporter) (*agentv1.CommandResult, error) {
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED}, nil
}

type cancellationExecutor struct {
	started   chan struct{}
	cancelled chan struct{}
}

func (e *cancellationExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, _ ProgressReporter) (*agentv1.CommandResult, error) {
	close(e.started)
	<-ctx.Done()
	close(e.cancelled)
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED}, nil
}

type contextObservingExecutor struct{ contexts chan context.Context }

func (e *contextObservingExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, _ ProgressReporter) (*agentv1.CommandResult, error) {
	e.contexts <- ctx
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED}, nil
}

func countAcknowledgements(messages []*agentv1.AgentMessage, state agentv1.CommandAcknowledgementState) int {
	count := 0
	for _, message := range messages {
		if acknowledgement := message.GetCommandAcknowledgement(); acknowledgement != nil && acknowledgement.GetState() == state {
			count++
		}
	}
	return count
}
func countProgress(messages []*agentv1.AgentMessage) int {
	count := 0
	for _, message := range messages {
		if message.GetCommandProgress() != nil {
			count++
		}
	}
	return count
}
func countResults(messages []*agentv1.AgentMessage) int {
	count := 0
	for _, message := range messages {
		if message.GetCommandResult() != nil {
			count++
		}
	}
	return count
}
