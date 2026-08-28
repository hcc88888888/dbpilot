package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestExecutorRegistryGatesRegisteredProcessIDs(t *testing.T) {
	registry := NewExecutorRegistry()
	require.Error(t, registry.Register(CommandKindExecuteRegisteredProcess, immediateExecutor{}), "a kind-wide process executor would bypass the process allowlist")
	require.Error(t, registry.RegisterProcess("sh -c", immediateExecutor{}))
	require.NoError(t, registry.RegisterProcess("collector.health", immediateExecutor{}))

	allowed := &agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_ExecuteRegisteredProcess{ExecuteRegisteredProcess: &agentv1.ExecuteRegisteredProcess{ProcessId: "collector.health"}}}
	_, ok := registry.executor(allowed)
	require.True(t, ok)
	denied := &agentv1.CommandEnvelope{Command: &agentv1.CommandEnvelope_ExecuteRegisteredProcess{ExecuteRegisteredProcess: &agentv1.ExecuteRegisteredProcess{ProcessId: "collector.other"}}}
	_, ok = registry.executor(denied)
	require.False(t, ok)
}

func TestPrepareDoesNotExecuteUntilMatchingStart(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	executor := &progressExecutor{events: &orderedEvents{}, calls: make(chan struct{}, 2)}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, executor))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	command := signedCollectNowEnvelope(t, privateKey, "command-prepare", "agent-a", []byte("nonce-prepare"), now, now.Add(time.Minute))
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: command}}
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour, Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	require.Eventually(t, func() bool { return countPrepared(stream.sentMessages()) == 1 }, time.Second, time.Millisecond)
	select {
	case <-executor.calls:
		t.Fatal("Prepare invoked executor before CommandStart")
	case <-time.After(50 * time.Millisecond):
	}
	token := bytes.Repeat([]byte{0x61}, sha256.Size)
	stream.receive <- commandStartMessage("command-prepare", token, 17, now.Add(30*time.Second))
	select {
	case <-executor.calls:
	case <-time.After(time.Second):
		t.Fatal("matching CommandStart did not invoke executor")
	}
	require.Eventually(t, func() bool {
		for _, message := range stream.sentMessages() {
			if result := message.GetCommandResult(); result != nil {
				return bytes.Equal(token, result.GetExecutionToken()) && result.GetLeaseRevision() == 17
			}
		}
		return false
	}, time.Second, time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

func TestResultAckOnlyMarksMatchingDigestReported(t *testing.T) {
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
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: signedCollectNowEnvelope(t, privateKey, "command-result-ack", "agent-a", []byte("nonce-result-ack"), now, now.Add(time.Minute))}}
	token := bytes.Repeat([]byte{0x72}, sha256.Size)
	stream.receive <- commandStartMessage("command-result-ack", token, 19, now.Add(30*time.Second))
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour, Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	require.Eventually(t, func() bool { return countResults(stream.sentMessages()) == 1 }, time.Second, time.Millisecond)
	entry, err := journal.Get(context.Background(), "command-result-ack")
	require.NoError(t, err)
	wrong := sha256.Sum256([]byte("wrong"))
	stream.receive <- resultAckMessage("command-result-ack", wrong[:], true, false, "")
	time.Sleep(20 * time.Millisecond)
	pending, err := journal.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	stream.receive <- resultAckMessage("command-result-ack", entry.ResultDigest[:], true, false, "")
	require.Eventually(t, func() bool {
		pending, pendingErr := journal.PendingResults(context.Background())
		return pendingErr == nil && len(pending) == 0
	}, time.Second, time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientReconnectReportsActiveCommands(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	now := time.Now().UTC()
	accepted, err := journal.Prepare(context.Background(), &agentv1.CommandEnvelope{
		CommandId: "recover-me", AgentId: "agent-a", Nonce: []byte("recover-nonce"), ExpiresAt: timestamp(now.Add(time.Hour)),
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}},
	}, now)
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
	defer cancel()
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

func TestControlClientReconnectKeepsInFlightExecutorAlive(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	executor := &reconnectSurvivingExecutor{started: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{})}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, executor))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	first := newFakeControlStream()
	second := newFakeControlStream()
	first.receive <- helloAckMessage()
	second.receive <- helloAckMessage()
	first.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))}}
	first.receive <- commandStartMessage("command-a", testExecutionToken(0x01), 1, now.Add(30*time.Second))
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{first, second}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Millisecond,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	<-executor.started
	first.receiveErrors <- io.EOF
	secondHello := second.nextSent(t).GetHello()
	require.Len(t, secondHello.GetActiveCommands(), 1)
	require.Equal(t, "command-a", secondHello.GetActiveCommands()[0].GetCommandId())
	select {
	case <-executor.cancelled:
		t.Fatal("transient session loss cancelled durable executor")
	case <-time.After(50 * time.Millisecond):
	}
	close(executor.release)
	require.Eventually(t, func() bool { return countResults(second.sentMessages()) == 1 }, time.Second, time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientDoesNotPublishStreamBeforeHelloAck(t *testing.T) {
	stream := newFakeControlStream()
	client := newTransportTestClient(t, (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	require.NotNil(t, stream.nextSent(t).GetHello())

	err := client.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: "old-command"}}})

	require.ErrorIs(t, err, ErrControlStreamDisconnected)
	require.Len(t, stream.sentMessages(), 1, "Hello must be the only output before HelloAck")
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientNeverSendsNewOutputToStaleOrHandshakingSession(t *testing.T) {
	first := newFakeControlStream()
	second := newFakeControlStream()
	first.receive <- helloAckMessage()
	first.receiveErrors <- io.EOF
	client := newTransportTestClient(t, (&sequenceStreamOpener{streams: []ControlStream{first, second}}).Open)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	require.NotNil(t, first.nextSent(t).GetHello())
	require.NotNil(t, second.nextSent(t).GetHello())

	err := client.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: "during-handshake"}}})
	require.ErrorIs(t, err, ErrControlStreamDisconnected)
	require.Len(t, first.sentMessages(), 1)
	require.Len(t, second.sentMessages(), 1)

	second.receive <- helloAckMessage()
	require.Eventually(t, func() bool {
		return client.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: "new-session"}}}) == nil
	}, time.Second, time.Millisecond)
	require.Len(t, first.sentMessages(), 1, "stale session must never receive new output")
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientCancellationWaitsForBlockedReceiveLoop(t *testing.T) {
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	stream.cancelRelease = make(chan struct{})
	client := newTransportTestClient(t, (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	require.NotNil(t, stream.nextSent(t).GetHello())
	require.Eventually(t, func() bool { return stream.activeReceives.Load() == 1 }, time.Second, time.Millisecond)

	cancel()
	select {
	case <-done:
		t.Fatal("Run returned before its blocked receive loop exited")
	case <-time.After(50 * time.Millisecond):
	}
	close(stream.cancelRelease)
	require.NoError(t, <-done)
	require.Zero(t, stream.activeReceives.Load())
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
	stream.receive <- commandStartMessage("command-a", testExecutionToken(0x02), 2, now.Add(30*time.Second))
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
		return countPrepared(messages) == 2 && countProgress(messages) == 1 && countResults(messages) == 1
	}, 2*time.Second, time.Millisecond)
	require.Equal(t, 1, len(executor.calls), "a replayed command ID must not execute twice")
	require.Less(t, events.index("prepare:command-a"), events.index("prepared:command-a"))
	entry, err := realJournal.Get(context.Background(), "command-a")
	require.NoError(t, err)
	require.Equal(t, commandjournal.StateCompleted, entry.State)
	pending, err := realJournal.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1, "a successful stream send is not a durability acknowledgement")
	stream.receive <- resultAckMessage("command-a", entry.ResultDigest[:], true, false, "")
	require.Eventually(t, func() bool {
		pending, pendingErr := realJournal.PendingResults(context.Background())
		return pendingErr == nil && len(pending) == 0
	}, time.Second, time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientReplaysPendingResultAfterSendFailureAndReconnect(t *testing.T) {
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
	first := newFakeControlStream()
	second := newFakeControlStream()
	first.receive <- helloAckMessage()
	second.receive <- helloAckMessage()
	first.sendFailure = func(message *agentv1.AgentMessage) error {
		if message.GetCommandResult() != nil {
			return errors.New("first result send failed")
		}
		return nil
	}
	first.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))}}
	first.receive <- commandStartMessage("command-a", testExecutionToken(0x03), 3, now.Add(30*time.Second))
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{first, second}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Millisecond,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	require.Eventually(t, func() bool { return countResults(second.sentMessages()) == 1 }, 2*time.Second, time.Millisecond)
	require.Zero(t, countResults(first.sentMessages()), "failed result send must not be treated as delivered")
	pending, err := journal.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1, "reconnect send must remain pending without server durability acknowledgement")
	entry, err := journal.Get(context.Background(), "command-a")
	require.NoError(t, err)
	second.receive <- resultAckMessage("command-a", entry.ResultDigest[:], false, true, "PERSISTENCE_RETRY")
	time.Sleep(20 * time.Millisecond)
	pending, err = journal.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1, "negative/retryable acknowledgement must keep the result pending")
	second.receive <- resultAckMessage("command-a", entry.ResultDigest[:], true, false, "")
	require.Eventually(t, func() bool {
		pending, pendingErr := journal.PendingResults(context.Background())
		return pendingErr == nil && len(pending) == 0
	}, time.Second, time.Millisecond)
	entry, err = journal.Get(context.Background(), "command-a")
	require.NoError(t, err)
	require.False(t, entry.ReportedAt.IsZero())
	cancel()
	require.NoError(t, <-done)
}

func resultAckMessage(commandID string, resultDigest []byte, persisted, retryable bool, reason string) *agentv1.ServerMessage {
	return &agentv1.ServerMessage{Message: &agentv1.ServerMessage_CommandResultAcknowledgement{CommandResultAcknowledgement: &agentv1.CommandResultAcknowledgement{CommandId: commandID, ResultDigest: resultDigest, Persisted: persisted, Retryable: retryable, ReasonCode: reason}}}
}

func TestControlClientSurfacesTerminalResultPersistenceFailure(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	realJournal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = realJournal.Close() })
	journal := &failingCompleteJournal{Journal: realJournal, completeCalled: make(chan struct{})}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, immediateExecutor{}))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))}}
	stream.receive <- commandStartMessage("command-a", testExecutionToken(0x04), 4, now.Add(30*time.Second))
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Millisecond,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	<-journal.completeCalled

	select {
	case runErr := <-done:
		require.ErrorContains(t, runErr, "persist terminal command result")
	case <-time.After(200 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("terminal result persistence failure was ignored")
	}
	require.Zero(t, countResults(stream.sentMessages()))
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

func TestControlClientRejectsCommandIDCollisionWithoutDuplicateAck(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	executor := &progressExecutor{events: &orderedEvents{}, calls: make(chan struct{}, 2)}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, executor))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	first := signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))
	collision := signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-b"), now, now.Add(time.Minute))
	collision.GetCollectNow().CollectionKinds = []string{"different"}
	signEnvelope(t, privateKey, collision)
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: first}}
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: collision}}
	stream.receive <- commandStartMessage("command-a", testExecutionToken(0x05), 5, now.Add(30*time.Second))
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()

	require.Eventually(t, func() bool {
		messages := stream.sentMessages()
		return countPrepared(messages) == 1 && countAcknowledgements(messages, agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED) == 1
	}, time.Second, time.Millisecond)
	require.Zero(t, countAcknowledgements(stream.sentMessages(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE))
	require.Equal(t, "COMMAND_ID_CONFLICT", acknowledgementReason(stream.sentMessages(), agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED))
	require.Eventually(t, func() bool { return len(executor.calls) == 1 }, time.Second, time.Millisecond)
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
	token := testExecutionToken(0x06)
	stream.receive <- commandStartMessage("command-a", token, 6, now.Add(30*time.Second))
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
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_CommandCancellation{CommandCancellation: &agentv1.CommandCancellation{CommandId: "command-a", ExecutionToken: token, LeaseRevision: 6}}}
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
	stream.receive <- commandStartMessage("command-a", testExecutionToken(0x07), 7, now.Add(30*time.Second))
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

func TestControlClientShutdownJoinsExecutorBeforeReturning(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	executor := &shutdownBlockingExecutor{started: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{})}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, executor))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))}}
	stream.receive <- commandStartMessage("command-a", testExecutionToken(0x08), 8, now.Add(30*time.Second))
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	<-executor.started
	cancel()
	<-executor.cancelled

	select {
	case <-done:
		t.Fatal("Run returned before cancelled executor cleanup completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(executor.release)
	require.NoError(t, <-done)
	entry, err := journal.Get(context.Background(), "command-a")
	require.NoError(t, err)
	require.Equal(t, commandjournal.StateCompleted, entry.State, "journal completion must finish before Run returns and its owner closes the journal")
}

func TestControlClientShutdownSurfacesCompletionFailureFromJoinedExecutor(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	realJournal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = realJournal.Close() })
	journal := &failingCompleteJournal{Journal: realJournal, completeCalled: make(chan struct{})}
	executor := &shutdownCompletionExecutor{started: make(chan struct{})}
	registry := NewExecutorRegistry()
	require.NoError(t, registry.Register(CommandKindCollectNow, executor))
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	now := time.Now().UTC()
	verifier.now = func() time.Time { return now }
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_Command{Command: signedCollectNowEnvelope(t, privateKey, "command-a", "agent-a", []byte("nonce-a"), now, now.Add(time.Minute))}}
	stream.receive <- commandStartMessage("command-a", testExecutionToken(0x09), 9, now.Add(30*time.Second))
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open,
		Journal: journal, Verifier: verifier, Executors: registry, HeartbeatInterval: time.Hour, ReconnectBackoff: time.Hour,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	<-executor.started
	cancel()
	<-journal.completeCalled

	require.ErrorContains(t, <-done, "persist terminal command result")
}

func timestamp(value time.Time) *timestamppb.Timestamp { return timestamppb.New(value) }

func newTransportTestClient(t *testing.T, opener StreamOpener) *ControlClient {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "transport.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	registry := NewExecutorRegistry()
	verifier, err := NewCommandVerifier("agent-a", publicKey, registry.Capabilities())
	require.NoError(t, err)
	client, err := NewControlClient(ControlClientConfig{
		AgentID: "agent-a", StreamOpener: opener, Journal: journal, Verifier: verifier, Executors: registry,
		HeartbeatInterval: time.Hour, ReconnectBackoff: time.Millisecond,
	})
	require.NoError(t, err)
	return client
}

type sequenceStreamOpener struct {
	mu      sync.Mutex
	streams []ControlStream
	index   int
}

func (o *sequenceStreamOpener) Open(ctx context.Context) (ControlStream, error) {
	return o.openWithContext(ctx)
}

func (o *sequenceStreamOpener) openWithContext(ctx context.Context) (ControlStream, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.index >= len(o.streams) {
		return nil, errors.New("no fake stream available")
	}
	stream := o.streams[o.index]
	o.index++
	if fake, ok := stream.(*fakeControlStream); ok {
		fake.setContext(ctx)
	}
	return stream, nil
}

type fakeControlStream struct {
	mu             sync.Mutex
	receive        chan *agentv1.ServerMessage
	receiveErrors  chan error
	sent           []*agentv1.AgentMessage
	events         *orderedEvents
	ctx            context.Context
	cancelRelease  chan struct{}
	activeReceives atomic.Int32
	sendFailure    func(*agentv1.AgentMessage) error
}

func newFakeControlStream() *fakeControlStream {
	return &fakeControlStream{receive: make(chan *agentv1.ServerMessage, 16), receiveErrors: make(chan error, 4)}
}

func (s *fakeControlStream) Send(message *agentv1.AgentMessage) error {
	if s.sendFailure != nil {
		if err := s.sendFailure(message); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.sent = append(s.sent, message)
	s.mu.Unlock()
	if prepared := message.GetCommandPrepared(); prepared != nil && s.events != nil {
		s.events.add("prepared:" + prepared.GetCommandId())
	}
	if acknowledgement := message.GetCommandAcknowledgement(); acknowledgement != nil && s.events != nil {
		if acknowledgement.GetState() == agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED {
			s.events.add("ack:accepted")
		}
	}
	return nil
}
func (s *fakeControlStream) Recv() (*agentv1.ServerMessage, error) {
	s.activeReceives.Add(1)
	defer s.activeReceives.Add(-1)
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
	case <-s.contextDone():
		if s.cancelRelease != nil {
			<-s.cancelRelease
		}
		return nil, context.Canceled
	}
}
func (s *fakeControlStream) CloseSend() error { return nil }
func (s *fakeControlStream) setContext(ctx context.Context) {
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()
}
func (s *fakeControlStream) contextDone() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return make(chan struct{})
	}
	return s.ctx.Done()
}
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

type failingCompleteJournal struct {
	commandjournal.Journal
	completeCalled chan struct{}
	once           sync.Once
}

func (j *failingCompleteJournal) Complete(context.Context, string, *agentv1.CommandResult, time.Time) error {
	j.once.Do(func() { close(j.completeCalled) })
	return errors.New("journal disk failure")
}

func (j *recordingCommandJournal) Prepare(ctx context.Context, envelope *agentv1.CommandEnvelope, at time.Time) (bool, error) {
	prepared, err := j.Journal.Prepare(ctx, envelope, at)
	if prepared && err == nil {
		j.events.add("prepare:" + envelope.GetCommandId())
	}
	return prepared, err
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

type shutdownBlockingExecutor struct {
	started   chan struct{}
	cancelled chan struct{}
	release   chan struct{}
}

func (e *shutdownBlockingExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, _ ProgressReporter) (*agentv1.CommandResult, error) {
	close(e.started)
	<-ctx.Done()
	close(e.cancelled)
	<-e.release
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED}, nil
}

type reconnectSurvivingExecutor struct {
	started   chan struct{}
	cancelled chan struct{}
	release   chan struct{}
}

func (e *reconnectSurvivingExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, _ ProgressReporter) (*agentv1.CommandResult, error) {
	close(e.started)
	select {
	case <-e.release:
		return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED}, nil
	case <-ctx.Done():
		close(e.cancelled)
		return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED}, nil
	}
}

type shutdownCompletionExecutor struct{ started chan struct{} }

func (e *shutdownCompletionExecutor) Execute(ctx context.Context, envelope *agentv1.CommandEnvelope, _ ProgressReporter) (*agentv1.CommandResult, error) {
	close(e.started)
	<-ctx.Done()
	return &agentv1.CommandResult{CommandId: envelope.GetCommandId(), State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED}, nil
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
func acknowledgementReason(messages []*agentv1.AgentMessage, state agentv1.CommandAcknowledgementState) string {
	for _, message := range messages {
		if acknowledgement := message.GetCommandAcknowledgement(); acknowledgement != nil && acknowledgement.GetState() == state {
			return acknowledgement.GetReasonCode()
		}
	}
	return ""
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

func countPrepared(messages []*agentv1.AgentMessage) int {
	count := 0
	for _, message := range messages {
		if message.GetCommandPrepared() != nil {
			count++
		}
	}
	return count
}

func commandStartMessage(commandID string, token []byte, revision uint64, deadline time.Time) *agentv1.ServerMessage {
	return &agentv1.ServerMessage{Message: &agentv1.ServerMessage_CommandStart{CommandStart: &agentv1.CommandStart{
		CommandId: commandID, ExecutionToken: token, LeaseRevision: revision, LeaseSeconds: 30, StartDeadline: timestamppb.New(deadline),
	}}}
}

func testExecutionToken(value byte) []byte {
	return bytes.Repeat([]byte{value}, sha256.Size)
}
