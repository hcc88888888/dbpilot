package job

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"dbpilot.local/platform/internal/agentcontrol"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEd25519CommandSignerParsesPKCS8PEMAndMatchesAgentVerifier(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	signer, err := NewEd25519CommandSignerPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	require.NoError(t, err)

	now := time.Now().UTC().Truncate(time.Second)
	envelope := &agentv1.CommandEnvelope{
		CommandId: "command-1", JobId: "job-1", AgentId: "agent-a", LeaseSeconds: 30,
		IssuedAt: timestamp(now), ExpiresAt: timestamp(now.Add(time.Minute)), Nonce: bytes.Repeat([]byte{0x42}, commandNonceBytes),
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"health"}}},
	}
	require.NoError(t, signer.Sign(context.Background(), envelope))
	verifier, err := agent.NewCommandVerifier("agent-a", publicKey, []string{"collect_now"})
	require.NoError(t, err)
	require.NoError(t, verifier.Verify(context.Background(), envelope))

	_, err = NewEd25519CommandSignerPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-pkcs8")}))
	require.Error(t, err)
	_, err = NewEd25519CommandSignerPEM([]byte("not PEM"))
	require.Error(t, err)
}

func TestTwoPhasePreparedPersistsFenceBeforeReturningStart(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	fixture.persistence.claimed = []OutboxMessage{message}

	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	require.Len(t, fixture.agents.envelopes, 1)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(fixture.agents.envelopes[0])
	require.NoError(t, err)
	digest := sha256.Sum256(encoded)
	message.PreparedEnvelope = encoded
	fixture.persistence.messages[message.ID] = message

	returned, err := fixture.lifecycle.Prepared(context.Background(), "agent-a", &agentv1.CommandPrepared{CommandId: message.ID, EnvelopeDigest: digest[:]})
	require.NoError(t, err)
	require.Nil(t, returned, "the lifecycle enqueues the committed Start while holding its command transition stripe")
	require.Len(t, fixture.agents.starts, 1)
	start := fixture.agents.starts[0]
	require.Equal(t, message.ID, start.GetCommandId())
	require.Len(t, start.GetExecutionToken(), sha256.Size)
	require.Equal(t, uint64(1), start.GetLeaseRevision())
	require.Equal(t, uint32(30), start.GetLeaseSeconds())
	require.Equal(t, fixture.now.Add(30*time.Second), start.GetStartDeadline().AsTime())

	stored := fixture.persistence.messages[message.ID]
	require.Equal(t, CommandPhaseStartAuthorized, stored.Phase)
	require.Equal(t, digest[:], stored.PrepareDigest)
	require.Equal(t, start.GetLeaseRevision(), stored.ExecutionRevision)
	tokenHash := sha256.Sum256(start.GetExecutionToken())
	require.Equal(t, tokenHash[:], stored.ExecutionTokenHash)
	require.NotEqual(t, start.GetExecutionToken(), stored.ExecutionTokenCiphertext)
	require.NotNil(t, stored.StartEnqueuedAt, "cancellation delivery must not overtake a committed-but-not-enqueued Start")
}

func TestTwoPhaseAES256GCMTokenProtectorRequiresExactKeyAndRoundTrips(t *testing.T) {
	_, err := NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x11}, 31))
	require.Error(t, err)
	_, err = NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x11}, 33))
	require.Error(t, err)
	protector, err := NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x11}, 32))
	require.NoError(t, err)
	token := bytes.Repeat([]byte{0x22}, sha256.Size)
	ciphertext, err := protector.Protect(context.Background(), token)
	require.NoError(t, err)
	require.NotEqual(t, token, ciphertext)
	restored, err := protector.Unprotect(context.Background(), ciphertext)
	require.NoError(t, err)
	require.Equal(t, token, restored)
}

func TestTwoPhaseCancelBeforePreparedPreventsStartDispatch(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	fixture.persistence.claimed = []OutboxMessage{message}
	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(fixture.agents.envelopes[0])
	require.NoError(t, err)
	digest := sha256.Sum256(encoded)
	message.PreparedEnvelope = encoded
	message.Phase = CommandPhasePreparing
	fixture.persistence.messages[message.ID] = message
	current := fixture.persistence.currentJob()
	_, err = fixture.persistence.RequestCancel(context.Background(), fixture.scope, current.ID, "operator", current.Version, fixture.now.Add(time.Second))
	require.NoError(t, err)

	start, err := fixture.lifecycle.Prepared(context.Background(), "agent-a", &agentv1.CommandPrepared{CommandId: message.ID, EnvelopeDigest: digest[:]})
	require.NoError(t, err)
	require.Nil(t, start)
	require.Empty(t, fixture.agents.starts, "a cancellation transaction that commits first must prevent Start")
	require.Equal(t, []string{"cancel-unfenced:" + message.ID}, fixture.agents.events, "the Agent's durable Prepare must be cleared even when cancellation wins the database CAS")
}

func TestPreparedRecoveryPeriodicallyAuthorizesAndReplaysStart(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message, _ := fixture.persistPreparedCommand(t, "command-a", "agent-a")
	fixture.persistence.claimed = nil

	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(time.Second))
	require.NoError(t, err)
	require.Len(t, fixture.agents.starts, 1)
	require.Equal(t, message.ID, fixture.agents.starts[0].GetCommandId())
	require.Equal(t, CommandPhaseStartAuthorized, fixture.persistence.messages[message.ID].Phase)
}

func TestPreparedRecoveryTimesOutJobAndCommandWithoutStart(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message, _ := fixture.persistPreparedCommand(t, "command-a", "agent-a")
	fixture.persistence.claimed = nil
	value := fixture.persistence.currentJob()
	timeout := fixture.now.Add(-time.Second)
	value.TimeoutAt = &timeout
	fixture.persistence.jobs[value.ID] = value

	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	require.Empty(t, fixture.agents.starts)
	require.Equal(t, StatusTimedOut, fixture.persistence.currentJob().Status)
	require.Equal(t, TargetTimedOut, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.Equal(t, "command.prepared_timed_out", fixture.audit.events[len(fixture.audit.events)-1].Action)
}

func TestDispatchPendingTimesOutUndeliveredPreparingCommandAtJobDeadline(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-offline", "agent-a")
	message.Phase = CommandPhasePreparing
	fixture.persistence.messages[message.ID] = message
	fixture.persistence.claimed = []OutboxMessage{message}
	value := fixture.persistence.currentJob()
	timeout := fixture.now.Add(-time.Second)
	value.TimeoutAt = &timeout
	fixture.persistence.jobs[value.ID] = value

	dispatched, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)

	require.NoError(t, err)
	require.Zero(t, dispatched)
	require.Empty(t, fixture.agents.envelopes, "an expired Job must not keep retrying an undelivered command")
	require.Equal(t, StatusTimedOut, fixture.persistence.currentJob().Status)
	require.Equal(t, TargetTimedOut, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.Equal(t, "command.undelivered_timed_out", fixture.audit.events[len(fixture.audit.events)-1].Action)
}

func TestPreparedEnvelopeExpiryPeriodicallyTerminalizesWithoutStartAndIsIdempotent(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message, _ := fixture.persistPreparedCommand(t, "command-expired-periodic", "agent-a")
	fixture.persistence.claimed = nil
	expiredAt := fixture.agents.envelopes[0].GetExpiresAt().AsTime().Add(time.Second)

	_, err := fixture.lifecycle.DispatchPending(context.Background(), expiredAt)
	require.NoError(t, err)
	require.Empty(t, fixture.agents.starts, "an expired immutable Prepare envelope must never be authorized")
	require.Equal(t, []string{"cancel-unfenced:" + message.ID}, fixture.agents.events)
	first := fixture.persistence.currentJob()
	require.Equal(t, StatusTimedOut, first.Status)
	require.Equal(t, TargetTimedOut, first.TargetResults[0].Status)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.Equal(t, "command.prepared_envelope_expired", fixture.audit.events[len(fixture.audit.events)-1].Action)

	_, err = fixture.lifecycle.DispatchPending(context.Background(), expiredAt.Add(DefaultOutboxLease))
	require.NoError(t, err)
	require.Equal(t, first.Version, fixture.persistence.currentJob().Version)
	require.Len(t, fixture.audit.events, 2, "RecordOnce must retain one dispatch Audit and one expiry Audit")
	require.Equal(t, []string{"cancel-unfenced:" + message.ID}, fixture.agents.events)
}

func TestPreparedEnvelopeExpiryOnConnectedSessionNeverStartsExecutor(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message, _ := fixture.persistPreparedCommand(t, "command-expired-connected", "agent-a")
	fixture.persistence.claimed = nil
	expiredAt := fixture.agents.envelopes[0].GetExpiresAt().AsTime().Add(time.Second)
	fixture.lifecycle.now = func() time.Time { return expiredAt }

	fixture.lifecycle.Connected(context.Background(), agentcontrol.SessionInfo{AgentID: "agent-a", ActiveCommands: []*agentv1.CommandRecoveryState{{CommandId: message.ID, State: agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_PREPARED}}})

	require.Empty(t, fixture.agents.starts)
	require.Equal(t, []string{"cancel-unfenced:" + message.ID}, fixture.agents.events)
	require.Equal(t, StatusTimedOut, fixture.persistence.currentJob().Status)
	require.Equal(t, TargetTimedOut, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.Empty(t, fixture.observerErrors())
}

func TestPreparedAcknowledgementAfterEnvelopeExpiryNeverAuthorizesStart(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message, digest := fixture.persistPreparedCommand(t, "command-expired-ack", "agent-a")
	expiredAt := fixture.agents.envelopes[0].GetExpiresAt().AsTime().Add(time.Second)
	fixture.lifecycle.now = func() time.Time { return expiredAt }

	start, err := fixture.lifecycle.Prepared(context.Background(), "agent-a", &agentv1.CommandPrepared{CommandId: message.ID, EnvelopeDigest: digest[:]})
	require.NoError(t, err)
	require.Nil(t, start)
	require.Empty(t, fixture.agents.starts)
	require.Equal(t, StatusTimedOut, fixture.persistence.currentJob().Status)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
}

func TestPreparedEnvelopeExpiryAndCancellationHonorTheCommittedWinnerWithoutStart(t *testing.T) {
	t.Run("cancellation commits first", func(t *testing.T) {
		fixture := newSingleTargetCommandLifecycleFixture(t)
		message, _ := fixture.persistPreparedCommand(t, "command-expiry-cancel-first", "agent-a")
		current := fixture.persistence.currentJob()
		_, err := fixture.persistence.RequestCancel(context.Background(), fixture.scope, current.ID, "operator", current.Version, fixture.now.Add(time.Second))
		require.NoError(t, err)
		expiredAt := fixture.agents.envelopes[0].GetExpiresAt().AsTime().Add(time.Second)
		fixture.lifecycle.now = func() time.Time { return expiredAt }

		fixture.lifecycle.Connected(context.Background(), agentcontrol.SessionInfo{AgentID: "agent-a", ActiveCommands: []*agentv1.CommandRecoveryState{{CommandId: message.ID, State: agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_PREPARED}}})

		require.Empty(t, fixture.agents.starts)
		require.Equal(t, StatusCancelled, fixture.persistence.currentJob().Status)
		require.Equal(t, CommandCancelled, fixture.persistence.messages[message.ID].CommandStatus)
	})

	t.Run("expiry commits first", func(t *testing.T) {
		fixture := newSingleTargetCommandLifecycleFixture(t)
		message, _ := fixture.persistPreparedCommand(t, "command-expiry-first", "agent-a")
		expiredAt := fixture.agents.envelopes[0].GetExpiresAt().AsTime().Add(time.Second)
		_, err := fixture.lifecycle.DispatchPending(context.Background(), expiredAt)
		require.NoError(t, err)
		current := fixture.persistence.currentJob()
		_, err = fixture.persistence.RequestCancel(context.Background(), fixture.scope, current.ID, "operator", current.Version, expiredAt.Add(time.Second))
		require.ErrorIs(t, err, ErrInvalidTransition)
		require.Empty(t, fixture.agents.starts)
		require.Equal(t, StatusTimedOut, current.Status)
		require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	})
}

func TestStartEnqueueMarkerFailureReplaysIdenticalPersistedStart(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message, digest := fixture.persistPreparedCommand(t, "command-a", "agent-a")
	fixture.persistence.claimed = nil
	fixture.persistence.markStartErrors = []error{errors.New("marker unavailable"), nil}

	_, err := fixture.lifecycle.Prepared(context.Background(), "agent-a", &agentv1.CommandPrepared{CommandId: message.ID, EnvelopeDigest: digest[:]})
	require.ErrorContains(t, err, "marker unavailable")
	require.Len(t, fixture.agents.starts, 1)
	require.Nil(t, fixture.persistence.messages[message.ID].StartEnqueuedAt)

	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(time.Second))
	require.NoError(t, err)
	require.Len(t, fixture.agents.starts, 2)
	require.True(t, proto.Equal(fixture.agents.starts[0], fixture.agents.starts[1]))
	require.NotNil(t, fixture.persistence.messages[message.ID].StartEnqueuedAt)
}

func TestTimeoutRepairPersistsJobAndAuditBeforeCommandFinalization(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	fixture.persistence.messages[message.ID] = message
	fixture.fenceMessage(t, message.ID)
	message = fixture.persistence.messages[message.ID]
	deadline := fixture.now.Add(-time.Second)
	message.ExecutionDeadline = &deadline
	fixture.persistence.messages[message.ID] = message
	fixture.persistence.expired = []OutboxMessage{message}
	fixture.persistence.finalizeErrors = []error{errors.New("terminal write unavailable"), nil}
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now.Add(-time.Minute))
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now.Add(-time.Minute)})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current

	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.ErrorContains(t, err, "terminal write unavailable")
	first := fixture.persistence.currentJob()
	require.Equal(t, StatusRunning, first.Status)
	require.Equal(t, CommandActive, fixture.persistence.messages[message.ID].CommandStatus)
	require.Empty(t, fixture.audit.events)

	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(DefaultOutboxLease+time.Second))
	require.NoError(t, err)
	require.Greater(t, fixture.persistence.currentJob().Version, first.Version)
	require.Equal(t, StatusTimedOut, fixture.persistence.currentJob().Status)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.Len(t, fixture.audit.events, 1, "timeout retry must use the same RecordOnce evidence")
}

func TestTimeoutAuditFailureLeavesCommandClaimableForIdempotentRepair(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	fixture.persistence.messages[message.ID] = message
	fixture.fenceMessage(t, message.ID)
	message = fixture.persistence.messages[message.ID]
	deadline := fixture.now.Add(-time.Second)
	message.ExecutionDeadline = &deadline
	fixture.persistence.messages[message.ID] = message
	fixture.persistence.expired = []OutboxMessage{message}
	fixture.audit.onceErrors = []error{errors.New("audit unavailable"), nil}
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now.Add(-time.Minute))
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now.Add(-time.Minute)})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current

	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.ErrorContains(t, err, "audit unavailable")
	first := fixture.persistence.currentJob()
	require.Equal(t, StatusTimedOut, first.Status)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.True(t, fixture.persistence.messages[message.ID].TerminalAuditPending)
	require.Empty(t, fixture.audit.events)

	restarted, restartErr := NewCommandLifecycle(CommandLifecycleConfig{
		DispatchRepository: fixture.persistence, Jobs: fixture.persistence, Agents: fixture.agents,
		Signer: fixture.lifecycle.signer, Audit: fixture.audit, TokenProtector: fixture.lifecycle.tokenProtector,
		ClaimLimit: 8, Now: func() time.Time { return fixture.now.Add(DefaultOutboxLease + time.Second) },
	})
	require.NoError(t, restartErr)
	fixture.lifecycle = restarted
	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(DefaultOutboxLease+time.Second))
	require.NoError(t, err)
	require.Equal(t, first.Version, fixture.persistence.currentJob().Version)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.Len(t, fixture.audit.events, 1)
	require.False(t, fixture.persistence.messages[message.ID].TerminalAuditPending)
}

func TestConnectedRepairsPendingTerminalAuditWithoutJobMutation(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	fixture.persistence.messages[message.ID] = message
	fixture.fenceMessage(t, message.ID)
	message = fixture.persistence.messages[message.ID]
	deadline := fixture.now.Add(-time.Second)
	message.ExecutionDeadline = &deadline
	fixture.persistence.messages[message.ID] = message
	fixture.persistence.expired = []OutboxMessage{message}
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now.Add(-time.Minute))
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now.Add(-time.Minute)})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current
	claims, err := fixture.persistence.ClaimExpiredExecution(context.Background(), 1, fixture.now)
	require.NoError(t, err)
	require.NoError(t, fixture.persistence.FinalizeExpiredExecution(context.Background(), claims[0], fixture.now))
	version := fixture.persistence.currentJob().Version

	fixture.lifecycle.Connected(context.Background(), agentcontrol.SessionInfo{AgentID: "agent-a"})
	require.Equal(t, version, fixture.persistence.currentJob().Version)
	require.Len(t, fixture.audit.events, 1)
	require.False(t, fixture.persistence.messages[message.ID].TerminalAuditPending)
}

func TestLegacyAcceptedAcknowledgementCannotInvalidateTimeoutClaim(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	fixture.persistence.messages[message.ID] = message
	fixture.fenceMessage(t, message.ID)
	message = fixture.persistence.messages[message.ID]
	deadline := fixture.now.Add(-time.Second)
	message.Phase = CommandPhaseStartAuthorized
	message.ExecutionDeadline = &deadline
	fixture.persistence.messages[message.ID] = message
	fixture.persistence.expired = []OutboxMessage{message}
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now.Add(-time.Minute))
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now.Add(-time.Minute)})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current
	claims, err := fixture.persistence.ClaimExpiredExecution(context.Background(), 1, fixture.now)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	before := fixture.persistence.messages[message.ID]

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: message.ID, State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})
	after := fixture.persistence.messages[message.ID]
	require.Equal(t, before.ExecutionDeadline, after.ExecutionDeadline)
	require.Equal(t, before.RecoveryRevision, after.RecoveryRevision)
	require.Equal(t, before.RecoveryClaimToken, after.RecoveryClaimToken)
	require.Equal(t, before.RecoveryClaimedRevision, after.RecoveryClaimedRevision)
	require.Equal(t, "command.acknowledgement_ignored", fixture.audit.events[0].Action)
	require.NoError(t, fixture.persistence.FinalizeExpiredExecution(context.Background(), claims[0], fixture.now.Add(time.Second)))
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
}

func TestPreparedRecoveryRunsOnConnectedSession(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message, _ := fixture.persistPreparedCommand(t, "command-a", "agent-a")
	fixture.persistence.claimed = nil

	fixture.lifecycle.Connected(context.Background(), agentcontrol.SessionInfo{AgentID: "agent-a", ActiveCommands: []*agentv1.CommandRecoveryState{{CommandId: message.ID, State: agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_PREPARED}}})
	require.Len(t, fixture.agents.starts, 1)
	require.Equal(t, message.ID, fixture.agents.starts[0].GetCommandId())
}

func TestConnectedPreparedCancellationUsesUnfencedCancelAndTerminalizes(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message, _ := fixture.persistPreparedCommand(t, "command-a", "agent-a")
	fixture.persistence.claimed = nil
	current := fixture.persistence.currentJob()
	_, err := fixture.persistence.RequestCancel(context.Background(), fixture.scope, current.ID, "operator", current.Version, fixture.now.Add(time.Second))
	require.NoError(t, err)

	fixture.lifecycle.Connected(context.Background(), agentcontrol.SessionInfo{AgentID: "agent-a", ActiveCommands: []*agentv1.CommandRecoveryState{{CommandId: message.ID, State: agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_PREPARED}}})
	require.Empty(t, fixture.agents.starts)
	require.Equal(t, []string{"cancel-unfenced:" + message.ID}, fixture.agents.events)
	require.Equal(t, StatusCancelled, fixture.persistence.currentJob().Status)
	require.Equal(t, CommandCancelled, fixture.persistence.messages[message.ID].CommandStatus)
}

func TestConnectedStartAuthorizedCancellationReplaysStartBeforeFencedCancelWithoutMarker(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	fixture.persistence.messages[message.ID] = message
	token := fixture.fenceMessage(t, message.ID)
	message = fixture.persistence.messages[message.ID]
	message.Phase = CommandPhaseStartAuthorized
	message.StartEnqueuedAt = nil
	fixture.persistence.messages[message.ID] = message
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current
	_, err = fixture.persistence.RequestCancel(context.Background(), fixture.scope, current.ID, "operator", current.Version, fixture.now.Add(time.Second))
	require.NoError(t, err)

	fixture.lifecycle.Connected(context.Background(), agentcontrol.SessionInfo{AgentID: "agent-a", ActiveCommands: []*agentv1.CommandRecoveryState{{CommandId: message.ID, State: agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_START_AUTHORIZED, ExecutionToken: token, LeaseRevision: 1}}})
	require.Equal(t, []string{"start:" + message.ID, "cancel:" + message.ID}, fixture.agents.events)
	require.NotNil(t, fixture.persistence.messages[message.ID].StartEnqueuedAt)
}

func TestResultFenceContradictoryLateResultReturnsNonRetryableConflict(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	token := bytes.Repeat([]byte{0x5a}, sha256.Size)
	tokenHash := sha256.Sum256(token)
	message := fixture.message(t, "command-a", "agent-a")
	message.Phase = CommandPhaseRunning
	message.CommandStatus = CommandActive
	message.ExecutionTokenHash = tokenHash[:]
	message.ExecutionRevision = 1
	fixture.persistence.messages[message.ID] = message
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current

	first := &agentv1.CommandResult{CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "done", ExecutionToken: token, LeaseRevision: 1}
	outcome, err := fixture.lifecycle.Result(context.Background(), "agent-a", first)
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	require.Equal(t, "PERSISTED", outcome.ReasonCode)
	version := fixture.persistence.currentJob().Version
	wrongFence := proto.Clone(first).(*agentv1.CommandResult)
	wrongFence.ExecutionToken = bytes.Repeat([]byte{0x6b}, sha256.Size)
	_, err = fixture.lifecycle.Result(context.Background(), "agent-a", wrongFence)
	require.ErrorIs(t, err, ErrConflict)
	require.Equal(t, version, fixture.persistence.currentJob().Version)

	contradictory := &agentv1.CommandResult{CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, Summary: "different", ErrorCode: "late_failure", ExecutionToken: token, LeaseRevision: 1}
	outcome, err = fixture.lifecycle.Result(context.Background(), "agent-a", contradictory)
	require.NoError(t, err)
	require.False(t, outcome.Persisted)
	require.False(t, outcome.Retryable)
	require.Equal(t, "RESULT_CONFLICT", outcome.ReasonCode)
	require.Equal(t, version, fixture.persistence.currentJob().Version)
	require.Equal(t, CommandSucceeded, fixture.persistence.messages[message.ID].CommandStatus)

	outcome, err = fixture.lifecycle.Result(context.Background(), "agent-a", first)
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	require.Equal(t, version, fixture.persistence.currentJob().Version)
}

func TestInterruptedAgentResultDurablyTimesOutWithoutReexecution(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-interrupted", "agent-a")
	fixture.persistence.messages[message.ID] = message
	token := fixture.fenceMessage(t, message.ID)
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err := ApplyTransition(current, Transition{
		Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning,
		TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now,
	})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current

	outcome, err := fixture.lifecycle.Result(context.Background(), "agent-a", &agentv1.CommandResult{
		CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED,
		Summary: "command execution was interrupted before a terminal result", ErrorCode: "EXECUTION_INTERRUPTED",
		ExecutionToken: token, LeaseRevision: 1,
	})
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.Equal(t, StatusTimedOut, fixture.persistence.currentJob().Status)
	require.Equal(t, TargetTimedOut, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Equal(t, "EXECUTION_INTERRUPTED", fixture.persistence.currentJob().TargetResults[0].ErrorSummary)
	require.Equal(t, "command.result", fixture.audit.events[0].Action)
	require.Equal(t, "failure", fixture.audit.events[0].Result)
}

func TestTwoPhaseRunningCancellationUsesPersistedExecutionFence(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	fixture.persistence.messages[message.ID] = message
	token := fixture.fenceMessage(t, message.ID)
	message = fixture.persistence.messages[message.ID]
	requested := fixture.now.Add(-time.Second)
	message.Phase = CommandPhaseCancelling
	message.CancellationRequestedAt = &requested
	message.CancellationAvailableAt = &requested
	message.CancellationReason = "operator requested cancellation"
	fixture.persistence.messages[message.ID] = message

	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	require.Equal(t, []recordedCancellation{{agentID: "agent-a", commandID: message.ID, token: token, executionRevision: 1, reason: message.CancellationReason}}, fixture.agents.fencedCancellations)
}

func TestDispatchPendingOverridesAuthoritySignsEnqueuesWithoutPublishingAndAudits(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	unsigned := fixture.unsignedEnvelope(t, "agent-a")
	fixture.persistence.claimed = []OutboxMessage{{
		ID: "command-a", Scope: fixture.scope, JobID: fixture.value.ID, TargetID: "agent-a", Type: commandOutboxType,
		Payload: unsigned, AvailableAt: fixture.now, CreatedAt: fixture.now,
	}}

	dispatched, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	require.Equal(t, 1, dispatched)
	require.Len(t, fixture.agents.envelopes, 1)
	envelope := fixture.agents.envelopes[0]
	require.Equal(t, "command-a", envelope.GetCommandId())
	require.Equal(t, fixture.value.ID, envelope.GetJobId())
	require.Equal(t, fixture.now, envelope.GetIssuedAt().AsTime())
	require.Equal(t, fixture.now.Add(DefaultCommandDeliveryTTL), envelope.GetExpiresAt().AsTime())
	require.Equal(t, uint32(30), envelope.GetLeaseSeconds())
	require.Len(t, envelope.GetNonce(), commandNonceBytes)
	verifier, verifyErr := agent.NewCommandVerifier("agent-a", fixture.publicKey, []string{"collect_now"})
	require.NoError(t, verifyErr)
	require.NoError(t, verifier.Verify(context.Background(), envelope))
	require.Empty(t, fixture.persistence.published, "enqueue is not proof of Agent delivery")
	require.Equal(t, StatusDispatched, fixture.persistence.currentJob().Status)
	require.Equal(t, "command.dispatched", fixture.audit.events[0].Action)
	assertTraceFields(t, fixture.audit.events[0], fixture.value, "command-a")
}

func TestDispatchPendingHonorsDurablePerJobPrepareSlotAndReleasesItAtTerminal(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.value.Type = "inspection.collect"
	fixture.value.MaxConcurrency = 1
	fixture.value.TargetTimeout = time.Minute
	batchDeadline := fixture.now.Add(2 * time.Minute)
	fixture.value.TimeoutAt = &batchDeadline
	fixture.persistence.jobs[fixture.value.ID] = fixture.value
	first := fixture.message(t, "command-a", "agent-a")
	second := fixture.message(t, "command-b", "agent-b")
	first.Phase = CommandPhasePending
	second.Phase = CommandPhasePending
	fixture.persistence.messages[first.ID] = first
	fixture.persistence.messages[second.ID] = second
	fixture.persistence.claimed = []OutboxMessage{first, second}

	dispatched, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)

	require.NoError(t, err)
	require.Equal(t, 1, dispatched)
	require.Len(t, fixture.agents.envelopes, 1)
	require.Equal(t, CommandPhasePreparing, fixture.persistence.messages[first.ID].Phase)
	require.Equal(t, CommandPhasePending, fixture.persistence.messages[second.ID].Phase)

	terminal := fixture.persistence.messages[first.ID]
	terminal.Phase = CommandPhaseSucceeded
	terminal.CommandStatus = CommandSucceeded
	fixture.persistence.messages[first.ID] = terminal
	fixture.persistence.claimed = []OutboxMessage{second}
	dispatched, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, 1, dispatched)
	require.Len(t, fixture.agents.envelopes, 2)
}

func TestDispatchRetryUsesByteIdenticalPreparedEnvelopeAndJournalDeduplicates(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.lifecycle.nonceReader = bytes.NewReader(bytes.Repeat([]byte{0x24}, commandNonceBytes))
	message := OutboxMessage{
		ID: "command-a", Scope: fixture.scope, JobID: fixture.value.ID, TargetID: "agent-a", Type: commandOutboxType,
		Payload: fixture.unsignedEnvelopeWithLease(t, "agent-a", 1), AvailableAt: fixture.now, CreatedAt: fixture.now,
	}
	fixture.persistence.claimed = []OutboxMessage{message}

	dispatched, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	require.Equal(t, 1, dispatched)
	dispatched, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(32*time.Second))
	require.NoError(t, err)
	require.Equal(t, 1, dispatched)
	require.Len(t, fixture.agents.envelopes, 2)
	require.True(t, proto.Equal(fixture.agents.envelopes[0], fixture.agents.envelopes[1]))
	first, err := proto.MarshalOptions{Deterministic: true}.Marshal(fixture.agents.envelopes[0])
	require.NoError(t, err)
	second, err := proto.MarshalOptions{Deterministic: true}.Marshal(fixture.agents.envelopes[1])
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Empty(t, fixture.persistence.published, "a missing acknowledgement must leave the command retryable")

	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, journal.Close()) })
	accepted, err := journal.Prepare(context.Background(), fixture.agents.envelopes[0], fixture.now)
	require.NoError(t, err)
	require.True(t, accepted)
	accepted, err = journal.Prepare(context.Background(), fixture.agents.envelopes[1], fixture.now)
	require.NoError(t, err)
	require.False(t, accepted, "the retry must be a command_id duplicate, not an envelope digest conflict")
}

func TestNoAcknowledgementRetryNearDeliveryDeadlineUsesSamePreparedEnvelope(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.lifecycle.nonceReader = bytes.NewReader(bytes.Repeat([]byte{0x37}, commandNonceBytes))
	message := fixture.messageWithLease(t, "command-a", "agent-a", 1)
	fixture.persistence.claimed = []OutboxMessage{message}

	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(23*time.Hour))
	require.NoError(t, err)
	require.Len(t, fixture.agents.envelopes, 2)
	require.True(t, proto.Equal(fixture.agents.envelopes[0], fixture.agents.envelopes[1]))
	require.Equal(t, fixture.now.Add(DefaultCommandDeliveryTTL), fixture.agents.envelopes[1].GetExpiresAt().AsTime())
	require.True(t, fixture.agents.envelopes[1].GetExpiresAt().AsTime().After(fixture.now.Add(23*time.Hour)))
}

func TestExpiredPreparedCommandTimesOutTargetPublishesAndAuditsWithoutDispatch(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.messageWithLease(t, "command-a", "agent-a", 1)
	fixture.persistence.claimed = []OutboxMessage{message}

	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	require.Len(t, fixture.agents.envelopes, 1)
	dispatched, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(DefaultCommandDeliveryTTL+time.Second))
	require.NoError(t, err)
	require.Zero(t, dispatched)
	require.Len(t, fixture.agents.envelopes, 1, "expired delivery must not reach the Registry")
	got := fixture.persistence.currentJob()
	require.Equal(t, StatusTimedOut, got.Status)
	require.Equal(t, TargetTimedOut, got.TargetResults[0].Status)
	require.Equal(t, []publishedCommand{{scope: fixture.scope, id: "command-a"}}, fixture.persistence.published)
	require.Equal(t, "command.delivery_timed_out", fixture.audit.events[len(fixture.audit.events)-1].Action)
	require.Equal(t, "command.delivery_timed_out:command-a", fixture.audit.events[len(fixture.audit.events)-1].DedupeKey)
	require.Equal(t, "delivery_deadline", fixture.audit.events[len(fixture.audit.events)-1].Detail["reason"])
}

func TestExpiredPreparedCommandAuditFailureLeavesUnpublishedAndRetryRecordsOnce(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.messageWithLease(t, "command-a", "agent-a", 1)
	fixture.persistence.claimed = []OutboxMessage{message}
	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	fixture.audit.onceErrors = []error{errors.New("audit unavailable"), nil}

	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(DefaultCommandDeliveryTTL+time.Second))
	require.Error(t, err)
	first := fixture.persistence.currentJob()
	require.Equal(t, StatusTimedOut, first.Status)
	require.Empty(t, fixture.persistence.published)
	require.Len(t, fixture.audit.events, 1)

	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(DefaultCommandDeliveryTTL+DefaultOutboxLease+2*time.Second))
	require.NoError(t, err)
	require.Equal(t, first.Version, fixture.persistence.currentJob().Version)
	require.Len(t, fixture.audit.events, 2)
	require.Equal(t, "command.delivery_timed_out", fixture.audit.events[1].Action)
	require.Equal(t, []publishedCommand{{scope: fixture.scope, id: "command-a"}}, fixture.persistence.published)
}

func TestExpiredPreparedCommandRetriesPublicationWithoutSecondJobMutation(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.messageWithLease(t, "command-a", "agent-a", 1)
	fixture.persistence.claimed = []OutboxMessage{message}
	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	fixture.persistence.markErrors = []error{errors.New("publication unavailable"), nil}

	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(DefaultCommandDeliveryTTL+time.Second))
	require.Error(t, err)
	first := fixture.persistence.currentJob()
	require.Equal(t, StatusTimedOut, first.Status)
	require.Empty(t, fixture.persistence.published)
	require.Len(t, fixture.audit.events, 2, "timeout audit must exist before publication")

	dispatched, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(DefaultCommandDeliveryTTL+DefaultOutboxLease+2*time.Second))
	require.NoError(t, err)
	require.Zero(t, dispatched)
	require.Equal(t, first.Version, fixture.persistence.currentJob().Version)
	require.Equal(t, []publishedCommand{{scope: fixture.scope, id: "command-a"}}, fixture.persistence.published)
	require.Equal(t, "command.delivery_timed_out", fixture.audit.events[len(fixture.audit.events)-1].Action)
	require.Len(t, fixture.audit.events, 2, "RecordOnce must not duplicate timeout evidence")
	require.Len(t, fixture.agents.envelopes, 1)
}

func TestExpiredPreparedCommandWithPreseededAuditPublishesWithoutDuplicateEvidence(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.messageWithLease(t, "command-a", "agent-a", 1)
	fixture.persistence.claimed = []OutboxMessage{message}
	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	expiredAt := fixture.now.Add(DefaultCommandDeliveryTTL + time.Second)
	target := TargetResult{TargetID: "agent-a", Status: TargetTimedOut, ErrorSummary: "delivery deadline exceeded", FinishedAt: timePointer(expiredAt)}
	value, _, err := fixture.lifecycle.applyTarget(context.Background(), message, target, expiredAt)
	require.NoError(t, err)
	_, err = fixture.audit.RecordOnce(context.Background(), audit.Event{
		DedupeKey: "command.delivery_timed_out:command-a", Scope: fixture.scope, OccurredAt: expiredAt,
		Action: "command.delivery_timed_out", Actor: audit.Actor{Type: "system", ID: "agent-control"},
		Resource: audit.Resource{Type: "job_target", ID: "agent-a"}, Result: "failure",
		RequestID: value.RequestID, TraceID: value.TraceID, JobID: value.ID, CommandID: "command-a",
		Detail: map[string]any{"reason": "delivery_deadline"},
	})
	require.NoError(t, err)
	version := fixture.persistence.currentJob().Version

	_, err = fixture.lifecycle.DispatchPending(context.Background(), expiredAt.Add(DefaultOutboxLease+time.Second))
	require.NoError(t, err)
	require.Equal(t, version, fixture.persistence.currentJob().Version)
	require.Len(t, fixture.audit.events, 2)
	require.Equal(t, []publishedCommand{{scope: fixture.scope, id: "command-a"}}, fixture.persistence.published)
}

func TestExpiredDeliveryFinishesSucceededPartialWhenAnotherTargetSucceeded(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	message := fixture.messageWithLease(t, "command-b", "agent-b", 1)
	fixture.persistence.claimed = []OutboxMessage{message}
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err := ApplyTransition(current, Transition{
		Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, At: fixture.now,
		TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetSucceeded}, {TargetID: "agent-b", Status: TargetRunning}},
	})
	require.NoError(t, err)
	fixture.persistence.jobs[fixture.value.ID] = current

	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(DefaultCommandDeliveryTTL+time.Second))
	require.NoError(t, err)

	got := fixture.persistence.currentJob()
	require.Equal(t, StatusSucceeded, got.Status)
	require.Equal(t, OutcomePartial, got.Outcome)
	require.Equal(t, Progress{TotalTargets: 2, CompletedTargets: 1, FailedTargets: 1}, got.Progress)
}

func TestAcceptedAcknowledgementIsIdempotentEvidenceOnly(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.persistence.messages["command-a"] = fixture.message(t, "command-a", "agent-a")
	fixture.persistence.jobs[fixture.value.ID] = transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	before := fixture.persistence.currentJob()

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})
	require.Equal(t, before.Version, fixture.persistence.currentJob().Version)
	require.Empty(t, fixture.persistence.currentJob().TargetResults)
	require.Empty(t, fixture.persistence.published)
	require.Len(t, fixture.audit.events, 1)
	require.Equal(t, "command.acknowledgement_ignored", fixture.audit.events[0].Action)
	require.Empty(t, fixture.observerErrors())

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE})
	require.Empty(t, fixture.persistence.published)
	require.Empty(t, fixture.persistence.currentJob().TargetResults)
	require.Len(t, fixture.audit.events, 1)
	require.Zero(t, fixture.persistence.markCalls)
}

func TestRejectedAcknowledgementDurablyTerminalizesTargetBeforePublication(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.persistence.messages["command-a"] = fixture.message(t, "command-a", "agent-a")
	fixture.persistence.jobs[fixture.value.ID] = transitionForTest(t, fixture.value, StatusDispatched, fixture.now)

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, ReasonCode: "busy"})

	require.Equal(t, []publishedCommand{{scope: fixture.scope, id: "command-a"}}, fixture.persistence.published)
	require.Equal(t, TargetFailed, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Equal(t, "failure", fixture.audit.events[0].Result)
}

func TestAcceptedAcknowledgementCannotCreateExecutionFenceOrDeadline(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	timeout := fixture.now.Add(10 * time.Second)
	value := fixture.value
	value.TimeoutAt = &timeout
	fixture.persistence.jobs[value.ID] = transitionForTest(t, value, StatusDispatched, fixture.now)
	message := fixture.messageWithLease(t, "command-a", "agent-a", 30)
	fixture.persistence.messages[message.ID] = message

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: message.ID, State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})

	stored := fixture.persistence.messages[message.ID]
	require.Empty(t, stored.CommandStatus)
	require.Nil(t, stored.ExecutionDeadline)
	require.Nil(t, stored.LastHeartbeatAt)
	require.Zero(t, stored.ExecutionRevision)
}

func TestDispatchPendingRejectsPayloadAuthorityAndAgentMismatchWithoutPublishing(t *testing.T) {
	for name, mutate := range map[string]func(*agentv1.CommandEnvelope, *OutboxMessage){
		"command id": func(envelope *agentv1.CommandEnvelope, _ *OutboxMessage) { envelope.CommandId = "payload-command" },
		"job id":     func(envelope *agentv1.CommandEnvelope, _ *OutboxMessage) { envelope.JobId = "payload-job" },
		"issued at":  func(envelope *agentv1.CommandEnvelope, _ *OutboxMessage) { envelope.IssuedAt = timestamp(time.Now()) },
		"expires at": func(envelope *agentv1.CommandEnvelope, _ *OutboxMessage) {
			envelope.ExpiresAt = timestamp(time.Now().Add(time.Hour))
		},
		"nonce":     func(envelope *agentv1.CommandEnvelope, _ *OutboxMessage) { envelope.Nonce = []byte("payload") },
		"signature": func(envelope *agentv1.CommandEnvelope, _ *OutboxMessage) { envelope.Signature = []byte("payload") },
		"agent":     func(_ *agentv1.CommandEnvelope, message *OutboxMessage) { message.TargetID = "agent-b" },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newCommandLifecycleFixture(t)
			envelope := &agentv1.CommandEnvelope{AgentId: "agent-a", LeaseSeconds: 30, Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"health"}}}}
			message := OutboxMessage{ID: "command-a", Scope: fixture.scope, JobID: fixture.value.ID, TargetID: "agent-a", Type: commandOutboxType, AvailableAt: fixture.now, CreatedAt: fixture.now}
			mutate(envelope, &message)
			message.Payload, _ = proto.Marshal(envelope)
			fixture.persistence.claimed = []OutboxMessage{message}

			dispatched, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
			require.Zero(t, dispatched)
			require.Error(t, err)
			require.Empty(t, fixture.agents.envelopes)
			require.Empty(t, fixture.persistence.published)
		})
	}
}

func TestObserverLooksUpEveryEventRetriesConflictsAndAggregatesPartialResult(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.persistence.messages["command-a"] = fixture.message(t, "command-a", "agent-a")
	fixture.persistence.messages["command-b"] = fixture.message(t, "command-b", "agent-b")
	tokenA := fixture.fenceMessage(t, "command-a")
	tokenB := fixture.fenceMessage(t, "command-b")
	fixture.persistence.jobs[fixture.value.ID] = transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	fixture.persistence.conflicts = 1

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})
	fixture.lifecycle.Progress(context.Background(), "agent-a", &agentv1.CommandProgress{CommandId: "command-a", Percent: 50, Stage: "executing", ExecutionToken: tokenA, LeaseRevision: 1})
	outcome, err := fixture.lifecycle.Result(context.Background(), "agent-a", &agentv1.CommandResult{
		CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "stored externally",
		Artifacts: []*agentv1.ArtifactReference{{ArtifactId: "artifact-large", Kind: "command-output", SizeBytes: 10 << 20}}, ExecutionToken: tokenA, LeaseRevision: 1,
	})
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	fixture.lifecycle.Acknowledged(context.Background(), "agent-b", &agentv1.CommandAcknowledgement{CommandId: "command-b", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})
	outcome, err = fixture.lifecycle.Result(context.Background(), "agent-b", &agentv1.CommandResult{CommandId: "command-b", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, Summary: "target failed", ErrorCode: "target_error", ExecutionToken: tokenB, LeaseRevision: 1})
	require.NoError(t, err)
	require.True(t, outcome.Persisted)

	got := fixture.persistence.currentJob()
	require.Equal(t, StatusSucceeded, got.Status)
	require.Equal(t, OutcomePartial, got.Outcome)
	require.Equal(t, Progress{TotalTargets: 2, CompletedTargets: 1, FailedTargets: 1}, got.Progress)
	require.Equal(t, []ArtifactReference{{ArtifactID: "artifact-large", Kind: "command-output"}}, got.Artifacts)
	require.GreaterOrEqual(t, fixture.persistence.lookups, 5)
	require.Empty(t, fixture.observerErrors())
	for _, event := range fixture.audit.events {
		assertTraceFields(t, event, fixture.value, event.CommandID)
	}

	version := got.Version
	_, err = fixture.lifecycle.Result(context.Background(), "agent-b", &agentv1.CommandResult{CommandId: "command-b", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, Summary: "target failed", ErrorCode: "target_error", ExecutionToken: tokenB, LeaseRevision: 1})
	require.NoError(t, err)
	require.Equal(t, version, fixture.persistence.currentJob().Version, "late terminal result must not mutate the Job")
	require.Empty(t, fixture.observerErrors())
}

func TestObserverAuditsAgentMismatchWithoutMutatingJob(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.persistence.messages["command-a"] = fixture.message(t, "command-a", "agent-a")
	fixture.persistence.jobs[fixture.value.ID] = transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	version := fixture.persistence.currentJob().Version

	fixture.lifecycle.Acknowledged(context.Background(), "agent-b", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})

	require.Equal(t, version, fixture.persistence.currentJob().Version)
	require.Len(t, fixture.audit.events, 1)
	require.Equal(t, "command.rejected", fixture.audit.events[0].Action)
	require.Equal(t, "failure", fixture.audit.events[0].Result)
	assertTraceFields(t, fixture.audit.events[0], fixture.value, "command-a")
	require.Len(t, fixture.observerErrors(), 1)
}

func TestCancelledResultCompletesCancellingJobAndLateDuplicateIsNoOp(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.persistence.messages["command-a"] = fixture.message(t, "command-a", "agent-a")
	fixture.persistence.messages["command-b"] = fixture.message(t, "command-b", "agent-b")
	tokenA := fixture.fenceMessage(t, "command-a")
	tokenB := fixture.fenceMessage(t, "command-b")
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}, {TargetID: "agent-b", Status: TargetRunning}}, At: fixture.now})
	require.NoError(t, err)
	current, err = ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusCancelling, Actor: "operator-1", At: fixture.now})
	require.NoError(t, err)
	fixture.persistence.jobs[fixture.value.ID] = current

	result := &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED, Summary: "cancelled", ExecutionToken: tokenA, LeaseRevision: 1}
	outcome, err := fixture.lifecycle.Result(context.Background(), "agent-a", result)
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	intermediate := fixture.persistence.currentJob()
	require.Equal(t, StatusCancelling, intermediate.Status)
	require.Equal(t, TargetCancelled, intermediate.TargetResults[0].Status)

	result = &agentv1.CommandResult{CommandId: "command-b", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED, Summary: "cancelled", ExecutionToken: tokenB, LeaseRevision: 1}
	outcome, err = fixture.lifecycle.Result(context.Background(), "agent-b", result)
	require.NoError(t, err)
	require.True(t, outcome.Persisted)

	got := fixture.persistence.currentJob()
	require.Equal(t, StatusCancelled, got.Status)
	require.Equal(t, TargetCancelled, got.TargetResults[0].Status)
	require.Equal(t, TargetCancelled, got.TargetResults[1].Status)
	require.Equal(t, "command.result", fixture.audit.events[0].Action)
	require.Equal(t, "failure", fixture.audit.events[0].Result)
	version := got.Version
	_, err = fixture.lifecycle.Result(context.Background(), "agent-b", result)
	require.NoError(t, err)
	require.Equal(t, version, fixture.persistence.currentJob().Version)
	require.Len(t, fixture.audit.events, 2, "result retry uses RecordOnce evidence")
	require.Empty(t, fixture.observerErrors())
}

func TestCancellationIntentPreventsUndeliveredExecutionAndTerminalizesLocally(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	fixture.persistence.messages[message.ID] = message
	fixture.persistence.claimed = []OutboxMessage{message}
	_, err := fixture.persistence.RequestCancel(context.Background(), fixture.scope, fixture.value.ID, "operator", fixture.value.Version, fixture.now)
	require.NoError(t, err)

	dispatched, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	require.Zero(t, dispatched)
	require.Empty(t, fixture.agents.envelopes)
	require.Equal(t, StatusCancelled, fixture.persistence.currentJob().Status)
	require.Equal(t, CommandCancelled, fixture.persistence.messages[message.ID].CommandStatus)
	require.Equal(t, "command.cancelled_before_dispatch", fixture.audit.events[0].Action)
}

func TestTooLateSuccessfulResultWinsOverCancellationRequest(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	published := fixture.now.Add(-time.Second)
	message.PublishedAt = &published
	message.CommandStatus = CommandActive
	fixture.persistence.messages[message.ID] = message
	token := fixture.fenceMessage(t, message.ID)
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now})
	require.NoError(t, err)
	current, err = ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusCancelling, Actor: "operator", At: fixture.now})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current

	outcome, err := fixture.lifecycle.Result(context.Background(), "agent-a", &agentv1.CommandResult{CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "completed before cancellation arrived", ExecutionToken: token, LeaseRevision: 1})
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	require.Equal(t, StatusSucceeded, fixture.persistence.currentJob().Status)
	require.Equal(t, OutcomeComplete, fixture.persistence.currentJob().Outcome)
}

func TestInvalidMetricTrialIsClassifiedBeforeTerminalCAS(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	recorder := &orderingTrialRecorder{persistence: fixture.persistence, commandID: "command-trial"}
	fixture.lifecycle.typedResultRecorder = recorder
	fixture.lifecycle.targetAuthorizer = allowTrialTarget{}
	digest := bytes.Repeat([]byte{1}, sha256.Size)
	payload, err := proto.Marshal(&agentv1.CommandEnvelope{AgentId: "agent-a", LeaseSeconds: 30, Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{AssignmentId: "assignment-a", ConfigurationRevision: 1, OperationRevision: 1, InstanceIds: []string{"instance-a"}, TemplateIds: []string{"template-a"}, Trial: true, TemplateRevisions: []*agentv1.MetricTemplateCommandReference{{TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: digest, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, CardinalityLimit: 1}}}}})
	require.NoError(t, err)
	message := fixture.message(t, "command-trial", "agent-a")
	message.Payload = payload
	fixture.persistence.messages[message.ID] = message
	token := fixture.fenceMessage(t, message.ID)
	result := &agentv1.CommandResult{CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, ExecutionToken: token, LeaseRevision: 1, MetricTemplateTrialResult: &agentv1.MetricTemplateTrialResult{RevisionId: "revision-a", QueryDigest: digest, StatusCode: "succeeded", MetricCount: 1, CandidateMetrics: []*agentv1.MetricTemplateCandidateMetric{nil}}}
	_, err = fixture.lifecycle.Result(context.Background(), "agent-a", result)
	require.NoError(t, err)
	require.True(t, recorder.classifiedBeforeCAS)
	require.Equal(t, CommandFailed, fixture.persistence.messages[message.ID].CommandStatus)
	require.Equal(t, TargetFailed, fixture.persistence.currentJob().TargetResults[0].Status)
}

func TestCancelledMetricTrialKeepsCancelledTerminalState(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	recorder := &orderingTrialRecorder{persistence: fixture.persistence, commandID: "command-trial-cancelled"}
	fixture.lifecycle.typedResultRecorder = recorder
	fixture.lifecycle.targetAuthorizer = allowTrialTarget{}
	digest := bytes.Repeat([]byte{1}, sha256.Size)
	payload, err := proto.Marshal(&agentv1.CommandEnvelope{AgentId: "agent-a", LeaseSeconds: 30, Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{AssignmentId: "assignment-a", ConfigurationRevision: 1, OperationRevision: 1, InstanceIds: []string{"instance-a"}, TemplateIds: []string{"template-a"}, Trial: true, TemplateRevisions: []*agentv1.MetricTemplateCommandReference{{TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: digest, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, CardinalityLimit: 1}}}}})
	require.NoError(t, err)
	message := fixture.message(t, recorder.commandID, "agent-a")
	message.Payload = payload
	fixture.persistence.messages[message.ID] = message
	token := fixture.fenceMessage(t, message.ID)
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err = ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now})
	require.NoError(t, err)
	current, err = ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusCancelling, Actor: "operator-1", At: fixture.now})
	require.NoError(t, err)
	fixture.persistence.jobs[fixture.value.ID] = current
	_, err = fixture.lifecycle.Result(context.Background(), "agent-a", &agentv1.CommandResult{CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED, ExecutionToken: token, LeaseRevision: 1})
	require.NoError(t, err)
	require.Equal(t, CommandCancelled, fixture.persistence.messages[message.ID].CommandStatus)
	require.Equal(t, TargetCancelled, fixture.persistence.currentJob().TargetResults[0].Status)
}

func TestTimedOutMetricTrialKeepsTimedOutTerminalState(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	recorder := &orderingTrialRecorder{persistence: fixture.persistence, commandID: "command-trial-timeout"}
	fixture.lifecycle.typedResultRecorder = recorder
	fixture.lifecycle.targetAuthorizer = allowTrialTarget{}
	digest := bytes.Repeat([]byte{1}, sha256.Size)
	payload, err := proto.Marshal(&agentv1.CommandEnvelope{AgentId: "agent-a", LeaseSeconds: 30, Command: &agentv1.CommandEnvelope_CollectDatabaseMetrics{CollectDatabaseMetrics: &agentv1.CollectDatabaseMetrics{AssignmentId: "assignment-a", ConfigurationRevision: 1, OperationRevision: 1, InstanceIds: []string{"instance-a"}, TemplateIds: []string{"template-a"}, Trial: true, TemplateRevisions: []*agentv1.MetricTemplateCommandReference{{TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: digest, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, CardinalityLimit: 1}}}}})
	require.NoError(t, err)
	message := fixture.message(t, recorder.commandID, "agent-a")
	message.Payload = payload
	fixture.persistence.messages[message.ID] = message
	token := fixture.fenceMessage(t, message.ID)
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err = ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now})
	require.NoError(t, err)
	fixture.persistence.jobs[fixture.value.ID] = current
	_, err = fixture.lifecycle.Result(context.Background(), "agent-a", &agentv1.CommandResult{CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT, ExecutionToken: token, LeaseRevision: 1})
	require.NoError(t, err)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.Equal(t, TargetTimedOut, fixture.persistence.currentJob().TargetResults[0].Status)
}

type orderingTrialRecorder struct {
	persistence         *memoryCommandPersistence
	commandID           string
	classifiedBeforeCAS bool
}

type allowTrialTarget struct{}

func (allowTrialTarget) AuthorizeTarget(context.Context, string, string) error { return nil }

func (recorder *orderingTrialRecorder) ClassifyMetricTemplateTrial(context.Context, platformscope.Scope, string, *agentv1.CollectDatabaseMetrics, *agentv1.CommandResult) (bool, error) {
	recorder.persistence.mu.Lock()
	recorder.classifiedBeforeCAS = !terminalCommandStatus(recorder.persistence.messages[recorder.commandID].CommandStatus)
	recorder.persistence.mu.Unlock()
	return false, nil
}

func (*orderingTrialRecorder) RecordMetricTemplateTrial(context.Context, platformscope.Scope, string, string, *agentv1.CollectDatabaseMetrics, *agentv1.CommandResult, time.Time) error {
	return nil
}

func TestReconnectRenewsKnownActiveCommandsAndReplaysCancellation(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	requested := fixture.now.Add(-time.Second)
	message.CommandStatus = CommandActive
	message.CancellationRequestedAt = &requested
	fixture.persistence.messages[message.ID] = message
	token := fixture.fenceMessage(t, message.ID)

	fixture.lifecycle.Connected(context.Background(), agentcontrol.SessionInfo{AgentID: "agent-a", ActiveCommands: []*agentv1.CommandRecoveryState{{CommandId: message.ID, State: agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_RUNNING, ExecutionToken: token, LeaseRevision: 1}}})

	require.Equal(t, []string{"agent-a/command-a"}, fixture.agents.cancellations)
	renewed := fixture.persistence.messages[message.ID]
	require.NotNil(t, renewed.LastHeartbeatAt)
	require.NotNil(t, renewed.ExecutionDeadline)
	require.Equal(t, fixture.now.Add(30*time.Second), *renewed.ExecutionDeadline)
}

func TestExpiredExecutionLeaseDurablyTimesOutTargetJobAndAuditOnce(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	published := fixture.now.Add(-time.Minute)
	deadline := fixture.now.Add(-time.Second)
	message.PublishedAt = &published
	fixture.persistence.messages[message.ID] = message
	fixture.fenceMessage(t, message.ID)
	message = fixture.persistence.messages[message.ID]
	message.PublishedAt = &published
	message.ExecutionDeadline = &deadline
	fixture.persistence.messages[message.ID] = message
	fixture.persistence.expired = []OutboxMessage{message}
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now.Add(-time.Minute))
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now.Add(-time.Minute)})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current

	_, err = fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	require.Equal(t, StatusTimedOut, fixture.persistence.currentJob().Status)
	require.Equal(t, TargetTimedOut, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Equal(t, CommandTimedOut, fixture.persistence.messages[message.ID].CommandStatus)
	require.Equal(t, "command.execution_timed_out", fixture.audit.events[0].Action)
	require.NotEmpty(t, fixture.audit.events[0].DedupeKey)
}

type commandLifecycleFixture struct {
	now         time.Time
	scope       platformscope.Scope
	value       Job
	publicKey   ed25519.PublicKey
	persistence *memoryCommandPersistence
	agents      *recordingCommandDispatcher
	audit       *recordingAudit
	lifecycle   *CommandLifecycle
	errorsMu    sync.Mutex
	errors      []error
}

func newCommandLifecycleFixture(t *testing.T) *commandLifecycleFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	value := Job{
		ID: "job-1", Type: "contract.collect", Scope: scope, Status: StatusQueued, Outcome: OutcomeNone,
		TargetResourceIDs: []string{"agent-a", "agent-b"}, SourceResource: ResourceReference{ResourceType: "contract", ResourceID: "resource-1"},
		IdempotencyKey: "idem-1", Version: 1, Progress: Progress{TotalTargets: 2}, Artifacts: []ArtifactReference{},
		CreatedAt: now.Add(-time.Minute), RequestID: "request-1", TraceID: "trace-1",
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519CommandSigner(privateKey)
	require.NoError(t, err)
	persistence := &memoryCommandPersistence{jobs: map[string]Job{value.ID: value}, messages: make(map[string]OutboxMessage)}
	fixture := &commandLifecycleFixture{now: now, scope: scope, value: value, publicKey: publicKey, persistence: persistence, agents: &recordingCommandDispatcher{}, audit: &recordingAudit{}}
	lifecycle, err := NewCommandLifecycle(CommandLifecycleConfig{
		DispatchRepository: persistence, Jobs: persistence, Agents: fixture.agents, Signer: signer, Audit: fixture.audit,
		ClaimLimit: 8, Now: func() time.Time { return now }, NonceReader: bytes.NewReader(bytes.Repeat([]byte{0x42}, 1024)),
		TokenReader: bytes.NewReader(bytes.Repeat([]byte{0x51}, 1024)), TokenProtector: testTokenProtector{},
		OnError: func(err error) {
			fixture.errorsMu.Lock()
			defer fixture.errorsMu.Unlock()
			fixture.errors = append(fixture.errors, err)
		},
	})
	require.NoError(t, err)
	fixture.lifecycle = lifecycle
	return fixture
}

func newSingleTargetCommandLifecycleFixture(t *testing.T) *commandLifecycleFixture {
	t.Helper()
	fixture := newCommandLifecycleFixture(t)
	fixture.value.TargetResourceIDs = []string{"agent-a"}
	fixture.value.Progress = Progress{TotalTargets: 1}
	fixture.persistence.jobs[fixture.value.ID] = fixture.value
	return fixture
}

func (fixture *commandLifecycleFixture) unsignedEnvelope(t *testing.T, agentID string) []byte {
	return fixture.unsignedEnvelopeWithLease(t, agentID, 30)
}

func (fixture *commandLifecycleFixture) unsignedEnvelopeWithLease(t *testing.T, agentID string, leaseSeconds uint32) []byte {
	t.Helper()
	encoded, err := proto.Marshal(&agentv1.CommandEnvelope{AgentId: agentID, LeaseSeconds: leaseSeconds, Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"health"}}}})
	require.NoError(t, err)
	return encoded
}

func (fixture *commandLifecycleFixture) message(t *testing.T, id, agentID string) OutboxMessage {
	return fixture.messageWithLease(t, id, agentID, 30)
}

func (fixture *commandLifecycleFixture) messageWithLease(t *testing.T, id, agentID string, leaseSeconds uint32) OutboxMessage {
	return OutboxMessage{ID: id, Scope: fixture.scope, JobID: fixture.value.ID, TargetID: agentID, Type: commandOutboxType, Payload: fixture.unsignedEnvelopeWithLease(t, agentID, leaseSeconds), AvailableAt: fixture.now, CreatedAt: fixture.now}
}

func (fixture *commandLifecycleFixture) persistPreparedCommand(t *testing.T, id, agentID string) (OutboxMessage, [sha256.Size]byte) {
	t.Helper()
	message := fixture.message(t, id, agentID)
	fixture.persistence.claimed = []OutboxMessage{message}
	_, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now)
	require.NoError(t, err)
	require.NotEmpty(t, fixture.agents.envelopes)
	envelope := fixture.agents.envelopes[len(fixture.agents.envelopes)-1]
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	require.NoError(t, err)
	digest := sha256.Sum256(encoded)
	message.PreparedEnvelope = encoded
	message.Phase = CommandPhasePrepared
	message.CommandStatus = CommandPending
	message.PrepareDigest = append([]byte(nil), digest[:]...)
	message.PreparedAt = timePointer(fixture.now)
	message.PublishedAt = timePointer(fixture.now)
	fixture.persistence.messages[id] = message
	return message, digest
}

func (fixture *commandLifecycleFixture) fenceMessage(t *testing.T, id string) []byte {
	t.Helper()
	message, ok := fixture.persistence.messages[id]
	require.True(t, ok)
	tokenArray := sha256.Sum256([]byte("execution-token:" + id))
	token := append([]byte(nil), tokenArray[:]...)
	hash := sha256.Sum256(token)
	ciphertext, err := (testTokenProtector{}).Protect(context.Background(), token)
	require.NoError(t, err)
	message.Phase = CommandPhaseRunning
	message.CommandStatus = CommandActive
	message.ExecutionTokenHash = append([]byte(nil), hash[:]...)
	message.ExecutionTokenCiphertext = ciphertext
	message.ExecutionRevision = 1
	message.RecoveryRevision = 1
	message.StartDeadline = timePointer(fixture.now.Add(30 * time.Second))
	message.StartEnqueuedAt = timePointer(fixture.now)
	message.ExecutionDeadline = timePointer(fixture.now.Add(30 * time.Second))
	fixture.persistence.messages[id] = message
	return token
}

func (fixture *commandLifecycleFixture) observerErrors() []error {
	fixture.errorsMu.Lock()
	defer fixture.errorsMu.Unlock()
	return append([]error(nil), fixture.errors...)
}

type publishedCommand struct {
	scope platformscope.Scope
	id    string
}

type memoryCommandPersistence struct {
	mu              sync.Mutex
	jobs            map[string]Job
	messages        map[string]OutboxMessage
	claimed         []OutboxMessage
	published       []publishedCommand
	lookups         int
	conflicts       int
	prepared        map[string][]byte
	markErrors      []error
	markCalls       int
	expired         []OutboxMessage
	markStartErrors []error
	finalizeErrors  []error
}

func (store *memoryCommandPersistence) CreateWithOutbox(context.Context, Job, []OutboxMessage) error {
	return errors.New("not implemented")
}
func (store *memoryCommandPersistence) CreateInTx(context.Context, *sql.Tx, Job, []OutboxMessage) error {
	return errors.New("not implemented")
}
func (store *memoryCommandPersistence) Get(_ context.Context, scope platformscope.Scope, id string) (Job, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.jobs[id]
	if !ok || value.Scope != scope {
		return Job{}, ErrNotFound
	}
	return normalizeJobUTC(value), nil
}
func (store *memoryCommandPersistence) Transition(_ context.Context, transition Transition) (Job, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.conflicts > 0 {
		store.conflicts--
		return Job{}, ErrConflict
	}
	current, ok := store.jobs[transition.JobID]
	if !ok || current.Scope != transition.Scope {
		return Job{}, ErrNotFound
	}
	next, err := ApplyTransition(current, transition)
	if err != nil {
		return Job{}, err
	}
	store.jobs[transition.JobID] = next
	return next, nil
}
func (store *memoryCommandPersistence) RequestCancel(ctx context.Context, scope platformscope.Scope, id, actor string, version int64, at time.Time) (Job, error) {
	next, err := store.Transition(ctx, Transition{Scope: scope, JobID: id, CurrentVersion: version, To: StatusCancelling, Actor: actor, At: at})
	if err != nil {
		return Job{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for commandID, message := range store.messages {
		if message.Scope == scope && message.JobID == id {
			requested := at.UTC()
			message.CancellationRequestedAt = &requested
			message.CancellationAvailableAt = &requested
			if message.Phase == CommandPhaseStartAuthorized || message.Phase == CommandPhaseRunning || message.Phase == CommandPhaseCancelling {
				message.Phase = CommandPhaseCancelling
			}
			store.messages[commandID] = message
		}
	}
	return next, nil
}
func (store *memoryCommandPersistence) ClaimOutbox(context.Context, int, time.Time) ([]OutboxMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	claimed := append([]OutboxMessage(nil), store.claimed...)
	for index := range claimed {
		claimed[index].PreparedEnvelope = append([]byte(nil), store.prepared[claimed[index].ID]...)
	}
	return claimed, nil
}
func (store *memoryCommandPersistence) ReservePrepareSlot(_ context.Context, scope platformscope.Scope, id string, _ time.Time) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	message, exists := store.messages[id]
	if !exists {
		return true, nil
	}
	if message.Scope != scope {
		return false, ErrNotFound
	}
	value, exists := store.jobs[message.JobID]
	if !exists {
		return false, ErrNotFound
	}
	if value.MaxConcurrency == 0 {
		return true, nil
	}
	if activePreparePhase(message.Phase) {
		return true, nil
	}
	active := 0
	for _, candidate := range store.messages {
		if candidate.JobID == message.JobID && activePreparePhase(candidate.Phase) {
			active++
		}
	}
	if active >= value.MaxConcurrency {
		return false, nil
	}
	message.Phase = CommandPhasePreparing
	store.messages[id] = message
	return true, nil
}
func (store *memoryCommandPersistence) MarkOutboxPublished(_ context.Context, scope platformscope.Scope, id string, _ time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.markCalls++
	if len(store.markErrors) > 0 {
		err := store.markErrors[0]
		store.markErrors = store.markErrors[1:]
		if err != nil {
			return err
		}
	}
	store.published = append(store.published, publishedCommand{scope: scope, id: id})
	return nil
}
func (store *memoryCommandPersistence) PrepareCommandEnvelope(_ context.Context, scope platformscope.Scope, id string, proposed []byte) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.prepared == nil {
		store.prepared = make(map[string][]byte)
	}
	if _, ok := store.prepared[id]; !ok {
		store.prepared[id] = append([]byte(nil), proposed...)
	}
	if message, ok := store.messages[id]; ok && message.Scope == scope && message.CancellationRequestedAt == nil && (message.Phase == "" || message.Phase == CommandPhasePending || message.Phase == CommandPhasePreparing) {
		message.Phase = CommandPhasePreparing
		message.PreparedEnvelope = append([]byte(nil), store.prepared[id]...)
		store.messages[id] = message
	}
	return append([]byte(nil), store.prepared[id]...), nil
}
func (store *memoryCommandPersistence) MarkPrepared(_ context.Context, scope platformscope.Scope, id string, digest [32]byte, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	message, ok := store.messages[id]
	if !ok || message.Scope != scope {
		return ErrNotFound
	}
	if len(message.PrepareDigest) > 0 && !bytes.Equal(message.PrepareDigest, digest[:]) {
		return ErrConflict
	}
	if message.Phase == CommandPhaseStartAuthorized || message.Phase == CommandPhaseRunning || message.Phase == CommandPhaseCancelling {
		return nil
	}
	if message.CancellationRequestedAt != nil {
		return ErrConflict
	}
	message.Phase = CommandPhasePrepared
	message.PrepareDigest = append([]byte(nil), digest[:]...)
	message.PreparedAt = timePointer(at.UTC())
	message.PublishedAt = timePointer(at.UTC())
	store.messages[id] = message
	return nil
}
func (store *memoryCommandPersistence) AuthorizeStart(_ context.Context, scope platformscope.Scope, id string, digest [32]byte, tokenHash [32]byte, ciphertext []byte, at, deadline time.Time) (StartGrant, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	message, ok := store.messages[id]
	if !ok || message.Scope != scope {
		return StartGrant{}, ErrNotFound
	}
	value := store.jobs[message.JobID]
	if !bytes.Equal(message.PrepareDigest, digest[:]) {
		return StartGrant{}, ErrConflict
	}
	if message.Phase == CommandPhaseStartAuthorized || message.Phase == CommandPhaseRunning || message.Phase == CommandPhaseCancelling {
		var storedHash [32]byte
		copy(storedHash[:], message.ExecutionTokenHash)
		return StartGrant{CommandID: id, TokenHash: storedHash, TokenCiphertext: append([]byte(nil), message.ExecutionTokenCiphertext...), ExecutionRevision: message.ExecutionRevision, RecoveryRevision: message.RecoveryRevision, StartDeadline: *message.StartDeadline}, nil
	}
	if value.Status == StatusCancelling || isTerminal(value.Status) || message.CancellationRequestedAt != nil {
		return StartGrant{}, ErrConflict
	}
	if message.Phase != CommandPhasePrepared {
		return StartGrant{}, ErrConflict
	}
	message.Phase = CommandPhaseStartAuthorized
	message.CommandStatus = CommandActive
	message.ExecutionTokenHash = append([]byte(nil), tokenHash[:]...)
	message.ExecutionTokenCiphertext = append([]byte(nil), ciphertext...)
	message.ExecutionRevision = 1
	message.RecoveryRevision = 1
	message.StartDeadline = timePointer(deadline.UTC())
	message.ExecutionDeadline = timePointer(deadline.UTC())
	message.LastHeartbeatAt = timePointer(at.UTC())
	store.messages[id] = message
	return StartGrant{CommandID: id, TokenHash: tokenHash, TokenCiphertext: append([]byte(nil), ciphertext...), ExecutionRevision: 1, RecoveryRevision: 1, StartDeadline: deadline.UTC()}, nil
}
func (store *memoryCommandPersistence) MarkStartEnqueued(_ context.Context, scope platformscope.Scope, id string, executionRevision uint64, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.markStartErrors) > 0 {
		err := store.markStartErrors[0]
		store.markStartErrors = store.markStartErrors[1:]
		if err != nil {
			return err
		}
	}
	message, ok := store.messages[id]
	if !ok || message.Scope != scope || message.ExecutionRevision != executionRevision {
		return ErrConflict
	}
	message.StartEnqueuedAt = timePointer(at.UTC())
	store.messages[id] = message
	return nil
}
func (store *memoryCommandPersistence) RenewExecutionLease(_ context.Context, scope platformscope.Scope, id string, tokenHash [32]byte, executionRevision uint64, at, deadline time.Time) (uint64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	message, ok := store.messages[id]
	if !ok || message.Scope != scope || !bytes.Equal(message.ExecutionTokenHash, tokenHash[:]) || message.ExecutionRevision != executionRevision {
		return 0, ErrConflict
	}
	message.RecoveryRevision++
	message.LastHeartbeatAt = timePointer(at.UTC())
	message.ExecutionDeadline = timePointer(deadline.UTC())
	message.StartEnqueuedAt = timePointer(at.UTC())
	message.RecoveryClaimToken = nil
	message.RecoveryClaimedDeadline = nil
	message.RecoveryClaimedRevision = 0
	store.messages[id] = message
	return message.RecoveryRevision, nil
}
func (store *memoryCommandPersistence) ClaimExpiredExecution(_ context.Context, _ int, _ time.Time) ([]RecoveryClaim, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	claims := make([]RecoveryClaim, 0, len(store.expired))
	for _, expired := range store.expired {
		message := store.messages[expired.ID]
		if message.ID == "" {
			message = expired
		}
		if message.ExecutionDeadline == nil {
			continue
		}
		if message.RecoveryRevision == 0 {
			message.RecoveryRevision = 1
		}
		token := sha256.Sum256([]byte("claim:" + message.ID))
		message.RecoveryClaimToken = append([]byte(nil), token[:]...)
		message.RecoveryClaimedDeadline = timePointer(message.ExecutionDeadline.UTC())
		message.RecoveryClaimedRevision = message.RecoveryRevision
		store.messages[message.ID] = message
		claims = append(claims, RecoveryClaim{Scope: message.Scope, CommandID: message.ID, JobID: message.JobID, TargetID: message.TargetID, ClaimToken: token, ClaimedDeadline: message.ExecutionDeadline.UTC(), ClaimedRecoveryRevision: message.RecoveryRevision})
	}
	return claims, nil
}
func (store *memoryCommandPersistence) FinalizeExpiredExecution(_ context.Context, claim RecoveryClaim, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	message := store.messages[claim.CommandID]
	if message.ExecutionDeadline == nil || message.RecoveryClaimedDeadline == nil || !bytes.Equal(message.RecoveryClaimToken, claim.ClaimToken[:]) || !message.ExecutionDeadline.Equal(claim.ClaimedDeadline) || message.RecoveryRevision != claim.ClaimedRecoveryRevision || message.RecoveryClaimedRevision != claim.ClaimedRecoveryRevision {
		return ErrConflict
	}
	current := store.jobs[message.JobID]
	next, err := timeoutMemoryJob(current, message, at)
	if err != nil {
		return err
	}
	if len(store.finalizeErrors) > 0 {
		err := store.finalizeErrors[0]
		store.finalizeErrors = store.finalizeErrors[1:]
		if err != nil {
			return err
		}
	}
	message.Phase = CommandPhaseTimedOut
	message.CommandStatus = CommandTimedOut
	message.TerminalAt = timePointer(at.UTC())
	message.ExecutionDeadline = nil
	message.RecoveryClaimToken = nil
	message.RecoveryClaimedDeadline = nil
	message.RecoveryClaimedRevision = 0
	message.TerminalAuditPending = true
	message.TerminalAuditDedupeKey = "command.execution_timed_out:" + message.ID
	message.TerminalAuditAction = "command.execution_timed_out"
	message.TerminalAuditResult = "failure"
	message.TerminalAuditDetail = map[string]any{"reason": "execution_deadline"}
	store.jobs[message.JobID] = next
	store.messages[claim.CommandID] = message
	return nil
}
func (store *memoryCommandPersistence) FinalizeExpiredPrepared(_ context.Context, scope platformscope.Scope, commandID string, expectedDigest [32]byte, expiresAt, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	message, ok := store.messages[commandID]
	if !ok || message.Scope != scope || expiresAt.After(at) || !bytes.Equal(message.PrepareDigest, expectedDigest[:]) {
		return ErrConflict
	}
	current := store.jobs[message.JobID]
	if message.Phase == CommandPhaseTimedOut {
		target, found := targetFor(current.TargetResults, message.TargetID)
		if found && target.Status == TargetTimedOut {
			return nil
		}
		return ErrConflict
	}
	if message.Phase != CommandPhasePrepared {
		return ErrConflict
	}
	next, err := timeoutMemoryJob(current, message, at)
	if err != nil {
		return err
	}
	message.Phase = CommandPhaseTimedOut
	message.CommandStatus = CommandTimedOut
	message.TerminalAt = timePointer(at.UTC())
	message.LeasedUntil = nil
	message.TerminalAuditPending = true
	message.TerminalAuditDedupeKey = "command.prepared_envelope_expired:" + message.ID
	message.TerminalAuditAction = "command.prepared_envelope_expired"
	message.TerminalAuditResult = "failure"
	message.TerminalAuditDetail = map[string]any{"reason": "prepare_envelope_expiry", "expires_at": expiresAt.UTC()}
	store.jobs[message.JobID] = next
	store.messages[commandID] = message
	return nil
}
func timeoutMemoryJob(current Job, message OutboxMessage, at time.Time) (Job, error) {
	if current.Status == StatusQueued {
		var err error
		current, err = ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusDispatched, At: at})
		if err != nil {
			return Job{}, err
		}
	}
	if !isTerminal(current.Status) {
		to := StatusRunning
		actor := ""
		if current.Status == StatusCancelling {
			to = StatusCancelling
			actor = current.CancelRequestedBy
		}
		var err error
		current, err = ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: to, Actor: actor, At: at, TargetResults: []TargetResult{{TargetID: message.TargetID, Status: TargetTimedOut, ErrorSummary: "execution lease expired", FinishedAt: timePointer(at)}}})
		if err != nil {
			return Job{}, err
		}
	}
	if !allTargetsTerminal(current) || isTerminal(current.Status) {
		return current, nil
	}
	to := StatusFailed
	if current.Progress.CompletedTargets > 0 {
		to = StatusSucceeded
	} else if allTargetsCancelled(current.TargetResults) {
		to = StatusCancelled
	} else if hasTimedOutTarget(current.TargetResults) {
		to = StatusTimedOut
	}
	return ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: to, Artifacts: collectArtifacts(current.TargetResults), ResultSummary: "Agent commands completed", At: at})
}
func (store *memoryCommandPersistence) ClaimPendingTerminalAudits(_ context.Context, limit int, at time.Time) ([]OutboxMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result []OutboxMessage
	for id, message := range store.messages {
		if len(result) >= limit {
			break
		}
		if message.TerminalAuditPending && (message.TerminalAuditLeasedUntil == nil || !message.TerminalAuditLeasedUntil.After(at)) {
			leasedUntil := at.Add(DefaultOutboxLease)
			message.TerminalAuditLeasedUntil = &leasedUntil
			message.TerminalAuditAttempts++
			store.messages[id] = message
			result = append(result, message)
		}
	}
	return result, nil
}
func (store *memoryCommandPersistence) PendingTerminalAuditsForAgent(_ context.Context, agentID string, limit int) ([]OutboxMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result []OutboxMessage
	for _, message := range store.messages {
		if len(result) >= limit {
			break
		}
		if message.TargetID == agentID && message.TerminalAuditPending {
			result = append(result, message)
		}
	}
	return result, nil
}
func (store *memoryCommandPersistence) MarkTerminalAuditRecorded(_ context.Context, scope platformscope.Scope, id, dedupeKey string, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	message := store.messages[id]
	if message.Scope != scope || message.TerminalAuditDedupeKey != dedupeKey {
		return ErrConflict
	}
	message.TerminalAuditPending = false
	message.TerminalAuditLeasedUntil = nil
	message.TerminalAuditRecordedAt = timePointer(at.UTC())
	store.messages[id] = message
	return nil
}
func (store *memoryCommandPersistence) PersistTerminalResult(_ context.Context, input TerminalResultCAS) (TerminalResultOutcome, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	message, ok := store.messages[input.CommandID]
	if !ok || message.Scope != input.Scope {
		return TerminalResultOutcome{CommandID: input.CommandID}, ErrNotFound
	}
	outcome := TerminalResultOutcome{CommandID: input.CommandID, JobID: message.JobID, TargetID: message.TargetID, Status: message.CommandStatus}
	if terminalCommandStatus(message.CommandStatus) {
		if !bytes.Equal(message.ExecutionTokenHash, input.TokenHash[:]) || message.ExecutionRevision != input.ExpectedExecutionRevision {
			return outcome, ErrConflict
		}
		if message.CommandStatus == input.Status && bytes.Equal(message.TerminalResultDigest, input.ResultDigest[:]) {
			outcome.Status = input.Status
			outcome.ResultDigest = input.ResultDigest
			outcome.Persisted = true
			outcome.Duplicate = true
			return outcome, nil
		}
		outcome.Conflict = true
		copy(outcome.ResultDigest[:], message.TerminalResultDigest)
		return outcome, nil
	}
	if !bytes.Equal(message.ExecutionTokenHash, input.TokenHash[:]) || message.ExecutionRevision != input.ExpectedExecutionRevision {
		return outcome, ErrConflict
	}
	message.Phase = phaseForCommandStatus(input.Status)
	message.CommandStatus = input.Status
	message.TerminalResultDigest = append([]byte(nil), input.ResultDigest[:]...)
	message.TerminalAt = timePointer(input.At.UTC())
	message.ExecutionDeadline = nil
	message.RecoveryClaimToken = nil
	message.RecoveryClaimedDeadline = nil
	message.RecoveryClaimedRevision = 0
	store.messages[input.CommandID] = message
	return TerminalResultOutcome{CommandID: input.CommandID, JobID: message.JobID, TargetID: message.TargetID, Status: input.Status, ResultDigest: input.ResultDigest, Persisted: true}, nil
}
func (store *memoryCommandPersistence) LookupCommand(_ context.Context, id string) (OutboxMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.lookups++
	value, ok := store.messages[id]
	if !ok {
		return OutboxMessage{}, ErrNotFound
	}
	return value, nil
}
func (store *memoryCommandPersistence) ClaimPendingCancellations(context.Context, int, time.Time) ([]OutboxMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result []OutboxMessage
	for _, message := range store.messages {
		if message.CancellationRequestedAt != nil && !terminalCommandStatus(message.CommandStatus) {
			result = append(result, message)
		}
	}
	return result, nil
}
func (store *memoryCommandPersistence) ClaimPreparedCommands(_ context.Context, limit int, at time.Time) ([]OutboxMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result []OutboxMessage
	for id, message := range store.messages {
		if len(result) >= limit {
			break
		}
		if (message.Phase == CommandPhasePrepared || message.Phase == CommandPhaseStartAuthorized) && (message.LeasedUntil == nil || !message.LeasedUntil.After(at)) {
			leasedUntil := at.Add(DefaultOutboxLease)
			message.LeasedUntil = &leasedUntil
			message.Attempts++
			store.messages[id] = message
			result = append(result, message)
		}
	}
	return result, nil
}
func (store *memoryCommandPersistence) DeferCancellation(_ context.Context, _ platformscope.Scope, id string, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	message := store.messages[id]
	message.CancellationAvailableAt = &at
	store.messages[id] = message
	return nil
}
func (store *memoryCommandPersistence) AcknowledgeCommand(_ context.Context, scope platformscope.Scope, id string, status CommandStatus, at time.Time, deadline *time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if status == CommandActive {
		return nil
	}
	store.markCalls++
	if len(store.markErrors) > 0 {
		err := store.markErrors[0]
		store.markErrors = store.markErrors[1:]
		if err != nil {
			return err
		}
	}
	message := store.messages[id]
	message.CommandStatus = status
	message.AcknowledgedAt = &at
	if status == CommandActive {
		message.LastHeartbeatAt = &at
		if message.StartEnqueuedAt == nil {
			message.StartEnqueuedAt = timePointer(at.UTC())
		}
	}
	message.ExecutionDeadline = deadline
	message.PublishedAt = &at
	store.messages[id] = message
	store.published = append(store.published, publishedCommand{scope: scope, id: id})
	return nil
}
func (store *memoryCommandPersistence) RenewCommandLease(_ context.Context, _ platformscope.Scope, id string, at, deadline time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	message := store.messages[id]
	message.LastHeartbeatAt = &at
	message.ExecutionDeadline = &deadline
	store.messages[id] = message
	return nil
}
func (store *memoryCommandPersistence) ClaimExpiredCommands(context.Context, int, time.Time) ([]OutboxMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]OutboxMessage(nil), store.expired...), nil
}
func (store *memoryCommandPersistence) MarkCommandTerminal(_ context.Context, scope platformscope.Scope, id string, status CommandStatus, at time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.markCalls++
	if len(store.markErrors) > 0 {
		err := store.markErrors[0]
		store.markErrors = store.markErrors[1:]
		if err != nil {
			return err
		}
	}
	message := store.messages[id]
	message.CommandStatus = status
	message.PublishedAt = &at
	message.ExecutionDeadline = nil
	store.messages[id] = message
	store.published = append(store.published, publishedCommand{scope: scope, id: id})
	return nil
}
func (store *memoryCommandPersistence) PendingCancellationsForAgent(_ context.Context, agentID string, _ int) ([]OutboxMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result []OutboxMessage
	for _, message := range store.messages {
		if message.TargetID == agentID && message.CancellationRequestedAt != nil && !terminalCommandStatus(message.CommandStatus) {
			result = append(result, message)
		}
	}
	return result, nil
}
func (store *memoryCommandPersistence) PreparedCommandsForAgent(_ context.Context, agentID string, limit int) ([]OutboxMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	var result []OutboxMessage
	for _, message := range store.messages {
		if len(result) >= limit {
			break
		}
		if message.TargetID == agentID && (message.Phase == CommandPhasePrepared || message.Phase == CommandPhaseStartAuthorized) {
			result = append(result, message)
		}
	}
	return result, nil
}
func (store *memoryCommandPersistence) currentJob() Job {
	store.mu.Lock()
	defer store.mu.Unlock()
	return normalizeJobUTC(store.jobs["job-1"])
}

type recordingCommandDispatcher struct {
	envelopes           []*agentv1.CommandEnvelope
	starts              []*agentv1.CommandStart
	cancellations       []string
	fencedCancellations []recordedCancellation
	events              []string
}

type recordedCancellation struct {
	agentID           string
	commandID         string
	token             []byte
	executionRevision uint64
	reason            string
}

type testTokenProtector struct{}

func (testTokenProtector) Protect(_ context.Context, token []byte) ([]byte, error) {
	return append([]byte("protected:"), token...), nil
}

func (testTokenProtector) Unprotect(_ context.Context, ciphertext []byte) ([]byte, error) {
	const prefix = "protected:"
	if !bytes.HasPrefix(ciphertext, []byte(prefix)) {
		return nil, errors.New("invalid protected token")
	}
	return append([]byte(nil), ciphertext[len(prefix):]...), nil
}

func (dispatcher *recordingCommandDispatcher) Dispatch(_ context.Context, _ string, envelope *agentv1.CommandEnvelope) error {
	dispatcher.envelopes = append(dispatcher.envelopes, proto.Clone(envelope).(*agentv1.CommandEnvelope))
	return nil
}
func (dispatcher *recordingCommandDispatcher) Start(_ context.Context, _ string, start *agentv1.CommandStart) error {
	dispatcher.starts = append(dispatcher.starts, proto.Clone(start).(*agentv1.CommandStart))
	dispatcher.events = append(dispatcher.events, "start:"+start.GetCommandId())
	return nil
}
func (dispatcher *recordingCommandDispatcher) ReplayStart(ctx context.Context, agentID string, start *agentv1.CommandStart) error {
	return dispatcher.Start(ctx, agentID, start)
}
func (dispatcher *recordingCommandDispatcher) Cancel(_ context.Context, agentID, commandID string) error {
	dispatcher.cancellations = append(dispatcher.cancellations, agentID+"/"+commandID)
	dispatcher.events = append(dispatcher.events, "cancel-unfenced:"+commandID)
	return nil
}
func (dispatcher *recordingCommandDispatcher) CancelPrepared(_ context.Context, agentID, commandID, _ string) error {
	dispatcher.cancellations = append(dispatcher.cancellations, agentID+"/"+commandID)
	dispatcher.events = append(dispatcher.events, "cancel-unfenced:"+commandID)
	return nil
}
func (dispatcher *recordingCommandDispatcher) CancelExecution(_ context.Context, agentID, commandID string, token []byte, executionRevision uint64, reason string) error {
	dispatcher.cancellations = append(dispatcher.cancellations, agentID+"/"+commandID)
	dispatcher.fencedCancellations = append(dispatcher.fencedCancellations, recordedCancellation{agentID: agentID, commandID: commandID, token: append([]byte(nil), token...), executionRevision: executionRevision, reason: reason})
	dispatcher.events = append(dispatcher.events, "cancel:"+commandID)
	return nil
}

type recordingAudit struct {
	events     []audit.Event
	once       map[string]audit.Event
	onceErrors []error
}

func (recorder *recordingAudit) Record(_ context.Context, event audit.Event) (audit.Event, error) {
	recorder.events = append(recorder.events, event)
	return event, nil
}

func (recorder *recordingAudit) RecordOnce(_ context.Context, event audit.Event) (audit.Event, error) {
	if len(recorder.onceErrors) > 0 {
		err := recorder.onceErrors[0]
		recorder.onceErrors = recorder.onceErrors[1:]
		if err != nil {
			return audit.Event{}, err
		}
	}
	if recorder.once == nil {
		recorder.once = make(map[string]audit.Event)
	}
	if existing, ok := recorder.once[event.DedupeKey]; ok {
		if existing.Action != event.Action || existing.Resource != event.Resource || existing.CommandID != event.CommandID || existing.JobID != event.JobID {
			return audit.Event{}, audit.ErrDedupeConflict
		}
		return existing, nil
	}
	recorder.once[event.DedupeKey] = event
	recorder.events = append(recorder.events, event)
	return event, nil
}

func transitionForTest(t *testing.T, current Job, status Status, at time.Time) Job {
	t.Helper()
	next, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: status, At: at})
	require.NoError(t, err)
	return next
}

func assertTraceFields(t *testing.T, event audit.Event, value Job, commandID string) {
	t.Helper()
	require.Equal(t, value.Scope, event.Scope)
	require.Equal(t, value.RequestID, event.RequestID)
	require.Equal(t, value.TraceID, event.TraceID)
	require.Equal(t, value.ID, event.JobID)
	require.Equal(t, commandID, event.CommandID)
	require.Equal(t, audit.Actor{Type: "system", ID: "agent-control"}, event.Actor)
}

func timestamp(value time.Time) *timestamppb.Timestamp { return timestamppb.New(value.UTC()) }
