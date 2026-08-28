package job

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	accepted, err := journal.Accept(context.Background(), fixture.agents.envelopes[0])
	require.NoError(t, err)
	require.True(t, accepted)
	accepted, err = journal.Accept(context.Background(), fixture.agents.envelopes[1])
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

func TestAcknowledgementPersistsJobAndAuditBeforePublicationAndRetriesMarker(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.persistence.messages["command-a"] = fixture.message(t, "command-a", "agent-a")
	fixture.persistence.jobs[fixture.value.ID] = transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	fixture.persistence.markErrors = []error{errors.New("publication unavailable"), nil}
	before := fixture.persistence.currentJob()

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})
	require.Greater(t, fixture.persistence.currentJob().Version, before.Version)
	require.Equal(t, TargetRunning, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Empty(t, fixture.persistence.published)
	require.Len(t, fixture.audit.events, 1)
	require.Len(t, fixture.observerErrors(), 1)

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE})
	require.Equal(t, []publishedCommand{{scope: fixture.scope, id: "command-a"}}, fixture.persistence.published)
	require.Equal(t, TargetRunning, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Len(t, fixture.audit.events, 1)
	require.Equal(t, 2, fixture.persistence.markCalls)
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

func TestAcceptedAcknowledgementPersistsExecutionDeadlineBoundedByJobTimeout(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	timeout := fixture.now.Add(10 * time.Second)
	value := fixture.value
	value.TimeoutAt = &timeout
	fixture.persistence.jobs[value.ID] = transitionForTest(t, value, StatusDispatched, fixture.now)
	message := fixture.messageWithLease(t, "command-a", "agent-a", 30)
	fixture.persistence.messages[message.ID] = message

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: message.ID, State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})

	stored := fixture.persistence.messages[message.ID]
	require.Equal(t, CommandActive, stored.CommandStatus)
	require.NotNil(t, stored.ExecutionDeadline)
	require.Equal(t, timeout, *stored.ExecutionDeadline)
	require.Equal(t, fixture.now, *stored.LastHeartbeatAt)
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
	fixture.persistence.jobs[fixture.value.ID] = transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	fixture.persistence.conflicts = 1

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})
	fixture.lifecycle.Progress(context.Background(), "agent-a", &agentv1.CommandProgress{CommandId: "command-a", Percent: 50, Stage: "executing"})
	outcome, err := fixture.lifecycle.Result(context.Background(), "agent-a", &agentv1.CommandResult{
		CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "stored externally",
		Artifacts: []*agentv1.ArtifactReference{{ArtifactId: "artifact-large", Kind: "command-output", SizeBytes: 10 << 20}},
	})
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	fixture.lifecycle.Acknowledged(context.Background(), "agent-b", &agentv1.CommandAcknowledgement{CommandId: "command-b", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})
	outcome, err = fixture.lifecycle.Result(context.Background(), "agent-b", &agentv1.CommandResult{CommandId: "command-b", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, Summary: "target failed", ErrorCode: "target_error"})
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
	_, err = fixture.lifecycle.Result(context.Background(), "agent-b", &agentv1.CommandResult{CommandId: "command-b", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, Summary: "target failed", ErrorCode: "target_error"})
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
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}, {TargetID: "agent-b", Status: TargetRunning}}, At: fixture.now})
	require.NoError(t, err)
	current, err = ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusCancelling, Actor: "operator-1", At: fixture.now})
	require.NoError(t, err)
	fixture.persistence.jobs[fixture.value.ID] = current

	result := &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED, Summary: "cancelled"}
	outcome, err := fixture.lifecycle.Result(context.Background(), "agent-a", result)
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	intermediate := fixture.persistence.currentJob()
	require.Equal(t, StatusCancelling, intermediate.Status)
	require.Equal(t, TargetCancelled, intermediate.TargetResults[0].Status)

	result = &agentv1.CommandResult{CommandId: "command-b", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED, Summary: "cancelled"}
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
	current := transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	current, err := ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: "agent-a", Status: TargetRunning}}, At: fixture.now})
	require.NoError(t, err)
	current, err = ApplyTransition(current, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusCancelling, Actor: "operator", At: fixture.now})
	require.NoError(t, err)
	fixture.persistence.jobs[current.ID] = current

	outcome, err := fixture.lifecycle.Result(context.Background(), "agent-a", &agentv1.CommandResult{CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "completed before cancellation arrived"})
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	require.Equal(t, StatusSucceeded, fixture.persistence.currentJob().Status)
	require.Equal(t, OutcomeComplete, fixture.persistence.currentJob().Outcome)
}

func TestReconnectRenewsKnownActiveCommandsAndReplaysCancellation(t *testing.T) {
	fixture := newSingleTargetCommandLifecycleFixture(t)
	message := fixture.message(t, "command-a", "agent-a")
	requested := fixture.now.Add(-time.Second)
	message.CommandStatus = CommandActive
	message.CancellationRequestedAt = &requested
	fixture.persistence.messages[message.ID] = message

	fixture.lifecycle.Connected(context.Background(), agentcontrol.SessionInfo{AgentID: "agent-a", ActiveCommands: []*agentv1.CommandRecoveryState{{CommandId: message.ID, State: agentv1.CommandExecutionState_COMMAND_EXECUTION_STATE_RUNNING}}})

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
	message.CommandStatus = CommandActive
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
	mu         sync.Mutex
	jobs       map[string]Job
	messages   map[string]OutboxMessage
	claimed    []OutboxMessage
	published  []publishedCommand
	lookups    int
	conflicts  int
	prepared   map[string][]byte
	markErrors []error
	markCalls  int
	expired    []OutboxMessage
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
	return append([]byte(nil), store.prepared[id]...), nil
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
func (store *memoryCommandPersistence) currentJob() Job {
	store.mu.Lock()
	defer store.mu.Unlock()
	return normalizeJobUTC(store.jobs["job-1"])
}

type recordingCommandDispatcher struct {
	envelopes     []*agentv1.CommandEnvelope
	cancellations []string
}

func (dispatcher *recordingCommandDispatcher) Dispatch(_ context.Context, _ string, envelope *agentv1.CommandEnvelope) error {
	dispatcher.envelopes = append(dispatcher.envelopes, proto.Clone(envelope).(*agentv1.CommandEnvelope))
	return nil
}
func (dispatcher *recordingCommandDispatcher) Cancel(_ context.Context, agentID, commandID string) error {
	dispatcher.cancellations = append(dispatcher.cancellations, agentID+"/"+commandID)
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
