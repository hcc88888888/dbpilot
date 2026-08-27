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
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}},
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
	require.Equal(t, "delivery_deadline", fixture.audit.events[len(fixture.audit.events)-1].Detail["reason"])
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
	require.Len(t, fixture.audit.events, 1, "failed publication must defer the timeout audit")

	dispatched, err := fixture.lifecycle.DispatchPending(context.Background(), fixture.now.Add(DefaultCommandDeliveryTTL+DefaultOutboxLease+2*time.Second))
	require.NoError(t, err)
	require.Zero(t, dispatched)
	require.Equal(t, first.Version, fixture.persistence.currentJob().Version)
	require.Equal(t, []publishedCommand{{scope: fixture.scope, id: "command-a"}}, fixture.persistence.published)
	require.Equal(t, "command.delivery_timed_out", fixture.audit.events[len(fixture.audit.events)-1].Action)
	require.Len(t, fixture.agents.envelopes, 1)
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

func TestAcknowledgementPublishesBeforeMutationAndDuplicateRetriesPublicationFailure(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.persistence.messages["command-a"] = fixture.message(t, "command-a", "agent-a")
	fixture.persistence.jobs[fixture.value.ID] = transitionForTest(t, fixture.value, StatusDispatched, fixture.now)
	fixture.persistence.markErrors = []error{errors.New("publication unavailable"), nil}
	before := fixture.persistence.currentJob()

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})
	require.Equal(t, before.Version, fixture.persistence.currentJob().Version)
	require.Empty(t, fixture.persistence.published)
	require.Empty(t, fixture.audit.events)
	require.Len(t, fixture.observerErrors(), 1)

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_DUPLICATE})
	require.Equal(t, []publishedCommand{{scope: fixture.scope, id: "command-a"}}, fixture.persistence.published)
	require.Equal(t, TargetRunning, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Len(t, fixture.audit.events, 1)
	require.Equal(t, 2, fixture.persistence.markCalls)
}

func TestRejectedAcknowledgementPublishesBeforeFailedTargetMapping(t *testing.T) {
	fixture := newCommandLifecycleFixture(t)
	fixture.persistence.messages["command-a"] = fixture.message(t, "command-a", "agent-a")
	fixture.persistence.jobs[fixture.value.ID] = transitionForTest(t, fixture.value, StatusDispatched, fixture.now)

	fixture.lifecycle.Acknowledged(context.Background(), "agent-a", &agentv1.CommandAcknowledgement{CommandId: "command-a", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_REJECTED, ReasonCode: "busy"})

	require.Equal(t, []publishedCommand{{scope: fixture.scope, id: "command-a"}}, fixture.persistence.published)
	require.Equal(t, TargetFailed, fixture.persistence.currentJob().TargetResults[0].Status)
	require.Equal(t, "failure", fixture.audit.events[0].Result)
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
			envelope := &agentv1.CommandEnvelope{AgentId: "agent-a", LeaseSeconds: 30, Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}}}
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
	fixture.lifecycle.Result(context.Background(), "agent-a", &agentv1.CommandResult{
		CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "stored externally",
		Artifacts: []*agentv1.ArtifactReference{{ArtifactId: "artifact-large", Kind: "command-output", SizeBytes: 10 << 20}},
	})
	fixture.lifecycle.Acknowledged(context.Background(), "agent-b", &agentv1.CommandAcknowledgement{CommandId: "command-b", State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED})
	fixture.lifecycle.Result(context.Background(), "agent-b", &agentv1.CommandResult{CommandId: "command-b", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, Summary: "target failed", ErrorCode: "target_error"})

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
	fixture.lifecycle.Result(context.Background(), "agent-b", &agentv1.CommandResult{CommandId: "command-b", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, Summary: "duplicate"})
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
	fixture.lifecycle.Result(context.Background(), "agent-a", result)
	intermediate := fixture.persistence.currentJob()
	require.Equal(t, StatusCancelling, intermediate.Status)
	require.Equal(t, TargetCancelled, intermediate.TargetResults[0].Status)

	result = &agentv1.CommandResult{CommandId: "command-b", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED, Summary: "cancelled"}
	fixture.lifecycle.Result(context.Background(), "agent-b", result)

	got := fixture.persistence.currentJob()
	require.Equal(t, StatusCancelled, got.Status)
	require.Equal(t, TargetCancelled, got.TargetResults[0].Status)
	require.Equal(t, TargetCancelled, got.TargetResults[1].Status)
	require.Equal(t, "command.result", fixture.audit.events[0].Action)
	require.Equal(t, "failure", fixture.audit.events[0].Result)
	version := got.Version
	fixture.lifecycle.Result(context.Background(), "agent-b", result)
	require.Equal(t, version, fixture.persistence.currentJob().Version)
	require.Len(t, fixture.audit.events, 3)
	require.Equal(t, "duplicate", fixture.audit.events[2].Result)
	require.Empty(t, fixture.observerErrors())
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
	encoded, err := proto.Marshal(&agentv1.CommandEnvelope{AgentId: agentID, LeaseSeconds: leaseSeconds, Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{}}})
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
func (store *memoryCommandPersistence) RequestCancel(context.Context, platformscope.Scope, string, string, time.Time) (Job, error) {
	return Job{}, errors.New("not implemented")
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
func (store *memoryCommandPersistence) currentJob() Job {
	store.mu.Lock()
	defer store.mu.Unlock()
	return normalizeJobUTC(store.jobs["job-1"])
}

type recordingCommandDispatcher struct{ envelopes []*agentv1.CommandEnvelope }

func (dispatcher *recordingCommandDispatcher) Dispatch(_ context.Context, _ string, envelope *agentv1.CommandEnvelope) error {
	dispatcher.envelopes = append(dispatcher.envelopes, proto.Clone(envelope).(*agentv1.CommandEnvelope))
	return nil
}
func (*recordingCommandDispatcher) Cancel(context.Context, string, string) error { return nil }

type recordingAudit struct{ events []audit.Event }

func (recorder *recordingAudit) Record(_ context.Context, event audit.Event) (audit.Event, error) {
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
