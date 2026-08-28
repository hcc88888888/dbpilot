package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/agentcontrol"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

// A missing durable command lookup, a scope-blind publication update, an
// unsigned command, or a result path that inlines large output makes this test
// fail. Only PostgreSQL and the external Agent transport are test boundaries;
// all lifecycle services are the production implementations.
func TestJobCommandLifecycle(t *testing.T) {
	if os.Getenv("DBPILOT_CONTRACT_E2E") != "1" {
		t.Skip("set DBPILOT_CONTRACT_E2E=1 to run the contract foundation lifecycle")
	}
	dsn := os.Getenv("DBPILOT_CONTRACT_POSTGRES_DSN")
	require.NotEmpty(t, dsn, "DBPILOT_CONTRACT_POSTGRES_DSN is required")

	database := contractDatabase(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.NoError(t, job.RunMigrations(ctx, database))
	require.NoError(t, platformdb.RunMigrations(ctx, database))

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := job.NewEd25519CommandSigner(privateKey)
	require.NoError(t, err)
	tokenProtector, err := job.NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x52}, 32))
	require.NoError(t, err)
	repository := job.NewPostgresRepository(database)
	auditService := audit.NewService(audit.NewPostgresStore(database))
	registry := agentcontrol.NewRegistry(8)
	lifecycle, err := job.NewCommandLifecycle(job.CommandLifecycleConfig{
		DispatchRepository: repository,
		Jobs:               repository,
		Agents:             registry,
		Signer:             signer,
		Audit:              auditService,
		ClaimLimit:         8,
		TokenProtector:     tokenProtector,
	})
	require.NoError(t, err)

	resultErrors := make(chan error, 16)
	controlServer := agentcontrol.NewServer(registry, &resultErrorObserver{CommandLifecycle: lifecycle, errors: resultErrors})
	streams := map[string]*contractAgentStream{}
	for _, agentID := range []string{"agent-a", "agent-b"} {
		stream := newContractAgentStream(contractPeerContext(agentID), contractHello(agentID))
		streams[agentID] = stream
		done := make(chan error, 1)
		go func() { done <- controlServer.Connect(stream) }()
		t.Cleanup(func() {
			stream.closeReceive()
			require.NoError(t, <-done)
		})
		require.NotNil(t, stream.nextSent(t).GetHelloAck())
	}

	created := time.Now().UTC().Truncate(time.Microsecond)
	scope := platformscope.Scope{TenantID: "tenant-contract", ProjectID: "project-contract"}
	value := job.Job{
		ID: "job-contract", Type: "contract.collect", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone,
		TargetResourceIDs: []string{"agent-a", "agent-b"}, InitiatedBy: "contract-test",
		SourceResource: job.ResourceReference{ResourceType: "contract_test", ResourceID: "two-target-lifecycle"},
		IdempotencyKey: "contract-lifecycle", Version: 1, Progress: job.Progress{TotalTargets: 2},
		Artifacts: []job.ArtifactReference{}, CreatedAt: created, RequestID: "request-contract", TraceID: "trace-contract",
	}
	messages := []job.OutboxMessage{
		contractOutbox(t, value, "command-a", "agent-a", created),
		contractOutbox(t, value, "command-b", "agent-b", created.Add(time.Microsecond)),
	}
	require.NoError(t, repository.CreateWithOutbox(ctx, value, messages))

	dispatched, err := lifecycle.DispatchPending(ctx, created.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, 2, dispatched)
	firstDelivery := make(map[string]*agentv1.CommandEnvelope, len(messages))
	for _, message := range messages {
		envelope := streams[message.TargetID].nextSent(t).GetCommand()
		require.NotNil(t, envelope)
		require.Equal(t, message.ID, envelope.GetCommandId())
		require.Equal(t, value.ID, envelope.GetJobId())
		verifier, verifyErr := agent.NewCommandVerifier(message.TargetID, publicKey, []string{"collect_now"})
		require.NoError(t, verifyErr)
		require.NoError(t, verifier.Verify(ctx, envelope))
		firstDelivery[message.ID] = envelope
	}
	var publishedBeforeAck int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM command_outbox WHERE published_at IS NOT NULL").Scan(&publishedBeforeAck))
	require.Zero(t, publishedBeforeAck)

	// Let the one-second Agent execution lease elapse in wall-clock time. The
	// independent delivery deadline must still keep the prepared command valid.
	time.Sleep(1100 * time.Millisecond)
	dispatched, err = lifecycle.DispatchPending(ctx, created.Add(job.DefaultOutboxLease+2*time.Second))
	require.NoError(t, err)
	require.Equal(t, 2, dispatched)
	for _, message := range messages {
		retry := streams[message.TargetID].nextSent(t).GetCommand()
		require.True(t, proto.Equal(firstDelivery[message.ID], retry))
		firstBytes, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(firstDelivery[message.ID])
		require.NoError(t, marshalErr)
		retryBytes, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(retry)
		require.NoError(t, marshalErr)
		require.Equal(t, firstBytes, retryBytes)
	}
	starts := make(map[string]*agentv1.CommandStart, len(messages))
	for _, message := range messages {
		streams[message.TargetID].push(contractPrepared(t, firstDelivery[message.ID]))
		start := streams[message.TargetID].nextSent(t).GetCommandStart()
		require.NotNil(t, start)
		require.Equal(t, message.ID, start.GetCommandId())
		require.Len(t, start.GetExecutionToken(), 32)
		require.Equal(t, uint64(1), start.GetLeaseRevision())
		starts[message.ID] = start
	}

	streams["agent-a"].push(
		contractAck("command-a"),
		contractProgress(starts["command-a"], 50),
		contractResult(starts["command-a"], agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, "artifact-large-output"),
	)
	streams["agent-b"].push(
		contractAck("command-b"),
		contractProgress(starts["command-b"], 75),
		contractResult(starts["command-b"], agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, ""),
	)

	var completed job.Job
	completedInTime := assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		var getErr error
		completed, getErr = repository.Get(ctx, scope, value.ID)
		assert.NoError(collect, getErr)
		assert.Equal(collect, job.StatusSucceeded, completed.Status)
		if len(completed.TargetResults) == 2 {
			assert.Equal(collect, job.TargetSucceeded, completed.TargetResults[0].Status)
			assert.Equal(collect, job.TargetFailed, completed.TargetResults[1].Status)
		} else {
			assert.Len(collect, completed.TargetResults, 2)
		}
	}, 10*time.Second, 20*time.Millisecond)
	if !completedInTime {
		rows, queryErr := database.QueryContext(ctx, "SELECT id, command_phase, command_status FROM command_outbox WHERE job_id = $1 ORDER BY id", value.ID)
		require.NoError(t, queryErr)
		defer rows.Close()
		var commands []string
		for rows.Next() {
			var id, phase, status string
			require.NoError(t, rows.Scan(&id, &phase, &status))
			commands = append(commands, id+":"+phase+":"+status)
		}
		var persistenceErrors []error
		for {
			select {
			case resultErr := <-resultErrors:
				persistenceErrors = append(persistenceErrors, resultErr)
			default:
				t.Fatalf("lifecycle stalled: job=%+v commands=%v result_errors=%v", completed, commands, persistenceErrors)
			}
		}
	}
	require.Equal(t, job.OutcomePartial, completed.Outcome)
	require.Equal(t, 1, completed.Progress.CompletedTargets)
	require.Equal(t, 1, completed.Progress.FailedTargets)
	require.Len(t, completed.TargetResults, 2)
	require.Equal(t, []job.ArtifactReference{{ArtifactID: "artifact-large-output", Kind: "command-output"}}, completed.TargetResults[0].Artifacts)
	encoded, err := proto.Marshal(&agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Artifacts: []*agentv1.ArtifactReference{{ArtifactId: "artifact-large-output", Kind: "command-output", SizeBytes: 8 << 20}}, ExecutionToken: starts["command-a"].GetExecutionToken(), LeaseRevision: starts["command-a"].GetLeaseRevision()})
	require.NoError(t, err)
	require.Less(t, len(encoded), 1024, "large output must be represented by metadata, not inline bytes")

	page, err := auditService.List(ctx, scope, audit.ListQuery{Limit: 100})
	require.NoError(t, err)
	require.NotEmpty(t, page.Items)
	seenCommands := map[string]bool{}
	for _, event := range page.Items {
		require.Equal(t, value.RequestID, event.RequestID)
		require.Equal(t, value.TraceID, event.TraceID)
		require.Equal(t, value.ID, event.JobID)
		require.NotEmpty(t, event.CommandID)
		seenCommands[event.CommandID] = true
	}
	require.Equal(t, map[string]bool{"command-a": true, "command-b": true}, seenCommands)
	for _, commandID := range []string{"command-a", "command-b"} {
		agentID := strings.Replace(commandID, "command-", "agent-", 1)
		resultAck := streams[agentID].nextSent(t).GetCommandResultAcknowledgement()
		require.NotNil(t, resultAck)
		require.Equal(t, commandID, resultAck.GetCommandId())
		require.True(t, resultAck.GetPersisted())
	}
	var publishedAfterAck int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM command_outbox WHERE published_at IS NOT NULL").Scan(&publishedAfterAck))
	require.Equal(t, 2, publishedAfterAck)

	raceCreated := created.Add(30 * time.Minute)
	raceJob := job.Job{
		ID: "job-start-cancel-race", Type: "contract.collect", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone,
		TargetResourceIDs: []string{"agent-a"}, InitiatedBy: "contract-test",
		SourceResource: job.ResourceReference{ResourceType: "contract_test", ResourceID: "start-cancel-race"},
		IdempotencyKey: "contract-start-cancel-race", Version: 1, Progress: job.Progress{TotalTargets: 1},
		Artifacts: []job.ArtifactReference{}, CreatedAt: raceCreated, RequestID: "request-start-cancel-race", TraceID: "trace-start-cancel-race",
	}
	raceMessage := contractOutbox(t, raceJob, "command-start-cancel-race", "agent-a", raceCreated)
	require.NoError(t, repository.CreateWithOutbox(ctx, raceJob, []job.OutboxMessage{raceMessage}))
	dispatched, err = lifecycle.DispatchPending(ctx, raceCreated.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, 1, dispatched)
	raceEnvelope := streams["agent-a"].nextSent(t).GetCommand()
	require.Equal(t, raceMessage.ID, raceEnvelope.GetCommandId())
	streams["agent-a"].push(contractPrepared(t, raceEnvelope))
	raceStart := streams["agent-a"].nextSent(t).GetCommandStart()
	require.NotNil(t, raceStart, "Start must be enqueued only after its PostgreSQL CAS commits")
	raceCurrent, err := repository.Get(ctx, scope, raceJob.ID)
	require.NoError(t, err)
	_, err = repository.RequestCancel(ctx, scope, raceJob.ID, "operator", raceCurrent.Version, time.Now().UTC())
	require.NoError(t, err)
	_, err = lifecycle.DispatchPending(ctx, time.Now().UTC())
	require.NoError(t, err)
	raceReplay := streams["agent-a"].nextSent(t).GetCommandStart()
	require.NotNil(t, raceReplay)
	require.True(t, proto.Equal(raceStart, raceReplay), "cancellation must replay the exact persisted Start fence first")
	raceCancellation := streams["agent-a"].nextSent(t).GetCommandCancellation()
	require.NotNil(t, raceCancellation)
	require.Equal(t, raceStart.GetExecutionToken(), raceCancellation.GetExecutionToken())
	require.Equal(t, raceStart.GetLeaseRevision(), raceCancellation.GetLeaseRevision())
	streams["agent-a"].push(contractAck(raceMessage.ID), contractResult(raceStart, agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, ""))
	raceResultAck := streams["agent-a"].nextSent(t).GetCommandResultAcknowledgement()
	require.NotNil(t, raceResultAck)
	require.True(t, raceResultAck.GetPersisted())
	raceCompleted, err := repository.Get(ctx, scope, raceJob.ID)
	require.NoError(t, err)
	require.Equal(t, job.StatusSucceeded, raceCompleted.Status, "Start-winning cancellation must preserve the Agent's true terminal result")

	timeoutCreated := created.Add(time.Hour)
	timeoutJob := job.Job{
		ID: "job-delivery-timeout", Type: "contract.collect", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone,
		TargetResourceIDs: []string{"agent-a"}, InitiatedBy: "contract-test",
		SourceResource: job.ResourceReference{ResourceType: "contract_test", ResourceID: "delivery-timeout"},
		IdempotencyKey: "contract-delivery-timeout", Version: 1, Progress: job.Progress{TotalTargets: 1},
		Artifacts: []job.ArtifactReference{}, CreatedAt: timeoutCreated, RequestID: "request-delivery-timeout", TraceID: "trace-delivery-timeout",
	}
	timeoutMessage := contractOutbox(t, timeoutJob, "command-delivery-timeout", "agent-a", timeoutCreated)
	require.NoError(t, repository.CreateWithOutbox(ctx, timeoutJob, []job.OutboxMessage{timeoutMessage}))
	dispatched, err = lifecycle.DispatchPending(ctx, timeoutCreated)
	require.NoError(t, err)
	require.Equal(t, 1, dispatched)
	require.Equal(t, timeoutMessage.ID, streams["agent-a"].nextSent(t).GetCommand().GetCommandId())

	dispatched, err = lifecycle.DispatchPending(ctx, timeoutCreated.Add(job.DefaultCommandDeliveryTTL+time.Second))
	require.NoError(t, err)
	require.Zero(t, dispatched)
	streams["agent-a"].requireNoSent(t)
	timedOut, err := repository.Get(ctx, scope, timeoutJob.ID)
	require.NoError(t, err)
	require.Equal(t, job.StatusTimedOut, timedOut.Status)
	require.Equal(t, job.TargetTimedOut, timedOut.TargetResults[0].Status)
	dedupeKey := "command.delivery_timed_out:" + timeoutMessage.ID

	existing, err := auditService.RecordOnce(ctx, audit.Event{
		DedupeKey: dedupeKey, Scope: scope, OccurredAt: timeoutCreated.Add(job.DefaultCommandDeliveryTTL + 2*time.Second),
		Action: "command.delivery_timed_out", Actor: audit.Actor{Type: "system", ID: "agent-control"},
		Resource: audit.Resource{Type: "job_target", ID: "agent-a"}, Result: "failure",
		RequestID: timeoutJob.RequestID, TraceID: timeoutJob.TraceID, JobID: timeoutJob.ID, CommandID: timeoutMessage.ID,
		Detail: map[string]any{"reason": "delivery_deadline"},
	})
	require.NoError(t, err)
	require.Equal(t, dedupeKey, existing.DedupeKey)
	_, err = auditService.RecordOnce(ctx, audit.Event{
		DedupeKey: dedupeKey, Scope: scope, Action: "command.conflicting", Actor: audit.Actor{Type: "system", ID: "agent-control"},
		Resource: audit.Resource{Type: "job_target", ID: "agent-a"}, Result: "failure",
		RequestID: timeoutJob.RequestID, TraceID: timeoutJob.TraceID, JobID: timeoutJob.ID, CommandID: timeoutMessage.ID,
		Detail: map[string]any{"reason": "delivery_deadline"},
	})
	require.ErrorIs(t, err, audit.ErrDedupeConflict)
	var publishedTimeout bool
	var timeoutAuditCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT published_at IS NOT NULL FROM command_outbox WHERE id = $1", timeoutMessage.ID).Scan(&publishedTimeout))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND dedupe_key = $3", scope.TenantID, scope.ProjectID, dedupeKey).Scan(&timeoutAuditCount))
	require.True(t, publishedTimeout)
	require.Equal(t, 1, timeoutAuditCount, "a published timeout command must have exactly one durable Audit event")

	cancelCreated := timeoutCreated.Add(2 * time.Hour)
	cancelJob := job.Job{
		ID: "job-cancel-before-dispatch", Type: "contract.collect", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone,
		TargetResourceIDs: []string{"agent-a"}, InitiatedBy: "contract-test",
		SourceResource: job.ResourceReference{ResourceType: "contract_test", ResourceID: "cancel-before-dispatch"},
		IdempotencyKey: "contract-cancel-before-dispatch", Version: 1, Progress: job.Progress{TotalTargets: 1},
		Artifacts: []job.ArtifactReference{}, CreatedAt: cancelCreated, RequestID: "request-cancel-before-dispatch", TraceID: "trace-cancel-before-dispatch",
	}
	cancelMessage := contractOutbox(t, cancelJob, "command-cancel-before-dispatch", "agent-a", cancelCreated)
	require.NoError(t, repository.CreateWithOutbox(ctx, cancelJob, []job.OutboxMessage{cancelMessage}))
	_, err = repository.RequestCancel(ctx, scope, cancelJob.ID, "operator", cancelJob.Version, cancelCreated.Add(time.Second))
	require.NoError(t, err)
	dispatched, err = lifecycle.DispatchPending(ctx, cancelCreated.Add(2*time.Second))
	require.NoError(t, err)
	require.Zero(t, dispatched)
	streams["agent-a"].requireNoSent(t)
	cancelled, err := repository.Get(ctx, scope, cancelJob.ID)
	require.NoError(t, err)
	require.Equal(t, job.StatusCancelled, cancelled.Status)
	var cancellationRequested bool
	var cancellationStatus string
	require.NoError(t, database.QueryRowContext(ctx, "SELECT cancellation_requested_at IS NOT NULL, command_status FROM command_outbox WHERE id = $1", cancelMessage.ID).Scan(&cancellationRequested, &cancellationStatus))
	require.True(t, cancellationRequested)
	require.Equal(t, string(job.CommandCancelled), cancellationStatus)

	recoveryCreated := cancelCreated.Add(time.Hour)
	recoveryTimeout := recoveryCreated.Add(time.Hour)
	recoveryJob := job.Job{
		ID: "job-execution-recovery", Type: "contract.collect", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone,
		TargetResourceIDs: []string{"agent-a"}, InitiatedBy: "contract-test",
		SourceResource: job.ResourceReference{ResourceType: "contract_test", ResourceID: "execution-recovery"},
		IdempotencyKey: "contract-execution-recovery", Version: 1, Progress: job.Progress{TotalTargets: 1}, TimeoutAt: &recoveryTimeout,
		Artifacts: []job.ArtifactReference{}, CreatedAt: recoveryCreated, RequestID: "request-execution-recovery", TraceID: "trace-execution-recovery",
	}
	recoveryMessage := contractOutbox(t, recoveryJob, "command-execution-recovery", "agent-a", recoveryCreated)
	require.NoError(t, repository.CreateWithOutbox(ctx, recoveryJob, []job.OutboxMessage{recoveryMessage}))
	dispatched, err = lifecycle.DispatchPending(ctx, recoveryCreated.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, 1, dispatched)
	recoveryEnvelope := streams["agent-a"].nextSent(t).GetCommand()
	require.Equal(t, recoveryMessage.ID, recoveryEnvelope.GetCommandId())
	streams["agent-a"].push(contractPrepared(t, recoveryEnvelope))
	recoveryStart := streams["agent-a"].nextSent(t).GetCommandStart()
	require.NotNil(t, recoveryStart)
	streams["agent-a"].push(contractAck(recoveryMessage.ID))
	require.Eventually(t, func() bool {
		var status string
		var deadline sql.NullTime
		queryErr := database.QueryRowContext(ctx, "SELECT command_status, execution_deadline_at FROM command_outbox WHERE id = $1", recoveryMessage.ID).Scan(&status, &deadline)
		return queryErr == nil && status == string(job.CommandActive) && deadline.Valid
	}, 5*time.Second, 20*time.Millisecond)
	time.Sleep(1100 * time.Millisecond)
	dispatched, err = lifecycle.DispatchPending(ctx, time.Now().UTC())
	require.NoError(t, err)
	require.Zero(t, dispatched)
	recovered, err := repository.Get(ctx, scope, recoveryJob.ID)
	require.NoError(t, err)
	require.Equal(t, job.StatusTimedOut, recovered.Status)
	var recoveryAuditCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE dedupe_key = $1", "command.execution_timed_out:"+recoveryMessage.ID).Scan(&recoveryAuditCount))
	require.Equal(t, 1, recoveryAuditCount)
}

func contractDatabase(t *testing.T, rawDSN string) *sql.DB {
	t.Helper()
	admin, err := sql.Open("postgres", rawDSN)
	require.NoError(t, err)
	require.NoError(t, admin.Ping())
	schema := fmt.Sprintf("contract_%d", time.Now().UnixNano())
	_, err = admin.Exec(`CREATE SCHEMA ` + pq.QuoteIdentifier(schema))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, dropErr := admin.Exec(`DROP SCHEMA ` + pq.QuoteIdentifier(schema) + ` CASCADE`)
		require.NoError(t, dropErr)
		require.NoError(t, admin.Close())
	})

	parsed, err := url.Parse(rawDSN)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	database, err := sql.Open("postgres", parsed.String())
	require.NoError(t, err)
	require.NoError(t, database.Ping())
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	return database
}

func contractOutbox(t *testing.T, value job.Job, commandID, agentID string, at time.Time) job.OutboxMessage {
	t.Helper()
	payload, err := proto.Marshal(&agentv1.CommandEnvelope{
		AgentId: agentID, LeaseSeconds: 1,
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"health"}}},
	})
	require.NoError(t, err)
	return job.OutboxMessage{ID: commandID, Scope: value.Scope, JobID: value.ID, TargetID: agentID, Type: "agent.command", Payload: payload, AvailableAt: at, CreatedAt: at}
}

func contractHello(agentID string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{AgentId: agentID, ProtocolVersion: agentcontrol.ProtocolVersion, Capabilities: []string{"collect_now"}}}}
}

func contractAck(commandID string) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandAcknowledgement{CommandAcknowledgement: &agentv1.CommandAcknowledgement{CommandId: commandID, State: agentv1.CommandAcknowledgementState_COMMAND_ACKNOWLEDGEMENT_STATE_ACCEPTED}}}
}

func contractPrepared(t *testing.T, envelope *agentv1.CommandEnvelope) *agentv1.AgentMessage {
	t.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	require.NoError(t, err)
	digest := sha256.Sum256(encoded)
	return &agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandPrepared{CommandPrepared: &agentv1.CommandPrepared{CommandId: envelope.GetCommandId(), EnvelopeDigest: digest[:]}}}
}

func contractProgress(start *agentv1.CommandStart, percent uint32) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: start.GetCommandId(), Percent: percent, Stage: "executing", ExecutionToken: append([]byte(nil), start.GetExecutionToken()...), LeaseRevision: start.GetLeaseRevision()}}}
}

func contractResult(start *agentv1.CommandStart, state agentv1.CommandResultState, artifactID string) *agentv1.AgentMessage {
	result := &agentv1.CommandResult{CommandId: start.GetCommandId(), State: state, Summary: state.String(), ExecutionToken: append([]byte(nil), start.GetExecutionToken()...), LeaseRevision: start.GetLeaseRevision()}
	if artifactID != "" {
		result.Artifacts = []*agentv1.ArtifactReference{{ArtifactId: artifactID, Kind: "command-output", ContentType: "application/octet-stream", SizeBytes: 8 << 20}}
	}
	return &agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandResult{CommandResult: result}}
}

func contractPeerContext(agentID string) context.Context {
	identity, _ := url.Parse("spiffe://dbpilot.local/agent/" + agentID)
	certificate := &x509.Certificate{URIs: []*url.URL{identity}}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
}

type contractAgentStream struct {
	ctx      context.Context
	receive  chan *agentv1.AgentMessage
	sent     chan *agentv1.ServerMessage
	closeOne sync.Once
}

func newContractAgentStream(ctx context.Context, messages ...*agentv1.AgentMessage) *contractAgentStream {
	stream := &contractAgentStream{ctx: ctx, receive: make(chan *agentv1.AgentMessage, 16), sent: make(chan *agentv1.ServerMessage, 16)}
	stream.push(messages...)
	return stream
}

func (stream *contractAgentStream) push(messages ...*agentv1.AgentMessage) {
	for _, message := range messages {
		stream.receive <- message
	}
}

func (stream *contractAgentStream) closeReceive() {
	stream.closeOne.Do(func() { close(stream.receive) })
}
func (stream *contractAgentStream) nextSent(t *testing.T) *agentv1.ServerMessage {
	t.Helper()
	select {
	case message := <-stream.sent:
		return message
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for AgentControl message")
		return nil
	}
}
func (stream *contractAgentStream) requireNoSent(t *testing.T) {
	t.Helper()
	select {
	case message := <-stream.sent:
		t.Fatalf("unexpected AgentControl message after delivery deadline: %s", message.GetMessageId())
	case <-time.After(100 * time.Millisecond):
	}
}
func (stream *contractAgentStream) Send(message *agentv1.ServerMessage) error {
	stream.sent <- message
	return nil
}
func (stream *contractAgentStream) Recv() (*agentv1.AgentMessage, error) {
	message, ok := <-stream.receive
	if !ok {
		return nil, io.EOF
	}
	return message, nil
}
func (stream *contractAgentStream) SetHeader(metadata.MD) error  { return nil }
func (stream *contractAgentStream) SendHeader(metadata.MD) error { return nil }
func (stream *contractAgentStream) SetTrailer(metadata.MD)       {}
func (stream *contractAgentStream) Context() context.Context     { return stream.ctx }
func (stream *contractAgentStream) SendMsg(message any) error {
	typed, ok := message.(*agentv1.ServerMessage)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	return stream.Send(typed)
}
func (stream *contractAgentStream) RecvMsg(message any) error {
	typed, ok := message.(*agentv1.AgentMessage)
	if !ok {
		return io.ErrUnexpectedEOF
	}
	received, err := stream.Recv()
	if err != nil {
		return err
	}
	proto.Reset(typed)
	proto.Merge(typed, received)
	return nil
}

var _ grpc.BidiStreamingServer[agentv1.AgentMessage, agentv1.ServerMessage] = (*contractAgentStream)(nil)

type resultErrorObserver struct {
	*job.CommandLifecycle
	errors chan error
}

func (observer *resultErrorObserver) Result(ctx context.Context, agentID string, result *agentv1.CommandResult) (agentcontrol.ResultPersistence, error) {
	outcome, err := observer.CommandLifecycle.Result(ctx, agentID, result)
	if err != nil {
		observer.errors <- err
	}
	return outcome, err
}
