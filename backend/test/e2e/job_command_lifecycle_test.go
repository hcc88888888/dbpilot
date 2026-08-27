package e2e_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
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
	})
	require.NoError(t, err)

	controlServer := agentcontrol.NewServer(registry, lifecycle)
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

	streams["agent-a"].push(
		contractAck("command-a"),
		contractProgress("command-a", 50),
		contractResult("command-a", agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, "artifact-large-output"),
	)
	streams["agent-b"].push(
		contractAck("command-b"),
		contractProgress("command-b", 75),
		contractResult("command-b", agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED, ""),
	)

	var completed job.Job
	require.Eventually(t, func() bool {
		var getErr error
		completed, getErr = repository.Get(ctx, scope, value.ID)
		return getErr == nil && completed.Status == job.StatusSucceeded
	}, 10*time.Second, 20*time.Millisecond)
	require.Equal(t, job.OutcomePartial, completed.Outcome)
	require.Equal(t, 1, completed.Progress.CompletedTargets)
	require.Equal(t, 1, completed.Progress.FailedTargets)
	require.Len(t, completed.TargetResults, 2)
	require.Equal(t, []job.ArtifactReference{{ArtifactID: "artifact-large-output", Kind: "command-output"}}, completed.TargetResults[0].Artifacts)
	encoded, err := proto.Marshal(&agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Artifacts: []*agentv1.ArtifactReference{{ArtifactId: "artifact-large-output", Kind: "command-output", SizeBytes: 8 << 20}}})
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
	var publishedAfterAck int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM command_outbox WHERE published_at IS NOT NULL").Scan(&publishedAfterAck))
	require.Equal(t, 2, publishedAfterAck)
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
		AgentId: agentID, LeaseSeconds: 60,
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

func contractProgress(commandID string, percent uint32) *agentv1.AgentMessage {
	return &agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: commandID, Percent: percent, Stage: "executing"}}}
}

func contractResult(commandID string, state agentv1.CommandResultState, artifactID string) *agentv1.AgentMessage {
	result := &agentv1.CommandResult{CommandId: commandID, State: state, Summary: state.String()}
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
