package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/gen/openapi"
	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"dbpilot.local/platform/internal/agentcontrol"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/controlplane"
	"dbpilot.local/platform/internal/idempotency"
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
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

func TestTwoPhaseCommandLifecycle(t *testing.T) {
	if os.Getenv("DBPILOT_CONTRACT_E2E") != "1" {
		t.Skip("set DBPILOT_CONTRACT_E2E=1 to run the two-phase command lifecycle")
	}
	dsn := os.Getenv("DBPILOT_CONTRACT_POSTGRES_DSN")
	require.NotEmpty(t, dsn, "DBPILOT_CONTRACT_POSTGRES_DSN is required")

	t.Run("cancel after Prepare wins before Start and executor remains untouched", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		environment := newContractCommandEnvironment(t, ctx, dsn)
		registry := agentcontrol.NewRegistry(16)
		lifecycle := environment.newLifecycle(t, registry)
		preparedGate := newBlockingPreparedObserver(lifecycle)
		_, streamOpener := startCommandControlServer(t, registry, preparedGate)
		executor := &countingCommandExecutor{}
		journal := startContractAgent(t, ctx, streamOpener, environment.publicKey, executor, 20*time.Millisecond)
		require.Eventually(t, func() bool { _, connected := registry.Session("agent-a"); return connected }, 3*time.Second, 10*time.Millisecond)

		scope := platformscope.Scope{TenantID: "tenant-prepare-cancel", ProjectID: "project-prepare-cancel"}
		created := time.Now().UTC().Truncate(time.Microsecond)
		value := contractJob("job-prepare-cancel", scope, "agent-a", created)
		message := contractOutbox(t, value, "command-prepare-cancel", "agent-a", created)
		require.NoError(t, environment.repository.CreateWithOutbox(ctx, value, []job.OutboxMessage{message}))
		dispatched, err := lifecycle.DispatchPending(ctx, created.Add(time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, 1, dispatched)
		preparedGate.wait(t)

		current, err := environment.repository.Get(ctx, scope, value.ID)
		require.NoError(t, err)
		_, err = environment.repository.RequestCancel(ctx, scope, value.ID, "operator", current.Version, time.Now().UTC())
		require.NoError(t, err)
		preparedGate.release()
		preparedGate.waitDone(t)
		require.Eventually(t, func() bool {
			_, dispatchErr := lifecycle.DispatchPending(ctx, time.Now().UTC())
			if dispatchErr != nil {
				return false
			}
			cancelled, getErr := environment.repository.Get(ctx, scope, value.ID)
			return getErr == nil && cancelled.Status == job.StatusCancelled
		}, 3*time.Second, 20*time.Millisecond)
		require.Eventually(t, func() bool {
			entry, getErr := journal.Get(ctx, message.ID)
			return getErr == nil && entry.State == commandjournal.StateCancelled
		}, 3*time.Second, 20*time.Millisecond)
		require.Zero(t, executor.calls.Load())
		var tokenCount int
		require.NoError(t, environment.database.QueryRowContext(ctx, "SELECT count(*) FROM command_outbox WHERE id = $1 AND execution_token_hash IS NOT NULL", message.ID).Scan(&tokenCount))
		require.Zero(t, tokenCount, "Cancel-winning transaction must prevent creation of a Start fence")
	})

	t.Run("Start-winning cancellation preserves the executor result", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		environment := newContractCommandEnvironment(t, ctx, dsn)
		registry := agentcontrol.NewRegistry(16)
		lifecycle := environment.newLifecycle(t, registry)
		_, streamOpener := startCommandControlServer(t, registry, lifecycle)
		executor := newStartWinningExecutor()
		t.Cleanup(executor.finishSuccessfully)
		journal := startContractAgent(t, ctx, streamOpener, environment.publicKey, executor, 20*time.Millisecond)
		require.Eventually(t, func() bool { _, connected := registry.Session("agent-a"); return connected }, 3*time.Second, 10*time.Millisecond)

		scope := platformscope.Scope{TenantID: "tenant-start-cancel", ProjectID: "project-start-cancel"}
		created := time.Now().UTC().Truncate(time.Microsecond)
		value := contractJob("job-start-cancel", scope, "agent-a", created)
		message := contractOutbox(t, value, "command-start-cancel", "agent-a", created)
		require.NoError(t, environment.repository.CreateWithOutbox(ctx, value, []job.OutboxMessage{message}))
		dispatched, err := lifecycle.DispatchPending(ctx, created.Add(time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, 1, dispatched)
		executor.waitStarted(t)
		current, err := environment.repository.Get(ctx, scope, value.ID)
		require.NoError(t, err)
		_, err = environment.repository.RequestCancel(ctx, scope, value.ID, "operator", current.Version, time.Now().UTC())
		require.NoError(t, err)
		require.Eventually(t, func() bool {
			_, dispatchErr := lifecycle.DispatchPending(ctx, time.Now().UTC())
			return dispatchErr == nil && executor.wasCancelled()
		}, 3*time.Second, 20*time.Millisecond)
		executor.finishSuccessfully()
		require.Eventually(t, func() bool {
			completed, getErr := environment.repository.Get(ctx, scope, value.ID)
			return getErr == nil && completed.Status == job.StatusSucceeded
		}, 3*time.Second, 20*time.Millisecond)
		require.Equal(t, int32(1), executor.calls.Load(), "an exact Start replay must not invoke the executor twice")
		require.Eventually(t, func() bool {
			pending, pendingErr := journal.PendingResults(ctx)
			return pendingErr == nil && len(pending) == 0
		}, 3*time.Second, 20*time.Millisecond)
		var phase string
		require.NoError(t, environment.database.QueryRowContext(ctx, "SELECT command_phase FROM command_outbox WHERE id = $1", message.ID).Scan(&phase))
		require.Equal(t, string(job.CommandPhaseSucceeded), phase)
	})

	t.Run("heartbeat invalidates a stale timeout claim", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		environment := newContractCommandEnvironment(t, ctx, dsn)
		registry := agentcontrol.NewRegistry(16)
		lifecycle := environment.newLifecycle(t, registry)
		_, streamOpener := startCommandControlServer(t, registry, lifecycle)
		executor := newBlockingCommandExecutor()
		startContractAgent(t, ctx, streamOpener, environment.publicKey, executor, 20*time.Millisecond)
		require.Eventually(t, func() bool { _, connected := registry.Session("agent-a"); return connected }, 3*time.Second, 10*time.Millisecond)

		scope := platformscope.Scope{TenantID: "tenant-heartbeat-timeout", ProjectID: "project-heartbeat-timeout"}
		created := time.Now().UTC().Truncate(time.Microsecond)
		value := contractJob("job-heartbeat-timeout", scope, "agent-a", created)
		message := contractOutbox(t, value, "command-heartbeat-timeout", "agent-a", created)
		require.NoError(t, environment.repository.CreateWithOutbox(ctx, value, []job.OutboxMessage{message}))
		dispatched, err := lifecycle.DispatchPending(ctx, created.Add(time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, 1, dispatched)
		executor.waitStarted(t)

		claimAt := time.Now().UTC().Add(10 * time.Second)
		claims, err := environment.repository.ClaimExpiredExecution(ctx, 1, claimAt)
		require.NoError(t, err)
		require.Len(t, claims, 1)
		claim := claims[0]
		require.Equal(t, message.ID, claim.CommandID)
		require.Eventually(t, func() bool {
			var claimCleared bool
			var revision uint64
			queryErr := environment.database.QueryRowContext(ctx, "SELECT recovery_claim_token IS NULL, recovery_revision FROM command_outbox WHERE id = $1", message.ID).Scan(&claimCleared, &revision)
			return queryErr == nil && claimCleared && revision > claim.ClaimedRecoveryRevision
		}, 3*time.Second, 20*time.Millisecond)
		err = environment.repository.FinalizeExpiredExecution(ctx, claim, claimAt.Add(time.Millisecond))
		require.ErrorIs(t, err, job.ErrConflict)
		current, err := environment.repository.Get(ctx, scope, value.ID)
		require.NoError(t, err)
		require.NotEqual(t, job.StatusTimedOut, current.Status)
		require.NotEqual(t, job.TargetTimedOut, current.TargetResults[0].Status)
	})

	t.Run("timeout worker accepts matching interrupted recovery evidence", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		environment := newContractCommandEnvironment(t, ctx, dsn)
		dispatcher := newCapturedCommandDispatcher()
		lifecycle := environment.newLifecycle(t, dispatcher)
		scope := platformscope.Scope{TenantID: "tenant-timeout-interrupted", ProjectID: "project-timeout-interrupted"}
		created := time.Now().UTC().Truncate(time.Microsecond)
		value := contractJob("job-timeout-interrupted", scope, "agent-a", created)
		message := contractOutbox(t, value, "command-timeout-interrupted", "agent-a", created)
		require.NoError(t, environment.repository.CreateWithOutbox(ctx, value, []job.OutboxMessage{message}))
		dispatched, err := lifecycle.DispatchPending(ctx, created.Add(time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, 1, dispatched)
		envelope := dispatcher.nextEnvelope(t)
		_, err = lifecycle.Prepared(ctx, "agent-a", contractPrepared(t, envelope).GetCommandPrepared())
		require.NoError(t, err)
		start := dispatcher.nextStart(t)

		journalPath := filepath.Join(t.TempDir(), "timeout-interrupted.db")
		journal, err := commandjournal.Open(journalPath)
		require.NoError(t, err)
		prepared, err := journal.Prepare(ctx, envelope, time.Now().UTC())
		require.NoError(t, err)
		require.True(t, prepared)
		require.NoError(t, journal.AuthorizeStart(ctx, start.GetCommandId(), start.GetExecutionToken(), start.GetLeaseRevision(), start.GetStartDeadline().AsTime()))
		require.NoError(t, journal.Close())
		journal, err = commandjournal.Open(journalPath)
		require.NoError(t, err)
		t.Cleanup(func() { _ = journal.Close() })

		timeoutAt := time.Now().UTC().Add(10 * time.Second)
		claims, err := environment.repository.ClaimExpiredExecution(ctx, 1, timeoutAt)
		require.NoError(t, err)
		require.Len(t, claims, 1)
		require.NoError(t, environment.repository.FinalizeExpiredExecution(ctx, claims[0], timeoutAt.Add(time.Millisecond)))
		_, err = lifecycle.DispatchPending(ctx, timeoutAt.Add(2*time.Millisecond))
		require.NoError(t, err)

		registry := agentcontrol.NewRegistry(16)
		_, streamOpener := startCommandControlServer(t, registry, lifecycle)
		executor := &countingCommandExecutor{}
		executors := agent.NewExecutorRegistry()
		require.NoError(t, executors.Register(agent.CommandKindCollectNow, executor))
		verifier, err := agent.NewCommandVerifier("agent-a", environment.publicKey, executors.Capabilities())
		require.NoError(t, err)
		client := startContractControlClient(t, ctx, streamOpener, journal, verifier, executors, 20*time.Millisecond)
		defer client.stop(t)

		require.Eventually(t, func() bool {
			pending, pendingErr := journal.PendingResults(ctx)
			return pendingErr == nil && len(pending) == 0
		}, 3*time.Second, 20*time.Millisecond)
		require.Zero(t, executor.calls.Load())
		stored, err := environment.repository.LookupCommand(ctx, message.ID)
		require.NoError(t, err)
		require.Equal(t, job.CommandPhaseTimedOut, stored.Phase)
		require.Len(t, stored.TerminalResultDigest, sha256.Size)
		current, err := environment.repository.Get(ctx, scope, value.ID)
		require.NoError(t, err)
		require.Equal(t, job.StatusTimedOut, current.Status)
		require.Equal(t, job.TargetTimedOut, current.TargetResults[0].Status)
		var interruptedAudits int
		require.NoError(t, environment.database.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE command_id = $1 AND action = 'command.execution_interrupted'", message.ID).Scan(&interruptedAudits))
		require.Equal(t, 1, interruptedAudits)
		var timeoutAudits int
		require.NoError(t, environment.database.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE command_id = $1 AND action = 'command.execution_timed_out'", message.ID).Scan(&timeoutAudits))
		require.Equal(t, 1, timeoutAudits)

		conflictResult := contractResult(start, agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, "").GetCommandResult()
		conflict, err := lifecycle.Result(ctx, "agent-a", conflictResult)
		require.NoError(t, err)
		require.False(t, conflict.Persisted)
		require.Equal(t, "RESULT_CONFLICT", conflict.ReasonCode)
	})

	t.Run("control-plane crash before ResultAck replays the durable result", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		environment := newContractCommandEnvironment(t, ctx, dsn)
		firstRegistry := agentcontrol.NewRegistry(16)
		firstLifecycle := environment.newLifecycle(t, firstRegistry)
		crashObserver := newPersistBeforeAckObserver(firstLifecycle)
		stopFirstServer, firstOpener := startCommandControlServer(t, firstRegistry, crashObserver)
		executor := &countingCommandExecutor{}
		executors := agent.NewExecutorRegistry()
		require.NoError(t, executors.Register(agent.CommandKindCollectNow, executor))
		verifier, err := agent.NewCommandVerifier("agent-a", environment.publicKey, executors.Capabilities())
		require.NoError(t, err)
		journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "result-replay.db"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = journal.Close() })

		firstClient := startContractControlClient(t, ctx, firstOpener, journal, verifier, executors, 20*time.Millisecond)
		require.Eventually(t, func() bool { _, connected := firstRegistry.Session("agent-a"); return connected }, 3*time.Second, 10*time.Millisecond)
		scope := platformscope.Scope{TenantID: "tenant-result-replay", ProjectID: "project-result-replay"}
		created := time.Now().UTC().Truncate(time.Microsecond)
		value := contractJob("job-result-replay", scope, "agent-a", created)
		message := contractOutbox(t, value, "command-result-replay", "agent-a", created)
		require.NoError(t, environment.repository.CreateWithOutbox(ctx, value, []job.OutboxMessage{message}))
		dispatched, err := firstLifecycle.DispatchPending(ctx, created.Add(time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, 1, dispatched)
		crashObserver.waitPersisted(t)
		completed, err := environment.repository.Get(ctx, scope, value.ID)
		require.NoError(t, err)
		require.Equal(t, job.StatusSucceeded, completed.Status)
		stopFirstServer()
		firstClient.stop(t)
		pending, err := journal.PendingResults(ctx)
		require.NoError(t, err)
		require.Len(t, pending, 1, "a result without ResultAck must remain durable")

		secondRegistry := agentcontrol.NewRegistry(16)
		secondLifecycle := environment.newLifecycle(t, secondRegistry)
		_, secondOpener := startCommandControlServer(t, secondRegistry, secondLifecycle)
		secondClient := startContractControlClient(t, ctx, secondOpener, journal, verifier, executors, 20*time.Millisecond)
		defer secondClient.stop(t)
		require.Eventually(t, func() bool {
			remaining, pendingErr := journal.PendingResults(ctx)
			return pendingErr == nil && len(remaining) == 0
		}, 3*time.Second, 20*time.Millisecond)
		require.Equal(t, int32(1), executor.calls.Load())
		var auditCount int
		require.NoError(t, environment.database.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE command_id = $1 AND action = 'command.result'", message.ID).Scan(&auditCount))
		require.Equal(t, 1, auditCount, "replayed Result must reuse durable Audit evidence")
		secondClient.stop(t)
		require.NoError(t, journal.Close())
	})

	t.Run("running Agent restart reports interruption without re-execution", func(t *testing.T) {
		database := contractDatabase(t, dsn)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		require.NoError(t, job.RunMigrations(ctx, database))
		require.NoError(t, platformdb.RunMigrations(ctx, database))

		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer, err := job.NewEd25519CommandSigner(privateKey)
		require.NoError(t, err)
		tokenProtector, err := job.NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x61}, 32))
		require.NoError(t, err)
		repository := job.NewPostgresRepository(database)
		auditService := audit.NewService(audit.NewPostgresStore(database))
		dispatcher := newCapturedCommandDispatcher()
		lifecycle, err := job.NewCommandLifecycle(job.CommandLifecycleConfig{
			DispatchRepository: repository, Jobs: repository, Agents: dispatcher, Signer: signer,
			Audit: auditService, ClaimLimit: 8, TokenProtector: tokenProtector,
		})
		require.NoError(t, err)

		scope := platformscope.Scope{TenantID: "tenant-restart", ProjectID: "project-restart"}
		created := time.Now().UTC().Truncate(time.Microsecond)
		value := contractJob("job-agent-restart", scope, "agent-a", created)
		message := contractOutbox(t, value, "command-agent-restart", "agent-a", created)
		require.NoError(t, repository.CreateWithOutbox(ctx, value, []job.OutboxMessage{message}))
		dispatched, err := lifecycle.DispatchPending(ctx, created.Add(time.Millisecond))
		require.NoError(t, err)
		require.Equal(t, 1, dispatched)
		envelope := dispatcher.nextEnvelope(t)
		require.Equal(t, message.ID, envelope.GetCommandId())
		_, err = lifecycle.Prepared(ctx, "agent-a", contractPrepared(t, envelope).GetCommandPrepared())
		require.NoError(t, err)
		start := dispatcher.nextStart(t)

		journalPath := filepath.Join(t.TempDir(), "command-journal.db")
		journal, err := commandjournal.Open(journalPath)
		require.NoError(t, err)
		prepared, err := journal.Prepare(ctx, envelope, time.Now().UTC())
		require.NoError(t, err)
		require.True(t, prepared)
		require.NoError(t, journal.AuthorizeStart(ctx, start.GetCommandId(), start.GetExecutionToken(), start.GetLeaseRevision(), start.GetStartDeadline().AsTime()))
		require.NoError(t, journal.Close())
		journal, err = commandjournal.Open(journalPath)
		require.NoError(t, err)

		registry := agentcontrol.NewRegistry(16)
		stopServer, streamOpener := startCommandControlServer(t, registry, lifecycle)
		defer stopServer()
		executor := &countingCommandExecutor{}
		executors := agent.NewExecutorRegistry()
		require.NoError(t, executors.Register(agent.CommandKindCollectNow, executor))
		verifier, err := agent.NewCommandVerifier("agent-a", publicKey, executors.Capabilities())
		require.NoError(t, err)
		client, err := agent.NewControlClient(agent.ControlClientConfig{
			AgentID: "agent-a", AgentVersion: "e2e", StreamOpener: streamOpener, Journal: journal,
			Verifier: verifier, Executors: executors, HeartbeatInterval: 20 * time.Millisecond, ReconnectBackoff: 20 * time.Millisecond,
		})
		require.NoError(t, err)
		clientContext, stopClient := context.WithCancel(ctx)
		clientDone := make(chan error, 1)
		go func() { clientDone <- client.Run(clientContext) }()
		defer func() {
			stopClient()
			require.NoError(t, <-clientDone)
			require.NoError(t, journal.Close())
		}()

		require.Eventually(t, func() bool {
			current, getErr := repository.Get(ctx, scope, value.ID)
			return getErr == nil && current.Status == job.StatusTimedOut
		}, 3*time.Second, 20*time.Millisecond)
		current, err := repository.Get(ctx, scope, value.ID)
		require.NoError(t, err)
		require.Equal(t, job.TargetTimedOut, current.TargetResults[0].Status)
		require.Zero(t, executor.calls.Load(), "an interrupted running command must never execute again after Agent restart")
		pending, err := journal.PendingResults(ctx)
		require.NoError(t, err)
		require.Empty(t, pending, "the interrupted result remains pending until its durable ResultAck arrives")
		var auditCount int
		require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE command_id = $1 AND action = 'command.result'", message.ID).Scan(&auditCount))
		require.Equal(t, 1, auditCount)
	})

	t.Run("HTTP cancel retry reconciles Audit without repeating the transaction", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		database := contractDatabase(t, dsn)
		require.NoError(t, job.RunMigrations(ctx, database))
		require.NoError(t, platformdb.RunMigrations(ctx, database))
		repository := job.NewPostgresRepository(database)
		scope := platformscope.Scope{TenantID: "tenant-http-reconcile", ProjectID: "project-http-reconcile"}
		created := time.Now().UTC().Truncate(time.Microsecond)
		value := contractJob("job-http-reconcile", scope, "agent-a", created)
		require.NoError(t, repository.CreateWithOutbox(ctx, value, nil))
		realAudit := audit.NewService(audit.NewPostgresStore(database))
		failingAudit := &failOnceContractAudit{inner: realAudit, fail: true}
		services := controlplane.Services{
			Jobs: repository, Audit: failingAudit,
			Idempotency: idempotency.NewService(idempotency.NewPostgresStore(database)),
		}
		resolver := contractPrincipalResolver{principal: controlplane.Principal{
			Subject: "operator-http", Grants: map[string]map[string]struct{}{scope.Key(): {openapi.PermissionCancelJob: {}}},
		}}
		handler := controlplane.NewHTTPHandler(services, resolver)
		newRequest := func(requestID, traceID string) *http.Request {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+scope.TenantID+"/projects/"+scope.ProjectID+"/jobs/"+value.ID+"/actions/cancel", nil)
			request.Header.Set("If-Match", `"1"`)
			request.Header.Set("Idempotency-Key", "cancel-http-reconcile")
			request.Header.Set("X-Request-ID", requestID)
			request.Header.Set("traceparent", "00-"+traceID+"-2222222222222222-01")
			return request
		}
		first := httptest.NewRecorder()
		handler.ServeHTTP(first, newRequest("request-http-original", "11111111111111111111111111111111"))
		require.Equal(t, http.StatusInternalServerError, first.Code, first.Body.String())
		afterFirst, err := repository.Get(ctx, scope, value.ID)
		require.NoError(t, err)
		require.Equal(t, job.StatusCancelling, afterFirst.Status)
		require.Equal(t, int64(2), afterFirst.Version)

		retry := httptest.NewRecorder()
		handler.ServeHTTP(retry, newRequest("request-http-retry", "33333333333333333333333333333333"))
		require.Equal(t, http.StatusAccepted, retry.Code, retry.Body.String())
		afterRetry, err := repository.Get(ctx, scope, value.ID)
		require.NoError(t, err)
		require.Equal(t, int64(2), afterRetry.Version, "reconciliation must not request cancellation twice")
		var auditCount int
		var auditRequestID, auditTraceID string
		require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*), min(request_id), min(trace_id) FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND action = 'job.cancel_requested'", scope.TenantID, scope.ProjectID).Scan(&auditCount, &auditRequestID, &auditTraceID))
		require.Equal(t, 1, auditCount)
		require.Equal(t, "request-http-original", auditRequestID)
		require.Equal(t, "11111111111111111111111111111111", auditTraceID)
		var state string
		require.NoError(t, database.QueryRowContext(ctx, "SELECT state FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND idempotency_key = $3", scope.TenantID, scope.ProjectID, "cancel-http-reconcile").Scan(&state))
		require.Equal(t, string(idempotency.StateCompleted), state)
	})
}

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

func contractJob(id string, scope platformscope.Scope, agentID string, created time.Time) job.Job {
	return job.Job{
		ID: id, Type: "contract.collect", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone,
		TargetResourceIDs: []string{agentID}, InitiatedBy: "contract-test",
		SourceResource: job.ResourceReference{ResourceType: "contract_test", ResourceID: id},
		IdempotencyKey: id, Version: 1, Progress: job.Progress{TotalTargets: 1},
		Artifacts: []job.ArtifactReference{}, CreatedAt: created, RequestID: "request-" + id, TraceID: "trace-" + id,
	}
}

type contractCommandEnvironment struct {
	database       *sql.DB
	repository     *job.PostgresRepository
	audit          *audit.Service
	publicKey      ed25519.PublicKey
	signer         job.CommandSigner
	tokenProtector job.TokenProtector
}

func newContractCommandEnvironment(t *testing.T, ctx context.Context, dsn string) *contractCommandEnvironment {
	t.Helper()
	database := contractDatabase(t, dsn)
	require.NoError(t, job.RunMigrations(ctx, database))
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := job.NewEd25519CommandSigner(privateKey)
	require.NoError(t, err)
	tokenProtector, err := job.NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x63}, 32))
	require.NoError(t, err)
	return &contractCommandEnvironment{
		database: database, repository: job.NewPostgresRepository(database), audit: audit.NewService(audit.NewPostgresStore(database)),
		publicKey: publicKey, signer: signer, tokenProtector: tokenProtector,
	}
}

func (environment *contractCommandEnvironment) newLifecycle(t *testing.T, agents agentcontrol.Dispatcher) *job.CommandLifecycle {
	t.Helper()
	lifecycle, err := job.NewCommandLifecycle(job.CommandLifecycleConfig{
		DispatchRepository: environment.repository, Jobs: environment.repository, Agents: agents,
		Signer: environment.signer, Audit: environment.audit, ClaimLimit: 8, TokenProtector: environment.tokenProtector,
	})
	require.NoError(t, err)
	return lifecycle
}

type blockingPreparedObserver struct {
	*job.CommandLifecycle
	received    chan struct{}
	proceed     chan struct{}
	done        chan struct{}
	receivedOne sync.Once
	releaseOne  sync.Once
}

func newBlockingPreparedObserver(lifecycle *job.CommandLifecycle) *blockingPreparedObserver {
	return &blockingPreparedObserver{CommandLifecycle: lifecycle, received: make(chan struct{}), proceed: make(chan struct{}), done: make(chan struct{})}
}

func (observer *blockingPreparedObserver) Prepared(ctx context.Context, agentID string, prepared *agentv1.CommandPrepared) (*agentv1.CommandStart, error) {
	observer.receivedOne.Do(func() { close(observer.received) })
	select {
	case <-observer.proceed:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	start, err := observer.CommandLifecycle.Prepared(ctx, agentID, prepared)
	close(observer.done)
	return start, err
}

func (observer *blockingPreparedObserver) wait(t *testing.T) {
	t.Helper()
	select {
	case <-observer.received:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for durable Agent Prepare")
	}
}

func (observer *blockingPreparedObserver) release() {
	observer.releaseOne.Do(func() { close(observer.proceed) })
}

func (observer *blockingPreparedObserver) waitDone(t *testing.T) {
	t.Helper()
	select {
	case <-observer.done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for prepared transaction outcome")
	}
}

type startWinningExecutor struct {
	calls     atomic.Int32
	started   chan struct{}
	cancelled chan struct{}
	release   chan struct{}
	startOne  sync.Once
	cancelOne sync.Once
	finishOne sync.Once
}

func newStartWinningExecutor() *startWinningExecutor {
	return &startWinningExecutor{started: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{})}
}

func (executor *startWinningExecutor) Execute(ctx context.Context, _ *agentv1.CommandEnvelope, _ agent.ProgressReporter) (*agentv1.CommandResult, error) {
	executor.calls.Add(1)
	executor.startOne.Do(func() { close(executor.started) })
	<-ctx.Done()
	executor.cancelOne.Do(func() { close(executor.cancelled) })
	<-executor.release
	return &agentv1.CommandResult{State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "committed before cancellation"}, nil
}

func (executor *startWinningExecutor) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for executor Start")
	}
}

func (executor *startWinningExecutor) wasCancelled() bool {
	select {
	case <-executor.cancelled:
		return true
	default:
		return false
	}
}

func (executor *startWinningExecutor) finishSuccessfully() {
	executor.finishOne.Do(func() { close(executor.release) })
}

type blockingCommandExecutor struct {
	calls    atomic.Int32
	started  chan struct{}
	startOne sync.Once
}

func newBlockingCommandExecutor() *blockingCommandExecutor {
	return &blockingCommandExecutor{started: make(chan struct{})}
}

func (executor *blockingCommandExecutor) Execute(ctx context.Context, _ *agentv1.CommandEnvelope, _ agent.ProgressReporter) (*agentv1.CommandResult, error) {
	executor.calls.Add(1)
	executor.startOne.Do(func() { close(executor.started) })
	<-ctx.Done()
	return nil, ctx.Err()
}

func (executor *blockingCommandExecutor) waitStarted(t *testing.T) {
	t.Helper()
	select {
	case <-executor.started:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for executor Start")
	}
}

type contractControlClientHandle struct {
	cancel context.CancelFunc
	done   chan error
	once   sync.Once
}

func startContractControlClient(t *testing.T, parent context.Context, opener agent.StreamOpener, journal agent.CommandJournal, verifier *agent.CommandVerifier, executors *agent.ExecutorRegistry, heartbeat time.Duration) *contractControlClientHandle {
	t.Helper()
	client, err := agent.NewControlClient(agent.ControlClientConfig{
		AgentID: "agent-a", AgentVersion: "e2e", StreamOpener: opener, Journal: journal,
		Verifier: verifier, Executors: executors, HeartbeatInterval: heartbeat, ReconnectBackoff: 20 * time.Millisecond,
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(parent)
	handle := &contractControlClientHandle{cancel: cancel, done: make(chan error, 1)}
	go func() { handle.done <- client.Run(ctx) }()
	return handle
}

func (handle *contractControlClientHandle) stop(t *testing.T) {
	t.Helper()
	handle.once.Do(func() {
		handle.cancel()
		require.NoError(t, <-handle.done)
	})
}

func startContractAgent(t *testing.T, parent context.Context, opener agent.StreamOpener, publicKey ed25519.PublicKey, executor agent.CommandExecutor, heartbeat time.Duration) *commandjournal.BoltJournal {
	t.Helper()
	journal, err := commandjournal.Open(filepath.Join(t.TempDir(), "live-command-journal.db"))
	require.NoError(t, err)
	executors := agent.NewExecutorRegistry()
	require.NoError(t, executors.Register(agent.CommandKindCollectNow, executor))
	verifier, err := agent.NewCommandVerifier("agent-a", publicKey, executors.Capabilities())
	require.NoError(t, err)
	handle := startContractControlClient(t, parent, opener, journal, verifier, executors, heartbeat)
	t.Cleanup(func() {
		handle.stop(t)
		require.NoError(t, journal.Close())
	})
	return journal
}

type persistBeforeAckObserver struct {
	*job.CommandLifecycle
	persisted chan struct{}
	once      sync.Once
}

func newPersistBeforeAckObserver(lifecycle *job.CommandLifecycle) *persistBeforeAckObserver {
	return &persistBeforeAckObserver{CommandLifecycle: lifecycle, persisted: make(chan struct{})}
}

func (observer *persistBeforeAckObserver) Result(ctx context.Context, agentID string, result *agentv1.CommandResult) (agentcontrol.ResultPersistence, error) {
	outcome, err := observer.CommandLifecycle.Result(ctx, agentID, result)
	if err != nil {
		return outcome, err
	}
	observer.once.Do(func() { close(observer.persisted) })
	<-ctx.Done()
	return outcome, ctx.Err()
}

func (observer *persistBeforeAckObserver) waitPersisted(t *testing.T) {
	t.Helper()
	select {
	case <-observer.persisted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for durable result and Audit before simulated crash")
	}
}

type failOnceContractAudit struct {
	inner *audit.Service
	mu    sync.Mutex
	fail  bool
}

func (service *failOnceContractAudit) RecordOnce(ctx context.Context, event audit.Event) (audit.Event, error) {
	service.mu.Lock()
	fail := service.fail
	service.fail = false
	service.mu.Unlock()
	if fail {
		return audit.Event{}, errors.New("injected Audit outage")
	}
	return service.inner.RecordOnce(ctx, event)
}

func (service *failOnceContractAudit) List(ctx context.Context, scope platformscope.Scope, query audit.ListQuery) (audit.Page, error) {
	return service.inner.List(ctx, scope, query)
}

type contractPrincipalResolver struct{ principal controlplane.Principal }

func (resolver contractPrincipalResolver) ResolvePrincipal(*http.Request) (controlplane.Principal, error) {
	return resolver.principal, nil
}

type capturedCommandDispatcher struct {
	envelopes chan *agentv1.CommandEnvelope
	starts    chan *agentv1.CommandStart
}

func newCapturedCommandDispatcher() *capturedCommandDispatcher {
	return &capturedCommandDispatcher{envelopes: make(chan *agentv1.CommandEnvelope, 16), starts: make(chan *agentv1.CommandStart, 16)}
}

func (dispatcher *capturedCommandDispatcher) Dispatch(_ context.Context, _ string, envelope *agentv1.CommandEnvelope) error {
	dispatcher.envelopes <- proto.Clone(envelope).(*agentv1.CommandEnvelope)
	return nil
}

func (dispatcher *capturedCommandDispatcher) Start(_ context.Context, _ string, start *agentv1.CommandStart) error {
	dispatcher.starts <- proto.Clone(start).(*agentv1.CommandStart)
	return nil
}

func (dispatcher *capturedCommandDispatcher) ReplayStart(ctx context.Context, agentID string, start *agentv1.CommandStart) error {
	return dispatcher.Start(ctx, agentID, start)
}

func (*capturedCommandDispatcher) Cancel(context.Context, string, string) error { return nil }
func (*capturedCommandDispatcher) CancelPrepared(context.Context, string, string, string) error {
	return nil
}
func (*capturedCommandDispatcher) CancelExecution(context.Context, string, string, []byte, uint64, string) error {
	return nil
}

func (dispatcher *capturedCommandDispatcher) nextEnvelope(t *testing.T) *agentv1.CommandEnvelope {
	t.Helper()
	select {
	case envelope := <-dispatcher.envelopes:
		return envelope
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for captured command envelope")
		return nil
	}
}

func (dispatcher *capturedCommandDispatcher) nextStart(t *testing.T) *agentv1.CommandStart {
	t.Helper()
	select {
	case start := <-dispatcher.starts:
		return start
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for captured command Start")
		return nil
	}
}

type countingCommandExecutor struct{ calls atomic.Int32 }

func (executor *countingCommandExecutor) Execute(context.Context, *agentv1.CommandEnvelope, agent.ProgressReporter) (*agentv1.CommandResult, error) {
	executor.calls.Add(1)
	return &agentv1.CommandResult{State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "executed"}, nil
}

type e2eGRPCControlStream struct {
	grpc.BidiStreamingClient[agentv1.AgentMessage, agentv1.ServerMessage]
	connection *grpc.ClientConn
}

func (stream *e2eGRPCControlStream) CloseSend() error {
	streamErr := stream.BidiStreamingClient.CloseSend()
	connectionErr := stream.connection.Close()
	if streamErr != nil {
		return streamErr
	}
	return connectionErr
}

func startCommandControlServer(t *testing.T, registry *agentcontrol.Registry, observer agentcontrol.Observer) (func(), agent.StreamOpener) {
	t.Helper()
	serverTLS, clientTLS := commandControlTLS(t)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	agentv1.RegisterAgentControlServer(server, agentcontrol.NewServer(registry, observer))
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			server.Stop()
			_ = listener.Close()
			<-serveDone
		})
	}
	t.Cleanup(stop)
	opener := func(ctx context.Context) (agent.ControlStream, error) {
		connection, err := grpc.DialContext(
			ctx, "bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
			grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)), grpc.WithBlock(),
		)
		if err != nil {
			return nil, err
		}
		stream, err := agentv1.NewAgentControlClient(connection).Connect(ctx)
		if err != nil {
			_ = connection.Close()
			return nil, err
		}
		return &e2eGRPCControlStream{BidiStreamingClient: stream, connection: connection}, nil
	}
	return stop, opener
}

func commandControlTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "DBPilot command E2E CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	require.NoError(t, err)
	caCertificate, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	serverCertificate := commandControlCertificate(t, 102, "bufnet", []string{"bufnet"}, nil, caCertificate, caPrivate)
	clientCertificate := commandControlCertificate(t, 103, "agent-a", nil, []string{"spiffe://dbpilot.local/agent/agent-a"}, caCertificate, caPrivate)
	pool := x509.NewCertPool()
	pool.AddCert(caCertificate)
	return &tls.Config{
		Certificates: []tls.Certificate{serverCertificate}, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: pool, MinVersion: tls.VersionTLS12,
	}, &tls.Config{
		Certificates: []tls.Certificate{clientCertificate}, RootCAs: pool, ServerName: "bufnet", MinVersion: tls.VersionTLS12,
	}
}

func commandControlCertificate(t *testing.T, serial int64, commonName string, dnsNames, uriStrings []string, ca *x509.Certificate, caKey ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames,
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	for _, raw := range uriStrings {
		identity, err := url.Parse(raw)
		require.NoError(t, err)
		template.URIs = append(template.URIs, identity)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	require.NoError(t, err)
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	)
	require.NoError(t, err)
	return certificate
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
