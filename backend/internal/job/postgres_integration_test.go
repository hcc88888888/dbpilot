package job

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestTwoPhaseLegacyActiveUpgradeRepairsJobAndAuditWithoutReexecution(t *testing.T) {
	ctx, database := openUnmigratedJobIntegrationDatabase(t)
	resetJobIntegrationSchema(t, ctx, database)
	applyJobMigrationFiles(t, ctx, database, "0001_jobs_outbox.sql", "0002_command_payload_bytea.sql", "0003_prepared_command_envelope.sql", "0004_command_execution_recovery.sql")
	now := time.Now().UTC().Truncate(time.Millisecond)
	value, message := integrationPersistenceFixture("legacy-active", platformscope.Scope{TenantID: "tenant-legacy", ProjectID: "project-legacy"}, now.Add(-5*time.Minute))
	repository := NewPostgresRepository(database)
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	_, err := database.ExecContext(ctx, `UPDATE jobs SET status = 'running', version = 2, dispatched_at = $1, started_at = $1 WHERE id = $2`, now.Add(-4*time.Minute), value.ID)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `UPDATE job_targets SET status = 'running' WHERE job_id = $1 AND target_id = $2`, value.ID, message.TargetID)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `UPDATE command_outbox SET published_at = $1, command_status = 'active', acknowledged_at = $1, execution_deadline_at = $2, execution_last_heartbeat_at = $1 WHERE id = $3`, now.Add(-4*time.Minute), now.Add(time.Hour), message.ID)
	require.NoError(t, err)

	applyJobMigrationFiles(t, ctx, database, "0005_two_phase_execution.sql")
	upgradedAt := time.Now().UTC()
	stored, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandPhaseRunning, stored.Phase)
	require.Equal(t, uint64(1), stored.ExecutionRevision)
	require.Equal(t, uint64(1), stored.RecoveryRevision)
	require.NotNil(t, stored.ExecutionDeadline)
	require.False(t, stored.ExecutionDeadline.After(upgradedAt), "legacy active work must become immediately claimable")
	require.Len(t, stored.ExecutionTokenHash, sha256.Size)
	require.NotEmpty(t, stored.ExecutionTokenCiphertext)

	require.NoError(t, platformdb.RunMigrations(ctx, database))
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519CommandSigner(privateKey)
	require.NoError(t, err)
	protector, err := NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x65}, 32))
	require.NoError(t, err)
	auditService := audit.NewService(audit.NewPostgresStore(database))
	agents := &recordingCommandDispatcher{}
	lifecycle, err := NewCommandLifecycle(CommandLifecycleConfig{
		DispatchRepository: repository, Jobs: repository, Agents: agents, Signer: signer,
		Audit: auditService, TokenProtector: protector, ClaimLimit: 4,
	})
	require.NoError(t, err)
	_, err = lifecycle.DispatchPending(ctx, now.Add(time.Second))
	require.NoError(t, err)
	repaired, err := repository.Get(ctx, value.Scope, value.ID)
	require.NoError(t, err)
	require.Equal(t, StatusTimedOut, repaired.Status)
	require.Equal(t, TargetTimedOut, repaired.TargetResults[0].Status)
	stored, err = repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandPhaseTimedOut, stored.Phase)
	require.Empty(t, agents.starts, "legacy active work must never be replayed")
	var evidence int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE command_id = $1 AND action = 'command.execution_timed_out'`, message.ID).Scan(&evidence))
	require.Equal(t, 1, evidence)
}

func TestTwoPhasePreparedRecoveryReplaysOrphanFromPostgres(t *testing.T) {
	ctx, _, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	value, message := integrationPersistenceFixture("prepared-recovery", platformscope.Scope{TenantID: "tenant-recovery", ProjectID: "project-recovery"}, now.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519CommandSigner(privateKey)
	require.NoError(t, err)
	protector, err := NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x66}, 32))
	require.NoError(t, err)
	agents := &recordingCommandDispatcher{}
	lifecycle, err := NewCommandLifecycle(CommandLifecycleConfig{
		DispatchRepository: repository, Jobs: repository, Agents: agents, Signer: signer,
		Audit: &recordingAudit{}, TokenProtector: protector, ClaimLimit: 4, Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	_, err = lifecycle.DispatchPending(ctx, now)
	require.NoError(t, err)
	require.Len(t, agents.envelopes, 1)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(agents.envelopes[0])
	require.NoError(t, err)
	digest := sha256.Sum256(encoded)
	require.NoError(t, repository.MarkPrepared(ctx, value.Scope, message.ID, digest, now))

	_, err = lifecycle.DispatchPending(ctx, now.Add(time.Second))
	require.NoError(t, err)
	require.Len(t, agents.starts, 1)
	stored, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandPhaseStartAuthorized, stored.Phase)
	require.Equal(t, agents.starts[0].GetLeaseRevision(), stored.ExecutionRevision)
}

func openUnmigratedJobIntegrationDatabase(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	if os.Getenv("DBPILOT_JOB_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_JOB_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_JOB_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_JOB_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	require.NoError(t, database.PingContext(ctx))
	return ctx, database
}

func applyJobMigrationFiles(t *testing.T, ctx context.Context, database *sql.DB, names ...string) {
	t.Helper()
	_, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
	require.NoError(t, err)
	for _, name := range names {
		content, readErr := migrationFiles.ReadFile("migrations/" + name)
		require.NoError(t, readErr)
		body := strings.TrimSpace(string(content))
		body = strings.TrimSpace(strings.TrimPrefix(body, "BEGIN;"))
		body = strings.TrimSpace(strings.TrimSuffix(body, "COMMIT;"))
		_, err = database.ExecContext(ctx, body)
		require.NoError(t, err)
		_, err = database.ExecContext(ctx, "INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)", "job/migrations/"+name)
		require.NoError(t, err)
	}
}

func TestStartCancelRaceCancelCommitPreventsStart(t *testing.T) {
	ctx, database, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	value, message := integrationPersistenceFixture("cancel-wins", platformscope.Scope{TenantID: "tenant-race", ProjectID: "project-race"}, now.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	digest := sha256.Sum256([]byte("prepared-cancel-wins"))
	require.NoError(t, repository.MarkPrepared(ctx, value.Scope, message.ID, digest, now))

	cancelled, err := repository.RequestCancel(ctx, value.Scope, value.ID, "operator", value.Version, now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, StatusCancelling, cancelled.Status)
	token := sha256.Sum256([]byte("token-cancel-wins"))
	_, err = repository.AuthorizeStart(ctx, value.Scope, message.ID, digest, token, []byte("ciphertext-cancel-wins"), now.Add(2*time.Second), now.Add(time.Minute))
	require.ErrorIs(t, err, ErrConflict)

	stored, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.NotEqual(t, CommandPhaseStartAuthorized, stored.Phase)
	require.Empty(t, stored.ExecutionTokenHash)
	_ = database
}

func TestStartCancelRaceStartCommitPreservesExecutionFence(t *testing.T) {
	ctx, _, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Date(2026, 8, 28, 12, 10, 0, 0, time.UTC)
	value, message := integrationPersistenceFixture("start-wins", platformscope.Scope{TenantID: "tenant-race", ProjectID: "project-race"}, now.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	digest := sha256.Sum256([]byte("prepared-start-wins"))
	require.NoError(t, repository.MarkPrepared(ctx, value.Scope, message.ID, digest, now))
	token := sha256.Sum256([]byte("token-start-wins"))
	grant, err := repository.AuthorizeStart(ctx, value.Scope, message.ID, digest, token, []byte("ciphertext-start-wins"), now.Add(time.Second), now.Add(time.Minute))
	require.NoError(t, err)
	require.Equal(t, uint64(1), grant.ExecutionRevision)

	_, err = repository.RequestCancel(ctx, value.Scope, value.ID, "operator", value.Version, now.Add(2*time.Second))
	require.NoError(t, err)
	stored, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandPhaseCancelling, stored.Phase)
	require.Equal(t, token[:], stored.ExecutionTokenHash)
	require.Equal(t, grant.ExecutionRevision, stored.ExecutionRevision)
}

func TestStartCancelRaceConcurrentTransactionsHaveOneStartDecision(t *testing.T) {
	ctx, _, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Date(2026, 8, 28, 12, 15, 0, 0, time.UTC)
	value, message := integrationPersistenceFixture("concurrent-race", platformscope.Scope{TenantID: "tenant-race", ProjectID: "project-race"}, now.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	digest := sha256.Sum256([]byte("prepared-concurrent-race"))
	token := sha256.Sum256([]byte("token-concurrent-race"))
	require.NoError(t, repository.MarkPrepared(ctx, value.Scope, message.ID, digest, now))

	start := make(chan struct{})
	startResult := make(chan error, 1)
	cancelResult := make(chan error, 1)
	go func() {
		<-start
		_, err := repository.AuthorizeStart(ctx, value.Scope, message.ID, digest, token, []byte("ciphertext-concurrent-race"), now.Add(time.Second), now.Add(time.Minute))
		startResult <- err
	}()
	go func() {
		<-start
		_, err := repository.RequestCancel(ctx, value.Scope, value.ID, "operator", value.Version, now.Add(time.Second))
		cancelResult <- err
	}()
	close(start)
	startErr := <-startResult
	require.NoError(t, <-cancelResult)
	require.True(t, startErr == nil || errors.Is(startErr, ErrConflict), "Start must either commit before cancellation or lose its CAS: %v", startErr)

	stored, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	if startErr == nil {
		require.Equal(t, CommandPhaseCancelling, stored.Phase)
		require.Equal(t, token[:], stored.ExecutionTokenHash)
	} else {
		require.Equal(t, CommandPhasePrepared, stored.Phase)
		require.Empty(t, stored.ExecutionTokenHash)
	}
}

func TestStartCancelRaceStartEnqueueMarkerIsDiagnosticOnly(t *testing.T) {
	ctx, _, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Date(2026, 8, 28, 12, 17, 0, 0, time.UTC)
	value, message := integrationPersistenceFixture("enqueue-marker", platformscope.Scope{TenantID: "tenant-race", ProjectID: "project-race"}, now.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	digest := sha256.Sum256([]byte("prepared-enqueue-marker"))
	token := sha256.Sum256([]byte("token-enqueue-marker"))
	require.NoError(t, repository.MarkPrepared(ctx, value.Scope, message.ID, digest, now))
	grant, err := repository.AuthorizeStart(ctx, value.Scope, message.ID, digest, token, []byte("ciphertext-enqueue-marker"), now.Add(time.Second), now.Add(time.Minute))
	require.NoError(t, err)
	_, err = repository.RequestCancel(ctx, value.Scope, value.ID, "operator", value.Version, now.Add(2*time.Second))
	require.NoError(t, err)

	claimed, err := repository.ClaimPendingCancellations(ctx, 1, now.Add(3*time.Second))
	require.NoError(t, err)
	require.Len(t, claimed, 1, "recovery must not depend on diagnostic Start enqueue evidence")
	require.Nil(t, claimed[0].StartEnqueuedAt)
	require.Equal(t, CommandPhaseCancelling, claimed[0].Phase)
	require.Equal(t, []byte("ciphertext-enqueue-marker"), claimed[0].ExecutionTokenCiphertext)
	require.NoError(t, repository.MarkStartEnqueued(ctx, value.Scope, message.ID, grant.ExecutionRevision, now.Add(4*time.Second)))
	stored, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.StartEnqueuedAt)
}

func TestLeaseFenceHeartbeatInvalidatesTimeoutClaim(t *testing.T) {
	ctx, _, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Date(2026, 8, 28, 12, 20, 0, 0, time.UTC)
	value, message := integrationPersistenceFixture("lease-fence", platformscope.Scope{TenantID: "tenant-lease-fence", ProjectID: "project-lease-fence"}, now.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	digest := sha256.Sum256([]byte("prepared-lease-fence"))
	token := sha256.Sum256([]byte("token-lease-fence"))
	require.NoError(t, repository.MarkPrepared(ctx, value.Scope, message.ID, digest, now))
	grant, err := repository.AuthorizeStart(ctx, value.Scope, message.ID, digest, token, []byte("ciphertext-lease-fence"), now, now.Add(time.Second))
	require.NoError(t, err)
	dispatched, err := repository.Transition(ctx, Transition{Scope: value.Scope, JobID: value.ID, CurrentVersion: value.Version, To: StatusDispatched, At: now.Add(-time.Second)})
	require.NoError(t, err)
	running, err := repository.Transition(ctx, Transition{Scope: value.Scope, JobID: value.ID, CurrentVersion: dispatched.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: message.TargetID, Status: TargetRunning}}, At: now})
	require.NoError(t, err)

	claims, err := repository.ClaimExpiredExecution(ctx, 1, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Len(t, claims, 1)
	newRevision, err := repository.RenewExecutionLease(ctx, value.Scope, message.ID, token, grant.ExecutionRevision, now.Add(2*time.Second), now.Add(time.Minute))
	require.NoError(t, err)
	require.Greater(t, newRevision, claims[0].ClaimedRecoveryRevision)
	require.ErrorIs(t, repository.FinalizeExpiredExecution(ctx, claims[0], now.Add(3*time.Second)), ErrConflict)
	storedJob, err := repository.Get(ctx, value.Scope, value.ID)
	require.NoError(t, err)
	require.Equal(t, running.Version, storedJob.Version)
	require.Equal(t, StatusRunning, storedJob.Status)
	require.Equal(t, TargetRunning, storedJob.TargetResults[0].Status)
	storedCommand, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandPhaseRunning, storedCommand.Phase)
	require.False(t, storedCommand.TerminalAuditPending)
}

func TestResultFenceTerminalResultInvalidatesTimeoutClaimAndIsIdempotent(t *testing.T) {
	ctx, _, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Date(2026, 8, 28, 12, 30, 0, 0, time.UTC)
	value, message := integrationPersistenceFixture("result-fence", platformscope.Scope{TenantID: "tenant-result-fence", ProjectID: "project-result-fence"}, now.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	prepareDigest := sha256.Sum256([]byte("prepared-result-fence"))
	token := sha256.Sum256([]byte("token-result-fence"))
	require.NoError(t, repository.MarkPrepared(ctx, value.Scope, message.ID, prepareDigest, now))
	grant, err := repository.AuthorizeStart(ctx, value.Scope, message.ID, prepareDigest, token, []byte("ciphertext-result-fence"), now, now.Add(time.Second))
	require.NoError(t, err)
	claims, err := repository.ClaimExpiredExecution(ctx, 1, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Len(t, claims, 1)

	resultDigest := sha256.Sum256([]byte("result-succeeded"))
	input := TerminalResultCAS{Scope: value.Scope, CommandID: message.ID, TokenHash: token, ExpectedExecutionRevision: grant.ExecutionRevision, Status: CommandSucceeded, ResultDigest: resultDigest, At: now.Add(2 * time.Second)}
	outcome, err := repository.PersistTerminalResult(ctx, input)
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	require.False(t, outcome.Conflict)
	require.ErrorIs(t, repository.FinalizeExpiredExecution(ctx, claims[0], now.Add(3*time.Second)), ErrConflict)

	contradictoryDigest := sha256.Sum256([]byte("result-failed"))
	contradictory := input
	contradictory.Status = CommandFailed
	contradictory.ResultDigest = contradictoryDigest
	conflict, err := repository.PersistTerminalResult(ctx, contradictory)
	require.NoError(t, err)
	require.True(t, conflict.Conflict)
	require.False(t, conflict.Persisted)
	stored, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandSucceeded, stored.CommandStatus)
	require.Equal(t, resultDigest[:], stored.TerminalResultDigest)

	duplicate, err := repository.PersistTerminalResult(ctx, input)
	require.NoError(t, err)
	require.True(t, duplicate.Persisted)
	require.True(t, duplicate.Duplicate)
}

func TestResultFenceResultWinsBeforeAtomicTimeoutAndKeepsJobConsistent(t *testing.T) {
	ctx, _, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	value, message, grant, token := createExpiredStartedCommand(t, ctx, repository, "result-wins-timeout", now)
	claims, err := repository.ClaimExpiredExecution(ctx, 1, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Len(t, claims, 1)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519CommandSigner(privateKey)
	require.NoError(t, err)
	protector, err := NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x77}, 32))
	require.NoError(t, err)
	lifecycle, err := NewCommandLifecycle(CommandLifecycleConfig{
		DispatchRepository: repository, Jobs: repository, Agents: &recordingCommandDispatcher{}, Signer: signer,
		Audit: &recordingAudit{}, TokenProtector: protector, Now: func() time.Time { return now.Add(2 * time.Second) },
	})
	require.NoError(t, err)
	result := &agentv1.CommandResult{
		CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "completed",
		ExecutionToken: token[:], LeaseRevision: grant.ExecutionRevision,
	}
	outcome, err := lifecycle.Result(ctx, message.TargetID, result)
	require.NoError(t, err)
	require.True(t, outcome.Persisted)
	require.ErrorIs(t, repository.FinalizeExpiredExecution(ctx, claims[0], now.Add(3*time.Second)), ErrConflict)
	storedJob, err := repository.Get(ctx, value.Scope, value.ID)
	require.NoError(t, err)
	require.Equal(t, StatusSucceeded, storedJob.Status)
	require.Equal(t, TargetSucceeded, storedJob.TargetResults[0].Status)
	storedCommand, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandPhaseSucceeded, storedCommand.Phase)
	require.False(t, storedCommand.TerminalAuditPending)
}

func TestTimeoutFenceAtomicallyTerminalizesJobTargetAndCommand(t *testing.T) {
	ctx, database, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	value, message, _, _ := createExpiredStartedCommand(t, ctx, repository, "atomic-timeout", now)
	claims, err := repository.ClaimExpiredExecution(ctx, 1, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Len(t, claims, 1)

	require.NoError(t, repository.FinalizeExpiredExecution(ctx, claims[0], now.Add(3*time.Second)))
	storedJob, err := repository.Get(ctx, value.Scope, value.ID)
	require.NoError(t, err)
	require.Equal(t, StatusTimedOut, storedJob.Status)
	require.Equal(t, TargetTimedOut, storedJob.TargetResults[0].Status)
	storedCommand, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandPhaseTimedOut, storedCommand.Phase)
	var pending bool
	var dedupe string
	require.NoError(t, database.QueryRowContext(ctx, `SELECT terminal_audit_pending, terminal_audit_dedupe_key FROM command_outbox WHERE id = $1`, message.ID).Scan(&pending, &dedupe))
	require.True(t, pending)
	require.Equal(t, "command.execution_timed_out:"+message.ID, dedupe)
}

func TestTimeoutFenceCommandWriteFailureRollsBackJobAndTarget(t *testing.T) {
	ctx, database, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	value, message, _, _ := createExpiredStartedCommand(t, ctx, repository, "atomic-rollback", now)
	claims, err := repository.ClaimExpiredExecution(ctx, 1, now.Add(2*time.Second))
	require.NoError(t, err)
	require.Len(t, claims, 1)
	_, err = database.ExecContext(ctx, `
		CREATE FUNCTION fail_timeout_command_update() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.command_phase = 'timed_out' THEN RAISE EXCEPTION 'injected timeout command failure'; END IF;
			RETURN NEW;
		END $$;
		CREATE TRIGGER fail_timeout_command_update BEFORE UPDATE ON command_outbox
		FOR EACH ROW EXECUTE FUNCTION fail_timeout_command_update();
	`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = database.Exec(`DROP TRIGGER IF EXISTS fail_timeout_command_update ON command_outbox`)
		_, _ = database.Exec(`DROP FUNCTION IF EXISTS fail_timeout_command_update()`)
	})

	require.ErrorContains(t, repository.FinalizeExpiredExecution(ctx, claims[0], now.Add(3*time.Second)), "injected timeout command failure")
	storedJob, err := repository.Get(ctx, value.Scope, value.ID)
	require.NoError(t, err)
	require.Equal(t, StatusRunning, storedJob.Status)
	require.Equal(t, TargetRunning, storedJob.TargetResults[0].Status)
	storedCommand, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandPhaseStartAuthorized, storedCommand.Phase)
	require.NotEmpty(t, storedCommand.RecoveryClaimToken)
}

func TestTimeoutFenceAuditFailureRepairsAfterRestartWithoutJobMutation(t *testing.T) {
	ctx, _, repository := openTwoPhaseIntegrationRepository(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	value, message, _, _ := createExpiredStartedCommand(t, ctx, repository, "audit-repair", now)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519CommandSigner(privateKey)
	require.NoError(t, err)
	protector, err := NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x78}, 32))
	require.NoError(t, err)
	auditRecorder := &recordingAudit{onceErrors: []error{errors.New("audit unavailable"), nil}}
	agents := &recordingCommandDispatcher{}
	lifecycle, err := NewCommandLifecycle(CommandLifecycleConfig{
		DispatchRepository: repository, Jobs: repository, Agents: agents, Signer: signer,
		Audit: auditRecorder, TokenProtector: protector, ClaimLimit: 4, Now: func() time.Time { return now.Add(2 * time.Second) },
	})
	require.NoError(t, err)
	_, err = lifecycle.DispatchPending(ctx, now.Add(2*time.Second))
	require.ErrorContains(t, err, "audit unavailable")
	storedJob, err := repository.Get(ctx, value.Scope, value.ID)
	require.NoError(t, err)
	require.Equal(t, StatusTimedOut, storedJob.Status)
	version := storedJob.Version
	storedCommand, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.Equal(t, CommandPhaseTimedOut, storedCommand.Phase)
	require.True(t, storedCommand.TerminalAuditPending)
	require.Empty(t, auditRecorder.events)

	restarted, err := NewCommandLifecycle(CommandLifecycleConfig{
		DispatchRepository: repository, Jobs: repository, Agents: agents, Signer: signer,
		Audit: auditRecorder, TokenProtector: protector, ClaimLimit: 4, Now: func() time.Time { return now.Add(DefaultOutboxLease + 3*time.Second) },
	})
	require.NoError(t, err)
	_, err = restarted.DispatchPending(ctx, now.Add(DefaultOutboxLease+3*time.Second))
	require.NoError(t, err)
	repairedJob, err := repository.Get(ctx, value.Scope, value.ID)
	require.NoError(t, err)
	require.Equal(t, version, repairedJob.Version)
	repairedCommand, err := repository.LookupCommand(ctx, message.ID)
	require.NoError(t, err)
	require.False(t, repairedCommand.TerminalAuditPending)
	require.NotNil(t, repairedCommand.TerminalAuditRecordedAt)
	require.Len(t, auditRecorder.events, 1)
}

func TestTimeoutFenceConcurrentHeartbeatResultAndTimeoutStress(t *testing.T) {
	ctx, database, repository := openTwoPhaseIntegrationRepository(t)
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	auditService := audit.NewService(audit.NewPostgresStore(database))
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := NewEd25519CommandSigner(privateKey)
	require.NoError(t, err)
	protector, err := NewAES256GCMTokenProtector(bytes.Repeat([]byte{0x79}, 32))
	require.NoError(t, err)

	for iteration := 0; iteration < 20; iteration++ {
		now := time.Now().UTC().Add(time.Duration(iteration) * time.Minute).Truncate(time.Millisecond)
		suffix := fmt.Sprintf("timeout-stress-%02d", iteration)
		value, message, grant, token := createExpiredStartedCommand(t, ctx, repository, suffix, now)
		claims, err := repository.ClaimExpiredExecution(ctx, 1, now.Add(2*time.Second))
		require.NoError(t, err)
		require.Len(t, claims, 1)
		lifecycle, err := NewCommandLifecycle(CommandLifecycleConfig{
			DispatchRepository: repository, Jobs: repository, Agents: &recordingCommandDispatcher{}, Signer: signer,
			Audit: auditService, TokenProtector: protector, ClaimLimit: 4, Now: func() time.Time { return now.Add(3 * time.Second) },
		})
		require.NoError(t, err)
		start := make(chan struct{})
		errorsChannel := make(chan error, 3)
		var wait sync.WaitGroup
		wait.Add(3)
		go func() {
			defer wait.Done()
			<-start
			tokenHash := sha256.Sum256(token[:])
			_, renewErr := repository.RenewExecutionLease(ctx, value.Scope, message.ID, tokenHash, grant.ExecutionRevision, now.Add(3*time.Second), now.Add(time.Minute))
			if renewErr != nil && !errors.Is(renewErr, ErrConflict) {
				errorsChannel <- renewErr
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			_, resultErr := lifecycle.Result(ctx, message.TargetID, &agentv1.CommandResult{
				CommandId: message.ID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "stress result",
				ExecutionToken: token[:], LeaseRevision: grant.ExecutionRevision,
			})
			if resultErr != nil && !errors.Is(resultErr, ErrConflict) {
				errorsChannel <- resultErr
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			finalizeErr := repository.FinalizeExpiredExecution(ctx, claims[0], now.Add(3*time.Second))
			if finalizeErr != nil && !errors.Is(finalizeErr, ErrConflict) {
				errorsChannel <- finalizeErr
			}
		}()
		close(start)
		wait.Wait()
		close(errorsChannel)
		for raceErr := range errorsChannel {
			require.NoError(t, raceErr)
		}
		_, err = lifecycle.DispatchPending(ctx, now.Add(4*time.Second))
		require.NoError(t, err)
		storedJob, err := repository.Get(ctx, value.Scope, value.ID)
		require.NoError(t, err)
		storedCommand, err := repository.LookupCommand(ctx, message.ID)
		require.NoError(t, err)
		switch storedCommand.Phase {
		case CommandPhaseTimedOut:
			require.Equal(t, StatusTimedOut, storedJob.Status)
			require.Equal(t, TargetTimedOut, storedJob.TargetResults[0].Status)
		case CommandPhaseSucceeded:
			require.Equal(t, StatusSucceeded, storedJob.Status)
			require.Equal(t, TargetSucceeded, storedJob.TargetResults[0].Status)
		default:
			t.Fatalf("iteration %d left inconsistent command phase %q with Job %q", iteration, storedCommand.Phase, storedJob.Status)
		}
	}
}

func createExpiredStartedCommand(t *testing.T, ctx context.Context, repository *PostgresRepository, suffix string, now time.Time) (Job, OutboxMessage, StartGrant, [sha256.Size]byte) {
	t.Helper()
	value, message := integrationPersistenceFixture(suffix, platformscope.Scope{TenantID: "tenant-" + suffix, ProjectID: "project-" + suffix}, now.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	dispatched, err := repository.Transition(ctx, Transition{Scope: value.Scope, JobID: value.ID, CurrentVersion: value.Version, To: StatusDispatched, At: now.Add(-30 * time.Second)})
	require.NoError(t, err)
	running, err := repository.Transition(ctx, Transition{Scope: value.Scope, JobID: value.ID, CurrentVersion: dispatched.Version, To: StatusRunning, TargetResults: []TargetResult{{TargetID: message.TargetID, Status: TargetRunning}}, At: now.Add(-20 * time.Second)})
	require.NoError(t, err)
	value = running
	digest := sha256.Sum256([]byte("prepared-" + suffix))
	token := sha256.Sum256([]byte("token-" + suffix))
	tokenHash := sha256.Sum256(token[:])
	require.NoError(t, repository.MarkPrepared(ctx, value.Scope, message.ID, digest, now))
	grant, err := repository.AuthorizeStart(ctx, value.Scope, message.ID, digest, tokenHash, []byte("ciphertext-"+suffix), now, now.Add(time.Second))
	require.NoError(t, err)
	return value, message, grant, token
}

func openTwoPhaseIntegrationRepository(t *testing.T) (context.Context, *sql.DB, *PostgresRepository) {
	t.Helper()
	if os.Getenv("DBPILOT_JOB_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_JOB_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_JOB_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_JOB_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	require.NoError(t, database.PingContext(ctx))
	resetJobIntegrationSchema(t, ctx, database)
	require.NoError(t, RunMigrations(ctx, database))
	return ctx, database, NewPostgresRepository(database)
}

func TestPostgresIntegration(t *testing.T) {
	if os.Getenv("DBPILOT_JOB_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_JOB_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_JOB_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_JOB_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	require.NoError(t, database.PingContext(ctx))

	resetJobIntegrationSchema(t, ctx, database)
	require.NoError(t, RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	assertJobDDL(t, ctx, database)

	repository := NewPostgresRepository(database)
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	assertModuleRollbackIsAtomic(t, ctx, database, repository, now)
	claimed := assertConcurrentClaimsAreUnique(t, ctx, repository, now)
	assertScopedPublication(t, ctx, repository, claimed[0], now.Add(time.Second))
	for _, message := range claimed[1:] {
		require.NoError(t, repository.MarkOutboxPublished(ctx, message.Scope, message.ID, now.Add(time.Second)))
	}
	assertLeaseExpiryReclaims(t, ctx, repository, now.Add(2*time.Minute))
}

func resetJobIntegrationSchema(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	_, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "DROP TABLE IF EXISTS command_outbox, job_targets, jobs CASCADE")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "DELETE FROM dbpilot_schema_migrations WHERE name LIKE 'job/migrations/%'")
	require.NoError(t, err)
}

func assertJobDDL(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	var jobs, targets, outbox string
	require.NoError(t, database.QueryRowContext(ctx, "SELECT 'jobs'::regclass::text, 'job_targets'::regclass::text, 'command_outbox'::regclass::text").Scan(&jobs, &targets, &outbox))
	require.Equal(t, []string{"jobs", "job_targets", "command_outbox"}, []string{jobs, targets, outbox})
	var applied int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM dbpilot_schema_migrations WHERE name = $1", "job/migrations/0001_jobs_outbox.sql").Scan(&applied))
	require.Equal(t, 1, applied)
}

func assertModuleRollbackIsAtomic(t *testing.T, ctx context.Context, database *sql.DB, repository *PostgresRepository, at time.Time) {
	t.Helper()
	_, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS integration_business_resources (id TEXT PRIMARY KEY)")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "TRUNCATE integration_business_resources")
	require.NoError(t, err)

	value, message := integrationPersistenceFixture("rollback", platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, at.Add(-time.Minute))
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "INSERT INTO integration_business_resources (id) VALUES ($1)", "business-rollback")
	require.NoError(t, err)
	require.NoError(t, repository.CreateInTx(ctx, tx, value, []OutboxMessage{message}))
	require.NoError(t, tx.Rollback())

	var businessCount, jobCount, outboxCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM integration_business_resources WHERE id = $1", "business-rollback").Scan(&businessCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE id = $1", value.ID).Scan(&jobCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM command_outbox WHERE id = $1", message.ID).Scan(&outboxCount))
	require.Equal(t, []int{0, 0, 0}, []int{businessCount, jobCount, outboxCount})
}

func assertConcurrentClaimsAreUnique(t *testing.T, ctx context.Context, repository *PostgresRepository, at time.Time) []OutboxMessage {
	t.Helper()
	for index := 0; index < 4; index++ {
		scope := platformscope.Scope{TenantID: fmt.Sprintf("tenant-%d", index%2), ProjectID: fmt.Sprintf("project-%d", index%2)}
		value, message := integrationPersistenceFixture(fmt.Sprintf("claim-%d", index), scope, at.Add(-time.Duration(10-index)*time.Minute))
		require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	}

	start := make(chan struct{})
	results := make(chan []OutboxMessage, 2)
	errorsChannel := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			messages, err := repository.ClaimOutbox(ctx, 2, at)
			if err != nil {
				errorsChannel <- err
				return
			}
			results <- messages
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		require.NoError(t, err)
	}
	var claimed []OutboxMessage
	for messages := range results {
		claimed = append(claimed, messages...)
	}
	require.Len(t, claimed, 4)
	ids := make([]string, len(claimed))
	for index, message := range claimed {
		require.NoError(t, message.Scope.Validate())
		ids[index] = message.ID
	}
	sort.Strings(ids)
	require.Equal(t, []string{"message-claim-0", "message-claim-1", "message-claim-2", "message-claim-3"}, ids)
	return claimed
}

func assertScopedPublication(t *testing.T, ctx context.Context, repository *PostgresRepository, message OutboxMessage, at time.Time) {
	t.Helper()
	wrongScope := platformscope.Scope{TenantID: message.Scope.TenantID + "-wrong", ProjectID: message.Scope.ProjectID}
	require.ErrorIs(t, repository.MarkOutboxPublished(ctx, wrongScope, message.ID, at), ErrNotFound)
	var published sql.NullTime
	require.NoError(t, repository.db.QueryRowContext(ctx, "SELECT published_at FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND id = $3", message.Scope.TenantID, message.Scope.ProjectID, message.ID).Scan(&published))
	require.False(t, published.Valid)
	require.NoError(t, repository.MarkOutboxPublished(ctx, message.Scope, message.ID, at))
}

func assertLeaseExpiryReclaims(t *testing.T, ctx context.Context, repository *PostgresRepository, at time.Time) {
	t.Helper()
	scope := platformscope.Scope{TenantID: "tenant-lease", ProjectID: "project-lease"}
	value, message := integrationPersistenceFixture("lease", scope, at.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))

	first, err := repository.ClaimOutbox(ctx, 1, at)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, message.ID, first[0].ID)
	second, err := repository.ClaimOutbox(ctx, 1, at.Add(time.Second))
	require.NoError(t, err)
	require.Empty(t, second)
	reclaimed, err := repository.ClaimOutbox(ctx, 1, at.Add(DefaultOutboxLease+time.Second))
	require.NoError(t, err)
	require.Len(t, reclaimed, 1)
	require.Equal(t, message.ID, reclaimed[0].ID)
	require.Equal(t, 2, reclaimed[0].Attempts)
	require.NoError(t, repository.MarkOutboxPublished(ctx, scope, message.ID, at.Add(DefaultOutboxLease+2*time.Second)))
}

func integrationPersistenceFixture(suffix string, scope platformscope.Scope, createdAt time.Time) (Job, OutboxMessage) {
	createdAt = createdAt.UTC()
	timeout := createdAt.Add(time.Hour)
	value := Job{
		ID: "job-" + suffix, Type: "integration.run", Scope: scope, Status: StatusQueued, Outcome: OutcomeNone,
		TargetResourceIDs: []string{"target-" + suffix}, InitiatedBy: "integration-test",
		SourceResource: ResourceReference{ResourceType: "integration", ResourceID: "resource-" + suffix},
		IdempotencyKey: "idempotency-" + suffix, Version: 1, Progress: Progress{TotalTargets: 1},
		Artifacts: []ArtifactReference{}, CreatedAt: createdAt, TimeoutAt: &timeout, RequestID: "request-" + suffix, TraceID: "trace-" + suffix,
	}
	payload, err := proto.Marshal(&agentv1.CommandEnvelope{AgentId: "target-" + suffix, LeaseSeconds: 30, Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"health"}}}})
	if err != nil {
		panic(err)
	}
	message := OutboxMessage{
		ID: "message-" + suffix, Scope: scope, JobID: value.ID, TargetID: value.TargetResourceIDs[0], Type: "agent.command",
		Payload: payload, AvailableAt: createdAt, CreatedAt: createdAt,
	}
	return value, message
}
