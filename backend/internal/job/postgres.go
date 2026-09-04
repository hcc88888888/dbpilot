package job

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/commandvalidation"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"google.golang.org/protobuf/proto"
)

const DefaultOutboxLease = 30 * time.Second
const DefaultCancellationRetry = 30 * time.Second

const terminalReconcileLease = 30 * time.Second
const terminalReconcileMaxAttempts = 8

const jobColumnsSQL = "id, tenant_id, project_id, job_type, status, outcome, instance_id, initiated_by, source_resource_type, source_resource_id, idempotency_key, version, total_targets, completed_targets, failed_targets, skipped_targets, error_summary, result_summary, artifacts, created_at, dispatched_at, started_at, finished_at, timeout_at, cancel_requested_by, cancel_requested_at, request_id, trace_id, max_concurrency, target_timeout_seconds"
const outboxColumnsSQL = "id, tenant_id, project_id, job_id, target_id, message_type, payload, prepared_envelope, available_at, created_at, lease_expires_at, published_at, attempts, command_status, acknowledged_at, execution_deadline_at, execution_last_heartbeat_at, recovery_lease_expires_at, cancellation_requested_at, cancellation_reason, cancellation_available_at, cancellation_lease_expires_at, cancellation_attempts, command_phase, prepare_digest, prepared_at, execution_token_hash, execution_token_ciphertext, execution_revision, recovery_revision, start_deadline_at, start_enqueued_at, recovery_claim_token, recovery_claimed_deadline, recovery_claimed_revision, terminal_result_digest, terminal_at, terminal_audit_pending, terminal_audit_dedupe_key, terminal_audit_action, terminal_audit_result, terminal_audit_detail, terminal_audit_lease_expires_at, terminal_audit_attempts, terminal_audit_recorded_at, terminal_target_status, terminal_target_error_summary, terminal_target_result_summary, terminal_target_artifacts, terminal_reconcile_pending"
const outboxColumnsAliasedSQL = "o.id, o.tenant_id, o.project_id, o.job_id, o.target_id, o.message_type, o.payload, o.prepared_envelope, o.available_at, o.created_at, o.lease_expires_at, o.published_at, o.attempts, o.command_status, o.acknowledged_at, o.execution_deadline_at, o.execution_last_heartbeat_at, o.recovery_lease_expires_at, o.cancellation_requested_at, o.cancellation_reason, o.cancellation_available_at, o.cancellation_lease_expires_at, o.cancellation_attempts, o.command_phase, o.prepare_digest, o.prepared_at, o.execution_token_hash, o.execution_token_ciphertext, o.execution_revision, o.recovery_revision, o.start_deadline_at, o.start_enqueued_at, o.recovery_claim_token, o.recovery_claimed_deadline, o.recovery_claimed_revision, o.terminal_result_digest, o.terminal_at, o.terminal_audit_pending, o.terminal_audit_dedupe_key, o.terminal_audit_action, o.terminal_audit_result, o.terminal_audit_detail, o.terminal_audit_lease_expires_at, o.terminal_audit_attempts, o.terminal_audit_recorded_at, o.terminal_target_status, o.terminal_target_error_summary, o.terminal_target_result_summary, o.terminal_target_artifacts, o.terminal_reconcile_pending"
const insertJobSQL = "INSERT INTO jobs (" + jobColumnsSQL + ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)"
const insertTargetSQL = "INSERT INTO job_targets (tenant_id, project_id, job_id, target_id, status, error_summary, result_summary, artifacts, finished_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
const upsertTargetSQL = "INSERT INTO job_targets (tenant_id, project_id, job_id, target_id, status, error_summary, result_summary, artifacts, finished_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (tenant_id, project_id, job_id, target_id) DO UPDATE SET status = EXCLUDED.status, error_summary = EXCLUDED.error_summary, result_summary = EXCLUDED.result_summary, artifacts = EXCLUDED.artifacts, finished_at = EXCLUDED.finished_at"
const insertOutboxSQL = "INSERT INTO command_outbox (id, tenant_id, project_id, job_id, target_id, message_type, payload, prepared_envelope, available_at, created_at, lease_expires_at, published_at, attempts) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"
const selectJobSQL = "SELECT " + jobColumnsSQL + " FROM jobs WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
const selectJobForUpdateSQL = selectJobSQL + " FOR UPDATE"
const selectTargetsSQL = "SELECT target_id, status, error_summary, result_summary, artifacts, finished_at FROM job_targets WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 ORDER BY target_id"
const updateJobSQL = "UPDATE jobs SET status = $1, outcome = $2, version = $3, completed_targets = $4, failed_targets = $5, skipped_targets = $6, error_summary = $7, result_summary = $8, artifacts = $9, dispatched_at = $10, started_at = $11, finished_at = $12, cancel_requested_by = $13, cancel_requested_at = $14 WHERE tenant_id = $15 AND project_id = $16 AND id = $17 AND version = $18"
const claimOutboxSQL = "WITH candidates AS (SELECT id FROM command_outbox WHERE published_at IS NULL AND cancellation_requested_at IS NULL AND command_status = 'pending' AND available_at <= $1 AND (lease_expires_at IS NULL OR lease_expires_at <= $1) ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT $2), claimed AS (UPDATE command_outbox AS o SET lease_expires_at = $3, attempts = o.attempts + 1 FROM candidates AS c WHERE o.id = c.id RETURNING " + outboxColumnsAliasedSQL + ") SELECT " + outboxColumnsSQL + " FROM claimed ORDER BY created_at, id"
const claimPreparedCommandsSQL = "WITH candidates AS (SELECT id FROM command_outbox WHERE command_phase IN ('prepared', 'start_authorized') AND (lease_expires_at IS NULL OR lease_expires_at <= $1) ORDER BY prepared_at, created_at, id FOR UPDATE SKIP LOCKED LIMIT $2), claimed AS (UPDATE command_outbox AS o SET lease_expires_at = $3, attempts = o.attempts + 1 FROM candidates AS c WHERE o.id = c.id RETURNING " + outboxColumnsAliasedSQL + ") SELECT " + outboxColumnsSQL + " FROM claimed ORDER BY prepared_at, created_at, id"
const claimPendingTerminalAuditsSQL = "WITH candidates AS (SELECT id FROM command_outbox WHERE terminal_audit_pending AND (terminal_audit_lease_expires_at IS NULL OR terminal_audit_lease_expires_at <= $1) ORDER BY terminal_at, id FOR UPDATE SKIP LOCKED LIMIT $2), claimed AS (UPDATE command_outbox AS o SET terminal_audit_lease_expires_at = $3, terminal_audit_attempts = o.terminal_audit_attempts + 1 FROM candidates AS c WHERE o.id = c.id RETURNING " + outboxColumnsAliasedSQL + ") SELECT " + outboxColumnsSQL + " FROM claimed ORDER BY terminal_at, id"
const markOutboxPublishedSQL = "UPDATE command_outbox SET published_at = COALESCE(published_at, $1), lease_expires_at = NULL WHERE tenant_id = $2 AND project_id = $3 AND id = $4"
const selectOutboxByIDSQL = "SELECT " + outboxColumnsSQL + " FROM command_outbox WHERE id = $1"
const selectOperationOutboxSQL = "SELECT " + outboxColumnsSQL + " FROM command_outbox WHERE id = $1 AND tenant_id = $2 AND project_id = $3 AND job_id = $4"
const prepareCommandEnvelopeSQL = "UPDATE command_outbox SET prepared_envelope = COALESCE(prepared_envelope, $4), command_phase = CASE WHEN command_phase = 'pending' THEN 'preparing' ELSE command_phase END WHERE tenant_id = $1 AND project_id = $2 AND id = $3 AND cancellation_requested_at IS NULL AND command_phase IN ('pending', 'preparing') RETURNING prepared_envelope"
const requestCommandCancellationSQL = "UPDATE command_outbox SET cancellation_requested_at = COALESCE(cancellation_requested_at, $4), cancellation_reason = CASE WHEN cancellation_requested_at IS NULL THEN $5 ELSE cancellation_reason END, cancellation_available_at = COALESCE(cancellation_available_at, $4), lease_expires_at = NULL, command_phase = CASE WHEN command_phase IN ('start_authorized', 'running', 'cancelling') THEN 'cancelling' ELSE command_phase END WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 AND command_status IN ('pending', 'active')"
const claimCancellationSQL = "WITH candidates AS (SELECT id FROM command_outbox WHERE cancellation_requested_at IS NOT NULL AND command_phase IN ('pending', 'preparing', 'prepared', 'start_authorized', 'running', 'cancelling') AND cancellation_available_at <= $1 AND (cancellation_lease_expires_at IS NULL OR cancellation_lease_expires_at <= $1) ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT $2), claimed AS (UPDATE command_outbox AS o SET cancellation_lease_expires_at = $3, cancellation_attempts = o.cancellation_attempts + 1 FROM candidates AS c WHERE o.id = c.id RETURNING " + outboxColumnsAliasedSQL + ") SELECT " + outboxColumnsSQL + " FROM claimed ORDER BY created_at, id"
const deferCancellationSQL = "UPDATE command_outbox SET cancellation_available_at = $1, cancellation_lease_expires_at = NULL WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND cancellation_requested_at IS NOT NULL AND command_status IN ('pending', 'active')"
const renewCommandLeaseSQL = "UPDATE command_outbox SET execution_last_heartbeat_at = $1, execution_deadline_at = $2, recovery_lease_expires_at = NULL WHERE tenant_id = $3 AND project_id = $4 AND id = $5 AND command_status = 'active'"
const claimExpiredCommandsSQL = "WITH candidates AS (SELECT id FROM command_outbox WHERE published_at IS NOT NULL AND command_status IN ('pending', 'active') AND execution_deadline_at IS NOT NULL AND execution_deadline_at <= $1 AND (recovery_lease_expires_at IS NULL OR recovery_lease_expires_at <= $1) ORDER BY execution_deadline_at, id FOR UPDATE SKIP LOCKED LIMIT $2), claimed AS (UPDATE command_outbox AS o SET recovery_lease_expires_at = $3 FROM candidates AS c WHERE o.id = c.id RETURNING " + outboxColumnsAliasedSQL + ") SELECT " + outboxColumnsSQL + " FROM claimed ORDER BY execution_deadline_at, id"
const markCommandTerminalSQL = "UPDATE command_outbox SET command_status = $1, command_phase = $1, terminal_at = COALESCE(terminal_at, $2), published_at = COALESCE(published_at, $2), lease_expires_at = NULL, execution_deadline_at = NULL, recovery_lease_expires_at = NULL, recovery_claim_token = NULL, recovery_claimed_deadline = NULL, recovery_claimed_revision = NULL, cancellation_lease_expires_at = NULL WHERE tenant_id = $3 AND project_id = $4 AND id = $5 AND (command_status IN ('pending', 'active', 'rejected') OR command_status = $1)"
const pendingCancellationsForAgentSQL = "SELECT " + outboxColumnsSQL + " FROM command_outbox WHERE target_id = $1 AND cancellation_requested_at IS NOT NULL AND command_phase IN ('pending', 'preparing', 'prepared', 'start_authorized', 'running', 'cancelling') ORDER BY created_at, id LIMIT $2"
const preparedCommandsForAgentSQL = "SELECT " + outboxColumnsSQL + " FROM command_outbox WHERE target_id = $1 AND command_phase IN ('prepared', 'start_authorized') ORDER BY prepared_at, created_at, id LIMIT $2"
const pendingTerminalAuditsForAgentSQL = "SELECT " + outboxColumnsSQL + " FROM command_outbox WHERE target_id = $1 AND terminal_audit_pending ORDER BY terminal_at, id LIMIT $2"
const markTerminalAuditRecordedSQL = "UPDATE command_outbox SET terminal_audit_pending = FALSE, terminal_audit_lease_expires_at = NULL, terminal_audit_recorded_at = COALESCE(terminal_audit_recorded_at, $1) WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND terminal_audit_dedupe_key = $5"
const insertCancellationSnapshotSQL = "INSERT INTO job_cancellation_snapshots (tenant_id, project_id, job_id, actor, operation_id, idempotency_key, request_fingerprint, owner_token, if_match, current_version, job_snapshot, audit_event_json, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"
const selectCancellationSnapshotSQL = "SELECT actor, operation_id, idempotency_key, request_fingerprint, owner_token, if_match, current_version, job_snapshot, audit_event_json, created_at FROM job_cancellation_snapshots WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 AND actor = $4 AND operation_id = $5 AND idempotency_key = $6 AND request_fingerprint = $7 AND if_match = $8"
const findCancellationSnapshotSQL = "SELECT job_id, actor, operation_id, idempotency_key, request_fingerprint, owner_token, if_match, current_version, job_snapshot, audit_event_json, created_at FROM job_cancellation_snapshots WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 AND actor = $4 AND operation_id = $5 AND idempotency_key = $6 AND request_fingerprint = $7"

var cancellationFingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var cancellationOwnerPattern = regexp.MustCompile(`^owner-[0-9a-f]{64}$`)

type PostgresRepository struct {
	db               *sql.DB
	targetAuthorizer commandvalidation.TargetAuthorizer
}

func NewPostgresRepository(database *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: database}
}

func NewPostgresRepositoryWithTargetAuthorizer(database *sql.DB, authorizer commandvalidation.TargetAuthorizer) *PostgresRepository {
	return &PostgresRepository{db: database, targetAuthorizer: authorizer}
}

func (repository *PostgresRepository) CreateWithOutbox(ctx context.Context, value Job, messages []OutboxMessage) error {
	if repository == nil || repository.db == nil {
		return errors.New("job PostgreSQL repository is unavailable")
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin job transaction: %w", err)
	}
	if err := repository.CreateInTx(ctx, tx, value, messages); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit job transaction: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) CreateInTx(ctx context.Context, tx *sql.Tx, value Job, messages []OutboxMessage) error {
	if tx == nil {
		return errors.New("job transaction is required")
	}
	value = normalizeJobUTC(value)
	if err := validateNewJob(value); err != nil {
		return err
	}
	normalizedMessages := make([]OutboxMessage, len(messages))
	for index, message := range messages {
		message = normalizeOutboxMessage(value, message)
		if err := validateOutboxMessage(ctx, value, message, repository.targetAuthorizer); err != nil {
			return err
		}
		normalizedMessages[index] = message
	}
	artifactJSON, err := json.Marshal(value.Artifacts)
	if err != nil {
		return fmt.Errorf("marshal job artifacts: %w", err)
	}
	if value.Artifacts == nil {
		artifactJSON = []byte("[]")
	}
	if _, err := tx.ExecContext(ctx, insertJobSQL, jobInsertArgs(value, artifactJSON)...); err != nil {
		return classifyWriteError("insert job", err)
	}
	for _, target := range initialTargets(value) {
		artifactJSON, marshalErr := json.Marshal(target.Artifacts)
		if marshalErr != nil {
			return fmt.Errorf("marshal target artifacts: %w", marshalErr)
		}
		if target.Artifacts == nil {
			artifactJSON = []byte("[]")
		}
		if _, err := tx.ExecContext(ctx, insertTargetSQL, targetArgs(value.Scope, value.ID, target, artifactJSON)...); err != nil {
			return classifyWriteError("insert job target", err)
		}
	}
	for _, message := range normalizedMessages {
		if _, err := tx.ExecContext(ctx, insertOutboxSQL, outboxInsertArgs(message)...); err != nil {
			return classifyWriteError("insert outbox message", err)
		}
	}
	return nil
}

func (repository *PostgresRepository) Get(ctx context.Context, scope platformscope.Scope, id string) (Job, error) {
	if repository == nil || repository.db == nil {
		return Job{}, errors.New("job PostgreSQL repository is unavailable")
	}
	if err := scope.Validate(); err != nil {
		return Job{}, err
	}
	if strings.TrimSpace(id) == "" {
		return Job{}, ErrNotFound
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Job{}, fmt.Errorf("begin job snapshot: %w", err)
	}
	rollback := func(cause error) (Job, error) {
		_ = tx.Rollback()
		return Job{}, cause
	}
	value, err := scanJob(tx.QueryRowContext(ctx, selectJobSQL, scope.TenantID, scope.ProjectID, id))
	if err != nil {
		return rollback(classifyReadError("get job", err))
	}
	results, err := getTargetsFrom(ctx, tx, scope, id)
	if err != nil {
		return rollback(err)
	}
	value.TargetResults = results
	value.TargetResourceIDs = make([]string, len(results))
	for index := range results {
		value.TargetResourceIDs[index] = results[index].TargetID
	}
	value = normalizeJobUTC(value)
	if err := ValidateTargets(value); err != nil {
		return rollback(fmt.Errorf("validate persisted job targets: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return Job{}, fmt.Errorf("commit job snapshot: %w", err)
	}
	return value, nil
}

func (repository *PostgresRepository) GetOperation(ctx context.Context, scope platformscope.Scope, jobID, commandID string) (Job, OutboxMessage, error) {
	if repository == nil || repository.db == nil || scope.Validate() != nil || strings.TrimSpace(jobID) == "" || strings.TrimSpace(commandID) == "" {
		return Job{}, OutboxMessage{}, ErrNotFound
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return Job{}, OutboxMessage{}, fmt.Errorf("begin operation snapshot: %w", err)
	}
	rollback := func(cause error) (Job, OutboxMessage, error) {
		_ = tx.Rollback()
		return Job{}, OutboxMessage{}, cause
	}
	value, err := scanJob(tx.QueryRowContext(ctx, selectJobSQL, scope.TenantID, scope.ProjectID, jobID))
	if err != nil {
		return rollback(classifyReadError("get operation job", err))
	}
	results, err := getTargetsFrom(ctx, tx, scope, jobID)
	if err != nil {
		return rollback(err)
	}
	value.TargetResults = results
	value.TargetResourceIDs = make([]string, len(results))
	for index := range results {
		value.TargetResourceIDs[index] = results[index].TargetID
	}
	value = normalizeJobUTC(value)
	if err := ValidateTargets(value); err != nil {
		return rollback(fmt.Errorf("validate operation Job targets: %w", err))
	}
	var outboxCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3`, scope.TenantID, scope.ProjectID, jobID).Scan(&outboxCount); err != nil {
		return rollback(classifyReadError("count operation outbox", err))
	}
	if outboxCount != 1 {
		return rollback(ErrConflict)
	}
	message, err := scanOutbox(tx.QueryRowContext(ctx, selectOperationOutboxSQL, commandID, scope.TenantID, scope.ProjectID, jobID))
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrConflict)
	}
	if err != nil {
		return rollback(classifyReadError("get operation outbox", err))
	}
	if err := tx.Commit(); err != nil {
		return Job{}, OutboxMessage{}, fmt.Errorf("commit operation snapshot: %w", err)
	}
	return value, message, nil
}

func (repository *PostgresRepository) ReconcileTerminalCommands(ctx context.Context, limit int, at time.Time) (int, error) {
	if repository == nil || repository.db == nil || ctx == nil || limit < 1 || limit > 1024 || at.IsZero() {
		return 0, ErrInvalidCommandPayload
	}
	values, err := repository.claimTerminalCommands(ctx, limit, at.UTC())
	if err != nil {
		return 0, err
	}
	var reconcileErrors []error
	reconciled := 0
	for _, value := range values {
		if err := repository.reconcileTerminalCommand(ctx, value, at.UTC()); err != nil {
			releaseErr := repository.recordTerminalReconcileFailure(ctx, value, at.UTC(), err)
			reconcileErrors = append(reconcileErrors, errors.Join(fmt.Errorf("reconcile terminal command %q: %w", value.commandID, err), releaseErr))
			continue
		}
		reconciled++
	}
	return reconciled, errors.Join(reconcileErrors...)
}

type terminalReconcileClaim struct {
	scope            platformscope.Scope
	jobID, commandID string
	token            []byte
	leaseExpiresAt   time.Time
}

func (repository *PostgresRepository) claimTerminalCommands(ctx context.Context, limit int, at time.Time) ([]terminalReconcileClaim, error) {
	token := make([]byte, sha256.Size)
	if _, err := rand.Read(token); err != nil {
		return nil, fmt.Errorf("generate terminal reconciliation claim: %w", err)
	}
	rows, err := repository.db.QueryContext(ctx, `
		WITH candidates AS (
			SELECT outbox.id
			FROM command_outbox outbox
			JOIN jobs value ON value.tenant_id=outbox.tenant_id AND value.project_id=outbox.project_id AND value.id=outbox.job_id
			JOIN job_targets target ON target.tenant_id=outbox.tenant_id AND target.project_id=outbox.project_id AND target.job_id=outbox.job_id AND target.target_id=outbox.target_id
			WHERE outbox.command_status IN ('succeeded','failed','cancelled','timed_out','rejected')
			  AND outbox.terminal_reconcile_quarantined_at IS NULL
			  AND COALESCE(outbox.terminal_reconcile_available_at,outbox.terminal_at,outbox.created_at) <= $1
			  AND (outbox.terminal_reconcile_lease_expires_at IS NULL OR outbox.terminal_reconcile_lease_expires_at <= $1)
			  AND (outbox.terminal_reconcile_pending OR value.status NOT IN ('succeeded','failed','cancelled','timed_out') OR target.status NOT IN ('succeeded','failed','skipped','cancelled','timed_out'))
			ORDER BY COALESCE(outbox.terminal_reconcile_available_at,outbox.terminal_at,outbox.created_at),outbox.terminal_at,outbox.created_at,outbox.id
			FOR UPDATE OF outbox SKIP LOCKED
			LIMIT $2
		), claimed AS (
			UPDATE command_outbox outbox
			SET terminal_reconcile_lease_expires_at=$3,
			    terminal_reconcile_claim_token=$4,
			    terminal_reconcile_attempts=outbox.terminal_reconcile_attempts+1
			FROM candidates
			WHERE outbox.id=candidates.id
			RETURNING outbox.tenant_id,outbox.project_id,outbox.job_id,outbox.id,outbox.terminal_reconcile_lease_expires_at,
			          COALESCE(outbox.terminal_reconcile_available_at,outbox.terminal_at,outbox.created_at) AS claim_key
		)
		SELECT tenant_id,project_id,job_id,id,terminal_reconcile_lease_expires_at
		FROM claimed
		ORDER BY claim_key,id
	`, at.UTC(), limit, at.UTC().Add(terminalReconcileLease), token)
	if err != nil {
		return nil, classifyReadError("list terminal commands for reconciliation", err)
	}
	values := make([]terminalReconcileClaim, 0, limit)
	for rows.Next() {
		value := terminalReconcileClaim{token: append([]byte(nil), token...)}
		if err := rows.Scan(&value.scope.TenantID, &value.scope.ProjectID, &value.jobID, &value.commandID, &value.leaseExpiresAt); err != nil {
			_ = rows.Close()
			return nil, classifyReadError("scan terminal command reconciliation", err)
		}
		values = append(values, value)
	}
	if err := rows.Close(); err != nil {
		return nil, classifyReadError("close terminal command reconciliation", err)
	}
	return values, nil
}

func (repository *PostgresRepository) reconcileTerminalCommand(ctx context.Context, claim terminalReconcileClaim, at time.Time) error {
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		_ = tx.Rollback()
		return cause
	}
	current, err := scanJob(tx.QueryRowContext(ctx, selectJobForUpdateSQL, claim.scope.TenantID, claim.scope.ProjectID, claim.jobID))
	if err != nil {
		return rollback(classifyReadError("lock Job for terminal command reconciliation", err))
	}
	current.TargetResults, err = getTargetsFrom(ctx, tx, claim.scope, claim.jobID)
	if err != nil {
		return rollback(err)
	}
	current.TargetResourceIDs = make([]string, len(current.TargetResults))
	for index := range current.TargetResults {
		current.TargetResourceIDs[index] = current.TargetResults[index].TargetID
	}
	message, err := scanOutbox(tx.QueryRowContext(ctx, selectOperationOutboxSQL+` FOR UPDATE`, claim.commandID, claim.scope.TenantID, claim.scope.ProjectID, claim.jobID))
	if err != nil {
		return rollback(classifyReadError("lock terminal command for reconciliation", err))
	}
	var storedToken []byte
	var ownsLease bool
	if err := tx.QueryRowContext(ctx, `SELECT terminal_reconcile_claim_token,COALESCE(terminal_reconcile_lease_expires_at=$5,FALSE) FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND job_id=$4`, claim.scope.TenantID, claim.scope.ProjectID, claim.commandID, claim.jobID, claim.leaseExpiresAt).Scan(&storedToken, &ownsLease); err != nil {
		return rollback(classifyReadError("verify terminal reconciliation claim", err))
	}
	if len(claim.token) != sha256.Size || len(storedToken) != sha256.Size || subtle.ConstantTimeCompare(claim.token, storedToken) != 1 || !ownsLease {
		return rollback(ErrConflict)
	}
	if !terminalCommandStatus(message.CommandStatus) || message.TerminalAt == nil || !containsTarget(current.TargetResourceIDs, message.TargetID) {
		return rollback(ErrConflict)
	}
	target, hasDescriptor, err := terminalTargetFromOutbox(message)
	if err != nil {
		return rollback(err)
	}
	existing, found := targetFor(current.TargetResults, message.TargetID)
	if found && isTerminalTarget(existing.Status) {
		if existing.Status != target.Status || hasDescriptor && !matchingTerminalTarget(existing, target) {
			return rollback(ErrConflict)
		}
		target = existing
	} else if isTerminal(current.Status) {
		return rollback(ErrConflict)
	} else {
		if current.Status == StatusQueued {
			current, err = transitionInTx(ctx, tx, Transition{Scope: claim.scope, JobID: claim.jobID, CurrentVersion: current.Version, To: StatusDispatched, At: at})
			if err != nil {
				return rollback(err)
			}
		}
		to, actor := StatusRunning, ""
		if current.Status == StatusCancelling {
			to, actor = StatusCancelling, current.CancelRequestedBy
		}
		current, err = transitionInTx(ctx, tx, Transition{Scope: claim.scope, JobID: claim.jobID, CurrentVersion: current.Version, To: to, Actor: actor, TargetResults: []TargetResult{target}, At: at})
		if err != nil {
			return rollback(err)
		}
	}
	if allTargetsTerminal(current) && !isTerminal(current.Status) {
		terminalStatus := terminalJobStatus(current)
		current, err = transitionInTx(ctx, tx, Transition{Scope: claim.scope, JobID: claim.jobID, CurrentVersion: current.Version, To: terminalStatus, Artifacts: collectArtifacts(current.TargetResults), ResultSummary: "Agent commands completed", At: at})
		if err != nil {
			return rollback(err)
		}
	}
	if isTerminal(current.Status) && current.Status != terminalJobStatus(current) {
		return rollback(ErrConflict)
	}
	artifacts, err := json.Marshal(target.Artifacts)
	if err != nil {
		return rollback(ErrInvalidCommandPayload)
	}
	result, err := tx.ExecContext(ctx, `UPDATE command_outbox SET terminal_target_status=$1,terminal_target_error_summary=$2,terminal_target_result_summary=$3,terminal_target_artifacts=$4,terminal_reconcile_pending=FALSE,terminal_reconcile_available_at=NULL,terminal_reconcile_lease_expires_at=NULL,terminal_reconcile_claim_token=NULL,terminal_reconcile_quarantined_at=NULL,terminal_reconcile_quarantine_reason='' WHERE tenant_id=$5 AND project_id=$6 AND id=$7 AND job_id=$8 AND command_status=$9 AND terminal_reconcile_claim_token=$10 AND terminal_reconcile_lease_expires_at=$11`, string(target.Status), target.ErrorSummary, target.ResultSummary, artifacts, claim.scope.TenantID, claim.scope.ProjectID, claim.commandID, claim.jobID, string(message.CommandStatus), claim.token, claim.leaseExpiresAt)
	if err != nil {
		return rollback(classifyWriteError("complete terminal command reconciliation", err))
	}
	if updated, rowsErr := result.RowsAffected(); rowsErr != nil || updated != 1 {
		return rollback(ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit terminal command reconciliation: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) recordTerminalReconcileFailure(ctx context.Context, claim terminalReconcileClaim, at time.Time, cause error) error {
	reason := ""
	switch {
	case errors.Is(cause, ErrConflict):
		reason = "terminal_state_conflict"
	case errors.Is(cause, ErrInvalidCommandPayload), errors.Is(cause, ErrNotFound):
		reason = "invalid_terminal_state"
	}
	result, err := repository.db.ExecContext(ctx, `
		UPDATE command_outbox
		SET terminal_reconcile_lease_expires_at=NULL,
		    terminal_reconcile_claim_token=NULL,
		    terminal_reconcile_available_at=CASE
		        WHEN $1::text<>'' OR terminal_reconcile_attempts >= $2 THEN terminal_reconcile_available_at
		        ELSE $3::timestamptz + LEAST(terminal_reconcile_attempts,60) * INTERVAL '1 second'
		    END,
		    terminal_reconcile_quarantined_at=CASE
		        WHEN $1::text<>'' OR terminal_reconcile_attempts >= $2 THEN COALESCE(terminal_reconcile_quarantined_at,$3::timestamptz)
		        ELSE NULL
		    END,
		    terminal_reconcile_quarantine_reason=CASE
		        WHEN $1::text<>'' THEN $1::text
		        WHEN terminal_reconcile_attempts >= $2 THEN 'retry_exhausted'
		        ELSE ''
		    END
		WHERE tenant_id=$4 AND project_id=$5 AND id=$6
		  AND command_status IN ('succeeded','failed','cancelled','timed_out','rejected')
		  AND terminal_reconcile_claim_token=$7
		  AND terminal_reconcile_lease_expires_at=$8
	`, reason, terminalReconcileMaxAttempts, at, claim.scope.TenantID, claim.scope.ProjectID, claim.commandID, claim.token, claim.leaseExpiresAt)
	if err != nil {
		return classifyWriteError("record terminal reconciliation failure", err)
	}
	if updated, rowsErr := result.RowsAffected(); rowsErr != nil || updated != 1 {
		return ErrConflict
	}
	return nil
}

func terminalTargetFromOutbox(message OutboxMessage) (TargetResult, bool, error) {
	if !terminalCommandStatus(message.CommandStatus) || message.TerminalAt == nil {
		return TargetResult{}, false, ErrInvalidCommandPayload
	}
	target := TargetResult{TargetID: message.TargetID, Status: message.TerminalTargetStatus, ErrorSummary: message.TerminalTargetError, ResultSummary: message.TerminalTargetResult, Artifacts: append([]ArtifactReference(nil), message.TerminalTargetArtifacts...), FinishedAt: timePointer(message.TerminalAt.UTC())}
	hasDescriptor := target.Status != ""
	if !hasDescriptor {
		switch message.CommandStatus {
		case CommandSucceeded:
			target.Status, target.ResultSummary = TargetSucceeded, "Agent command succeeded"
		case CommandCancelled:
			target.Status, target.ResultSummary = TargetCancelled, "Agent command cancelled"
		case CommandTimedOut:
			target.Status, target.ErrorSummary, target.ResultSummary = TargetTimedOut, "command_timed_out", "Agent command failed"
		case CommandRejected:
			target.Status, target.ErrorSummary, target.ResultSummary = TargetFailed, "command_rejected", "Agent command failed"
		default:
			target.Status, target.ErrorSummary, target.ResultSummary = TargetFailed, "command_failed", "Agent command failed"
		}
	}
	if !isTerminalTarget(target.Status) || !terminalTargetMatchesCommand(target.Status, message.CommandStatus) {
		return TargetResult{}, false, ErrConflict
	}
	return target, hasDescriptor, nil
}

func terminalTargetMatchesCommand(target TargetStatus, command CommandStatus) bool {
	switch command {
	case CommandSucceeded:
		return target == TargetSucceeded
	case CommandCancelled:
		return target == TargetCancelled
	case CommandTimedOut:
		return target == TargetTimedOut
	case CommandFailed, CommandRejected:
		return target == TargetFailed
	default:
		return false
	}
}

func terminalJobStatus(value Job) Status {
	if value.Progress.CompletedTargets > 0 {
		return StatusSucceeded
	}
	if allTargetsCancelled(value.TargetResults) {
		return StatusCancelled
	}
	if hasTimedOutTarget(value.TargetResults) {
		return StatusTimedOut
	}
	return StatusFailed
}

// UpgradeOperationIdempotencyKey binds a verified legacy operation snapshot to
// a stronger key without allowing the Job or its sole Outbox payload to change
// between verification and the one-way update.
func (repository *PostgresRepository) UpgradeOperationIdempotencyKey(ctx context.Context, expected Job, expectedMessage OutboxMessage, currentKey string) (Job, OutboxMessage, error) {
	if repository == nil || repository.db == nil || ctx == nil || expected.Scope.Validate() != nil || strings.TrimSpace(expected.ID) == "" || strings.TrimSpace(expectedMessage.ID) == "" || expectedMessage.Scope != expected.Scope || expectedMessage.JobID != expected.ID || strings.TrimSpace(expected.IdempotencyKey) == "" || strings.TrimSpace(currentKey) == "" || currentKey == expected.IdempotencyKey || expected.Version < 1 {
		return Job{}, OutboxMessage{}, ErrConflict
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Job{}, OutboxMessage{}, fmt.Errorf("begin operation key upgrade: %w", err)
	}
	rollback := func(cause error) (Job, OutboxMessage, error) {
		_ = tx.Rollback()
		return Job{}, OutboxMessage{}, cause
	}
	value, err := scanJob(tx.QueryRowContext(ctx, selectJobForUpdateSQL, expected.Scope.TenantID, expected.Scope.ProjectID, expected.ID))
	if err != nil {
		return rollback(classifyReadError("lock operation Job for key upgrade", err))
	}
	results, err := getTargetsFrom(ctx, tx, expected.Scope, expected.ID)
	if err != nil {
		return rollback(err)
	}
	value.TargetResults = results
	value.TargetResourceIDs = make([]string, len(results))
	for index := range results {
		value.TargetResourceIDs[index] = results[index].TargetID
	}
	value = normalizeJobUTC(value)
	if err := ValidateTargets(value); err != nil {
		return rollback(fmt.Errorf("validate operation Job key upgrade targets: %w", err))
	}
	var outboxCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3`, expected.Scope.TenantID, expected.Scope.ProjectID, expected.ID).Scan(&outboxCount); err != nil {
		return rollback(classifyReadError("count operation key upgrade outbox", err))
	}
	if outboxCount != 1 {
		return rollback(ErrConflict)
	}
	message, err := scanOutbox(tx.QueryRowContext(ctx, selectOperationOutboxSQL+` FOR UPDATE`, expectedMessage.ID, expected.Scope.TenantID, expected.Scope.ProjectID, expected.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrConflict)
	}
	if err != nil {
		return rollback(classifyReadError("lock operation outbox for key upgrade", err))
	}
	if !sameOperationUpgradeSnapshot(value, message, expected, expectedMessage) || value.IdempotencyKey != expected.IdempotencyKey && value.IdempotencyKey != currentKey {
		return rollback(ErrConflict)
	}
	if value.IdempotencyKey == currentKey {
		if value.Version != expected.Version+1 {
			return rollback(ErrConflict)
		}
	} else {
		if value.Version != expected.Version {
			return rollback(ErrConflict)
		}
		result, updateErr := tx.ExecContext(ctx, `UPDATE jobs SET idempotency_key=$1,version=version+1 WHERE tenant_id=$2 AND project_id=$3 AND id=$4 AND idempotency_key=$5 AND version=$6`, currentKey, expected.Scope.TenantID, expected.Scope.ProjectID, expected.ID, expected.IdempotencyKey, expected.Version)
		if updateErr != nil {
			return rollback(classifyWriteError("upgrade operation idempotency key", updateErr))
		}
		if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
			return rollback(ErrConflict)
		}
		value.IdempotencyKey = currentKey
		value.Version++
	}
	if err := tx.Commit(); err != nil {
		return Job{}, OutboxMessage{}, fmt.Errorf("commit operation key upgrade: %w", err)
	}
	return value, message, nil
}

func sameOperationUpgradeSnapshot(value Job, message OutboxMessage, expected Job, expectedMessage OutboxMessage) bool {
	if value.ID != expected.ID || value.Type != expected.Type || value.Scope != expected.Scope || value.InstanceID != expected.InstanceID || value.InitiatedBy != expected.InitiatedBy || value.SourceResource != expected.SourceResource || value.RequestID != expected.RequestID || value.TraceID != expected.TraceID || !value.CreatedAt.Equal(expected.CreatedAt) || !sameTimePointer(value.TimeoutAt, expected.TimeoutAt) || value.MaxConcurrency != expected.MaxConcurrency || value.TargetTimeout != expected.TargetTimeout || len(value.TargetResourceIDs) != len(expected.TargetResourceIDs) {
		return false
	}
	for index := range value.TargetResourceIDs {
		if value.TargetResourceIDs[index] != expected.TargetResourceIDs[index] {
			return false
		}
	}
	return message.ID == expectedMessage.ID && message.Scope == expectedMessage.Scope && message.JobID == expectedMessage.JobID && message.TargetID == expectedMessage.TargetID && message.Type == expectedMessage.Type && bytes.Equal(message.Payload, expectedMessage.Payload) && message.AvailableAt.Equal(expectedMessage.AvailableAt) && message.CreatedAt.Equal(expectedMessage.CreatedAt)
}

func sameTimePointer(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func (repository *PostgresRepository) Transition(ctx context.Context, transition Transition) (Job, error) {
	if repository == nil || repository.db == nil {
		return Job{}, errors.New("job PostgreSQL repository is unavailable")
	}
	if err := transition.Scope.Validate(); err != nil {
		return Job{}, err
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, fmt.Errorf("begin job transition: %w", err)
	}
	next, err := transitionInTx(ctx, tx, transition)
	if err != nil {
		_ = tx.Rollback()
		return Job{}, err
	}
	if err := tx.Commit(); err != nil {
		return Job{}, fmt.Errorf("commit job transition: %w: %w", ErrAmbiguousCommit, err)
	}
	return next, nil
}

func transitionInTx(ctx context.Context, tx *sql.Tx, transition Transition) (Job, error) {
	current, err := scanJob(tx.QueryRowContext(ctx, selectJobForUpdateSQL, transition.Scope.TenantID, transition.Scope.ProjectID, transition.JobID))
	if err != nil {
		return Job{}, classifyReadError("get job for transition", err)
	}
	if transition.CurrentVersion == 0 {
		transition.CurrentVersion = current.Version
	}
	current.TargetResults, err = getTargetsFrom(ctx, tx, transition.Scope, transition.JobID)
	if err != nil {
		return Job{}, err
	}
	current.TargetResourceIDs = make([]string, len(current.TargetResults))
	for index := range current.TargetResults {
		current.TargetResourceIDs[index] = current.TargetResults[index].TargetID
	}
	next, err := ApplyTransition(current, transition)
	if err != nil {
		return Job{}, err
	}
	artifactJSON, err := json.Marshal(next.Artifacts)
	if err != nil {
		return Job{}, fmt.Errorf("marshal job artifacts: %w", err)
	}
	if next.Artifacts == nil {
		artifactJSON = []byte("[]")
	}
	result, err := tx.ExecContext(ctx, updateJobSQL, updateJobArgs(next, current.Version, artifactJSON)...)
	if err != nil {
		return Job{}, classifyWriteError("update job", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return Job{}, fmt.Errorf("read job update result: %w", err)
	}
	if updated != 1 {
		return Job{}, ErrConflict
	}
	for _, target := range transition.TargetResults {
		target = normalizeTargetResultsUTC([]TargetResult{target})[0]
		artifactJSON, marshalErr := json.Marshal(target.Artifacts)
		if marshalErr != nil {
			return Job{}, fmt.Errorf("marshal target artifacts: %w", marshalErr)
		}
		if target.Artifacts == nil {
			artifactJSON = []byte("[]")
		}
		if _, err := tx.ExecContext(ctx, upsertTargetSQL, targetArgs(next.Scope, next.ID, target, artifactJSON)...); err != nil {
			return Job{}, classifyWriteError("upsert job target", err)
		}
	}
	return next, nil
}

func (repository *PostgresRepository) RequestCancel(ctx context.Context, scope platformscope.Scope, id, actor string, currentVersion int64, at time.Time) (Job, error) {
	return repository.requestCancel(ctx, scope, id, actor, currentVersion, at, nil)
}

func (repository *PostgresRepository) RequestCancelWithSnapshot(ctx context.Context, scope platformscope.Scope, id, actor string, currentVersion int64, at time.Time, snapshot CancellationSnapshotInput) (Job, error) {
	if validateCancellationSnapshotInput(actor, currentVersion, snapshot) != nil {
		return Job{}, ErrInvalidTransition
	}
	return repository.requestCancel(ctx, scope, id, actor, currentVersion, at, &snapshot)
}

func (repository *PostgresRepository) requestCancel(ctx context.Context, scope platformscope.Scope, id, actor string, currentVersion int64, at time.Time, snapshot *CancellationSnapshotInput) (Job, error) {
	if repository == nil || repository.db == nil || scope.Validate() != nil || strings.TrimSpace(id) == "" || strings.TrimSpace(actor) == "" || currentVersion < 1 || at.IsZero() {
		return Job{}, ErrInvalidTransition
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, fmt.Errorf("begin job cancellation: %w", err)
	}
	next, err := transitionInTx(ctx, tx, Transition{Scope: scope, JobID: id, CurrentVersion: currentVersion, To: StatusCancelling, Actor: actor, At: at.UTC()})
	if err != nil {
		_ = tx.Rollback()
		return Job{}, err
	}
	if _, err := tx.ExecContext(ctx, requestCommandCancellationSQL, scope.TenantID, scope.ProjectID, id, at.UTC(), "job cancellation requested"); err != nil {
		_ = tx.Rollback()
		return Job{}, classifyWriteError("persist command cancellation intent", err)
	}
	if snapshot != nil {
		encodedJob, marshalErr := json.Marshal(next)
		if marshalErr != nil {
			_ = tx.Rollback()
			return Job{}, fmt.Errorf("marshal cancellation response snapshot: %w", marshalErr)
		}
		_, snapshotErr := tx.ExecContext(ctx, insertCancellationSnapshotSQL,
			scope.TenantID, scope.ProjectID, id, snapshot.Key.Actor, snapshot.Key.OperationID,
			snapshot.Key.IdempotencyKey, snapshot.Key.RequestFingerprint, snapshot.OwnerToken,
			snapshot.Key.IfMatch, currentVersion, encodedJob, snapshot.AuditEventJSON, at.UTC(),
		)
		if snapshotErr != nil {
			_ = tx.Rollback()
			return Job{}, classifyWriteError("persist cancellation response snapshot", snapshotErr)
		}
	}
	if err := tx.Commit(); err != nil {
		return Job{}, fmt.Errorf("commit job cancellation: %w: %w", ErrAmbiguousCommit, err)
	}
	return next, nil
}

func (repository *PostgresRepository) GetCancellationSnapshot(ctx context.Context, scope platformscope.Scope, jobID string, key CancellationSnapshotKey) (CancellationSnapshot, error) {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(jobID) == "" || validateCancellationSnapshotKey(key) != nil {
		return CancellationSnapshot{}, ErrNotFound
	}
	value := CancellationSnapshot{Scope: scope, JobID: jobID}
	var encodedJob []byte
	err := repository.db.QueryRowContext(ctx, selectCancellationSnapshotSQL,
		scope.TenantID, scope.ProjectID, jobID, key.Actor, key.OperationID,
		key.IdempotencyKey, key.RequestFingerprint, key.IfMatch,
	).Scan(
		&value.Key.Actor, &value.Key.OperationID, &value.Key.IdempotencyKey,
		&value.Key.RequestFingerprint, &value.OwnerToken, &value.Key.IfMatch,
		&value.CurrentVersion, &encodedJob, &value.AuditEventJSON, &value.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CancellationSnapshot{}, ErrNotFound
	}
	if err != nil {
		return CancellationSnapshot{}, fmt.Errorf("read cancellation response snapshot: %w", err)
	}
	if json.Unmarshal(encodedJob, &value.Job) != nil || value.Key != key || value.Job.Scope != scope || value.Job.ID != jobID || value.Job.Status != StatusCancelling || value.Job.Version != value.CurrentVersion+1 || value.Job.CancelRequestedBy != key.Actor || value.Job.CancelRequestedAt == nil || !cancellationOwnerPattern.MatchString(value.OwnerToken) || !json.Valid(value.AuditEventJSON) || value.CreatedAt.IsZero() || ValidateTargets(value.Job) != nil {
		return CancellationSnapshot{}, ErrInvalidTransition
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.AuditEventJSON = append([]byte(nil), value.AuditEventJSON...)
	return value, nil
}

func (repository *PostgresRepository) FindCancellationSnapshot(ctx context.Context, scope platformscope.Scope, jobID string, correlation CancellationSnapshotCorrelation) (CancellationSnapshot, error) {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(jobID) == "" || validateCancellationSnapshotCorrelation(correlation) != nil {
		return CancellationSnapshot{}, ErrNotFound
	}
	value := CancellationSnapshot{Scope: scope}
	var encodedJob []byte
	err := repository.db.QueryRowContext(ctx, findCancellationSnapshotSQL,
		scope.TenantID, scope.ProjectID, jobID, correlation.Actor, correlation.OperationID,
		correlation.IdempotencyKey, correlation.RequestFingerprint,
	).Scan(
		&value.JobID, &value.Key.Actor, &value.Key.OperationID, &value.Key.IdempotencyKey,
		&value.Key.RequestFingerprint, &value.OwnerToken, &value.Key.IfMatch,
		&value.CurrentVersion, &encodedJob, &value.AuditEventJSON, &value.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return CancellationSnapshot{}, ErrNotFound
	}
	if err != nil {
		return CancellationSnapshot{}, fmt.Errorf("find cancellation response snapshot: %w", err)
	}
	if value.JobID != jobID || value.Key.Actor != correlation.Actor || value.Key.OperationID != correlation.OperationID || value.Key.IdempotencyKey != correlation.IdempotencyKey || value.Key.RequestFingerprint != correlation.RequestFingerprint || json.Unmarshal(encodedJob, &value.Job) != nil || validateCancellationSnapshotKey(value.Key) != nil || value.Job.Scope != scope || value.Job.ID != jobID || value.Job.Status != StatusCancelling || value.Job.Version != value.CurrentVersion+1 || value.Job.CancelRequestedBy != correlation.Actor || value.Job.CancelRequestedAt == nil || !cancellationOwnerPattern.MatchString(value.OwnerToken) || !json.Valid(value.AuditEventJSON) || value.CreatedAt.IsZero() || ValidateTargets(value.Job) != nil {
		return CancellationSnapshot{}, ErrInvalidTransition
	}
	value.CreatedAt = value.CreatedAt.UTC()
	value.AuditEventJSON = append([]byte(nil), value.AuditEventJSON...)
	return value, nil
}

func validateCancellationSnapshotInput(actor string, currentVersion int64, input CancellationSnapshotInput) error {
	if input.Key.Actor != actor || input.OwnerToken == "" || !cancellationOwnerPattern.MatchString(input.OwnerToken) || !json.Valid(input.AuditEventJSON) || input.Key.IfMatch != fmt.Sprintf("\"%d\"", currentVersion) {
		return ErrInvalidTransition
	}
	return validateCancellationSnapshotKey(input.Key)
}

func validateCancellationSnapshotKey(key CancellationSnapshotKey) error {
	for _, value := range []string{key.Actor, key.OperationID, key.IdempotencyKey, key.IfMatch} {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\t") {
			return ErrInvalidTransition
		}
	}
	if !cancellationFingerprintPattern.MatchString(key.RequestFingerprint) {
		return ErrInvalidTransition
	}
	return nil
}

func validateCancellationSnapshotCorrelation(correlation CancellationSnapshotCorrelation) error {
	for _, value := range []string{correlation.Actor, correlation.OperationID, correlation.IdempotencyKey} {
		if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\r\n\t") {
			return ErrInvalidTransition
		}
	}
	if !cancellationFingerprintPattern.MatchString(correlation.RequestFingerprint) {
		return ErrInvalidTransition
	}
	return nil
}

func (repository *PostgresRepository) ClaimOutbox(ctx context.Context, limit int, at time.Time) ([]OutboxMessage, error) {
	if repository == nil || repository.db == nil {
		return nil, errors.New("job PostgreSQL repository is unavailable")
	}
	if limit <= 0 || at.IsZero() {
		return nil, errors.New("positive outbox claim limit and time are required")
	}
	at = at.UTC()
	rows, err := repository.db.QueryContext(ctx, claimOutboxSQL, at, limit, at.Add(DefaultOutboxLease))
	if err != nil {
		return nil, fmt.Errorf("claim outbox: %w", err)
	}
	defer rows.Close()
	messages := make([]OutboxMessage, 0, limit)
	for rows.Next() {
		message, scanErr := scanOutbox(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan claimed outbox: %w", scanErr)
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate claimed outbox: %w", err)
	}
	return messages, nil
}

// ReservePrepareSlot serializes prepare admission on the durable Job row. A
// command already in an active phase owns its prior reservation after restart;
// a pending command is admitted only when the persisted active-phase count is
// below the Job's configured maximum.
func (repository *PostgresRepository) ReservePrepareSlot(ctx context.Context, scope platformscope.Scope, commandID string, at time.Time) (bool, error) {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(commandID) == "" || at.IsZero() {
		return false, ErrInvalidCommandPayload
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin prepare slot reservation: %w", err)
	}
	rollback := func(cause error) (bool, error) { _ = tx.Rollback(); return false, cause }
	var jobID string
	var phase CommandPhase
	var cancellation sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT job_id, command_phase, cancellation_requested_at
		FROM command_outbox
		WHERE tenant_id = $1 AND project_id = $2 AND id = $3
		FOR UPDATE
	`, scope.TenantID, scope.ProjectID, commandID).Scan(&jobID, &phase, &cancellation)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrNotFound)
	}
	if err != nil {
		return rollback(fmt.Errorf("lock command for prepare slot: %w", err))
	}
	if cancellation.Valid {
		return rollback(ErrConflict)
	}
	var maxConcurrency sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT max_concurrency FROM jobs WHERE tenant_id = $1 AND project_id = $2 AND id = $3 FOR UPDATE`, scope.TenantID, scope.ProjectID, jobID).Scan(&maxConcurrency)
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrNotFound)
	}
	if err != nil {
		return rollback(fmt.Errorf("lock Job for prepare slot: %w", err))
	}
	if !maxConcurrency.Valid {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit unrestricted prepare slot: %w", err)
		}
		return true, nil
	}
	if maxConcurrency.Int64 < 1 || maxConcurrency.Int64 > 1000 {
		return rollback(ErrInvalidTransition)
	}
	if activePreparePhase(phase) {
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit resumed prepare slot: %w", err)
		}
		return true, nil
	}
	if phase != "" && phase != CommandPhasePending {
		return rollback(ErrConflict)
	}
	var active int
	err = tx.QueryRowContext(ctx, `
		SELECT count(*) FROM command_outbox
		WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3
			AND command_phase IN ('preparing', 'prepared', 'start_authorized', 'running', 'cancelling')
	`, scope.TenantID, scope.ProjectID, jobID).Scan(&active)
	if err != nil {
		return rollback(fmt.Errorf("count active prepare slots: %w", err))
	}
	if int64(active) >= maxConcurrency.Int64 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE command_outbox SET lease_expires_at = NULL, available_at = GREATEST(available_at, $1)
			WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND command_phase = 'pending'
		`, at.UTC().Add(time.Second), scope.TenantID, scope.ProjectID, commandID); err != nil {
			return rollback(fmt.Errorf("defer full prepare slot: %w", err))
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("commit full prepare slot deferral: %w", err)
		}
		return false, nil
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE command_outbox SET command_phase = 'preparing'
		WHERE tenant_id = $1 AND project_id = $2 AND id = $3 AND command_phase = 'pending' AND cancellation_requested_at IS NULL
	`, scope.TenantID, scope.ProjectID, commandID)
	if err != nil {
		return rollback(fmt.Errorf("reserve prepare slot: %w", err))
	}
	if !exactlyOneAffected(result) {
		return rollback(ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit prepare slot reservation: %w", err)
	}
	return true, nil
}

func activePreparePhase(phase CommandPhase) bool {
	return phase == CommandPhasePreparing || phase == CommandPhasePrepared || phase == CommandPhaseStartAuthorized || phase == CommandPhaseRunning || phase == CommandPhaseCancelling
}

func exactlyOneAffected(result sql.Result) bool {
	if result == nil {
		return false
	}
	rows, err := result.RowsAffected()
	return err == nil && rows == 1
}

func (repository *PostgresRepository) MarkOutboxPublished(ctx context.Context, scope platformscope.Scope, id string, at time.Time) error {
	if repository == nil || repository.db == nil {
		return errors.New("job PostgreSQL repository is unavailable")
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" || at.IsZero() {
		return ErrNotFound
	}
	result, err := repository.db.ExecContext(ctx, markOutboxPublishedSQL, at.UTC(), scope.TenantID, scope.ProjectID, id)
	if err != nil {
		return fmt.Errorf("mark outbox published: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read outbox publication result: %w", err)
	}
	if count != 1 {
		return ErrNotFound
	}
	return nil
}

func (repository *PostgresRepository) ClaimPendingCancellations(ctx context.Context, limit int, at time.Time) ([]OutboxMessage, error) {
	return repository.claimCommands(ctx, claimCancellationSQL, "claim pending cancellations", limit, at)
}

func (repository *PostgresRepository) ClaimPreparedCommands(ctx context.Context, limit int, at time.Time) ([]OutboxMessage, error) {
	return repository.claimCommands(ctx, claimPreparedCommandsSQL, "claim prepared commands", limit, at)
}

func (repository *PostgresRepository) ClaimPendingTerminalAudits(ctx context.Context, limit int, at time.Time) ([]OutboxMessage, error) {
	return repository.claimCommands(ctx, claimPendingTerminalAuditsSQL, "claim pending terminal Audits", limit, at)
}

func (repository *PostgresRepository) ClaimExpiredCommands(ctx context.Context, limit int, at time.Time) ([]OutboxMessage, error) {
	return repository.claimCommands(ctx, claimExpiredCommandsSQL, "claim expired commands", limit, at)
}

func (repository *PostgresRepository) claimCommands(ctx context.Context, query, operation string, limit int, at time.Time) ([]OutboxMessage, error) {
	if repository == nil || repository.db == nil {
		return nil, errors.New("job PostgreSQL repository is unavailable")
	}
	if ctx == nil || limit <= 0 || at.IsZero() {
		return nil, ErrInvalidCommandPayload
	}
	at = at.UTC()
	rows, err := repository.db.QueryContext(ctx, query, at, limit, at.Add(DefaultOutboxLease))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	defer rows.Close()
	result := make([]OutboxMessage, 0, limit)
	for rows.Next() {
		message, err := scanOutbox(rows)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", operation, err)
		}
		result = append(result, message)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s: %w", operation, err)
	}
	return result, nil
}

func (repository *PostgresRepository) DeferCancellation(ctx context.Context, scope platformscope.Scope, id string, availableAt time.Time) error {
	return repository.execScopedCommand(ctx, deferCancellationSQL, []any{availableAt.UTC(), scope.TenantID, scope.ProjectID, id})
}

func (repository *PostgresRepository) RenewCommandLease(ctx context.Context, scope platformscope.Scope, id string, at, deadline time.Time) error {
	if at.IsZero() || !deadline.After(at) {
		return ErrInvalidCommandPayload
	}
	return repository.execScopedCommand(ctx, renewCommandLeaseSQL, []any{at.UTC(), deadline.UTC(), scope.TenantID, scope.ProjectID, id})
}

func (repository *PostgresRepository) MarkCommandTerminal(ctx context.Context, scope platformscope.Scope, id string, status CommandStatus, at time.Time) error {
	if !terminalCommandStatus(status) || at.IsZero() {
		return ErrInvalidCommandPayload
	}
	return repository.execScopedCommand(ctx, markCommandTerminalSQL, []any{string(status), at.UTC(), scope.TenantID, scope.ProjectID, id})
}

func (repository *PostgresRepository) PersistTerminalCommand(ctx context.Context, input TerminalCommand) error {
	if repository == nil || repository.db == nil || ctx == nil || validateTerminalCommand(input) != nil {
		return ErrInvalidCommandPayload
	}
	artifacts, err := json.Marshal(input.Target.Artifacts)
	if err != nil {
		return ErrInvalidCommandPayload
	}
	detail, err := json.Marshal(input.Audit.Detail)
	if err != nil {
		return ErrInvalidCommandPayload
	}
	var jobID string
	if err := repository.db.QueryRowContext(ctx, `SELECT job_id FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, input.Scope.TenantID, input.Scope.ProjectID, input.CommandID).Scan(&jobID); err != nil {
		return classifyReadError("lookup terminal command Job", err)
	}
	tx, err := repository.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	rollback := func(cause error) error {
		_ = tx.Rollback()
		return cause
	}
	var lockedJobID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM jobs WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, input.Scope.TenantID, input.Scope.ProjectID, jobID).Scan(&lockedJobID); err != nil {
		return rollback(classifyReadError("lock terminal command Job", err))
	}
	message, err := scanOutbox(tx.QueryRowContext(ctx, `SELECT `+outboxColumnsSQL+` FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, input.Scope.TenantID, input.Scope.ProjectID, input.CommandID))
	if errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrNotFound)
	}
	if err != nil {
		return rollback(classifyReadError("lock terminal command", err))
	}
	if message.JobID != lockedJobID || message.TargetID != input.Target.TargetID {
		return rollback(ErrConflict)
	}
	if message.TerminalTargetStatus != "" && (message.TerminalTargetStatus != input.Target.Status || message.TerminalTargetError != input.Target.ErrorSummary || message.TerminalTargetResult != input.Target.ResultSummary || !artifactReferencesEqual(message.TerminalTargetArtifacts, input.Target.Artifacts)) {
		return rollback(ErrConflict)
	}
	if message.TerminalAuditDedupeKey != "" && (message.TerminalAuditDedupeKey != input.Audit.DedupeKey || message.TerminalAuditAction != input.Audit.Action || message.TerminalAuditResult != input.Audit.Result || !terminalAuditDetailsEqual(message.TerminalAuditDetail, input.Audit.Detail)) {
		return rollback(ErrConflict)
	}
	if terminalCommandStatus(message.CommandStatus) {
		if message.CommandStatus != input.Status {
			return rollback(ErrConflict)
		}
	} else if input.Status == CommandRejected {
		if message.CancellationRequestedAt != nil || message.Phase != "" && message.Phase != CommandPhasePending && message.Phase != CommandPhasePreparing && message.Phase != CommandPhasePrepared {
			return rollback(ErrConflict)
		}
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE command_outbox
		SET command_status=$1,command_phase=$1,terminal_at=COALESCE(terminal_at,$2),published_at=COALESCE(published_at,$2),
			acknowledged_at=CASE WHEN $1='rejected' THEN COALESCE(acknowledged_at,$2) ELSE acknowledged_at END,
			lease_expires_at=NULL,execution_deadline_at=NULL,recovery_lease_expires_at=NULL,
			recovery_claim_token=NULL,recovery_claimed_deadline=NULL,recovery_claimed_revision=NULL,cancellation_lease_expires_at=NULL,
			terminal_target_status=$3,terminal_target_error_summary=$4,terminal_target_result_summary=$5,terminal_target_artifacts=$6,
			terminal_reconcile_pending=TRUE,terminal_audit_pending=(terminal_audit_recorded_at IS NULL),
			terminal_audit_dedupe_key=$7,terminal_audit_action=$8,terminal_audit_result=$9,terminal_audit_detail=$10,
			terminal_audit_lease_expires_at=CASE WHEN terminal_audit_recorded_at IS NULL THEN NULL ELSE terminal_audit_lease_expires_at END
		WHERE tenant_id=$11 AND project_id=$12 AND id=$13
	`, string(input.Status), input.At.UTC(), string(input.Target.Status), input.Target.ErrorSummary, input.Target.ResultSummary, artifacts, input.Audit.DedupeKey, input.Audit.Action, input.Audit.Result, detail, input.Scope.TenantID, input.Scope.ProjectID, input.CommandID)
	if err != nil {
		return rollback(classifyWriteError("persist terminal command", err))
	}
	if updated, rowsErr := result.RowsAffected(); rowsErr != nil || updated != 1 {
		return rollback(ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit terminal command: %w: %w", ErrAmbiguousCommit, err)
	}
	return nil
}

func validateTerminalCommand(input TerminalCommand) error {
	if input.Scope.Validate() != nil || strings.TrimSpace(input.CommandID) == "" || !terminalCommandStatus(input.Status) || input.At.IsZero() || input.Target.TargetID == "" || !isTerminalTarget(input.Target.Status) || !terminalTargetMatchesCommand(input.Target.Status, input.Status) || strings.TrimSpace(input.Audit.DedupeKey) == "" || strings.TrimSpace(input.Audit.Action) == "" || input.Audit.Result != "success" && input.Audit.Result != "failure" {
		return ErrInvalidCommandPayload
	}
	for _, value := range []string{input.Target.ErrorSummary, input.Target.ResultSummary} {
		if len(value) > maximumInlineResultSummary || strings.ContainsAny(value, "\r\n\t") {
			return ErrInvalidCommandPayload
		}
	}
	for _, value := range []string{input.Audit.DedupeKey, input.Audit.Action} {
		if len(value) > 512 || strings.ContainsAny(value, "\r\n\t") {
			return ErrInvalidCommandPayload
		}
	}
	for _, artifact := range input.Target.Artifacts {
		if strings.TrimSpace(artifact.ArtifactID) == "" || strings.TrimSpace(artifact.Kind) == "" {
			return ErrInvalidCommandPayload
		}
	}
	return nil
}

func artifactReferencesEqual(left, right []ArtifactReference) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func terminalAuditDetailsEqual(left, right map[string]any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func CancelValidationInTx(ctx context.Context, tx *sql.Tx, scope platformscope.Scope, jobID, commandID, agentID string, at time.Time) error {
	if ctx == nil || tx == nil || scope.Validate() != nil || strings.TrimSpace(jobID) == "" || strings.TrimSpace(commandID) == "" || strings.TrimSpace(agentID) == "" || at.IsZero() {
		return ErrInvalidCommandPayload
	}
	var jobType string
	var status Status
	var totalTargets int
	if err := tx.QueryRowContext(ctx, `SELECT job_type,status,total_targets FROM jobs WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, scope.TenantID, scope.ProjectID, jobID).Scan(&jobType, &status, &totalTargets); err != nil {
		return classifyReadError("lock validation Job for retirement", err)
	}
	if jobType != "database_instance.validate" || totalTargets != 1 || isTerminal(status) {
		return ErrConflict
	}
	var targetID string
	if err := tx.QueryRowContext(ctx, `SELECT target_id FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3 AND id=$4 FOR UPDATE`, scope.TenantID, scope.ProjectID, jobID, commandID).Scan(&targetID); err != nil {
		return classifyReadError("lock validation command for retirement", err)
	}
	if targetID != agentID {
		return ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE job_targets SET status='cancelled',error_summary='',result_summary='database instance connection validation cancelled',artifacts='[]'::jsonb,finished_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND job_id=$4 AND target_id=$5`, at.UTC(), scope.TenantID, scope.ProjectID, jobID, agentID)
	if err != nil {
		return classifyWriteError("cancel validation target on retirement", err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return ErrConflict
	}
	result, err = tx.ExecContext(ctx, `UPDATE jobs SET status='cancelled',outcome='none',version=version+1,completed_targets=0,failed_targets=1,skipped_targets=0,error_summary='',result_summary='database instance connection validation cancelled',artifacts='[]'::jsonb,finished_at=$1,cancel_requested_by='instance-retire',cancel_requested_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND id=$4 AND status IN ('queued','dispatched','running','cancelling')`, at.UTC(), scope.TenantID, scope.ProjectID, jobID)
	if err != nil {
		return classifyWriteError("cancel validation Job on retirement", err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return ErrConflict
	}
	detail := `{"reason":"instance_retired"}`
	result, err = tx.ExecContext(ctx, `UPDATE command_outbox SET command_status='cancelled',command_phase='cancelled',terminal_at=$1,published_at=COALESCE(published_at,$1),lease_expires_at=NULL,execution_deadline_at=NULL,recovery_lease_expires_at=NULL,recovery_claim_token=NULL,recovery_claimed_deadline=NULL,recovery_claimed_revision=NULL,cancellation_lease_expires_at=NULL,terminal_audit_pending=TRUE,terminal_audit_dedupe_key=$2,terminal_audit_action='command.validation_cancelled_on_retire',terminal_audit_result='failure',terminal_audit_detail=$3::jsonb,terminal_audit_lease_expires_at=NULL,terminal_audit_attempts=0,terminal_audit_recorded_at=NULL,terminal_target_status='cancelled',terminal_target_error_summary='',terminal_target_result_summary='database instance connection validation cancelled',terminal_target_artifacts='[]'::jsonb,terminal_reconcile_pending=FALSE WHERE tenant_id=$4 AND project_id=$5 AND job_id=$6 AND id=$7 AND command_status IN ('pending','active','rejected')`, at.UTC(), "command.validation_cancelled_on_retire:"+commandID, detail, scope.TenantID, scope.ProjectID, jobID, commandID)
	if err != nil {
		return classifyWriteError("cancel validation command on retirement", err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return ErrConflict
	}
	return nil
}

func (repository *PostgresRepository) RepairValidationTerminal(ctx context.Context, scope platformscope.Scope, jobID, commandID, agentID string, target TargetResult, commandStatus CommandStatus, at time.Time) error {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(jobID) == "" || strings.TrimSpace(commandID) == "" || strings.TrimSpace(agentID) == "" || target.TargetID != agentID || !isTerminalTarget(target.Status) || !terminalCommandStatus(commandStatus) || at.IsZero() {
		return ErrInvalidCommandPayload
	}
	message, err := repository.LookupCommand(ctx, commandID)
	if err != nil {
		return err
	}
	if message.Scope != scope || message.JobID != jobID || message.TargetID != agentID {
		return ErrConflict
	}
	for attempt := 0; attempt < commandTransitionAttempts; attempt++ {
		current, err := repository.Get(ctx, scope, jobID)
		if err != nil {
			return err
		}
		if len(current.TargetResourceIDs) != 1 || current.TargetResourceIDs[0] != agentID {
			return ErrConflict
		}
		existing, found := targetFor(current.TargetResults, agentID)
		if found && isTerminalTarget(existing.Status) {
			if !matchingTerminalTarget(existing, target) {
				return ErrConflict
			}
			if isTerminal(current.Status) {
				if current.Status != terminalJobStatusForTarget(target.Status) {
					return ErrConflict
				}
				return repository.persistValidationRepairCommand(ctx, scope, commandID, target, commandStatus, at)
			}
			if current.Status != StatusRunning && current.Status != StatusCancelling {
				return ErrConflict
			}
			_, err = repository.Transition(ctx, Transition{Scope: scope, JobID: jobID, CurrentVersion: current.Version, To: terminalJobStatusForTarget(target.Status), ResultSummary: "Agent commands completed", At: at})
			if errors.Is(err, ErrConflict) {
				continue
			}
			if err != nil {
				return err
			}
			return repository.persistValidationRepairCommand(ctx, scope, commandID, target, commandStatus, at)
		}
		if isTerminal(current.Status) {
			if !found || !matchingTerminalTarget(existing, target) || current.Status != terminalJobStatusForTarget(target.Status) {
				return ErrConflict
			}
			return repository.persistValidationRepairCommand(ctx, scope, commandID, target, commandStatus, at)
		}
		if current.Status == StatusQueued {
			_, err = repository.Transition(ctx, Transition{Scope: scope, JobID: jobID, CurrentVersion: current.Version, To: StatusDispatched, At: at})
			if errors.Is(err, ErrConflict) {
				continue
			}
			if err != nil {
				return err
			}
			continue
		}
		transitionTo := StatusRunning
		actor := ""
		if current.Status == StatusCancelling {
			transitionTo = StatusCancelling
			actor = current.CancelRequestedBy
		}
		next, err := repository.Transition(ctx, Transition{Scope: scope, JobID: jobID, CurrentVersion: current.Version, To: transitionTo, TargetResults: []TargetResult{target}, Actor: actor, At: at})
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return err
		}
		_, err = repository.Transition(ctx, Transition{Scope: scope, JobID: jobID, CurrentVersion: next.Version, To: terminalJobStatusForTarget(target.Status), ResultSummary: "Agent commands completed", At: at})
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return err
		}
		return repository.persistValidationRepairCommand(ctx, scope, commandID, target, commandStatus, at)
	}
	return ErrConflict
}

func (repository *PostgresRepository) persistValidationRepairCommand(ctx context.Context, scope platformscope.Scope, commandID string, target TargetResult, status CommandStatus, at time.Time) error {
	stored, err := repository.LookupCommand(ctx, commandID)
	if err != nil {
		return err
	}
	if stored.Scope != scope {
		return ErrConflict
	}
	if terminalCommandStatus(stored.CommandStatus) {
		if stored.CommandStatus != status {
			return ErrConflict
		}
		if stored.TerminalTargetStatus != "" {
			if stored.TerminalTargetStatus != target.Status || stored.TerminalTargetError != target.ErrorSummary || stored.TerminalTargetResult != target.ResultSummary || !artifactReferencesEqual(stored.TerminalTargetArtifacts, target.Artifacts) {
				return ErrConflict
			}
			return nil
		}
	}
	state := agentv1.CommandResultState_COMMAND_RESULT_STATE_FAILED.String()
	auditResult := "failure"
	switch status {
	case CommandSucceeded:
		state, auditResult = agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED.String(), "success"
	case CommandCancelled:
		state = agentv1.CommandResultState_COMMAND_RESULT_STATE_CANCELLED.String()
	case CommandTimedOut:
		state = agentv1.CommandResultState_COMMAND_RESULT_STATE_TIMED_OUT.String()
	}
	return repository.PersistTerminalCommand(ctx, TerminalCommand{Scope: scope, CommandID: commandID, Status: status, Target: target, Audit: TerminalAudit{DedupeKey: "command.result:" + commandID, Action: "command.result", Result: auditResult, Detail: map[string]any{"artifact_count": len(target.Artifacts), "state": state}}, At: at})
}

func terminalJobStatusForTarget(status TargetStatus) Status {
	switch status {
	case TargetSucceeded:
		return StatusSucceeded
	case TargetCancelled:
		return StatusCancelled
	case TargetTimedOut:
		return StatusTimedOut
	default:
		return StatusFailed
	}
}

func (repository *PostgresRepository) PendingCancellationsForAgent(ctx context.Context, agentID string, limit int) ([]OutboxMessage, error) {
	if repository == nil || repository.db == nil || ctx == nil || strings.TrimSpace(agentID) == "" || limit <= 0 {
		return nil, ErrInvalidCommandPayload
	}
	rows, err := repository.db.QueryContext(ctx, pendingCancellationsForAgentSQL, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending Agent cancellations: %w", err)
	}
	defer rows.Close()
	result := make([]OutboxMessage, 0, limit)
	for rows.Next() {
		message, err := scanOutbox(rows)
		if err != nil {
			return nil, fmt.Errorf("scan pending Agent cancellation: %w", err)
		}
		result = append(result, message)
	}
	return result, rows.Err()
}

func (repository *PostgresRepository) PreparedCommandsForAgent(ctx context.Context, agentID string, limit int) ([]OutboxMessage, error) {
	if repository == nil || repository.db == nil || ctx == nil || strings.TrimSpace(agentID) == "" || limit <= 0 {
		return nil, ErrInvalidCommandPayload
	}
	rows, err := repository.db.QueryContext(ctx, preparedCommandsForAgentSQL, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("list prepared Agent commands: %w", err)
	}
	defer rows.Close()
	result := make([]OutboxMessage, 0, limit)
	for rows.Next() {
		message, err := scanOutbox(rows)
		if err != nil {
			return nil, fmt.Errorf("scan prepared Agent command: %w", err)
		}
		result = append(result, message)
	}
	return result, rows.Err()
}

func (repository *PostgresRepository) PendingTerminalAuditsForAgent(ctx context.Context, agentID string, limit int) ([]OutboxMessage, error) {
	if repository == nil || repository.db == nil || ctx == nil || strings.TrimSpace(agentID) == "" || limit <= 0 {
		return nil, ErrInvalidCommandPayload
	}
	rows, err := repository.db.QueryContext(ctx, pendingTerminalAuditsForAgentSQL, agentID, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending terminal Audits for Agent: %w", err)
	}
	defer rows.Close()
	result := make([]OutboxMessage, 0, limit)
	for rows.Next() {
		message, err := scanOutbox(rows)
		if err != nil {
			return nil, fmt.Errorf("scan pending terminal Audit: %w", err)
		}
		result = append(result, message)
	}
	return result, rows.Err()
}

func (repository *PostgresRepository) MarkTerminalAuditRecorded(ctx context.Context, scope platformscope.Scope, commandID, dedupeKey string, at time.Time) error {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(commandID) == "" || strings.TrimSpace(dedupeKey) == "" || at.IsZero() {
		return ErrInvalidCommandPayload
	}
	return repository.execScopedCommand(ctx, markTerminalAuditRecordedSQL, []any{at.UTC(), scope.TenantID, scope.ProjectID, commandID, dedupeKey})
}

func (repository *PostgresRepository) execScopedCommand(ctx context.Context, query string, args []any) error {
	if repository == nil || repository.db == nil || ctx == nil || len(args) < 4 {
		return ErrInvalidCommandPayload
	}
	result, err := repository.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrNotFound
	}
	return nil
}

func terminalCommandStatus(status CommandStatus) bool {
	switch status {
	case CommandSucceeded, CommandFailed, CommandCancelled, CommandTimedOut, CommandRejected:
		return true
	default:
		return false
	}
}

func (repository *PostgresRepository) LookupCommand(ctx context.Context, commandID string) (OutboxMessage, error) {
	if repository == nil || repository.db == nil {
		return OutboxMessage{}, errors.New("job PostgreSQL repository is unavailable")
	}
	if strings.TrimSpace(commandID) == "" {
		return OutboxMessage{}, ErrNotFound
	}
	message, err := scanOutbox(repository.db.QueryRowContext(ctx, selectOutboxByIDSQL, commandID))
	if err != nil {
		return OutboxMessage{}, classifyReadError("lookup command", err)
	}
	return message, nil
}

func (repository *PostgresRepository) PrepareCommandEnvelope(ctx context.Context, scope platformscope.Scope, commandID string, proposed []byte) ([]byte, error) {
	if repository == nil || repository.db == nil {
		return nil, errors.New("job PostgreSQL repository is unavailable")
	}
	if scope.Validate() != nil || strings.TrimSpace(commandID) == "" || len(proposed) == 0 {
		return nil, ErrInvalidCommandPayload
	}
	var stored []byte
	if err := repository.db.QueryRowContext(ctx, prepareCommandEnvelopeSQL, scope.TenantID, scope.ProjectID, commandID, proposed).Scan(&stored); err != nil {
		return nil, classifyReadError("prepare command envelope", err)
	}
	if len(stored) == 0 {
		return nil, ErrInvalidCommandPayload
	}
	return append([]byte(nil), stored...), nil
}

func (repository *PostgresRepository) MarkPrepared(ctx context.Context, scope platformscope.Scope, commandID string, digest [32]byte, at time.Time) error {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(commandID) == "" || at.IsZero() {
		return ErrInvalidCommandPayload
	}
	result, err := repository.db.ExecContext(ctx, `
		UPDATE command_outbox
		SET command_phase = 'prepared', prepare_digest = COALESCE(prepare_digest, $4),
			prepared_at = COALESCE(prepared_at, $5), published_at = COALESCE(published_at, $5), lease_expires_at = NULL
		WHERE tenant_id = $1 AND project_id = $2 AND id = $3
			AND cancellation_requested_at IS NULL
			AND command_phase IN ('pending', 'preparing', 'prepared')
			AND (prepare_digest IS NULL OR prepare_digest = $4)
	`, scope.TenantID, scope.ProjectID, commandID, digest[:], at.UTC())
	if err != nil {
		return classifyWriteError("mark command prepared", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read prepared command update result: %w", err)
	}
	if updated == 1 {
		return nil
	}
	var phase CommandPhase
	var storedDigest []byte
	var cancellation sql.NullTime
	err = repository.db.QueryRowContext(ctx, `SELECT command_phase, prepare_digest, cancellation_requested_at FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND id = $3`, scope.TenantID, scope.ProjectID, commandID).Scan(&phase, &storedDigest, &cancellation)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("classify prepared command: %w", err)
	}
	if subtle.ConstantTimeCompare(storedDigest, digest[:]) == 1 && (phase == CommandPhasePrepared || phase == CommandPhaseStartAuthorized || phase == CommandPhaseRunning || phase == CommandPhaseCancelling) {
		return nil
	}
	return ErrConflict
}

func (repository *PostgresRepository) AuthorizeStart(ctx context.Context, scope platformscope.Scope, commandID string, expectedDigest [32]byte, tokenHash [32]byte, tokenCiphertext []byte, at, deadline time.Time) (StartGrant, error) {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(commandID) == "" || len(tokenCiphertext) == 0 || at.IsZero() || !deadline.After(at) {
		return StartGrant{}, ErrInvalidCommandPayload
	}
	var jobID, targetID string
	if err := repository.db.QueryRowContext(ctx, `SELECT job_id, target_id FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND id = $3`, scope.TenantID, scope.ProjectID, commandID).Scan(&jobID, &targetID); err != nil {
		return StartGrant{}, classifyReadError("lookup command for Start", err)
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return StartGrant{}, fmt.Errorf("begin command Start authorization: %w", err)
	}
	rollback := func(cause error) (StartGrant, error) {
		_ = tx.Rollback()
		return StartGrant{}, cause
	}
	var jobStatus Status
	if err := tx.QueryRowContext(ctx, `SELECT status FROM jobs WHERE tenant_id = $1 AND project_id = $2 AND id = $3 FOR UPDATE`, scope.TenantID, scope.ProjectID, jobID).Scan(&jobStatus); err != nil {
		return rollback(classifyReadError("lock Job for Start", err))
	}
	var targetStatus TargetStatus
	if err := tx.QueryRowContext(ctx, `SELECT status FROM job_targets WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 AND target_id = $4 FOR UPDATE`, scope.TenantID, scope.ProjectID, jobID, targetID).Scan(&targetStatus); err != nil {
		return rollback(classifyReadError("lock Job target for Start", err))
	}
	if isTerminalTarget(targetStatus) {
		return rollback(ErrConflict)
	}
	var phase CommandPhase
	var cancellation sql.NullTime
	var storedDigest, storedTokenHash, storedCiphertext []byte
	var executionRevision, recoveryRevision uint64
	var storedDeadline sql.NullTime
	err = tx.QueryRowContext(ctx, `
		SELECT command_phase, cancellation_requested_at, prepare_digest, execution_token_hash,
			execution_token_ciphertext, execution_revision, recovery_revision, start_deadline_at
		FROM command_outbox
		WHERE tenant_id = $1 AND project_id = $2 AND id = $3 AND job_id = $4 AND target_id = $5
		FOR UPDATE
	`, scope.TenantID, scope.ProjectID, commandID, jobID, targetID).Scan(&phase, &cancellation, &storedDigest, &storedTokenHash, &storedCiphertext, &executionRevision, &recoveryRevision, &storedDeadline)
	if err != nil {
		return rollback(classifyReadError("lock command for Start", err))
	}
	if subtle.ConstantTimeCompare(storedDigest, expectedDigest[:]) != 1 {
		return rollback(ErrConflict)
	}
	if phase == CommandPhaseStartAuthorized || phase == CommandPhaseRunning || phase == CommandPhaseCancelling {
		grant, grantErr := startGrantFromStored(commandID, storedTokenHash, storedCiphertext, executionRevision, recoveryRevision, storedDeadline)
		if grantErr != nil {
			return rollback(grantErr)
		}
		if err := tx.Commit(); err != nil {
			return StartGrant{}, fmt.Errorf("commit duplicate command Start authorization: %w", err)
		}
		return grant, nil
	}
	if jobStatus == StatusCancelling || isTerminal(jobStatus) || cancellation.Valid {
		return rollback(ErrConflict)
	}
	if phase != CommandPhasePrepared {
		return rollback(ErrConflict)
	}
	executionRevision = 1
	recoveryRevision = 1
	result, err := tx.ExecContext(ctx, `
		UPDATE command_outbox
		SET command_phase = 'start_authorized', command_status = 'active', execution_token_hash = $1,
			execution_token_ciphertext = $2, execution_revision = $3, recovery_revision = $4,
			start_deadline_at = $5, execution_deadline_at = $5, execution_last_heartbeat_at = $6,
			recovery_claim_token = NULL, recovery_claimed_deadline = NULL, recovery_claimed_revision = NULL,
			recovery_lease_expires_at = NULL
		WHERE tenant_id = $7 AND project_id = $8 AND id = $9 AND command_phase = 'prepared'
			AND cancellation_requested_at IS NULL AND prepare_digest = $10
	`, tokenHash[:], tokenCiphertext, executionRevision, recoveryRevision, deadline.UTC(), at.UTC(), scope.TenantID, scope.ProjectID, commandID, expectedDigest[:])
	if err != nil {
		return rollback(classifyWriteError("authorize command Start", err))
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("read command Start authorization result: %w", err))
	}
	if updated != 1 {
		return rollback(ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return StartGrant{}, fmt.Errorf("commit command Start authorization: %w: %w", ErrAmbiguousCommit, err)
	}
	return StartGrant{CommandID: commandID, TokenHash: tokenHash, TokenCiphertext: append([]byte(nil), tokenCiphertext...), ExecutionRevision: executionRevision, RecoveryRevision: recoveryRevision, StartDeadline: deadline.UTC()}, nil
}

func startGrantFromStored(commandID string, tokenHash, ciphertext []byte, executionRevision, recoveryRevision uint64, deadline sql.NullTime) (StartGrant, error) {
	if len(tokenHash) != sha256.Size || len(ciphertext) == 0 || executionRevision == 0 || recoveryRevision == 0 || !deadline.Valid {
		return StartGrant{}, ErrInvalidCommandPayload
	}
	var hash [sha256.Size]byte
	copy(hash[:], tokenHash)
	return StartGrant{CommandID: commandID, TokenHash: hash, TokenCiphertext: append([]byte(nil), ciphertext...), ExecutionRevision: executionRevision, RecoveryRevision: recoveryRevision, StartDeadline: deadline.Time.UTC()}, nil
}

func (repository *PostgresRepository) MarkStartEnqueued(ctx context.Context, scope platformscope.Scope, commandID string, executionRevision uint64, at time.Time) error {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(commandID) == "" || executionRevision == 0 || at.IsZero() {
		return ErrInvalidCommandPayload
	}
	result, err := repository.db.ExecContext(ctx, `
		UPDATE command_outbox
		SET start_enqueued_at = COALESCE(start_enqueued_at, $1)
		WHERE tenant_id = $2 AND project_id = $3 AND id = $4
			AND execution_revision = $5
			AND command_phase IN ('start_authorized', 'running', 'cancelling', 'succeeded', 'failed', 'cancelled', 'timed_out')
	`, at.UTC(), scope.TenantID, scope.ProjectID, commandID, executionRevision)
	if err != nil {
		return classifyWriteError("mark command Start enqueued", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read command Start enqueue result: %w", err)
	}
	if updated != 1 {
		return ErrConflict
	}
	return nil
}

func (repository *PostgresRepository) RenewExecutionLease(ctx context.Context, scope platformscope.Scope, commandID string, tokenHash [32]byte, expectedExecutionRevision uint64, at, deadline time.Time) (uint64, error) {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(commandID) == "" || expectedExecutionRevision == 0 || at.IsZero() || !deadline.After(at) {
		return 0, ErrInvalidCommandPayload
	}
	var recoveryRevision uint64
	err := repository.db.QueryRowContext(ctx, `
		UPDATE command_outbox
		SET command_phase = CASE WHEN command_phase = 'start_authorized' THEN 'running' ELSE command_phase END,
			recovery_revision = recovery_revision + 1, execution_last_heartbeat_at = $1,
			execution_deadline_at = $2, start_enqueued_at = COALESCE(start_enqueued_at, $1), recovery_claim_token = NULL,
			recovery_claimed_deadline = NULL, recovery_claimed_revision = NULL,
			recovery_lease_expires_at = NULL
		WHERE tenant_id = $3 AND project_id = $4 AND id = $5
			AND command_phase IN ('start_authorized', 'running', 'cancelling')
			AND execution_token_hash = $6 AND execution_revision = $7
		RETURNING recovery_revision
	`, at.UTC(), deadline.UTC(), scope.TenantID, scope.ProjectID, commandID, tokenHash[:], expectedExecutionRevision).Scan(&recoveryRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrConflict
	}
	if err != nil {
		return 0, fmt.Errorf("renew fenced execution lease: %w", err)
	}
	return recoveryRevision, nil
}

func (repository *PostgresRepository) ClaimExpiredExecution(ctx context.Context, limit int, at time.Time) ([]RecoveryClaim, error) {
	if repository == nil || repository.db == nil || ctx == nil || limit <= 0 || at.IsZero() {
		return nil, ErrInvalidCommandPayload
	}
	at = at.UTC()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin expired execution claim: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT tenant_id, project_id, id, job_id, target_id, execution_deadline_at, recovery_revision
		FROM command_outbox
		WHERE command_phase IN ('start_authorized', 'running', 'cancelling')
			AND execution_deadline_at IS NOT NULL AND execution_deadline_at <= $1
			AND (recovery_claim_token IS NULL OR recovery_lease_expires_at <= $1)
		ORDER BY execution_deadline_at, id
		FOR UPDATE SKIP LOCKED
		LIMIT $2
	`, at, limit)
	if err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("select expired execution claims: %w", err)
	}
	claims := make([]RecoveryClaim, 0, limit)
	for rows.Next() {
		var claim RecoveryClaim
		if err := rows.Scan(&claim.Scope.TenantID, &claim.Scope.ProjectID, &claim.CommandID, &claim.JobID, &claim.TargetID, &claim.ClaimedDeadline, &claim.ClaimedRecoveryRevision); err != nil {
			_ = rows.Close()
			_ = tx.Rollback()
			return nil, fmt.Errorf("scan expired execution claim: %w", err)
		}
		claim.ClaimedDeadline = claim.ClaimedDeadline.UTC()
		claims = append(claims, claim)
	}
	if err := rows.Close(); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("close expired execution claims: %w", err)
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("iterate expired execution claims: %w", err)
	}
	for index := range claims {
		if _, err := rand.Read(claims[index].ClaimToken[:]); err != nil {
			_ = tx.Rollback()
			return nil, fmt.Errorf("generate recovery claim token: %w", err)
		}
		result, err := tx.ExecContext(ctx, `
			UPDATE command_outbox
			SET recovery_claim_token = $1, recovery_claimed_deadline = $2,
				recovery_claimed_revision = $3, recovery_lease_expires_at = $4
			WHERE tenant_id = $5 AND project_id = $6 AND id = $7
				AND command_phase IN ('start_authorized', 'running', 'cancelling')
				AND execution_deadline_at = $2 AND recovery_revision = $3
		`, claims[index].ClaimToken[:], claims[index].ClaimedDeadline, claims[index].ClaimedRecoveryRevision, at.Add(DefaultOutboxLease), claims[index].Scope.TenantID, claims[index].Scope.ProjectID, claims[index].CommandID)
		if err != nil {
			_ = tx.Rollback()
			return nil, classifyWriteError("claim expired execution", err)
		}
		updated, err := result.RowsAffected()
		if err != nil || updated != 1 {
			_ = tx.Rollback()
			if err != nil {
				return nil, fmt.Errorf("read expired execution claim result: %w", err)
			}
			return nil, ErrConflict
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit expired execution claims: %w", err)
	}
	return claims, nil
}

func (repository *PostgresRepository) FinalizeExpiredExecution(ctx context.Context, claim RecoveryClaim, at time.Time) error {
	if repository == nil || repository.db == nil || ctx == nil || claim.Scope.Validate() != nil || strings.TrimSpace(claim.CommandID) == "" || strings.TrimSpace(claim.JobID) == "" || strings.TrimSpace(claim.TargetID) == "" || claim.ClaimedDeadline.IsZero() || claim.ClaimedRecoveryRevision == 0 || at.IsZero() {
		return ErrInvalidCommandPayload
	}
	at = at.UTC()
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin expired execution finalization: %w", err)
	}
	rollback := func(cause error) error {
		_ = tx.Rollback()
		return cause
	}
	value, err := scanJob(tx.QueryRowContext(ctx, selectJobForUpdateSQL, claim.Scope.TenantID, claim.Scope.ProjectID, claim.JobID))
	if err != nil {
		return rollback(classifyReadError("lock Job for expired execution", err))
	}
	message, err := scanOutbox(tx.QueryRowContext(ctx, `SELECT `+outboxColumnsSQL+` FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND id = $3 FOR UPDATE`, claim.Scope.TenantID, claim.Scope.ProjectID, claim.CommandID))
	if err != nil {
		return rollback(classifyReadError("lock expired command", err))
	}
	if message.JobID != claim.JobID || message.TargetID != claim.TargetID || !matchingRecoveryClaim(message, claim) {
		return rollback(ErrConflict)
	}
	value.TargetResults, err = getTargetsFrom(ctx, tx, claim.Scope, claim.JobID)
	if err != nil {
		return rollback(err)
	}
	value.TargetResourceIDs = make([]string, len(value.TargetResults))
	for index := range value.TargetResults {
		value.TargetResourceIDs[index] = value.TargetResults[index].TargetID
	}
	if _, err := timeoutJobTargetInTx(ctx, tx, value, message, at); err != nil {
		return rollback(err)
	}
	auditDetail, err := json.Marshal(map[string]any{"reason": "execution_deadline"})
	if err != nil {
		return rollback(fmt.Errorf("marshal timeout Audit detail: %w", err))
	}
	dedupeKey := "command.execution_timed_out:" + message.ID
	result, err := tx.ExecContext(ctx, `
		UPDATE command_outbox
		SET command_phase = 'timed_out', command_status = 'timed_out', terminal_at = $1,
			execution_deadline_at = NULL, recovery_lease_expires_at = NULL,
			recovery_claim_token = NULL, recovery_claimed_deadline = NULL,
			recovery_claimed_revision = NULL, cancellation_lease_expires_at = NULL,
			terminal_audit_pending = TRUE, terminal_audit_dedupe_key = $8,
			terminal_audit_action = 'command.execution_timed_out', terminal_audit_result = 'failure',
			terminal_audit_detail = $9, terminal_audit_lease_expires_at = NULL,
			terminal_audit_attempts = 0, terminal_audit_recorded_at = NULL,
			terminal_target_status = 'timed_out', terminal_target_error_summary = 'execution lease expired',
			terminal_target_result_summary = '', terminal_target_artifacts = '[]'::jsonb,
			terminal_reconcile_pending = FALSE
		WHERE tenant_id = $2 AND project_id = $3 AND id = $4
			AND command_phase IN ('start_authorized', 'running', 'cancelling')
			AND recovery_claim_token = $5 AND execution_deadline_at = $6
			AND recovery_claimed_deadline = $6 AND recovery_revision = $7
			AND recovery_claimed_revision = $7
	`, at, claim.Scope.TenantID, claim.Scope.ProjectID, claim.CommandID, claim.ClaimToken[:], claim.ClaimedDeadline.UTC(), claim.ClaimedRecoveryRevision, dedupeKey, auditDetail)
	if err != nil {
		return rollback(classifyWriteError("finalize expired execution", err))
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("read expired execution finalization result: %w", err))
	}
	if updated != 1 {
		return rollback(ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit expired execution finalization: %w: %w", ErrAmbiguousCommit, err)
	}
	return nil
}

func (repository *PostgresRepository) FinalizeExpiredPrepared(ctx context.Context, scope platformscope.Scope, commandID string, expectedDigest [sha256.Size]byte, expiresAt, at time.Time) error {
	if repository == nil || repository.db == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(commandID) == "" || expiresAt.IsZero() || at.IsZero() || expiresAt.After(at) {
		return ErrInvalidCommandPayload
	}
	expiresAt, at = expiresAt.UTC(), at.UTC()
	var jobID string
	if err := repository.db.QueryRowContext(ctx, `SELECT job_id FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND id = $3`, scope.TenantID, scope.ProjectID, commandID).Scan(&jobID); err != nil {
		return classifyReadError("lookup expired prepared command", err)
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin expired prepared finalization: %w", err)
	}
	rollback := func(cause error) error {
		_ = tx.Rollback()
		return cause
	}
	value, err := scanJob(tx.QueryRowContext(ctx, selectJobForUpdateSQL, scope.TenantID, scope.ProjectID, jobID))
	if err != nil {
		return rollback(classifyReadError("lock Job for expired Prepare", err))
	}
	message, err := scanOutbox(tx.QueryRowContext(ctx, `SELECT `+outboxColumnsSQL+` FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND id = $3 FOR UPDATE`, scope.TenantID, scope.ProjectID, commandID))
	if err != nil {
		return rollback(classifyReadError("lock expired prepared command", err))
	}
	if message.JobID != jobID || len(message.PrepareDigest) != sha256.Size || subtle.ConstantTimeCompare(message.PrepareDigest, expectedDigest[:]) != 1 {
		return rollback(ErrConflict)
	}
	value.TargetResults, err = getTargetsFrom(ctx, tx, scope, jobID)
	if err != nil {
		return rollback(err)
	}
	value.TargetResourceIDs = make([]string, len(value.TargetResults))
	for index := range value.TargetResults {
		value.TargetResourceIDs[index] = value.TargetResults[index].TargetID
	}
	if message.Phase == CommandPhaseTimedOut {
		target, found := targetFor(value.TargetResults, message.TargetID)
		if !found || target.Status != TargetTimedOut {
			return rollback(ErrConflict)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit duplicate expired prepared finalization: %w", err)
		}
		return nil
	}
	if message.Phase != CommandPhasePrepared {
		return rollback(ErrConflict)
	}
	if _, err := timeoutJobTargetInTx(ctx, tx, value, message, at); err != nil {
		return rollback(err)
	}
	auditDetail, err := json.Marshal(map[string]any{"reason": "prepare_envelope_expiry", "expires_at": expiresAt})
	if err != nil {
		return rollback(fmt.Errorf("marshal expired Prepare Audit detail: %w", err))
	}
	dedupeKey := "command.prepared_envelope_expired:" + message.ID
	result, err := tx.ExecContext(ctx, `
		UPDATE command_outbox
		SET command_phase = 'timed_out', command_status = 'timed_out', terminal_at = $1,
			lease_expires_at = NULL, execution_deadline_at = NULL, recovery_lease_expires_at = NULL,
			cancellation_lease_expires_at = NULL,
			terminal_audit_pending = TRUE, terminal_audit_dedupe_key = $5,
			terminal_audit_action = 'command.prepared_envelope_expired', terminal_audit_result = 'failure',
			terminal_audit_detail = $6, terminal_audit_lease_expires_at = NULL,
			terminal_audit_attempts = 0, terminal_audit_recorded_at = NULL,
			terminal_target_status = 'timed_out', terminal_target_error_summary = 'execution lease expired',
			terminal_target_result_summary = '', terminal_target_artifacts = '[]'::jsonb,
			terminal_reconcile_pending = FALSE
		WHERE tenant_id = $2 AND project_id = $3 AND id = $4
			AND command_phase = 'prepared' AND prepare_digest = $7
	`, at, scope.TenantID, scope.ProjectID, commandID, dedupeKey, auditDetail, expectedDigest[:])
	if err != nil {
		return rollback(classifyWriteError("finalize expired prepared command", err))
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("read expired prepared finalization result: %w", err))
	}
	if updated != 1 {
		return rollback(ErrConflict)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit expired prepared finalization: %w: %w", ErrAmbiguousCommit, err)
	}
	return nil
}

func timeoutJobTargetInTx(ctx context.Context, tx *sql.Tx, current Job, message OutboxMessage, at time.Time) (Job, error) {
	if current.ID != message.JobID || current.Scope != message.Scope || !containsTarget(current.TargetResourceIDs, message.TargetID) {
		return Job{}, ErrInvalidCommandPayload
	}
	if isTerminal(current.Status) {
		target, found := targetFor(current.TargetResults, message.TargetID)
		if current.Status == StatusTimedOut && found && target.Status == TargetTimedOut {
			return current, nil
		}
		return Job{}, ErrConflict
	}
	if current.Status == StatusQueued {
		var err error
		current, err = transitionInTx(ctx, tx, Transition{Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: StatusDispatched, At: at})
		if err != nil {
			return Job{}, err
		}
	}
	existing, found := targetFor(current.TargetResults, message.TargetID)
	if found && isTerminalTarget(existing.Status) {
		if existing.Status != TargetTimedOut {
			return Job{}, ErrConflict
		}
	} else {
		to := StatusRunning
		actor := ""
		if current.Status == StatusCancelling {
			to = StatusCancelling
			actor = current.CancelRequestedBy
		}
		var err error
		current, err = transitionInTx(ctx, tx, Transition{
			Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: to, Actor: actor, At: at,
			TargetResults: []TargetResult{{TargetID: message.TargetID, Status: TargetTimedOut, ErrorSummary: "execution lease expired", FinishedAt: timePointer(at)}},
		})
		if err != nil {
			return Job{}, err
		}
	}
	if !allTargetsTerminal(current) {
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
	return transitionInTx(ctx, tx, Transition{
		Scope: current.Scope, JobID: current.ID, CurrentVersion: current.Version, To: to,
		Artifacts: collectArtifacts(current.TargetResults), ResultSummary: "Agent commands completed", At: at,
	})
}

func (repository *PostgresRepository) PersistTerminalResult(ctx context.Context, input TerminalResultCAS) (TerminalResultOutcome, error) {
	base := TerminalResultOutcome{CommandID: input.CommandID}
	terminalInput := TerminalCommand{Scope: input.Scope, CommandID: input.CommandID, Status: input.Status, Target: input.Target, Audit: input.Audit, At: input.At}
	if repository == nil || repository.db == nil || ctx == nil || input.ExpectedExecutionRevision == 0 || input.Status == CommandRejected || (input.AllowTimedOutDigestAttach && input.Status != CommandTimedOut) || validateTerminalCommand(terminalInput) != nil {
		return base, ErrInvalidCommandPayload
	}
	var jobID string
	if err := repository.db.QueryRowContext(ctx, `SELECT job_id FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, input.Scope.TenantID, input.Scope.ProjectID, input.CommandID).Scan(&jobID); err != nil {
		return base, classifyReadError("lookup command terminal result Job", err)
	}
	tx, err := repository.db.BeginTx(ctx, nil)
	if err != nil {
		return base, fmt.Errorf("begin terminal result persistence: %w", err)
	}
	rollback := func(cause error) (TerminalResultOutcome, error) {
		_ = tx.Rollback()
		return base, cause
	}
	var lockedJobID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM jobs WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, input.Scope.TenantID, input.Scope.ProjectID, jobID).Scan(&lockedJobID); err != nil {
		return rollback(classifyReadError("lock command terminal result Job", err))
	}
	message, err := scanOutbox(tx.QueryRowContext(ctx, `SELECT `+outboxColumnsSQL+` FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR UPDATE`, input.Scope.TenantID, input.Scope.ProjectID, input.CommandID))
	if err != nil {
		return rollback(classifyReadError("lock command terminal result", err))
	}
	base.JobID, base.TargetID, base.Status = message.JobID, message.TargetID, message.CommandStatus
	if message.JobID != lockedJobID || message.TargetID != input.Target.TargetID {
		return rollback(ErrConflict)
	}
	if len(message.TerminalResultDigest) == sha256.Size {
		copy(base.ResultDigest[:], message.TerminalResultDigest)
	}
	fenceMatches := len(message.ExecutionTokenHash) == sha256.Size && subtle.ConstantTimeCompare(message.ExecutionTokenHash, input.TokenHash[:]) == 1 && message.ExecutionRevision == input.ExpectedExecutionRevision
	if message.Phase == CommandPhaseSucceeded || message.Phase == CommandPhaseFailed || message.Phase == CommandPhaseCancelled || message.Phase == CommandPhaseTimedOut || message.Phase == CommandPhaseRejected {
		if !fenceMatches {
			return rollback(ErrConflict)
		}
		if message.Phase == CommandPhaseTimedOut && message.CommandStatus == CommandTimedOut && len(message.TerminalResultDigest) == 0 && input.AllowTimedOutDigestAttach {
			result, updateErr := tx.ExecContext(ctx, `
				UPDATE command_outbox
				SET terminal_result_digest = $1
				WHERE tenant_id = $2 AND project_id = $3 AND id = $4
					AND command_phase = 'timed_out' AND command_status = 'timed_out'
					AND terminal_result_digest IS NULL
					AND execution_token_hash = $5 AND execution_revision = $6
			`, input.ResultDigest[:], input.Scope.TenantID, input.Scope.ProjectID, input.CommandID, input.TokenHash[:], input.ExpectedExecutionRevision)
			if updateErr != nil {
				return rollback(classifyWriteError("attach interrupted result digest to timed-out command", updateErr))
			}
			updated, rowsErr := result.RowsAffected()
			if rowsErr != nil {
				return rollback(fmt.Errorf("read timed-out result digest attachment: %w", rowsErr))
			}
			if updated != 1 {
				return rollback(ErrConflict)
			}
			base.ResultDigest = input.ResultDigest
			base.Persisted = true
			base.Duplicate = true
			if err := tx.Commit(); err != nil {
				return TerminalResultOutcome{}, fmt.Errorf("commit timed-out result digest attachment: %w: %w", ErrAmbiguousCommit, err)
			}
			return base, nil
		}
		if message.CommandStatus == input.Status && len(message.TerminalResultDigest) == sha256.Size && subtle.ConstantTimeCompare(message.TerminalResultDigest, input.ResultDigest[:]) == 1 {
			if !terminalEvidenceCompatible(message, terminalInput) {
				return rollback(ErrConflict)
			}
			if err := persistTerminalEvidenceTx(ctx, tx, terminalInput); err != nil {
				return rollback(err)
			}
			base.Persisted = true
			base.Duplicate = true
			if err := tx.Commit(); err != nil {
				return TerminalResultOutcome{}, fmt.Errorf("commit duplicate terminal result: %w", err)
			}
			return base, nil
		}
		base.Conflict = true
		if err := tx.Commit(); err != nil {
			return TerminalResultOutcome{}, fmt.Errorf("commit terminal result conflict classification: %w", err)
		}
		return base, nil
	}
	if !fenceMatches || (message.Phase != CommandPhaseStartAuthorized && message.Phase != CommandPhaseRunning && message.Phase != CommandPhaseCancelling) {
		return rollback(ErrConflict)
	}
	phase := phaseForCommandStatus(input.Status)
	result, err := tx.ExecContext(ctx, `
		UPDATE command_outbox
		SET command_phase = $1, command_status = $2, terminal_result_digest = $3, terminal_at = $4,
			execution_deadline_at = NULL, recovery_lease_expires_at = NULL,
			recovery_claim_token = NULL, recovery_claimed_deadline = NULL,
			recovery_claimed_revision = NULL, cancellation_lease_expires_at = NULL
		WHERE tenant_id = $5 AND project_id = $6 AND id = $7
			AND command_phase IN ('start_authorized', 'running', 'cancelling')
			AND execution_token_hash = $8 AND execution_revision = $9
	`, string(phase), string(input.Status), input.ResultDigest[:], input.At.UTC(), input.Scope.TenantID, input.Scope.ProjectID, input.CommandID, input.TokenHash[:], input.ExpectedExecutionRevision)
	if err != nil {
		return rollback(classifyWriteError("persist terminal result", err))
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("read terminal result persistence: %w", err))
	}
	if updated != 1 {
		return rollback(ErrConflict)
	}
	if err := persistTerminalEvidenceTx(ctx, tx, terminalInput); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return TerminalResultOutcome{}, fmt.Errorf("commit terminal result: %w: %w", ErrAmbiguousCommit, err)
	}
	return TerminalResultOutcome{CommandID: input.CommandID, JobID: base.JobID, TargetID: base.TargetID, Status: input.Status, ResultDigest: input.ResultDigest, Persisted: true}, nil
}

func terminalEvidenceCompatible(message OutboxMessage, input TerminalCommand) bool {
	targetCompatible := message.TerminalTargetStatus == "" || message.TerminalTargetStatus == input.Target.Status && message.TerminalTargetError == input.Target.ErrorSummary && message.TerminalTargetResult == input.Target.ResultSummary && artifactReferencesEqual(message.TerminalTargetArtifacts, input.Target.Artifacts)
	auditCompatible := message.TerminalAuditDedupeKey == "" || message.TerminalAuditDedupeKey == input.Audit.DedupeKey && message.TerminalAuditAction == input.Audit.Action && message.TerminalAuditResult == input.Audit.Result && terminalAuditDetailsEqual(message.TerminalAuditDetail, input.Audit.Detail)
	return targetCompatible && auditCompatible
}

func persistTerminalEvidenceTx(ctx context.Context, tx *sql.Tx, input TerminalCommand) error {
	artifacts, err := json.Marshal(input.Target.Artifacts)
	if err != nil {
		return ErrInvalidCommandPayload
	}
	detail, err := json.Marshal(input.Audit.Detail)
	if err != nil {
		return ErrInvalidCommandPayload
	}
	result, err := tx.ExecContext(ctx, `UPDATE command_outbox SET terminal_target_status=$1,terminal_target_error_summary=$2,terminal_target_result_summary=$3,terminal_target_artifacts=$4,terminal_reconcile_pending=TRUE,terminal_audit_pending=(terminal_audit_recorded_at IS NULL),terminal_audit_dedupe_key=$5,terminal_audit_action=$6,terminal_audit_result=$7,terminal_audit_detail=$8,terminal_audit_lease_expires_at=CASE WHEN terminal_audit_recorded_at IS NULL THEN NULL ELSE terminal_audit_lease_expires_at END WHERE tenant_id=$9 AND project_id=$10 AND id=$11 AND command_status=$12 AND terminal_at IS NOT NULL`, string(input.Target.Status), input.Target.ErrorSummary, input.Target.ResultSummary, artifacts, input.Audit.DedupeKey, input.Audit.Action, input.Audit.Result, detail, input.Scope.TenantID, input.Scope.ProjectID, input.CommandID, string(input.Status))
	if err != nil {
		return classifyWriteError("persist terminal command evidence", err)
	}
	if updated, rowsErr := result.RowsAffected(); rowsErr != nil || updated != 1 {
		return ErrConflict
	}
	return nil
}

func phaseForCommandStatus(status CommandStatus) CommandPhase {
	switch status {
	case CommandSucceeded:
		return CommandPhaseSucceeded
	case CommandFailed:
		return CommandPhaseFailed
	case CommandCancelled:
		return CommandPhaseCancelled
	case CommandTimedOut:
		return CommandPhaseTimedOut
	case CommandRejected:
		return CommandPhaseRejected
	default:
		return CommandPhasePending
	}
}

type rowQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func getTargetsFrom(ctx context.Context, queryer rowQueryer, scope platformscope.Scope, id string) ([]TargetResult, error) {
	rows, err := queryer.QueryContext(ctx, selectTargetsSQL, scope.TenantID, scope.ProjectID, id)
	if err != nil {
		return nil, fmt.Errorf("get job targets: %w", err)
	}
	defer rows.Close()
	var results []TargetResult
	for rows.Next() {
		var value TargetResult
		var artifacts []byte
		var finished sql.NullTime
		if err := rows.Scan(&value.TargetID, &value.Status, &value.ErrorSummary, &value.ResultSummary, &artifacts, &finished); err != nil {
			return nil, fmt.Errorf("scan job target: %w", err)
		}
		if err := json.Unmarshal(artifacts, &value.Artifacts); err != nil {
			return nil, fmt.Errorf("decode job target artifacts: %w", err)
		}
		value.FinishedAt = nullTimePointer(finished)
		results = append(results, value)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate job targets: %w", err)
	}
	return results, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanJob(row rowScanner) (Job, error) {
	var value Job
	var artifacts []byte
	var dispatched, started, finished, timeout, cancelRequested sql.NullTime
	var maxConcurrency, targetTimeoutSeconds sql.NullInt64
	err := row.Scan(
		&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.Type, &value.Status, &value.Outcome, &value.InstanceID,
		&value.InitiatedBy, &value.SourceResource.ResourceType, &value.SourceResource.ResourceID, &value.IdempotencyKey, &value.Version,
		&value.Progress.TotalTargets, &value.Progress.CompletedTargets, &value.Progress.FailedTargets, &value.Progress.SkippedTargets,
		&value.ErrorSummary, &value.ResultSummary, &artifacts, &value.CreatedAt, &dispatched, &started, &finished, &timeout,
		&value.CancelRequestedBy, &cancelRequested, &value.RequestID, &value.TraceID, &maxConcurrency, &targetTimeoutSeconds,
	)
	if err != nil {
		return Job{}, err
	}
	if err := json.Unmarshal(artifacts, &value.Artifacts); err != nil {
		return Job{}, fmt.Errorf("decode job artifacts: %w", err)
	}
	value.DispatchedAt = nullTimePointer(dispatched)
	value.StartedAt = nullTimePointer(started)
	value.FinishedAt = nullTimePointer(finished)
	value.TimeoutAt = nullTimePointer(timeout)
	value.CancelRequestedAt = nullTimePointer(cancelRequested)
	if maxConcurrency.Valid {
		value.MaxConcurrency = int(maxConcurrency.Int64)
	}
	if targetTimeoutSeconds.Valid {
		value.TargetTimeout = time.Duration(targetTimeoutSeconds.Int64) * time.Second
	}
	value = normalizeJobUTC(value)
	if err := validateExecutionLimits(value); err != nil {
		return Job{}, fmt.Errorf("validate persisted job execution limits: %w", err)
	}
	return value, nil
}

func scanOutbox(row rowScanner) (OutboxMessage, error) {
	var value OutboxMessage
	var leased, published, acknowledged, executionDeadline, lastHeartbeat, recoveryLeased, cancelRequested, cancelAvailable, cancelLeased sql.NullTime
	var prepared, startDeadline, startEnqueued, claimedDeadline, terminal, terminalAuditLeased, terminalAuditRecorded sql.NullTime
	var claimedRevision sql.NullInt64
	var terminalAuditDetail, terminalTargetArtifacts []byte
	err := row.Scan(
		&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.JobID, &value.TargetID, &value.Type,
		&value.Payload, &value.PreparedEnvelope, &value.AvailableAt, &value.CreatedAt, &leased, &published, &value.Attempts,
		&value.CommandStatus, &acknowledged, &executionDeadline, &lastHeartbeat, &recoveryLeased,
		&cancelRequested, &value.CancellationReason, &cancelAvailable, &cancelLeased, &value.CancellationAttempts,
		&value.Phase, &value.PrepareDigest, &prepared, &value.ExecutionTokenHash, &value.ExecutionTokenCiphertext,
		&value.ExecutionRevision, &value.RecoveryRevision, &startDeadline, &startEnqueued, &value.RecoveryClaimToken,
		&claimedDeadline, &claimedRevision, &value.TerminalResultDigest, &terminal,
		&value.TerminalAuditPending, &value.TerminalAuditDedupeKey, &value.TerminalAuditAction, &value.TerminalAuditResult,
		&terminalAuditDetail, &terminalAuditLeased, &value.TerminalAuditAttempts, &terminalAuditRecorded,
		&value.TerminalTargetStatus, &value.TerminalTargetError, &value.TerminalTargetResult, &terminalTargetArtifacts, &value.TerminalReconcilePending,
	)
	if err != nil {
		return OutboxMessage{}, err
	}
	value.AvailableAt = value.AvailableAt.UTC()
	value.CreatedAt = value.CreatedAt.UTC()
	value.LeasedUntil = nullTimePointer(leased)
	value.PublishedAt = nullTimePointer(published)
	value.AcknowledgedAt = nullTimePointer(acknowledged)
	value.ExecutionDeadline = nullTimePointer(executionDeadline)
	value.LastHeartbeatAt = nullTimePointer(lastHeartbeat)
	value.RecoveryLeasedUntil = nullTimePointer(recoveryLeased)
	value.CancellationRequestedAt = nullTimePointer(cancelRequested)
	value.CancellationAvailableAt = nullTimePointer(cancelAvailable)
	value.CancellationLeasedUntil = nullTimePointer(cancelLeased)
	value.PreparedAt = nullTimePointer(prepared)
	value.StartDeadline = nullTimePointer(startDeadline)
	value.StartEnqueuedAt = nullTimePointer(startEnqueued)
	value.RecoveryClaimedDeadline = nullTimePointer(claimedDeadline)
	if claimedRevision.Valid && claimedRevision.Int64 > 0 {
		value.RecoveryClaimedRevision = uint64(claimedRevision.Int64)
	}
	value.TerminalAt = nullTimePointer(terminal)
	value.TerminalAuditLeasedUntil = nullTimePointer(terminalAuditLeased)
	value.TerminalAuditRecordedAt = nullTimePointer(terminalAuditRecorded)
	if len(terminalAuditDetail) == 0 {
		terminalAuditDetail = []byte("{}")
	}
	if err := json.Unmarshal(terminalAuditDetail, &value.TerminalAuditDetail); err != nil {
		return OutboxMessage{}, fmt.Errorf("decode terminal audit detail: %w", err)
	}
	if len(terminalTargetArtifacts) == 0 {
		terminalTargetArtifacts = []byte("[]")
	}
	if err := json.Unmarshal(terminalTargetArtifacts, &value.TerminalTargetArtifacts); err != nil {
		return OutboxMessage{}, fmt.Errorf("decode terminal target artifacts: %w", err)
	}
	value.PrepareDigest = append([]byte(nil), value.PrepareDigest...)
	value.ExecutionTokenHash = append([]byte(nil), value.ExecutionTokenHash...)
	value.ExecutionTokenCiphertext = append([]byte(nil), value.ExecutionTokenCiphertext...)
	value.RecoveryClaimToken = append([]byte(nil), value.RecoveryClaimToken...)
	value.TerminalResultDigest = append([]byte(nil), value.TerminalResultDigest...)
	return value, nil
}

func validateNewJob(value Job) error {
	if err := value.Scope.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(value.ID) == "" || strings.TrimSpace(value.Type) == "" || strings.TrimSpace(value.IdempotencyKey) == "" || value.Status != StatusQueued || value.Outcome != OutcomeNone || value.Version < 1 || value.CreatedAt.IsZero() || !validProgressChange(value.Progress, value.Progress) {
		return fmt.Errorf("create job: %w", ErrInvalidTransition)
	}
	if err := ValidateTargets(value); err != nil {
		return fmt.Errorf("create job targets: %w", err)
	}
	return nil
}

func validateOutboxMessage(ctx context.Context, value Job, message OutboxMessage, authorizer commandvalidation.TargetAuthorizer) error {
	if ctx == nil || strings.TrimSpace(message.ID) == "" || message.ID != strings.TrimSpace(message.ID) || message.Type != commandOutboxType || message.JobID != value.ID || message.Scope != value.Scope || !containsTarget(value.TargetResourceIDs, message.TargetID) || message.CreatedAt.IsZero() || message.AvailableAt.IsZero() || len(message.Payload) == 0 || len(message.PreparedEnvelope) != 0 || message.LeasedUntil != nil || message.PublishedAt != nil || message.Attempts != 0 || message.CommandStatus != "" || message.AcknowledgedAt != nil || message.ExecutionDeadline != nil || message.LastHeartbeatAt != nil || message.RecoveryLeasedUntil != nil || message.CancellationRequestedAt != nil || message.CancellationReason != "" || message.CancellationAvailableAt != nil || message.CancellationLeasedUntil != nil || message.CancellationAttempts != 0 || message.Phase != "" || len(message.PrepareDigest) != 0 || message.PreparedAt != nil || len(message.ExecutionTokenHash) != 0 || len(message.ExecutionTokenCiphertext) != 0 || message.ExecutionRevision != 0 || message.RecoveryRevision != 0 || message.StartDeadline != nil || message.StartEnqueuedAt != nil || len(message.RecoveryClaimToken) != 0 || message.RecoveryClaimedDeadline != nil || message.RecoveryClaimedRevision != 0 || len(message.TerminalResultDigest) != 0 || message.TerminalAt != nil || message.TerminalAuditPending || message.TerminalAuditDedupeKey != "" || message.TerminalAuditAction != "" || message.TerminalAuditResult != "" || len(message.TerminalAuditDetail) != 0 || message.TerminalAuditLeasedUntil != nil || message.TerminalAuditAttempts != 0 || message.TerminalAuditRecordedAt != nil || message.TerminalTargetStatus != "" || message.TerminalTargetError != "" || message.TerminalTargetResult != "" || len(message.TerminalTargetArtifacts) != 0 || message.TerminalReconcilePending {
		return fmt.Errorf("create outbox message: %w", ErrInvalidCommandPayload)
	}
	envelope := new(agentv1.CommandEnvelope)
	if err := proto.Unmarshal(message.Payload, envelope); err != nil || len(envelope.ProtoReflect().GetUnknown()) != 0 {
		return fmt.Errorf("create outbox message: %w", ErrInvalidCommandPayload)
	}
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, message.Payload) {
		return fmt.Errorf("create outbox message: %w", ErrInvalidCommandPayload)
	}
	if envelope.GetCommandId() != "" || envelope.GetJobId() != "" || envelope.GetIssuedAt() != nil || envelope.GetExpiresAt() != nil || len(envelope.GetNonce()) != 0 || len(envelope.GetSignature()) != 0 || envelope.GetAgentId() != message.TargetID || envelope.GetLeaseSeconds() == 0 || envelope.GetLeaseSeconds() > commandvalidation.MaximumTimeoutSeconds {
		return fmt.Errorf("create outbox message: %w", ErrInvalidCommandPayload)
	}
	if err := commandvalidation.Validate(ctx, envelope, authorizer); err != nil {
		return fmt.Errorf("create outbox message: %w: %v", ErrInvalidCommandPayload, err)
	}
	return nil
}

func initialTargets(value Job) []TargetResult {
	byID := make(map[string]TargetResult, len(value.TargetResults))
	for _, result := range value.TargetResults {
		byID[result.TargetID] = result
	}
	targets := make([]TargetResult, 0, len(value.TargetResourceIDs))
	for _, id := range value.TargetResourceIDs {
		result, ok := byID[id]
		if !ok {
			result = TargetResult{TargetID: id, Status: TargetQueued}
		}
		targets = append(targets, result)
	}
	return targets
}

func normalizeOutboxMessage(value Job, message OutboxMessage) OutboxMessage {
	if message.Scope == (platformscope.Scope{}) {
		message.Scope = value.Scope
	}
	if message.JobID == "" {
		message.JobID = value.ID
	}
	if message.CreatedAt.IsZero() {
		message.CreatedAt = value.CreatedAt
	}
	if message.AvailableAt.IsZero() {
		message.AvailableAt = message.CreatedAt
	}
	message.CreatedAt = message.CreatedAt.UTC()
	message.AvailableAt = message.AvailableAt.UTC()
	message.LeasedUntil = utcPointer(message.LeasedUntil)
	message.PublishedAt = utcPointer(message.PublishedAt)
	message.AcknowledgedAt = utcPointer(message.AcknowledgedAt)
	message.ExecutionDeadline = utcPointer(message.ExecutionDeadline)
	message.LastHeartbeatAt = utcPointer(message.LastHeartbeatAt)
	message.RecoveryLeasedUntil = utcPointer(message.RecoveryLeasedUntil)
	message.CancellationRequestedAt = utcPointer(message.CancellationRequestedAt)
	message.CancellationAvailableAt = utcPointer(message.CancellationAvailableAt)
	message.CancellationLeasedUntil = utcPointer(message.CancellationLeasedUntil)
	message.Payload = append([]byte(nil), message.Payload...)
	message.PreparedEnvelope = append([]byte(nil), message.PreparedEnvelope...)
	return message
}

func jobInsertArgs(value Job, artifacts []byte) []any {
	return []any{
		value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.Type, string(value.Status), string(value.Outcome), value.InstanceID,
		value.InitiatedBy, value.SourceResource.ResourceType, value.SourceResource.ResourceID, value.IdempotencyKey, value.Version,
		value.Progress.TotalTargets, value.Progress.CompletedTargets, value.Progress.FailedTargets, value.Progress.SkippedTargets,
		value.ErrorSummary, value.ResultSummary, artifacts, value.CreatedAt, nullableTime(value.DispatchedAt), nullableTime(value.StartedAt), nullableTime(value.FinishedAt), nullableTime(value.TimeoutAt), value.CancelRequestedBy, nullableTime(value.CancelRequestedAt), value.RequestID, value.TraceID,
		nullablePositiveInt(value.MaxConcurrency), nullablePositiveInt(int(value.TargetTimeout / time.Second)),
	}
}

func nullablePositiveInt(value int) any {
	if value <= 0 {
		return nil
	}
	return value
}

func targetArgs(scope platformscope.Scope, jobID string, value TargetResult, artifacts []byte) []any {
	return []any{scope.TenantID, scope.ProjectID, jobID, value.TargetID, string(value.Status), value.ErrorSummary, value.ResultSummary, artifacts, nullableTime(value.FinishedAt)}
}

func outboxInsertArgs(value OutboxMessage) []any {
	return []any{value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.JobID, value.TargetID, value.Type, value.Payload, nullableBytes(value.PreparedEnvelope), value.AvailableAt, value.CreatedAt, nullableTime(value.LeasedUntil), nullableTime(value.PublishedAt), value.Attempts}
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func updateJobArgs(value Job, currentVersion int64, artifacts []byte) []any {
	return []any{
		string(value.Status), string(value.Outcome), value.Version, value.Progress.CompletedTargets, value.Progress.FailedTargets, value.Progress.SkippedTargets,
		value.ErrorSummary, value.ResultSummary, artifacts, nullableTime(value.DispatchedAt), nullableTime(value.StartedAt), nullableTime(value.FinishedAt), value.CancelRequestedBy, nullableTime(value.CancelRequestedAt),
		value.Scope.TenantID, value.Scope.ProjectID, value.ID, currentVersion,
	}
}

func nullableTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func nullTimePointer(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	return timePointer(value.Time.UTC())
}

func classifyReadError(operation string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func classifyWriteError(operation string, err error) error {
	var postgresError *pq.Error
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return ErrConflict
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func jobColumnNames() []string {
	return strings.Split(jobColumnsSQL, ", ")
}
