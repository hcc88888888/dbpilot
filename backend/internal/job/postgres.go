package job

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
)

const DefaultOutboxLease = 30 * time.Second

const jobColumnsSQL = "id, tenant_id, project_id, job_type, status, outcome, instance_id, initiated_by, source_resource_type, source_resource_id, idempotency_key, version, total_targets, completed_targets, failed_targets, skipped_targets, error_summary, result_summary, artifacts, created_at, dispatched_at, started_at, finished_at, timeout_at, cancel_requested_by, cancel_requested_at, request_id, trace_id"
const insertJobSQL = "INSERT INTO jobs (" + jobColumnsSQL + ") VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)"
const insertTargetSQL = "INSERT INTO job_targets (tenant_id, project_id, job_id, target_id, status, error_summary, result_summary, artifacts, finished_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
const upsertTargetSQL = "INSERT INTO job_targets (tenant_id, project_id, job_id, target_id, status, error_summary, result_summary, artifacts, finished_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (tenant_id, project_id, job_id, target_id) DO UPDATE SET status = EXCLUDED.status, error_summary = EXCLUDED.error_summary, result_summary = EXCLUDED.result_summary, artifacts = EXCLUDED.artifacts, finished_at = EXCLUDED.finished_at"
const insertOutboxSQL = "INSERT INTO command_outbox (id, tenant_id, project_id, job_id, target_id, message_type, payload, available_at, created_at, lease_expires_at, published_at, attempts) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"
const selectJobSQL = "SELECT " + jobColumnsSQL + " FROM jobs WHERE tenant_id = $1 AND project_id = $2 AND id = $3"
const selectTargetsSQL = "SELECT target_id, status, error_summary, result_summary, artifacts, finished_at FROM job_targets WHERE tenant_id = $1 AND project_id = $2 AND job_id = $3 ORDER BY target_id"
const updateJobSQL = "UPDATE jobs SET status = $1, outcome = $2, version = $3, completed_targets = $4, failed_targets = $5, skipped_targets = $6, error_summary = $7, result_summary = $8, artifacts = $9, dispatched_at = $10, started_at = $11, finished_at = $12, cancel_requested_by = $13, cancel_requested_at = $14 WHERE tenant_id = $15 AND project_id = $16 AND id = $17 AND version = $18"
const claimOutboxSQL = "WITH candidates AS (SELECT id FROM command_outbox WHERE published_at IS NULL AND available_at <= $1 AND (lease_expires_at IS NULL OR lease_expires_at <= $1) ORDER BY created_at, id FOR UPDATE SKIP LOCKED LIMIT $2), claimed AS (UPDATE command_outbox AS o SET lease_expires_at = $3, attempts = o.attempts + 1 FROM candidates AS c WHERE o.id = c.id RETURNING o.id, o.tenant_id, o.project_id, o.job_id, o.target_id, o.message_type, o.payload, o.available_at, o.created_at, o.lease_expires_at, o.published_at, o.attempts) SELECT id, tenant_id, project_id, job_id, target_id, message_type, payload, available_at, created_at, lease_expires_at, published_at, attempts FROM claimed ORDER BY created_at, id"
const markOutboxPublishedSQL = "UPDATE command_outbox SET published_at = $1, lease_expires_at = NULL WHERE tenant_id = $2 AND project_id = $3 AND id = $4 AND published_at IS NULL"
const selectOutboxByIDSQL = "SELECT id, tenant_id, project_id, job_id, target_id, message_type, payload, available_at, created_at, lease_expires_at, published_at, attempts FROM command_outbox WHERE id = $1"

type PostgresRepository struct {
	db *sql.DB
}

func NewPostgresRepository(database *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: database}
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
	for _, message := range messages {
		message = normalizeOutboxMessage(value, message)
		if err := validateOutboxMessage(value, message); err != nil {
			return err
		}
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
	rollback := func(value Job, cause error) (Job, error) {
		_ = tx.Rollback()
		return value, cause
	}
	current, err := scanJob(tx.QueryRowContext(ctx, selectJobSQL, transition.Scope.TenantID, transition.Scope.ProjectID, transition.JobID))
	if err != nil {
		return rollback(Job{}, classifyReadError("get job for transition", err))
	}
	if transition.CurrentVersion == 0 {
		transition.CurrentVersion = current.Version
	}
	current.TargetResults, err = getTargetsFrom(ctx, tx, transition.Scope, transition.JobID)
	if err != nil {
		return rollback(Job{}, err)
	}
	current.TargetResourceIDs = make([]string, len(current.TargetResults))
	for index := range current.TargetResults {
		current.TargetResourceIDs[index] = current.TargetResults[index].TargetID
	}
	next, err := ApplyTransition(current, transition)
	if err != nil {
		return rollback(Job{}, err)
	}
	artifactJSON, err := json.Marshal(next.Artifacts)
	if err != nil {
		return rollback(Job{}, fmt.Errorf("marshal job artifacts: %w", err))
	}
	if next.Artifacts == nil {
		artifactJSON = []byte("[]")
	}
	result, err := tx.ExecContext(ctx, updateJobSQL, updateJobArgs(next, current.Version, artifactJSON)...)
	if err != nil {
		return rollback(Job{}, classifyWriteError("update job", err))
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return rollback(Job{}, fmt.Errorf("read job update result: %w", err))
	}
	if updated != 1 {
		return rollback(Job{}, ErrConflict)
	}
	for _, target := range transition.TargetResults {
		target = normalizeTargetResultsUTC([]TargetResult{target})[0]
		artifactJSON, marshalErr := json.Marshal(target.Artifacts)
		if marshalErr != nil {
			return rollback(Job{}, fmt.Errorf("marshal target artifacts: %w", marshalErr))
		}
		if target.Artifacts == nil {
			artifactJSON = []byte("[]")
		}
		if _, err := tx.ExecContext(ctx, upsertTargetSQL, targetArgs(next.Scope, next.ID, target, artifactJSON)...); err != nil {
			return rollback(Job{}, classifyWriteError("upsert job target", err))
		}
	}
	if err := tx.Commit(); err != nil {
		return Job{}, fmt.Errorf("commit job transition: %w: %w", ErrAmbiguousCommit, err)
	}
	return next, nil
}

func (repository *PostgresRepository) RequestCancel(ctx context.Context, scope platformscope.Scope, id, actor string, at time.Time) (Job, error) {
	return repository.Transition(ctx, Transition{Scope: scope, JobID: id, To: StatusCancelling, Actor: actor, At: at})
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
	err := row.Scan(
		&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.Type, &value.Status, &value.Outcome, &value.InstanceID,
		&value.InitiatedBy, &value.SourceResource.ResourceType, &value.SourceResource.ResourceID, &value.IdempotencyKey, &value.Version,
		&value.Progress.TotalTargets, &value.Progress.CompletedTargets, &value.Progress.FailedTargets, &value.Progress.SkippedTargets,
		&value.ErrorSummary, &value.ResultSummary, &artifacts, &value.CreatedAt, &dispatched, &started, &finished, &timeout,
		&value.CancelRequestedBy, &cancelRequested, &value.RequestID, &value.TraceID,
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
	return normalizeJobUTC(value), nil
}

func scanOutbox(row rowScanner) (OutboxMessage, error) {
	var value OutboxMessage
	var leased, published sql.NullTime
	err := row.Scan(&value.ID, &value.Scope.TenantID, &value.Scope.ProjectID, &value.JobID, &value.TargetID, &value.Type, &value.Payload, &value.AvailableAt, &value.CreatedAt, &leased, &published, &value.Attempts)
	if err != nil {
		return OutboxMessage{}, err
	}
	value.AvailableAt = value.AvailableAt.UTC()
	value.CreatedAt = value.CreatedAt.UTC()
	value.LeasedUntil = nullTimePointer(leased)
	value.PublishedAt = nullTimePointer(published)
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

func validateOutboxMessage(value Job, message OutboxMessage) error {
	if message.ID == "" || message.Type == "" || message.JobID != value.ID || message.Scope != value.Scope || message.CreatedAt.IsZero() || message.AvailableAt.IsZero() || len(message.Payload) == 0 {
		return fmt.Errorf("create outbox message: %w", ErrInvalidTransition)
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
	message.Payload = append([]byte(nil), message.Payload...)
	return message
}

func jobInsertArgs(value Job, artifacts []byte) []any {
	return []any{
		value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.Type, string(value.Status), string(value.Outcome), value.InstanceID,
		value.InitiatedBy, value.SourceResource.ResourceType, value.SourceResource.ResourceID, value.IdempotencyKey, value.Version,
		value.Progress.TotalTargets, value.Progress.CompletedTargets, value.Progress.FailedTargets, value.Progress.SkippedTargets,
		value.ErrorSummary, value.ResultSummary, artifacts, value.CreatedAt, nullableTime(value.DispatchedAt), nullableTime(value.StartedAt), nullableTime(value.FinishedAt), nullableTime(value.TimeoutAt), value.CancelRequestedBy, nullableTime(value.CancelRequestedAt), value.RequestID, value.TraceID,
	}
}

func targetArgs(scope platformscope.Scope, jobID string, value TargetResult, artifacts []byte) []any {
	return []any{scope.TenantID, scope.ProjectID, jobID, value.TargetID, string(value.Status), value.ErrorSummary, value.ResultSummary, artifacts, nullableTime(value.FinishedAt)}
}

func outboxInsertArgs(value OutboxMessage) []any {
	return []any{value.ID, value.Scope.TenantID, value.Scope.ProjectID, value.JobID, value.TargetID, value.Type, value.Payload, value.AvailableAt, value.CreatedAt, nullableTime(value.LeasedUntil), nullableTime(value.PublishedAt), value.Attempts}
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
