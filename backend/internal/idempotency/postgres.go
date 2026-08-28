package idempotency

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const insertClaimSQL = "INSERT INTO idempotency_records (tenant_id, project_id, actor, operation_id, idempotency_key, request_fingerprint, owner_token, state, audit_event_json, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'processing', $8, $9, $10, $10) ON CONFLICT (tenant_id, project_id, actor, operation_id, idempotency_key) DO NOTHING"
const reclaimExpiredCompletedSQL = "UPDATE idempotency_records SET request_fingerprint = $1, owner_token = $2, state = 'processing', response_status = 0, response_headers = '{}'::jsonb, response_json = NULL, audit_event_json = $3, expires_at = $4, created_at = $5, updated_at = $5 WHERE tenant_id = $6 AND project_id = $7 AND actor = $8 AND operation_id = $9 AND idempotency_key = $10 AND state = 'completed' AND expires_at <= $5"
const selectRecordSQL = "SELECT request_fingerprint, owner_token, state, response_status, response_headers, response_json, audit_event_json, created_at FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND actor = $3 AND operation_id = $4 AND idempotency_key = $5"
const commitSideEffectSQL = "UPDATE idempotency_records SET state = 'side_effect_committed', response_status = $1, response_headers = $2, response_json = $3, audit_event_json = $4, updated_at = $5 WHERE tenant_id = $6 AND project_id = $7 AND actor = $8 AND operation_id = $9 AND idempotency_key = $10 AND request_fingerprint = $11 AND owner_token = $12 AND state = 'processing'"
const markAuditedSQL = "UPDATE idempotency_records SET state = 'audited', updated_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND actor = $4 AND operation_id = $5 AND idempotency_key = $6 AND request_fingerprint = $7 AND owner_token = $8 AND state = 'side_effect_committed'"
const completeClaimSQL = "UPDATE idempotency_records SET state = 'completed', updated_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND actor = $4 AND operation_id = $5 AND idempotency_key = $6 AND request_fingerprint = $7 AND owner_token = $8 AND state = 'audited'"
const abortClaimSQL = "DELETE FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND actor = $3 AND operation_id = $4 AND idempotency_key = $5 AND request_fingerprint = $6 AND owner_token = $7 AND state = 'processing'"

type PostgresStore struct{ database *sql.DB }

func NewPostgresStore(database *sql.DB) *PostgresStore {
	return &PostgresStore{database: database}
}

func (store *PostgresStore) Claim(ctx context.Context, request ClaimRequest) (Claim, error) {
	key, fingerprint, owner := request.Key, request.Fingerprint, request.OwnerToken
	now, expires := request.Now, request.ExpiresAt
	if store == nil || store.database == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || !ownerPattern.MatchString(owner) || now.IsZero() || !expires.After(now) || len(request.Reconciliation) > maximumReconciliationBytes || len(request.Reconciliation) != 0 && validateReconciliation(request.Reconciliation) != nil {
		return Claim{}, ErrInvalid
	}
	now, expires = now.UTC(), expires.UTC()
	var reconciliation any
	if len(request.Reconciliation) != 0 {
		reconciliation = string(request.Reconciliation)
	}
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Claim{}, fmt.Errorf("begin idempotency claim: %w", err)
	}
	rollback := func(cause error) (Claim, error) {
		_ = transaction.Rollback()
		return Claim{}, cause
	}
	inserted, err := transaction.ExecContext(ctx, insertClaimSQL, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, owner, reconciliation, expires, now)
	if err != nil {
		return rollback(fmt.Errorf("insert idempotency claim: %w", err))
	}
	rows, err := inserted.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("read idempotency insert result: %w", err))
	}
	if rows == 1 {
		if err := transaction.Commit(); err != nil {
			return Claim{}, fmt.Errorf("commit idempotency claim: %w", err)
		}
		return Claim{Claimed: true, OwnerToken: owner, State: StateProcessing, CreatedAt: now, Reconciliation: append([]byte(nil), request.Reconciliation...)}, nil
	}
	reclaimed, err := transaction.ExecContext(ctx, reclaimExpiredCompletedSQL, fingerprint, owner, reconciliation, expires, now, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey)
	if err != nil {
		return rollback(fmt.Errorf("reclaim expired idempotency key: %w", err))
	}
	rows, err = reclaimed.RowsAffected()
	if err != nil {
		return rollback(fmt.Errorf("read idempotency reclaim result: %w", err))
	}
	if rows == 1 {
		if err := transaction.Commit(); err != nil {
			return Claim{}, fmt.Errorf("commit reclaimed idempotency key: %w", err)
		}
		return Claim{Claimed: true, OwnerToken: owner, State: StateProcessing, CreatedAt: now, Reconciliation: append([]byte(nil), request.Reconciliation...)}, nil
	}
	record, err := scanClaim(transaction.QueryRowContext(ctx, selectRecordSQL, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrNotClaimed)
		}
		return rollback(fmt.Errorf("read existing idempotency key: %w", err))
	}
	if err := transaction.Commit(); err != nil {
		return Claim{}, fmt.Errorf("commit idempotency lookup: %w", err)
	}
	if record.fingerprint != fingerprint {
		return Claim{}, ErrKeyConflict
	}
	switch record.state {
	case StateProcessing:
		if !request.RecoverProcessing {
			return Claim{}, ErrInProgress
		}
		return Claim{OwnerToken: record.owner, State: record.state, CreatedAt: record.createdAt.UTC(), Reconciliation: append([]byte(nil), record.reconciliation...)}, nil
	case StateSideEffectCommitted, StateAudited:
		response := cloneResponse(record.response)
		return Claim{OwnerToken: record.owner, State: record.state, Response: &response, Reconciliation: append([]byte(nil), record.reconciliation...)}, nil
	case StateCompleted:
		response := cloneResponse(record.response)
		return Claim{State: StateCompleted, Response: &response}, nil
	default:
		return Claim{}, ErrNotClaimed
	}
}

func (store *PostgresStore) CommitSideEffect(ctx context.Context, key Key, fingerprint, owner string, response Response, reconciliation []byte, at time.Time) (Response, error) {
	if store == nil || store.database == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || !ownerPattern.MatchString(owner) || validateResponse(response) != nil || validateReconciliation(reconciliation) != nil || at.IsZero() {
		return Response{}, ErrInvalid
	}
	headerJSON, err := json.Marshal(response.Header)
	if err != nil {
		return Response{}, ErrInvalid
	}
	at = at.UTC()
	result, err := store.database.ExecContext(ctx, commitSideEffectSQL, response.Status, string(headerJSON), response.Body, string(reconciliation), at, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, owner)
	if err != nil {
		return Response{}, fmt.Errorf("commit idempotency side effect: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Response{}, fmt.Errorf("read idempotency side-effect result: %w", err)
	}
	if rows != 1 {
		return Response{}, ErrOwnershipConflict
	}
	return cloneResponse(response), nil
}

func (store *PostgresStore) MarkAudited(ctx context.Context, key Key, fingerprint, owner string, at time.Time) error {
	if store == nil || store.database == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || !ownerPattern.MatchString(owner) || at.IsZero() {
		return ErrInvalid
	}
	result, err := store.database.ExecContext(ctx, markAuditedSQL, at.UTC(), key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, owner)
	if err != nil {
		return fmt.Errorf("mark idempotency audit: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read idempotency audit result: %w", err)
	}
	if rows != 1 {
		return ErrOwnershipConflict
	}
	return nil
}

func (store *PostgresStore) Complete(ctx context.Context, key Key, fingerprint, owner string, response Response, at time.Time) (Response, error) {
	if store == nil || store.database == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || !ownerPattern.MatchString(owner) || validateResponse(response) != nil || at.IsZero() {
		return Response{}, ErrInvalid
	}
	result, err := store.database.ExecContext(ctx, completeClaimSQL, at.UTC(), key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, owner)
	if err != nil {
		return Response{}, fmt.Errorf("complete idempotency claim: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Response{}, fmt.Errorf("read idempotency completion result: %w", err)
	}
	if rows != 1 {
		return Response{}, ErrOwnershipConflict
	}
	return cloneResponse(response), nil
}

func (store *PostgresStore) Abort(ctx context.Context, key Key, fingerprint, owner string) error {
	if store == nil || store.database == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || !ownerPattern.MatchString(owner) {
		return ErrInvalid
	}
	result, err := store.database.ExecContext(ctx, abortClaimSQL, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, owner)
	if err != nil {
		return fmt.Errorf("abort idempotency claim: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read idempotency abort result: %w", err)
	}
	if rows != 1 {
		return ErrOwnershipConflict
	}
	return nil
}

type storedClaim struct {
	fingerprint    string
	owner          string
	state          State
	response       Response
	reconciliation []byte
	createdAt      time.Time
}

func scanClaim(scanner interface{ Scan(...any) error }) (storedClaim, error) {
	var value storedClaim
	var headerJSON []byte
	if err := scanner.Scan(&value.fingerprint, &value.owner, &value.state, &value.response.Status, &headerJSON, &value.response.Body, &value.reconciliation, &value.createdAt); err != nil {
		return storedClaim{}, err
	}
	value.createdAt = value.createdAt.UTC()
	if value.createdAt.IsZero() {
		return storedClaim{}, ErrInvalid
	}
	if value.state == StateSideEffectCommitted || value.state == StateAudited || value.state == StateCompleted {
		var storedHeader http.Header
		if err := json.Unmarshal(headerJSON, &storedHeader); err != nil {
			return storedClaim{}, ErrInvalid
		}
		value.response.Header = make(http.Header, len(storedHeader))
		for name, values := range storedHeader {
			for _, item := range values {
				value.response.Header.Add(name, item)
			}
		}
		if validateResponse(value.response) != nil {
			return storedClaim{}, ErrInvalid
		}
		if value.state != StateCompleted && validateReconciliation(value.reconciliation) != nil {
			return storedClaim{}, ErrInvalid
		}
	}
	return value, nil
}

var _ Store = (*PostgresStore)(nil)
