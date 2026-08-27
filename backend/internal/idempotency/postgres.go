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

const insertClaimSQL = "INSERT INTO idempotency_records (tenant_id, project_id, actor, operation_id, idempotency_key, request_fingerprint, state, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, 'processing', $7, $8, $8) ON CONFLICT (tenant_id, project_id, actor, operation_id, idempotency_key) DO NOTHING"
const reclaimExpiredSQL = "UPDATE idempotency_records SET request_fingerprint = $1, state = 'processing', response_status = 0, response_headers = '{}'::jsonb, response_json = NULL, expires_at = $2, updated_at = $3 WHERE tenant_id = $4 AND project_id = $5 AND actor = $6 AND operation_id = $7 AND idempotency_key = $8 AND expires_at <= $3"
const selectRecordSQL = "SELECT request_fingerprint, state, response_status, response_headers, response_json FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND actor = $3 AND operation_id = $4 AND idempotency_key = $5"
const completeClaimSQL = "UPDATE idempotency_records SET state = 'completed', response_status = $1, response_headers = $2, response_json = $3, updated_at = $4 WHERE tenant_id = $5 AND project_id = $6 AND actor = $7 AND operation_id = $8 AND idempotency_key = $9 AND request_fingerprint = $10 AND state = 'processing' AND expires_at > $11"
const abortClaimSQL = "DELETE FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND actor = $3 AND operation_id = $4 AND idempotency_key = $5 AND request_fingerprint = $6 AND state = 'processing'"

type PostgresStore struct{ database *sql.DB }

func NewPostgresStore(database *sql.DB) *PostgresStore {
	return &PostgresStore{database: database}
}

func (store *PostgresStore) Claim(ctx context.Context, key Key, fingerprint string, now, expires time.Time) (Claim, error) {
	if store == nil || store.database == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || now.IsZero() || !expires.After(now) {
		return Claim{}, ErrInvalid
	}
	now, expires = now.UTC(), expires.UTC()
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return Claim{}, fmt.Errorf("begin idempotency claim: %w", err)
	}
	rollback := func(cause error) (Claim, error) {
		_ = transaction.Rollback()
		return Claim{}, cause
	}
	inserted, err := transaction.ExecContext(ctx, insertClaimSQL, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, expires, now)
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
		return Claim{Claimed: true}, nil
	}
	reclaimed, err := transaction.ExecContext(ctx, reclaimExpiredSQL, fingerprint, expires, now, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey)
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
		return Claim{Claimed: true}, nil
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
		return Claim{}, ErrInProgress
	case StateCompleted:
		response := cloneResponse(record.response)
		return Claim{Response: &response}, nil
	default:
		return Claim{}, ErrNotClaimed
	}
}

func (store *PostgresStore) Complete(ctx context.Context, key Key, fingerprint string, response Response, at time.Time) (Response, error) {
	if store == nil || store.database == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) || validateResponse(response) != nil || at.IsZero() {
		return Response{}, ErrInvalid
	}
	headerJSON, err := json.Marshal(response.Header)
	if err != nil {
		return Response{}, ErrInvalid
	}
	at = at.UTC()
	result, err := store.database.ExecContext(ctx, completeClaimSQL, response.Status, string(headerJSON), response.Body, at, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint, at)
	if err != nil {
		return Response{}, fmt.Errorf("complete idempotency claim: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return Response{}, fmt.Errorf("read idempotency completion result: %w", err)
	}
	if rows != 1 {
		return Response{}, ErrNotClaimed
	}
	return cloneResponse(response), nil
}

func (store *PostgresStore) Abort(ctx context.Context, key Key, fingerprint string) error {
	if store == nil || store.database == nil || ctx == nil || validateKey(key) != nil || !fingerprintPattern.MatchString(fingerprint) {
		return ErrInvalid
	}
	_, err := store.database.ExecContext(ctx, abortClaimSQL, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey, fingerprint)
	if err != nil {
		return fmt.Errorf("abort idempotency claim: %w", err)
	}
	return nil
}

type storedClaim struct {
	fingerprint string
	state       State
	response    Response
}

func scanClaim(scanner interface{ Scan(...any) error }) (storedClaim, error) {
	var value storedClaim
	var headerJSON []byte
	if err := scanner.Scan(&value.fingerprint, &value.state, &value.response.Status, &headerJSON, &value.response.Body); err != nil {
		return storedClaim{}, err
	}
	if value.state == StateCompleted {
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
	}
	return value, nil
}

var _ Store = (*PostgresStore)(nil)
