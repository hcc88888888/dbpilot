package enrollment

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/lib/pq"
)

const createEnrollmentTokenSQL = `INSERT INTO agent_enrollment_tokens (
    token_hash, tenant_id, project_id, host_id, agent_id, display_name, labels,
    expires_at, created_at, enrollment_revision, issued_by, idempotency_key
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING token_hash`

const consumeEnrollmentTokenSQL = `UPDATE agent_enrollment_tokens SET consumed_at = $2
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
RETURNING tenant_id, project_id, host_id, agent_id, display_name, labels, enrollment_revision`

type postgresQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type PostgresRepository struct{ database postgresQuerier }

func NewPostgresRepository(database postgresQuerier) *PostgresRepository {
	return &PostgresRepository{database: database}
}

func (repository *PostgresRepository) Create(ctx context.Context, token EnrollmentToken) error {
	if repository == nil || repository.database == nil || ctx == nil || token.Validate() != nil {
		return ErrEnrollmentRequestInvalid
	}
	labels, err := json.Marshal(token.Labels)
	if err != nil {
		return ErrEnrollmentRequestInvalid
	}
	var storedHash []byte
	err = repository.database.QueryRowContext(ctx, createEnrollmentTokenSQL,
		token.TokenHash[:], token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID,
		token.DisplayName, labels, token.ExpiresAt, token.CreatedAt, token.EnrollmentRevision,
		token.IssuedBy, token.IdempotencyKey,
	).Scan(&storedHash)
	if err != nil {
		return mapPostgresError(err)
	}
	if !bytes.Equal(storedHash, token.TokenHash[:]) {
		return ErrEnrollmentRequestInvalid
	}
	return nil
}

func (repository *PostgresRepository) Consume(ctx context.Context, hash [32]byte, now time.Time) (EnrollmentGrant, error) {
	if repository == nil || repository.database == nil || ctx == nil || hash == ([32]byte{}) || !validUTC(now) {
		return EnrollmentGrant{}, ErrEnrollmentRequestInvalid
	}
	var grant EnrollmentGrant
	var labels []byte
	var revision int64
	err := repository.database.QueryRowContext(ctx, consumeEnrollmentTokenSQL, hash[:], now).Scan(
		&grant.Scope.TenantID, &grant.Scope.ProjectID, &grant.HostID, &grant.AgentID,
		&grant.DisplayName, &labels, &revision,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentGrant{}, ErrEnrollmentTokenInvalid
	}
	if err != nil {
		return EnrollmentGrant{}, mapPostgresError(err)
	}
	if revision < 1 || json.Unmarshal(labels, &grant.Labels) != nil {
		return EnrollmentGrant{}, ErrEnrollmentRequestInvalid
	}
	grant.EnrollmentRevision = uint64(revision)
	if grant.Validate() != nil {
		return EnrollmentGrant{}, ErrEnrollmentRequestInvalid
	}
	return grant, nil
}

func mapPostgresError(err error) error {
	var postgresError *pq.Error
	if !errors.As(err, &postgresError) {
		return err
	}
	switch postgresError.Code {
	case "23505", "23503":
		return ErrEnrollmentConflict
	case "23502", "23514", "22P02", "22001":
		return ErrEnrollmentRequestInvalid
	default:
		return err
	}
}

var _ TokenStore = (*PostgresRepository)(nil)
