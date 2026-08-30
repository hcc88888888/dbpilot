package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"dbpilot.local/platform/internal/hostinventory"
	"github.com/lib/pq"
)

const createEnrollmentTokenSQL = `INSERT INTO agent_enrollment_tokens (
    token_hash, tenant_id, project_id, host_id, agent_id, display_name, labels,
    expires_at, created_at, enrollment_revision, issued_by, idempotency_key, request_fingerprint, generation
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
RETURNING token_hash, generation`

const findEnrollmentTokenReplacementSQL = `SELECT token_hash, consumed_at, generation
FROM agent_enrollment_tokens
WHERE tenant_id = $1 AND project_id = $2 AND host_id = $3 AND agent_id = $4
  AND consumed_at IS NULL
FOR UPDATE`

const replaceEnrollmentTokenSQL = `UPDATE agent_enrollment_tokens SET
    token_hash = $1, host_id = $2, agent_id = $3, display_name = $4, labels = $5,
    expires_at = $6, created_at = $7, enrollment_revision = $8, generation = $9,
    issued_by = $10, idempotency_key = $11, request_fingerprint = $12
WHERE token_hash = $13 AND generation = $14 AND consumed_at IS NULL
RETURNING token_hash, generation`

const resolveEnrollmentSQL = `SELECT
    t.tenant_id, t.project_id, t.host_id, t.agent_id, t.display_name, t.labels, t.enrollment_revision,
    t.consumed_at, (t.expires_at > CURRENT_TIMESTAMP) AS active,
    i.csr_digest, i.certificate_pem, i.certificate_chain_pem, i.expires_at, i.issued_at, i.enrollment_revision
FROM agent_enrollment_tokens t
LEFT JOIN agent_enrollment_issuances i ON i.token_hash = t.token_hash
WHERE t.token_hash = $1`

const insertIssuanceSQL = `INSERT INTO agent_enrollment_issuances (
    token_hash, csr_digest, tenant_id, project_id, host_id, agent_id,
    certificate_pem, certificate_chain_pem, expires_at, issued_at, enrollment_revision
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

const consumeCommittedTokenSQL = `UPDATE agent_enrollment_tokens
SET consumed_at = CURRENT_TIMESTAMP
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > CURRENT_TIMESTAMP`

const insertEnrollmentAuditSQL = `INSERT INTO audit_events (
    id, tenant_id, project_id, occurred_at, action, actor_type, actor_id,
    resource_type, resource_id, result, request_id, trace_id, job_id, command_id,
    dedupe_key, detail, created_at
) VALUES ($1, $2, $3, $4, $5, 'user', $6, 'host', $7, 'success', $8, $9, '', '', $10, $11, $4)`

type postgresDatabase interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

type enrollmentRowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type PostgresRepository struct{ database postgresDatabase }

func NewPostgresRepository(database postgresDatabase) *PostgresRepository {
	return &PostgresRepository{database: database}
}

func (repository *PostgresRepository) Create(ctx context.Context, token EnrollmentToken) (EnrollmentTokenCreation, error) {
	if repository == nil || repository.database == nil || ctx == nil || token.Validate() != nil {
		return EnrollmentTokenCreation{}, ErrEnrollmentRequestInvalid
	}
	labels, err := json.Marshal(token.Labels)
	if err != nil {
		return EnrollmentTokenCreation{}, ErrEnrollmentRequestInvalid
	}
	transaction, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EnrollmentTokenCreation{}, err
	}
	rollback := func() { _ = transaction.Rollback() }
	var existingHash []byte
	var consumedAt sql.NullTime
	var generation int64
	err = transaction.QueryRowContext(ctx, findEnrollmentTokenReplacementSQL, token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID).Scan(&existingHash, &consumedAt, &generation)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		generation = 1
		err = transaction.QueryRowContext(ctx, createEnrollmentTokenSQL,
			token.TokenHash[:], token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID,
			token.DisplayName, labels, token.ExpiresAt, token.CreatedAt, token.EnrollmentRevision,
			token.IssuedBy, token.IdempotencyKey, token.RequestFingerprint, generation,
		).Scan(&existingHash, &generation)
	case err != nil:
		rollback()
		return EnrollmentTokenCreation{}, mapPostgresError(err)
	default:
		rollback()
		return EnrollmentTokenCreation{}, ErrEnrollmentConflict
	}
	if err != nil {
		rollback()
		return EnrollmentTokenCreation{}, mapPostgresError(err)
	}
	if !bytes.Equal(existingHash, token.TokenHash[:]) || generation < 1 {
		rollback()
		return EnrollmentTokenCreation{}, ErrEnrollmentRequestInvalid
	}
	if err := insertEnrollmentAudit(ctx, transaction, token, uint64(generation), false); err != nil {
		rollback()
		return EnrollmentTokenCreation{}, err
	}
	if err := transaction.Commit(); err != nil {
		return EnrollmentTokenCreation{}, err
	}
	return EnrollmentTokenCreation{Generation: uint64(generation)}, nil
}

func (repository *PostgresRepository) Replace(ctx context.Context, token EnrollmentToken, expectedGeneration uint64) (EnrollmentTokenCreation, error) {
	if repository == nil || repository.database == nil || ctx == nil || token.Validate() != nil || expectedGeneration == 0 {
		return EnrollmentTokenCreation{}, ErrEnrollmentRequestInvalid
	}
	labels, err := json.Marshal(token.Labels)
	if err != nil {
		return EnrollmentTokenCreation{}, ErrEnrollmentRequestInvalid
	}
	transaction, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EnrollmentTokenCreation{}, err
	}
	rollback := func() { _ = transaction.Rollback() }
	var existingHash []byte
	var consumedAt sql.NullTime
	var generation int64
	err = transaction.QueryRowContext(ctx, findEnrollmentTokenReplacementSQL, token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID).Scan(&existingHash, &consumedAt, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		rollback()
		return EnrollmentTokenCreation{}, ErrEnrollmentNotFound
	}
	if err != nil {
		rollback()
		return EnrollmentTokenCreation{}, mapPostgresError(err)
	}
	if consumedAt.Valid || generation < 1 {
		rollback()
		return EnrollmentTokenCreation{}, ErrEnrollmentConflict
	}
	if uint64(generation) != expectedGeneration {
		rollback()
		return EnrollmentTokenCreation{}, ErrEnrollmentGenerationConflict
	}
	generation++
	err = transaction.QueryRowContext(ctx, replaceEnrollmentTokenSQL,
		token.TokenHash[:], token.HostID, token.AgentID, token.DisplayName, labels, token.ExpiresAt, token.CreatedAt,
		token.EnrollmentRevision, generation, token.IssuedBy, token.IdempotencyKey, token.RequestFingerprint, existingHash, expectedGeneration,
	).Scan(&existingHash, &generation)
	if err != nil {
		rollback()
		return EnrollmentTokenCreation{}, mapPostgresError(err)
	}
	if !bytes.Equal(existingHash, token.TokenHash[:]) || generation < 2 {
		rollback()
		return EnrollmentTokenCreation{}, ErrEnrollmentRequestInvalid
	}
	if err := insertEnrollmentAudit(ctx, transaction, token, uint64(generation), true); err != nil {
		rollback()
		return EnrollmentTokenCreation{}, err
	}
	if err := transaction.Commit(); err != nil {
		return EnrollmentTokenCreation{}, err
	}
	return EnrollmentTokenCreation{Generation: uint64(generation), Replaced: true}, nil
}

func insertEnrollmentAudit(ctx context.Context, transaction *sql.Tx, token EnrollmentToken, generation uint64, replaced bool) error {
	action := "host.enrollment_created"
	if replaced {
		action = "host.enrollment_replaced"
	}
	identity := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d", token.Scope.Key(), token.Audit.Actor, token.Audit.OperationID, token.Audit.IdempotencyKey, generation)
	digest := sha256.Sum256([]byte(identity))
	hexDigest := hex.EncodeToString(digest[:])
	detail, err := json.Marshal(map[string]any{"operation_id": token.Audit.OperationID, "generation": generation})
	if err != nil {
		return ErrEnrollmentRequestInvalid
	}
	_, err = transaction.ExecContext(ctx, insertEnrollmentAuditSQL,
		"audit-enrollment-"+hexDigest, token.Scope.TenantID, token.Scope.ProjectID, token.CreatedAt, action,
		token.Audit.Actor, token.HostID, token.Audit.RequestID, token.Audit.TraceID,
		"host.enrollment:"+hexDigest, detail,
	)
	if err != nil {
		return fmt.Errorf("record enrollment Audit: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) Resolve(ctx context.Context, key EnrollmentAttemptKey) (EnrollmentResolution, error) {
	if repository == nil || repository.database == nil || ctx == nil || key.Validate() != nil {
		return EnrollmentResolution{}, ErrEnrollmentRequestInvalid
	}
	return resolveEnrollment(ctx, repository.database, resolveEnrollmentSQL, key)
}

func (repository *PostgresRepository) Complete(ctx context.Context, completion EnrollmentCompletion) (EnrollResult, error) {
	if repository == nil || repository.database == nil || ctx == nil || completion.Key.Validate() != nil || completion.Grant.Validate() != nil ||
		completion.Observation.Validate() != nil || !validUTC(completion.CompletedAt) || validateEnrollmentResult(completion.Result, completion.Grant) != nil ||
		completion.Key.AgentID != completion.Grant.AgentID || completion.Key.HostID != completion.Grant.HostID ||
		completion.Observation.AgentID != completion.Grant.AgentID || completion.Observation.HostID != completion.Grant.HostID {
		return EnrollResult{}, ErrEnrollmentRequestInvalid
	}
	transaction, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EnrollResult{}, fmt.Errorf("begin enrollment completion: %w", err)
	}
	rollback := func() { _ = transaction.Rollback() }
	resolution, err := resolveEnrollment(ctx, transaction, resolveEnrollmentSQL+" FOR UPDATE OF t", completion.Key)
	if err != nil {
		rollback()
		return EnrollResult{}, err
	}
	if resolution.Response != nil {
		rollback()
		return cloneEnrollmentResult(*resolution.Response), nil
	}
	if !enrollmentGrantsEqual(resolution.Grant, completion.Grant) {
		rollback()
		return EnrollResult{}, ErrEnrollmentTokenInvalid
	}
	hostRepository := hostinventory.NewPostgresRepository(transaction)
	if _, err := hostRepository.RecordEnrollment(ctx, completion.Grant.Scope, hostinventory.Enrollment{
		HostID: completion.Grant.HostID, AgentID: completion.Grant.AgentID, DisplayName: completion.Grant.DisplayName,
		Labels: completion.Grant.Labels, Revision: completion.Grant.EnrollmentRevision, EnrolledAt: completion.CompletedAt,
	}, completion.Observation, completion.CompletedAt); err != nil {
		rollback()
		return EnrollResult{}, fmt.Errorf("record enrolled Host: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, insertIssuanceSQL,
		completion.Key.TokenHash[:], completion.Key.CSRDigest[:], completion.Grant.Scope.TenantID, completion.Grant.Scope.ProjectID,
		completion.Grant.HostID, completion.Grant.AgentID, completion.Result.CertificatePEM, completion.Result.CertificateChainPEM,
		completion.Result.ExpiresAt, completion.CompletedAt, completion.Grant.EnrollmentRevision,
	); err != nil {
		rollback()
		return EnrollResult{}, mapPostgresError(err)
	}
	consumed, err := transaction.ExecContext(ctx, consumeCommittedTokenSQL, completion.Key.TokenHash[:])
	if err != nil {
		rollback()
		return EnrollResult{}, mapPostgresError(err)
	}
	rows, err := consumed.RowsAffected()
	if err != nil || rows != 1 {
		rollback()
		return EnrollResult{}, ErrEnrollmentTokenInvalid
	}
	if err := transaction.Commit(); err != nil {
		return EnrollResult{}, fmt.Errorf("commit enrollment completion: %w", err)
	}
	return cloneEnrollmentResult(completion.Result), nil
}

func enrollmentGrantsEqual(first, second EnrollmentGrant) bool {
	if first.Scope != second.Scope || first.HostID != second.HostID || first.AgentID != second.AgentID || first.DisplayName != second.DisplayName || first.EnrollmentRevision != second.EnrollmentRevision || len(first.Labels) != len(second.Labels) {
		return false
	}
	for key, value := range first.Labels {
		if second.Labels[key] != value {
			return false
		}
	}
	return true
}

func resolveEnrollment(ctx context.Context, querier enrollmentRowQuerier, query string, key EnrollmentAttemptKey) (EnrollmentResolution, error) {
	var grant EnrollmentGrant
	var labels []byte
	var revision int64
	var consumedAt sql.NullTime
	var active bool
	var issuanceDigest, certificatePEM, chainPEM []byte
	var issuanceExpiresAt, issuedAt sql.NullTime
	var issuanceRevision sql.NullInt64
	err := querier.QueryRowContext(ctx, query, key.TokenHash[:]).Scan(
		&grant.Scope.TenantID, &grant.Scope.ProjectID, &grant.HostID, &grant.AgentID, &grant.DisplayName, &labels, &revision,
		&consumedAt, &active, &issuanceDigest, &certificatePEM, &chainPEM, &issuanceExpiresAt, &issuedAt, &issuanceRevision,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentResolution{}, ErrEnrollmentTokenInvalid
	}
	if err != nil {
		return EnrollmentResolution{}, mapPostgresError(err)
	}
	if revision < 1 || json.Unmarshal(labels, &grant.Labels) != nil {
		return EnrollmentResolution{}, ErrEnrollmentRequestInvalid
	}
	grant.EnrollmentRevision = uint64(revision)
	if grant.Validate() != nil || grant.AgentID != key.AgentID || (key.HostID != "" && grant.HostID != key.HostID) {
		return EnrollmentResolution{}, ErrEnrollmentTokenInvalid
	}
	if len(issuanceDigest) != 0 {
		if len(issuanceDigest) != len(key.CSRDigest) || !bytes.Equal(issuanceDigest, key.CSRDigest[:]) || !consumedAt.Valid ||
			len(certificatePEM) == 0 || len(chainPEM) == 0 || !issuanceExpiresAt.Valid || !issuedAt.Valid || !issuanceRevision.Valid || issuanceRevision.Int64 < 1 {
			return EnrollmentResolution{}, ErrEnrollmentTokenInvalid
		}
		response := EnrollResult{
			HostID: grant.HostID, AgentID: grant.AgentID, CertificatePEM: append([]byte(nil), certificatePEM...),
			CertificateChainPEM: append([]byte(nil), chainPEM...), ExpiresAt: issuanceExpiresAt.Time.UTC(),
			EnrollmentRevision: uint64(issuanceRevision.Int64),
		}
		if validateEnrollmentResult(response, grant) != nil {
			return EnrollmentResolution{}, ErrEnrollmentRequestInvalid
		}
		return EnrollmentResolution{Grant: grant, Response: &response}, nil
	}
	if consumedAt.Valid || !active {
		return EnrollmentResolution{}, ErrEnrollmentTokenInvalid
	}
	return EnrollmentResolution{Grant: grant}, nil
}

func mapPostgresError(err error) error {
	var postgresError *pq.Error
	if !errors.As(err, &postgresError) {
		return err
	}
	switch postgresError.Code {
	case "40001":
		return ErrEnrollmentGenerationConflict
	case "23505", "23503":
		return ErrEnrollmentConflict
	case "23502", "23514", "22P02", "22001":
		return ErrEnrollmentRequestInvalid
	default:
		return err
	}
}

var _ EnrollmentStore = (*PostgresRepository)(nil)
