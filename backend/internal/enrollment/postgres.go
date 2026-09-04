package enrollment

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformscope"
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
ORDER BY generation DESC
LIMIT 1
FOR UPDATE`

const replaceEnrollmentTokenSQL = `UPDATE agent_enrollment_tokens SET
    token_hash = $1, host_id = $2, agent_id = $3, display_name = $4, labels = $5,
    expires_at = $6, created_at = $7, enrollment_revision = $8, generation = $9,
    issued_by = $10, idempotency_key = $11, request_fingerprint = $12
WHERE token_hash = $13 AND generation = $14 AND consumed_at IS NULL
RETURNING token_hash, generation`

const resolveReplacementSQL = `SELECT enrollment_revision, generation
FROM agent_enrollment_tokens
WHERE tenant_id = $1 AND project_id = $2 AND host_id = $3 AND agent_id = $4
  AND issued_by = $5 AND idempotency_key = $6 AND request_fingerprint = $7`

const resolveEnrollmentSQL = `SELECT
    t.tenant_id, t.project_id, t.host_id, t.agent_id, t.display_name, t.labels, t.enrollment_revision,
	    t.consumed_at, (t.expires_at > CURRENT_TIMESTAMP) AS active, t.generation,
	    i.csr_digest, i.certificate_pem, i.certificate_chain_pem, i.expires_at, i.issued_at, i.enrollment_revision,
	    i.credential_generation, i.certificate_fingerprint, i.certificate_serial, i.revoked_at,
	    h.status, h.credential_generation, h.active_certificate_fingerprint, h.active_certificate_serial, h.credential_revoked_at
FROM agent_enrollment_tokens t
LEFT JOIN agent_enrollment_issuances i ON i.token_hash = t.token_hash
LEFT JOIN managed_hosts h ON h.tenant_id=t.tenant_id AND h.project_id=t.project_id AND h.host_id=t.host_id AND h.agent_id=t.agent_id
WHERE t.token_hash = $1`

const resolveSupersededCredentialsSQL = `SELECT credential_generation,certificate_fingerprint,certificate_serial FROM (
    SELECT credential_generation,certificate_fingerprint,certificate_serial
    FROM agent_enrollment_issuances
    WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 AND agent_id=$4
      AND credential_generation<$5 AND revoked_at IS NOT NULL
    UNION ALL
    SELECT credential_generation,certificate_fingerprint,certificate_serial
    FROM agent_credential_imports
    WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 AND agent_id=$4
      AND credential_generation<$5
) credentials
ORDER BY credential_generation DESC`

const insertIssuanceSQL = `INSERT INTO agent_enrollment_issuances (
    token_hash, csr_digest, tenant_id, project_id, host_id, agent_id,
	    certificate_pem, certificate_chain_pem, expires_at, issued_at, enrollment_revision
	    , credential_generation, certificate_fingerprint, certificate_serial
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`

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
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	BeginTx(context.Context, *sql.TxOptions) (*sql.Tx, error)
}

type enrollmentRowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type generationZeroImportTarget struct {
	scope  platformscope.Scope
	hostID string
}

type PostgresRepository struct {
	database              postgresDatabase
	generationZeroMu      sync.RWMutex
	generationZeroImports map[string]generationZeroImportTarget
}

func NewPostgresRepository(database postgresDatabase) *PostgresRepository {
	return &PostgresRepository{database: database}
}

func (repository *PostgresRepository) ConfigureGenerationZeroImport(agentID string, scope platformscope.Scope, hostID string) error {
	if repository == nil || repository.database == nil || !identifierPattern.MatchString(agentID) || scope.Validate() != nil || !identifierPattern.MatchString(hostID) {
		return ErrEnrollmentRequestInvalid
	}
	target := generationZeroImportTarget{scope: scope, hostID: hostID}
	repository.generationZeroMu.Lock()
	defer repository.generationZeroMu.Unlock()
	if repository.generationZeroImports == nil {
		repository.generationZeroImports = make(map[string]generationZeroImportTarget)
	}
	if existing, ok := repository.generationZeroImports[agentID]; ok && existing != target {
		return ErrEnrollmentConflict
	}
	repository.generationZeroImports[agentID] = target
	return nil
}

func (repository *PostgresRepository) ValidateGenerationZeroImports(ctx context.Context) error {
	if repository == nil || repository.database == nil || ctx == nil {
		return ErrEnrollmentRequestInvalid
	}
	repository.generationZeroMu.RLock()
	targets := make(map[string]generationZeroImportTarget, len(repository.generationZeroImports))
	for agentID, target := range repository.generationZeroImports {
		targets[agentID] = target
	}
	repository.generationZeroMu.RUnlock()
	for agentID, target := range targets {
		var status string
		var generation int64
		var fingerprint []byte
		var serial string
		var revokedAt sql.NullTime
		var imported, issued bool
		err := repository.database.QueryRowContext(ctx, `SELECT host.status,host.credential_generation,host.active_certificate_fingerprint,host.active_certificate_serial,host.credential_revoked_at,EXISTS(SELECT 1 FROM agent_credential_imports imported WHERE imported.tenant_id=host.tenant_id AND imported.project_id=host.project_id AND imported.host_id=host.host_id AND imported.agent_id=host.agent_id),EXISTS(SELECT 1 FROM agent_enrollment_issuances issuance WHERE issuance.tenant_id=host.tenant_id AND issuance.project_id=host.project_id AND issuance.host_id=host.host_id AND issuance.agent_id=host.agent_id) FROM managed_hosts host WHERE host.tenant_id=$1 AND host.project_id=$2 AND host.host_id=$3 AND host.agent_id=$4`, target.scope.TenantID, target.scope.ProjectID, target.hostID, agentID).Scan(&status, &generation, &fingerprint, &serial, &revokedAt, &imported, &issued)
		generationZero := err == nil && status != string(hostinventory.HostDecommissioned) && generation == 0 && len(fingerprint) == 0 && serial == "" && !revokedAt.Valid && !imported && !issued
		persistedImport := err == nil && status != string(hostinventory.HostDecommissioned) && generation == 1 && len(fingerprint) == sha256.Size && certificateSerialPattern.MatchString(serial) && !revokedAt.Valid && imported && !issued
		if !generationZero && !persistedImport {
			return ErrEnrollmentRequestInvalid
		}
	}
	return nil
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
		var status, serial string
		var fingerprint []byte
		var revokedAt sql.NullTime
		var imported bool
		err = transaction.QueryRowContext(ctx, `SELECT host.status,host.credential_generation,host.active_certificate_fingerprint,host.active_certificate_serial,host.credential_revoked_at,EXISTS(SELECT 1 FROM agent_credential_imports imported WHERE imported.tenant_id=host.tenant_id AND imported.project_id=host.project_id AND imported.host_id=host.host_id AND imported.agent_id=host.agent_id AND imported.credential_generation=host.credential_generation AND imported.certificate_fingerprint=host.active_certificate_fingerprint AND imported.certificate_serial=host.active_certificate_serial) FROM managed_hosts host WHERE host.tenant_id=$1 AND host.project_id=$2 AND host.host_id=$3 AND host.agent_id=$4 FOR UPDATE`, token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID).Scan(&status, &generation, &fingerprint, &serial, &revokedAt, &imported)
		if err != nil || status == string(hostinventory.HostDecommissioned) || generation != 1 || expectedGeneration != 1 || len(fingerprint) != sha256.Size || !certificateSerialPattern.MatchString(serial) || revokedAt.Valid || !imported {
			rollback()
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return EnrollmentTokenCreation{}, mapPostgresError(err)
			}
			return EnrollmentTokenCreation{}, ErrEnrollmentNotFound
		}
		consumedAt.Valid = true
	}
	if err != nil {
		rollback()
		return EnrollmentTokenCreation{}, mapPostgresError(err)
	}
	if generation < 1 {
		rollback()
		return EnrollmentTokenCreation{}, ErrEnrollmentConflict
	}
	if uint64(generation) != expectedGeneration {
		rollback()
		return EnrollmentTokenCreation{}, ErrEnrollmentGenerationConflict
	}
	generation++
	if consumedAt.Valid {
		err = transaction.QueryRowContext(ctx, createEnrollmentTokenSQL,
			token.TokenHash[:], token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID,
			token.DisplayName, labels, token.ExpiresAt, token.CreatedAt, token.EnrollmentRevision,
			token.IssuedBy, token.IdempotencyKey, token.RequestFingerprint, generation,
		).Scan(&existingHash, &generation)
	} else {
		err = transaction.QueryRowContext(ctx, replaceEnrollmentTokenSQL,
			token.TokenHash[:], token.HostID, token.AgentID, token.DisplayName, labels, token.ExpiresAt, token.CreatedAt,
			token.EnrollmentRevision, generation, token.IssuedBy, token.IdempotencyKey, token.RequestFingerprint, existingHash, expectedGeneration,
		).Scan(&existingHash, &generation)
	}
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

func (repository *PostgresRepository) ResolveReplacement(ctx context.Context, scope platformscope.Scope, request ReplacementLookup) (ReplacementState, error) {
	if repository == nil || repository.database == nil || ctx == nil || scope.Validate() != nil || request.Validate() != nil {
		return ReplacementState{}, ErrEnrollmentRequestInvalid
	}
	state := ReplacementState{HostID: request.HostID, AgentID: request.AgentID}
	var revision, generation int64
	err := repository.database.QueryRowContext(ctx, resolveReplacementSQL,
		scope.TenantID, scope.ProjectID, request.HostID, request.AgentID, request.IssuedBy, request.IdempotencyKey, request.RequestFingerprint,
	).Scan(&revision, &generation)
	if errors.Is(err, sql.ErrNoRows) {
		return ReplacementState{}, ErrEnrollmentNotFound
	}
	if err != nil {
		return ReplacementState{}, mapPostgresError(err)
	}
	if revision < 1 || generation < 1 {
		return ReplacementState{}, ErrEnrollmentRequestInvalid
	}
	state.EnrollmentRevision, state.Generation = uint64(revision), uint64(generation)
	return state, nil
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
	transaction, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return EnrollmentResolution{}, err
	}
	rollback := func() { _ = transaction.Rollback() }
	resolution, err := resolveEnrollment(ctx, transaction, resolveEnrollmentSQL, key)
	if err != nil {
		rollback()
		return EnrollmentResolution{}, err
	}
	if resolution.Response != nil {
		resolution.SupersededCredentials, err = loadSupersededCredentials(ctx, transaction, resolution.Grant)
		if err != nil {
			rollback()
			return EnrollmentResolution{}, err
		}
	}
	if err := transaction.Commit(); err != nil {
		return EnrollmentResolution{}, fmt.Errorf("commit enrollment resolution: %w", err)
	}
	return resolution, nil
}

func (repository *PostgresRepository) AuthorizeAgentCredential(ctx context.Context, agentID string, fingerprint [sha256.Size]byte, serial string) error {
	if repository == nil || repository.database == nil || ctx == nil || !identifierPattern.MatchString(agentID) || fingerprint == ([sha256.Size]byte{}) || !certificateSerialPattern.MatchString(serial) {
		return ErrEnrollmentTokenInvalid
	}
	if err := repository.authorizeCurrentAgentCredential(ctx, agentID, fingerprint, serial); err == nil {
		return nil
	}
	repository.generationZeroMu.RLock()
	target, configured := repository.generationZeroImports[agentID]
	repository.generationZeroMu.RUnlock()
	if !configured {
		return ErrEnrollmentTokenInvalid
	}
	for attempt := 0; attempt < 16; attempt++ {
		err := repository.importGenerationZeroCredentialOnce(ctx, agentID, target, fingerprint, serial)
		if !errors.Is(err, ErrEnrollmentGenerationConflict) {
			return err
		}
	}
	return ErrEnrollmentTokenInvalid
}

func (repository *PostgresRepository) authorizeCurrentAgentCredential(ctx context.Context, agentID string, fingerprint [sha256.Size]byte, serial string) error {
	var status string
	var generation int64
	var storedFingerprint []byte
	var storedSerial string
	var revokedAt sql.NullTime
	err := repository.database.QueryRowContext(ctx, `SELECT status,credential_generation,active_certificate_fingerprint,active_certificate_serial,credential_revoked_at FROM managed_hosts WHERE agent_id=$1`, agentID).Scan(&status, &generation, &storedFingerprint, &storedSerial, &revokedAt)
	if err != nil || status == string(hostinventory.HostDecommissioned) || generation < 1 || revokedAt.Valid || len(storedFingerprint) != sha256.Size || len(storedSerial) != len(serial) || subtle.ConstantTimeCompare(storedFingerprint, fingerprint[:]) != 1 || subtle.ConstantTimeCompare([]byte(storedSerial), []byte(serial)) != 1 {
		return ErrEnrollmentTokenInvalid
	}
	return nil
}

func (repository *PostgresRepository) importGenerationZeroCredentialOnce(ctx context.Context, agentID string, target generationZeroImportTarget, fingerprint [sha256.Size]byte, serial string) error {
	transaction, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ErrEnrollmentTokenInvalid
	}
	rollback := func() { _ = transaction.Rollback() }
	result, err := transaction.ExecContext(ctx, `UPDATE managed_hosts SET credential_generation=1,active_certificate_fingerprint=$1,active_certificate_serial=$2,credential_revoked_at=NULL,version=version+1,updated_at=CURRENT_TIMESTAMP WHERE tenant_id=$3 AND project_id=$4 AND host_id=$5 AND agent_id=$6 AND status<>'decommissioned' AND credential_generation=0 AND octet_length(active_certificate_fingerprint)=0 AND active_certificate_serial='' AND credential_revoked_at IS NULL`, fingerprint[:], serial, target.scope.TenantID, target.scope.ProjectID, target.hostID, agentID)
	if err != nil {
		rollback()
		if isEnrollmentSerializationFailure(err) {
			return ErrEnrollmentGenerationConflict
		}
		return ErrEnrollmentTokenInvalid
	}
	rows, err := result.RowsAffected()
	if err != nil {
		rollback()
		return ErrEnrollmentTokenInvalid
	}
	if rows == 0 {
		rollback()
		if err := repository.authorizeCurrentAgentCredential(ctx, agentID, fingerprint, serial); err != nil {
			return ErrEnrollmentTokenInvalid
		}
		return nil
	}
	if rows != 1 {
		rollback()
		return ErrEnrollmentConflict
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO agent_credential_imports (tenant_id,project_id,host_id,agent_id,credential_generation,certificate_fingerprint,certificate_serial,imported_at,import_source) VALUES ($1,$2,$3,$4,1,$5,$6,CURRENT_TIMESTAMP,'verified_mtls')`, target.scope.TenantID, target.scope.ProjectID, target.hostID, agentID, fingerprint[:], serial); err != nil {
		rollback()
		if isEnrollmentSerializationFailure(err) {
			return ErrEnrollmentGenerationConflict
		}
		return ErrEnrollmentTokenInvalid
	}
	identity := sha256.Sum256(append([]byte(target.scope.Key()+"\x00"+target.hostID+"\x00"+agentID+"\x00"), fingerprint[:]...))
	detail, _ := json.Marshal(map[string]any{"credential_generation": 1, "source": "verified_mtls"})
	if _, err := transaction.ExecContext(ctx, `INSERT INTO audit_events (id,tenant_id,project_id,occurred_at,action,actor_type,actor_id,resource_type,resource_id,result,request_id,trace_id,job_id,command_id,dedupe_key,detail,created_at) VALUES ($1,$2,$3,CURRENT_TIMESTAMP,'host.credential_generation_zero_imported','system','generation-zero-import','host',$4,'success','','','','',$5,$6,CURRENT_TIMESTAMP) ON CONFLICT (tenant_id,project_id,dedupe_key) WHERE dedupe_key<>'' DO NOTHING`, "audit-agent-import-"+hex.EncodeToString(identity[:16]), target.scope.TenantID, target.scope.ProjectID, target.hostID, "agent-credential-import:"+hex.EncodeToString(identity[:]), detail); err != nil {
		rollback()
		if isEnrollmentSerializationFailure(err) {
			return ErrEnrollmentGenerationConflict
		}
		return ErrEnrollmentTokenInvalid
	}
	if err := transaction.Commit(); err != nil {
		if isEnrollmentSerializationFailure(err) {
			return ErrEnrollmentGenerationConflict
		}
		return ErrEnrollmentTokenInvalid
	}
	return nil
}

func isEnrollmentSerializationFailure(err error) bool {
	var postgresError *pq.Error
	return errors.As(err, &postgresError) && (postgresError.Code == "40001" || postgresError.Code == "40P01")
}

func (repository *PostgresRepository) Complete(ctx context.Context, completion EnrollmentCompletion) (EnrollmentCompletionResult, error) {
	normalized, normalizeErr := normalizeEnrollmentResult(completion.Result, completion.Grant)
	if normalizeErr == nil {
		completion.Result = normalized
	}
	if repository == nil || repository.database == nil || ctx == nil || completion.Key.Validate() != nil || completion.Grant.Validate() != nil ||
		completion.Observation.Validate() != nil || !validUTC(completion.CompletedAt) || validateEnrollmentResult(completion.Result, completion.Grant) != nil ||
		completion.Key.AgentID != completion.Grant.AgentID || completion.Key.HostID != completion.Grant.HostID ||
		completion.Observation.AgentID != completion.Grant.AgentID || completion.Observation.HostID != completion.Grant.HostID {
		return EnrollmentCompletionResult{}, ErrEnrollmentRequestInvalid
	}
	transaction, err := repository.database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EnrollmentCompletionResult{}, fmt.Errorf("begin enrollment completion: %w", err)
	}
	rollback := func() { _ = transaction.Rollback() }
	resolution, err := resolveEnrollment(ctx, transaction, resolveEnrollmentSQL+" FOR UPDATE OF t", completion.Key)
	if err != nil {
		rollback()
		return EnrollmentCompletionResult{}, err
	}
	if resolution.Response != nil {
		superseded, supersededErr := loadSupersededCredentials(ctx, transaction, resolution.Grant)
		rollback()
		if supersededErr != nil {
			return EnrollmentCompletionResult{}, supersededErr
		}
		return EnrollmentCompletionResult{Response: cloneEnrollmentResult(*resolution.Response), SupersededCredentials: superseded}, nil
	}
	if !enrollmentGrantsEqual(resolution.Grant, completion.Grant) {
		rollback()
		return EnrollmentCompletionResult{}, ErrEnrollmentTokenInvalid
	}
	hostRepository := hostinventory.NewPostgresRepository(transaction)
	if _, err := hostRepository.RecordEnrollment(ctx, completion.Grant.Scope, hostinventory.Enrollment{
		HostID: completion.Grant.HostID, AgentID: completion.Grant.AgentID, DisplayName: completion.Grant.DisplayName,
		Labels: completion.Grant.Labels, Revision: completion.Grant.EnrollmentRevision, EnrolledAt: completion.CompletedAt,
	}, completion.Observation, completion.CompletedAt); err != nil {
		if !errors.Is(err, hostinventory.ErrConflict) {
			rollback()
			return EnrollmentCompletionResult{}, fmt.Errorf("record enrolled Host: %w", err)
		}
		existing, getErr := hostRepository.Get(ctx, completion.Grant.Scope, completion.Grant.HostID)
		if getErr != nil || existing.AgentID != completion.Grant.AgentID || existing.Status == hostinventory.HostDecommissioned {
			rollback()
			return EnrollmentCompletionResult{}, ErrEnrollmentConflict
		}
	}
	if _, err := transaction.ExecContext(ctx, insertIssuanceSQL,
		completion.Key.TokenHash[:], completion.Key.CSRDigest[:], completion.Grant.Scope.TenantID, completion.Grant.Scope.ProjectID,
		completion.Grant.HostID, completion.Grant.AgentID, completion.Result.CertificatePEM, completion.Result.CertificateChainPEM,
		completion.Result.ExpiresAt, completion.CompletedAt, completion.Grant.EnrollmentRevision,
		completion.Result.CredentialGeneration, completion.Result.CertificateFingerprint[:], completion.Result.CertificateSerial,
	); err != nil {
		rollback()
		return EnrollmentCompletionResult{}, mapPostgresError(err)
	}
	activated, err := transaction.ExecContext(ctx, `UPDATE managed_hosts SET credential_generation=$1,active_certificate_fingerprint=$2,active_certificate_serial=$3,credential_revoked_at=NULL,version=version+1,updated_at=$4 WHERE tenant_id=$5 AND project_id=$6 AND host_id=$7 AND agent_id=$8 AND status<>'decommissioned' AND credential_generation<$1`, completion.Result.CredentialGeneration, completion.Result.CertificateFingerprint[:], completion.Result.CertificateSerial, completion.CompletedAt, completion.Grant.Scope.TenantID, completion.Grant.Scope.ProjectID, completion.Grant.HostID, completion.Grant.AgentID)
	if err != nil {
		rollback()
		return EnrollmentCompletionResult{}, mapPostgresError(err)
	}
	if rows, rowsErr := activated.RowsAffected(); rowsErr != nil || rows != 1 {
		rollback()
		return EnrollmentCompletionResult{}, ErrEnrollmentGenerationConflict
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE agent_enrollment_issuances SET revoked_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND host_id=$4 AND agent_id=$5 AND credential_generation<$6 AND revoked_at IS NULL`, completion.CompletedAt, completion.Grant.Scope.TenantID, completion.Grant.Scope.ProjectID, completion.Grant.HostID, completion.Grant.AgentID, completion.Result.CredentialGeneration); err != nil {
		rollback()
		return EnrollmentCompletionResult{}, mapPostgresError(err)
	}
	consumed, err := transaction.ExecContext(ctx, consumeCommittedTokenSQL, completion.Key.TokenHash[:])
	if err != nil {
		rollback()
		return EnrollmentCompletionResult{}, mapPostgresError(err)
	}
	rows, err := consumed.RowsAffected()
	if err != nil || rows != 1 {
		rollback()
		return EnrollmentCompletionResult{}, ErrEnrollmentTokenInvalid
	}
	superseded, err := loadSupersededCredentials(ctx, transaction, completion.Grant)
	if err != nil {
		rollback()
		return EnrollmentCompletionResult{}, err
	}
	if err := transaction.Commit(); err != nil {
		return EnrollmentCompletionResult{}, fmt.Errorf("commit enrollment completion: %w", err)
	}
	return EnrollmentCompletionResult{Response: cloneEnrollmentResult(completion.Result), SupersededCredentials: superseded}, nil
}

func enrollmentGrantsEqual(first, second EnrollmentGrant) bool {
	if first.Scope != second.Scope || first.HostID != second.HostID || first.AgentID != second.AgentID || first.DisplayName != second.DisplayName || first.EnrollmentRevision != second.EnrollmentRevision || first.Generation != second.Generation || len(first.Labels) != len(second.Labels) {
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
	var generation int64
	var consumedAt sql.NullTime
	var active bool
	var issuanceDigest, certificatePEM, chainPEM []byte
	var issuanceExpiresAt, issuedAt sql.NullTime
	var issuanceRevision, credentialGeneration sql.NullInt64
	var certificateFingerprint []byte
	var certificateSerial sql.NullString
	var issuanceRevokedAt sql.NullTime
	var hostStatus, hostCertificateSerial sql.NullString
	var hostGeneration sql.NullInt64
	var hostCertificateFingerprint []byte
	var hostCredentialRevokedAt sql.NullTime
	err := querier.QueryRowContext(ctx, query, key.TokenHash[:]).Scan(
		&grant.Scope.TenantID, &grant.Scope.ProjectID, &grant.HostID, &grant.AgentID, &grant.DisplayName, &labels, &revision,
		&consumedAt, &active, &generation, &issuanceDigest, &certificatePEM, &chainPEM, &issuanceExpiresAt, &issuedAt, &issuanceRevision,
		&credentialGeneration, &certificateFingerprint, &certificateSerial, &issuanceRevokedAt,
		&hostStatus, &hostGeneration, &hostCertificateFingerprint, &hostCertificateSerial, &hostCredentialRevokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentResolution{}, ErrEnrollmentTokenInvalid
	}
	if err != nil {
		return EnrollmentResolution{}, mapPostgresError(err)
	}
	if revision < 1 || generation < 1 || json.Unmarshal(labels, &grant.Labels) != nil {
		return EnrollmentResolution{}, ErrEnrollmentRequestInvalid
	}
	grant.EnrollmentRevision, grant.Generation = uint64(revision), uint64(generation)
	if grant.Validate() != nil || grant.AgentID != key.AgentID || (key.HostID != "" && grant.HostID != key.HostID) {
		return EnrollmentResolution{}, ErrEnrollmentTokenInvalid
	}
	if len(issuanceDigest) != 0 {
		if len(issuanceDigest) != len(key.CSRDigest) || !bytes.Equal(issuanceDigest, key.CSRDigest[:]) || !consumedAt.Valid ||
			len(certificatePEM) == 0 || len(chainPEM) == 0 || !issuanceExpiresAt.Valid || !issuedAt.Valid || !issuanceRevision.Valid || issuanceRevision.Int64 < 1 || !credentialGeneration.Valid || credentialGeneration.Int64 != generation || len(certificateFingerprint) != sha256.Size || !certificateSerial.Valid || certificateSerial.String == "" || issuanceRevokedAt.Valid ||
			!hostStatus.Valid || hostStatus.String == string(hostinventory.HostDecommissioned) || !hostGeneration.Valid || hostGeneration.Int64 != credentialGeneration.Int64 || hostCredentialRevokedAt.Valid || len(hostCertificateFingerprint) != sha256.Size || !hostCertificateSerial.Valid || len(hostCertificateSerial.String) != len(certificateSerial.String) || subtle.ConstantTimeCompare(hostCertificateFingerprint, certificateFingerprint) != 1 || subtle.ConstantTimeCompare([]byte(hostCertificateSerial.String), []byte(certificateSerial.String)) != 1 {
			return EnrollmentResolution{}, ErrEnrollmentTokenInvalid
		}
		response := EnrollResult{
			HostID: grant.HostID, AgentID: grant.AgentID, CertificatePEM: append([]byte(nil), certificatePEM...),
			CertificateChainPEM: append([]byte(nil), chainPEM...), ExpiresAt: issuanceExpiresAt.Time.UTC(),
			EnrollmentRevision: uint64(issuanceRevision.Int64), CredentialGeneration: uint64(credentialGeneration.Int64), CertificateSerial: certificateSerial.String,
		}
		copy(response.CertificateFingerprint[:], certificateFingerprint)
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

func loadSupersededCredentials(ctx context.Context, querier enrollmentRowQuerier, grant EnrollmentGrant) ([]AgentCredential, error) {
	rows, err := querier.QueryContext(ctx, resolveSupersededCredentialsSQL, grant.Scope.TenantID, grant.Scope.ProjectID, grant.HostID, grant.AgentID, grant.Generation)
	if err != nil {
		return nil, mapPostgresError(err)
	}
	defer rows.Close()
	credentials := make([]AgentCredential, 0)
	for rows.Next() {
		var generation int64
		var fingerprint []byte
		var serial string
		if err := rows.Scan(&generation, &fingerprint, &serial); err != nil || generation < 1 || len(fingerprint) != sha256.Size {
			return nil, ErrEnrollmentRequestInvalid
		}
		credential := AgentCredential{Generation: uint64(generation), Serial: serial}
		copy(credential.Fingerprint[:], fingerprint)
		if !credential.valid() {
			return nil, ErrEnrollmentRequestInvalid
		}
		credentials = append(credentials, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, mapPostgresError(err)
	}
	return credentials, nil
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
