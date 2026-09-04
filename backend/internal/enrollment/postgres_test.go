package enrollment

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPostgresCreatePersistsHashScopeAndNoRawToken(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	raw := []byte("never-persist-this-enrollment-token")
	token := validEnrollmentToken(HashToken(raw), now)
	labels, err := json.Marshal(token.Labels)
	require.NoError(t, err)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT token_hash, consumed_at, generation`).
		WithArgs(token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID).WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(`(?s)INSERT INTO agent_enrollment_tokens.*request_fingerprint.*generation.*RETURNING token_hash, generation`).
		WithArgs(token.TokenHash[:], token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID, token.DisplayName, labels, token.ExpiresAt, token.CreatedAt, token.EnrollmentRevision, token.IssuedBy, token.IdempotencyKey, token.RequestFingerprint, 1).
		WillReturnRows(sqlmock.NewRows([]string{"token_hash", "generation"}).AddRow(token.TokenHash[:], 1))
	mock.ExpectExec(`INSERT INTO audit_events`).
		WithArgs(sqlmock.AnyArg(), token.Scope.TenantID, token.Scope.ProjectID, token.CreatedAt, "host.enrollment_created", token.Audit.Actor, token.HostID, token.Audit.RequestID, token.Audit.TraceID, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	_, err = NewPostgresRepository(database).Create(context.Background(), token)

	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresReplaceUsesGenerationCASAndCommitsAuditInTheSameTransaction(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	oldHash := HashToken([]byte("old-token"))
	token := validEnrollmentToken(HashToken([]byte("replacement-token")), now)
	token.IdempotencyKey = "replace-host-1"
	token.Audit.OperationID = "replaceHostEnrollment"
	labels, err := json.Marshal(token.Labels)
	require.NoError(t, err)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT token_hash, consumed_at, generation`).
		WithArgs(token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID).
		WillReturnRows(sqlmock.NewRows([]string{"token_hash", "consumed_at", "generation"}).AddRow(oldHash[:], nil, 1))
	mock.ExpectQuery(`(?s)UPDATE agent_enrollment_tokens SET.*WHERE token_hash = \$13 AND generation = \$14.*RETURNING token_hash, generation`).
		WithArgs(token.TokenHash[:], token.HostID, token.AgentID, token.DisplayName, labels, token.ExpiresAt, token.CreatedAt, token.EnrollmentRevision, 2, token.IssuedBy, token.IdempotencyKey, token.RequestFingerprint, oldHash[:], uint64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"token_hash", "generation"}).AddRow(token.TokenHash[:], 2))
	mock.ExpectExec(`INSERT INTO audit_events`).
		WithArgs(sqlmock.AnyArg(), token.Scope.TenantID, token.Scope.ProjectID, token.CreatedAt, "host.enrollment_replaced", token.Audit.Actor, token.HostID, token.Audit.RequestID, token.Audit.TraceID, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	creation, err := NewPostgresRepository(database).Replace(context.Background(), token, 1)

	require.NoError(t, err)
	require.Equal(t, EnrollmentTokenCreation{Generation: 2, Replaced: true}, creation)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresReplacementAuditFailureRollsBackTokenGeneration(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	oldHash := HashToken([]byte("old-token"))
	token := validEnrollmentToken(HashToken([]byte("replacement-token")), now)
	token.IdempotencyKey = "replace-host-1"
	token.Audit.OperationID = "replaceHostEnrollment"
	labels, err := json.Marshal(token.Labels)
	require.NoError(t, err)
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT token_hash, consumed_at, generation`).
		WithArgs(token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID).
		WillReturnRows(sqlmock.NewRows([]string{"token_hash", "consumed_at", "generation"}).AddRow(oldHash[:], nil, 1))
	mock.ExpectQuery(`UPDATE agent_enrollment_tokens SET`).
		WithArgs(token.TokenHash[:], token.HostID, token.AgentID, token.DisplayName, labels, token.ExpiresAt, token.CreatedAt, token.EnrollmentRevision, 2, token.IssuedBy, token.IdempotencyKey, token.RequestFingerprint, oldHash[:], uint64(1)).
		WillReturnRows(sqlmock.NewRows([]string{"token_hash", "generation"}).AddRow(token.TokenHash[:], 2))
	mock.ExpectExec(`INSERT INTO audit_events`).WillReturnError(errors.New("audit unavailable"))
	mock.ExpectRollback()

	_, err = NewPostgresRepository(database).Replace(context.Background(), token, 1)

	require.ErrorContains(t, err, "record enrollment Audit")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresResolveReplacementRequiresExactScopeAndOperationCorrelation(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	request := ReplacementLookup{
		HostID: "host-1", AgentID: "agent-1", IssuedBy: "operator-1", IdempotencyKey: "replace-1",
		RequestFingerprint: "sha256:" + strings.Repeat("1", 64),
	}
	mock.ExpectQuery(`(?s)SELECT enrollment_revision, generation.*tenant_id = \$1.*project_id = \$2.*host_id = \$3.*agent_id = \$4.*issued_by = \$5.*idempotency_key = \$6.*request_fingerprint = \$7`).
		WithArgs(scope.TenantID, scope.ProjectID, request.HostID, request.AgentID, request.IssuedBy, request.IdempotencyKey, request.RequestFingerprint).
		WillReturnRows(sqlmock.NewRows([]string{"enrollment_revision", "generation"}).AddRow(3, 8))

	state, err := NewPostgresRepository(database).ResolveReplacement(context.Background(), scope, request)

	require.NoError(t, err)
	require.Equal(t, ReplacementState{HostID: "host-1", AgentID: "agent-1", EnrollmentRevision: 3, Generation: 8}, state)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresResolveReturnsActiveGrantAndExactCommittedReplay(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	hash := HashToken([]byte("opaque-token"))
	csrDigest := sha256.Sum256([]byte("csr"))
	key := EnrollmentAttemptKey{TokenHash: hash, CSRDigest: csrDigest, AgentID: "agent-1", HostID: "host-1"}
	grant := EnrollmentGrant{
		Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, HostID: "host-1", AgentID: "agent-1",
		DisplayName: "Primary database host", Labels: map[string]string{"role": "database"}, EnrollmentRevision: 1, Generation: 1,
	}
	labels, err := json.Marshal(grant.Labels)
	require.NoError(t, err)
	columns := enrollmentResolutionColumns()
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT.*t.consumed_at.*expires_at > CURRENT_TIMESTAMP.*LEFT JOIN agent_enrollment_issuances`).
		WithArgs(hash[:]).WillReturnRows(sqlmock.NewRows(columns).AddRow(
		grant.Scope.TenantID, grant.Scope.ProjectID, grant.HostID, grant.AgentID, grant.DisplayName, labels, grant.EnrollmentRevision,
		nil, true, 1, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	))
	mock.ExpectCommit()
	issuedAt := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(time.Hour)
	certificate, _ := testCertificateAuthority(t, issuedAt)
	fingerprint, serial, err := enrollmentCertificateIdentity(certificate)
	require.NoError(t, err)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT.*LEFT JOIN agent_enrollment_issuances`).WithArgs(hash[:]).WillReturnRows(sqlmock.NewRows(columns).AddRow(
		grant.Scope.TenantID, grant.Scope.ProjectID, grant.HostID, grant.AgentID, grant.DisplayName, labels, grant.EnrollmentRevision,
		issuedAt, false, 1, csrDigest[:], certificate, certificate, expiresAt, issuedAt, grant.EnrollmentRevision, 1, fingerprint[:], serial,
		nil, string(hostinventory.HostOnline), 1, fingerprint[:], serial, nil,
	))
	mock.ExpectQuery(`(?s)SELECT credential_generation,certificate_fingerprint,certificate_serial.*agent_enrollment_issuances`).
		WithArgs(grant.Scope.TenantID, grant.Scope.ProjectID, grant.HostID, grant.AgentID, grant.Generation).
		WillReturnRows(sqlmock.NewRows([]string{"credential_generation", "certificate_fingerprint", "certificate_serial"}))
	mock.ExpectCommit()
	repository := NewPostgresRepository(database)

	first, err := repository.Resolve(context.Background(), key)
	require.NoError(t, err)
	require.Equal(t, grant, first.Grant)
	require.Nil(t, first.Response)
	replayed, err := repository.Resolve(context.Background(), key)
	require.NoError(t, err)
	require.Equal(t, certificate, replayed.Response.CertificatePEM)
	require.Equal(t, expiresAt, replayed.Response.ExpiresAt)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresResolveReadsActiveReplayAndSupersededLeavesInOneSnapshot(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	hash := HashToken([]byte("replacement-token"))
	csrDigest := sha256.Sum256([]byte("replacement-csr"))
	key := EnrollmentAttemptKey{TokenHash: hash, CSRDigest: csrDigest, AgentID: "agent-1", HostID: "host-1"}
	grant := EnrollmentGrant{Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, HostID: key.HostID, AgentID: key.AgentID, DisplayName: "Primary database host", Labels: map[string]string{}, EnrollmentRevision: 1, Generation: 2}
	labels, err := json.Marshal(grant.Labels)
	require.NoError(t, err)
	issuedAt := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	certificate, _ := testCertificateAuthority(t, issuedAt)
	fingerprint, serial, err := enrollmentCertificateIdentity(certificate)
	require.NoError(t, err)
	oldFingerprint := sha256.Sum256([]byte("old-leaf"))

	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT.*LEFT JOIN agent_enrollment_issuances.*LEFT JOIN managed_hosts`).WithArgs(hash[:]).WillReturnRows(sqlmock.NewRows(enrollmentResolutionColumns()).AddRow(
		grant.Scope.TenantID, grant.Scope.ProjectID, grant.HostID, grant.AgentID, grant.DisplayName, labels, grant.EnrollmentRevision,
		issuedAt, false, grant.Generation, csrDigest[:], certificate, certificate, issuedAt.Add(time.Hour), issuedAt, grant.EnrollmentRevision, grant.Generation, fingerprint[:], serial,
		nil, string(hostinventory.HostOnline), grant.Generation, fingerprint[:], serial, nil,
	))
	mock.ExpectQuery(`(?s)SELECT credential_generation,certificate_fingerprint,certificate_serial.*agent_enrollment_issuances`).
		WithArgs(grant.Scope.TenantID, grant.Scope.ProjectID, grant.HostID, grant.AgentID, grant.Generation).
		WillReturnRows(sqlmock.NewRows([]string{"credential_generation", "certificate_fingerprint", "certificate_serial"}).AddRow(1, oldFingerprint[:], "01"))
	mock.ExpectCommit()

	resolution, err := NewPostgresRepository(database).Resolve(context.Background(), key)

	require.NoError(t, err)
	require.Equal(t, []AgentCredential{{Generation: 1, Fingerprint: oldFingerprint, Serial: "01"}}, resolution.SupersededCredentials)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresResolveMapsExpiredOrMissingTokenToFixedError(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	hash := HashToken([]byte("expired-token"))
	csrDigest := sha256.Sum256([]byte("csr"))
	key := EnrollmentAttemptKey{TokenHash: hash, CSRDigest: csrDigest, AgentID: "agent-1"}
	grant := validEnrollmentToken(hash, time.Now().UTC()).Grant()
	labels, _ := json.Marshal(grant.Labels)
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT.*LEFT JOIN agent_enrollment_issuances`).WithArgs(hash[:]).WillReturnRows(sqlmock.NewRows(enrollmentResolutionColumns()).AddRow(
		grant.Scope.TenantID, grant.Scope.ProjectID, grant.HostID, grant.AgentID, grant.DisplayName, labels, grant.EnrollmentRevision,
		nil, false, grant.Generation, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
	))
	mock.ExpectRollback()

	_, err = NewPostgresRepository(database).Resolve(context.Background(), key)

	require.ErrorIs(t, err, ErrEnrollmentTokenInvalid)
	require.NotContains(t, err.Error(), string(hash[:]))
	require.NoError(t, mock.ExpectationsWereMet())
}

func enrollmentResolutionColumns() []string {
	return []string{
		"tenant_id", "project_id", "host_id", "agent_id", "display_name", "labels", "enrollment_revision",
		"consumed_at", "active", "generation", "csr_digest", "certificate_pem", "certificate_chain_pem", "expires_at", "issued_at", "issuance_revision", "credential_generation", "certificate_fingerprint", "certificate_serial", "revoked_at",
		"host_status", "host_credential_generation", "host_certificate_fingerprint", "host_certificate_serial", "host_credential_revoked_at",
	}
}

func TestRunMigrationsCreatesHashOnlyEnrollmentTable(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("enrollment/migrations/0001_agent_enrollment.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`(?s)CREATE TABLE agent_enrollment_tokens.*token_hash BYTEA PRIMARY KEY.*expires_at TIMESTAMPTZ.*consumed_at TIMESTAMPTZ.*UNIQUE.*idempotency_key`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("enrollment/migrations/0001_agent_enrollment.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("enrollment/migrations/0002_recoverable_enrollment.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`(?s)ALTER TABLE agent_enrollment_tokens.*request_fingerprint.*generation.*CREATE TABLE IF NOT EXISTS agent_enrollment_issuances.*csr_digest BYTEA.*certificate_pem BYTEA`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("enrollment/migrations/0002_recoverable_enrollment.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("enrollment/migrations/0003_certificate_generation.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)ALTER TABLE agent_enrollment_issuances.*credential_generation.*certificate_fingerprint.*agent_enrollment_tokens_identity_generation_idx").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("enrollment/migrations/0003_certificate_generation.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("enrollment/migrations/0004_decommission_credential_revocation.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)CREATE FUNCTION revoke_agent_issuances_on_host_decommission.*CREATE TRIGGER managed_hosts_revoke_agent_issuances.*UPDATE agent_enrollment_issuances").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("enrollment/migrations/0004_decommission_credential_revocation.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("enrollment/migrations/0005_generation_zero_import.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)CREATE TABLE agent_credential_imports.*credential_generation.*verified_mtls.*managed_hosts_active_certificate_fingerprint_idx").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("enrollment/migrations/0005_generation_zero_import.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("enrollment/migrations/0006_generation_zero_import_immutability.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)CREATE FUNCTION dbpilot_reject_agent_credential_import_mutation.*CREATE TRIGGER agent_credential_imports_immutable").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("enrollment/migrations/0006_generation_zero_import_immutability.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectQuery("SELECT issuance.token_hash").WillReturnRows(sqlmock.NewRows([]string{"token_hash", "certificate_pem", "generation", "tenant_id", "project_id", "host_id", "agent_id", "issued_at"}))

	err = RunMigrations(context.Background(), database)

	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func bytesOfEnrollmentTest(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func TestEnrollmentMigration0001RemainsByteIdenticalToAppliedSchema(t *testing.T) {
	want, err := os.ReadFile("testdata/0001_agent_enrollment_original.sql")
	require.NoError(t, err)
	got, err := migrationFiles.ReadFile("migrations/0001_agent_enrollment.sql")
	require.NoError(t, err)
	require.Equal(t, want, got, "an applied migration must never be rewritten")
}
