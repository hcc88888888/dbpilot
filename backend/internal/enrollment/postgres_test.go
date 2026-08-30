package enrollment

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

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
	mock.ExpectQuery(`(?s)INSERT INTO agent_enrollment_tokens.*token_hash.*tenant_id.*project_id.*idempotency_key.*RETURNING token_hash`).
		WithArgs(token.TokenHash[:], token.Scope.TenantID, token.Scope.ProjectID, token.HostID, token.AgentID, token.DisplayName, labels, token.ExpiresAt, token.CreatedAt, token.EnrollmentRevision, token.IssuedBy, token.IdempotencyKey).
		WillReturnRows(sqlmock.NewRows([]string{"token_hash"}).AddRow(token.TokenHash[:]))

	err = NewPostgresRepository(database).Create(context.Background(), token)

	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresConsumeAtomicallyEnforcesSingleUseAndExpiry(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	hash := HashToken([]byte("opaque-token"))
	grant := EnrollmentGrant{
		Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, HostID: "host-1", AgentID: "agent-1",
		DisplayName: "Primary database host", Labels: map[string]string{"role": "database"}, EnrollmentRevision: 1,
	}
	labels, err := json.Marshal(grant.Labels)
	require.NoError(t, err)
	mock.ExpectQuery(`(?s)UPDATE agent_enrollment_tokens SET consumed_at = \$2.*WHERE token_hash = \$1.*consumed_at IS NULL.*expires_at > \$2.*RETURNING tenant_id, project_id, host_id, agent_id, display_name, labels, enrollment_revision`).
		WithArgs(hash[:], now).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "project_id", "host_id", "agent_id", "display_name", "labels", "enrollment_revision"}).
			AddRow(grant.Scope.TenantID, grant.Scope.ProjectID, grant.HostID, grant.AgentID, grant.DisplayName, labels, grant.EnrollmentRevision))
	mock.ExpectQuery(`UPDATE agent_enrollment_tokens SET consumed_at`).WithArgs(hash[:], now.Add(time.Second)).
		WillReturnError(sql.ErrNoRows)
	repository := NewPostgresRepository(database)

	first, err := repository.Consume(context.Background(), hash, now)
	require.NoError(t, err)
	require.Equal(t, grant, first)
	_, err = repository.Consume(context.Background(), hash, now.Add(time.Second))
	require.ErrorIs(t, err, ErrEnrollmentTokenInvalid)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresConsumeMapsExpiredOrMissingTokenToFixedError(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	hash := HashToken([]byte("expired-token"))
	now := time.Now().UTC()
	mock.ExpectQuery(`UPDATE agent_enrollment_tokens SET consumed_at`).WithArgs(hash[:], now).WillReturnError(sql.ErrNoRows)

	_, err = NewPostgresRepository(database).Consume(context.Background(), hash, now)

	require.ErrorIs(t, err, ErrEnrollmentTokenInvalid)
	require.NotContains(t, err.Error(), string(hash[:]))
	require.NoError(t, mock.ExpectationsWereMet())
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

	err = RunMigrations(context.Background(), database)

	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
