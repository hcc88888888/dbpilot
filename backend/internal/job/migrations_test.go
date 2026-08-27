package job

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestRunMigrationsAppliesEmbeddedSchemaThroughSharedRegistry(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("job/migrations/0001_jobs_outbox.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)CREATE TABLE jobs.*CREATE TABLE job_targets.*CREATE TABLE command_outbox").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("job/migrations/0001_jobs_outbox.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("job/migrations/0002_command_payload_bytea.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)DO \\$\\$.*ALTER TABLE command_outbox.*payload TYPE BYTEA").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("job/migrations/0002_command_payload_bytea.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	require.NoError(t, RunMigrations(context.Background(), database))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestEmbeddedMigrationDefinesScopeIdempotencyAndLeaseIndexes(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/0001_jobs_outbox.sql")
	require.NoError(t, err)
	schema := string(content)
	for _, required := range []string{
		"UNIQUE (tenant_id, project_id, idempotency_key, job_type)",
		"CREATE INDEX jobs_scope_idx",
		"CREATE INDEX job_targets_scope_idx",
		"CREATE INDEX command_outbox_lease_idx",
		"payload BYTEA NOT NULL",
		"lease_expires_at",
		"total_targets <= 10000",
	} {
		require.Contains(t, schema, required)
	}
	upgrade, err := migrationFiles.ReadFile("migrations/0002_command_payload_bytea.sql")
	require.NoError(t, err)
	require.Contains(t, string(upgrade), "payload TYPE BYTEA")
}
