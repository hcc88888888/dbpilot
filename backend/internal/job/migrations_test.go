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
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("job/migrations/0003_prepared_command_envelope.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("ALTER TABLE command_outbox.*prepared_envelope BYTEA").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("job/migrations/0003_prepared_command_envelope.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("job/migrations/0004_command_execution_recovery.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)ALTER TABLE command_outbox.*command_status.*command_outbox_cancellation_idx").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("job/migrations/0004_command_execution_recovery.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("job/migrations/0005_two_phase_execution.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)ALTER TABLE command_outbox.*command_phase.*recovery_revision.*command_outbox_expired_execution_v2_idx").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("job/migrations/0005_two_phase_execution.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("job/migrations/0006_cancellation_response_snapshot.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)CREATE TABLE job_cancellation_snapshots.*request_fingerprint.*owner_token.*job_snapshot.*audit_event_json.*job_cancellation_snapshots_correlation_idx").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("job/migrations/0006_cancellation_response_snapshot.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("job/migrations/0007_inspection_concurrency.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)ALTER TABLE jobs.*max_concurrency.*target_timeout_seconds.*command_outbox_job_phase_idx").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("job/migrations/0007_inspection_concurrency.sql").WillReturnResult(sqlmock.NewResult(0, 1))
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
	prepared, err := migrationFiles.ReadFile("migrations/0003_prepared_command_envelope.sql")
	require.NoError(t, err)
	require.Contains(t, string(prepared), "prepared_envelope BYTEA")
	recovery, err := migrationFiles.ReadFile("migrations/0004_command_execution_recovery.sql")
	require.NoError(t, err)
	for _, required := range []string{"command_status", "execution_deadline_at", "execution_last_heartbeat_at", "cancellation_requested_at", "cancellation_lease_expires_at", "command_outbox_execution_deadline_idx", "command_outbox_cancellation_idx"} {
		require.Contains(t, string(recovery), required)
	}
	twoPhase, err := migrationFiles.ReadFile("migrations/0005_two_phase_execution.sql")
	require.NoError(t, err)
	for _, required := range []string{"command_phase", "prepare_digest", "execution_token_ciphertext", "execution_token_hash", "execution_revision", "recovery_revision", "start_deadline_at", "start_enqueued_at", "recovery_claim_token", "recovery_claimed_deadline", "recovery_claimed_revision", "terminal_result_digest", "terminal_at", "terminal_audit_pending", "terminal_audit_dedupe_key", "terminal_audit_detail", "terminal_audit_recorded_at", "command_outbox_prepared_idx", "command_outbox_prepared_recovery_idx", "command_outbox_pending_cancellation_v2_idx", "command_outbox_expired_execution_v2_idx", "command_outbox_terminal_audit_pending_idx"} {
		require.Contains(t, string(twoPhase), required)
	}
	require.Contains(t, string(twoPhase), "WHERE command_status = 'active'")
	require.Contains(t, string(twoPhase), "execution_deadline_at = LEAST")
	cancellationSnapshot, err := migrationFiles.ReadFile("migrations/0006_cancellation_response_snapshot.sql")
	require.NoError(t, err)
	for _, required := range []string{"job_cancellation_snapshots", "request_fingerprint", "owner_token", "if_match", "current_version", "job_snapshot", "audit_event_json", "job_cancellation_snapshots_correlation_idx"} {
		require.Contains(t, string(cancellationSnapshot), required)
	}
	concurrency, err := migrationFiles.ReadFile("migrations/0007_inspection_concurrency.sql")
	require.NoError(t, err)
	for _, required := range []string{"max_concurrency", "target_timeout_seconds", "command_outbox_job_phase_idx", "inspection.collect"} {
		require.Contains(t, string(concurrency), required)
	}
}
