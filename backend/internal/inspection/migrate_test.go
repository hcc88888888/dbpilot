package inspection

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestMigrationDefinesScopedImmutableInspectionStorage(t *testing.T) {
	// Break caught: omitting a scope key, snapshot bound, occurrence key, or
	// append-only report guard can cross tenants or rewrite historical output.
	content, err := migrationFiles.ReadFile("migrations/0001_host_inspection.sql")
	require.NoError(t, err)
	schema := string(content)
	for _, table := range []string{
		"inspection_items", "inspection_policies", "inspection_policy_items",
		"inspection_runs", "inspection_target_runs", "inspection_findings", "inspection_reports",
	} {
		require.Contains(t, schema, "CREATE TABLE "+table)
	}
	for _, required := range []string{
		"PRIMARY KEY (tenant_id, project_id, item_id, version)",
		"FOREIGN KEY (tenant_id, project_id, policy_id)",
		"FOREIGN KEY (tenant_id, project_id, run_id)",
		"UNIQUE (tenant_id, project_id, occurrence_key)",
		"snapshot JSONB NOT NULL",
		"octet_length(snapshot::text)",
		"CREATE INDEX inspection_policies_due_idx ON inspection_policies (enabled, next_run_at, lease_expires_at)",
		"inspection_reports_immutable",
	} {
		require.Contains(t, schema, required)
	}
}

func TestMigrationAppliesThroughSharedRegistryExactlyOnce(t *testing.T) {
	// Break caught: an unregistered module migration can run twice and leave a
	// partially applied inspection schema during concurrent process startup.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("inspection/migrations/0001_host_inspection.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)CREATE TABLE inspection_items.*CREATE TABLE inspection_reports").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("inspection/migrations/0001_host_inspection.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	require.NoError(t, RunMigrations(context.Background(), database))
	require.NoError(t, mock.ExpectationsWereMet())
}
