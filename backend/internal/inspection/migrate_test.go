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
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("inspection/migrations/0002_history_guards.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)CREATE OR REPLACE FUNCTION reject_inspection_history_mutation.*inspection_items_immutable.*inspection_findings_immutable.*inspection_runs_immutable_fields").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("inspection/migrations/0002_history_guards.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("inspection/migrations/0003_pagination_keys.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)CREATE INDEX inspection_items_pagination_v2_idx.*ALTER TABLE inspection_reports.*created_at.*CREATE INDEX inspection_reports_pagination_v2_idx").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("inspection/migrations/0003_pagination_keys.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery("SELECT EXISTS").WithArgs("inspection/migrations/0004_target_run_guards.sql").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec("(?s)CREATE OR REPLACE FUNCTION guard_inspection_target_run_mutation.*inspection_target_runs_guard.*inspection_runs_delete_guard").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO dbpilot_schema_migrations").WithArgs("inspection/migrations/0004_target_run_guards.sql").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	require.NoError(t, RunMigrations(context.Background(), database))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestMigrationAddsHistoricalMutationGuardsWithoutBlockingLifecycleColumns(t *testing.T) {
	// Break caught: application-level conventions alone cannot prevent direct
	// SQL from rewriting item/finding history or immutable Run snapshots.
	content, err := migrationFiles.ReadFile("migrations/0002_history_guards.sql")
	require.NoError(t, err)
	schema := string(content)
	for _, required := range []string{
		"inspection_items_immutable",
		"inspection_findings_immutable",
		"inspection_runs_immutable_fields",
		"OLD.policy_snapshot IS DISTINCT FROM NEW.policy_snapshot",
		"OLD.item_snapshot IS DISTINCT FROM NEW.item_snapshot",
	} {
		require.Contains(t, schema, required)
	}
	for _, mutable := range []string{"NEW.status", "NEW.completed_target_count", "NEW.failed_target_count", "NEW.report_id", "NEW.started_at", "NEW.finished_at"} {
		require.NotContains(t, schema, mutable, "lifecycle column must not be part of the immutable-field comparison")
	}
}

func TestMigrationAddsUniqueItemAndReportPaginationKeys(t *testing.T) {
	// Break caught: a non-unique item cursor or report ordering without a
	// persisted created_at key can skip equal-time rows across pages.
	content, err := migrationFiles.ReadFile("migrations/0003_pagination_keys.sql")
	require.NoError(t, err)
	schema := string(content)
	require.Contains(t, schema, "inspection_items (tenant_id, project_id, created_at DESC, item_id DESC, version DESC)")
	require.Contains(t, schema, "created_at TIMESTAMPTZ GENERATED ALWAYS AS (generated_at) STORED")
	require.Contains(t, schema, "inspection_reports (tenant_id, project_id, created_at DESC, id DESC)")
}

func TestMigrationGuardsTargetIdentityAndHistoricalRunDeletion(t *testing.T) {
	// Break caught: mutating or deleting a TargetRun rewrites command/target
	// history, while deleting a Run can cascade that history away.
	content, err := migrationFiles.ReadFile("migrations/0004_target_run_guards.sql")
	require.NoError(t, err)
	schema := string(content)
	for _, required := range []string{
		"inspection_target_runs_guard",
		"inspection_runs_delete_guard",
		"OLD.tenant_id IS DISTINCT FROM NEW.tenant_id",
		"OLD.project_id IS DISTINCT FROM NEW.project_id",
		"OLD.run_id IS DISTINCT FROM NEW.run_id",
		"OLD.target_id IS DISTINCT FROM NEW.target_id",
		"OLD.agent_id IS DISTINCT FROM NEW.agent_id",
		"OLD.command_id IS DISTINCT FROM NEW.command_id",
		"OLD.target_snapshot IS DISTINCT FROM NEW.target_snapshot",
	} {
		require.Contains(t, schema, required)
	}
	for _, mutable := range []string{"NEW.status", "NEW.error_code", "NEW.observed_at"} {
		require.NotContains(t, schema, mutable, "TargetRun lifecycle column must remain mutable")
	}
}
