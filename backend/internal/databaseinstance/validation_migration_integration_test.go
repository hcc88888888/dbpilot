package databaseinstance

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestValidationMigrationAcceptsExactPendingCorrelationAndRejectsOrphan(t *testing.T) {
	if os.Getenv("DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN is required")
	}
	ctx := context.Background()
	for _, test := range []struct {
		name       string
		validation bool
		wantError  bool
	}{
		{name: "exact pending", validation: true},
		{name: "orphan pending", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			database := openValidationMigrationDatabase(t, ctx, dsn, test.name)
			_, err := database.ExecContext(ctx, `CREATE TABLE dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE managed_database_instances (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    instance_id TEXT PRIMARY KEY,
    connection_test_status TEXT NOT NULL,
    connection_validation_job_id TEXT NOT NULL DEFAULT '',
    connection_validation_command_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE database_instance_validations (
    tenant_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    status TEXT NOT NULL
);`)
			require.NoError(t, err)
			for _, name := range []string{
				"databaseinstance/migrations/0001_database_instances.sql",
				"databaseinstance/migrations/0002_database_instance_lifecycle.sql",
				"databaseinstance/migrations/0003_validation_correlation.sql",
			} {
				_, err = database.ExecContext(ctx, `INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)`, name)
				require.NoError(t, err)
			}
			jobID, commandID := "job-validation-base", "command-validation-base"
			if test.validation {
				_, err = database.ExecContext(ctx, `INSERT INTO database_instance_validations (tenant_id,project_id,job_id,command_id,instance_id,status) VALUES ('tenant-a','project-a',$1,$2,'instance-a','running')`, jobID, commandID)
				require.NoError(t, err)
			}
			correlatedJob, correlatedCommand := "", ""
			if test.validation {
				correlatedJob, correlatedCommand = jobID, commandID
			}
			_, err = database.ExecContext(ctx, `INSERT INTO managed_database_instances (tenant_id,project_id,instance_id,connection_test_status,connection_validation_job_id,connection_validation_command_id) VALUES ('tenant-a','project-a','instance-a','running',$1,$2)`, correlatedJob, correlatedCommand)
			require.NoError(t, err)

			err = RunMigrations(ctx, database)
			if test.wantError {
				require.ErrorContains(t, err, "orphan")
				return
			}
			require.NoError(t, err)
			require.NoError(t, RunMigrations(ctx, database))
			var constraint bool
			require.NoError(t, database.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='managed_database_instances'::regclass AND conname='managed_database_instances_active_validation_shape')`).Scan(&constraint))
			require.True(t, constraint)
		})
	}
}

func openValidationMigrationDatabase(t *testing.T, ctx context.Context, dsn, suffix string) *sql.DB {
	t.Helper()
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.PingContext(ctx))
	schema := fmt.Sprintf("validation_migration_%d", time.Now().UnixNano())
	quoted := pq.QuoteIdentifier(schema)
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+quoted)
	require.NoError(t, err)
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	database, err := sql.Open("postgres", parsed.String())
	require.NoError(t, err)
	require.NoError(t, database.PingContext(ctx))
	t.Cleanup(func() {
		require.NoError(t, database.Close())
		_, dropErr := admin.ExecContext(context.Background(), "DROP SCHEMA IF EXISTS "+quoted+" CASCADE")
		require.NoError(t, dropErr)
		require.NoError(t, admin.Close())
	})
	return database
}
