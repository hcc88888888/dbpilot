package platformdb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestPlatformPostgresIntegration(t *testing.T) {
	if os.Getenv("DBPILOT_PLATFORM_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_PLATFORM_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_PLATFORM_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_PLATFORM_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin := openPlatformIntegrationDB(t, ctx, dsn)
	schema := fmt.Sprintf("platform_services_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanupContext, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})

	database := openPlatformIntegrationDB(t, ctx, platformIntegrationDSN(t, dsn, schema))
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	require.NoError(t, RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	var applied int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM dbpilot_schema_migrations WHERE name = $1", "platformdb/migrations/0001_platform_services.sql").Scan(&applied))
	require.Equal(t, 1, applied)

	scope := platformscope.Scope{TenantID: "tenant-integration", ProjectID: "project-integration"}
	wrongScope := platformscope.Scope{TenantID: scope.TenantID, ProjectID: "project-other"}
	auditService := audit.NewService(audit.NewPostgresStore(database))
	recorded, err := auditService.Record(ctx, audit.Event{
		Scope: scope, Actor: audit.Actor{Type: "user", ID: "operator-integration"}, Action: "inspection.completed",
		Resource: audit.Resource{Type: "inspection", ID: "inspection-integration"}, Result: "succeeded", RequestID: "request-integration",
		Detail: map[string]any{"statement": "select password from users"},
	})
	require.NoError(t, err)
	page, err := auditService.List(ctx, scope, audit.ListQuery{Limit: 10})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, recorded.ID, page.Items[0].ID)
	require.NotContains(t, fmt.Sprint(page.Items[0].Detail), "select password from users")
	wrongPage, err := auditService.List(ctx, wrongScope, audit.ListQuery{Limit: 10})
	require.NoError(t, err)
	require.Empty(t, wrongPage.Items)

	_, err = database.ExecContext(ctx, "UPDATE audit_events SET result = 'changed' WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, recorded.ID)
	require.ErrorContains(t, err, "append-only")
	_, err = database.ExecContext(ctx, "DELETE FROM audit_events WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, recorded.ID)
	require.ErrorContains(t, err, "append-only")

	created := time.Now().UTC().Truncate(time.Microsecond)
	_, err = database.ExecContext(ctx, "INSERT INTO artifacts (id, tenant_id, project_id, kind, content_type, size_bytes, checksum, source_resource_type, source_resource_id, job_id, created_by, created_at, storage_reference) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
		"artifact-integration", scope.TenantID, scope.ProjectID, "report", "application/json", 42, "sha256:integration", "inspection", "inspection-integration", "job-integration", "operator-integration", created, "object/integration")
	require.NoError(t, err)
	metadata, err := artifact.NewPostgresStore(database).Get(ctx, scope, "artifact-integration")
	require.NoError(t, err)
	require.Equal(t, int64(42), metadata.SizeBytes)
	require.Equal(t, "sha256:integration", metadata.Checksum)
	_, err = artifact.NewPostgresStore(database).Get(ctx, wrongScope, "artifact-integration")
	require.ErrorIs(t, err, artifact.ErrNotFound)
}

func TestHTTPIdempotencyMigrationPreservesCustomStateConstraint(t *testing.T) {
	if os.Getenv("DBPILOT_PLATFORM_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_PLATFORM_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_PLATFORM_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_PLATFORM_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin := openPlatformIntegrationDB(t, ctx, dsn)
	schema := fmt.Sprintf("platform_migration_upgrade_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, cleanupErr := admin.ExecContext(context.Background(), "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})
	database := openPlatformIntegrationDB(t, ctx, platformIntegrationDSN(t, dsn, schema))
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	_, err = database.ExecContext(ctx, "CREATE TABLE dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
	require.NoError(t, err)
	require.NoError(t, applyMigration(ctx, database, "migrations/0002_idempotency.sql"))
	require.NoError(t, applyMigration(ctx, database, "migrations/0003_idempotency_fencing.sql"))
	_, err = database.ExecContext(ctx, "ALTER TABLE idempotency_records ADD CONSTRAINT customer_state_policy CHECK (state <> 'customer_reserved')")
	require.NoError(t, err)

	require.NoError(t, applyMigration(ctx, database, "migrations/0005_http_idempotency_reconciliation.sql"))

	var customConstraint int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM pg_constraint WHERE conrelid = 'idempotency_records'::regclass AND conname = 'customer_state_policy'").Scan(&customConstraint))
	require.Equal(t, 1, customConstraint)
}

func openPlatformIntegrationDB(t *testing.T, ctx context.Context, dsn string) *sql.DB {
	t.Helper()
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, database.PingContext(ctx))
	return database
}

func platformIntegrationDSN(t *testing.T, dsn, schema string) string {
	t.Helper()
	if strings.Contains(dsn, "://") {
		parsed, err := url.Parse(dsn)
		require.NoError(t, err)
		query := parsed.Query()
		query.Set("search_path", schema)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return dsn + " search_path=" + schema
}
