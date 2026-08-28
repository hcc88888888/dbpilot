package platformdb

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
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

func TestHTTPIdempotencyMigrationUpgradesLegacyRowsAndPreservesCustomStateConstraint(t *testing.T) {
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
	require.NoError(t, applyMigration(ctx, database, "migrations/0001_platform_services.sql"))
	require.NoError(t, applyMigration(ctx, database, "migrations/0002_idempotency.sql"))
	require.NoError(t, applyMigration(ctx, database, "migrations/0003_idempotency_fencing.sql"))
	require.NoError(t, applyMigration(ctx, database, "migrations/0004_audit_dedupe.sql"))
	_, err = database.ExecContext(ctx, "ALTER TABLE idempotency_records ADD CONSTRAINT customer_state_policy CHECK (state <> 'customer_reserved')")
	require.NoError(t, err)
	created := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	expires := created.Add(24 * time.Hour)
	processingOwner := "owner-1111111111111111111111111111111111111111111111111111111111111111"
	completedOwner := "owner-2222222222222222222222222222222222222222222222222222222222222222"
	processingFingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"
	completedFingerprint := "sha256:70b9d78842924a3f00599c8298f0e6786ea68aa7b6ea5f5f74335c7d26d0579d"
	completedHeaders := `{"Content-Type":["application/json"],"ETag":["\"8\""]}`
	completedBody := []byte(`{"id":"job-legacy","version":8}`)
	_, err = database.ExecContext(ctx, "INSERT INTO idempotency_records (tenant_id, project_id, actor, operation_id, idempotency_key, request_fingerprint, owner_token, state, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'processing', $8, $9, $9)",
		"tenant-upgrade", "project-upgrade", "operator-upgrade", "cancelJob", "legacy-processing", processingFingerprint, processingOwner, expires, created)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "INSERT INTO idempotency_records (tenant_id, project_id, actor, operation_id, idempotency_key, request_fingerprint, owner_token, state, response_status, response_headers, response_json, expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, 'completed', $8, $9, $10, $11, $12, $12)",
		"tenant-upgrade", "project-upgrade", "operator-upgrade", "cancelJob", "legacy-completed", completedFingerprint, completedOwner, http.StatusAccepted, completedHeaders, completedBody, expires, created)
	require.NoError(t, err)

	require.NoError(t, applyMigration(ctx, database, "migrations/0005_http_idempotency_reconciliation.sql"))
	require.NoError(t, applyMigration(ctx, database, "migrations/0005_http_idempotency_reconciliation.sql"))

	var rowCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2", "tenant-upgrade", "project-upgrade").Scan(&rowCount))
	require.Equal(t, 2, rowCount)
	var processingState, storedProcessingOwner, storedProcessingFingerprint string
	var processingStatus int
	var processingHeaders, processingResponse, processingAudit []byte
	var processingExpiry time.Time
	require.NoError(t, database.QueryRowContext(ctx, "SELECT state, request_fingerprint, owner_token, response_status, response_headers, response_json, audit_event_json, expires_at FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND idempotency_key = $3", "tenant-upgrade", "project-upgrade", "legacy-processing").Scan(&processingState, &storedProcessingFingerprint, &storedProcessingOwner, &processingStatus, &processingHeaders, &processingResponse, &processingAudit, &processingExpiry))
	require.Equal(t, "processing", processingState)
	require.Equal(t, processingFingerprint, storedProcessingFingerprint)
	require.Equal(t, processingOwner, storedProcessingOwner)
	require.Zero(t, processingStatus)
	require.JSONEq(t, `{}`, string(processingHeaders))
	require.Nil(t, processingResponse)
	require.Nil(t, processingAudit)
	require.Equal(t, expires, processingExpiry.UTC())
	var completedState, storedCompletedOwner, storedCompletedFingerprint string
	var completedStatus int
	var storedHeaders, storedBody, completedAudit []byte
	var completedExpiry time.Time
	require.NoError(t, database.QueryRowContext(ctx, "SELECT state, request_fingerprint, owner_token, response_status, response_headers, response_json, audit_event_json, expires_at FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND idempotency_key = $3", "tenant-upgrade", "project-upgrade", "legacy-completed").Scan(&completedState, &storedCompletedFingerprint, &storedCompletedOwner, &completedStatus, &storedHeaders, &storedBody, &completedAudit, &completedExpiry))
	require.Equal(t, "completed", completedState)
	require.Equal(t, completedFingerprint, storedCompletedFingerprint)
	require.Equal(t, completedOwner, storedCompletedOwner)
	require.Equal(t, http.StatusAccepted, completedStatus)
	require.JSONEq(t, completedHeaders, string(storedHeaders))
	require.Equal(t, completedBody, storedBody)
	require.Nil(t, completedAudit)
	require.Equal(t, expires, completedExpiry.UTC())
	var customConstraint int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM pg_constraint WHERE conrelid = 'idempotency_records'::regclass AND conname = 'customer_state_policy'").Scan(&customConstraint))
	require.Equal(t, 1, customConstraint)
	var migrationCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM dbpilot_schema_migrations WHERE name = $1", "platformdb/migrations/0005_http_idempotency_reconciliation.sql").Scan(&migrationCount))
	require.Equal(t, 1, migrationCount)
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
