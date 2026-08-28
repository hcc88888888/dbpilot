package idempotency_test

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

	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestPostgresClaimFencingIntegration(t *testing.T) {
	if os.Getenv("DBPILOT_IDEMPOTENCY_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_IDEMPOTENCY_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_IDEMPOTENCY_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_IDEMPOTENCY_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin := openIdempotencyIntegrationDB(t, ctx, dsn)
	schema := fmt.Sprintf("idempotency_fencing_%d", time.Now().UnixNano())
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

	database := openIdempotencyIntegrationDB(t, ctx, idempotencyIntegrationDSN(t, dsn, schema))
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	require.NoError(t, platformdb.RunMigrations(ctx, database))

	store := idempotency.NewPostgresStore(database)
	key := idempotency.Key{
		Scope: platformscope.Scope{TenantID: "tenant-integration", ProjectID: "project-integration"},
		Actor: "operator-integration", OperationID: "cancelJob", IdempotencyKey: "cancel-integration",
	}
	fingerprint := "sha256:0a9896a42ff3a8f7c9edfe3c97cc1e9d2b6bc06122f89876a49ea3bc4cc51b59"
	ownerOne := "owner-1111111111111111111111111111111111111111111111111111111111111111"
	ownerTwo := "owner-2222222222222222222222222222222222222222222222222222222222222222"
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)

	claim, err := store.Claim(ctx, key, fingerprint, ownerOne, now, now.Add(time.Hour))
	require.NoError(t, err)
	require.True(t, claim.Claimed)
	require.Equal(t, ownerOne, claim.OwnerToken)

	claim, err = store.Claim(ctx, key, fingerprint, ownerTwo, now.Add(48*time.Hour), now.Add(49*time.Hour))
	require.ErrorIs(t, err, idempotency.ErrInProgress, "processing must not be reclaimed after expiry")
	require.False(t, claim.Claimed)

	result, err := database.ExecContext(ctx, "UPDATE idempotency_records SET owner_token = $1 WHERE tenant_id = $2 AND project_id = $3 AND actor = $4 AND operation_id = $5 AND idempotency_key = $6 AND state = 'processing'", ownerTwo, key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey)
	require.NoError(t, err)
	updated, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), updated)

	response := idempotency.Response{Status: http.StatusAccepted, Header: http.Header{"ETag": {`"8"`}}, Body: []byte(`{"id":"job-1","version":8}`)}
	_, err = store.CommitSideEffect(ctx, key, fingerprint, ownerOne, response, now.Add(48*time.Hour))
	require.ErrorIs(t, err, idempotency.ErrOwnershipConflict)
	err = store.Abort(ctx, key, fingerprint, ownerOne)
	require.ErrorIs(t, err, idempotency.ErrOwnershipConflict)

	var storedOwner, state string
	require.NoError(t, database.QueryRowContext(ctx, "SELECT owner_token, state FROM idempotency_records WHERE tenant_id = $1 AND project_id = $2 AND actor = $3 AND operation_id = $4 AND idempotency_key = $5", key.Scope.TenantID, key.Scope.ProjectID, key.Actor, key.OperationID, key.IdempotencyKey).Scan(&storedOwner, &state))
	require.Equal(t, ownerTwo, storedOwner)
	require.Equal(t, string(idempotency.StateProcessing), state)

	committed, err := store.CommitSideEffect(ctx, key, fingerprint, ownerTwo, response, now.Add(48*time.Hour))
	require.NoError(t, err)
	require.Equal(t, response, committed)
	require.NoError(t, store.MarkAudited(ctx, key, fingerprint, ownerTwo, now.Add(48*time.Hour)))
	completed, err := store.Complete(ctx, key, fingerprint, ownerTwo, response, now.Add(48*time.Hour))
	require.NoError(t, err)
	require.Equal(t, response, completed)
}

func openIdempotencyIntegrationDB(t *testing.T, ctx context.Context, dsn string) *sql.DB {
	t.Helper()
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, database.PingContext(ctx))
	return database
}

func idempotencyIntegrationDSN(t *testing.T, dsn, schema string) string {
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
