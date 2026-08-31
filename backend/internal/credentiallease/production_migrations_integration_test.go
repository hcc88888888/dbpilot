package credentiallease_test

import (
	"context"
	"database/sql"
	"dbpilot.local/platform/internal/credentiallease"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/pluginassignment"
	"dbpilot.local/platform/internal/plugincatalog"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresProductionMigrationOrderExposesDurableRenewalIdentity(t *testing.T) {
	if os.Getenv("DBPILOT_CREDENTIAL_LEASE_POSTGRES_INTEGRATION") != "1" {
		t.Skip("integration disabled")
	}
	dsn := os.Getenv("DBPILOT_CREDENTIAL_LEASE_POSTGRES_DSN")
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.Ping())
	schema := fmt.Sprintf("dbpilot_task11_production_%d", time.Now().UnixNano())
	quoted := `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	_, err = admin.Exec("CREATE SCHEMA " + quoted)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	db, err := sql.Open("postgres", parsed.String())
	require.NoError(t, err)
	require.NoError(t, db.Ping())
	t.Cleanup(func() {
		require.NoError(t, db.Close())
		_, e := admin.Exec("DROP SCHEMA " + quoted + " CASCADE")
		require.NoError(t, e)
		require.NoError(t, admin.Close())
	})
	ctx := context.Background()
	for _, migrate := range []func(context.Context, *sql.DB) error{platformdb.RunMigrations, job.RunMigrations, hostinventory.RunMigrations, discovery.RunMigrations, databaseinstance.RunMigrations, plugincatalog.RunMigrations, pluginassignment.RunMigrations, credentiallease.RunMigrations} {
		require.NoError(t, migrate(ctx, db))
	}
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='command_outbox' AND column_name='id'`).Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='credential_lease_audits' AND column_name='lease_id_hash'`).Scan(&count))
	require.Equal(t, 1, count)
}
