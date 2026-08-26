package alert

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// Run with a disposable PostgreSQL database, for example:
//
//	DBPILOT_ALERT_POSTGRES_INTEGRATION=1 \
//	  DBPILOT_ALERT_POSTGRES_DSN=postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable \
//	  go test ./internal/alert -run TestPostgresConcurrentFirstEventWritesAreSerialized -count=1
func TestPostgresConcurrentFirstEventWritesAreSerialized(t *testing.T) {
	if os.Getenv("DBPILOT_ALERT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ALERT_POSTGRES_INTEGRATION=1 to run the PostgreSQL concurrency integration test")
	}
	dsn := os.Getenv("DBPILOT_ALERT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ALERT_POSTGRES_DSN is required when DBPILOT_ALERT_POSTGRES_INTEGRATION=1")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin := openAlertIntegrationDB(t, dsn, "alert-race-admin")
	schema := fmt.Sprintf("alert_race_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err := admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanupCtx, "DROP SCHEMA IF EXISTS "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})

	setupAlertConcurrencySchema(t, ctx, admin, quotedSchema)
	writerOneDB := openAlertIntegrationDB(t, alertIntegrationDSN(t, dsn, schema, "alert-race-writer-1"), "")
	writerTwoDB := openAlertIntegrationDB(t, alertIntegrationDSN(t, dsn, schema, "alert-race-writer-2"), "")
	writerOneDB.SetMaxOpenConns(1)
	writerTwoDB.SetMaxOpenConns(1)
	t.Cleanup(func() {
		require.NoError(t, writerOneDB.Close())
		require.NoError(t, writerTwoDB.Close())
	})

	gate, err := admin.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gate.Close()) })
	_, err = gate.ExecContext(ctx, "SELECT pg_advisory_lock($1, $2)", int32(2147483647), int32(2147483646))
	require.NoError(t, err)

	at := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	scope := Scope{TenantID: "tenant-concurrent", ProjectID: "project-concurrent"}
	first := AlertEvent{ID: "event-first", Scope: scope, RuleID: "rule-1", Fingerprint: "shared-fingerprint", Labels: map[string]string{"host": "db-a"}, Evidence: map[string]string{}, State: EventPending, FirstSeen: at, LastSeen: at, LastActor: "system:evaluator"}
	second := first
	second.ID = "event-second"
	second.FirstSeen = at.Add(-time.Minute)
	second.LastSeen = second.FirstSeen

	type writeResult struct {
		writer int
		err    error
	}
	results := make(chan writeResult, 2)
	go func() {
		_, writeErr := NewPostgresRepository(writerOneDB).PutEvent(ctx, first)
		results <- writeResult{writer: 1, err: writeErr}
	}()
	waitForAdvisoryWait(t, ctx, admin, "alert-race-writer-1")
	go func() {
		_, writeErr := NewPostgresRepository(writerTwoDB).PutEvent(ctx, second)
		results <- writeResult{writer: 2, err: writeErr}
	}()
	waitForAdvisoryWait(t, ctx, admin, "alert-race-writer-2")

	_, err = gate.ExecContext(ctx, "SELECT pg_advisory_unlock($1, $2)", int32(2147483647), int32(2147483646))
	require.NoError(t, err)
	one, two := <-results, <-results
	byWriter := map[int]error{one.writer: one.err, two.writer: two.err}
	require.NoError(t, byWriter[1])
	require.ErrorIs(t, byWriter[2], ErrInvalidEventTransition)

	var eventID string
	var firstSeen time.Time
	require.NoError(t, writerOneDB.QueryRowContext(ctx, "SELECT id, first_seen FROM alert_events WHERE tenant_id = $1 AND project_id = $2 AND fingerprint = $3", scope.TenantID, scope.ProjectID, first.Fingerprint).Scan(&eventID, &firstSeen))
	require.Equal(t, first.ID, eventID)
	require.True(t, first.FirstSeen.Equal(firstSeen))
	var auditCount int
	require.NoError(t, writerOneDB.QueryRowContext(ctx, "SELECT count(*) FROM alert_audit_log WHERE tenant_id = $1 AND project_id = $2", scope.TenantID, scope.ProjectID).Scan(&auditCount))
	require.Equal(t, 1, auditCount)
}

func setupAlertConcurrencySchema(t *testing.T, ctx context.Context, db *sql.DB, schema string) {
	t.Helper()
	statements := []string{
		"CREATE TABLE " + schema + ".alert_events (id TEXT NOT NULL, tenant_id TEXT NOT NULL, project_id TEXT NOT NULL, rule_id TEXT NOT NULL, fingerprint TEXT NOT NULL, labels JSONB NOT NULL DEFAULT '{}'::jsonb, evidence JSONB NOT NULL DEFAULT '{}'::jsonb, state TEXT NOT NULL, first_seen TIMESTAMPTZ NOT NULL, last_seen TIMESTAMPTZ NOT NULL, firing_at TIMESTAMPTZ, acknowledged_at TIMESTAMPTZ, resolved_at TIMESTAMPTZ, last_actor TEXT NOT NULL DEFAULT '', PRIMARY KEY (tenant_id, project_id, id), UNIQUE (tenant_id, project_id, fingerprint))",
		"CREATE TABLE " + schema + ".alert_audit_log (id TEXT NOT NULL, tenant_id TEXT NOT NULL, project_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, target_id TEXT NOT NULL, occurred_at TIMESTAMPTZ NOT NULL, details JSONB NOT NULL DEFAULT '{}'::jsonb, PRIMARY KEY (tenant_id, project_id, id))",
		"CREATE FUNCTION " + schema + ".hold_first_event_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2147483647, 2147483646); RETURN NEW; END $$",
		"CREATE TRIGGER hold_first_event_insert BEFORE INSERT ON " + schema + ".alert_events FOR EACH ROW EXECUTE FUNCTION " + schema + ".hold_first_event_insert()",
	}
	for _, statement := range statements {
		_, err := db.ExecContext(ctx, statement)
		require.NoError(t, err)
	}
}

func openAlertIntegrationDB(t *testing.T, dsn, applicationName string) *sql.DB {
	t.Helper()
	if applicationName != "" {
		dsn = alertIntegrationDSN(t, dsn, "", applicationName)
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, db.PingContext(ctx))
	return db
}

func alertIntegrationDSN(t *testing.T, dsn, schema, applicationName string) string {
	t.Helper()
	if strings.Contains(dsn, "://") {
		parsed, err := url.Parse(dsn)
		require.NoError(t, err)
		query := parsed.Query()
		if schema != "" {
			query.Set("search_path", schema)
		}
		if applicationName != "" {
			query.Set("application_name", applicationName)
		}
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	if schema != "" {
		dsn += " search_path=" + schema
	}
	if applicationName != "" {
		dsn += " application_name=" + applicationName
	}
	return dsn
}

func waitForAdvisoryWait(t *testing.T, ctx context.Context, db *sql.DB, applicationName string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		err := db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = $1 AND wait_event_type = 'Lock' AND lower(wait_event) = 'advisory')", applicationName).Scan(&waiting)
		require.NoError(t, err)
		if waiting {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("writer %s did not reach an advisory-lock wait: %v", applicationName, ctx.Err())
		case <-ticker.C:
		}
	}
}
