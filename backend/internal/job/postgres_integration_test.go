package job

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestPostgresIntegration(t *testing.T) {
	if os.Getenv("DBPILOT_JOB_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_JOB_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_JOB_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_JOB_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	require.NoError(t, database.PingContext(ctx))

	resetJobIntegrationSchema(t, ctx, database)
	require.NoError(t, RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	assertJobDDL(t, ctx, database)

	repository := NewPostgresRepository(database)
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	assertModuleRollbackIsAtomic(t, ctx, database, repository, now)
	claimed := assertConcurrentClaimsAreUnique(t, ctx, repository, now)
	assertScopedPublication(t, ctx, repository, claimed[0], now.Add(time.Second))
	for _, message := range claimed[1:] {
		require.NoError(t, repository.MarkOutboxPublished(ctx, message.Scope, message.ID, now.Add(time.Second)))
	}
	assertLeaseExpiryReclaims(t, ctx, repository, now.Add(2*time.Minute))
}

func resetJobIntegrationSchema(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	_, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "DROP TABLE IF EXISTS command_outbox, job_targets, jobs CASCADE")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "DELETE FROM dbpilot_schema_migrations WHERE name IN ($1, $2)", "job/migrations/0001_jobs_outbox.sql", "job/migrations/0002_command_payload_bytea.sql")
	require.NoError(t, err)
}

func assertJobDDL(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	var jobs, targets, outbox string
	require.NoError(t, database.QueryRowContext(ctx, "SELECT 'jobs'::regclass::text, 'job_targets'::regclass::text, 'command_outbox'::regclass::text").Scan(&jobs, &targets, &outbox))
	require.Equal(t, []string{"jobs", "job_targets", "command_outbox"}, []string{jobs, targets, outbox})
	var applied int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM dbpilot_schema_migrations WHERE name = $1", "job/migrations/0001_jobs_outbox.sql").Scan(&applied))
	require.Equal(t, 1, applied)
}

func assertModuleRollbackIsAtomic(t *testing.T, ctx context.Context, database *sql.DB, repository *PostgresRepository, at time.Time) {
	t.Helper()
	_, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS integration_business_resources (id TEXT PRIMARY KEY)")
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "TRUNCATE integration_business_resources")
	require.NoError(t, err)

	value, message := integrationPersistenceFixture("rollback", platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, at.Add(-time.Minute))
	tx, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, "INSERT INTO integration_business_resources (id) VALUES ($1)", "business-rollback")
	require.NoError(t, err)
	require.NoError(t, repository.CreateInTx(ctx, tx, value, []OutboxMessage{message}))
	require.NoError(t, tx.Rollback())

	var businessCount, jobCount, outboxCount int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM integration_business_resources WHERE id = $1", "business-rollback").Scan(&businessCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE id = $1", value.ID).Scan(&jobCount))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM command_outbox WHERE id = $1", message.ID).Scan(&outboxCount))
	require.Equal(t, []int{0, 0, 0}, []int{businessCount, jobCount, outboxCount})
}

func assertConcurrentClaimsAreUnique(t *testing.T, ctx context.Context, repository *PostgresRepository, at time.Time) []OutboxMessage {
	t.Helper()
	for index := 0; index < 4; index++ {
		scope := platformscope.Scope{TenantID: fmt.Sprintf("tenant-%d", index%2), ProjectID: fmt.Sprintf("project-%d", index%2)}
		value, message := integrationPersistenceFixture(fmt.Sprintf("claim-%d", index), scope, at.Add(-time.Duration(10-index)*time.Minute))
		require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))
	}

	start := make(chan struct{})
	results := make(chan []OutboxMessage, 2)
	errorsChannel := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			messages, err := repository.ClaimOutbox(ctx, 2, at)
			if err != nil {
				errorsChannel <- err
				return
			}
			results <- messages
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		require.NoError(t, err)
	}
	var claimed []OutboxMessage
	for messages := range results {
		claimed = append(claimed, messages...)
	}
	require.Len(t, claimed, 4)
	ids := make([]string, len(claimed))
	for index, message := range claimed {
		require.NoError(t, message.Scope.Validate())
		ids[index] = message.ID
	}
	sort.Strings(ids)
	require.Equal(t, []string{"message-claim-0", "message-claim-1", "message-claim-2", "message-claim-3"}, ids)
	return claimed
}

func assertScopedPublication(t *testing.T, ctx context.Context, repository *PostgresRepository, message OutboxMessage, at time.Time) {
	t.Helper()
	wrongScope := platformscope.Scope{TenantID: message.Scope.TenantID + "-wrong", ProjectID: message.Scope.ProjectID}
	require.ErrorIs(t, repository.MarkOutboxPublished(ctx, wrongScope, message.ID, at), ErrNotFound)
	var published sql.NullTime
	require.NoError(t, repository.db.QueryRowContext(ctx, "SELECT published_at FROM command_outbox WHERE tenant_id = $1 AND project_id = $2 AND id = $3", message.Scope.TenantID, message.Scope.ProjectID, message.ID).Scan(&published))
	require.False(t, published.Valid)
	require.NoError(t, repository.MarkOutboxPublished(ctx, message.Scope, message.ID, at))
}

func assertLeaseExpiryReclaims(t *testing.T, ctx context.Context, repository *PostgresRepository, at time.Time) {
	t.Helper()
	scope := platformscope.Scope{TenantID: "tenant-lease", ProjectID: "project-lease"}
	value, message := integrationPersistenceFixture("lease", scope, at.Add(-time.Minute))
	require.NoError(t, repository.CreateWithOutbox(ctx, value, []OutboxMessage{message}))

	first, err := repository.ClaimOutbox(ctx, 1, at)
	require.NoError(t, err)
	require.Len(t, first, 1)
	require.Equal(t, message.ID, first[0].ID)
	second, err := repository.ClaimOutbox(ctx, 1, at.Add(time.Second))
	require.NoError(t, err)
	require.Empty(t, second)
	reclaimed, err := repository.ClaimOutbox(ctx, 1, at.Add(DefaultOutboxLease+time.Second))
	require.NoError(t, err)
	require.Len(t, reclaimed, 1)
	require.Equal(t, message.ID, reclaimed[0].ID)
	require.Equal(t, 2, reclaimed[0].Attempts)
	require.NoError(t, repository.MarkOutboxPublished(ctx, scope, message.ID, at.Add(DefaultOutboxLease+2*time.Second)))
}

func integrationPersistenceFixture(suffix string, scope platformscope.Scope, createdAt time.Time) (Job, OutboxMessage) {
	createdAt = createdAt.UTC()
	timeout := createdAt.Add(time.Hour)
	value := Job{
		ID: "job-" + suffix, Type: "integration.run", Scope: scope, Status: StatusQueued, Outcome: OutcomeNone,
		TargetResourceIDs: []string{"target-" + suffix}, InitiatedBy: "integration-test",
		SourceResource: ResourceReference{ResourceType: "integration", ResourceID: "resource-" + suffix},
		IdempotencyKey: "idempotency-" + suffix, Version: 1, Progress: Progress{TotalTargets: 1},
		Artifacts: []ArtifactReference{}, CreatedAt: createdAt, TimeoutAt: &timeout, RequestID: "request-" + suffix, TraceID: "trace-" + suffix,
	}
	message := OutboxMessage{
		ID: "message-" + suffix, Scope: scope, JobID: value.ID, TargetID: value.TargetResourceIDs[0], Type: "agent.command",
		Payload: []byte(fmt.Sprintf(`{"command_id":%q}`, "command-"+suffix)), AvailableAt: createdAt, CreatedAt: createdAt,
	}
	return value, message
}
