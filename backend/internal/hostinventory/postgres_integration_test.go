package hostinventory

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestHostPostgresIntegrationKeepsScopeRevisionAndObservationHistory(t *testing.T) {
	if os.Getenv("DBPILOT_HOSTINVENTORY_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_HOSTINVENTORY_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_HOSTINVENTORY_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_HOSTINVENTORY_POSTGRES_DSN is required")
	}
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	ctx := context.Background()
	require.NoError(t, database.PingContext(ctx))
	_, err = database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS dbpilot_schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
	require.NoError(t, err)
	require.NoError(t, applyMigration(ctx, database, "migrations/0001_host_inventory.sql"))
	legacyAt := time.Now().UTC().Truncate(time.Microsecond)
	_, err = database.ExecContext(ctx, `INSERT INTO managed_hosts (
		tenant_id, project_id, host_id, agent_id, display_name, hostname, operating_system,
		architecture, observation_revision, enrolled_at, status, updated_at
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9, 'decommissioned', $9)`,
		"tenant-legacy", "project-legacy", "host-legacy", "agent-legacy", "Legacy host", "legacy.example", "linux", "amd64", legacyAt)
	require.NoError(t, err)
	require.NoError(t, RunMigrations(ctx, database))
	legacy, err := NewPostgresRepository(database).Get(ctx, platformscope.Scope{TenantID: "tenant-legacy", ProjectID: "project-legacy"}, "host-legacy")
	require.NoError(t, err)
	require.Equal(t, HostDecommissioned, legacy.Status)
	require.Nil(t, legacy.DecommissionTransition, "0002 must not invent causality for a pre-correlation transition")
	scope := platformscope.Scope{TenantID: "tenant-host-integration", ProjectID: "project-host-integration"}
	transaction, err := database.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = transaction.Rollback() })
	repository := NewPostgresRepository(transaction)
	first := validObservationFixture()
	first.HostID, first.AgentID, first.Revision = "host-integration", "agent-integration", 1
	first.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	host, err := repository.RecordObservation(ctx, scope, first, first.ObservedAt)
	require.NoError(t, err)
	require.True(t, host.LastHeartbeatAt.IsZero())
	second := first
	second.Revision, second.AgentVersion, second.ObservedAt = 2, "1.1.0", first.ObservedAt.Add(time.Second)
	host, err = repository.RecordObservation(ctx, scope, second, second.ObservedAt)
	require.NoError(t, err)
	require.Equal(t, uint64(2), host.ObservationRevision)

	stale := first
	stale.AgentVersion = "must-not-win"
	host, err = repository.RecordObservation(ctx, scope, stale, second.ObservedAt.Add(time.Second))
	require.ErrorIs(t, err, ErrStaleRevision)
	require.Equal(t, Host{}, host)
	equal := second
	equal.AgentVersion = "equal-replay-must-not-win"
	host, err = repository.RecordObservation(ctx, scope, equal, second.ObservedAt.Add(2*time.Second))
	require.NoError(t, err)
	require.Equal(t, uint64(2), host.ObservationRevision)
	require.Equal(t, "1.1.0", host.AgentVersion)
	_, err = transaction.ExecContext(ctx, "SAVEPOINT duplicate_agent")
	require.NoError(t, err)
	duplicateAgent := second
	duplicateAgent.HostID, duplicateAgent.Revision = "host-integration-duplicate", 3
	_, err = repository.RecordObservation(ctx, scope, duplicateAgent, duplicateAgent.ObservedAt.Add(time.Second))
	require.ErrorIs(t, err, ErrConflict)
	_, rollbackErr := transaction.ExecContext(ctx, "ROLLBACK TO SAVEPOINT duplicate_agent")
	require.NoError(t, rollbackErr)
	_, err = transaction.ExecContext(ctx, "RELEASE SAVEPOINT duplicate_agent")
	require.NoError(t, err)
	var observations int
	require.NoError(t, transaction.QueryRowContext(ctx, "SELECT count(*) FROM host_observations WHERE tenant_id = $1 AND project_id = $2 AND host_id = $3", scope.TenantID, scope.ProjectID, first.HostID).Scan(&observations))
	require.Equal(t, 2, observations)

	_, err = repository.Get(ctx, platformscope.Scope{TenantID: scope.TenantID, ProjectID: "other-project"}, first.HostID)
	require.True(t, errors.Is(err, ErrNotFound))
	heartbeatAt := second.ObservedAt.Add(time.Second)
	host, err = repository.RecordHeartbeat(ctx, scope, first.AgentID, heartbeatAt)
	require.NoError(t, err)
	require.Equal(t, heartbeatAt, host.LastHeartbeatAt)
	page, err := repository.List(ctx, scope, Filter{Status: HostOnline, Limit: 10, now: heartbeatAt, staleAfter: time.Minute, offlineAfter: 5 * time.Minute})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, first.HostID, page.Items[0].ID)
	transition := validDecommissionTransition()
	_, err = repository.Decommission(ctx, scope, first.HostID, host.Version+1, heartbeatAt.Add(time.Second), transition)
	require.ErrorIs(t, err, ErrConflict)
	host, err = repository.Decommission(ctx, scope, first.HostID, host.Version, heartbeatAt.Add(time.Second), transition)
	require.NoError(t, err)
	require.Equal(t, HostDecommissioned, host.Status)
	require.NotNil(t, host.DecommissionTransition)
	require.True(t, host.DecommissionTransition.Matches(transition))
	_, err = transaction.ExecContext(ctx, "UPDATE host_observations SET observed_at = observed_at WHERE tenant_id = $1 AND project_id = $2 AND host_id = $3", scope.TenantID, scope.ProjectID, first.HostID)
	require.Error(t, err, "append-only history must reject even a no-op UPDATE")
}
