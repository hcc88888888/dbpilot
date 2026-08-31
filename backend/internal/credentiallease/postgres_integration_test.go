package credentiallease

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestPostgresAuthorizerRequiresExactCurrentLeaseScopeAndExecutionFence(t *testing.T) {
	database := credentialLeasePostgresFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := database.ExecContext(ctx, `INSERT INTO plugin_assignments VALUES ('tenant-1','project-1','host-1','agent-1','assignment-1','mysql',5,7,'running')`)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `INSERT INTO plugin_assignment_instances VALUES ('tenant-1','project-1','assignment-1','instance-1')`)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `INSERT INTO managed_database_instances VALUES ('tenant-1','project-1','host-1','agent-1','instance-1','mysql',9,'secret://database/instance-1','secret://tls/instance-1','monitoring',5)`)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `INSERT INTO plugin_reconcile_operations VALUES ('tenant-1','project-1','assignment-1',5,7,'command-1')`)
	require.NoError(t, err)
	fence := &integrationFence{active: true, commandID: "command-1", now: now}
	authorizer := PostgresAuthorizer{Database: database, Fences: fence}
	agent := AuthenticatedAgent{AgentID: "agent-1", SessionID: "session-1"}
	request := LeaseRequest{Nonce: make([]byte, 32), AssignmentID: "assignment-1", InstanceID: "instance-1", ConfigurationRevision: 5}

	grant, err := authorizer.Authorize(ctx, agent, request)
	require.NoError(t, err)
	require.Equal(t, uint64(7), grant.OperationRevision)
	require.Equal(t, uint64(9), grant.InstanceRevision)
	require.Equal(t, "secret://database/instance-1", grant.CredentialRef)
	require.Equal(t, "command-1", fence.seenCommandID)

	wrongAgent := agent
	wrongAgent.AgentID = "agent-2"
	_, err = authorizer.Authorize(ctx, wrongAgent, request)
	require.ErrorIs(t, err, ErrLeaseRejected)
	stale := request
	stale.ConfigurationRevision = 4
	_, err = authorizer.Authorize(ctx, agent, stale)
	require.ErrorIs(t, err, ErrLeaseRejected)

	_, err = database.ExecContext(ctx, `DELETE FROM plugin_assignment_instances`)
	require.NoError(t, err)
	_, err = authorizer.Authorize(ctx, agent, request)
	require.ErrorIs(t, err, ErrLeaseRejected)
	_, err = database.ExecContext(ctx, `INSERT INTO plugin_assignment_instances VALUES ('tenant-1','project-1','assignment-1','instance-1')`)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `UPDATE managed_database_instances SET management_status='retired'`)
	require.NoError(t, err)
	_, err = authorizer.Authorize(ctx, agent, request)
	require.ErrorIs(t, err, ErrLeaseRejected)
	_, err = database.ExecContext(ctx, `UPDATE managed_database_instances SET management_status='monitoring'`)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `UPDATE plugin_assignments SET desired_state='stopped'`)
	require.NoError(t, err)
	_, err = authorizer.Authorize(ctx, agent, request)
	require.ErrorIs(t, err, ErrLeaseRejected)
	_, err = database.ExecContext(ctx, `UPDATE plugin_assignments SET desired_state='running'`)
	require.NoError(t, err)
	fence.active = false
	_, err = authorizer.Authorize(ctx, agent, request)
	require.ErrorIs(t, err, ErrLeaseRejected)
}

type integrationFence struct {
	active        bool
	commandID     string
	seenCommandID string
	now           time.Time
}

func (fence *integrationFence) ExecutionLeaseActive(_ string, commandID string, at time.Time) bool {
	fence.seenCommandID = commandID
	return fence.active && commandID == fence.commandID && !at.Before(fence.now.Add(-time.Minute))
}

func credentialLeasePostgresFixture(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("DBPILOT_CREDENTIAL_LEASE_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_CREDENTIAL_LEASE_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_CREDENTIAL_LEASE_POSTGRES_DSN")
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.Ping())
	schema := fmt.Sprintf("dbpilot_task11_%d", time.Now().UnixNano())
	quoted := `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	_, err = admin.Exec("CREATE SCHEMA " + quoted)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	database, err := sql.Open("postgres", parsed.String())
	require.NoError(t, err)
	require.NoError(t, database.Ping())
	t.Cleanup(func() {
		require.NoError(t, database.Close())
		_, dropErr := admin.Exec("DROP SCHEMA " + quoted + " CASCADE")
		require.NoError(t, dropErr)
		require.NoError(t, admin.Close())
	})
	statements := []string{
		`CREATE TABLE plugin_assignments (tenant_id TEXT,project_id TEXT,host_id TEXT,agent_id TEXT,assignment_id TEXT,database_family TEXT,configuration_revision BIGINT,operation_revision BIGINT,desired_state TEXT)`,
		`CREATE TABLE plugin_assignment_instances (tenant_id TEXT,project_id TEXT,assignment_id TEXT,instance_id TEXT)`,
		`CREATE TABLE managed_database_instances (tenant_id TEXT,project_id TEXT,host_id TEXT,agent_id TEXT,instance_id TEXT,database_family TEXT,revision BIGINT,credential_ref TEXT,tls_ref TEXT,management_status TEXT,plugin_assignment_revision BIGINT)`,
		`CREATE TABLE plugin_reconcile_operations (tenant_id TEXT,project_id TEXT,assignment_id TEXT,configuration_revision BIGINT,operation_revision BIGINT,command_id TEXT)`,
	}
	for _, statement := range statements {
		_, err = database.Exec(statement)
		require.NoError(t, err)
	}
	return database
}
