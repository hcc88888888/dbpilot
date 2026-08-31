package pluginassignment

import (
	"context"
	"regexp"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestLoadPluginInstanceDescriptorsQueriesExactHostOwnershipFence(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	assignment := Assignment{ID: "assignment-a", Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, HostID: "host-a", AgentID: "agent-a", PluginID: "dbpilot.mysql", DatabaseFamily: "mysql", DesiredVersionID: "version-a", DesiredVersion: "1.0.0", ArtifactID: "artifact-a", ArtifactSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", DesiredState: DesiredRunning, ConfigurationRevision: 1, OperationRevision: 1, RolloutPercentage: 100, InstanceIDs: []string{"instance-a"}, ReconcileState: ReconcilePending, Revision: 1, CreatedAt: now, UpdatedAt: now}
	query := `SELECT instance_id,database_variant,endpoint,unix_socket FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3 AND agent_id=$4 AND database_family=$5 AND management_status<>'retired' AND instance_id = ANY($6) ORDER BY instance_id`
	mock.ExpectQuery(regexp.QuoteMeta(query)).WithArgs("tenant-a", "project-a", "host-a", "agent-a", "mysql", sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{"instance_id", "database_variant", "endpoint", "unix_socket"}).AddRow("instance-a", "mysql", "127.0.0.1:3306", ""))

	values, err := NewPostgresRepository(database, nil).LoadPluginInstanceDescriptors(context.Background(), assignment)
	require.NoError(t, err)
	require.Len(t, values, 1)
	mock.ExpectClose()
	require.NoError(t, database.Close())
	require.NoError(t, mock.ExpectationsWereMet())
}
