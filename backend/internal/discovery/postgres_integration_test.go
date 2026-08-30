package discovery

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformscope"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryPostgresIntegrationFencesRevisionAndMarksDisappeared(t *testing.T) {
	if os.Getenv("DBPILOT_DISCOVERY_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_DISCOVERY_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_DISCOVERY_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_DISCOVERY_POSTGRES_DSN is required")
	}
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	ctx := context.Background()
	require.NoError(t, database.PingContext(ctx))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	suffix := time.Now().UTC().Format("150405.000000000")
	scope := platformscope.Scope{TenantID: "tenant-discovery-" + suffix, ProjectID: "project-discovery-" + suffix}
	hostID, agentID := "host-discovery-"+suffix, "agent-discovery-"+suffix
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DELETE FROM discovery_candidates WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM discovery_scan_state WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM host_observations WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM managed_hosts WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
	})
	now := time.Now().UTC().Truncate(time.Microsecond)
	hostObservation := hostinventory.Observation{HostID: hostID, AgentID: agentID, Revision: 1, AgentVersion: "test", Hostname: "discovery.example", OS: "linux", Architecture: "amd64", LogicalCPUCount: 1, MemoryCapacityBytes: 1024, NetworkAddresses: []string{}, Capabilities: []string{"native_discovery_v1"}, ObservedAt: now}
	_, err = hostinventory.NewPostgresRepository(database).RecordObservation(ctx, scope, hostObservation, now)
	require.NoError(t, err)
	observation := CandidateObservation{ObservationID: "proc-100-1", Source: SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .8, Evidence: []Evidence{{Kind: EvidenceProcessName, Value: "mysqld"}}, ObservedAt: now}
	fingerprint, err := Fingerprint(hostID, observation)
	require.NoError(t, err)
	observation.Fingerprint = fingerprint
	service := NewService(NewPostgresRepository(database))
	service.Now = func() time.Time { return now }
	service.DisappearanceGrace = 10 * time.Minute
	first, err := service.RecordReport(ctx, Report{HostID: hostID, AgentID: agentID, ObservationRevision: 1, RuleRevision: 4, Candidates: []CandidateObservation{observation}, ObservedAt: now})
	require.NoError(t, err)
	require.Len(t, first, 1)
	firstSeen := first[0].FirstSeenAt
	replayed, err := service.RecordReport(ctx, Report{HostID: hostID, AgentID: agentID, ObservationRevision: 1, RuleRevision: 4, Candidates: []CandidateObservation{observation}, ObservedAt: now})
	require.NoError(t, err)
	require.Len(t, replayed, 1)
	require.Equal(t, firstSeen, replayed[0].FirstSeenAt)
	_, err = service.RecordReport(ctx, Report{HostID: hostID, AgentID: agentID, ObservationRevision: 0, RuleRevision: 4, ObservedAt: now})
	require.Error(t, err)
	later := now.Add(11 * time.Minute)
	service.Now = func() time.Time { return later }
	page, err := service.RecordReport(ctx, Report{HostID: hostID, AgentID: agentID, ObservationRevision: 2, RuleRevision: 4, ObservedAt: later})
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.Equal(t, StatusDisappeared, page[0].Status)
}
