package discovery

import (
	"context"
	"crypto/ed25519"
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
	service.Now = func() time.Time { return now.Add(24 * time.Hour) }
	service.DisappearanceGrace = 10 * time.Minute
	attestation, key := signedTestAttestation(t, now, 4, 10*time.Minute)
	service.RuleKeys = map[string]ed25519.PublicKey{"test": key}
	service.Policies = StaticRulePolicyRegistry{Allowed: []RuleAttestation{attestation}}
	firstReport := Report{HostID: hostID, AgentID: agentID, ObservationRevision: 1, RuleRevision: 4, Candidates: []CandidateObservation{observation}, ObservedAt: now, RuleAttestation: attestation}
	start := make(chan struct{})
	results := make(chan []Candidate, 2)
	failures := make(chan error, 2)
	for index := 0; index < 2; index++ {
		go func() {
			<-start
			values, recordErr := service.RecordReport(ctx, firstReport)
			results <- values
			failures <- recordErr
		}()
	}
	close(start)
	first := <-results
	firstErr := <-failures
	secondConcurrent := <-results
	secondErr := <-failures
	require.NoError(t, firstErr)
	require.NoError(t, secondErr)
	require.Len(t, first, 1)
	require.Len(t, secondConcurrent, 1)
	firstSeen := first[0].FirstSeenAt
	require.Equal(t, firstSeen, secondConcurrent[0].FirstSeenAt)
	service.Now = func() time.Time { return now.Add(2 * time.Hour) }
	service.Policies = StaticRulePolicyRegistry{}
	service.RuleKeys = map[string]ed25519.PublicKey{}
	delayed, err := service.RecordReport(ctx, firstReport)
	require.NoError(t, err)
	require.Len(t, delayed, 1, "exact committed replay must bypass current expiry and skew admission")
	alteredSignature := firstReport
	alteredSignature.RuleAttestation.Signature = append([]byte(nil), firstReport.RuleAttestation.Signature...)
	alteredSignature.RuleAttestation.Signature[0] ^= 0xff
	_, err = service.RecordReport(ctx, alteredSignature)
	require.ErrorIs(t, err, ErrInvalidSignature, "same payload with changed signature must not match committed wire digest")
	service.Now = func() time.Time { return now }
	service.RuleKeys = map[string]ed25519.PublicKey{"test": key}
	service.Policies = StaticRulePolicyRegistry{Allowed: []RuleAttestation{attestation}}
	replayed, err := service.RecordReport(ctx, Report{HostID: hostID, AgentID: agentID, ObservationRevision: 1, RuleRevision: 4, Candidates: []CandidateObservation{observation}, ObservedAt: now, RuleAttestation: attestation})
	require.NoError(t, err)
	require.Len(t, replayed, 1)
	require.Equal(t, firstSeen, replayed[0].FirstSeenAt)
	conflicting := firstReport
	conflicting.Candidates = append([]CandidateObservation(nil), firstReport.Candidates...)
	conflicting.Candidates[0].VersionHint = "8.4"
	conflicting.Candidates[0].Evidence = append(conflicting.Candidates[0].Evidence, Evidence{Kind: EvidenceVersionHint, Value: "8.4"})
	_, err = service.RecordReport(ctx, conflicting)
	require.ErrorIs(t, err, ErrConflict)
	_, err = service.RecordReport(ctx, Report{HostID: hostID, AgentID: agentID, ObservationRevision: 0, RuleRevision: 4, ObservedAt: now, RuleAttestation: attestation})
	require.Error(t, err)
	_, err = database.ExecContext(ctx, "UPDATE discovery_candidates SET first_seen_at=CURRENT_TIMESTAMP-INTERVAL '11 minutes',last_seen_at=CURRENT_TIMESTAMP-INTERVAL '11 minutes' WHERE tenant_id=$1 AND project_id=$2 AND host_id=$3", scope.TenantID, scope.ProjectID, hostID)
	require.NoError(t, err)
	secondObserved := time.Now().UTC().Truncate(time.Microsecond)
	page, err := service.RecordReport(ctx, Report{HostID: hostID, AgentID: agentID, ObservationRevision: 2, RuleRevision: 4, ObservedAt: secondObserved, RuleAttestation: attestation})
	require.NoError(t, err)
	require.Len(t, page, 1)
	require.Equal(t, StatusDisappeared, page[0].Status)
}
