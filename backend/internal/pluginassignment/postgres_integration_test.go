package pluginassignment_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"dbpilot.local/platform/internal/plugincatalog"
	"dbpilot.local/platform/internal/reconciliation"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestPluginAssignmentPostgresConcurrentProvisionObservationAndReconcile(t *testing.T) {
	database, scope, hostID, agentID := pluginAssignmentPostgresFixture(t)
	ctx := context.Background()
	jobs := job.NewPostgresRepositoryWithTargetAuthorizer(database, pluginassignment.InstanceTargetAuthorizer{Database: database})
	assignments := pluginassignment.NewPostgresRepository(database, jobs)
	instances := databaseinstance.NewPostgresRepositoryWithProvisioner(database, assignments)
	firstID, firstRequest := insertAssignmentCandidate(t, database, scope, hostID, agentID, "candidate-a", "127.0.0.1:3307", 12)
	secondID, secondRequest := insertAssignmentCandidate(t, database, scope, hostID, agentID, "candidate-b", "127.0.0.1:3308", 12)
	start := make(chan struct{})
	results := make(chan error, 24)
	var valuesMu sync.Mutex
	instanceIDs := map[string]struct{}{}
	for index := 0; index < 24; index++ {
		index := index
		go func() {
			<-start
			candidateID, request := firstID, firstRequest
			if index%2 == 1 {
				candidateID, request = secondID, secondRequest
			}
			value, err := instances.AcceptCandidate(ctx, scope, candidateID, request)
			if err == nil {
				valuesMu.Lock()
				instanceIDs[value.ID] = struct{}{}
				valuesMu.Unlock()
			}
			results <- err
		}()
	}
	close(start)
	var acceptanceErrors []error
	for index := 0; index < 24; index++ {
		if err := <-results; err != nil {
			acceptanceErrors = append(acceptanceErrors, err)
		}
	}
	require.Empty(t, acceptanceErrors)
	require.Len(t, instanceIDs, 2)
	page, err := assignments.List(ctx, scope, pluginassignment.Filter{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assignment := page.Items[0]
	require.Len(t, assignment.InstanceIDs, 2)
	require.Equal(t, uint64(2), assignment.ConfigurationRevision)
	require.Equal(t, uint64(2), assignment.OperationRevision)
	var assignmentCount, membershipCount int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM plugin_assignments WHERE tenant_id=$1 AND project_id=$2`, scope.TenantID, scope.ProjectID).Scan(&assignmentCount))
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM plugin_assignment_instances WHERE tenant_id=$1 AND project_id=$2`, scope.TenantID, scope.ProjectID).Scan(&membershipCount))
	require.Equal(t, 1, assignmentCount)
	require.Equal(t, 2, membershipCount)
	service := pluginassignment.NewService(assignments)
	seedIncompatiblePluginVersion(t, database, scope, time.Now().UTC())
	incompatible := "2.0.0"
	_, err = service.SetDesiredState(ctx, scope, assignment.ID, assignment.Revision, pluginassignment.DesiredUpdate{DesiredVersion: &incompatible, Audit: pluginassignment.MutationAudit{Actor: "operator", OperationID: "updatePluginAssignment", IdempotencyKey: "incompatible-version", RequestFingerprint: "sha256:abababababababababababababababababababababababababababababababab", RequestID: "request-incompatible"}})
	require.ErrorIs(t, err, pluginassignment.ErrVersionUnavailable)
	revisionRace := make(chan error, 2)
	for index, state := range []pluginassignment.DesiredState{pluginassignment.DesiredStopped, pluginassignment.DesiredInstalled} {
		index, state := index, state
		go func() {
			_, updateErr := service.SetDesiredState(ctx, scope, assignment.ID, assignment.Revision, pluginassignment.DesiredUpdate{DesiredState: &state, Audit: pluginassignment.MutationAudit{Actor: "operator", OperationID: "updatePluginAssignment", IdempotencyKey: fmt.Sprintf("revision-race-%d", index), RequestFingerprint: fmt.Sprintf("sha256:%064x", 100+index), RequestID: fmt.Sprintf("request-race-%d", index)}})
			revisionRace <- updateErr
		}()
	}
	firstRace, secondRace := <-revisionRace, <-revisionRace
	require.True(t, firstRace == nil && errors.Is(secondRace, pluginassignment.ErrPrecondition) || secondRace == nil && errors.Is(firstRace, pluginassignment.ErrPrecondition), "race results: first=%v second=%v", firstRace, secondRace)
	assignment, err = service.Get(ctx, scope, assignment.ID)
	require.NoError(t, err)
	running := pluginassignment.DesiredRunning
	assignment, err = service.SetDesiredState(ctx, scope, assignment.ID, assignment.Revision, pluginassignment.DesiredUpdate{DesiredState: &running, Audit: pluginassignment.MutationAudit{Actor: "operator", OperationID: "updatePluginAssignment", IdempotencyKey: "restore-running", RequestFingerprint: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", RequestID: "request-restore-running"}})
	require.NoError(t, err)

	reconciler := reconciliation.NewPluginReconciler(assignments)
	reconcileStart := make(chan struct{})
	reconcileResults := make(chan reconciliation.ReconcileResult, 24)
	reconcileErrors := make(chan error, 24)
	for index := 0; index < 24; index++ {
		go func() {
			<-reconcileStart
			result, err := reconciler.Reconcile(ctx, time.Now().UTC(), 10)
			reconcileResults <- result
			reconcileErrors <- err
		}()
	}
	close(reconcileStart)
	enqueued := 0
	for index := 0; index < 24; index++ {
		require.NoError(t, <-reconcileErrors)
		enqueued += (<-reconcileResults).Enqueued
	}
	require.Equal(t, 1, enqueued)
	var jobCount, outboxCount int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE tenant_id=$1 AND project_id=$2 AND job_type='plugin.reconcile'`, scope.TenantID, scope.ProjectID).Scan(&jobCount))
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM command_outbox o JOIN jobs j ON j.tenant_id=o.tenant_id AND j.project_id=o.project_id AND j.id=o.job_id WHERE j.tenant_id=$1 AND j.project_id=$2 AND j.job_type='plugin.reconcile'`, scope.TenantID, scope.ProjectID).Scan(&outboxCount))
	require.Equal(t, 1, jobCount)
	require.Equal(t, 1, outboxCount)

	now := time.Now().UTC().Truncate(time.Microsecond)
	observed := pluginassignment.ObservedState{AssignmentID: assignment.ID, PluginID: assignment.PluginID, DatabaseFamily: assignment.DatabaseFamily, InstalledVersion: assignment.DesiredVersion, ActiveSlot: pluginassignment.SlotA, ProcessState: pluginassignment.ProcessRunning, Health: pluginassignment.HealthHealthy, CircuitState: pluginassignment.CircuitClosed, BoundInstanceCount: 2, ActiveConfigurationRevision: assignment.ConfigurationRevision, ObservedOperationRevision: assignment.OperationRevision, ObservationRevision: 5, ObservedAt: now}
	require.NoError(t, service.RecordObservation(ctx, pluginassignment.ObservationReport{Scope: scope, HostID: hostID, AgentID: agentID, ObservationRevision: 5, Assignments: []pluginassignment.ObservedState{observed}, ObservedAt: now}))
	matching, err := reconciler.Reconcile(ctx, time.Now().UTC(), 10)
	require.NoError(t, err)
	require.Zero(t, matching.Enqueued)
	require.Zero(t, matching.Claimed)
	observed.ObservationRevision = 4
	require.ErrorIs(t, service.RecordObservation(ctx, pluginassignment.ObservationReport{Scope: scope, HostID: hostID, AgentID: agentID, ObservationRevision: 4, Assignments: []pluginassignment.ObservedState{observed}, ObservedAt: now}), pluginassignment.ErrStaleObservation)

	_, err = database.ExecContext(ctx, `UPDATE plugin_versions SET status='revoked',revision=revision+1,revocation_reason='security_revoke' WHERE tenant_id=$1 AND project_id=$2 AND version_id=$3`, scope.TenantID, scope.ProjectID, assignment.DesiredVersionID)
	require.NoError(t, err)
	current, err := service.Get(ctx, scope, assignment.ID)
	require.NoError(t, err)
	forced, err := service.ForceReconcile(ctx, scope, current.ID, pluginassignment.MutationAudit{Actor: "operator", OperationID: "reconcilePluginAssignment", IdempotencyKey: "revoked", RequestFingerprint: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", RequestID: "request-revoked"})
	require.NoError(t, err)
	_, err = reconciler.ReconcileAssignment(ctx, forced, time.Now().UTC())
	require.ErrorIs(t, err, pluginassignment.ErrVersionRevoked)
	blocked, err := service.Get(ctx, scope, assignment.ID)
	require.NoError(t, err)
	require.Equal(t, pluginassignment.ReconcileBlocked, blocked.ReconcileState)
	require.Equal(t, "version_revoked", blocked.BlockedReason)
	stopped := pluginassignment.DesiredStopped
	stopping, err := service.SetDesiredState(ctx, scope, blocked.ID, blocked.Revision, pluginassignment.DesiredUpdate{DesiredState: &stopped, Audit: pluginassignment.MutationAudit{Actor: "operator", OperationID: "updatePluginAssignment", IdempotencyKey: "stop-revoked", RequestFingerprint: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", RequestID: "request-stop-revoked"}})
	require.NoError(t, err)
	_, err = reconciler.ReconcileAssignment(ctx, stopping, time.Now().UTC())
	require.NoError(t, err, "revoked running plugins must still accept a safe stop command")
}

func TestPluginAssignmentFailureRollsBackCandidateAndInstance(t *testing.T) {
	database, scope, hostID, agentID := pluginAssignmentPostgresFixture(t)
	candidateID, request := insertAssignmentCandidate(t, database, scope, hostID, agentID, "candidate-fail", "127.0.0.1:3310", 21)
	failure := errors.New("assignment planning failed")
	repository := databaseinstance.NewPostgresRepositoryWithProvisioner(database, databaseinstance.AcceptanceProvisionerFunc(func(context.Context, *sql.Tx, databaseinstance.Instance, databaseinstance.MutationAudit) (databaseinstance.AssignmentBinding, error) {
		return databaseinstance.AssignmentBinding{}, failure
	}))
	_, err := repository.AcceptCandidate(context.Background(), scope, candidateID, request)
	require.ErrorIs(t, err, failure)
	var status, accepted string
	require.NoError(t, database.QueryRow(`SELECT status,accepted_instance_id FROM discovery_candidates WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3`, scope.TenantID, scope.ProjectID, candidateID).Scan(&status, &accepted))
	require.Equal(t, "awaiting_confirmation", status)
	require.Empty(t, accepted)
	var instances int
	require.NoError(t, database.QueryRow(`SELECT count(*) FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3`, scope.TenantID, scope.ProjectID, candidateID).Scan(&instances))
	require.Zero(t, instances)
}

func TestPluginAssignmentExpiredLeaseIsReclaimedAndOldTokenIsFenced(t *testing.T) {
	database, scope, hostID, agentID := pluginAssignmentPostgresFixture(t)
	jobs := job.NewPostgresRepositoryWithTargetAuthorizer(database, pluginassignment.InstanceTargetAuthorizer{Database: database})
	assignments := pluginassignment.NewPostgresRepository(database, jobs)
	candidateID, request := insertAssignmentCandidate(t, database, scope, hostID, agentID, "candidate-lease", "127.0.0.1:3311", 31)
	_, err := databaseinstance.NewPostgresRepositoryWithProvisioner(database, assignments).AcceptCandidate(context.Background(), scope, candidateID, request)
	require.NoError(t, err)
	page, err := assignments.List(context.Background(), scope, pluginassignment.Filter{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	oldClaim, err := assignments.ClaimOne(context.Background(), page.Items[0], time.Now().UTC(), time.Second)
	require.NoError(t, err)
	_, err = database.Exec(`UPDATE plugin_assignments SET reconcile_lease_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, scope.TenantID, scope.ProjectID, page.Items[0].ID)
	require.NoError(t, err)
	reclaimed, err := assignments.ClaimDue(context.Background(), time.Now().UTC(), 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, reclaimed, 1)
	require.NotEqual(t, oldClaim.Token, reclaimed[0].Token)
	require.ErrorIs(t, assignments.MarkConverged(context.Background(), oldClaim), pluginassignment.ErrClaimLost)
}

func TestPluginAssignmentRetirementDetachesMembershipAndLastInstanceQueuesAbsent(t *testing.T) {
	database, scope, hostID, agentID := pluginAssignmentPostgresFixture(t)
	ctx := context.Background()
	jobs := job.NewPostgresRepositoryWithTargetAuthorizer(database, pluginassignment.InstanceTargetAuthorizer{Database: database})
	assignments := pluginassignment.NewPostgresRepository(database, jobs)
	instances := databaseinstance.NewPostgresRepositoryWithProvisioner(database, assignments)
	firstCandidate, firstRequest := insertAssignmentCandidate(t, database, scope, hostID, agentID, "retire-a", "127.0.0.1:3321", 41)
	secondCandidate, secondRequest := insertAssignmentCandidate(t, database, scope, hostID, agentID, "retire-b", "127.0.0.1:3322", 41)
	first, err := instances.AcceptCandidate(ctx, scope, firstCandidate, firstRequest)
	require.NoError(t, err)
	second, err := instances.AcceptCandidate(ctx, scope, secondCandidate, secondRequest)
	require.NoError(t, err)
	first, err = instances.Get(ctx, scope, first.ID)
	require.NoError(t, err)
	_, err = instances.Retire(ctx, scope, first.ID, first.Revision, databaseinstance.MutationAudit{Actor: "operator", OperationID: "retireDatabaseInstance", IdempotencyKey: "retire-first", RequestFingerprint: "sha256:1111111111111111111111111111111111111111111111111111111111111111", RequestID: "request-retire-first"})
	require.NoError(t, err)
	page, err := assignments.List(ctx, scope, pluginassignment.Filter{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, []string{second.ID}, page.Items[0].InstanceIDs)
	require.Equal(t, pluginassignment.DesiredRunning, page.Items[0].DesiredState)
	second, err = instances.Get(ctx, scope, second.ID)
	require.NoError(t, err)
	_, err = instances.Retire(ctx, scope, second.ID, second.Revision, databaseinstance.MutationAudit{Actor: "operator", OperationID: "retireDatabaseInstance", IdempotencyKey: "retire-last", RequestFingerprint: "sha256:2222222222222222222222222222222222222222222222222222222222222222", RequestID: "request-retire-last"})
	require.NoError(t, err)
	page, err = assignments.List(ctx, scope, pluginassignment.Filter{})
	require.NoError(t, err)
	require.Empty(t, page.Items[0].InstanceIDs)
	require.Equal(t, pluginassignment.DesiredAbsent, page.Items[0].DesiredState)
	_, err = reconciliation.NewPluginReconciler(assignments).ReconcileAssignment(ctx, page.Items[0], time.Now().UTC())
	require.NoError(t, err)
	var jobsCreated int
	require.NoError(t, database.QueryRow(`SELECT count(*) FROM jobs WHERE tenant_id=$1 AND project_id=$2 AND job_type='plugin.reconcile'`, scope.TenantID, scope.ProjectID).Scan(&jobsCreated))
	require.Equal(t, 1, jobsCreated)
}

func pluginAssignmentPostgresFixture(t *testing.T) (*sql.DB, platformscope.Scope, string, string) {
	t.Helper()
	if os.Getenv("DBPILOT_PLUGIN_ASSIGNMENT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_PLUGIN_ASSIGNMENT_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_PLUGIN_ASSIGNMENT_POSTGRES_DSN")
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.Ping())
	schema := fmt.Sprintf("dbpilot_task8_%d", time.Now().UnixNano())
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
	ctx := context.Background()
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, job.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, discovery.RunMigrations(ctx, database))
	require.NoError(t, databaseinstance.RunMigrations(ctx, database))
	require.NoError(t, plugincatalog.RunMigrations(ctx, database))
	require.NoError(t, pluginassignment.RunMigrations(ctx, database))
	suffix := fmt.Sprint(time.Now().UnixNano())
	scope := platformscope.Scope{TenantID: "tenant-" + suffix, ProjectID: "project-" + suffix}
	hostID, agentID := "host-"+suffix, "agent-"+suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = hostinventory.NewPostgresRepository(database).RecordObservation(ctx, scope, hostinventory.Observation{HostID: hostID, AgentID: agentID, Revision: 1, AgentVersion: "test", Hostname: "host.test", OS: "linux", Architecture: "amd64", LogicalCPUCount: 2, MemoryCapacityBytes: 1024, NetworkAddresses: []string{}, Capabilities: []string{"plugin.reconcile.v1"}, ObservedAt: now}, now)
	require.NoError(t, err)
	seedAvailablePlugin(t, database, scope, now)
	return database, scope, hostID, agentID
}

func seedAvailablePlugin(t *testing.T, database *sql.DB, scope platformscope.Scope, now time.Time) {
	t.Helper()
	_, err := database.Exec(`INSERT INTO artifacts (id,tenant_id,project_id,kind,content_type,size_bytes,checksum,created_by,created_at,storage_reference) VALUES ('artifact-mysql',$1,$2,'plugin_package','application/gzip',1,$3,'test',$4,'sha256/test')`, scope.TenantID, scope.ProjectID, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now)
	require.NoError(t, err)
	_, err = database.Exec(`INSERT INTO plugin_definitions (tenant_id,project_id,plugin_id,name,database_family,protocol_version,supported_variants,capabilities) VALUES ($1,$2,'dbpilot.mysql','MySQL','mysql','1','["mysql"]'::jsonb,'["metrics"]'::jsonb)`, scope.TenantID, scope.ProjectID)
	require.NoError(t, err)
	_, err = database.Exec(`INSERT INTO plugin_versions (version_id,tenant_id,project_id,plugin_id,semantic_version,status,artifact_id,package_sha256,manifest_digest,publisher_id,signing_key_id,protocol_version,minimum_agent_protocol_version,maximum_agent_protocol_version,supported_variants,database_version_range,capabilities,metric_template_schema_version,platforms,revision,created_at,approved_at) VALUES ('mysql-version-1',$1,$2,'dbpilot.mysql','1.2.3','available','artifact-mysql',$3,$4,'publisher','key','1','1','1','["mysql"]'::jsonb,'>=5.7','["metrics"]'::jsonb,1,'[{"operating_system":"linux","architecture":"amd64","sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size_bytes":1}]'::jsonb,1,$5,$5)`, scope.TenantID, scope.ProjectID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now)
	require.NoError(t, err)
}

func seedIncompatiblePluginVersion(t *testing.T, database *sql.DB, scope platformscope.Scope, now time.Time) {
	t.Helper()
	_, err := database.Exec(`INSERT INTO plugin_versions (version_id,tenant_id,project_id,plugin_id,semantic_version,status,artifact_id,package_sha256,manifest_digest,publisher_id,signing_key_id,protocol_version,minimum_agent_protocol_version,maximum_agent_protocol_version,supported_variants,database_version_range,capabilities,metric_template_schema_version,platforms,revision,created_at,approved_at) VALUES ('mysql-version-2',$1,$2,'dbpilot.mysql','2.0.0','available','artifact-mysql',$3,$4,'publisher','key','1','1','1','["mysql"]'::jsonb,'>=5.7','["metrics"]'::jsonb,1,'[{"operating_system":"linux","architecture":"arm64","sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","size_bytes":1}]'::jsonb,1,$5,$5)`, scope.TenantID, scope.ProjectID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", now)
	require.NoError(t, err)
}

func insertAssignmentCandidate(t *testing.T, database *sql.DB, scope platformscope.Scope, hostID, agentID, name, endpoint string, revision uint64) (string, databaseinstance.AcceptCandidateRequest) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	candidateID := name + "-" + fmt.Sprint(revision)
	digest := make([]byte, 32)
	fingerprintDigest := sha256.Sum256([]byte(name + ":" + fmt.Sprint(revision)))
	fingerprint := fingerprintDigest[:]
	_, err := database.ExecContext(ctx, `INSERT INTO discovery_scan_state (tenant_id,project_id,host_id,agent_id,observation_revision,rule_revision,report_digest,observed_at,received_at,rule_set_digest,disappearance_grace_seconds,agent_observed_at) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$7,$6,600,$7) ON CONFLICT (tenant_id,project_id,host_id) DO UPDATE SET observation_revision=EXCLUDED.observation_revision,received_at=EXCLUDED.received_at,observed_at=EXCLUDED.observed_at,agent_observed_at=EXCLUDED.agent_observed_at`, scope.TenantID, scope.ProjectID, hostID, agentID, revision, digest, now)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `INSERT INTO discovery_scan_sources (tenant_id,project_id,host_id,discovery_source,result_status,reason_code,observation_revision,rule_revision,rule_set_digest,observed_at,updated_at) VALUES ($1,$2,$3,'native','completed','healthy',$4,1,$5,$6,$6) ON CONFLICT (tenant_id,project_id,host_id,discovery_source) DO UPDATE SET result_status='completed',reason_code='healthy',observation_revision=EXCLUDED.observation_revision,updated_at=EXCLUDED.updated_at`, scope.TenantID, scope.ProjectID, hostID, revision, digest, now)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `INSERT INTO discovery_candidates (candidate_id,tenant_id,project_id,host_id,agent_id,observation_id,discovery_source,database_family,database_variant,normalized_endpoint,process_identity,confidence,evidence_summary,fingerprint,rule_revision,observation_revision,first_seen_at,last_seen_at,status,updated_at) VALUES ($1,$2,$3,$4,$5,$1,'native','mysql','mysql',$6,$1,0.9,'[]'::jsonb,$7,1,$8,$9,$9,'awaiting_confirmation',$9)`, candidateID, scope.TenantID, scope.ProjectID, hostID, agentID, endpoint, fingerprint, revision, now)
	require.NoError(t, err)
	request := databaseinstance.AcceptCandidateRequest{DisplayName: name, DatabaseFamily: "mysql", DatabaseVariant: "mysql", Endpoint: endpoint, CredentialRef: "secret://vault/mysql", Labels: map[string]string{}, ExpectedCandidateRevision: revision, CandidateFingerprint: fmt.Sprintf("%x", fingerprint), Audit: databaseinstance.MutationAudit{Actor: "operator", OperationID: "acceptDiscoveryCandidate", IdempotencyKey: "accept-" + name, RequestFingerprint: fmt.Sprintf("sha256:%064x", revision), RequestID: "request-" + name}}
	return candidateID, request
}
