package databaseinstance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestDatabaseInstancePostgresConcurrentAcceptanceIsAtomicAndReplayable(t *testing.T) {
	database, scope, hostID, agentID := databaseInstancePostgresFixture(t)
	ctx := context.Background()
	candidateID := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-concurrent", "127.0.0.1:3306", "mysqld.service", 7)
	repository := NewPostgresRepository(database)
	request := integrationAcceptRequest("same-key", 7)

	start := make(chan struct{})
	values := make(chan Instance, 24)
	errorsChannel := make(chan error, 24)
	var group sync.WaitGroup
	for index := 0; index < 24; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			value, err := repository.AcceptCandidate(ctx, scope, candidateID, request)
			values <- value
			errorsChannel <- err
		}()
	}
	close(start)
	group.Wait()
	close(values)
	close(errorsChannel)
	var instanceID string
	for err := range errorsChannel {
		require.NoError(t, err)
	}
	for value := range values {
		require.NoError(t, value.Validate())
		if instanceID == "" {
			instanceID = value.ID
		}
		require.Equal(t, instanceID, value.ID)
	}
	var instances, audits, accepted int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3", scope.TenantID, scope.ProjectID, candidateID).Scan(&instances))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND action='database_instance.accepted' AND resource_id=$3", scope.TenantID, scope.ProjectID, instanceID).Scan(&audits))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM discovery_candidates WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3 AND status='accepted' AND accepted_instance_id=$4", scope.TenantID, scope.ProjectID, candidateID, instanceID).Scan(&accepted))
	require.Equal(t, 1, instances)
	require.Equal(t, 1, audits)
	require.Equal(t, 1, accepted)
	var sensitiveColumns int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name IN ('managed_database_instances','database_instance_mutations') AND (column_name ILIKE '%password%' OR column_name ILIKE '%token%' OR column_name ILIKE '%secret_value%')`).Scan(&sensitiveColumns))
	require.Zero(t, sensitiveColumns)
	var leakedAudit int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND detail::text LIKE '%secret://%'`, scope.TenantID, scope.ProjectID).Scan(&leakedAudit))
	require.Zero(t, leakedAudit)
}

func TestDatabaseInstancePostgresDifferentKeysAndUnknownCommitRecoverSameInstance(t *testing.T) {
	database, scope, hostID, agentID := databaseInstancePostgresFixture(t)
	ctx := context.Background()
	candidateID := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-unknown", "127.0.0.1:3307", "mysql-alt.service", 9)
	repository := NewPostgresRepository(database)
	request := integrationAcceptRequest("first-key", 9)
	request.Endpoint = "127.0.0.1:3307"
	originalCommit := repository.commit
	repository.commit = func(transaction *sql.Tx) error {
		err := originalCommit(transaction)
		if err != nil {
			return err
		}
		return errors.New("simulated lost commit acknowledgement")
	}

	first, err := repository.AcceptCandidate(ctx, scope, candidateID, request)
	require.NoError(t, err)
	repository.commit = originalCommit
	secondRequest := integrationAcceptRequest("second-key", 9)
	secondRequest.Endpoint = "127.0.0.1:3307"
	second, err := repository.AcceptCandidate(ctx, scope, candidateID, secondRequest)
	require.NoError(t, err)
	require.Equal(t, first.ID, second.ID)

	conflicting := secondRequest
	conflicting.DisplayName = "Different"
	conflicting.Audit.RequestFingerprint = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	_, err = repository.AcceptCandidate(ctx, scope, candidateID, conflicting)
	require.ErrorIs(t, err, ErrConflict)
}

func TestDatabaseInstancePostgresRetriesSerializableAcceptAndUpdate(t *testing.T) {
	database, scope, hostID, agentID := databaseInstancePostgresFixture(t)
	ctx := context.Background()
	candidateID := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-serialization", "127.0.0.1:3380", "mysql-serialization.service", 29)
	repository := NewPostgresRepository(database)
	originalCommit := repository.commit
	commitCalls := 0
	repository.commit = func(transaction *sql.Tx) error {
		commitCalls++
		if commitCalls == 1 {
			_ = transaction.Rollback()
			return &pq.Error{Code: "40001"}
		}
		return originalCommit(transaction)
	}
	request := integrationAcceptRequest("accept-serialization", 29)
	request.Endpoint = "127.0.0.1:3380"
	request.Audit.RequestFingerprint = "sha256:2929292929292929292929292929292929292929292929292929292929292929"

	accepted, err := repository.AcceptCandidate(ctx, scope, candidateID, request)
	require.NoError(t, err)
	require.Equal(t, 2, commitCalls)

	commitCalls = 0
	name := "Retried update"
	update := Update{DisplayName: &name, Audit: MutationAudit{Actor: "operator-1", OperationID: "updateDatabaseInstance", IdempotencyKey: "update-serialization", RequestFingerprint: "sha256:2828282828282828282828282828282828282828282828282828282828282828", RequestID: "request-update-serialization"}}
	updated, err := repository.Update(ctx, scope, accepted.ID, accepted.Revision, update)
	require.NoError(t, err)
	require.Equal(t, 2, commitCalls)
	require.Equal(t, name, updated.DisplayName)
}

func TestDatabaseInstancePostgresRejectsStaleCrossScopeAndDuplicateEndpoint(t *testing.T) {
	database, scope, hostID, agentID := databaseInstancePostgresFixture(t)
	ctx := context.Background()
	repository := NewPostgresRepository(database)
	firstCandidate := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-first", "127.0.0.1:3310", "mysql-one.service", 11)
	firstRequest := integrationAcceptRequest("first", 11)
	firstRequest.Endpoint = "127.0.0.1:3310"
	first, err := repository.AcceptCandidate(ctx, scope, firstCandidate, firstRequest)
	require.NoError(t, err)
	require.NotEmpty(t, first.ID)
	changedEndpointCandidate := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-first-moved", "127.0.0.1:3312", "mysql-one.service", 14)
	changedEndpointRequest := integrationAcceptRequest("first-moved", 14)
	changedEndpointRequest.Endpoint = "127.0.0.1:3312"
	changedEndpointRequest.Audit.RequestFingerprint = "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	moved, err := repository.AcceptCandidate(ctx, scope, changedEndpointCandidate, changedEndpointRequest)
	require.NoError(t, err)
	require.Equal(t, first.ID, moved.ID, "a stable native service identity must survive an endpoint change")
	require.Equal(t, "127.0.0.1:3312", moved.Endpoint)

	secondCandidate := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-second", "127.0.0.1:3312", "mysql-two.service", 12)
	secondRequest := integrationAcceptRequest("second", 12)
	secondRequest.Endpoint = "127.0.0.1:3312"
	secondRequest.Audit.RequestFingerprint = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	_, err = repository.AcceptCandidate(ctx, scope, secondCandidate, secondRequest)
	require.ErrorIs(t, err, ErrConflict)

	staleCandidate := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-stale", "127.0.0.1:3311", "mysql-stale.service", 13)
	staleRequest := integrationAcceptRequest("stale", 12)
	staleRequest.Endpoint = "127.0.0.1:3311"
	staleRequest.Audit.RequestFingerprint = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	_, err = repository.AcceptCandidate(ctx, scope, staleCandidate, staleRequest)
	require.ErrorIs(t, err, ErrPrecondition)

	wrongScope := platformscope.Scope{TenantID: scope.TenantID + "-other", ProjectID: scope.ProjectID}
	_, err = repository.AcceptCandidate(ctx, wrongScope, staleCandidate, staleRequest)
	require.ErrorIs(t, err, ErrNotFound)
	for index, status := range []string{"ignored", "disappeared"} {
		candidateID := insertCurrentCandidate(t, database, scope, hostID, agentID, fmt.Sprintf("candidate-%s", status), fmt.Sprintf("127.0.0.1:%d", 3340+index), fmt.Sprintf("mysql-%s.service", status), uint64(40+index))
		_, err = database.ExecContext(ctx, `UPDATE discovery_candidates SET status=$1 WHERE tenant_id=$2 AND project_id=$3 AND candidate_id=$4`, status, scope.TenantID, scope.ProjectID, candidateID)
		require.NoError(t, err)
		request := integrationAcceptRequest(status, uint64(40+index))
		request.Endpoint = fmt.Sprintf("127.0.0.1:%d", 3340+index)
		request.Audit.RequestFingerprint = fmt.Sprintf("sha256:%064x", 40+index)
		_, err = repository.AcceptCandidate(ctx, scope, candidateID, request)
		require.ErrorIs(t, err, ErrConflict, status)
	}
}

func TestDatabaseInstancePostgresPagesUpdatesAndRetiresWithCAS(t *testing.T) {
	database, scope, hostID, agentID := databaseInstancePostgresFixture(t)
	ctx := context.Background()
	repository := NewPostgresRepository(database)
	for index := 0; index < 3; index++ {
		candidateID := insertCurrentCandidate(t, database, scope, hostID, agentID, fmt.Sprintf("candidate-page-%d", index), fmt.Sprintf("127.0.0.1:%d", 3320+index), fmt.Sprintf("mysql-page-%d.service", index), uint64(20+index))
		request := integrationAcceptRequest(fmt.Sprintf("page-%d", index), uint64(20+index))
		request.Endpoint = fmt.Sprintf("127.0.0.1:%d", 3320+index)
		request.Audit.RequestFingerprint = fmt.Sprintf("sha256:%064x", index+10)
		_, err := repository.AcceptCandidate(ctx, scope, candidateID, request)
		require.NoError(t, err)
	}
	first, err := repository.List(ctx, scope, Filter{DatabaseFamily: "mysql", Limit: 2})
	require.NoError(t, err)
	require.Len(t, first.Items, 2)
	require.NotEmpty(t, first.NextCursor)
	second, err := repository.List(ctx, scope, Filter{DatabaseFamily: "mysql", Cursor: first.NextCursor, Limit: 2})
	require.NoError(t, err)
	require.Len(t, second.Items, 1)
	for _, value := range append(append([]Instance{}, first.Items...), second.Items...) {
		require.Equal(t, agentID+"\x00mysql", value.FutureAssignmentKey())
	}

	instance := first.Items[0]
	name := "Updated MySQL"
	update := Update{DisplayName: &name, Audit: MutationAudit{Actor: "operator-1", OperationID: "updateDatabaseInstance", IdempotencyKey: "update-1", RequestFingerprint: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", RequestID: "request-update"}}
	updated, err := repository.Update(ctx, scope, instance.ID, instance.Revision, update)
	require.NoError(t, err)
	require.Equal(t, name, updated.DisplayName)
	replayedUpdate, err := repository.Update(ctx, scope, instance.ID, instance.Revision, update)
	require.NoError(t, err)
	require.Equal(t, updated, replayedUpdate)
	retireAudit := MutationAudit{Actor: "operator-1", OperationID: "retireDatabaseInstance", IdempotencyKey: "retire-1", RequestFingerprint: "sha256:abababababababababababababababababababababababababababababababab", RequestID: "request-retire"}
	retired, err := repository.Retire(ctx, scope, instance.ID, updated.Revision, retireAudit)
	require.NoError(t, err)
	require.Equal(t, StatusRetired, retired.ManagementStatus)
	replayedRetire, err := repository.Retire(ctx, scope, instance.ID, updated.Revision, retireAudit)
	require.NoError(t, err)
	require.Equal(t, retired, replayedRetire)
}

func TestDatabaseInstancePostgresAuditFailureRollsBackAcceptance(t *testing.T) {
	database, scope, hostID, agentID := databaseInstancePostgresFixture(t)
	ctx := context.Background()
	candidateID := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-audit-rollback", "127.0.0.1:3390", "mysql-audit.service", 30)
	_, err := database.ExecContext(ctx, `CREATE OR REPLACE FUNCTION dbpilot_task6_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'task6 audit failure'; END; $$`)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, fmt.Sprintf(`CREATE TRIGGER dbpilot_task6_reject_audit BEFORE INSERT ON audit_events FOR EACH ROW WHEN (NEW.tenant_id = '%s') EXECUTE FUNCTION dbpilot_task6_reject_audit()`, scope.TenantID))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), `DROP TRIGGER IF EXISTS dbpilot_task6_reject_audit ON audit_events`)
		_, _ = database.ExecContext(context.Background(), `DROP FUNCTION IF EXISTS dbpilot_task6_reject_audit()`)
	})
	request := integrationAcceptRequest("audit-rollback", 30)
	request.Endpoint = "127.0.0.1:3390"
	request.Audit.RequestFingerprint = "sha256:3030303030303030303030303030303030303030303030303030303030303030"

	_, err = NewPostgresRepository(database).AcceptCandidate(ctx, scope, candidateID, request)
	require.Error(t, err)
	var status, acceptedInstanceID string
	require.NoError(t, database.QueryRowContext(ctx, `SELECT status,accepted_instance_id FROM discovery_candidates WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3`, scope.TenantID, scope.ProjectID, candidateID).Scan(&status, &acceptedInstanceID))
	require.Equal(t, "awaiting_confirmation", status)
	require.Empty(t, acceptedInstanceID)
	var count int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM managed_database_instances WHERE tenant_id=$1 AND project_id=$2 AND candidate_id=$3`, scope.TenantID, scope.ProjectID, candidateID).Scan(&count))
	require.Zero(t, count)
}

func databaseInstancePostgresFixture(t *testing.T) (*sql.DB, platformscope.Scope, string, string) {
	t.Helper()
	if os.Getenv("DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION=1 to run")
	}
	database, err := sql.Open("postgres", os.Getenv("DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	ctx := context.Background()
	require.NoError(t, database.PingContext(ctx))
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, discovery.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	suffix := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	scope := platformscope.Scope{TenantID: "tenant-dbi-" + suffix, ProjectID: "project-dbi-" + suffix}
	hostID, agentID := "host-dbi-"+suffix, "agent-dbi-"+suffix
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = hostinventory.NewPostgresRepository(database).RecordObservation(ctx, scope, hostinventory.Observation{HostID: hostID, AgentID: agentID, Revision: 1, AgentVersion: "test", Hostname: "dbi.example", OS: "linux", Architecture: "amd64", LogicalCPUCount: 1, MemoryCapacityBytes: 1024, NetworkAddresses: []string{}, Capabilities: []string{"native_discovery_v1"}, ObservedAt: now}, now)
	require.NoError(t, err)
	return database, scope, hostID, agentID
}

func insertCurrentCandidate(t *testing.T, database *sql.DB, scope platformscope.Scope, hostID, agentID, candidateID, endpoint, identity string, revision uint64) string {
	t.Helper()
	candidateID = candidateID + "-" + hostID
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := make([]byte, 32)
	fingerprint := make([]byte, 32)
	for index := range fingerprint {
		fingerprint[index] = byte(revision + uint64(index))
	}
	_, err := database.ExecContext(ctx, `INSERT INTO discovery_scan_state (tenant_id,project_id,host_id,agent_id,observation_revision,rule_revision,report_digest,observed_at,received_at,rule_set_digest,disappearance_grace_seconds,agent_observed_at) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$7,$6,600,$7) ON CONFLICT (tenant_id,project_id,host_id) DO UPDATE SET observation_revision=EXCLUDED.observation_revision,received_at=EXCLUDED.received_at,observed_at=EXCLUDED.observed_at,agent_observed_at=EXCLUDED.agent_observed_at`, scope.TenantID, scope.ProjectID, hostID, agentID, revision, digest, now)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `INSERT INTO discovery_scan_sources (tenant_id,project_id,host_id,discovery_source,result_status,reason_code,observation_revision,rule_revision,rule_set_digest,observed_at,updated_at) VALUES ($1,$2,$3,'native','completed','healthy',$4,1,$5,$6,$6) ON CONFLICT (tenant_id,project_id,host_id,discovery_source) DO UPDATE SET result_status='completed',reason_code='healthy',observation_revision=EXCLUDED.observation_revision,updated_at=EXCLUDED.updated_at`, scope.TenantID, scope.ProjectID, hostID, revision, digest, now)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `INSERT INTO discovery_candidates (candidate_id,tenant_id,project_id,host_id,agent_id,observation_id,discovery_source,database_family,database_variant,normalized_endpoint,process_identity,confidence,evidence_summary,fingerprint,rule_revision,observation_revision,first_seen_at,last_seen_at,status,updated_at) VALUES ($1,$2,$3,$4,$5,$1,'native','mysql','mysql',$6,$7,0.9,'[]'::jsonb,$8,1,$9,$10,$10,'awaiting_confirmation',$10)`, candidateID, scope.TenantID, scope.ProjectID, hostID, agentID, endpoint, identity, fingerprint, revision, now)
	require.NoError(t, err)
	return candidateID
}

func integrationAcceptRequest(key string, revision uint64) AcceptCandidateRequest {
	request := validAcceptRequest()
	request.DatabaseVariant = "mysql"
	request.ExpectedCandidateRevision = revision
	request.CandidateFingerprint = fmt.Sprintf("%x", candidateFingerprintBytes(revision))
	request.Audit.IdempotencyKey = key
	request.Audit.RequestFingerprint = fmt.Sprintf("sha256:%064x", revision)
	request.Audit.RequestID = "request-" + key
	return request
}

func candidateFingerprintBytes(revision uint64) []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = byte(revision + uint64(index))
	}
	return value
}
