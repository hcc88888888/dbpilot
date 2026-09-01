package credentiallease_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/controlplanemigrations"
	"dbpilot.local/platform/internal/credentiallease"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestPostgresProductionMigrationsProveDurableCredentialRenewal(t *testing.T) {
	database, cleanup := productionMigrationDatabase(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	options := controlplanemigrations.Options{
		PluginCatalogEnabled:    true,
		CredentialLeasesEnabled: true,
		Now:                     func() time.Time { return now },
	}
	require.NoError(t, controlplanemigrations.Run(ctx, database, options))
	require.NoError(t, controlplanemigrations.Run(ctx, database, options), "the production migration composition must be restart-idempotent")

	success := seedDurableRenewalFixture(t, database, "success", now)
	lease, fence, service, err := requestDurableRenewal(ctx, database, success)
	require.NoError(t, err, "a restarted service must renew from durable production-schema evidence")
	require.Equal(t, success.commandID, fence.commandID)
	require.GreaterOrEqual(t, fence.calls, 2, "initial and post-provider authorization must both observe the absent live fence")
	require.Equal(t, success.secret, lease.SecretBytes)
	require.Equal(t, success.username, lease.Username)
	assertIssuedAuditIsHashOnly(t, database, success, lease)
	lease.Release()
	service.Close()

	mutations := []struct {
		name   string
		mutate func(*testing.T, *sql.DB, durableRenewalFixture)
	}{
		{name: "configuration revision", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE plugin_assignments SET configuration_revision=configuration_revision+1 WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, value.tenantID, value.projectID, value.assignmentID)
			require.NoError(t, err)
		}},
		{name: "operation revision", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE plugin_assignments SET operation_revision=operation_revision+1 WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, value.tenantID, value.projectID, value.assignmentID)
			require.NoError(t, err)
		}},
		{name: "assignment membership", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`DELETE FROM plugin_assignment_instances WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, value.tenantID, value.projectID, value.assignmentID)
			require.NoError(t, err)
		}},
		{name: "credential reference", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE managed_database_instances SET credential_ref='secret://database/revoked' WHERE instance_id=$1`, value.instanceID)
			require.NoError(t, err)
		}},
		{name: "instance status", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE managed_database_instances SET management_status='retired',retired_at=$2 WHERE instance_id=$1`, value.instanceID, time.Now().UTC())
			require.NoError(t, err)
		}},
		{name: "desired state", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE plugin_assignments SET desired_state='stopped' WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, value.tenantID, value.projectID, value.assignmentID)
			require.NoError(t, err)
		}},
		{name: "version revocation", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE plugin_versions SET status='revoked',revision=revision+1,revocation_reason='test revocation' WHERE tenant_id=$1 AND project_id=$2 AND version_id=$3`, value.tenantID, value.projectID, value.versionID)
			require.NoError(t, err)
		}},
		{name: "observation health", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE plugin_observations SET health='unhealthy' WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, value.tenantID, value.projectID, value.assignmentID)
			require.NoError(t, err)
		}},
		{name: "observation configuration revision", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE plugin_observations SET active_configuration_revision=active_configuration_revision-1 WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, value.tenantID, value.projectID, value.assignmentID)
			require.NoError(t, err)
		}},
		{name: "observation operation revision", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE plugin_observations SET observed_operation_revision=observed_operation_revision-1 WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, value.tenantID, value.projectID, value.assignmentID)
			require.NoError(t, err)
		}},
		{name: "agent identity", mutate: func(t *testing.T, database *sql.DB, value durableRenewalFixture) {
			_, err := database.Exec(`UPDATE plugin_assignments SET agent_id='agent-other' WHERE tenant_id=$1 AND project_id=$2 AND assignment_id=$3`, value.tenantID, value.projectID, value.assignmentID)
			require.NoError(t, err)
		}},
	}
	for index, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			value := seedDurableRenewalFixture(t, database, fmt.Sprintf("drift-%02d", index), now.Add(time.Duration(index+1)*time.Second))
			test.mutate(t, database, value)
			lease, _, service, err := requestDurableRenewal(ctx, database, value)
			if service != nil {
				service.Close()
			}
			lease.Release()
			require.ErrorIs(t, err, credentiallease.ErrLeaseRejected)
		})
	}

	cleanup()
}

type durableRenewalFixture struct {
	tenantID      string
	projectID     string
	hostID        string
	agentID       string
	assignmentID  string
	instanceID    string
	versionID     string
	commandID     string
	jobID         string
	credentialRef string
	username      string
	secret        []byte
}

func seedDurableRenewalFixture(t *testing.T, database *sql.DB, suffix string, now time.Time) durableRenewalFixture {
	t.Helper()
	value := durableRenewalFixture{
		tenantID:      "tenant-" + suffix,
		projectID:     "project-" + suffix,
		hostID:        "host-" + suffix,
		agentID:       "agent-" + suffix,
		assignmentID:  "assignment-" + suffix,
		instanceID:    "instance-" + suffix,
		versionID:     "version-" + suffix,
		commandID:     "command-" + suffix,
		jobID:         "job-" + suffix,
		credentialRef: "secret://database/instance-" + suffix,
		username:      "dbpilot_" + strings.ReplaceAll(suffix, "-", "_"),
		secret:        []byte("task11-production-secret-" + suffix),
	}
	pluginID := "plugin-" + suffix
	artifactID := "artifact-" + suffix
	candidateID := "candidate-" + suffix
	digest := strings.Repeat("a", 64)
	sourceFingerprint := strings.Repeat("b", 64)
	tx, err := database.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	exec := func(statement string, arguments ...any) {
		t.Helper()
		_, execErr := tx.Exec(statement, arguments...)
		require.NoError(t, execErr)
	}
	exec(`INSERT INTO managed_hosts
(tenant_id,project_id,host_id,agent_id,display_name,hostname,operating_system,architecture,observation_revision,enrolled_at,status,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,'linux','amd64',1,$7,'online',$7)`, value.tenantID, value.projectID, value.hostID, value.agentID, "Host "+suffix, value.hostID+".example", now)
	exec(`INSERT INTO discovery_candidates
(candidate_id,tenant_id,project_id,host_id,agent_id,observation_id,discovery_source,database_family,database_variant,normalized_endpoint,confidence,evidence_summary,fingerprint,rule_revision,observation_revision,first_seen_at,last_seen_at,status,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,'native','mysql','mysql','127.0.0.1:3306',1,'[]'::jsonb,decode($7,'hex'),1,1,$8,$8,'accepted',$8)`, candidateID, value.tenantID, value.projectID, value.hostID, value.agentID, "observation-"+suffix, sourceFingerprint, now)
	exec(`INSERT INTO managed_database_instances
(instance_id,tenant_id,project_id,host_id,agent_id,candidate_id,discovery_source,source_fingerprint,source_identity,database_family,database_variant,display_name,endpoint,credential_ref,capability_state,connection_test_status,management_status,revision,created_at,updated_at,canonical_connection)
VALUES ($1,$2,$3,$4,$5,$6,'native',$7,$8,'mysql','mysql',$9,'127.0.0.1:3306',$10,'plugin_not_installed','not_tested','monitoring',9,$11,$11,$12)`, value.instanceID, value.tenantID, value.projectID, value.hostID, value.agentID, candidateID, sourceFingerprint, "native:"+suffix, "MySQL "+suffix, value.credentialRef, now, "mysql://127.0.0.1:3306/"+suffix)
	exec(`UPDATE discovery_candidates SET accepted_instance_id=$2 WHERE candidate_id=$1`, candidateID, value.instanceID)
	exec(`INSERT INTO artifacts
(id,tenant_id,project_id,kind,content_type,size_bytes,checksum,created_at,storage_reference)
VALUES ($1,$2,$3,'plugin-package','application/octet-stream',1,$4,$5,$6)`, artifactID, value.tenantID, value.projectID, "sha256:"+digest, now, "object://plugins/"+artifactID)
	exec(`INSERT INTO plugin_definitions
(tenant_id,project_id,plugin_id,name,database_family,protocol_version,supported_variants,capabilities,latest_available_version)
VALUES ($1,$2,$3,$4,'mysql','v1','["mysql"]'::jsonb,'[]'::jsonb,'1.0.0')`, value.tenantID, value.projectID, pluginID, "MySQL "+suffix)
	exec(`INSERT INTO plugin_versions
(version_id,tenant_id,project_id,plugin_id,semantic_version,status,artifact_id,package_sha256,manifest_digest,publisher_id,signing_key_id,protocol_version,minimum_agent_protocol_version,maximum_agent_protocol_version,supported_variants,database_version_range,capabilities,metric_template_schema_version,platforms,revision,created_at,approved_at)
VALUES ($1,$2,$3,$4,'1.0.0','available',$5,$6,$6,'publisher-1','key-1','v1','v1','v1','["mysql"]'::jsonb,'*','[]'::jsonb,1,'[{"os":"linux","arch":"amd64"}]'::jsonb,1,$7,$7)`, value.versionID, value.tenantID, value.projectID, pluginID, artifactID, digest, now)
	exec(`INSERT INTO plugin_assignments
(assignment_id,tenant_id,project_id,host_id,agent_id,plugin_id,database_family,desired_version_id,desired_version,artifact_id,artifact_sha256,manifest_digest,desired_state,configuration_revision,operation_revision,rollout_percentage,instance_ids,template_revision_ids,reconcile_state,revision,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$6,'mysql',$7,'1.0.0',$8,$9,$9,'running',5,7,100,jsonb_build_array($10::text),'[]'::jsonb,'converged',1,$11,$11)`, value.assignmentID, value.tenantID, value.projectID, value.hostID, value.agentID, pluginID, value.versionID, artifactID, digest, value.instanceID, now)
	exec(`INSERT INTO plugin_assignment_instances
(tenant_id,project_id,assignment_id,instance_id,created_at,updated_at)
VALUES ($1,$2,$3,$4,$5,$5)`, value.tenantID, value.projectID, value.assignmentID, value.instanceID, now)
	exec(`INSERT INTO jobs
(id,tenant_id,project_id,job_type,status,outcome,source_resource_type,source_resource_id,idempotency_key,version,total_targets,completed_targets,created_at,finished_at,request_id,trace_id)
VALUES ($1,$2,$3,'plugin.reconcile','succeeded','complete','plugin_assignment',$4,$5,1,1,1,$6,$6,$7,$8)`, value.jobID, value.tenantID, value.projectID, value.assignmentID, "idem-"+suffix, now, "request-"+suffix, "trace-"+suffix)
	exec(`INSERT INTO command_outbox
(id,tenant_id,project_id,job_id,target_id,message_type,payload,available_at,created_at,published_at,command_status,command_phase,terminal_at)
VALUES ($1,$2,$3,$4,$5,'agent.plugin.reconcile.v1',decode('00','hex'),$6,$6,$6,'succeeded','succeeded',$6)`, value.commandID, value.tenantID, value.projectID, value.jobID, value.agentID, now)
	exec(`INSERT INTO plugin_reconcile_operations
(tenant_id,project_id,assignment_id,configuration_revision,operation_revision,job_id,command_id,created_at)
VALUES ($1,$2,$3,5,7,$4,$5,$6)`, value.tenantID, value.projectID, value.assignmentID, value.jobID, value.commandID, now)
	exec(`INSERT INTO plugin_observations
(tenant_id,project_id,assignment_id,host_id,agent_id,plugin_id,database_family,installed_version,active_slot,process_state,process_id,started_at,health,restart_count,circuit_state,bound_instance_count,active_configuration_revision,observed_operation_revision,observation_revision,observation_digest,observed_at,received_at)
VALUES ($1,$2,$3,$4,$5,$6,'mysql','1.0.0','a','running',123,$7,'healthy',0,'closed',1,5,7,1,$8,$7,$7)`, value.tenantID, value.projectID, value.assignmentID, value.hostID, value.agentID, pluginID, now, digest)
	exec(`INSERT INTO credential_lease_audits
(tenant_id,project_id,agent_id,host_id,assignment_id,instance_id,configuration_revision,operation_revision,instance_revision,credential_revision,lease_id_hash,result,expiry_class,occurred_at)
VALUES ($1,$2,$3,$4,$5,$6,5,7,9,11,$7,'issued','short',$8)`, value.tenantID, value.projectID, value.agentID, value.hostID, value.assignmentID, value.instanceID, "sha256:"+strings.Repeat("1", 64), now)
	require.NoError(t, tx.Commit())
	return value
}

type inactiveFence struct {
	calls     int
	commandID string
}

func (fence *inactiveFence) ExecutionLeaseActive(_ string, commandID string, _ time.Time) bool {
	fence.calls++
	fence.commandID = commandID
	return false
}

func requestDurableRenewal(ctx context.Context, database *sql.DB, value durableRenewalFixture) (credentiallease.Lease, *inactiveFence, *credentiallease.ApplicationService, error) {
	provider, err := credentiallease.NewMemoryProvider(map[string]credentiallease.Credential{
		value.credentialRef: {Username: value.username, SecretBytes: value.secret, Revision: 12},
	})
	if err != nil {
		return credentiallease.Lease{}, nil, nil, err
	}
	fence := &inactiveFence{}
	authorizer := credentiallease.PostgresAuthorizer{Database: database, Fences: fence}
	service, err := credentiallease.NewService(credentiallease.Config{
		Authorizer: authorizer,
		Renewals:   authorizer,
		Provider:   provider,
		Clock:      credentiallease.PostgresClock{Database: database},
		Audit:      credentiallease.PostgresAuditRecorder{Database: database},
		TTL:        30 * time.Second,
		Random:     bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)),
	})
	if err != nil {
		return credentiallease.Lease{}, fence, nil, err
	}
	request := credentiallease.LeaseRequest{
		Nonce:                 bytes.Repeat([]byte{0x24}, credentiallease.RequestNonceBytes),
		InstanceID:            value.instanceID,
		AssignmentID:          value.assignmentID,
		DatabaseFamily:        "mysql",
		ConfigurationRevision: 5,
		OperationRevision:     7,
	}
	lease, err := service.Lease(ctx, credentiallease.AuthenticatedAgent{AgentID: value.agentID, SessionID: "session-" + strings.TrimPrefix(value.agentID, "agent-")}, request)
	return lease, fence, service, err
}

func assertIssuedAuditIsHashOnly(t *testing.T, database *sql.DB, value durableRenewalFixture, lease credentiallease.Lease) {
	t.Helper()
	var tenantID, projectID, agentID, hostID, assignmentID, instanceID, leaseIDHash, result, expiryClass string
	var configurationRevision, operationRevision, instanceRevision, credentialRevision uint64
	var occurredAt time.Time
	err := database.QueryRow(`SELECT tenant_id,project_id,agent_id,host_id,assignment_id,instance_id,configuration_revision,operation_revision,instance_revision,credential_revision,lease_id_hash,result,expiry_class,occurred_at
FROM credential_lease_audits WHERE tenant_id=$1 AND project_id=$2 ORDER BY audit_id DESC LIMIT 1`, value.tenantID, value.projectID).Scan(&tenantID, &projectID, &agentID, &hostID, &assignmentID, &instanceID, &configurationRevision, &operationRevision, &instanceRevision, &credentialRevision, &leaseIDHash, &result, &expiryClass, &occurredAt)
	require.NoError(t, err)
	require.Equal(t, value.tenantID, tenantID)
	require.Equal(t, value.projectID, projectID)
	require.Equal(t, value.agentID, agentID)
	require.Equal(t, value.hostID, hostID)
	require.Equal(t, value.assignmentID, assignmentID)
	require.Equal(t, value.instanceID, instanceID)
	require.Equal(t, uint64(5), configurationRevision)
	require.Equal(t, uint64(7), operationRevision)
	require.Equal(t, uint64(9), instanceRevision)
	require.Equal(t, uint64(12), credentialRevision)
	require.Equal(t, credentiallease.LeaseIDAuditHash(lease.ID), leaseIDHash)
	require.NotEqual(t, lease.ID, leaseIDHash)
	require.Equal(t, "issued", result)
	require.Equal(t, "short", expiryClass)
	require.False(t, occurredAt.IsZero())

	var rowJSON string
	require.NoError(t, database.QueryRow(`SELECT row_to_json(a)::text FROM credential_lease_audits a WHERE tenant_id=$1 AND project_id=$2 ORDER BY audit_id DESC LIMIT 1`, value.tenantID, value.projectID).Scan(&rowJSON))
	require.NotContains(t, rowJSON, lease.ID)
	require.NotContains(t, rowJSON, value.username)
	require.NotContains(t, rowJSON, string(value.secret))
	require.Contains(t, rowJSON, leaseIDHash)
}

func productionMigrationDatabase(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	if os.Getenv("DBPILOT_CREDENTIAL_LEASE_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_CREDENTIAL_LEASE_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_CREDENTIAL_LEASE_POSTGRES_DSN")
	require.NotEmpty(t, dsn)
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.Ping())
	publicBefore := namespaceSnapshot(t, admin, "public")
	schema := fmt.Sprintf("dbpilot_task11_production_%d", time.Now().UnixNano())
	quoted := `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	_, err = admin.Exec("CREATE SCHEMA " + quoted)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	database, err := sql.Open("postgres", parsed.String())
	require.NoError(t, err)
	require.NoError(t, database.Ping())
	var currentSchema string
	require.NoError(t, database.QueryRow(`SELECT current_schema()`).Scan(&currentSchema))
	require.Equal(t, schema, currentSchema)

	cleaned := false
	cleanup := func() {
		if cleaned {
			return
		}
		cleaned = true
		require.NoError(t, database.Close())
		_, dropErr := admin.Exec("DROP SCHEMA " + quoted + " CASCADE")
		require.NoError(t, dropErr)
		var exists bool
		require.NoError(t, admin.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname=$1)`, schema).Scan(&exists))
		require.False(t, exists, "the integration test must remove only its unique schema")
		require.Equal(t, publicBefore, namespaceSnapshot(t, admin, "public"), "production migrations must not modify public")
		require.NoError(t, admin.Close())
	}
	t.Cleanup(cleanup)
	return database, cleanup
}

func namespaceSnapshot(t *testing.T, database *sql.DB, namespace string) []string {
	t.Helper()
	rows, err := database.Query(`
SELECT object FROM (
    SELECT 'class:' || c.relkind::text || ':' || c.relname AS object
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1
    UNION ALL
    SELECT 'proc:' || p.prokind::text || ':' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')' AS object
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=$1
    UNION ALL
    SELECT 'type:' || t.typtype::text || ':' || t.typname AS object
      FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname=$1
) objects ORDER BY object`, namespace)
	require.NoError(t, err)
	defer rows.Close()
	var result []string
	for rows.Next() {
		var object string
		require.NoError(t, rows.Scan(&object))
		result = append(result, object)
	}
	require.NoError(t, rows.Err())
	return result
}
