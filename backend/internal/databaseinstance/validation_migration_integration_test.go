package databaseinstance

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestValidationMigrationUpgradesReal0002EraStates(t *testing.T) {
	if os.Getenv("DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN is required")
	}
	ctx := context.Background()
	for _, test := range []struct {
		name       string
		validation bool
		job        bool
		retired    bool
		wantError  bool
	}{
		{name: "valid pending", validation: true, job: true},
		{name: "active orphan", wantError: true},
		{name: "active missing job outbox", validation: true, wantError: true},
		{name: "retired pending", validation: true, job: true, retired: true},
		{name: "retired missing job outbox", validation: true, retired: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, scope, hostID, agentID := real0002ValidationDatabase(t, ctx, dsn, test.name)
			now := time.Now().UTC().Truncate(time.Microsecond)
			endpoint := "127.0.0.1:3306"
			candidateID := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-"+strings.ReplaceAll(test.name, " ", "-"), endpoint, "mysqld.service", 1)
			request := integrationAcceptRequest("accept-"+strings.ReplaceAll(test.name, " ", "-"), 1)
			request.Endpoint = endpoint
			instance, err := NewPostgresRepository(database).AcceptCandidate(ctx, scope, candidateID, request)
			require.NoError(t, err)
			jobID := "job-validation-" + strings.ReplaceAll(test.name, " ", "-")
			commandID := "command-validation-" + strings.ReplaceAll(test.name, " ", "-")
			management := "connection_testing"
			var retiredAt any
			if test.retired {
				management = "retired"
				retiredAt = now
			}
			_, err = database.ExecContext(ctx, `UPDATE managed_database_instances SET capability_state='plugin_available',connection_test_status='queued',connection_test_error_code='',connection_test_at=$1,management_status=$2,retired_at=$3,updated_at=$1 WHERE tenant_id=$4 AND project_id=$5 AND instance_id=$6`, now, management, retiredAt, scope.TenantID, scope.ProjectID, instance.ID)
			require.NoError(t, err)
			if test.job {
				payload, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.CommandEnvelope{AgentId: agentID, LeaseSeconds: 30, Command: &agentv1.CommandEnvelope_ValidateDatabaseInstance{ValidateDatabaseInstance: &agentv1.ValidateDatabaseInstance{AssignmentId: "assignment-a", InstanceId: instance.ID, ConfigurationRevision: 1}}})
				require.NoError(t, marshalErr)
				timeout := now.Add(time.Minute)
				value := job.Job{ID: jobID, Type: "database_instance.validate", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone, InstanceID: instance.ID, TargetResourceIDs: []string{agentID}, InitiatedBy: "operator", SourceResource: job.ResourceReference{ResourceType: "database_instance", ResourceID: instance.ID}, IdempotencyKey: "validation-" + jobID, Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: 30 * time.Second, RequestID: "request-" + jobID, TraceID: "trace-" + jobID}
				message := job.OutboxMessage{ID: commandID, Scope: scope, JobID: jobID, TargetID: agentID, Type: "agent.command", Payload: payload, AvailableAt: now, CreatedAt: now}
				require.NoError(t, job.NewPostgresRepositoryWithTargetAuthorizer(database, allowMigrationTarget{}).CreateWithOutbox(ctx, value, []job.OutboxMessage{message}))
			}
			if test.validation {
				_, err = database.ExecContext(ctx, `INSERT INTO database_instance_validations (tenant_id,project_id,job_id,command_id,instance_id,assignment_id,configuration_revision,operation_revision,actor_id,operation_id,idempotency_key,request_fingerprint,request_id,trace_id,previous_management_status,status,error_code,requested_at) VALUES ($1,$2,$3,$4,$5,'assignment-a',1,1,'operator','testDatabaseInstanceConnection',$6,$7,$8,'trace-validation','managed','queued','',$9)`, scope.TenantID, scope.ProjectID, jobID, commandID, instance.ID, "idempotency-"+jobID, "sha256:"+fmt.Sprintf("%064x", 71), "request-validation", now)
				require.NoError(t, err)
			}

			err = RunMigrations(ctx, database)
			if test.wantError {
				require.ErrorContains(t, err, "orphan")
				return
			}
			require.NoError(t, err)
			require.NoError(t, RunMigrations(ctx, database), "migration restart must be idempotent")
			var connectionStatus, errorCode, correlationJob, correlationCommand, storedManagement string
			require.NoError(t, database.QueryRowContext(ctx, `SELECT connection_test_status,connection_test_error_code,connection_validation_job_id,connection_validation_command_id,management_status FROM managed_database_instances WHERE instance_id=$1`, instance.ID).Scan(&connectionStatus, &errorCode, &correlationJob, &correlationCommand, &storedManagement))
			if !test.retired {
				require.Equal(t, "queued", connectionStatus)
				require.Equal(t, jobID, correlationJob)
				require.Equal(t, commandID, correlationCommand)
				return
			}
			require.Equal(t, "retired", storedManagement)
			require.Equal(t, "plugin_failed", connectionStatus)
			require.Equal(t, "plugin_failed", errorCode)
			require.Empty(t, correlationJob)
			require.Empty(t, correlationCommand)
			var validationStatus string
			require.NoError(t, database.QueryRowContext(ctx, `SELECT status FROM database_instance_validations WHERE job_id=$1`, jobID).Scan(&validationStatus))
			require.Equal(t, "plugin_failed", validationStatus)
			if test.job {
				storedJob, getErr := job.NewPostgresRepository(database).Get(ctx, scope, jobID)
				require.NoError(t, getErr)
				require.Equal(t, job.StatusCancelled, storedJob.Status)
				storedCommand, getErr := job.NewPostgresRepository(database).LookupCommand(ctx, commandID)
				require.NoError(t, getErr)
				require.Equal(t, job.CommandCancelled, storedCommand.CommandStatus)
			}
		})
	}
}

type allowMigrationTarget struct{}

func (allowMigrationTarget) AuthorizeTarget(context.Context, string, string) error { return nil }

func real0002ValidationDatabase(t *testing.T, ctx context.Context, dsn, suffix string) (*sql.DB, platformscope.Scope, string, string) {
	t.Helper()
	database := openValidationMigrationDatabase(t, ctx, dsn)
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, discovery.RunMigrations(ctx, database))
	require.NoError(t, job.RunMigrations(ctx, database))
	for _, path := range []string{"migrations/0001_database_instances.sql", "migrations/0002_database_instance_lifecycle.sql"} {
		body, err := migrationFiles.ReadFile(path)
		require.NoError(t, err)
		contents := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(body)), "BEGIN;")), "COMMIT;"))
		_, err = database.ExecContext(ctx, contents)
		require.NoError(t, err)
		_, err = database.ExecContext(ctx, `INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)`, "databaseinstance/"+path)
		require.NoError(t, err)
	}
	clean := strings.ReplaceAll(suffix, " ", "-")
	scope := platformscope.Scope{TenantID: "tenant-migration-" + clean, ProjectID: "project-migration-" + clean}
	hostID, agentID := "host-migration-"+clean, "agent-migration-"+clean
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := hostinventory.NewPostgresRepository(database).RecordObservation(ctx, scope, hostinventory.Observation{HostID: hostID, AgentID: agentID, Revision: 1, AgentVersion: "test", Hostname: hostID + ".example", OS: "linux", Architecture: "amd64", LogicalCPUCount: 1, MemoryCapacityBytes: 1024, NetworkAddresses: []string{}, Capabilities: []string{"native_discovery_v1"}, ObservedAt: now}, now)
	require.NoError(t, err)
	return database, scope, hostID, agentID
}

func openValidationMigrationDatabase(t *testing.T, ctx context.Context, dsn string) *sql.DB {
	t.Helper()
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.PingContext(ctx))
	schema := fmt.Sprintf("validation_migration_%d", time.Now().UnixNano())
	quoted := pq.QuoteIdentifier(schema)
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+quoted)
	require.NoError(t, err)
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	database, err := sql.Open("postgres", parsed.String())
	require.NoError(t, err)
	require.NoError(t, database.PingContext(ctx))
	t.Cleanup(func() {
		require.NoError(t, database.Close())
		_, dropErr := admin.ExecContext(context.Background(), "DROP SCHEMA IF EXISTS "+quoted+" CASCADE")
		require.NoError(t, dropErr)
		require.NoError(t, admin.Close())
	})
	return database
}
