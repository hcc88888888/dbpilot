package databaseinstance

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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

func TestRetiredValidationWinnerMigrationUpgradesReal0004AppliedState(t *testing.T) {
	if os.Getenv("DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_DATABASE_INSTANCE_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_DATABASE_INSTANCE_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, test := range []struct {
		name             string
		jobStatus        job.Status
		commandStatus    job.CommandStatus
		wantTarget       job.TargetStatus
		wantValidation   ConnectionTestStatus
		wantAudit        string
		wantCommandAudit string
		wantError        bool
	}{
		{name: "succeeded winner", jobStatus: job.StatusSucceeded, commandStatus: job.CommandSucceeded, wantTarget: job.TargetSucceeded, wantValidation: ConnectionSucceeded, wantAudit: "database_instance.connection_test_succeeded", wantCommandAudit: "command.result"},
		{name: "failed winner", jobStatus: job.StatusFailed, commandStatus: job.CommandFailed, wantTarget: job.TargetFailed, wantValidation: ConnectionPluginFailed, wantAudit: "database_instance.connection_test_failed", wantCommandAudit: "command.result"},
		{name: "timed out winner", jobStatus: job.StatusTimedOut, commandStatus: job.CommandTimedOut, wantTarget: job.TargetTimedOut, wantValidation: ConnectionPluginFailed, wantAudit: "database_instance.connection_test_failed", wantCommandAudit: "command.execution_timed_out"},
		{name: "active becomes cancelled", wantTarget: job.TargetCancelled, wantValidation: ConnectionPluginFailed, wantAudit: "database_instance.connection_test_cancelled_on_retire", wantCommandAudit: "command.validation_cancelled_on_retire"},
		{name: "conflicting Job and Outbox", jobStatus: job.StatusSucceeded, commandStatus: job.CommandFailed, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			database, scope, hostID, agentID := real0004ValidationDatabase(t, ctx, dsn, test.name)
			now := time.Now().UTC().Truncate(time.Microsecond)
			clean := strings.ReplaceAll(test.name, " ", "-")
			endpoint := "127.0.0.1:3406"
			candidateID := insertCurrentCandidate(t, database, scope, hostID, agentID, "candidate-"+clean, endpoint, "mysqld.service", 1)
			request := integrationAcceptRequest("accept-"+clean, 1)
			request.Endpoint = endpoint
			instance, err := NewPostgresRepository(database).AcceptCandidate(ctx, scope, candidateID, request)
			require.NoError(t, err)
			jobID, commandID := "job-validation-"+clean, "command-validation-"+clean
			payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.CommandEnvelope{AgentId: agentID, LeaseSeconds: 30, Command: &agentv1.CommandEnvelope_ValidateDatabaseInstance{ValidateDatabaseInstance: &agentv1.ValidateDatabaseInstance{AssignmentId: "assignment-a", InstanceId: instance.ID, ConfigurationRevision: 1}}})
			require.NoError(t, err)
			timeout := now.Add(time.Minute)
			value := job.Job{ID: jobID, Type: "database_instance.validate", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone, InstanceID: instance.ID, TargetResourceIDs: []string{agentID}, InitiatedBy: "operator", SourceResource: job.ResourceReference{ResourceType: "database_instance", ResourceID: instance.ID}, IdempotencyKey: "validation-" + jobID, Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, TimeoutAt: &timeout, MaxConcurrency: 1, TargetTimeout: 30 * time.Second, RequestID: "request-" + jobID, TraceID: "trace-" + jobID}
			message := job.OutboxMessage{ID: commandID, Scope: scope, JobID: jobID, TargetID: agentID, Type: "agent.command", Payload: payload, AvailableAt: now, CreatedAt: now}
			require.NoError(t, job.NewPostgresRepositoryWithTargetAuthorizer(database, allowMigrationTarget{}).CreateWithOutbox(ctx, value, []job.OutboxMessage{message}))
			_, err = database.ExecContext(ctx, `UPDATE managed_database_instances SET capability_state='plugin_available',connection_test_status='queued',connection_test_error_code='',connection_test_at=$1,management_status='retired',retired_at=$1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND instance_id=$4`, now, scope.TenantID, scope.ProjectID, instance.ID)
			require.NoError(t, err)
			_, err = database.ExecContext(ctx, `INSERT INTO database_instance_validations (tenant_id,project_id,job_id,command_id,instance_id,assignment_id,configuration_revision,operation_revision,actor_id,operation_id,idempotency_key,request_fingerprint,request_id,trace_id,previous_management_status,status,error_code,requested_at) VALUES ($1,$2,$3,$4,$5,'assignment-a',1,1,'operator','testDatabaseInstanceConnection',$6,$7,$8,'trace-validation','managed','queued','',$9)`, scope.TenantID, scope.ProjectID, jobID, commandID, instance.ID, "idempotency-"+jobID, "sha256:"+fmt.Sprintf("%064x", 91), "request-validation", now)
			require.NoError(t, err)
			if test.jobStatus != "" {
				targetStatus := test.wantTarget
				if test.wantError {
					targetStatus = job.TargetSucceeded
				}
				completed, failed := 0, 1
				outcome := job.OutcomeNone
				if test.jobStatus == job.StatusSucceeded {
					completed, failed, outcome = 1, 0, job.OutcomeComplete
				}
				_, err = database.ExecContext(ctx, `UPDATE job_targets SET status=$1,error_summary=CASE WHEN $1='failed' THEN 'plugin_failed' ELSE '' END,result_summary='historical terminal winner',finished_at=$2 WHERE tenant_id=$3 AND project_id=$4 AND job_id=$5 AND target_id=$6`, string(targetStatus), now, scope.TenantID, scope.ProjectID, jobID, agentID)
				require.NoError(t, err)
				_, err = database.ExecContext(ctx, `UPDATE jobs SET status=$1,outcome=$2,version=version+1,completed_targets=$3,failed_targets=$4,result_summary='historical terminal winner',finished_at=$5 WHERE tenant_id=$6 AND project_id=$7 AND id=$8`, string(test.jobStatus), string(outcome), completed, failed, now, scope.TenantID, scope.ProjectID, jobID)
				require.NoError(t, err)
				_, err = database.ExecContext(ctx, `UPDATE command_outbox SET command_status=$1,command_phase=$1,terminal_at=$2,published_at=$2 WHERE tenant_id=$3 AND project_id=$4 AND id=$5`, string(test.commandStatus), now, scope.TenantID, scope.ProjectID, commandID)
				require.NoError(t, err)
			}
			applyDatabaseInstanceMigrationFiles(t, ctx, database, "0003_validation_correlation.sql", "0003a_retired_validation_repair.sql", "0004_validation_orphan_guard.sql")

			err = job.RunMigrations(ctx, database)
			if err == nil {
				err = RunMigrations(ctx, database)
			}
			if test.wantError {
				require.ErrorContains(t, err, "conflicting")
				return
			}
			require.NoError(t, err)
			require.NoError(t, job.RunMigrations(ctx, database))
			require.NoError(t, RunMigrations(ctx, database), "0004-applied upgrade restart must be idempotent")
			var validationStatus, storedTarget, storedJob, storedCommand string
			var completed, failed int
			require.NoError(t, database.QueryRowContext(ctx, `SELECT status FROM database_instance_validations WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3`, scope.TenantID, scope.ProjectID, jobID).Scan(&validationStatus))
			require.NoError(t, database.QueryRowContext(ctx, `SELECT status FROM job_targets WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3 AND target_id=$4`, scope.TenantID, scope.ProjectID, jobID, agentID).Scan(&storedTarget))
			require.NoError(t, database.QueryRowContext(ctx, `SELECT status,completed_targets,failed_targets FROM jobs WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, scope.TenantID, scope.ProjectID, jobID).Scan(&storedJob, &completed, &failed))
			require.NoError(t, database.QueryRowContext(ctx, `SELECT command_status FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, scope.TenantID, scope.ProjectID, commandID).Scan(&storedCommand))
			require.Equal(t, string(test.wantValidation), validationStatus)
			require.Equal(t, string(test.wantTarget), storedTarget)
			wantCommand := test.commandStatus
			wantJob := test.jobStatus
			if wantJob == "" {
				wantJob, wantCommand = job.StatusCancelled, job.CommandCancelled
			}
			require.Equal(t, string(wantJob), storedJob)
			require.Equal(t, string(wantCommand), storedCommand)
			if test.wantTarget == job.TargetSucceeded {
				require.Equal(t, []int{1, 0}, []int{completed, failed})
			} else {
				require.Equal(t, []int{0, 1}, []int{completed, failed})
			}
			var auditCount int
			require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3 AND command_id=$4 AND action=$5`, scope.TenantID, scope.ProjectID, jobID, commandID, test.wantAudit).Scan(&auditCount))
			require.Equal(t, 1, auditCount)
			var pending bool
			var action string
			require.NoError(t, database.QueryRowContext(ctx, `SELECT terminal_audit_pending,terminal_audit_action FROM command_outbox WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, scope.TenantID, scope.ProjectID, commandID).Scan(&pending, &action))
			require.True(t, pending)
			require.Equal(t, test.wantCommandAudit, action)
		})
	}
}

type allowMigrationTarget struct{}

func (allowMigrationTarget) AuthorizeTarget(context.Context, string, string) error { return nil }

func real0004ValidationDatabase(t *testing.T, ctx context.Context, dsn, suffix string) (*sql.DB, platformscope.Scope, string, string) {
	t.Helper()
	database := openValidationMigrationDatabase(t, ctx, dsn)
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, discovery.RunMigrations(ctx, database))
	applyExternalJobMigrationFiles(t, ctx, database,
		"0001_jobs_outbox.sql", "0002_command_payload_bytea.sql", "0003_prepared_command_envelope.sql",
		"0004_command_execution_recovery.sql", "0005_two_phase_execution.sql", "0006_cancellation_response_snapshot.sql",
		"0007_inspection_concurrency.sql",
	)
	applyDatabaseInstanceMigrationFiles(t, ctx, database, "0001_database_instances.sql", "0002_database_instance_lifecycle.sql")
	clean := strings.ReplaceAll(suffix, " ", "-")
	scope := platformscope.Scope{TenantID: "tenant-migration-" + clean, ProjectID: "project-migration-" + clean}
	hostID, agentID := "host-migration-"+clean, "agent-migration-"+clean
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := hostinventory.NewPostgresRepository(database).RecordObservation(ctx, scope, hostinventory.Observation{HostID: hostID, AgentID: agentID, Revision: 1, AgentVersion: "test", Hostname: hostID + ".example", OS: "linux", Architecture: "amd64", LogicalCPUCount: 1, MemoryCapacityBytes: 1024, NetworkAddresses: []string{}, Capabilities: []string{"native_discovery_v1"}, ObservedAt: now}, now)
	require.NoError(t, err)
	return database, scope, hostID, agentID
}

func applyExternalJobMigrationFiles(t *testing.T, ctx context.Context, database *sql.DB, names ...string) {
	t.Helper()
	for _, name := range names {
		body, err := os.ReadFile(filepath.Join("..", "job", "migrations", name))
		require.NoError(t, err)
		contents := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(body)), "BEGIN;")), "COMMIT;"))
		_, err = database.ExecContext(ctx, contents)
		require.NoError(t, err)
		_, err = database.ExecContext(ctx, `INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)`, "job/migrations/"+name)
		require.NoError(t, err)
	}
}

func applyDatabaseInstanceMigrationFiles(t *testing.T, ctx context.Context, database *sql.DB, names ...string) {
	t.Helper()
	for _, name := range names {
		body, err := migrationFiles.ReadFile("migrations/" + name)
		require.NoError(t, err)
		contents := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(body)), "BEGIN;")), "COMMIT;"))
		_, err = database.ExecContext(ctx, contents)
		require.NoError(t, err)
		_, err = database.ExecContext(ctx, `INSERT INTO dbpilot_schema_migrations (name) VALUES ($1)`, "databaseinstance/migrations/"+name)
		require.NoError(t, err)
	}
}

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
