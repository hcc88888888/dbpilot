package metrictemplate

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"dbpilot.local/platform/internal/plugincatalog"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestMetricTemplatePostgres16TrialConcurrencyTimeoutAndBoundedMetrics(t *testing.T) {
	database, scope := metricTemplatePostgresFixture(t)
	ctx := context.Background()
	jobs := job.NewPostgresRepositoryWithTargetAuthorizer(database, pluginassignment.InstanceTargetAuthorizer{Database: database})
	repository := NewPostgresRepository(database, jobs)
	service := NewService(repository, DeterministicDialectValidator{Validate: func(context.Context, TemplateDefinition) error { return nil }}, repository, time.Now)
	seedMetricTemplateTrialTarget(t, database, scope, time.Now().UTC())

	_, err := service.CreateTemplate(ctx, scope, TemplateDraft{ID: "mysql.concurrent_trial", DatabaseFamily: "mysql", Name: "Concurrent trial"}, integrationActor("creator", "createMetricTemplate", "concurrent-template"))
	require.NoError(t, err)
	draft, err := service.CreateDraft(ctx, scope, "mysql.concurrent_trial", Draft{CreatedBy: "creator", TemplateDefinition: validDefinition()}, integrationActor("creator", "createMetricTemplateRevision", "concurrent-draft"))
	require.NoError(t, err)
	validated, err := service.Validate(ctx, scope, draft.ID, draft.ResourceRevision, integrationActor("creator", "validateMetricTemplateRevision", "concurrent-validate"))
	require.NoError(t, err)

	start := make(chan struct{})
	results := make(chan struct {
		job job.Job
		err error
	}, 2)
	for index := 0; index < 2; index++ {
		index := index
		go func() {
			<-start
			value, startErr := service.StartTrial(ctx, scope, validated.ID, TrialRequest{InstanceID: "instance-task12", PluginVersionID: "version-task12", Actor: integrationActor("creator", "trialMetricTemplateRevision", fmt.Sprintf("concurrent-trial-%d", index))})
			results <- struct {
				job job.Job
				err error
			}{job: value, err: startErr}
		}()
	}
	close(start)
	first, second := <-results, <-results
	require.True(t, first.err == nil && second.err != nil || second.err == nil && first.err != nil, "trial race results: %v %v", first.err, second.err)
	running := first.job
	if running.ID == "" {
		running = second.job
	}
	var trialCount int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM metric_template_trials WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3 AND status='running'`, scope.TenantID, scope.ProjectID, validated.ID).Scan(&trialCount))
	require.Equal(t, 1, trialCount)
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM metric_template_trials WHERE tenant_id=$1 AND project_id=$2 AND revision_id=$3 AND instance_id='instance-task12' AND assignment_id='assignment-task12'`, scope.TenantID, scope.ProjectID, validated.ID).Scan(&trialCount))
	require.Equal(t, 1, trialCount, "the stable template id must not be substituted for the revision id in the trial command")

	now := time.Now().UTC()
	_, err = database.ExecContext(ctx, `UPDATE jobs SET status='timed_out',finished_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND id=$4`, now, scope.TenantID, scope.ProjectID, running.ID)
	require.NoError(t, err)
	failed, err := repository.FailTerminalTrials(ctx, 128, now.Add(time.Second))
	require.NoError(t, err)
	require.Equal(t, 1, failed)
	revision, err := repository.GetRevision(ctx, scope, validated.ID)
	require.NoError(t, err)
	require.Equal(t, StatusTrialFailed, revision.Status)
	var trialStatus, statusCode string
	require.NoError(t, database.QueryRowContext(ctx, `SELECT status,status_code FROM metric_template_trials WHERE tenant_id=$1 AND project_id=$2 AND job_id=$3`, scope.TenantID, scope.ProjectID, running.ID).Scan(&trialStatus, &statusCode))
	require.Equal(t, "failed", trialStatus)
	require.Equal(t, "job_timed_out", statusCode)

	_, err = service.CreateTemplate(ctx, scope, TemplateDraft{ID: "mysql.multi_value_trial", DatabaseFamily: "mysql", Name: "Multi value trial"}, integrationActor("creator", "createMetricTemplate", "metrics-template"))
	require.NoError(t, err)
	definition := validDefinition()
	definition.MaxRows = 100
	definition.CardinalityLimit = 200
	definition.ValueMappings = []ValueMapping{
		{SourceColumn: "value", MetricName: "mysql.connections.current", MetricType: MetricGauge, Unit: "1"},
		{SourceColumn: "other", MetricName: "mysql.connections.other", MetricType: MetricGauge, Unit: "1"},
	}
	draft, err = service.CreateDraft(ctx, scope, "mysql.multi_value_trial", Draft{CreatedBy: "creator", TemplateDefinition: definition}, integrationActor("creator", "createMetricTemplateRevision", "metrics-draft"))
	require.NoError(t, err)
	validated, err = service.Validate(ctx, scope, draft.ID, draft.ResourceRevision, integrationActor("creator", "validateMetricTemplateRevision", "metrics-validate"))
	require.NoError(t, err)
	metricJob, err := service.StartTrial(ctx, scope, validated.ID, TrialRequest{InstanceID: "instance-task12", PluginVersionID: "version-task12", Actor: integrationActor("creator", "trialMetricTemplateRevision", "metrics-trial")})
	require.NoError(t, err)
	metrics := make([]CandidateMetric, 101)
	for index := range metrics {
		name := "mysql.connections.current"
		if index%2 == 1 {
			name = "mysql.connections.other"
		}
		metrics[index] = CandidateMetric{Name: name, MetricType: MetricGauge, Unit: "1", Value: float64(index)}
	}
	passed, err := repository.RecordTrialResult(ctx, scope, metricJob.ID, TrialResult{RevisionID: validated.ID, QueryDigest: validated.QueryDigest, StatusCode: "succeeded", Metrics: metrics, RowCount: 51, ColumnCount: 2, MetricCount: len(metrics), DurationMillis: 10}, time.Now().UTC())
	require.NoError(t, err)
	require.Equal(t, StatusTrialPassed, passed.Status)
}

func TestMetricTemplatePostgres16WorkflowRevisionRaceRollbackAndRedaction(t *testing.T) {
	database, scope := metricTemplatePostgresFixture(t)
	ctx := context.Background()
	jobs := job.NewPostgresRepository(database)
	repository := NewPostgresRepository(database, jobs)
	dialect := DeterministicDialectValidator{Validate: func(context.Context, TemplateDefinition) error { return nil }}
	service := NewService(repository, dialect, repository, time.Now)
	creator := integrationActor("creator", "createMetricTemplate", "template-create")
	created, err := service.CreateTemplate(ctx, scope, TemplateDraft{ID: "mysql.custom_connections", DatabaseFamily: "mysql", Name: "Custom connections"}, creator)
	require.NoError(t, err)
	require.Zero(t, created.LatestRevision)
	first := createValidatedTrialPassedRevision(t, ctx, database, service, scope, "mysql.custom_connections", "creator", 1)
	_, err = service.Approve(ctx, scope, first.ID, first.ResourceRevision, integrationActor("creator", "approveMetricTemplateRevision", "self-approve"))
	require.ErrorIs(t, err, ErrSelfApproval)
	approved, err := service.Approve(ctx, scope, first.ID, first.ResourceRevision, integrationActor("approver", "approveMetricTemplateRevision", "approve-first"))
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 2)
	var publishedMu sync.Mutex
	var published []Revision
	for index := 0; index < 2; index++ {
		index := index
		go func() {
			<-start
			value, publishErr := service.Publish(ctx, scope, approved.ID, approved.ResourceRevision, PublishScope{Actor: integrationActor("approver", "publishMetricTemplateRevision", fmt.Sprintf("publish-race-%d", index))})
			if publishErr == nil {
				publishedMu.Lock()
				published = append(published, value)
				publishedMu.Unlock()
			}
			results <- publishErr
		}()
	}
	close(start)
	firstErr, secondErr := <-results, <-results
	require.True(t, firstErr == nil && secondErr != nil || secondErr == nil && firstErr != nil, "race results: %v %v", firstErr, secondErr)
	require.Len(t, published, 1)
	second := createValidatedTrialPassedRevision(t, ctx, database, service, scope, "mysql.custom_connections", "creator", 2)
	secondApproved, err := service.Approve(ctx, scope, second.ID, second.ResourceRevision, integrationActor("approver", "approveMetricTemplateRevision", "approve-second"))
	require.NoError(t, err)
	secondPublished, err := service.Publish(ctx, scope, secondApproved.ID, secondApproved.ResourceRevision, PublishScope{Actor: integrationActor("approver", "publishMetricTemplateRevision", "publish-second")})
	require.NoError(t, err)
	require.Equal(t, StatusPublished, secondPublished.Status)
	prior, err := repository.GetRevision(ctx, scope, approved.ID)
	require.NoError(t, err)
	require.Equal(t, StatusSuperseded, prior.Status)
	rolledBack, err := service.Publish(ctx, scope, prior.ID, prior.ResourceRevision, PublishScope{Actor: integrationActor("approver", "publishMetricTemplateRevision", "rollback-first")})
	require.NoError(t, err)
	require.Equal(t, StatusPublished, rolledBack.Status)
	var publicationCount int
	require.NoError(t, database.QueryRowContext(ctx, `SELECT count(*) FROM metric_template_publications WHERE tenant_id=$1 AND project_id=$2 AND template_id=$3`, scope.TenantID, scope.ProjectID, "mysql.custom_connections").Scan(&publicationCount))
	require.Equal(t, 3, publicationCount)
	queryText := "SELECT value FROM metrics"
	for _, table := range []string{"audit_events", "metric_template_mutations", "jobs", "command_outbox"} {
		var leaked bool
		require.NoError(t, database.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+table+` WHERE lower(row_to_json(`+table+`)::text) LIKE $1)`, "%"+strings.ToLower(queryText)+"%").Scan(&leaked))
		require.False(t, leaked, table)
	}
	_, err = repository.GetRevision(ctx, platformscope.Scope{TenantID: scope.TenantID, ProjectID: "other-project"}, rolledBack.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func createValidatedTrialPassedRevision(t *testing.T, ctx context.Context, database *sql.DB, service *ApplicationService, scope platformscope.Scope, templateID, creator string, number int) Revision {
	t.Helper()
	draft, err := service.CreateDraft(ctx, scope, templateID, Draft{CreatedBy: creator, TemplateDefinition: validDefinition()}, integrationActor(creator, "createMetricTemplateRevision", fmt.Sprintf("draft-%d", number)))
	require.NoError(t, err)
	validated, err := service.Validate(ctx, scope, draft.ID, draft.ResourceRevision, integrationActor(creator, "validateMetricTemplateRevision", fmt.Sprintf("validate-%d", number)))
	require.NoError(t, err)
	now := time.Now().UTC()
	_, err = database.ExecContext(ctx, `UPDATE metric_template_revisions SET status='trial_running',resource_revision=resource_revision+1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND revision_id=$4 AND status='validated'`, now, scope.TenantID, scope.ProjectID, validated.ID)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, `UPDATE metric_template_revisions SET status='trial_passed',resource_revision=resource_revision+1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND revision_id=$4 AND status='trial_running'`, now.Add(time.Microsecond), scope.TenantID, scope.ProjectID, validated.ID)
	require.NoError(t, err)
	value, err := service.repository.GetRevision(ctx, scope, validated.ID)
	require.NoError(t, err)
	return value
}

func integrationActor(subject, operation, key string) Actor {
	return Actor{Subject: subject, OperationID: operation, IdempotencyKey: key, RequestFingerprint: "sha256:" + strings.Repeat("a", 64), RequestID: "request-" + key, TraceID: "trace-" + key}
}

func metricTemplatePostgresFixture(t *testing.T) (*sql.DB, platformscope.Scope) {
	t.Helper()
	if os.Getenv("DBPILOT_METRIC_TEMPLATE_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_METRIC_TEMPLATE_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_METRIC_TEMPLATE_POSTGRES_DSN")
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.Ping())
	schema := fmt.Sprintf("dbpilot_task12_%d", time.Now().UnixNano())
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
	require.NoError(t, alert.RunMigrations(ctx, database))
	require.NoError(t, job.RunMigrations(ctx, database))
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, discovery.RunMigrations(ctx, database))
	require.NoError(t, databaseinstance.RunMigrations(ctx, database))
	require.NoError(t, plugincatalog.RunMigrations(ctx, database))
	require.NoError(t, pluginassignment.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	return database, platformscope.Scope{TenantID: "tenant-task12", ProjectID: "project-task12"}
}

func seedMetricTemplateTrialTarget(t *testing.T, database *sql.DB, scope platformscope.Scope, now time.Time) {
	t.Helper()
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
VALUES ($1,$2,'host-task12','agent-task12','Task12 host','task12.example','linux','amd64',1,$3,'online',$3)`, scope.TenantID, scope.ProjectID, now)
	exec(`INSERT INTO discovery_candidates
(candidate_id,tenant_id,project_id,host_id,agent_id,observation_id,discovery_source,database_family,database_variant,normalized_endpoint,confidence,evidence_summary,fingerprint,rule_revision,observation_revision,first_seen_at,last_seen_at,status,updated_at)
VALUES ('candidate-task12',$1,$2,'host-task12','agent-task12','observation-task12','native','mysql','mysql','127.0.0.1:3306',1,'[]'::jsonb,decode($3,'hex'),1,1,$4,$4,'accepted',$4)`, scope.TenantID, scope.ProjectID, sourceFingerprint, now)
	exec(`INSERT INTO managed_database_instances
(instance_id,tenant_id,project_id,host_id,agent_id,candidate_id,discovery_source,source_fingerprint,source_identity,database_family,database_variant,display_name,endpoint,credential_ref,capability_state,connection_test_status,plugin_assignment_revision,management_status,revision,created_at,updated_at,canonical_connection)
VALUES ('instance-task12',$1,$2,'host-task12','agent-task12','candidate-task12','native',$3,'native:task12','mysql','mysql','Task12 MySQL','127.0.0.1:3306','secret://database/task12','plugin_not_installed','not_tested',5,'monitoring',1,$4,$4,'mysql://127.0.0.1:3306/task12')`, scope.TenantID, scope.ProjectID, sourceFingerprint, now)
	exec(`UPDATE discovery_candidates SET accepted_instance_id='instance-task12' WHERE tenant_id=$1 AND project_id=$2 AND candidate_id='candidate-task12'`, scope.TenantID, scope.ProjectID)
	exec(`INSERT INTO artifacts
(id,tenant_id,project_id,kind,content_type,size_bytes,checksum,created_at,storage_reference)
VALUES ('artifact-task12',$1,$2,'plugin-package','application/octet-stream',1,$3,$4,'object://plugins/task12')`, scope.TenantID, scope.ProjectID, "sha256:"+digest, now)
	exec(`INSERT INTO plugin_definitions
(tenant_id,project_id,plugin_id,name,database_family,protocol_version,supported_variants,capabilities,latest_available_version)
VALUES ($1,$2,'plugin-task12','Task12 MySQL','mysql','v1','["mysql"]'::jsonb,'["metrics.collect"]'::jsonb,'1.0.0')`, scope.TenantID, scope.ProjectID)
	exec(`INSERT INTO plugin_versions
(version_id,tenant_id,project_id,plugin_id,semantic_version,status,artifact_id,package_sha256,manifest_digest,publisher_id,signing_key_id,protocol_version,minimum_agent_protocol_version,maximum_agent_protocol_version,supported_variants,database_version_range,capabilities,metric_template_schema_version,platforms,revision,created_at,approved_at)
VALUES ('version-task12',$1,$2,'plugin-task12','1.0.0','available','artifact-task12',$3,$3,'publisher-task12','key-task12','v1','v1','v1','["mysql"]'::jsonb,'*','["metrics.collect"]'::jsonb,1,'[{"os":"linux","arch":"amd64"}]'::jsonb,1,$4,$4)`, scope.TenantID, scope.ProjectID, digest, now)
	exec(`INSERT INTO plugin_assignments
(assignment_id,tenant_id,project_id,host_id,agent_id,plugin_id,database_family,desired_version_id,desired_version,artifact_id,artifact_sha256,manifest_digest,desired_state,configuration_revision,operation_revision,rollout_percentage,instance_ids,template_revision_ids,reconcile_state,revision,created_at,updated_at)
VALUES ('assignment-task12',$1,$2,'host-task12','agent-task12','plugin-task12','mysql','version-task12','1.0.0','artifact-task12',$3,$3,'running',5,7,100,'["instance-task12"]'::jsonb,'[]'::jsonb,'converged',1,$4,$4)`, scope.TenantID, scope.ProjectID, digest, now)
	exec(`INSERT INTO plugin_assignment_instances
(tenant_id,project_id,assignment_id,instance_id,created_at,updated_at)
VALUES ($1,$2,'assignment-task12','instance-task12',$3,$3)`, scope.TenantID, scope.ProjectID, now)
	exec(`INSERT INTO plugin_observations
(tenant_id,project_id,assignment_id,host_id,agent_id,plugin_id,database_family,installed_version,active_slot,process_state,process_id,started_at,health,restart_count,circuit_state,bound_instance_count,active_configuration_revision,observed_operation_revision,observation_revision,observation_digest,observed_at,received_at)
VALUES ($1,$2,'assignment-task12','host-task12','agent-task12','plugin-task12','mysql','1.0.0','a','running',123,$3,'healthy',0,'closed',1,5,7,1,$4,$3,$3)`, scope.TenantID, scope.ProjectID, now, digest)
	require.NoError(t, tx.Commit())
}
