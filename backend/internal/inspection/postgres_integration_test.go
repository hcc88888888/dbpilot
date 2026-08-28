package inspection

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPostgresIntegrationRollbackRemovesRunTargetsJobAndOutbox(t *testing.T) {
	// Break caught: an outbox PK failure after Run/Target/Job inserts must roll
	// back every row owned by the inspection transaction.
	ctx, database, repository, jobRepository := openInspectionIntegration(t, "rollback")
	scope := platformscope.Scope{TenantID: "tenant-rollback", ProjectID: "project-rollback"}
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	seedInspectionItem(t, ctx, repository, scope, now)

	baselineRun, baselineTargets, baselineJob, baselineMessages := liveRunFixture("baseline", scope, now)
	require.NoError(t, jobRepository.CreateWithOutbox(ctx, baselineJob, baselineMessages))
	run, targets, value, messages := liveRunFixture("rollback", scope, now.Add(time.Minute))
	messages[0].ID = baselineMessages[0].ID
	targets[0].CommandID = baselineMessages[0].ID
	err := repository.CreateRunWithJob(ctx, run, targets, value, messages)
	require.Error(t, err)

	for table, predicate := range map[string]string{
		"inspection_runs": "id = 'run-rollback'", "inspection_target_runs": "run_id = 'run-rollback'",
		"jobs": "id = 'job-rollback'", "job_targets": "job_id = 'job-rollback'", "command_outbox": "job_id = 'job-rollback'",
	} {
		var count int
		require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE "+predicate).Scan(&count))
		require.Zero(t, count, table)
	}
	_ = baselineRun
	_ = baselineTargets
}

func TestSchedulerClaimersReceiveDisjointPolicies(t *testing.T) {
	// Break caught: without FOR UPDATE SKIP LOCKED and persisted leases, two
	// controller instances can dispatch the same due policy concurrently.
	ctx, _, repository, _ := openInspectionIntegration(t, "claims")
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-claims", ProjectID: "project-claims"}
	seedInspectionItem(t, ctx, repository, scope, now)
	for index := 0; index < 4; index++ {
		policy := livePolicyFixture(fmt.Sprintf("policy-%d", index), scope, now.Add(-time.Minute), now)
		require.NoError(t, repository.CreatePolicy(ctx, policy))
	}

	start := make(chan struct{})
	results := make(chan []Policy, 2)
	errorsChannel := make(chan error, 2)
	var workers sync.WaitGroup
	for index := 0; index < 2; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			claimed, err := repository.ClaimDuePolicies(ctx, now, 2, time.Minute)
			results <- claimed
			errorsChannel <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		require.NoError(t, err)
	}
	seen := make(map[string]struct{})
	for claimed := range results {
		require.Len(t, claimed, 2)
		for _, policy := range claimed {
			_, duplicate := seen[policy.ID]
			require.False(t, duplicate, policy.ID)
			seen[policy.ID] = struct{}{}
		}
	}
	require.Len(t, seen, 4)
}

func TestSchedulerRestartReclaimsExpiredLeaseWithoutLosingOccurrence(t *testing.T) {
	// Break caught: a controller crash after claim must leave next_run_at intact
	// and make the same occurrence reclaimable once the lease expires.
	ctx, database, repository, _ := openInspectionIntegration(t, "reclaim")
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-reclaim", ProjectID: "project-reclaim"}
	seedInspectionItem(t, ctx, repository, scope, now)
	policy := livePolicyFixture("policy-reclaim", scope, now.Add(-time.Minute), now)
	require.NoError(t, repository.CreatePolicy(ctx, policy))
	first, err := repository.ClaimDuePolicies(ctx, now, 1, time.Second)
	require.NoError(t, err)
	require.Len(t, first, 1)
	var persisted time.Time
	require.NoError(t, database.QueryRowContext(ctx, "SELECT next_run_at FROM inspection_policies WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, policy.ID).Scan(&persisted))
	require.Equal(t, policy.NextRunAt.UTC(), persisted.UTC())
	second, err := repository.ClaimDuePolicies(ctx, now.Add(2*time.Second), 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, second, 1)
	require.Equal(t, first[0].Claim.Occurrence, second[0].Claim.Occurrence)
	require.NotEqual(t, first[0].Claim.Token, second[0].Claim.Token)
}

func TestSchedulerDuplicateOccurrenceReturnsExistingRun(t *testing.T) {
	// Break caught: replaying a durably created occurrence after uncertain
	// controller delivery must not create a second Run, Job, or command.
	ctx, database, repository, _ := openInspectionIntegration(t, "duplicate")
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-duplicate", ProjectID: "project-duplicate"}
	item := seedInspectionItem(t, ctx, repository, scope, now)
	policy := livePolicyFixture("policy-duplicate", scope, now.Add(-time.Minute), now)
	require.NoError(t, repository.CreatePolicy(ctx, policy))
	claimed, err := repository.ClaimDuePolicies(ctx, now, 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	policy = claimed[0]
	run, targets, value, messages := liveRunFixture("first", scope, now)
	makeScheduled(&run, &value, policy)
	first, err := repository.CreateClaimedRunWithJob(ctx, policy, run, targets, value, messages)
	require.NoError(t, err)

	_, err = database.ExecContext(ctx, "UPDATE inspection_policies SET next_run_at = $1, claim_token = $2, lease_expires_at = $3 WHERE tenant_id = $4 AND project_id = $5 AND id = $6", policy.Claim.Occurrence, "claim-replay", now.Add(time.Minute), scope.TenantID, scope.ProjectID, policy.ID)
	require.NoError(t, err)
	policy.Claim.Token = "claim-replay"
	run2, targets2, value2, messages2 := liveRunFixture("second", scope, now.Add(time.Second))
	makeScheduled(&run2, &value2, policy)
	second, err := repository.CreateClaimedRunWithJob(ctx, policy, run2, targets2, value2, messages2)
	require.NoError(t, err)
	require.Equal(t, first.ID, second.ID)
	var runs, jobs, commands int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND occurrence_key = $3", scope.TenantID, scope.ProjectID, run.OccurrenceKey).Scan(&runs))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM jobs WHERE tenant_id = $1 AND project_id = $2 AND source_resource_id IN ($3, $4)", scope.TenantID, scope.ProjectID, run.ID, run2.ID).Scan(&jobs))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM command_outbox WHERE job_id IN ($1, $2)", value.ID, value2.ID).Scan(&commands))
	require.Equal(t, []int{1, 1, 1}, []int{runs, jobs, commands})
	_ = item
}

func TestInspectionReportRowsAreImmutableInPostgres(t *testing.T) {
	// Break caught: an UPDATE or DELETE of a completed report would rewrite the
	// historical conclusion after it was published.
	ctx, database, repository, _ := openInspectionIntegration(t, "report")
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-report", ProjectID: "project-report"}
	seedInspectionItem(t, ctx, repository, scope, now)
	run, targets, value, messages := liveRunFixture("report", scope, now)
	require.NoError(t, repository.CreateRunWithJob(ctx, run, targets, value, messages))
	_, err := database.ExecContext(ctx, "INSERT INTO inspection_reports (tenant_id, project_id, id, run_id, status, summary, snapshot, artifacts, generated_at) VALUES ($1, $2, $3, $4, 'completed', 'stable', '{}'::jsonb, '[]'::jsonb, $5)", scope.TenantID, scope.ProjectID, "report-1", run.ID, now)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "UPDATE inspection_reports SET summary = 'changed' WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, "report-1")
	require.ErrorContains(t, err, "immutable")
	_, err = database.ExecContext(ctx, "DELETE FROM inspection_reports WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, "report-1")
	require.ErrorContains(t, err, "immutable")
}

func TestPostgresIntegrationRepositoryReadsStayInExactScope(t *testing.T) {
	// Break caught: a parent-scoped API backed by an unscoped item, policy, run,
	// or report query can disclose another project's inspection history.
	ctx, database, repository, _ := openInspectionIntegration(t, "reads")
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-reads", ProjectID: "project-a"}
	other := platformscope.Scope{TenantID: scope.TenantID, ProjectID: "project-b"}
	seedInspectionItem(t, ctx, repository, scope, now)
	seedInspectionItem(t, ctx, repository, other, now)
	policy := livePolicyFixture("policy-shared-id", scope, now.Add(time.Hour), now)
	otherPolicy := livePolicyFixture("policy-shared-id", other, now.Add(time.Hour), now)
	require.NoError(t, repository.CreatePolicy(ctx, policy))
	require.NoError(t, repository.CreatePolicy(ctx, otherPolicy))

	items, err := repository.ListItems(ctx, scope, ItemFilter{CursorFilter: CursorFilter{Limit: 10}})
	require.NoError(t, err)
	require.Len(t, items.Items, 1)
	policies, err := repository.ListPolicies(ctx, scope, PolicyFilter{CursorFilter: CursorFilter{Limit: 10}})
	require.NoError(t, err)
	require.Len(t, policies.Items, 1)
	gotPolicy, err := repository.GetPolicy(ctx, scope, policy.ID)
	require.NoError(t, err)
	require.Equal(t, scope, gotPolicy.Scope)
	gotPolicy.Name = "updated policy"
	gotPolicy.UpdatedAt = now.Add(time.Second)
	updated, err := repository.UpdatePolicy(ctx, gotPolicy, gotPolicy.Version)
	require.NoError(t, err)
	require.Equal(t, int64(2), updated.Version)
	_, err = repository.UpdatePolicy(ctx, gotPolicy, gotPolicy.Version)
	require.ErrorIs(t, err, ErrConflict)

	run, targets, value, messages := liveRunFixture("reads", scope, now)
	require.NoError(t, repository.CreateRunWithJob(ctx, run, targets, value, messages))
	runs, err := repository.ListRuns(ctx, scope, RunFilter{CursorFilter: CursorFilter{Limit: 10}})
	require.NoError(t, err)
	require.Len(t, runs.Items, 1)
	_, err = repository.GetRun(ctx, other, run.ID)
	require.ErrorIs(t, err, ErrNotFound)

	_, err = database.ExecContext(ctx, "INSERT INTO inspection_reports (tenant_id, project_id, id, run_id, status, summary, snapshot, artifacts, generated_at) VALUES ($1, $2, $3, $4, 'completed', 'stable', '{\"healthy\":1}'::jsonb, '[]'::jsonb, $5)", scope.TenantID, scope.ProjectID, "report-reads", run.ID, now)
	require.NoError(t, err)
	report, err := repository.GetReport(ctx, scope, "report-reads")
	require.NoError(t, err)
	require.Equal(t, run.ID, report.RunID)
	reports, err := repository.ListReports(ctx, scope, ReportFilter{CursorFilter: CursorFilter{Limit: 10}})
	require.NoError(t, err)
	require.Len(t, reports.Items, 1)
	_, err = repository.GetReport(ctx, other, "report-reads")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestPostgresIntegrationServiceCreatesOneRunTargetJobAndUnsignedOutbox(t *testing.T) {
	// Break caught: unit-only construction can miss a persistence mismatch that
	// drops a target, Job row, or exact unsigned protobuf payload.
	ctx, database, repository, _ := openInspectionIntegration(t, "service")
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-service", ProjectID: "project-service"}
	seedInspectionItem(t, ctx, repository, scope, now)
	pinned, err := repository.ListItems(ctx, scope, ItemFilter{
		CursorFilter: CursorFilter{Limit: 2},
		Versions:     []PolicyItem{{ItemID: "host.cpu.utilization", Version: 1}},
	})
	require.NoError(t, err)
	require.Len(t, pinned.Items, 1)
	require.NoError(t, pinned.Items[0].Validate())
	resolver, err := NewConfiguredTargetResolver([]HostTarget{{Scope: scope, AgentID: "agent-1", DisplayName: "Agent 1", Host: "agent-1.example"}})
	require.NoError(t, err)
	ids := []string{"run-service", "job-service", "command-service", "run-duplicate-proposal", "job-duplicate-proposal", "command-duplicate-proposal"}
	service := &Service{
		Repository: repository, Targets: resolver, Now: func() time.Time { return now },
		NewID: func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil },
	}
	request := CreateRunRequest{
		Scope: scope, Selector: TargetSelector{AgentIDs: []string{"agent-1"}}, Items: []PolicyItem{{ItemID: "host.cpu.utilization", Version: 1}},
		TargetTimeout: time.Minute, MaxConcurrency: 1, IdempotencyKey: "service-key", InitiatedBy: "operator-1", RequestID: "request-service",
	}
	run, err := service.CreateRun(ctx, request)
	require.NoError(t, err)
	replayed, err := service.CreateRun(ctx, request)
	require.NoError(t, err)
	require.Equal(t, run.ID, replayed.ID)
	for table, predicate := range map[string]string{
		"inspection_runs": "id = 'run-service'", "inspection_target_runs": "run_id = 'run-service'", "jobs": "id = 'job-service'", "job_targets": "job_id = 'job-service'", "command_outbox": "job_id = 'job-service'",
	} {
		var count int
		require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE "+predicate).Scan(&count))
		require.Equal(t, 1, count, table)
	}
	var payload []byte
	require.NoError(t, database.QueryRowContext(ctx, "SELECT payload FROM command_outbox WHERE id = $1", "command-service").Scan(&payload))
	envelope := new(agentv1.CommandEnvelope)
	require.NoError(t, proto.Unmarshal(payload, envelope))
	require.True(t, proto.Equal(&agentv1.CommandEnvelope{
		AgentId: "agent-1", LeaseSeconds: 60,
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"host"}}},
	}, envelope))
}

func openInspectionIntegration(t *testing.T, suffix string) (context.Context, *sql.DB, *PostgresRepository, *job.PostgresRepository) {
	t.Helper()
	if os.Getenv("DBPILOT_CONTRACT_E2E") != "1" {
		t.Skip("set DBPILOT_CONTRACT_E2E=1 to run")
	}
	dsn := os.Getenv("DBPILOT_INSPECTION_POSTGRES_DSN")
	require.NotEmpty(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = admin.Close() })
	require.NoError(t, admin.PingContext(ctx))
	schema := fmt.Sprintf("inspection_%s_%d", suffix, time.Now().UnixNano())
	quoted := pq.QuoteIdentifier(schema)
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+quoted)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanup, "DROP SCHEMA IF EXISTS "+quoted+" CASCADE")
		require.NoError(t, cleanupErr)
	})
	database, err := sql.Open("postgres", inspectionSchemaDSN(t, dsn, schema))
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	require.NoError(t, database.PingContext(ctx))
	require.NoError(t, job.RunMigrations(ctx, database))
	require.NoError(t, RunMigrations(ctx, database))
	jobs := job.NewPostgresRepository(database)
	return ctx, database, NewPostgresRepository(database, jobs), jobs
}

func inspectionSchemaDSN(t *testing.T, dsn, schema string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func seedInspectionItem(t *testing.T, ctx context.Context, repository *PostgresRepository, scope platformscope.Scope, now time.Time) Item {
	t.Helper()
	item := builtinItem("host.cpu.utilization")
	item.Scope, item.Enabled, item.CreatedAt, item.UpdatedAt = scope, true, now, now
	require.NoError(t, repository.CreateItem(ctx, item))
	return item
}

func livePolicyFixture(id string, scope platformscope.Scope, occurrence, now time.Time) Policy {
	return Policy{
		Scope: scope, ID: id, Name: id, Enabled: true, Version: 1,
		Schedule: &Schedule{Cron: "* * * * *", Timezone: "UTC"}, NextRunAt: &occurrence,
		Items: []PolicyItem{{ItemID: "host.cpu.utilization", Version: 1}}, Selector: TargetSelector{AgentIDs: []string{"agent-1"}},
		TargetTimeout: time.Minute, MaxConcurrency: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func liveRunFixture(suffix string, scope platformscope.Scope, now time.Time) (Run, []TargetRun, job.Job, []job.OutboxMessage) {
	item := builtinItem("host.cpu.utilization")
	item.Scope, item.Enabled, item.CreatedAt, item.UpdatedAt = scope, true, now, now
	run := Run{
		Scope: scope, ID: "run-" + suffix, JobID: "job-" + suffix, Status: RunQueued, Trigger: RunTriggerManual,
		ItemSnapshot: []Item{item}, TargetCount: 1, AuditCorrelation: "inspection-run:run-" + suffix,
		IdempotencyKey: "run-key-" + suffix, InitiatedBy: "integration", RequestID: "request-" + suffix, CreatedAt: now,
	}
	commandID := "command-" + suffix
	targets := []TargetRun{{TargetID: "agent-1", AgentID: "agent-1", CommandID: commandID, DisplayName: "Agent 1", Host: "agent-1.example", Status: TargetPending}}
	timeout := now.Add(time.Minute)
	value := job.Job{
		ID: run.JobID, Type: "inspection.collect", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone,
		TargetResourceIDs: []string{"agent-1"}, InitiatedBy: "integration", SourceResource: job.ResourceReference{ResourceType: "inspection_run", ResourceID: run.ID},
		IdempotencyKey: run.IdempotencyKey, Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, TimeoutAt: &timeout,
		RequestID: run.RequestID, TraceID: run.TraceID,
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.CommandEnvelope{
		AgentId: "agent-1", LeaseSeconds: 60,
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"host"}}},
	})
	if err != nil {
		panic(err)
	}
	messages := []job.OutboxMessage{{ID: commandID, Scope: scope, JobID: value.ID, TargetID: "agent-1", Type: "agent.command", Payload: payload, AvailableAt: now, CreatedAt: now}}
	return run, targets, value, messages
}

func makeScheduled(run *Run, value *job.Job, policy Policy) {
	run.PolicyID, run.PolicyVersion, run.Trigger = policy.ID, policy.Version, RunTriggerScheduled
	run.OccurrenceKey = scheduledOccurrenceKey(policy, policy.Claim.Occurrence)
	run.ScheduledFor = utcCopy(&policy.Claim.Occurrence)
	run.PolicySnapshot = clonePolicy(&policy)
	run.IdempotencyKey = run.OccurrenceKey
	value.IdempotencyKey = run.OccurrenceKey
}
