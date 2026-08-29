package inspection

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/audit"
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

func TestPostgresIntegrationWorkerClaimersReceiveDisjointRuns(t *testing.T) {
	// Break caught: collection/evaluation/report repair must use the same
	// disjoint SKIP LOCKED semantics as scheduling across control-plane replicas.
	ctx, _, repository, _ := openInspectionIntegration(t, "worker-claims")
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := platformscope.Scope{TenantID: "tenant-worker-claims", ProjectID: "project-worker-claims"}
	seedInspectionItem(t, ctx, repository, scope, now)
	for index := 0; index < 4; index++ {
		run, targets, value, messages := liveRunFixture(fmt.Sprintf("worker-%d", index), scope, now.Add(time.Duration(index)*time.Microsecond))
		require.NoError(t, repository.CreateRunWithJob(ctx, run, targets, value, messages))
	}

	start := make(chan struct{})
	results := make(chan []RunClaim, 2)
	errorsChannel := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			claimed, err := repository.ClaimRuns(ctx, now.Add(time.Second), 2, time.Minute)
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
		for _, claim := range claimed {
			_, duplicate := seen[claim.Detail.Run.ID]
			require.False(t, duplicate, claim.Detail.Run.ID)
			seen[claim.Detail.Run.ID] = struct{}{}
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

func TestSchedulerLongOutageCreatesOnlyLatestOccurrenceAndAdvancesPastNow(t *testing.T) {
	ctx, database, repository, _ := openInspectionIntegration(t, "coalesce-outage")
	now := time.Date(2026, 8, 29, 12, 34, 45, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-coalesce", ProjectID: "project-coalesce"}
	seedInspectionItem(t, ctx, repository, scope, now)
	stale := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	policy := livePolicyFixture("policy-coalesce", scope, stale, now)
	require.NoError(t, repository.CreatePolicy(ctx, policy))
	targets, err := NewConfiguredTargetResolver([]HostTarget{{Scope: scope, AgentID: "agent-1", DisplayName: "Agent 1", Host: "agent-1.example", Labels: map[string]string{}}})
	require.NoError(t, err)
	ids := []string{"run-coalesced", "job-coalesced", "command-coalesced"}
	service := Service{
		Repository: repository, Targets: targets, Now: func() time.Time { return now }, ClaimLimit: 1, ClaimLease: time.Minute,
		NewID: func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil },
	}

	created, err := service.ScheduleDue(ctx, now)
	require.NoError(t, err)
	require.Equal(t, 1, created)
	latest := time.Date(2026, 8, 29, 12, 34, 0, 0, time.UTC)
	next := latest.Add(time.Minute)
	var runCount int
	var scheduledFor, nextRunAt time.Time
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*), min(scheduled_for) FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND policy_id = $3", scope.TenantID, scope.ProjectID, policy.ID).Scan(&runCount, &scheduledFor))
	require.Equal(t, 1, runCount)
	require.Equal(t, latest, scheduledFor.UTC())
	require.NoError(t, database.QueryRowContext(ctx, "SELECT next_run_at FROM inspection_policies WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, policy.ID).Scan(&nextRunAt))
	require.Equal(t, next, nextRunAt.UTC())
	created, err = service.ScheduleDue(ctx, now)
	require.NoError(t, err)
	require.Zero(t, created)
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
	coalescePolicyClaim(t, &policy, now)
	run, targets, value, messages := liveRunFixture("first", scope, now)
	makeScheduled(&run, &value, policy)
	first, err := repository.CreateClaimedRunWithJob(ctx, policy, run, targets, value, messages)
	require.NoError(t, err)

	_, err = database.ExecContext(ctx, "UPDATE inspection_policies SET next_run_at = $1, claim_token = $2, lease_expires_at = $3 WHERE tenant_id = $4 AND project_id = $5 AND id = $6", policy.Claim.ClaimedOccurrence, "claim-replay", now.Add(time.Minute), scope.TenantID, scope.ProjectID, policy.ID)
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

func TestPostgresIntegrationReportFinalizationCrashRepairsAuditWithoutRepeatingWork(t *testing.T) {
	// Break caught: a crash after report finalization but before Audit.RecordOnce
	// must leave one immutable report/finding plus repairable Audit evidence.
	ctx, database, repository, _ := openInspectionIntegration(t, "report-audit-repair")
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := platformscope.Scope{TenantID: "tenant-report-repair", ProjectID: "project-report-repair"}
	item := seedInspectionItem(t, ctx, repository, scope, now)
	run, targets, value, messages := liveRunFixture("report-repair", scope, now)
	require.NoError(t, repository.CreateRunWithJob(ctx, run, targets, value, messages))

	claims, err := repository.ClaimRuns(ctx, now.Add(time.Second), 1, time.Minute)
	require.NoError(t, err)
	require.Len(t, claims, 1)
	claim, err := repository.MarkCollecting(ctx, claims[0], now.Add(time.Second))
	require.NoError(t, err)
	claim, err = repository.BeginEvaluation(ctx, claim)
	require.NoError(t, err)
	targets[0].Status = TargetSucceeded
	targets[0].ObservedAt = now.Add(2 * time.Second)
	finding := Finding{
		ID: "inspection-finding-report-repair", Scope: scope, RunID: run.ID, TargetID: targets[0].TargetID,
		ItemID: item.ID, ItemVersion: item.Version, Level: LevelHealthy, ObservedAt: targets[0].ObservedAt,
		Evidence: map[string]string{"metric": item.MetricRule.MetricName, "value": "12", "samples": "1"}, Summary: "healthy",
	}
	claim, err = repository.SaveEvaluation(ctx, claim, targets, []Finding{finding}, now.Add(3*time.Second))
	require.NoError(t, err)
	report := ReportSnapshot{
		Scope: scope, ID: "inspection-report-" + run.ID, RunID: run.ID, Status: ReportCompleted, Summary: "healthy",
		Snapshot:    []byte(`{"report_id":"inspection-report-run-report-repair","run_id":"run-report-repair"}`),
		Artifacts:   []job.ArtifactReference{{ArtifactID: "inspection-report-run-report-repair.json", Kind: "inspection-report"}, {ArtifactID: "inspection-report-run-report-repair.html", Kind: "inspection-report"}},
		GeneratedAt: claim.ReportGeneratedAt, CreatedAt: claim.ReportGeneratedAt,
	}
	event := audit.Event{
		Scope: scope, OccurredAt: claim.ReportGeneratedAt, Action: "inspection.report.completed",
		Actor: audit.Actor{Type: "system", ID: "inspection-worker"}, Resource: audit.Resource{Type: "inspection_report", ID: report.ID},
		Result: "completed", RequestID: run.RequestID, JobID: run.JobID, DedupeKey: run.AuditCorrelation + ":report",
		Detail: map[string]any{"run_id": run.ID, "report_id": report.ID, "status": "completed"},
	}
	_, err = repository.FinalizeReport(ctx, claim, report, RunCompleted, event, now.Add(4*time.Second))
	require.NoError(t, err)

	var reports, findings int
	var status RunStatus
	var pending bool
	var persistedDedupe string
	require.NoError(t, database.QueryRowContext(ctx, "SELECT status, report_audit_pending, report_audit_dedupe_key FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, run.ID).Scan(&status, &pending, &persistedDedupe))
	require.Equal(t, RunCompleted, status)
	require.True(t, pending)
	require.Equal(t, event.DedupeKey, persistedDedupe)
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM inspection_reports WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3", scope.TenantID, scope.ProjectID, run.ID).Scan(&reports))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM inspection_findings WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3", scope.TenantID, scope.ProjectID, run.ID).Scan(&findings))
	require.Equal(t, []int{1, 1}, []int{reports, findings})

	failingAudit := &memoryAuditRecorder{err: errors.New("audit unavailable")}
	worker := &Worker{Runs: repository, Jobs: &memoryJobReader{}, Evaluator: &Evaluator{}, Artifacts: &memoryArtifactWriter{}, Audit: failingAudit}
	processed, err := worker.Process(ctx, now.Add(5*time.Second), 1)
	require.ErrorContains(t, err, "audit unavailable")
	require.Equal(t, 1, processed)
	require.NoError(t, database.QueryRowContext(ctx, "SELECT report_audit_pending FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, run.ID).Scan(&pending))
	require.True(t, pending)

	recordedAudit := &memoryAuditRecorder{}
	worker.Audit = recordedAudit
	processed, err = worker.Process(ctx, now.Add(6*time.Second), 1)
	require.NoError(t, err)
	require.Equal(t, 1, processed)
	require.Len(t, recordedAudit.events, 1)
	require.Equal(t, event.DedupeKey, recordedAudit.events[0].DedupeKey)
	require.NoError(t, database.QueryRowContext(ctx, "SELECT report_audit_pending FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, run.ID).Scan(&pending))
	require.False(t, pending)
	require.Empty(t, worker.Artifacts.(*memoryArtifactWriter).values)
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM inspection_reports WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3", scope.TenantID, scope.ProjectID, run.ID).Scan(&reports))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM inspection_findings WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3", scope.TenantID, scope.ProjectID, run.ID).Scan(&findings))
	require.Equal(t, []int{1, 1}, []int{reports, findings}, "Audit repair must not repeat evaluation or reporting")
	t.Logf("crash repair evidence: run=%s reports=%d findings=%d audit_pending=%t audit_events_replayed=%d", run.ID, reports, findings, pending, len(recordedAudit.events))
}

func TestPostgresIntegrationFullBuiltinCatalogHydratesOneAcceptedHostSnapshot(t *testing.T) {
	// Break caught: the worker must reconstruct every built-in metadata/log
	// Observation from the same accepted host snapshot, not just metric rules.
	ctx, database, repository, _ := openInspectionIntegration(t, "full-host-snapshot")
	now := time.Now().UTC().Truncate(time.Microsecond)
	createdAt := now.Add(-2 * time.Second)
	sampledAt := now.Add(-time.Second)
	deadline := now.Add(30 * time.Second)
	scope := platformscope.Scope{TenantID: "tenant-full-snapshot", ProjectID: "project-full-snapshot"}
	agentID := "agent-full-snapshot"
	samples := fullBuiltinHostSamples(scope, agentID, sampledAt)
	accepted, err := alert.NewPostgresRepository(database).AppendBatch(ctx, agentID, "batch-full-snapshot", samples)
	require.NoError(t, err)
	require.True(t, accepted)
	items := BuiltinHostItems()
	evidence, err := repository.LoadHostSnapshot(ctx, scope, agentID, items, createdAt, deadline, maxTargetObservations)
	require.NoError(t, err)
	require.True(t, evidence.Complete)
	target := TargetRun{
		TargetID: agentID, AgentID: agentID, CommandID: "command-full-snapshot", Status: TargetEvaluating,
		DisplayName: "Full snapshot", Host: "db-a", AdvertisedSources: []SourceType{SourceMetric, SourceMetadata, SourceLogSummary},
		ObservedAt: evidence.SampledAt, Observations: evidence.Observations,
	}
	snapshot := RunSnapshot{ID: "run-full-snapshot", Scope: scope, CreatedAt: createdAt, Items: items, Targets: []TargetRun{target}}
	findings, err := (&Evaluator{Evidence: repository, Now: func() time.Time { return deadline }}).EvaluateTarget(ctx, snapshot, target)
	require.NoError(t, err)
	require.Len(t, findings, len(items))
	for _, finding := range findings {
		require.NotEqual(t, LevelMissingData, finding.Level, finding.ItemID)
		require.NotEqual(t, LevelUnsupported, finding.Level, finding.ItemID)
	}
	require.Equal(t, LevelWarning, findingByItem(t, findings, "host.log.error_summary").Level)
	t.Logf("full host snapshot evidence: samples=%d hydrated=%d findings=%d sampled_at=%s", len(samples), len(evidence.Observations), len(findings), evidence.SampledAt.Format(time.RFC3339Nano))
}

func TestPostgresIntegrationEvidenceFenceRejectsUnrelatedWrongSourceAndLateBackdatedSamples(t *testing.T) {
	// Break caught: source identity, Run sample fence, and server accepted_at are
	// independent requirements; satisfying only one must remain missing_data.
	ctx, database, repository, _ := openInspectionIntegration(t, "evidence-fence")
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := platformscope.Scope{TenantID: "tenant-evidence-fence", ProjectID: "project-evidence-fence"}
	item := builtinItem("host.cpu.utilization")
	baseLabels := hostSnapshotLabels("inspection-host-snapshot")

	createdAt := now.Add(-time.Second)
	deadline := now.Add(30 * time.Second)
	unrelated := []alert.MetricSample{
		hostMetricSample(scope, "agent-unrelated", "dbpilot.inspection.host.marker", 1, now, baseLabels),
		hostMetricSample(scope, "agent-unrelated", item.MetricRule.MetricName, 12, createdAt.Add(-time.Second), baseLabels),
	}
	accepted, err := alert.NewPostgresRepository(database).AppendBatch(ctx, "agent-unrelated", "batch-unrelated", unrelated)
	require.NoError(t, err)
	require.True(t, accepted)
	evidence, err := repository.LoadHostSnapshot(ctx, scope, "agent-unrelated", []Item{item}, createdAt, deadline, 32)
	require.NoError(t, err)
	require.False(t, evidence.Complete, "fresh unrelated source metric plus stale required metric must not satisfy completeness")

	wrongLabels := hostSnapshotLabels("other-source")
	wrongSource := hostMetricSample(scope, "agent-wrong-source", item.MetricRule.MetricName, 99, now, wrongLabels)
	accepted, err = alert.NewPostgresRepository(database).AppendBatch(ctx, "agent-wrong-source", "batch-wrong-source", []alert.MetricSample{wrongSource})
	require.NoError(t, err)
	require.True(t, accepted)
	observations, err := repository.Samples(ctx, scope, "agent-wrong-source", []string{item.MetricRule.MetricName}, createdAt, deadline, 32)
	require.NoError(t, err)
	require.Empty(t, observations, "same-name metric from a different source must not evaluate")
	require.Equal(t, LevelMissingData, evaluatePersistedMetric(t, ctx, repository, scope, "agent-wrong-source", item, createdAt, now).Level)

	lateCreatedAt := now.Add(-10 * time.Second)
	lateDeadline := now.Add(-2 * time.Second)
	lateSample := hostMetricSample(scope, "agent-late", item.MetricRule.MetricName, 99, now.Add(-5*time.Second), baseLabels)
	accepted, err = alert.NewPostgresRepository(database).AppendBatch(ctx, "agent-late", "batch-late", []alert.MetricSample{lateSample})
	require.NoError(t, err)
	require.True(t, accepted)
	observations, err = repository.Samples(ctx, scope, "agent-late", []string{item.MetricRule.MetricName}, lateCreatedAt, lateDeadline, 32)
	require.NoError(t, err)
	require.Empty(t, observations, "late-ingested backdated metric must fail the accepted_at deadline")
	require.Equal(t, LevelMissingData, evaluatePersistedMetric(t, ctx, repository, scope, "agent-late", item, lateCreatedAt, lateDeadline).Level)
}

func TestPostgresIntegrationHistoricalRowsRejectMutationWhileLifecycleUpdatesRemainPossible(t *testing.T) {
	// Break caught: direct SQL must not rewrite item/finding decisions or Run
	// identity/snapshots, but workers still need to advance Run/Target status.
	ctx, database, repository, _ := openInspectionIntegration(t, "history-guards")
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-history", ProjectID: "project-history"}
	item := seedInspectionItem(t, ctx, repository, scope, now)
	run, targets, value, messages := liveRunFixture("history", scope, now)
	require.NoError(t, repository.CreateRunWithJob(ctx, run, targets, value, messages))

	_, err := database.ExecContext(ctx, "UPDATE inspection_target_runs SET status = 'collecting' WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND target_id = $4", scope.TenantID, scope.ProjectID, run.ID, targets[0].TargetID)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "UPDATE inspection_runs SET status = 'collecting', started_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND id = $4", now.Add(time.Second), scope.TenantID, scope.ProjectID, run.ID)
	require.NoError(t, err)
	var targetStatus, runStatus string
	require.NoError(t, database.QueryRowContext(ctx, "SELECT status FROM inspection_target_runs WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND target_id = $4", scope.TenantID, scope.ProjectID, run.ID, targets[0].TargetID).Scan(&targetStatus))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT status FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, run.ID).Scan(&runStatus))
	require.Equal(t, []string{"collecting", "collecting"}, []string{targetStatus, runStatus})

	_, err = database.ExecContext(ctx, "UPDATE inspection_items SET enabled = FALSE WHERE tenant_id = $1 AND project_id = $2 AND item_id = $3 AND version = $4", scope.TenantID, scope.ProjectID, item.ID, item.Version)
	require.ErrorContains(t, err, "immutable")
	_, err = database.ExecContext(ctx, "DELETE FROM inspection_items WHERE tenant_id = $1 AND project_id = $2 AND item_id = $3 AND version = $4", scope.TenantID, scope.ProjectID, item.ID, item.Version)
	require.ErrorContains(t, err, "immutable")

	_, err = database.ExecContext(ctx, "INSERT INTO inspection_findings (tenant_id, project_id, id, run_id, target_id, item_id, item_version, level, observed_at, evidence) VALUES ($1, $2, $3, $4, $5, $6, $7, 'healthy', $8, '{}'::jsonb)", scope.TenantID, scope.ProjectID, "finding-history", run.ID, targets[0].TargetID, item.ID, item.Version, now)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "UPDATE inspection_findings SET level = 'critical' WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, "finding-history")
	require.ErrorContains(t, err, "immutable")
	_, err = database.ExecContext(ctx, "DELETE FROM inspection_findings WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, "finding-history")
	require.ErrorContains(t, err, "immutable")

	_, err = database.ExecContext(ctx, "UPDATE inspection_runs SET item_snapshot = '[]'::jsonb WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, run.ID)
	require.ErrorContains(t, err, "immutable")
	_, err = database.ExecContext(ctx, "UPDATE inspection_runs SET policy_snapshot = '{}'::jsonb WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, run.ID)
	require.ErrorContains(t, err, "immutable")
}

func TestPostgresIntegrationTargetIdentityAndHistoricalRunDeletionAreGuarded(t *testing.T) {
	// Break caught: direct SQL must not retarget a persisted command, replace a
	// target snapshot, delete a TargetRun, or cascade-delete a historical Run.
	ctx, database, repository, _ := openInspectionIntegration(t, "target-guards")
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-target-guards", ProjectID: "project-target-guards"}
	seedInspectionItem(t, ctx, repository, scope, now)
	run, targets, value, messages := liveRunFixture("target-guards", scope, now)
	require.NoError(t, repository.CreateRunWithJob(ctx, run, targets, value, messages))

	observed := now.Add(time.Second)
	_, err := database.ExecContext(ctx, "UPDATE inspection_target_runs SET status = 'collecting', error_code = 'collection_pending', observed_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND run_id = $4 AND target_id = $5", observed, scope.TenantID, scope.ProjectID, run.ID, targets[0].TargetID)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "UPDATE inspection_runs SET status = 'collecting', completed_target_count = 0, failed_target_count = 0, started_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND id = $4", observed, scope.TenantID, scope.ProjectID, run.ID)
	require.NoError(t, err)
	var targetStatus, errorCode, runStatus string
	var observedAt time.Time
	require.NoError(t, database.QueryRowContext(ctx, "SELECT status, error_code, observed_at FROM inspection_target_runs WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND target_id = $4", scope.TenantID, scope.ProjectID, run.ID, targets[0].TargetID).Scan(&targetStatus, &errorCode, &observedAt))
	require.NoError(t, database.QueryRowContext(ctx, "SELECT status FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, run.ID).Scan(&runStatus))
	require.Equal(t, []string{"collecting", "collection_pending", "collecting"}, []string{targetStatus, errorCode, runStatus})
	require.Equal(t, observed, observedAt.UTC())

	for name, statement := range map[string]string{
		"target identity":  "UPDATE inspection_target_runs SET target_id = 'agent-other' WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND target_id = $4",
		"agent identity":   "UPDATE inspection_target_runs SET agent_id = 'agent-other' WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND target_id = $4",
		"command identity": "UPDATE inspection_target_runs SET command_id = 'command-other' WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND target_id = $4",
		"target snapshot":  "UPDATE inspection_target_runs SET target_snapshot = '{}'::jsonb WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND target_id = $4",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := database.ExecContext(ctx, statement, scope.TenantID, scope.ProjectID, run.ID, targets[0].TargetID)
			require.ErrorContains(t, err, "identity and snapshot are immutable")
		})
	}
	_, err = database.ExecContext(ctx, "DELETE FROM inspection_target_runs WHERE tenant_id = $1 AND project_id = $2 AND run_id = $3 AND target_id = $4", scope.TenantID, scope.ProjectID, run.ID, targets[0].TargetID)
	require.ErrorContains(t, err, "target runs cannot be deleted")
	_, err = database.ExecContext(ctx, "DELETE FROM inspection_runs WHERE tenant_id = $1 AND project_id = $2 AND id = $3", scope.TenantID, scope.ProjectID, run.ID)
	require.ErrorContains(t, err, "inspection runs cannot be deleted")
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

func TestPostgresIntegrationRunIdempotencyScopesActorOperationAndRejectsFingerprintConflict(t *testing.T) {
	ctx, _, repository, _ := openInspectionIntegration(t, "run-idempotency-v2")
	now := time.Now().UTC().Truncate(time.Microsecond)
	scope := platformscope.Scope{TenantID: "tenant-idempotency-v2", ProjectID: "project-idempotency-v2"}
	seedInspectionItem(t, ctx, repository, scope, now)
	create := func(suffix, actor, operation, key, fingerprint string) (Run, error) {
		run, targets, value, messages := liveRunFixture(suffix, scope, now)
		run.IdempotencyActor, run.IdempotencyOperation, run.IdempotencyKey, run.IdempotencyFingerprint = actor, operation, key, fingerprint
		run.InitiatedBy, value.InitiatedBy = actor, actor
		value.IdempotencyKey = "inspection-run:" + run.ID
		return run, repository.CreateRunWithJob(ctx, run, targets, value, messages)
	}
	fingerprintA := "sha256:" + strings.Repeat("a", 64)
	fingerprintB := "sha256:" + strings.Repeat("b", 64)
	first, err := create("idem-first", "operator-a", "CreateInspectionRun", "same-key", fingerprintA)
	require.NoError(t, err)
	second, err := create("idem-actor", "operator-b", "CreateInspectionRun", "same-key", fingerprintA)
	require.NoError(t, err)
	third, err := create("idem-operation", "operator-a", "RunInspectionPolicy", "same-key", fingerprintA)
	require.NoError(t, err)
	_, err = create("idem-conflict", "operator-a", "CreateInspectionRun", "same-key", fingerprintB)
	require.ErrorIs(t, err, ErrIdempotencyConflict)

	for _, expected := range []Run{first, second, third} {
		found, err := repository.GetRunByIdempotency(ctx, scope, RunIdempotency{Actor: expected.IdempotencyActor, Operation: expected.IdempotencyOperation, Key: expected.IdempotencyKey, Fingerprint: expected.IdempotencyFingerprint})
		require.NoError(t, err)
		require.Equal(t, expected.ID, found.ID)
	}
}

func TestPostgresIntegrationRetryRunPreservesOriginalScheduledSnapshots(t *testing.T) {
	// Break caught: a retry issued after policy/inventory changes must repeat the
	// original pinned operation, not silently adopt the latest configuration.
	ctx, database, repository, _ := openInspectionIntegration(t, "retry-snapshot")
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-retry", ProjectID: "project-retry"}
	seedInspectionItem(t, ctx, repository, scope, now)
	policy := livePolicyFixture("policy-retry", scope, now.Add(-time.Minute), now)
	policy.Name = "original scheduled policy"
	require.NoError(t, repository.CreatePolicy(ctx, policy))
	originalResolver, err := NewConfiguredTargetResolver([]HostTarget{{
		Scope: scope, AgentID: "agent-1", DisplayName: "Original Agent", Host: "original.example",
		Labels: map[string]string{"environment": "original"}, Capabilities: []string{"host.metrics"}, AdvertisedSources: []SourceType{SourceMetric},
	}})
	require.NoError(t, err)
	originalIDs := []string{"run-original", "job-original", "command-original"}
	originalService := &Service{
		Repository: repository, Targets: originalResolver, Now: func() time.Time { return now },
		NewID:      func() (string, error) { id := originalIDs[0]; originalIDs = originalIDs[1:]; return id, nil },
		ClaimLimit: 1, ClaimLease: time.Minute,
	}
	count, err := originalService.ScheduleDue(ctx, now)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	original, err := repository.GetRun(ctx, scope, "run-original")
	require.NoError(t, err)
	require.NotNil(t, original.Run.PolicySnapshot)
	require.Equal(t, "original scheduled policy", original.Run.PolicySnapshot.Name)

	current, err := repository.GetPolicy(ctx, scope, policy.ID)
	require.NoError(t, err)
	current.Name = "later policy"
	current.UpdatedAt = now.Add(time.Second)
	_, err = repository.UpdatePolicy(ctx, current, current.Version)
	require.NoError(t, err)
	_, err = database.ExecContext(ctx, "UPDATE inspection_runs SET status = 'failed', finished_at = $1 WHERE tenant_id = $2 AND project_id = $3 AND id = $4", now.Add(time.Minute), scope.TenantID, scope.ProjectID, original.Run.ID)
	require.NoError(t, err)

	changedResolver, err := NewConfiguredTargetResolver([]HostTarget{{
		Scope: scope, AgentID: "agent-1", DisplayName: "Changed Agent", Host: "changed.example",
		Labels: map[string]string{"environment": "changed"}, Capabilities: []string{"changed.capability"}, AdvertisedSources: []SourceType{SourceMetadata},
	}})
	require.NoError(t, err)
	retryIDs := []string{"run-retry", "job-retry", "command-retry"}
	retryService := &Service{
		Repository: repository, Targets: changedResolver, Now: func() time.Time { return now.Add(2 * time.Minute) },
		NewID: func() (string, error) { id := retryIDs[0]; retryIDs = retryIDs[1:]; return id, nil },
	}
	retry, err := retryService.RetryRun(ctx, scope, original.Run.ID, "retry-snapshot-key", "operator-2", "request-retry-snapshot", "trace-retry-snapshot", RunIdempotency{}, "")
	require.NoError(t, err)
	require.Equal(t, "run-original", retry.RetryOfRunID)
	require.NotEqual(t, original.Run.JobID, retry.JobID)
	require.NotNil(t, retry.PolicySnapshot)
	require.Equal(t, "original scheduled policy", retry.PolicySnapshot.Name)
	retryDetail, err := repository.GetRun(ctx, scope, retry.ID)
	require.NoError(t, err)
	require.Equal(t, original.Run.ItemSnapshot, retryDetail.Run.ItemSnapshot)
	require.NotEqual(t, original.Targets[0].CommandID, retryDetail.Targets[0].CommandID)
	require.Equal(t, "original.example", retryDetail.Targets[0].Host)
	require.Equal(t, "original", retryDetail.Targets[0].Labels["environment"])
}

func TestPostgresIntegrationPaginationUsesLimitPlusOneAndUniqueDescendingCursors(t *testing.T) {
	// Break caught: equal timestamps and multiple versions must cross page
	// boundaries without duplication, omission, or a false More flag.
	ctx, database, repository, _ := openInspectionIntegration(t, "pagination")
	now := time.Date(2026, 8, 28, 8, 0, 0, 123456789, time.UTC)
	databaseCreated := time.Date(2026, 8, 28, 8, 0, 0, 123457000, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-pagination", ProjectID: "project-pagination"}
	for version := 1; version <= 3; version++ {
		require.NoError(t, repository.CreateItem(ctx, paginationItemFixture(scope, version, now)))
	}
	itemFirst, err := repository.ListItems(ctx, scope, ItemFilter{CursorFilter: CursorFilter{Limit: 2}})
	require.NoError(t, err)
	require.Equal(t, []int{3, 2}, []int{itemFirst.Items[0].Version, itemFirst.Items[1].Version})
	require.Equal(t, []time.Time{databaseCreated, databaseCreated}, []time.Time{itemFirst.Items[0].CreatedAt, itemFirst.Items[1].CreatedAt})
	require.True(t, itemFirst.More)
	require.NotEmpty(t, itemFirst.NextCursor)
	itemSecond, err := repository.ListItems(ctx, scope, ItemFilter{CursorFilter: CursorFilter{Cursor: itemFirst.NextCursor, Limit: 2}})
	require.NoError(t, err)
	require.Equal(t, []int{1}, []int{itemSecond.Items[0].Version})
	require.Equal(t, databaseCreated, itemSecond.Items[0].CreatedAt)
	require.False(t, itemSecond.More)
	require.Empty(t, itemSecond.NextCursor)

	for _, id := range []string{"policy-c", "policy-b", "policy-a"} {
		policy := livePolicyFixture(id, scope, now.Add(time.Hour), now)
		policy.Items = []PolicyItem{{ItemID: "custom.pagination.utilization", Version: 1}}
		require.NoError(t, repository.CreatePolicy(ctx, policy))
	}
	policyFirst, err := repository.ListPolicies(ctx, scope, PolicyFilter{CursorFilter: CursorFilter{Limit: 2}})
	require.NoError(t, err)
	require.Equal(t, []string{"policy-c", "policy-b"}, []string{policyFirst.Items[0].ID, policyFirst.Items[1].ID})
	require.True(t, policyFirst.More)
	policySecond, err := repository.ListPolicies(ctx, scope, PolicyFilter{CursorFilter: CursorFilter{Cursor: policyFirst.NextCursor, Limit: 2}})
	require.NoError(t, err)
	require.Equal(t, []string{"policy-a"}, []string{policySecond.Items[0].ID})
	require.False(t, policySecond.More)

	runsByID := make(map[string]Run)
	for _, suffix := range []string{"page-c", "page-b", "page-a"} {
		run, targets, value, messages := liveRunFixture(suffix, scope, now)
		require.NoError(t, repository.CreateRunWithJob(ctx, run, targets, value, messages))
		runsByID[run.ID] = run
	}
	runFirst, err := repository.ListRuns(ctx, scope, RunFilter{CursorFilter: CursorFilter{Limit: 2}})
	require.NoError(t, err)
	require.Equal(t, []string{"run-page-c", "run-page-b"}, []string{runFirst.Items[0].ID, runFirst.Items[1].ID})
	require.True(t, runFirst.More)
	runSecond, err := repository.ListRuns(ctx, scope, RunFilter{CursorFilter: CursorFilter{Cursor: runFirst.NextCursor, Limit: 2}})
	require.NoError(t, err)
	require.Equal(t, []string{"run-page-a"}, []string{runSecond.Items[0].ID})
	require.False(t, runSecond.More)

	for _, suffix := range []string{"c", "b", "a"} {
		run := runsByID["run-page-"+suffix]
		_, err := database.ExecContext(ctx, "INSERT INTO inspection_reports (tenant_id, project_id, id, run_id, status, summary, snapshot, artifacts, generated_at) VALUES ($1, $2, $3, $4, 'completed', 'stable', '{}'::jsonb, '[]'::jsonb, $5)", scope.TenantID, scope.ProjectID, "report-"+suffix, run.ID, now)
		require.NoError(t, err)
	}
	reportFirst, err := repository.ListReports(ctx, scope, ReportFilter{CursorFilter: CursorFilter{Limit: 2}})
	require.NoError(t, err)
	require.Equal(t, []string{"report-c", "report-b"}, []string{reportFirst.Items[0].ID, reportFirst.Items[1].ID})
	require.True(t, reportFirst.More)
	reportSecond, err := repository.ListReports(ctx, scope, ReportFilter{CursorFilter: CursorFilter{Cursor: reportFirst.NextCursor, Limit: 2}})
	require.NoError(t, err)
	require.Equal(t, []string{"report-a"}, []string{reportSecond.Items[0].ID})
	require.False(t, reportSecond.More)
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
	require.NoError(t, alert.RunMigrations(ctx, database))
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

func paginationItemFixture(scope platformscope.Scope, version int, now time.Time) Item {
	return Item{
		Scope: scope, ID: "custom.pagination.utilization", Version: version, Name: "Pagination item", Category: "host",
		ScopeType: ScopeHost, SourceType: SourceMetric, Enabled: true,
		MetricRule:       &MetricRule{MetricName: "system.pagination.utilization", Labels: map[string]string{}, Window: 5 * time.Minute, Aggregation: AggregationLatest, Operator: OperatorGTE, WarningThreshold: 80, CriticalThreshold: 90},
		EvidenceSelector: []string{"value"}, CreatedAt: now, UpdatedAt: now,
	}
}

func liveRunFixture(suffix string, scope platformscope.Scope, now time.Time) (Run, []TargetRun, job.Job, []job.OutboxMessage) {
	item := builtinItem("host.cpu.utilization")
	item.Scope, item.Enabled, item.CreatedAt, item.UpdatedAt = scope, true, now, now
	run := Run{
		Scope: scope, ID: "run-" + suffix, JobID: "job-" + suffix, Status: RunQueued, Trigger: RunTriggerManual,
		ItemSnapshot: []Item{item}, TargetCount: 1, AuditCorrelation: "inspection-run:run-" + suffix,
		IdempotencyKey: "run-key-" + suffix, IdempotencyActor: "integration", IdempotencyOperation: "CreateInspectionRun", IdempotencyFingerprint: "sha256:" + strings.Repeat("a", 64),
		InitiatedBy: "integration", RequestID: "request-" + suffix,
		TargetTimeout: time.Minute, MaxConcurrency: 1, CreatedAt: now,
	}
	commandID := "command-" + suffix
	targets := []TargetRun{{TargetID: "agent-1", AgentID: "agent-1", CommandID: commandID, DisplayName: "Agent 1", Host: "agent-1.example", Status: TargetPending}}
	timeout := now.Add(time.Minute)
	value := job.Job{
		ID: run.JobID, Type: "inspection.collect", Scope: scope, Status: job.StatusQueued, Outcome: job.OutcomeNone,
		TargetResourceIDs: []string{"agent-1"}, InitiatedBy: "integration", SourceResource: job.ResourceReference{ResourceType: "inspection_run", ResourceID: run.ID},
		IdempotencyKey: run.IdempotencyKey, Version: 1, Progress: job.Progress{TotalTargets: 1}, Artifacts: []job.ArtifactReference{}, CreatedAt: now, TimeoutAt: &timeout,
		TargetTimeout: time.Minute, MaxConcurrency: 1,
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

func coalescePolicyClaim(t *testing.T, policy *Policy, now time.Time) {
	t.Helper()
	require.NotNil(t, policy)
	require.NotNil(t, policy.Claim)
	claimed := policy.Claim.Occurrence.UTC()
	latest, next, err := CoalescedScheduledOccurrences(*policy.Schedule, claimed, now.UTC())
	require.NoError(t, err)
	policy.Claim.ClaimedOccurrence = claimed
	policy.Claim.Occurrence = latest
	policy.Claim.NextOccurrence = next
}

func fullBuiltinHostSamples(scope platformscope.Scope, agentID string, sampledAt time.Time) []alert.MetricSample {
	values := map[string]float64{
		"system.cpu.utilization":                                       12,
		"system.cpu.load_average.1m_per_cpu":                           0.5,
		"system.memory.utilization":                                    22,
		"system.swap.utilization":                                      3,
		"system.filesystem.utilization":                                40,
		"system.filesystem.inode_utilization":                          30,
		"dbpilot.inspection.host.agent.heartbeat_age_seconds":          0,
		"dbpilot.inspection.host.metric.age_seconds":                   0,
		"dbpilot.inspection.host.spool.utilization":                    10,
		"dbpilot.inspection.host.log.summary_available":                1,
		"dbpilot.inspection.host.oom.count":                            0,
		"dbpilot.inspection.host.time.synchronization_available":       1,
		"dbpilot.inspection.host.time.synchronized":                    1,
		"dbpilot.inspection.host.database.process_allowlist_available": 1,
		"dbpilot.inspection.host.database.required_process_count":      2,
		"dbpilot.inspection.host.log.warning_count":                    1,
		"dbpilot.inspection.host.log.error_count":                      0,
		"dbpilot.inspection.host.log.critical_count":                   0,
	}
	labels := hostSnapshotLabels(hostSnapshotSourceID)
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]alert.MetricSample, 0, len(names))
	for _, name := range names {
		result = append(result, hostMetricSample(scope, agentID, name, values[name], sampledAt, labels))
	}
	return result
}

func hostMetricSample(scope platformscope.Scope, agentID, name string, value float64, sampledAt time.Time, labels map[string]string) alert.MetricSample {
	cloned := make(map[string]string, len(labels))
	for key, item := range labels {
		cloned[key] = item
	}
	return alert.MetricSample{Scope: alert.Scope{TenantID: scope.TenantID, ProjectID: scope.ProjectID}, AgentID: agentID, Name: name, Labels: cloned, Value: value, SampledAt: sampledAt}
}

func hostSnapshotLabels(source string) map[string]string {
	return map[string]string{"instance": "inspection-host-snapshot", "component": "inspection-host-snapshot", "role": "collector", "host": "db-a", "dbpilot_source_id": source}
}

func findingByItem(t *testing.T, findings []Finding, itemID string) Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.ItemID == itemID {
			return finding
		}
	}
	t.Fatalf("finding %q not found", itemID)
	return Finding{}
}

func evaluatePersistedMetric(t *testing.T, ctx context.Context, repository *PostgresRepository, scope platformscope.Scope, agentID string, item Item, createdAt, evaluationAt time.Time) Finding {
	t.Helper()
	target := TargetRun{TargetID: agentID, AgentID: agentID, Status: TargetEvaluating, AdvertisedSources: []SourceType{SourceMetric}}
	snapshot := RunSnapshot{ID: "run-" + agentID, Scope: scope, CreatedAt: createdAt.UTC(), Items: []Item{item}, Targets: []TargetRun{target}}
	findings, err := (&Evaluator{Evidence: repository, Now: func() time.Time { return evaluationAt.UTC() }}).EvaluateTarget(ctx, snapshot, target)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	return findings[0]
}
