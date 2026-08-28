package inspection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"testing"
	"time"

	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestWorkerWaitsForFreshHostSnapshotAfterSuccessfulCommand(t *testing.T) {
	// Break caught: command success must never be treated as proof that its
	// telemetry batch has already been ingested.
	fixture := newWorkerFixture(t, []TargetRun{workerTarget("agent-a")}, []job.TargetResult{workerJobResult("agent-a", job.TargetSucceeded)})
	fixture.now = fixture.created.Add(time.Minute)
	fixture.deadline = fixture.created.Add(5 * time.Minute)
	fixture.repository.freshAt = map[string]time.Time{}

	processed, err := fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, err)
	require.Equal(t, 1, processed)
	require.Equal(t, RunCollecting, fixture.repository.detail.Run.Status)
	require.Empty(t, fixture.repository.detail.Findings)
	require.Zero(t, fixture.evidence.calls)
	require.Equal(t, []freshnessRequest{{TargetID: "agent-a", SourceID: hostSnapshotSourceID, From: fixture.created, To: fixture.deadline}}, fixture.repository.freshnessRequests)
}

func TestWorkerFreshUnrelatedMarkerDoesNotSatisfyRequiredMetric(t *testing.T) {
	// Break caught: a fresh source marker cannot release evaluation while the
	// required item metric in that snapshot is absent or stale.
	fixture := newWorkerFixture(t, []TargetRun{workerTarget("agent-a")}, []job.TargetResult{workerJobResult("agent-a", job.TargetSucceeded)})
	fixture.now = fixture.created.Add(time.Minute)
	fixture.deadline = fixture.created.Add(5 * time.Minute)
	fixture.repository.freshAt = map[string]time.Time{"agent-a": fixture.created.Add(time.Second)}
	fixture.repository.hostComplete = map[string]bool{"agent-a": false}
	fixture.evidence.observations = map[string][]Observation{
		"agent-a": {{ID: "stale-required", TargetID: "agent-a", Name: "system.cpu.utilization", SourceType: SourceMetric, Value: 99, ObservedAt: fixture.created.Add(-time.Second)}},
	}

	_, err := fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, err)
	require.Equal(t, RunCollecting, fixture.repository.detail.Run.Status)
	require.Zero(t, fixture.evidence.calls)
}

func TestFreshnessDeadlineProducesMissingDataFromStaleOnlyEvidence(t *testing.T) {
	// Break caught: a stale pre-run sample must not satisfy freshness, and the
	// persisted Job deadline is the exact point at which waiting becomes a
	// deterministic missing_data result.
	fixture := newWorkerFixture(t, []TargetRun{workerTarget("agent-a")}, []job.TargetResult{workerJobResult("agent-a", job.TargetSucceeded)})
	fixture.deadline = fixture.created.Add(5 * time.Minute)
	fixture.now = fixture.deadline
	fixture.repository.freshAt = map[string]time.Time{"agent-a": fixture.created.Add(-time.Nanosecond)}

	processed, err := fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, err)
	require.Equal(t, 1, processed)
	require.Equal(t, RunFailed, fixture.repository.detail.Run.Status)
	require.Len(t, fixture.repository.detail.Findings, 1)
	require.Equal(t, LevelMissingData, fixture.repository.detail.Findings[0].Level)
	require.Equal(t, "0", fixture.repository.detail.Findings[0].Evidence["samples"])
	require.Equal(t, 1, fixture.evidence.calls, "deadline evaluation must produce item-specific missing_data")
}

func TestWorkerEvaluationNeverUsesEvidenceAfterJobDeadline(t *testing.T) {
	// Break caught: a later repair pass must not move the evidence window past
	// the persisted Job deadline and silently change the historical conclusion.
	fixture := newWorkerFixture(t, []TargetRun{workerTarget("agent-a")}, []job.TargetResult{workerJobResult("agent-a", job.TargetSucceeded)})
	fixture.deadline = fixture.created.Add(5 * time.Minute)
	fixture.now = fixture.deadline.Add(time.Minute)
	fixture.repository.freshAt = map[string]time.Time{"agent-a": fixture.created.Add(time.Second)}
	fixture.evidence.observations = map[string][]Observation{
		"agent-a": {
			{ID: "within-deadline", TargetID: "agent-a", Name: "system.cpu.utilization", SourceType: SourceMetric, Value: 12, ObservedAt: fixture.deadline.Add(-time.Second)},
			{ID: "after-deadline", TargetID: "agent-a", Name: "system.cpu.utilization", SourceType: SourceMetric, Value: 99, ObservedAt: fixture.deadline.Add(time.Second)},
		},
	}

	_, err := fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, err)
	require.Len(t, fixture.repository.detail.Findings, 1)
	require.Equal(t, LevelHealthy, fixture.repository.detail.Findings[0].Level)
	require.Equal(t, fixture.deadline.Add(-time.Second), fixture.repository.detail.Findings[0].ObservedAt)
}

func TestWorkerFailedTargetDoesNotFabricateFindingsAndSiblingContinues(t *testing.T) {
	// Break caught: mapping one executor failure must not synthesize health or
	// cancel evaluation of a successful sibling.
	targets := []TargetRun{workerTarget("agent-a"), workerTarget("agent-b")}
	results := []job.TargetResult{
		workerJobResult("agent-a", job.TargetFailed),
		workerJobResult("agent-b", job.TargetSucceeded),
	}
	fixture := newWorkerFixture(t, targets, results)
	fixture.repository.freshAt = map[string]time.Time{"agent-b": fixture.created.Add(time.Second)}
	fixture.evidence.observations = map[string][]Observation{
		"agent-b": {{ID: "sample-b", TargetID: "agent-b", Name: "system.cpu.utilization", SourceType: SourceMetric, Value: 12, ObservedAt: fixture.created.Add(time.Second)}},
	}

	processed, err := fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, err)
	require.Equal(t, 1, processed)
	require.Equal(t, RunPartial, fixture.repository.detail.Run.Status)
	require.Equal(t, TargetFailed, targetByID(t, fixture.repository.detail.Targets, "agent-a").Status)
	require.Equal(t, "collection_failed", targetByID(t, fixture.repository.detail.Targets, "agent-a").ErrorCode)
	require.Equal(t, TargetSucceeded, targetByID(t, fixture.repository.detail.Targets, "agent-b").Status)
	require.Len(t, fixture.repository.detail.Findings, 1)
	require.Equal(t, "agent-b", fixture.repository.detail.Findings[0].TargetID)
	require.Equal(t, 1, fixture.evidence.calls)
	require.Len(t, fixture.repository.report.Artifacts, 2)
}

func TestWorkerMapsCancelledTargetWithoutCancellingSibling(t *testing.T) {
	// Break caught: target-local cancellation must remain target-local and a
	// valid sibling must still produce a report and a partial Run.
	targets := []TargetRun{workerTarget("agent-a"), workerTarget("agent-b")}
	results := []job.TargetResult{
		workerJobResult("agent-a", job.TargetCancelled),
		workerJobResult("agent-b", job.TargetSucceeded),
	}
	fixture := newWorkerFixture(t, targets, results)
	fixture.repository.freshAt = map[string]time.Time{"agent-b": fixture.created.Add(time.Second)}
	fixture.evidence.observations = map[string][]Observation{
		"agent-b": {{ID: "sample-b", TargetID: "agent-b", Name: "system.cpu.utilization", SourceType: SourceMetric, Value: 12, ObservedAt: fixture.created.Add(time.Second)}},
	}

	_, err := fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, err)
	require.Equal(t, RunPartial, fixture.repository.detail.Run.Status)
	require.Equal(t, TargetCancelled, targetByID(t, fixture.repository.detail.Targets, "agent-a").Status)
	require.Equal(t, TargetSucceeded, targetByID(t, fixture.repository.detail.Targets, "agent-b").Status)
}

func TestWorkerFinalizesAllCancelledTargetsAsCancelled(t *testing.T) {
	// Break caught: AggregateRunStatus intentionally returns cancelled when all
	// targets cancel; report persistence must accept that terminal outcome.
	fixture := newWorkerFixture(t, []TargetRun{workerTarget("agent-a")}, []job.TargetResult{workerJobResult("agent-a", job.TargetCancelled)})

	_, err := fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, err)
	require.Equal(t, RunCancelled, fixture.repository.detail.Run.Status)
	require.Equal(t, TargetCancelled, fixture.repository.detail.Targets[0].Status)
	require.Empty(t, fixture.repository.detail.Findings)
}

func TestWorkerArtifactFailureRetriesReportWithoutRepeatingEvaluation(t *testing.T) {
	// Break caught: a crash or failure between JSON and HTML publication must
	// leave generating_report repairable without another collection/evaluation.
	fixture := newWorkerFixture(t, []TargetRun{workerTarget("agent-a")}, []job.TargetResult{workerJobResult("agent-a", job.TargetSucceeded)})
	fixture.repository.freshAt = map[string]time.Time{"agent-a": fixture.created.Add(time.Second)}
	fixture.evidence.observations = map[string][]Observation{
		"agent-a": {{ID: "sample-a", TargetID: "agent-a", Name: "system.cpu.utilization", SourceType: SourceMetric, Value: 12, ObservedAt: fixture.created.Add(time.Second)}},
	}
	fixture.artifacts.failAt = 2

	_, firstErr := fixture.worker().Process(context.Background(), fixture.now, 1)
	require.Error(t, firstErr)
	require.Equal(t, RunGeneratingReport, fixture.repository.detail.Run.Status)
	require.Equal(t, 1, fixture.evidence.calls)
	require.Empty(t, fixture.repository.report.ID)
	firstJSONChecksum := fixture.artifacts.values[0].Checksum

	fixture.artifacts.failAt = 0
	fixture.jobs.err = errors.New("Job storage unavailable during report repair")
	jobCalls := fixture.jobs.calls
	fixture.now = fixture.now.Add(time.Minute)
	_, secondErr := fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, secondErr)
	require.Equal(t, RunCompleted, fixture.repository.detail.Run.Status)
	require.Equal(t, 1, fixture.evidence.calls, "report repair must not evaluate again")
	require.Equal(t, jobCalls, fixture.jobs.calls, "report repair must not load the Job")
	require.Equal(t, firstJSONChecksum, fixture.artifacts.values[1].Checksum, "stable persisted generation time must keep retry bytes identical")
}

func TestFindingCompletenessControlsTargetAndRunOutcome(t *testing.T) {
	// Break caught: one valid Finding must not mask a missing or unsupported
	// sibling item on the same target.
	tests := []struct {
		name       string
		findings   []Finding
		wantTarget TargetStatus
		wantRun    RunStatus
	}{
		{"all valid", []Finding{{Level: LevelHealthy}, {Level: LevelWarning}}, TargetSucceeded, RunCompleted},
		{"incomplete valid", []Finding{{Level: LevelHealthy}}, TargetFailed, RunFailed},
		{"valid plus missing", []Finding{{Level: LevelHealthy}, {Level: LevelMissingData}}, TargetFailed, RunFailed},
		{"valid plus unsupported", []Finding{{Level: LevelHealthy}, {Level: LevelUnsupported}}, TargetUnsupported, RunFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := TargetRun{}
			applyFindingOutcome(&target, test.findings, 2)
			require.Equal(t, test.wantTarget, target.Status)
			require.Equal(t, test.wantRun, AggregateRunStatus([]TargetStatus{target.Status}))
		})
	}

	valid := TargetRun{}
	applyFindingOutcome(&valid, []Finding{{Level: LevelHealthy}}, 1)
	missing := TargetRun{}
	applyFindingOutcome(&missing, []Finding{{Level: LevelMissingData}}, 1)
	require.Equal(t, RunPartial, AggregateRunStatus([]TargetStatus{valid.Status, missing.Status}))
}

func TestWorkerAuditFailureRepairsPersistedEventWithoutRerendering(t *testing.T) {
	// Break caught: Audit is a best-effort side effect after finalization; its
	// repair must replay only the persisted event and never render artifacts.
	fixture := newWorkerFixture(t, []TargetRun{workerTarget("agent-a")}, []job.TargetResult{workerJobResult("agent-a", job.TargetSucceeded)})
	fixture.repository.freshAt = map[string]time.Time{"agent-a": fixture.created.Add(time.Second)}
	fixture.evidence.observations = map[string][]Observation{
		"agent-a": {{ID: "sample-a", TargetID: "agent-a", Name: "system.cpu.utilization", SourceType: SourceMetric, Value: 12, ObservedAt: fixture.created.Add(time.Second)}},
	}
	fixture.audits.err = errors.New("audit unavailable")

	_, err := fixture.worker().Process(context.Background(), fixture.now, 1)
	require.NoError(t, err)
	require.Equal(t, RunCompleted, fixture.repository.detail.Run.Status)
	require.NotNil(t, fixture.repository.pendingAudit)
	require.Len(t, fixture.artifacts.values, 2)

	fixture.audits.err = nil
	fixture.now = fixture.now.Add(time.Minute)
	_, err = fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, err)
	require.Nil(t, fixture.repository.pendingAudit)
	require.Len(t, fixture.audits.events, 1)
	require.Len(t, fixture.artifacts.values, 2, "Audit repair must not render again")
	require.Equal(t, 1, fixture.evidence.calls, "Audit repair must not evaluate again")
}

func TestWorkerAuditBacklogDoesNotStarveActiveRuns(t *testing.T) {
	// Break caught: Audit repair is best effort and must not consume the only
	// bounded slot while an inspection Run still needs evaluation/reporting.
	fixture := newWorkerFixture(t, []TargetRun{workerTarget("agent-a")}, []job.TargetResult{workerJobResult("agent-a", job.TargetSucceeded)})
	fixture.repository.freshAt = map[string]time.Time{"agent-a": fixture.created.Add(time.Second)}
	fixture.evidence.observations = map[string][]Observation{
		"agent-a": {{ID: "sample-a", TargetID: "agent-a", Name: "system.cpu.utilization", SourceType: SourceMetric, Value: 12, ObservedAt: fixture.created.Add(time.Second)}},
	}
	fixture.repository.pendingAudit = &ReportAuditClaim{
		Scope: fixture.repository.detail.Run.Scope, RunID: "old-run", Token: "old-audit",
		Event: audit.Event{Scope: fixture.repository.detail.Run.Scope, DedupeKey: "old-run:report"},
	}
	fixture.audits.err = errors.New("audit unavailable")

	processed, err := fixture.worker().Process(context.Background(), fixture.now, 1)

	require.NoError(t, err)
	require.Equal(t, 1, processed)
	require.Equal(t, RunCompleted, fixture.repository.detail.Run.Status)
}

type workerFixture struct {
	created    time.Time
	now        time.Time
	deadline   time.Time
	repository *memoryRunWorkerRepository
	jobs       *memoryJobReader
	evidence   *workerEvidenceStore
	artifacts  *memoryArtifactWriter
	audits     *memoryAuditRecorder
}

func newWorkerFixture(t *testing.T, targets []TargetRun, results []job.TargetResult) *workerFixture {
	t.Helper()
	created := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	deadline := created.Add(5 * time.Minute)
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	item := Item{
		ID: "cpu.utilization", Version: 3, Name: "CPU <utilization>", Category: "capacity", ScopeType: ScopeHost,
		SourceType: SourceMetric, EvidenceSelector: []string{"value"}, RecommendationTemplate: "review CPU", Enabled: true,
		MetricRule: &MetricRule{MetricName: "system.cpu.utilization", Labels: map[string]string{}, Window: 10 * time.Minute, Aggregation: AggregationLatest, Operator: OperatorGTE, WarningThreshold: 80, CriticalThreshold: 90},
	}
	run := Run{
		Scope: scope, ID: "run-a", PolicyID: "policy-a", PolicyVersion: 7, JobID: "job-a", Status: RunCollecting,
		Trigger: RunTriggerManual, ItemSnapshot: []Item{item}, TargetCount: len(targets), AuditCorrelation: "inspection-run:run-a",
		InitiatedBy: "operator-a", RequestID: "request-a", TraceID: "trace-a", CreatedAt: created,
	}
	for index := range targets {
		targets[index].Status = TargetCollecting
	}
	repository := &memoryRunWorkerRepository{detail: RunDetail{Run: run, Targets: targets}, freshAt: map[string]time.Time{}}
	value := job.Job{
		ID: run.JobID, Scope: scope, Type: "inspection", Status: job.StatusSucceeded, Outcome: job.AggregateOutcome(results),
		TargetResourceIDs: targetIDs(targets), TargetResults: results, TimeoutAt: &deadline, FinishedAt: timePointerValue(deadline.Add(-time.Second)),
		CreatedAt: created, RequestID: run.RequestID, TraceID: run.TraceID,
	}
	return &workerFixture{
		created: created, now: created.Add(2 * time.Minute), deadline: deadline, repository: repository,
		jobs: &memoryJobReader{value: value}, evidence: &workerEvidenceStore{observations: map[string][]Observation{}},
		artifacts: &memoryArtifactWriter{}, audits: &memoryAuditRecorder{},
	}
}

func (fixture *workerFixture) worker() *Worker {
	fixture.jobs.value.TimeoutAt = &fixture.deadline
	return &Worker{Runs: fixture.repository, Jobs: fixture.jobs, Evaluator: &Evaluator{Evidence: fixture.evidence, Now: func() time.Time { return fixture.now }}, Artifacts: fixture.artifacts, Audit: fixture.audits}
}

func workerTarget(id string) TargetRun {
	return TargetRun{TargetID: id, AgentID: id, CommandID: "command-" + id, DisplayName: "Host " + id, Host: id + ".internal", AdvertisedSources: []SourceType{SourceMetric}, Status: TargetCollecting}
}

func workerJobResult(id string, status job.TargetStatus) job.TargetResult {
	finished := time.Date(2026, 8, 29, 10, 1, 0, 0, time.UTC)
	return job.TargetResult{TargetID: id, Status: status, FinishedAt: &finished}
}

func targetIDs(targets []TargetRun) []string {
	result := make([]string, len(targets))
	for index := range targets {
		result[index] = targets[index].TargetID
	}
	return result
}

func targetByID(t *testing.T, targets []TargetRun, id string) TargetRun {
	t.Helper()
	for _, target := range targets {
		if target.TargetID == id {
			return target
		}
	}
	t.Fatalf("target %q not found", id)
	return TargetRun{}
}

type freshnessRequest struct {
	TargetID string
	SourceID string
	From     time.Time
	To       time.Time
}

type memoryRunWorkerRepository struct {
	detail              RunDetail
	report              ReportSnapshot
	freshAt             map[string]time.Time
	hostComplete        map[string]bool
	hostObservations    map[string][]Observation
	freshnessRequests   []freshnessRequest
	released            int
	pendingAudit        *ReportAuditClaim
	recordedAuditDedupe string
	reportGeneratedAt   time.Time
}

func (repository *memoryRunWorkerRepository) ClaimRuns(_ context.Context, now time.Time, limit int, lease time.Duration) ([]RunClaim, error) {
	if limit < 1 || lease <= 0 || isTerminalRun(repository.detail.Run.Status) {
		return []RunClaim{}, nil
	}
	generatedAt := repository.reportGeneratedAt
	if generatedAt.IsZero() {
		generatedAt = now
	}
	return []RunClaim{{Detail: cloneRunDetail(repository.detail), Token: "claim-a", LeaseExpiresAt: now.Add(lease), ReportGeneratedAt: generatedAt}}, nil
}

func (repository *memoryRunWorkerRepository) MarkCollecting(_ context.Context, claim RunClaim, at time.Time) (RunClaim, error) {
	repository.detail.Run.Status = RunCollecting
	for index := range repository.detail.Targets {
		repository.detail.Targets[index].Status = TargetCollecting
	}
	if repository.detail.Run.StartedAt == nil {
		repository.detail.Run.StartedAt = timePointerValue(at.UTC())
	}
	claim.Detail = cloneRunDetail(repository.detail)
	return claim, nil
}

func (repository *memoryRunWorkerRepository) BeginEvaluation(_ context.Context, claim RunClaim) (RunClaim, error) {
	repository.detail.Run.Status = RunEvaluating
	for index := range repository.detail.Targets {
		repository.detail.Targets[index].Status = TargetEvaluating
	}
	claim.Detail = cloneRunDetail(repository.detail)
	return claim, nil
}

func (repository *memoryRunWorkerRepository) FreshSnapshotAt(_ context.Context, scope platformscope.Scope, targetID, sourceID string, from, to time.Time) (time.Time, bool, error) {
	repository.freshnessRequests = append(repository.freshnessRequests, freshnessRequest{TargetID: targetID, SourceID: sourceID, From: from, To: to})
	at, ok := repository.freshAt[targetID]
	return at, ok && !at.Before(from) && !at.After(to), nil
}

func (repository *memoryRunWorkerRepository) LoadHostSnapshot(_ context.Context, _ platformscope.Scope, targetID string, _ []Item, from, to time.Time, _ int) (HostSnapshotEvidence, error) {
	repository.freshnessRequests = append(repository.freshnessRequests, freshnessRequest{TargetID: targetID, SourceID: hostSnapshotSourceID, From: from, To: to})
	at, ok := repository.freshAt[targetID]
	complete := ok && !at.Before(from) && !at.After(to)
	if value, exists := repository.hostComplete[targetID]; exists {
		complete = value
	}
	return HostSnapshotEvidence{SampledAt: at, Observations: append([]Observation(nil), repository.hostObservations[targetID]...), Complete: complete}, nil
}

func (repository *memoryRunWorkerRepository) SaveEvaluation(_ context.Context, claim RunClaim, targets []TargetRun, findings []Finding, generatedAt time.Time) (RunClaim, error) {
	repository.detail.Targets = append([]TargetRun(nil), targets...)
	repository.detail.Findings = append([]Finding(nil), findings...)
	repository.detail.Run.Status = RunGeneratingReport
	claim.Detail = cloneRunDetail(repository.detail)
	claim.ReportGeneratedAt = generatedAt.UTC()
	repository.reportGeneratedAt = claim.ReportGeneratedAt
	return claim, nil
}

func (repository *memoryRunWorkerRepository) ReleaseRun(context.Context, RunClaim) error {
	repository.released++
	return nil
}

func (repository *memoryRunWorkerRepository) FinalizeReport(_ context.Context, claim RunClaim, report ReportSnapshot, terminal RunStatus, event audit.Event, at time.Time) (ReportAuditClaim, error) {
	repository.report = report
	repository.detail.Run.Status = terminal
	repository.detail.Run.ReportID = report.ID
	repository.detail.Run.FinishedAt = timePointerValue(at.UTC())
	repository.detail.Run.CompletedTargetCount = 0
	repository.detail.Run.FailedTargetCount = 0
	for _, target := range repository.detail.Targets {
		if target.Status == TargetSucceeded {
			repository.detail.Run.CompletedTargetCount++
		} else {
			repository.detail.Run.FailedTargetCount++
		}
	}
	repository.pendingAudit = &ReportAuditClaim{Scope: repository.detail.Run.Scope, RunID: repository.detail.Run.ID, Event: event}
	return *repository.pendingAudit, nil
}

func (repository *memoryRunWorkerRepository) ClaimPendingReportAudits(context.Context, time.Time, int, time.Duration) ([]ReportAuditClaim, error) {
	if repository.pendingAudit == nil {
		return []ReportAuditClaim{}, nil
	}
	return []ReportAuditClaim{*repository.pendingAudit}, nil
}

func (repository *memoryRunWorkerRepository) MarkReportAuditRecorded(_ context.Context, claim ReportAuditClaim, _ time.Time) error {
	repository.recordedAuditDedupe = claim.Event.DedupeKey
	repository.pendingAudit = nil
	return nil
}

func (repository *memoryRunWorkerRepository) ReleaseReportAudit(context.Context, ReportAuditClaim) error {
	return nil
}

type memoryJobReader struct {
	value job.Job
	err   error
	calls int
}

func (reader *memoryJobReader) Get(context.Context, platformscope.Scope, string) (job.Job, error) {
	reader.calls++
	return reader.value, reader.err
}

type workerEvidenceStore struct {
	observations map[string][]Observation
	calls        int
}

func (store *workerEvidenceStore) Samples(_ context.Context, _ platformscope.Scope, targetID string, _ []string, _, _ time.Time, _ int) ([]Observation, error) {
	store.calls++
	return append([]Observation(nil), store.observations[targetID]...), nil
}

type memoryArtifactWriter struct {
	values []artifact.Artifact
	err    error
	failAt int
	calls  int
}

func (writer *memoryArtifactWriter) Put(_ context.Context, value artifact.Artifact, contents []byte) (artifact.Artifact, error) {
	writer.calls++
	if writer.err != nil {
		return artifact.Artifact{}, writer.err
	}
	if writer.failAt > 0 && writer.calls == writer.failAt {
		return artifact.Artifact{}, errors.New("artifact write failed")
	}
	digest := sha256.Sum256(contents)
	want := "sha256:" + hex.EncodeToString(digest[:])
	if value.Checksum != want || value.SizeBytes != int64(len(contents)) {
		return artifact.Artifact{}, errors.New("artifact metadata mismatch")
	}
	writer.values = append(writer.values, value)
	return value, nil
}

type memoryAuditRecorder struct {
	events []audit.Event
	err    error
}

func (recorder *memoryAuditRecorder) RecordOnce(_ context.Context, event audit.Event) (audit.Event, error) {
	if recorder.err != nil {
		return audit.Event{}, recorder.err
	}
	recorder.events = append(recorder.events, event)
	return event, nil
}

func cloneRunDetail(value RunDetail) RunDetail {
	value.Targets = append([]TargetRun(nil), value.Targets...)
	value.Findings = append([]Finding(nil), value.Findings...)
	return value
}

func isTerminalRun(status RunStatus) bool {
	return status == RunCompleted || status == RunPartial || status == RunFailed || status == RunCancelled
}

func sortFindings(values []Finding) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].TargetID != values[j].TargetID {
			return values[i].TargetID < values[j].TargetID
		}
		if values[i].ItemID != values[j].ItemID {
			return values[i].ItemID < values[j].ItemID
		}
		return values[i].ItemVersion < values[j].ItemVersion
	})
}
