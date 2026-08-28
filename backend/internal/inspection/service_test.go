package inspection

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestCreateRunSnapshotsTargetsAndBuildsExactUnsignedHostCommands(t *testing.T) {
	// Break caught: losing sorted target identity, pinned items, or the exact
	// unsigned CollectNow shape can make a run non-reproducible or undispatchable.
	fixture := newServiceFixture(t)
	run, err := fixture.service.CreateRun(context.Background(), CreateRunRequest{
		Scope: fixture.scope, Selector: TargetSelector{AgentIDs: []string{"agent-b"}, Labels: map[string]string{"role": "db"}},
		Items: []PolicyItem{{ItemID: "host.cpu.utilization", Version: 1}}, TargetTimeout: time.Minute, MaxConcurrency: 2,
		IdempotencyKey: "request-key-1", InitiatedBy: "operator-1", RequestID: "request-1", TraceID: "trace-1",
	})
	require.NoError(t, err)
	require.Equal(t, "run-1", run.ID)
	require.Equal(t, RunTriggerManual, run.Trigger)
	require.Equal(t, []string{"agent-a", "agent-b"}, fixture.repository.job.TargetResourceIDs)
	require.Equal(t, "run-1", fixture.repository.job.SourceResource.ResourceID)
	require.Equal(t, "request-key-1", fixture.repository.job.IdempotencyKey)
	require.Equal(t, []string{"agent-a", "agent-b"}, []string{fixture.repository.targets[0].AgentID, fixture.repository.targets[1].AgentID})
	require.Equal(t, []string{"command-a", "command-b"}, []string{fixture.repository.targets[0].CommandID, fixture.repository.targets[1].CommandID})
	require.Equal(t, fixture.repository.run.ItemSnapshot[0].ID, "host.cpu.utilization")

	require.Len(t, fixture.repository.messages, 2)
	for index, message := range fixture.repository.messages {
		envelope := new(agentv1.CommandEnvelope)
		require.NoError(t, proto.Unmarshal(message.Payload, envelope))
		require.True(t, proto.Equal(&agentv1.CommandEnvelope{
			AgentId:      []string{"agent-a", "agent-b"}[index],
			LeaseSeconds: 60,
			Command:      &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"host"}}},
		}, envelope))
		require.Empty(t, envelope.CommandId)
		require.Empty(t, envelope.JobId)
		require.Empty(t, envelope.Signature)
	}
}

func TestScheduleParserRejectsDescriptorsSecondsAndImplicitOrInvalidZones(t *testing.T) {
	// Break caught: accepting cron descriptors, six fields, or a machine-local
	// zone makes occurrences differ across controller hosts.
	for _, schedule := range []Schedule{
		{Cron: "@daily", Timezone: "UTC"},
		{Cron: "0 0 2 * * *", Timezone: "UTC"},
		{Cron: "0 2 * * *", Timezone: ""},
		{Cron: "0 2 * * *", Timezone: "Mars/Olympus"},
	} {
		_, err := NextScheduledOccurrence(schedule, time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC))
		require.ErrorIs(t, err, ErrInvalidSchedule)
	}
	next, err := NextScheduledOccurrence(Schedule{Cron: "0 2 * * *", Timezone: "Asia/Shanghai"}, time.Date(2026, 8, 28, 0, 30, 0, 0, time.UTC))
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 8, 28, 18, 0, 0, 0, time.UTC), next)
}

func TestRetryRunRequiresFailedOrPartialAndCreatesFreshIdentity(t *testing.T) {
	// Break caught: an operator retry must not reuse the original Run, Job, or
	// Command IDs, and must retain retry_of_run_id for audit correlation.
	fixture := newServiceFixture(t)
	fixture.repository.detail = RunDetail{Run: Run{
		Scope: fixture.scope, ID: "run-old", JobID: "job-old", Status: RunFailed, Trigger: RunTriggerManual,
		ItemSnapshot: []Item{builtinItem("host.cpu.utilization")}, TargetCount: 1, CreatedAt: fixture.now,
	}, Targets: []TargetRun{{TargetID: "agent-a", AgentID: "agent-a", CommandID: "command-old", Status: TargetFailed}}}
	run, err := fixture.service.RetryRun(context.Background(), fixture.scope, "run-old", "retry-key", "operator-2")
	require.NoError(t, err)
	require.Equal(t, "run-1", run.ID)
	require.Equal(t, "run-old", run.RetryOfRunID)
	require.Equal(t, RunTriggerRetry, run.Trigger)
	require.Equal(t, "job-1", run.JobID)
	require.Equal(t, "command-a", fixture.repository.targets[0].CommandID)
	require.NotEqual(t, "command-old", fixture.repository.targets[0].CommandID)

	fixture.repository.detail.Run.Status = RunCompleted
	_, err = fixture.service.RetryRun(context.Background(), fixture.scope, "run-old", "another-key", "operator-2")
	require.ErrorIs(t, err, ErrRunNotRetryable)
}

func TestScheduleDueUsesClaimAwareCreationAndAdvancesFromClaimedOccurrence(t *testing.T) {
	// Break caught: scheduled work must use the repository path that atomically
	// verifies the lease claim and advances from the exact claimed occurrence.
	fixture := newServiceFixture(t)
	occurrence := fixture.now.Add(-time.Hour)
	policy := policyFixture()
	policy.Scope = fixture.scope
	policy.Selector = TargetSelector{AgentIDs: []string{"agent-a"}}
	policy.NextRunAt = &occurrence
	policy.Claim = &PolicyClaim{Token: "claim-1", Occurrence: occurrence, LeaseExpiresAt: fixture.now.Add(time.Minute)}
	fixture.repository.claimed = []Policy{policy}

	count, err := fixture.service.ScheduleDue(context.Background(), fixture.now)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.True(t, fixture.repository.claimAware)
	require.Equal(t, occurrence, fixture.repository.claimedPolicy.Claim.Occurrence)
	require.Equal(t, RunTriggerScheduled, fixture.repository.run.Trigger)
	require.Equal(t, scheduledOccurrenceKey(policy, occurrence), fixture.repository.run.OccurrenceKey)
	require.Equal(t, fixture.repository.run.OccurrenceKey, fixture.repository.job.IdempotencyKey)
}

func TestCreateRunRejectsForgedRetryLinkOnManualRequest(t *testing.T) {
	// Break caught: retry_of_run_id is service-owned correlation and must only
	// be set after RetryRun verifies the original terminal state.
	fixture := newServiceFixture(t)
	_, err := fixture.service.CreateRun(context.Background(), CreateRunRequest{
		Scope: fixture.scope, RetryOfRunID: "run-unverified", Selector: TargetSelector{AgentIDs: []string{"agent-a"}},
		Items: []PolicyItem{{ItemID: "host.cpu.utilization", Version: 1}}, TargetTimeout: time.Minute, MaxConcurrency: 1,
		IdempotencyKey: "request-key", InitiatedBy: "operator-1", RequestID: "request-1",
	})
	require.ErrorIs(t, err, ErrInvalid)
}

type serviceFixture struct {
	scope      platformscope.Scope
	now        time.Time
	repository *memoryInspectionRepository
	service    *Service
}

func newServiceFixture(t *testing.T) serviceFixture {
	t.Helper()
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	resolver, err := NewConfiguredTargetResolver([]HostTarget{
		{Scope: scope, AgentID: "agent-b", DisplayName: "B", Host: "b.example", Labels: map[string]string{"role": "db"}},
		{Scope: scope, AgentID: "agent-a", DisplayName: "A", Host: "a.example", Labels: map[string]string{"role": "db"}},
	})
	require.NoError(t, err)
	repository := &memoryInspectionRepository{items: []Item{builtinItem("host.cpu.utilization")}}
	ids := []string{"run-1", "job-1", "command-a", "command-b"}
	service := &Service{
		Repository: repository, Targets: resolver, Now: func() time.Time { return now },
		NewID: func() (string, error) {
			if len(ids) == 0 {
				return "", errors.New("unexpected id request")
			}
			id := ids[0]
			ids = ids[1:]
			return id, nil
		},
		ClaimLimit: 10, ClaimLease: time.Minute,
	}
	return serviceFixture{scope: scope, now: now, repository: repository, service: service}
}

type memoryInspectionRepository struct {
	items         []Item
	detail        RunDetail
	claimed       []Policy
	run           Run
	targets       []TargetRun
	job           job.Job
	messages      []job.OutboxMessage
	claimAware    bool
	claimedPolicy Policy
}

func (repository *memoryInspectionRepository) CreateItem(context.Context, Item) error { return nil }
func (repository *memoryInspectionRepository) ListItems(context.Context, platformscope.Scope, ItemFilter) (ItemPage, error) {
	return ItemPage{Items: append([]Item(nil), repository.items...)}, nil
}
func (repository *memoryInspectionRepository) CreatePolicy(context.Context, Policy) error { return nil }
func (repository *memoryInspectionRepository) ListPolicies(context.Context, platformscope.Scope, PolicyFilter) (PolicyPage, error) {
	return PolicyPage{}, nil
}
func (repository *memoryInspectionRepository) GetPolicy(context.Context, platformscope.Scope, string) (Policy, error) {
	return Policy{}, ErrNotFound
}
func (repository *memoryInspectionRepository) UpdatePolicy(context.Context, Policy, int64) (Policy, error) {
	return Policy{}, nil
}
func (repository *memoryInspectionRepository) ClaimDuePolicies(context.Context, time.Time, int, time.Duration) ([]Policy, error) {
	return append([]Policy(nil), repository.claimed...), nil
}
func (repository *memoryInspectionRepository) CreateRunWithJob(_ context.Context, run Run, targets []TargetRun, value job.Job, messages []job.OutboxMessage) error {
	repository.capture(run, targets, value, messages)
	return nil
}
func (repository *memoryInspectionRepository) CreateClaimedRunWithJob(_ context.Context, policy Policy, run Run, targets []TargetRun, value job.Job, messages []job.OutboxMessage) (Run, error) {
	repository.claimAware = true
	repository.claimedPolicy = policy
	repository.capture(run, targets, value, messages)
	return run, nil
}
func (repository *memoryInspectionRepository) GetRun(context.Context, platformscope.Scope, string) (RunDetail, error) {
	return repository.detail, nil
}
func (repository *memoryInspectionRepository) GetRunByIdempotencyKey(context.Context, platformscope.Scope, string) (Run, error) {
	return Run{}, ErrNotFound
}
func (repository *memoryInspectionRepository) ListRuns(context.Context, platformscope.Scope, RunFilter) (RunPage, error) {
	return RunPage{}, nil
}
func (repository *memoryInspectionRepository) GetReport(context.Context, platformscope.Scope, string) (ReportSnapshot, error) {
	return ReportSnapshot{}, nil
}
func (repository *memoryInspectionRepository) ListReports(context.Context, platformscope.Scope, ReportFilter) (ReportPage, error) {
	return ReportPage{}, nil
}
func (repository *memoryInspectionRepository) capture(run Run, targets []TargetRun, value job.Job, messages []job.OutboxMessage) {
	repository.run = run
	repository.targets = append([]TargetRun(nil), targets...)
	repository.job = value
	repository.messages = append([]job.OutboxMessage(nil), messages...)
}

var _ Repository = (*memoryInspectionRepository)(nil)
