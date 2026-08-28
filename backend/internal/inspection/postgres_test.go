package inspection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestPostgresListRunsUsesExactScopeAndDescendingTupleCursor(t *testing.T) {
	// Break caught: dropping either scope column or using a one-column cursor
	// can leak another project or duplicate rows with equal timestamps.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	before := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	mock.ExpectQuery("SELECT .* FROM inspection_runs WHERE tenant_id = \\$1 AND project_id = \\$2 AND \\(created_at, id\\) < \\(\\$3, \\$4\\) ORDER BY created_at DESC, id DESC LIMIT \\$5").
		WithArgs(scope.TenantID, scope.ProjectID, before, "run-9", 11).
		WillReturnRows(sqlmock.NewRows(runColumnNames()))

	page, err := NewPostgresRepository(database, nil).ListRuns(context.Background(), scope, RunFilter{Before: before, BeforeID: "run-9", Limit: 11})
	require.NoError(t, err)
	require.Empty(t, page.Items)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPolicyCASRejectsStaleVersion(t *testing.T) {
	// Break caught: accepting a zero-row compare-and-swap would let an older
	// editor overwrite a newer policy and its pinned item versions.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	policy := policyFixture()
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE inspection_policies SET .* WHERE tenant_id = \\$[0-9]+ AND project_id = \\$[0-9]+ AND id = \\$[0-9]+ AND version = \\$[0-9]+ RETURNING").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err = NewPostgresRepository(database, nil).UpdatePolicy(context.Background(), policy, policy.Version-1)
	require.ErrorIs(t, err, ErrConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSchedulerClaimLeasesWithoutAdvancingOccurrence(t *testing.T) {
	// Break caught: advancing next_run_at while merely claiming a policy loses
	// the scheduled occurrence when run/job/outbox creation later rolls back.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	policy := policyFixture()
	policy.NextRunAt = timePointerValue(now.Add(-time.Minute))
	mock.ExpectBegin()
	mock.ExpectQuery("(?s)SELECT .* FROM inspection_policies.*enabled = TRUE.*next_run_at <= \\$1.*lease_expires_at IS NULL OR lease_expires_at <= \\$1.*FOR UPDATE SKIP LOCKED.*LIMIT \\$2").
		WithArgs(now, 1).
		WillReturnRows(policyRows(policy))
	mock.ExpectQuery("UPDATE inspection_policies SET claim_token = \\$1, lease_expires_at = \\$2 WHERE tenant_id = \\$3 AND project_id = \\$4 AND id = \\$5 AND version = \\$6 RETURNING claim_token").
		WithArgs(sqlmock.AnyArg(), now.Add(30*time.Second), policy.Scope.TenantID, policy.Scope.ProjectID, policy.ID, policy.Version).
		WillReturnRows(sqlmock.NewRows([]string{"claim_token"}).AddRow("claim-1"))
	mock.ExpectCommit()

	claimed, err := NewPostgresRepository(database, nil).ClaimDuePolicies(context.Background(), now, 1, 30*time.Second)
	require.NoError(t, err)
	require.Len(t, claimed, 1)
	require.Equal(t, *policy.NextRunAt, claimed[0].Claim.Occurrence)
	require.Equal(t, "claim-1", claimed[0].Claim.Token)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresCreateItemPersistsTenantProjectAndImmutableSnapshot(t *testing.T) {
	// Break caught: an item insert without exact scope or a versioned JSON
	// snapshot cannot safely back policy pins and historical run evaluation.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	item := builtinItem("host.cpu.utilization")
	item.Scope = platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	item.Enabled = true
	item.CreatedAt = now
	item.UpdatedAt = now
	mock.ExpectExec("INSERT INTO inspection_items .*tenant_id, project_id, item_id, version.*snapshot").
		WithArgs(item.Scope.TenantID, item.Scope.ProjectID, item.ID, item.Version, true, true, item.Category, item.SourceType, sqlmock.AnyArg(), now, now).
		WillReturnResult(sqlmock.NewResult(0, 1))

	require.NoError(t, NewPostgresRepository(database, nil).CreateItem(context.Background(), item))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStoredSystemItemJSONRoundTripRemainsCanonical(t *testing.T) {
	// Break caught: JSON round-tripping storage metadata must not make an
	// otherwise canonical built-in item unusable when a Run snapshots it.
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	item := builtinItem("host.cpu.utilization")
	item.Scope = platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	item.Enabled, item.CreatedAt, item.UpdatedAt = true, now, now
	encoded, err := json.Marshal(item)
	require.NoError(t, err)
	var decoded Item
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.NoError(t, decoded.Validate())
}

func TestPostgresCreateRunRollsBackInspectionRowsWhenJobOutboxCreationFails(t *testing.T) {
	// Break caught: a failed Job/outbox write must not leave a Run or TargetRun
	// visible outside the shared PostgreSQL transaction.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	forced := errors.New("forced outbox insert failure")
	creator := &recordingJobCreator{err: forced}
	run, targets, value, messages := runPersistenceFixture()
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO inspection_runs .*RETURNING id").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(run.ID))
	mock.ExpectExec("INSERT INTO inspection_target_runs").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectRollback()

	err = NewPostgresRepository(database, creator).CreateRunWithJob(context.Background(), run, targets, value, messages)
	require.ErrorIs(t, err, forced)
	require.Equal(t, 1, creator.calls)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestSchedulerClaimDuplicateOccurrenceReturnsExistingRunAndAdvancesMatchingClaimOnly(t *testing.T) {
	// Break caught: replaying a claimed occurrence must return its existing Run
	// without creating another Job, while a stale claim token must never advance.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	creator := &recordingJobCreator{}
	run, targets, value, messages := runPersistenceFixture()
	policy := policyFixture()
	occurrence := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	next, err := NextScheduledOccurrence(*policy.Schedule, occurrence)
	require.NoError(t, err)
	policy.NextRunAt = &occurrence
	policy.Claim = &PolicyClaim{Token: "claim-1", Occurrence: occurrence, LeaseExpiresAt: occurrence.Add(time.Minute)}
	run.PolicyID, run.PolicyVersion, run.Trigger = policy.ID, policy.Version, RunTriggerScheduled
	run.OccurrenceKey, run.ScheduledFor, run.IdempotencyKey = scheduledOccurrenceKey(policy, occurrence), &occurrence, scheduledOccurrenceKey(policy, occurrence)
	run.PolicySnapshot = clonePolicy(&policy)
	existing := run
	existing.ID, existing.JobID = "run-existing", "job-existing"
	mock.ExpectBegin()
	mock.ExpectQuery("INSERT INTO inspection_runs .*ON CONFLICT \\(tenant_id, project_id, occurrence_key\\) DO NOTHING RETURNING id").WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectQuery("SELECT .* FROM inspection_runs WHERE tenant_id = \\$1 AND project_id = \\$2 AND occurrence_key = \\$3").
		WithArgs(run.Scope.TenantID, run.Scope.ProjectID, run.OccurrenceKey).
		WillReturnRows(runRows(existing))
	mock.ExpectQuery("UPDATE inspection_policies SET next_run_at = \\$1, claim_token = NULL, lease_expires_at = NULL WHERE tenant_id = \\$2 AND project_id = \\$3 AND id = \\$4 AND version = \\$5 AND next_run_at = \\$6 AND claim_token = \\$7 RETURNING next_run_at").
		WithArgs(next, policy.Scope.TenantID, policy.Scope.ProjectID, policy.ID, policy.Version, occurrence, policy.Claim.Token).
		WillReturnRows(sqlmock.NewRows([]string{"next_run_at"}).AddRow(next))
	mock.ExpectCommit()

	got, err := NewPostgresRepository(database, creator).CreateClaimedRunWithJob(context.Background(), policy, run, targets, value, messages)
	require.NoError(t, err)
	require.Equal(t, existing.ID, got.ID)
	require.Zero(t, creator.calls)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresCreatePolicyPinsScopedItemVersionsInOneTransaction(t *testing.T) {
	// Break caught: creating the policy row without its scope-qualified pinned
	// item rows makes scheduled runs depend on mutable catalog state.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	policy := policyFixture()
	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO inspection_policies .*tenant_id, project_id.*item_snapshot").
		WithArgs(
			policy.Scope.TenantID, policy.Scope.ProjectID, policy.ID, policy.Name, policy.Enabled, policy.Version,
			policy.Schedule.Cron, policy.Schedule.Timezone, *policy.NextRunAt, sqlmock.AnyArg(), sqlmock.AnyArg(),
			int(policy.TargetTimeout/time.Second), policy.MaxConcurrency, policy.CreatedAt, policy.UpdatedAt,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("INSERT INTO inspection_policy_items").
		WithArgs(policy.Scope.TenantID, policy.Scope.ProjectID, policy.ID, policy.Items[0].ItemID, policy.Items[0].Version, 0).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	require.NoError(t, NewPostgresRepository(database, nil).CreatePolicy(context.Background(), policy))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresCreatePolicyRejectsInvalidCronBeforeOpeningTransaction(t *testing.T) {
	// Break caught: persisting an invalid schedule strands a leased policy that
	// can only fail after the scheduler has claimed it.
	database, _, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	policy := policyFixture()
	policy.Schedule.Cron = "0 0 2 * * *"

	err = NewPostgresRepository(database, nil).CreatePolicy(context.Background(), policy)
	require.ErrorIs(t, err, ErrInvalid)
}

func TestPolicyValidationAllowsEnabledManualPolicyWithoutSchedule(t *testing.T) {
	// Break caught: schedule is optional; enabled manual policies must remain
	// runnable through RunInspectionPolicy without being scheduler candidates.
	policy := policyFixture()
	policy.Schedule = nil
	policy.NextRunAt = nil
	require.NoError(t, validatePolicy(policy))
}

func TestPolicyValidationRejectsEmptyTargetSelector(t *testing.T) {
	// Break caught: persisting a zero-target selector only fails after claim and
	// repeatedly leases a policy that can never produce a Run.
	policy := policyFixture()
	policy.Selector = TargetSelector{}
	require.ErrorIs(t, validatePolicy(policy), ErrInvalid)
}

func TestPostgresGetRunScopesRunTargetsAndFindings(t *testing.T) {
	// Break caught: scoping only the parent query still permits child TargetRun
	// or Finding rows from another tenant/project to enter a report snapshot.
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	run, targets, _, _ := runPersistenceFixture()
	mock.ExpectQuery("SELECT .* FROM inspection_runs WHERE tenant_id = \\$1 AND project_id = \\$2 AND id = \\$3").
		WithArgs(run.Scope.TenantID, run.Scope.ProjectID, run.ID).
		WillReturnRows(runRows(run))
	targetSnapshot, err := json.Marshal(targets[0])
	require.NoError(t, err)
	mock.ExpectQuery("SELECT target_snapshot FROM inspection_target_runs WHERE tenant_id = \\$1 AND project_id = \\$2 AND run_id = \\$3 ORDER BY target_id").
		WithArgs(run.Scope.TenantID, run.Scope.ProjectID, run.ID).
		WillReturnRows(sqlmock.NewRows([]string{"target_snapshot"}).AddRow(targetSnapshot))
	mock.ExpectQuery("SELECT .* FROM inspection_findings WHERE tenant_id = \\$1 AND project_id = \\$2 AND run_id = \\$3 ORDER BY target_id, item_id, item_version").
		WithArgs(run.Scope.TenantID, run.Scope.ProjectID, run.ID).
		WillReturnRows(sqlmock.NewRows(findingColumnNames()))

	detail, err := NewPostgresRepository(database, nil).GetRun(context.Background(), run.Scope, run.ID)
	require.NoError(t, err)
	require.Equal(t, run.ID, detail.Run.ID)
	require.Equal(t, targets[0].CommandID, detail.Targets[0].CommandID)
	require.Empty(t, detail.Findings)
	require.NoError(t, mock.ExpectationsWereMet())
}

func policyFixture() Policy {
	now := time.Date(2026, 8, 28, 7, 0, 0, 0, time.UTC)
	next := now.Add(time.Hour)
	return Policy{
		Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		ID:    "policy-1", Name: "daily host inspection", Enabled: true, Version: 2,
		Schedule:  &Schedule{Cron: "0 2 * * *", Timezone: "Asia/Shanghai"},
		NextRunAt: &next,
		Items:     []PolicyItem{{ItemID: "host.cpu.utilization", Version: 1}},
		Selector:  TargetSelector{AgentIDs: []string{"agent-1"}}, TargetTimeout: time.Minute, MaxConcurrency: 1,
		CreatedAt: now, UpdatedAt: now,
	}
}

func timePointerValue(value time.Time) *time.Time { return &value }

type recordingJobCreator struct {
	calls int
	err   error
}

func (creator *recordingJobCreator) CreateInTx(context.Context, *sql.Tx, job.Job, []job.OutboxMessage) error {
	creator.calls++
	return creator.err
}

func runPersistenceFixture() (Run, []TargetRun, job.Job, []job.OutboxMessage) {
	now := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	item := builtinItem("host.cpu.utilization")
	run := Run{
		Scope: scope, ID: "run-1", JobID: "job-1", Status: RunQueued, Trigger: RunTriggerManual,
		ItemSnapshot: []Item{item}, TargetCount: 1, AuditCorrelation: "inspection-run:run-1",
		IdempotencyKey: "request-key", InitiatedBy: "operator-1", RequestID: "request-1", CreatedAt: now,
	}
	targets := []TargetRun{{TargetID: "agent-1", AgentID: "agent-1", CommandID: "command-1", DisplayName: "Agent 1", Host: "agent-1.example", Status: TargetPending}}
	value := job.Job{ID: "job-1", Scope: scope, IdempotencyKey: "request-key"}
	messages := []job.OutboxMessage{{ID: "command-1", Scope: scope, JobID: "job-1", TargetID: "agent-1"}}
	return run, targets, value, messages
}

func runRows(value Run) *sqlmock.Rows {
	policySnapshot, _ := json.Marshal(value.PolicySnapshot)
	itemSnapshot, _ := json.Marshal(value.ItemSnapshot)
	return sqlmock.NewRows(runColumnNames()).AddRow(
		value.Scope.TenantID, value.Scope.ProjectID, value.ID, nullableString(value.PolicyID), nullableInt64(value.PolicyVersion), nullableString(value.RetryOfRunID), value.JobID,
		value.Status, value.Trigger, nullableString(value.OccurrenceKey), nullableTimeValue(value.ScheduledFor), policySnapshot, itemSnapshot,
		value.TargetCount, value.CompletedTargetCount, value.FailedTargetCount, nullableString(value.ReportID), value.AuditCorrelation, nullableString(value.IdempotencyKey),
		value.InitiatedBy, value.RequestID, value.TraceID, nullableTimeValue(value.StartedAt), nullableTimeValue(value.FinishedAt), value.CreatedAt,
	)
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableInt64(value int64) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableTimeValue(value *time.Time) any {
	if value == nil {
		return nil
	}
	return *value
}

func findingColumnNames() []string {
	return []string{"id", "run_id", "target_id", "item_id", "item_version", "level", "observed_at", "evidence", "warning_threshold", "critical_threshold", "summary", "recommendation"}
}

func policyRows(value Policy) *sqlmock.Rows {
	selector, _ := json.Marshal(value.Selector)
	items, _ := json.Marshal(value.Items)
	var cronValue, timezoneValue any
	if value.Schedule != nil {
		cronValue, timezoneValue = value.Schedule.Cron, value.Schedule.Timezone
	}
	var nextRunAt, claimToken, leaseExpiresAt any
	if value.NextRunAt != nil {
		nextRunAt = *value.NextRunAt
	}
	if value.Claim != nil {
		claimToken, leaseExpiresAt = value.Claim.Token, value.Claim.LeaseExpiresAt
	}
	return sqlmock.NewRows(strings.Split(policyColumnsSQL, ", ")).AddRow(
		value.Scope.TenantID, value.Scope.ProjectID, value.ID, value.Name, value.Enabled, value.Version,
		cronValue, timezoneValue, nextRunAt, selector, items, int(value.TargetTimeout/time.Second), value.MaxConcurrency,
		value.CreatedAt, value.UpdatedAt, claimToken, leaseExpiresAt,
	)
}
