package metrictemplate

import (
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestRevisionStateMachineRequiresSuccessfulTrialAndSeparateApprover(t *testing.T) {
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	revision := validRevision(now)

	revision, err := revision.Transition(StatusValidated, "creator", now.Add(time.Minute))
	require.NoError(t, err)
	_, err = revision.Transition(StatusApproved, "approver", now.Add(2*time.Minute))
	require.ErrorIs(t, err, ErrInvalidTransition)

	revision, err = revision.Transition(StatusTrialRunning, "creator", now.Add(2*time.Minute))
	require.NoError(t, err)
	revision, err = revision.Transition(StatusTrialPassed, "creator", now.Add(3*time.Minute))
	require.NoError(t, err)
	revision, err = revision.Transition(StatusApprovalPending, "creator", now.Add(4*time.Minute))
	require.NoError(t, err)
	_, err = revision.Transition(StatusApproved, "creator", now.Add(5*time.Minute))
	require.ErrorIs(t, err, ErrSelfApproval)

	approved, err := revision.Transition(StatusApproved, "approver", now.Add(5*time.Minute))
	require.NoError(t, err)
	require.Equal(t, "approver", approved.ApprovedBy)
	require.Equal(t, uint64(6), approved.ResourceRevision)
	require.Equal(t, `"6"`, approved.ETag())
	require.Equal(t, StatusApprovalPending, revision.Status, "transitions must not mutate an immutable revision snapshot")
}

func TestFailedValidationAndTrialAreFixedTerminalStates(t *testing.T) {
	now := time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC)
	for _, status := range []Status{StatusValidationFailed, StatusTrialFailed, StatusRejected, StatusSuperseded} {
		revision := validRevision(now)
		switch status {
		case StatusValidationFailed:
			revision.Status = StatusValidating
		case StatusTrialFailed:
			revision.Status = StatusTrialRunning
		case StatusRejected:
			revision.Status = StatusApprovalPending
		case StatusSuperseded:
			revision.Status = StatusPublished
		}
		failed, err := revision.Transition(status, "operator", now.Add(time.Minute))
		require.NoError(t, err)
		_, err = failed.Transition(StatusDraft, "operator", now.Add(2*time.Minute))
		require.ErrorIs(t, err, ErrInvalidTransition)
	}
}

func TestUnsafeDraftRemainsRepresentableUntilValidationRecordsFailure(t *testing.T) {
	revision := validRevision(time.Date(2026, 9, 1, 2, 0, 0, 0, time.UTC))
	revision.ReadOnlyStatement = "DELETE FROM metrics"
	revision.QueryDigest = DefinitionDigest(revision.ReadOnlyStatement)
	require.NoError(t, revision.Validate(), "draft shape and digest are valid even before semantic validation")
	_, err := ValidateDefinition(revision.Definition())
	require.ErrorIs(t, err, ErrValidationFailed)
}

func TestTrialResultEnforcesStoredRowColumnAndCardinalityLimits(t *testing.T) {
	result := TrialResult{RevisionID: "revision-a", QueryDigest: strings64("a"), StatusCode: "succeeded", RowCount: 2, ColumnCount: 2, MetricCount: 2, Metrics: []CandidateMetric{{Name: "mysql.custom.value", Value: 1, Unit: "1", MetricType: MetricGauge, Labels: map[string]string{"role": "primary"}}, {Name: "mysql.custom.value", Value: 2, Unit: "1", MetricType: MetricGauge, Labels: map[string]string{"role": "replica"}}}}
	mappings := []ValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: MetricGauge, Unit: "1"}}
	labels := []LabelMapping{{SourceColumn: "role", Label: "role"}}
	require.Equal(t, "high_cardinality", trialLimitFailure(result, 1, 2, 2, mappings, labels))
	require.Equal(t, "bounds_exceeded", trialLimitFailure(result, 2, 1, 2, mappings, labels))
	require.Empty(t, trialLimitFailure(result, 2, 2, 2, mappings, labels))
}

func validRevision(now time.Time) Revision {
	return Revision{
		ID: "revision-a", Scope: platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}, TemplateID: "mysql.custom_connections", Revision: 1,
		DatabaseFamily: "mysql", Variants: []string{"mysql"}, Name: "Custom connections", QueryKind: QuerySQL,
		ReadOnlyStatement: "SELECT value FROM metrics", CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2,
		ValueMappings: []ValueMapping{{SourceColumn: "value", MetricName: "mysql.connections.current", MetricType: MetricGauge, Unit: "1"}},
		LabelMappings: []LabelMapping{}, CardinalityLimit: 10, QueryDigest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Status: StatusDraft, CreatedBy: "creator", ResourceRevision: 1, CreatedAt: now, UpdatedAt: now,
	}
}
