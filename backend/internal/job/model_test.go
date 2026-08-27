package job

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
)

func TestArtifactReferenceMatchesContractShape(t *testing.T) {
	encoded, err := json.Marshal(ArtifactReference{ArtifactID: "artifact-1", Kind: "report"})
	require.NoError(t, err)
	require.JSONEq(t, `{"artifact_id":"artifact-1","kind":"report"}`, string(encoded))
}

func TestTransitionAllowsSuccessfulLifecycle(t *testing.T) {
	created := time.Date(2026, 8, 28, 16, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	current := Job{
		ID: "job-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		Type: "inspection.run", Status: StatusQueued, Outcome: OutcomeNone, Version: 1,
		Progress: Progress{TotalTargets: 2}, CreatedAt: created,
	}

	dispatchedAt := created.Add(time.Second)
	current = requireTransition(t, current, Transition{To: StatusDispatched, At: dispatchedAt})
	require.Equal(t, StatusDispatched, current.Status)
	require.Equal(t, int64(2), current.Version)
	require.Equal(t, dispatchedAt.UTC(), *current.DispatchedAt)

	startedAt := dispatchedAt.Add(time.Second)
	current = requireTransition(t, current, Transition{To: StatusRunning, At: startedAt})
	require.Equal(t, startedAt.UTC(), *current.StartedAt)

	finishedAt := startedAt.Add(time.Second)
	progress := Progress{TotalTargets: 2, CompletedTargets: 2}
	current = requireTransition(t, current, Transition{
		To: StatusSucceeded, At: finishedAt, Progress: &progress,
		TargetResults: []TargetResult{{TargetID: "db-1", Status: TargetSucceeded}, {TargetID: "db-2", Status: TargetSucceeded}},
	})
	require.Equal(t, StatusSucceeded, current.Status)
	require.Equal(t, OutcomeComplete, current.Outcome)
	require.Equal(t, int64(4), current.Version)
	require.Equal(t, finishedAt.UTC(), *current.FinishedAt)
	require.Equal(t, time.UTC, current.CreatedAt.Location())
}

func TestTransitionAllowsFailureAndTimeoutFromRunning(t *testing.T) {
	for _, terminal := range []Status{StatusFailed, StatusTimedOut} {
		t.Run(string(terminal), func(t *testing.T) {
			current := runningJob()
			finished := time.Date(2026, 8, 28, 19, 0, 0, 0, time.FixedZone("CST", 8*60*60))
			got := requireTransition(t, current, Transition{To: terminal, At: finished, ErrorSummary: "worker unavailable"})
			require.Equal(t, terminal, got.Status)
			require.Equal(t, OutcomeNone, got.Outcome)
			require.Equal(t, finished.UTC(), *got.FinishedAt)
			require.Equal(t, "worker unavailable", got.ErrorSummary)
		})
	}
}

func TestTransitionAllowsCancellation(t *testing.T) {
	current := runningJob()
	requestedAt := current.StartedAt.Add(time.Minute)
	current = requireTransition(t, current, Transition{To: StatusCancelling, At: requestedAt, Actor: "operator-7"})
	require.Equal(t, StatusCancelling, current.Status)
	require.Equal(t, "operator-7", current.CancelRequestedBy)
	require.Equal(t, requestedAt.UTC(), *current.CancelRequestedAt)

	finishedAt := requestedAt.Add(time.Second)
	current = requireTransition(t, current, Transition{To: StatusCancelled, At: finishedAt})
	require.Equal(t, StatusCancelled, current.Status)
	require.Equal(t, OutcomeNone, current.Outcome)
	require.Equal(t, finishedAt.UTC(), *current.FinishedAt)
}

func TestTransitionRejectsTerminalRegressionAndCancellation(t *testing.T) {
	finished := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	terminal := runningJob()
	terminal = requireTransition(t, terminal, Transition{To: StatusSucceeded, At: finished})

	_, err := ApplyTransition(terminal, Transition{To: StatusRunning, At: finished.Add(time.Second)})
	require.ErrorIs(t, err, ErrInvalidTransition)

	_, err = ApplyTransition(terminal, Transition{To: StatusCancelling, At: finished.Add(time.Second), Actor: "operator"})
	require.ErrorIs(t, err, ErrInvalidTransition)
}

func TestTransitionRejectsProgressRegression(t *testing.T) {
	current := runningJob()
	current.Progress = Progress{TotalTargets: 4, CompletedTargets: 2, FailedTargets: 1}
	regressed := Progress{TotalTargets: 4, CompletedTargets: 1, FailedTargets: 1}

	_, err := ApplyTransition(current, Transition{To: StatusSucceeded, At: time.Now(), Progress: &regressed})
	require.True(t, errors.Is(err, ErrInvalidTransition))
}

func TestAggregateTargetResultsReturnsPartialForMixedResults(t *testing.T) {
	results := []TargetResult{{TargetID: "db-1", Status: TargetSucceeded}, {TargetID: "db-2", Status: TargetFailed}}

	require.Equal(t, OutcomePartial, AggregateOutcome(results))
	require.Equal(t, Progress{TotalTargets: 2, CompletedTargets: 1, FailedTargets: 1}, AggregateProgress(results))
}

func TestTransitionMergesIncrementalTargetResultsWhileRunning(t *testing.T) {
	current := runningJob()
	originalStartedAt := *current.StartedAt
	current.Progress = Progress{TotalTargets: 2, CompletedTargets: 1}
	current.TargetResults = []TargetResult{{TargetID: "db-1", Status: TargetSucceeded}}
	at := current.StartedAt.Add(time.Minute)
	progress := Progress{TotalTargets: 2, CompletedTargets: 1, FailedTargets: 1}

	current = requireTransition(t, current, Transition{
		To: StatusRunning, At: at, Progress: &progress,
		TargetResults: []TargetResult{{TargetID: "db-2", Status: TargetFailed}},
	})
	require.Len(t, current.TargetResults, 2)
	require.Equal(t, OutcomeNone, current.Outcome)
	require.Equal(t, originalStartedAt, *current.StartedAt)

	current = requireTransition(t, current, Transition{To: StatusSucceeded, At: at.Add(time.Second)})
	require.Equal(t, OutcomePartial, current.Outcome)
}

func requireTransition(t *testing.T, current Job, transition Transition) Job {
	t.Helper()
	got, err := ApplyTransition(current, transition)
	require.NoError(t, err)
	return got
}

func runningJob() Job {
	created := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	dispatched := created.Add(time.Second)
	started := dispatched.Add(time.Second)
	return Job{
		ID: "job-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		Type: "inspection.run", Status: StatusRunning, Outcome: OutcomeNone, Version: 3,
		Progress: Progress{TotalTargets: 1}, CreatedAt: created, DispatchedAt: &dispatched, StartedAt: &started,
	}
}
