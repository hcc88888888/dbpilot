package job

import (
	"encoding/json"
	"errors"
	"fmt"
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
		TargetResourceIDs: []string{"db-1", "db-2"},
		TargetResults:     []TargetResult{{TargetID: "db-1", Status: TargetQueued}, {TargetID: "db-2", Status: TargetQueued}},
		Progress:          Progress{TotalTargets: 2}, CreatedAt: created,
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

func TestCancellationCanStartBeforeDispatchAndActualResultsChooseTerminalState(t *testing.T) {
	created := time.Date(2026, 8, 28, 8, 0, 0, 0, time.UTC)
	for _, initial := range []Status{StatusQueued, StatusDispatched, StatusRunning} {
		t.Run(string(initial), func(t *testing.T) {
			current := runningJob()
			current.Status = initial
			current.Version = 1
			current.TargetResults = []TargetResult{{TargetID: "db-1", Status: TargetQueued}}
			current.Progress = Progress{TotalTargets: 1}
			if initial == StatusQueued {
				current.DispatchedAt, current.StartedAt = nil, nil
			} else if initial == StatusDispatched {
				current.StartedAt = nil
			}
			cancelling := requireTransition(t, current, Transition{To: StatusCancelling, Actor: "operator", At: created})
			require.Equal(t, StatusCancelling, cancelling.Status)
		})
	}

	tests := []struct {
		name   string
		target TargetStatus
		to     Status
	}{
		{name: "too late success", target: TargetSucceeded, to: StatusSucceeded},
		{name: "cancelled", target: TargetCancelled, to: StatusCancelled},
		{name: "failed", target: TargetFailed, to: StatusFailed},
		{name: "timed out", target: TargetTimedOut, to: StatusTimedOut},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := requireTransition(t, runningJob(), Transition{To: StatusCancelling, Actor: "operator", At: created})
			current = requireTransition(t, current, Transition{To: StatusCancelling, Actor: "operator", At: created.Add(time.Second), TargetResults: []TargetResult{{TargetID: "db-1", Status: test.target}}})
			current = requireTransition(t, current, Transition{To: test.to, At: created.Add(2 * time.Second)})
			require.Equal(t, test.to, current.Status)
		})
	}
}

func TestCancellingSelfTransitionRequiresTargetEvidenceAndPreservesRequester(t *testing.T) {
	current := runningJob()
	cancelling, err := ApplyTransition(current, Transition{To: StatusCancelling, Actor: "operator-1", At: current.CreatedAt.Add(3 * time.Second)})
	require.NoError(t, err)

	_, err = ApplyTransition(cancelling, Transition{To: StatusCancelling, Actor: "operator-1", At: current.CreatedAt.Add(4 * time.Second)})
	require.ErrorIs(t, err, ErrInvalidTransition)

	next, err := ApplyTransition(cancelling, Transition{To: StatusCancelling, Actor: "operator-1", At: current.CreatedAt.Add(4 * time.Second), TargetResults: []TargetResult{{TargetID: "db-1", Status: TargetCancelled}}})
	require.NoError(t, err)
	require.Equal(t, cancelling.CancelRequestedBy, next.CancelRequestedBy)
	require.Equal(t, cancelling.CancelRequestedAt, next.CancelRequestedAt)
}

func TestTransitionRejectsTerminalRegressionAndCancellation(t *testing.T) {
	finished := time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC)
	terminal := runningJob()
	completed := Progress{TotalTargets: 1, CompletedTargets: 1}
	terminal = requireTransition(t, terminal, Transition{To: StatusSucceeded, At: finished, Progress: &completed, TargetResults: []TargetResult{{TargetID: "db-1", Status: TargetSucceeded}}})

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

func TestAggregateOutcomeRequiresEveryTargetToBeTerminal(t *testing.T) {
	tests := []struct {
		name    string
		results []TargetResult
		want    Outcome
	}{
		{name: "all succeeded", results: []TargetResult{{Status: TargetSucceeded}, {Status: TargetSucceeded}}, want: OutcomeComplete},
		{name: "success and failure", results: []TargetResult{{Status: TargetSucceeded}, {Status: TargetFailed}}, want: OutcomePartial},
		{name: "success and running", results: []TargetResult{{Status: TargetSucceeded}, {Status: TargetRunning}}, want: OutcomeNone},
		{name: "all failed", results: []TargetResult{{Status: TargetFailed}, {Status: TargetFailed}}, want: OutcomeNone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, AggregateOutcome(test.results))
		})
	}
}

func TestValidateTargetsRejectsDuplicatesUnknownAndMaximumOverflow(t *testing.T) {
	base := runningJob()
	base.TargetResourceIDs = []string{"db-1", "db-1"}
	base.Progress.TotalTargets = 2
	require.ErrorIs(t, ValidateTargets(base), ErrInvalidTransition)

	overflow := Job{TargetResourceIDs: make([]string, MaximumTargetsPerJob+1), Progress: Progress{TotalTargets: MaximumTargetsPerJob + 1}}
	for index := range overflow.TargetResourceIDs {
		overflow.TargetResourceIDs[index] = fmt.Sprintf("db-%d", index)
	}
	require.ErrorIs(t, ValidateTargets(overflow), ErrInvalidTransition)

	base = runningJob()
	progress := Progress{TotalTargets: 1, CompletedTargets: 1}
	_, err := ApplyTransition(base, Transition{
		To: StatusRunning, At: base.StartedAt.Add(time.Second), Progress: &progress,
		TargetResults: []TargetResult{{TargetID: "db-unknown", Status: TargetSucceeded}},
	})
	require.ErrorIs(t, err, ErrInvalidTransition)
}

func TestTransitionRejectsDuplicateUpdatesAndTerminalTargetRegression(t *testing.T) {
	current := runningJob()
	at := current.StartedAt.Add(time.Second)
	_, err := ApplyTransition(current, Transition{
		To: StatusRunning, At: at,
		TargetResults: []TargetResult{{TargetID: "db-1", Status: TargetRunning}, {TargetID: "db-1", Status: TargetRunning}},
	})
	require.ErrorIs(t, err, ErrInvalidTransition)

	current.TargetResults[0].Status = TargetSucceeded
	current.Progress = Progress{TotalTargets: 1, CompletedTargets: 1}
	_, err = ApplyTransition(current, Transition{
		To: StatusRunning, At: at,
		TargetResults: []TargetResult{{TargetID: "db-1", Status: TargetRunning}},
	})
	require.ErrorIs(t, err, ErrInvalidTransition)
}

func TestTransitionRequiresConsistentCompleteTargetsForSucceeded(t *testing.T) {
	tests := []struct {
		name     string
		results  []TargetResult
		progress Progress
		wantErr  bool
		outcome  Outcome
	}{
		{name: "all succeeded", results: []TargetResult{{TargetID: "db-1", Status: TargetSucceeded}, {TargetID: "db-2", Status: TargetSucceeded}}, progress: Progress{TotalTargets: 2, CompletedTargets: 2}, outcome: OutcomeComplete},
		{name: "partial success", results: []TargetResult{{TargetID: "db-1", Status: TargetSucceeded}, {TargetID: "db-2", Status: TargetFailed}}, progress: Progress{TotalTargets: 2, CompletedTargets: 1, FailedTargets: 1}, outcome: OutcomePartial},
		{name: "running target", results: []TargetResult{{TargetID: "db-1", Status: TargetSucceeded}, {TargetID: "db-2", Status: TargetRunning}}, progress: Progress{TotalTargets: 2, CompletedTargets: 1}, wantErr: true},
		{name: "counter mismatch", results: []TargetResult{{TargetID: "db-1", Status: TargetSucceeded}, {TargetID: "db-2", Status: TargetFailed}}, progress: Progress{TotalTargets: 2, CompletedTargets: 2}, wantErr: true},
		{name: "no successful target", results: []TargetResult{{TargetID: "db-1", Status: TargetFailed}, {TargetID: "db-2", Status: TargetSkipped}}, progress: Progress{TotalTargets: 2, FailedTargets: 1, SkippedTargets: 1}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := runningJob()
			current.TargetResourceIDs = []string{"db-1", "db-2"}
			current.TargetResults = []TargetResult{{TargetID: "db-1", Status: TargetRunning}, {TargetID: "db-2", Status: TargetRunning}}
			current.Progress = Progress{TotalTargets: 2}
			got, err := ApplyTransition(current, Transition{To: StatusSucceeded, At: current.StartedAt.Add(time.Second), Progress: &test.progress, TargetResults: test.results})
			if test.wantErr {
				require.ErrorIs(t, err, ErrInvalidTransition)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.outcome, got.Outcome)
			require.Equal(t, test.progress, got.Progress)
		})
	}
}

func TestTransitionMergesIncrementalTargetResultsWhileRunning(t *testing.T) {
	current := runningJob()
	originalStartedAt := *current.StartedAt
	current.TargetResourceIDs = []string{"db-1", "db-2"}
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
		TargetResourceIDs: []string{"db-1"}, TargetResults: []TargetResult{{TargetID: "db-1", Status: TargetRunning}},
		Progress: Progress{TotalTargets: 1}, CreatedAt: created, DispatchedAt: &dispatched, StartedAt: &started,
	}
}
