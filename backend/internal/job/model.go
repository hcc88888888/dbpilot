// Package job defines DBPilot's durable, tenant-scoped background job model.
package job

import (
	"errors"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

var (
	ErrNotFound          = errors.New("job not found")
	ErrConflict          = errors.New("job version conflict")
	ErrInvalidTransition = errors.New("invalid job transition")
	ErrAmbiguousCommit   = errors.New("job transition commit outcome is ambiguous")
)

const MaximumTargetsPerJob = 10_000

type Status string

const (
	StatusQueued     Status = "queued"
	StatusDispatched Status = "dispatched"
	StatusRunning    Status = "running"
	StatusSucceeded  Status = "succeeded"
	StatusFailed     Status = "failed"
	StatusCancelling Status = "cancelling"
	StatusCancelled  Status = "cancelled"
	StatusTimedOut   Status = "timed_out"
)

type Outcome string

const (
	OutcomeComplete Outcome = "complete"
	OutcomePartial  Outcome = "partial"
	OutcomeNone     Outcome = "none"
)

type TargetStatus string

const (
	TargetQueued    TargetStatus = "queued"
	TargetRunning   TargetStatus = "running"
	TargetSucceeded TargetStatus = "succeeded"
	TargetFailed    TargetStatus = "failed"
	TargetSkipped   TargetStatus = "skipped"
	TargetCancelled TargetStatus = "cancelled"
	TargetTimedOut  TargetStatus = "timed_out"
)

type Progress struct {
	TotalTargets     int `json:"total_targets"`
	CompletedTargets int `json:"completed_targets"`
	FailedTargets    int `json:"failed_targets"`
	SkippedTargets   int `json:"skipped_targets"`
}

type ResourceReference struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
}

type ArtifactReference struct {
	ArtifactID string `json:"artifact_id"`
	Kind       string `json:"kind"`
}

type TargetResult struct {
	TargetID      string              `json:"target_id"`
	Status        TargetStatus        `json:"status"`
	ErrorSummary  string              `json:"error_summary,omitempty"`
	ResultSummary string              `json:"result_summary,omitempty"`
	Artifacts     []ArtifactReference `json:"artifacts,omitempty"`
	FinishedAt    *time.Time          `json:"finished_at,omitempty"`
}

type Job struct {
	ID                string              `json:"id"`
	Type              string              `json:"type"`
	Scope             platformscope.Scope `json:"scope"`
	Status            Status              `json:"status"`
	Outcome           Outcome             `json:"outcome"`
	InstanceID        string              `json:"instance_id,omitempty"`
	TargetResourceIDs []string            `json:"target_resource_ids,omitempty"`
	InitiatedBy       string              `json:"initiated_by,omitempty"`
	SourceResource    ResourceReference   `json:"source_resource"`
	IdempotencyKey    string              `json:"idempotency_key,omitempty"`
	Version           int64               `json:"version"`
	Progress          Progress            `json:"progress"`
	TargetResults     []TargetResult      `json:"target_results,omitempty"`
	ErrorSummary      string              `json:"error_summary,omitempty"`
	ResultSummary     string              `json:"result_summary,omitempty"`
	Artifacts         []ArtifactReference `json:"artifacts"`
	CreatedAt         time.Time           `json:"created_at"`
	DispatchedAt      *time.Time          `json:"dispatched_at,omitempty"`
	StartedAt         *time.Time          `json:"started_at,omitempty"`
	FinishedAt        *time.Time          `json:"finished_at,omitempty"`
	TimeoutAt         *time.Time          `json:"timeout_at,omitempty"`
	CancelRequestedBy string              `json:"cancel_requested_by,omitempty"`
	CancelRequestedAt *time.Time          `json:"cancel_requested_at,omitempty"`
	RequestID         string              `json:"request_id"`
	TraceID           string              `json:"trace_id"`
}

type Transition struct {
	Scope          platformscope.Scope
	JobID          string
	CurrentVersion int64
	To             Status
	Progress       *Progress
	TargetResults  []TargetResult
	ErrorSummary   string
	ResultSummary  string
	Artifacts      []ArtifactReference
	Actor          string
	At             time.Time
}

type OutboxMessage struct {
	ID               string              `json:"id"`
	Scope            platformscope.Scope `json:"scope"`
	JobID            string              `json:"job_id"`
	TargetID         string              `json:"target_id,omitempty"`
	Type             string              `json:"type"`
	Payload          []byte              `json:"payload"`
	PreparedEnvelope []byte              `json:"-"`
	AvailableAt      time.Time           `json:"available_at"`
	CreatedAt        time.Time           `json:"created_at"`
	LeasedUntil      *time.Time          `json:"leased_until,omitempty"`
	PublishedAt      *time.Time          `json:"published_at,omitempty"`
	Attempts         int                 `json:"attempts"`
}

func ApplyTransition(current Job, transition Transition) (Job, error) {
	if transition.CurrentVersion != 0 && transition.CurrentVersion != current.Version {
		return Job{}, ErrConflict
	}
	if err := ValidateTargets(current); err != nil {
		return Job{}, err
	}
	if transition.At.IsZero() || !allowedTransition(current.Status, transition.To) {
		return Job{}, ErrInvalidTransition
	}
	if transition.To == StatusCancelling && transition.Actor == "" {
		return Job{}, ErrInvalidTransition
	}
	if current.Status == StatusCancelling && transition.To == StatusCancelling && len(transition.TargetResults) == 0 {
		return Job{}, ErrInvalidTransition
	}
	if !validTargetUpdates(current, transition.TargetResults) {
		return Job{}, ErrInvalidTransition
	}

	next := normalizeJobUTC(current)
	at := transition.At.UTC()
	next.Status = transition.To
	next.Version++
	if transition.TargetResults != nil {
		next.TargetResults = mergeTargetResults(next.TargetResults, transition.TargetResults)
	}
	reconciled := AggregateProgressForTargets(next.TargetResourceIDs, next.TargetResults)
	if transition.Progress != nil && *transition.Progress != reconciled {
		return Job{}, ErrInvalidTransition
	}
	if !validProgressChange(current.Progress, reconciled) {
		return Job{}, ErrInvalidTransition
	}
	next.Progress = reconciled
	if transition.ErrorSummary != "" {
		next.ErrorSummary = transition.ErrorSummary
	}
	if transition.ResultSummary != "" {
		next.ResultSummary = transition.ResultSummary
	}
	if transition.Artifacts != nil {
		next.Artifacts = append([]ArtifactReference(nil), transition.Artifacts...)
	}

	switch transition.To {
	case StatusDispatched:
		next.DispatchedAt = timePointer(at)
	case StatusRunning:
		if current.Status == StatusDispatched {
			next.StartedAt = timePointer(at)
		}
	case StatusCancelling:
		if current.Status != StatusCancelling {
			next.CancelRequestedBy = transition.Actor
			next.CancelRequestedAt = timePointer(at)
		}
	case StatusSucceeded, StatusFailed, StatusCancelled, StatusTimedOut:
		next.FinishedAt = timePointer(at)
	}

	if isTerminal(transition.To) {
		if len(next.TargetResults) > 0 {
			next.Outcome = AggregateOutcome(next.TargetResults)
		} else {
			next.Outcome = outcomeFromProgress(next.Progress)
		}
	} else {
		next.Outcome = OutcomeNone
	}
	if transition.To == StatusSucceeded && !validSucceededJob(next) {
		return Job{}, ErrInvalidTransition
	}
	return next, nil
}

func AggregateOutcome(results []TargetResult) Outcome {
	succeeded := 0
	other := 0
	for _, result := range results {
		switch result.Status {
		case TargetSucceeded:
			succeeded++
		case TargetFailed, TargetSkipped, TargetCancelled, TargetTimedOut:
			other++
		default:
			return OutcomeNone
		}
	}
	if succeeded > 0 && other > 0 {
		return OutcomePartial
	}
	if succeeded > 0 && other == 0 {
		return OutcomeComplete
	}
	return OutcomeNone
}

func AggregateTargetResults(results []TargetResult) Outcome {
	return AggregateOutcome(results)
}

func AggregateProgress(results []TargetResult) Progress {
	progress := Progress{TotalTargets: len(results)}
	for _, result := range results {
		switch result.Status {
		case TargetSucceeded:
			progress.CompletedTargets++
		case TargetFailed, TargetCancelled, TargetTimedOut:
			progress.FailedTargets++
		case TargetSkipped:
			progress.SkippedTargets++
		}
	}
	return progress
}

// AggregateProgressForTargets reconciles persisted counters with the expected
// target set. Missing target rows are treated as queued and contribute no
// terminal counter.
func AggregateProgressForTargets(expected []string, results []TargetResult) Progress {
	progress := AggregateProgress(results)
	progress.TotalTargets = len(expected)
	return progress
}

// ValidateTargets is the pure invariant gate shared by creation and state
// transitions. It bounds fan-out, rejects duplicate/unknown targets, and keeps
// persisted counters derived from target rows.
func ValidateTargets(value Job) error {
	if len(value.TargetResourceIDs) > MaximumTargetsPerJob || value.Progress.TotalTargets != len(value.TargetResourceIDs) {
		return ErrInvalidTransition
	}
	expected := make(map[string]struct{}, len(value.TargetResourceIDs))
	for _, id := range value.TargetResourceIDs {
		if id == "" {
			return ErrInvalidTransition
		}
		if _, duplicate := expected[id]; duplicate {
			return ErrInvalidTransition
		}
		expected[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(value.TargetResults))
	for _, result := range value.TargetResults {
		if _, ok := expected[result.TargetID]; !ok || !validTargetStatus(result.Status) {
			return ErrInvalidTransition
		}
		if _, duplicate := seen[result.TargetID]; duplicate {
			return ErrInvalidTransition
		}
		seen[result.TargetID] = struct{}{}
	}
	if value.Progress != AggregateProgressForTargets(value.TargetResourceIDs, value.TargetResults) {
		return ErrInvalidTransition
	}
	return nil
}

func allowedTransition(from, to Status) bool {
	switch from {
	case StatusQueued:
		return to == StatusDispatched
	case StatusDispatched:
		return to == StatusRunning
	case StatusRunning:
		return to == StatusRunning || to == StatusSucceeded || to == StatusFailed || to == StatusTimedOut || to == StatusCancelling
	case StatusCancelling:
		return to == StatusCancelling || to == StatusCancelled
	default:
		return false
	}
}

func validTargetUpdates(current Job, updates []TargetResult) bool {
	if updates == nil {
		return true
	}
	expected := make(map[string]struct{}, len(current.TargetResourceIDs))
	for _, id := range current.TargetResourceIDs {
		expected[id] = struct{}{}
	}
	states := make(map[string]TargetStatus, len(current.TargetResults))
	for _, result := range current.TargetResults {
		states[result.TargetID] = result.Status
	}
	seen := make(map[string]struct{}, len(updates))
	for _, update := range updates {
		if _, ok := expected[update.TargetID]; !ok || !validTargetStatus(update.Status) {
			return false
		}
		if _, duplicate := seen[update.TargetID]; duplicate {
			return false
		}
		seen[update.TargetID] = struct{}{}
		from := states[update.TargetID]
		if from == "" {
			from = TargetQueued
		}
		if !allowedTargetTransition(from, update.Status) {
			return false
		}
	}
	return true
}

func allowedTargetTransition(from, to TargetStatus) bool {
	if isTerminalTarget(from) {
		return false
	}
	switch from {
	case TargetQueued:
		return to == TargetQueued || to == TargetRunning || isTerminalTarget(to)
	case TargetRunning:
		return to == TargetRunning || isTerminalTarget(to)
	default:
		return false
	}
}

func validTargetStatus(status TargetStatus) bool {
	return status == TargetQueued || status == TargetRunning || isTerminalTarget(status)
}

func isTerminalTarget(status TargetStatus) bool {
	return status == TargetSucceeded || status == TargetFailed || status == TargetSkipped || status == TargetCancelled || status == TargetTimedOut
}

func validSucceededJob(value Job) bool {
	if len(value.TargetResourceIDs) == 0 || len(value.TargetResults) != len(value.TargetResourceIDs) {
		return false
	}
	for _, result := range value.TargetResults {
		if !isTerminalTarget(result.Status) {
			return false
		}
	}
	terminalCount := value.Progress.CompletedTargets + value.Progress.FailedTargets + value.Progress.SkippedTargets
	return terminalCount == value.Progress.TotalTargets && (value.Outcome == OutcomeComplete || value.Outcome == OutcomePartial)
}

func validProgressChange(current, next Progress) bool {
	if current.TotalTargets != next.TotalTargets || next.TotalTargets < 0 || next.CompletedTargets < current.CompletedTargets || next.FailedTargets < current.FailedTargets || next.SkippedTargets < current.SkippedTargets {
		return false
	}
	return next.CompletedTargets+next.FailedTargets+next.SkippedTargets <= next.TotalTargets
}

func outcomeFromProgress(progress Progress) Outcome {
	if progress.CompletedTargets > 0 && progress.FailedTargets+progress.SkippedTargets > 0 {
		return OutcomePartial
	}
	if progress.TotalTargets > 0 && progress.CompletedTargets == progress.TotalTargets {
		return OutcomeComplete
	}
	return OutcomeNone
}

func isTerminal(status Status) bool {
	return status == StatusSucceeded || status == StatusFailed || status == StatusCancelled || status == StatusTimedOut
}

func normalizeJobUTC(value Job) Job {
	value.CreatedAt = value.CreatedAt.UTC()
	value.DispatchedAt = utcPointer(value.DispatchedAt)
	value.StartedAt = utcPointer(value.StartedAt)
	value.FinishedAt = utcPointer(value.FinishedAt)
	value.TimeoutAt = utcPointer(value.TimeoutAt)
	value.CancelRequestedAt = utcPointer(value.CancelRequestedAt)
	value.TargetResourceIDs = append([]string(nil), value.TargetResourceIDs...)
	value.TargetResults = normalizeTargetResultsUTC(value.TargetResults)
	value.Artifacts = append([]ArtifactReference(nil), value.Artifacts...)
	return value
}

func normalizeTargetResultsUTC(results []TargetResult) []TargetResult {
	normalized := make([]TargetResult, len(results))
	for index, result := range results {
		normalized[index] = result
		normalized[index].FinishedAt = utcPointer(result.FinishedAt)
		normalized[index].Artifacts = append([]ArtifactReference(nil), result.Artifacts...)
	}
	return normalized
}

func mergeTargetResults(current, updates []TargetResult) []TargetResult {
	merged := normalizeTargetResultsUTC(current)
	positions := make(map[string]int, len(merged))
	for index := range merged {
		positions[merged[index].TargetID] = index
	}
	for _, update := range normalizeTargetResultsUTC(updates) {
		if index, ok := positions[update.TargetID]; ok {
			merged[index] = update
			continue
		}
		positions[update.TargetID] = len(merged)
		merged = append(merged, update)
	}
	return merged
}

func utcPointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	return timePointer(value.UTC())
}

func timePointer(value time.Time) *time.Time {
	return &value
}
