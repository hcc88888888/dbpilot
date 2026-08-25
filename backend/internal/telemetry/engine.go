package telemetry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"dbpilot.local/platform/internal/policy"
)

const defaultHealthCheckTimeout = 5 * time.Second

var (
	// ErrPolicyVersionRollback means an Apply request tried to replace the
	// active pipeline with an older policy.
	ErrPolicyVersionRollback = policy.ErrPolicyVersionRollback
	// ErrCandidateVersionMismatch prevents a builder from activating a runtime
	// that was built for another policy version.
	ErrCandidateVersionMismatch = errors.New("telemetry candidate version does not match policy")
	// ErrNilCandidate protects the lifecycle from a malformed Builder.
	ErrNilCandidate = errors.New("telemetry builder returned a nil candidate")
)

// Builder constructs a not-yet-running telemetry pipeline from a compiled
// policy. It must not start the candidate; Engine owns its lifecycle.
type Builder interface {
	Build(ctx context.Context, cfg RuntimeConfig) (Candidate, error)
}

// Candidate is a pipeline whose lifecycle can be controlled by Engine.
// Healthy must return only after the candidate is ready to receive telemetry.
type Candidate interface {
	Start(ctx context.Context) error
	Healthy(ctx context.Context) error
	Stop(ctx context.Context) error
	Version() uint64
}

// ApplyState describes the outcome of a policy application attempt.
type ApplyState string

const (
	ApplyActive     ApplyState = "ACTIVE"
	ApplyRejected   ApplyState = "REJECTED"
	ApplyRolledBack ApplyState = "ROLLED_BACK"
)

// Error codes are stable machine-readable summaries. The returned error
// retains the underlying operational failure for diagnostics.
const (
	ErrorCodeValidationFailed   = "VALIDATION_FAILED"
	ErrorCodeCompileFailed      = "COMPILE_FAILED"
	ErrorCodeBuildFailed        = "BUILD_FAILED"
	ErrorCodeCandidateVersion   = "CANDIDATE_VERSION_MISMATCH"
	ErrorCodeStartFailed        = "START_FAILED"
	ErrorCodeHealthCheckFailed  = "HEALTH_CHECK_FAILED"
	ErrorCodeVersionRejected    = "POLICY_VERSION_REJECTED"
	ErrorCodePreviousStopFailed = "PREVIOUS_STOP_FAILED"
)

// ApplyResult is returned for every Apply attempt, including rejected and
// rolled-back candidates. Version always identifies the requested policy.
type ApplyResult struct {
	Version   uint64
	State     ApplyState
	ErrorCode string
}

// Engine serializes telemetry pipeline transitions. Candidate construction is
// deliberately outside the transition lock, while Start/Healthy/swap/Stop are
// one serialized two-phase transition so a concurrent Apply cannot stop a
// pipeline that another Apply has made active.
type Engine struct {
	builder Builder
	catalog Catalog

	transitionMu sync.Mutex
	active       Candidate
}

// NewEngine creates an empty telemetry engine. A nil builder is retained so
// Apply can return a structured rejection rather than panic.
func NewEngine(builder Builder) *Engine {
	return &Engine{builder: builder, catalog: NewCatalog()}
}

// ActiveVersion returns zero when no pipeline has been activated.
func (e *Engine) ActiveVersion() uint64 {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if e.active == nil {
		return 0
	}
	return e.active.Version()
}

// Apply compiles, starts, and health-checks a replacement before atomically
// publishing it. A pre-swap failure stops only the new candidate and keeps the
// old pipeline active. The active pipeline is stopped only after the swap.
func (e *Engine) Apply(ctx context.Context, p policy.Policy) (ApplyResult, error) {
	result := ApplyResult{Version: p.Version}

	// A repeated active version is a no-op. It bypasses compilation because the
	// already-active pipeline is the only accepted representation of that
	// version in this process.
	e.transitionMu.Lock()
	if e.active != nil && p.Version == e.active.Version() {
		e.transitionMu.Unlock()
		return ApplyResult{Version: p.Version, State: ApplyActive}, nil
	}
	e.transitionMu.Unlock()

	if err := policy.ValidateStructural(p); err != nil {
		e.transitionMu.Lock()
		defer e.transitionMu.Unlock()
		return e.preSwapFailure(result, ErrorCodeValidationFailed, err)
	}
	cfg, err := Compile(p, e.catalog)
	if err != nil {
		e.transitionMu.Lock()
		defer e.transitionMu.Unlock()
		return e.preSwapFailure(result, ErrorCodeCompileFailed, err)
	}

	// Build through old-pipeline retirement is serialized. Compilation above is
	// intentionally outside this critical lifecycle region.
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if e.active != nil {
		activeVersion := e.active.Version()
		switch {
		case p.Version == activeVersion:
			return ApplyResult{Version: p.Version, State: ApplyActive}, nil
		case p.Version < activeVersion:
			return ApplyResult{
				Version: p.Version, State: ApplyRejected, ErrorCode: ErrorCodeVersionRejected,
			}, fmt.Errorf("%w: active=%d incoming=%d", ErrPolicyVersionRollback, activeVersion, p.Version)
		}
	}
	if e.builder == nil {
		return e.preSwapFailure(result, ErrorCodeBuildFailed, errors.New("telemetry builder is required"))
	}

	candidate, err := e.builder.Build(ctx, cfg)
	if err != nil {
		return e.preSwapFailure(result, ErrorCodeBuildFailed, err)
	}
	if candidate == nil {
		return e.preSwapFailure(result, ErrorCodeBuildFailed, ErrNilCandidate)
	}
	if candidate.Version() != p.Version {
		return e.stopFailedCandidate(result, candidate, ErrorCodeCandidateVersion,
			fmt.Errorf("%w: candidate=%d policy=%d", ErrCandidateVersionMismatch, candidate.Version(), p.Version))
	}
	if err := candidate.Start(ctx); err != nil {
		return e.stopFailedCandidate(result, candidate, ErrorCodeStartFailed, err)
	}

	healthCtx, cancel := context.WithTimeout(ctx, defaultHealthCheckTimeout)
	err = candidate.Healthy(healthCtx)
	cancel()
	if err != nil {
		return e.stopFailedCandidate(result, candidate, ErrorCodeHealthCheckFailed, err)
	}

	old := e.active
	e.active = candidate
	if old == nil {
		return ApplyResult{Version: p.Version, State: ApplyActive}, nil
	}
	if err := stopCandidate(old); err != nil {
		return ApplyResult{Version: p.Version, State: ApplyActive, ErrorCode: ErrorCodePreviousStopFailed}, err
	}
	return ApplyResult{Version: p.Version, State: ApplyActive}, nil
}

func (e *Engine) preSwapFailure(result ApplyResult, code string, err error) (ApplyResult, error) {
	result.ErrorCode = code
	if e.active == nil {
		result.State = ApplyRejected
	} else {
		result.State = ApplyRolledBack
	}
	return result, err
}

func (e *Engine) stopFailedCandidate(result ApplyResult, candidate Candidate, code string, cause error) (ApplyResult, error) {
	if stopErr := stopCandidate(candidate); stopErr != nil {
		cause = fmt.Errorf("%w; candidate cleanup: %v", cause, stopErr)
	}
	return e.preSwapFailure(result, code, cause)
}

func stopCandidate(candidate Candidate) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultHealthCheckTimeout)
	defer cancel()
	return candidate.Stop(ctx)
}
