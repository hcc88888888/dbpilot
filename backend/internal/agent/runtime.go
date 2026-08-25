// Package agent supervises the embedded DBPilot telemetry components. It owns
// policy activation and orderly process shutdown; collection and delivery
// remain owned by the telemetry engine, spool, and exporter respectively.
package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
)

var (
	// ErrNoUsablePolicy means neither the stored policy nor the current remote
	// policy could be verified and activated at startup.
	ErrNoUsablePolicy      = errors.New("no usable telemetry policy")
	ErrInvalidDependencies = errors.New("invalid agent runtime dependencies")
)

// StartupError distinguishes an Agent that cannot safely collect because no
// last-known-good or remote signed policy was usable. Callers can use
// errors.Is(err, ErrNoUsablePolicy) while retaining the typed startup cause.
type StartupError struct{ Cause error }

func (e *StartupError) Error() string { return fmt.Sprintf("agent startup: %v", e.Cause) }
func (e *StartupError) Unwrap() error { return errors.Join(ErrNoUsablePolicy, e.Cause) }

const (
	defaultPollInterval    = 30 * time.Second
	defaultExportInterval  = 5 * time.Second
	defaultShutdownTimeout = 10 * time.Second
)

// PolicySource fetches only a signed DBPilot policy envelope. It has no raw
// receiver, collector, YAML, executable, or shell configuration surface.
type PolicySource interface {
	Fetch(context.Context) (policy.SignatureEnvelope, error)
}

// PolicyVerifier verifies the signature and runtime policy restrictions.
type PolicyVerifier interface {
	Verify(context.Context, policy.SignatureEnvelope) (policy.Policy, error)
}

// Engine is the lifecycle view Runtime needs from telemetry.Engine.
type Engine interface {
	Apply(context.Context, policy.Policy) (telemetry.ApplyResult, error)
	ActiveVersion() uint64
	Stop(context.Context) error
}

// Store is the narrow durable-state view used by Runtime. spool.Store
// implements it without exposing its segment representation.
type Store interface {
	ActivePolicy() (policy.SignatureEnvelope, error)
	PutPolicy(policy.SignatureEnvelope) error
	Seal() error
	Close() error
}

// Exporter sends pending data. exporter.Client implements this interface.
type Exporter interface {
	SendPending(context.Context) error
}

// PolicyStatus is a local, typed representation of the status reported to
// DBPilot. A transport adapter can map it to the protobuf contract.
type PolicyStatus struct {
	AgentID   string
	Version   uint64
	State     string
	ErrorCode string
	Reported  time.Time
}

// HealthReporter reports policy lifecycle outcomes. Reporting is best effort:
// loss of the server must never stop an already healthy collector pipeline.
type HealthReporter interface {
	Report(context.Context, PolicyStatus) error
}

// Dependencies makes runtime ownership explicit and keeps the supervisor
// independently testable from gRPC and collector component implementations.
type Dependencies struct {
	AgentID        string
	PolicySource   PolicySource
	PolicyVerifier PolicyVerifier
	Engine         Engine
	Store          Store
	Exporter       Exporter
	HealthReporter HealthReporter

	PollInterval    time.Duration
	ExportInterval  time.Duration
	ShutdownTimeout time.Duration
	Now             func() time.Time
}

// Runtime supervises one agent process. It never binds an administration
// listener; all remote interaction enters through the injected narrow ports.
type Runtime struct {
	deps Dependencies
}

func NewRuntime(deps Dependencies) *Runtime {
	if deps.PollInterval <= 0 {
		deps.PollInterval = defaultPollInterval
	}
	if deps.ExportInterval <= 0 {
		deps.ExportInterval = defaultExportInterval
	}
	if deps.ShutdownTimeout <= 0 {
		deps.ShutdownTimeout = defaultShutdownTimeout
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &Runtime{deps: deps}
}

// Run activates a last-known-good policy when possible, then polls for newer
// signed policies while exporting from the durable spool. Context cancellation
// is a normal process-stop path and returns nil after ordered shutdown.
func (r *Runtime) Run(ctx context.Context) error {
	if err := r.valid(); err != nil {
		return err
	}
	if ctx == nil {
		return fmt.Errorf("%w: context is required", ErrInvalidDependencies)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	usable := r.activateStored(runCtx)
	if runCtx.Err() == nil {
		if r.activateRemote(runCtx) {
			usable = true
		}
	}
	if !usable {
		_ = r.shutdown()
		return &StartupError{Cause: ErrNoUsablePolicy}
	}
	if runCtx.Err() != nil {
		return r.shutdown()
	}

	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		r.policyLoop(runCtx)
	}()
	go func() {
		defer workers.Done()
		r.exportLoop(runCtx)
	}()
	<-runCtx.Done()
	workers.Wait()
	return r.shutdown()
}

func (r *Runtime) valid() error {
	if r == nil || r.deps.AgentID == "" || r.deps.PolicySource == nil || r.deps.PolicyVerifier == nil || r.deps.Engine == nil || r.deps.Store == nil || r.deps.Exporter == nil || r.deps.HealthReporter == nil {
		return ErrInvalidDependencies
	}
	return nil
}

func (r *Runtime) activateStored(ctx context.Context) bool {
	envelope, err := r.deps.Store.ActivePolicy()
	if err != nil {
		return false
	}
	return r.verifyAndApply(ctx, envelope, false)
}

func (r *Runtime) activateRemote(ctx context.Context) bool {
	envelope, err := r.deps.PolicySource.Fetch(ctx)
	if err != nil {
		return false
	}
	return r.verifyAndApply(ctx, envelope, true)
}

func (r *Runtime) verifyAndApply(ctx context.Context, envelope policy.SignatureEnvelope, persist bool) bool {
	p, err := r.deps.PolicyVerifier.Verify(ctx, envelope)
	if err != nil {
		r.report(p.AgentID, envelope.Policy.Version, telemetry.ApplyRejected, "POLICY_VERIFICATION_FAILED")
		return false
	}
	if p.AgentID != r.deps.AgentID {
		r.report(p.AgentID, p.Version, telemetry.ApplyRejected, "POLICY_AGENT_MISMATCH")
		return false
	}
	if !persist && r.deps.Engine.ActiveVersion() == p.Version {
		return true
	}
	result, applyErr := r.deps.Engine.Apply(ctx, p)
	r.report(p.AgentID, result.Version, result.State, result.ErrorCode)
	if applyErr != nil || result.State != telemetry.ApplyActive {
		return false
	}
	if persist {
		if err := r.deps.Store.PutPolicy(envelope); err != nil {
			r.report(p.AgentID, p.Version, telemetry.ApplyRolledBack, "POLICY_PERSIST_FAILED")
			return false
		}
	}
	return true
}

func (r *Runtime) policyLoop(ctx context.Context) {
	ticker := time.NewTicker(r.deps.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = r.activateRemote(ctx)
		}
	}
}

func (r *Runtime) exportLoop(ctx context.Context) {
	ticker := time.NewTicker(r.deps.ExportInterval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		// exporter.Client retains batches and performs its own bounded retry
		// backoff. Its errors are deliberately isolated from collector health.
		_ = r.deps.Exporter.SendPending(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Runtime) report(agentID string, version uint64, state telemetry.ApplyState, code string) {
	if agentID == "" {
		agentID = r.deps.AgentID
	}
	ctx, cancel := context.WithTimeout(context.Background(), r.deps.ShutdownTimeout)
	defer cancel()
	_ = r.deps.HealthReporter.Report(ctx, PolicyStatus{
		AgentID: agentID, Version: version, State: string(state), ErrorCode: code, Reported: r.deps.Now().UTC(),
	})
}

// shutdown establishes the on-disk handoff boundary in the only safe order:
// stop receivers, seal what they produced, make one bounded delivery attempt,
// then close persistent state.
func (r *Runtime) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), r.deps.ShutdownTimeout)
	defer cancel()
	var errs []error
	if err := r.deps.Engine.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("stop receivers: %w", err))
	}
	if err := r.deps.Store.Seal(); err != nil {
		errs = append(errs, fmt.Errorf("seal spool: %w", err))
	}
	// A failed flush is already durable and must not prevent state closure.
	_ = r.deps.Exporter.SendPending(ctx)
	if err := r.deps.Store.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close spool: %w", err))
	}
	return errors.Join(errs...)
}

var (
	_ Engine = (*telemetry.Engine)(nil)
	_ Store  = (*spool.Store)(nil)
)
