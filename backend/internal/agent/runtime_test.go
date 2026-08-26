package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"github.com/stretchr/testify/require"
)

func TestRuntimeStartsFromLastValidPolicyWhileServerUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stored := signedEnvelope(7)
	engine := &fakeEngine{}
	source := &fakePolicySource{err: errors.New("server unavailable"), onFetch: func(int) { cancel() }}
	runtime := NewRuntime(Dependencies{
		AgentID:        "agent-a",
		PolicySource:   source,
		PolicyVerifier: fakeVerifier{},
		Engine:         engine,
		Store:          &fakeStore{stored: &stored},
		Exporter:       &fakeExporter{},
		HealthReporter: &fakeReporter{},
	})

	require.NoError(t, runtime.Run(ctx))
	require.Equal(t, uint64(7), engine.ActiveVersion())
	require.Equal(t, 1, source.Calls())
}

func TestRuntimeActivatesNewerRemotePolicyAndPersistsIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stored, remote := signedEnvelope(7), signedEnvelope(8)
	engine := &fakeEngine{onApply: func(p policy.Policy) {
		if p.Version == 8 {
			cancel()
		}
	}}
	store := &fakeStore{stored: &stored}
	reporter := &fakeReporter{}
	runtime := NewRuntime(Dependencies{
		AgentID: "agent-a", PolicySource: &fakePolicySource{envelopes: []policy.SignatureEnvelope{remote}},
		PolicyVerifier: fakeVerifier{}, Engine: engine, Store: store, Exporter: &fakeExporter{}, HealthReporter: reporter,
	})

	require.NoError(t, runtime.Run(ctx))
	require.Equal(t, uint64(8), engine.ActiveVersion())
	require.Equal(t, uint64(8), store.Saved().Policy.Version)
	require.Contains(t, reporter.States(), string(telemetry.ApplyActive))
}

func TestRuntimeRejectsInvalidRemotePolicyAndReportsStatus(t *testing.T) {
	bad := signedEnvelope(3)
	reporter := &fakeReporter{}
	runtime := NewRuntime(Dependencies{
		AgentID: "agent-a", PolicySource: &fakePolicySource{envelopes: []policy.SignatureEnvelope{bad}},
		PolicyVerifier: fakeVerifier{err: errors.New("signature is invalid")}, Engine: &fakeEngine{},
		Store: &fakeStore{}, Exporter: &fakeExporter{}, HealthReporter: reporter,
	})

	err := runtime.Run(context.Background())
	require.ErrorIs(t, err, ErrNoUsablePolicy)
	require.Contains(t, reporter.States(), string(telemetry.ApplyRejected))
}

func TestRuntimeReportsRollbackWhenCandidateActivationFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stored, remote := signedEnvelope(7), signedEnvelope(8)
	reporter := &fakeReporter{}
	engine := &fakeEngine{onApply: func(p policy.Policy) {
		if p.Version == 8 {
			cancel()
		}
	}, applyErr: errors.New("candidate unhealthy"), failVersion: 8}
	runtime := NewRuntime(Dependencies{
		AgentID: "agent-a", PolicySource: &fakePolicySource{envelopes: []policy.SignatureEnvelope{remote}},
		PolicyVerifier: fakeVerifier{}, Engine: engine, Store: &fakeStore{stored: &stored},
		Exporter: &fakeExporter{}, HealthReporter: reporter,
	})

	require.NoError(t, runtime.Run(ctx))
	require.Equal(t, uint64(7), engine.ActiveVersion())
	require.Contains(t, reporter.States(), string(telemetry.ApplyRolledBack))
}

func TestRuntimeRetriesExporterWithoutStoppingCollectors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stored := signedEnvelope(1)
	exporter := &fakeExporter{err: errors.New("gateway offline"), onSend: func(calls int) {
		if calls == 2 {
			cancel()
		}
	}}
	engine := &fakeEngine{}
	runtime := NewRuntime(Dependencies{
		AgentID: "agent-a", PolicySource: &fakePolicySource{err: errors.New("offline")}, PolicyVerifier: fakeVerifier{},
		Engine: engine, Store: &fakeStore{stored: &stored}, Exporter: exporter, HealthReporter: &fakeReporter{},
		ExportInterval: time.Millisecond,
	})

	require.NoError(t, runtime.Run(ctx))
	require.GreaterOrEqual(t, exporter.Calls(), 2)
	require.Equal(t, 1, engine.StopCalls(), "collectors stop only during shutdown")
}

func TestRuntimeReturnsCleanlyWhenItsContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	stored := signedEnvelope(1)
	runtime := NewRuntime(Dependencies{
		AgentID: "agent-a", PolicySource: &fakePolicySource{err: errors.New("offline")}, PolicyVerifier: fakeVerifier{},
		Engine: &fakeEngine{onApply: func(policy.Policy) { cancel() }}, Store: &fakeStore{stored: &stored},
		Exporter: &fakeExporter{}, HealthReporter: &fakeReporter{},
	})

	require.NoError(t, runtime.Run(ctx))
}

func TestRuntimeShutsDownInReceiverSealFlushCloseOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stored := signedEnvelope(1)
	events := &eventLog{}
	runtime := NewRuntime(Dependencies{
		AgentID: "agent-a", PolicySource: &fakePolicySource{err: errors.New("offline")}, PolicyVerifier: fakeVerifier{},
		Engine: &fakeEngine{events: events, onApply: func(policy.Policy) { cancel() }},
		Store:  &fakeStore{stored: &stored, events: events}, Exporter: &fakeExporter{events: events}, HealthReporter: &fakeReporter{},
	})

	require.NoError(t, runtime.Run(ctx))
	require.Equal(t, []string{"stop", "seal", "flush", "close"}, events.Values())
}

func TestRuntimeRunsAndClosesComponentCollectorBeforeSpoolSeal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stored := signedEnvelope(1)
	events := &eventLog{}
	componentCollector := &fakeComponentCollector{events: events, onRun: cancel}
	runtime := NewRuntime(Dependencies{
		AgentID: "agent-a", PolicySource: &fakePolicySource{err: errors.New("offline")}, PolicyVerifier: fakeVerifier{},
		Engine: &fakeEngine{events: events}, Store: &fakeStore{stored: &stored, events: events},
		Exporter: &fakeExporter{}, HealthReporter: &fakeReporter{}, ComponentCollector: componentCollector,
	})

	require.NoError(t, runtime.Run(ctx))
	require.True(t, componentCollector.Ran())
	values := events.Values()
	require.Less(t, eventIndex(values, "component-close"), eventIndex(values, "seal"))
}

func TestRuntimeReturnsAndReportsComponentCollectorFailure(t *testing.T) {
	stored := signedEnvelope(1)
	reporter := &fakeReporter{}
	collectorErr := errors.New("append dependency telemetry: spool unavailable")
	componentCollector := &fakeComponentCollector{runErr: collectorErr}
	runtime := NewRuntime(Dependencies{
		AgentID: "agent-a", PolicySource: &fakePolicySource{err: errors.New("offline")}, PolicyVerifier: fakeVerifier{},
		Engine: &fakeEngine{}, Store: &fakeStore{stored: &stored}, Exporter: &fakeExporter{},
		HealthReporter: reporter, ComponentCollector: componentCollector,
	})

	err := runtime.Run(context.Background())
	require.ErrorIs(t, err, collectorErr)
	require.Contains(t, reporter.States(), "DEGRADED")
	require.Contains(t, reporter.ErrorCodes(), "COMPONENT_COLLECTOR_FAILED")
}

func signedEnvelope(version uint64) policy.SignatureEnvelope {
	return policy.SignatureEnvelope{Policy: policy.Policy{
		AgentID: "agent-a", Version: version, IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		Sources: []policy.Source{{ID: "host", Kind: policy.SourceHostMetrics, Interval: 5 * time.Second}},
		Limits:  policy.Limits{MaxSpoolBytes: 1 << 20, MaxBatchBytes: 1 << 16, MaxEventsPerSec: 100},
	}}
}

type fakePolicySource struct {
	mu        sync.Mutex
	envelopes []policy.SignatureEnvelope
	err       error
	calls     int
	onFetch   func(int)
}

func (s *fakePolicySource) Fetch(context.Context) (policy.SignatureEnvelope, error) {
	s.mu.Lock()
	s.calls++
	calls := s.calls
	onFetch := s.onFetch
	err := s.err
	if len(s.envelopes) == 0 {
		s.mu.Unlock()
		if onFetch != nil {
			onFetch(calls)
		}
		if err != nil {
			return policy.SignatureEnvelope{}, err
		}
		return policy.SignatureEnvelope{}, errors.New("no policy")
	}
	envelope := s.envelopes[0]
	if len(s.envelopes) > 1 {
		s.envelopes = s.envelopes[1:]
	}
	s.mu.Unlock()
	if onFetch != nil {
		onFetch(calls)
	}
	if err != nil {
		return policy.SignatureEnvelope{}, err
	}
	return envelope, nil
}
func (s *fakePolicySource) Calls() int { s.mu.Lock(); defer s.mu.Unlock(); return s.calls }

type fakeVerifier struct{ err error }

func (v fakeVerifier) Verify(_ context.Context, envelope policy.SignatureEnvelope) (policy.Policy, error) {
	if v.err != nil {
		return policy.Policy{}, v.err
	}
	return envelope.Policy, nil
}

type fakeEngine struct {
	mu          sync.Mutex
	active      uint64
	applyErr    error
	failVersion uint64
	onApply     func(policy.Policy)
	stops       int
	events      *eventLog
}

func (e *fakeEngine) Apply(_ context.Context, p policy.Policy) (telemetry.ApplyResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.onApply != nil {
		defer e.onApply(p)
	}
	if e.failVersion == p.Version {
		return telemetry.ApplyResult{Version: p.Version, State: telemetry.ApplyRolledBack, ErrorCode: telemetry.ErrorCodeHealthCheckFailed}, e.applyErr
	}
	e.active = p.Version
	return telemetry.ApplyResult{Version: p.Version, State: telemetry.ApplyActive}, nil
}
func (e *fakeEngine) ActiveVersion() uint64 { e.mu.Lock(); defer e.mu.Unlock(); return e.active }
func (e *fakeEngine) Stop(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stops++
	if e.events != nil {
		e.events.Add("stop")
	}
	return nil
}
func (e *fakeEngine) StopCalls() int { e.mu.Lock(); defer e.mu.Unlock(); return e.stops }

type fakeStore struct {
	mu     sync.Mutex
	stored *policy.SignatureEnvelope
	saved  *policy.SignatureEnvelope
	events *eventLog
}

func (s *fakeStore) ActivePolicy() (policy.SignatureEnvelope, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stored == nil {
		return policy.SignatureEnvelope{}, spool.ErrNoActivePolicy
	}
	return *s.stored, nil
}
func (s *fakeStore) PutPolicy(envelope policy.SignatureEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = &envelope
	s.stored = &envelope
	return nil
}
func (s *fakeStore) Seal() error {
	if s.events != nil {
		s.events.Add("seal")
	}
	return nil
}
func (s *fakeStore) Close() error {
	if s.events != nil {
		s.events.Add("close")
	}
	return nil
}
func (s *fakeStore) Saved() policy.SignatureEnvelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saved == nil {
		return policy.SignatureEnvelope{}
	}
	return *s.saved
}

type fakeExporter struct {
	mu     sync.Mutex
	err    error
	calls  int
	onSend func(int)
	events *eventLog
}

func (e *fakeExporter) SendPending(context.Context) error {
	e.mu.Lock()
	e.calls++
	calls := e.calls
	e.mu.Unlock()
	if e.events != nil {
		e.events.Add("flush")
	}
	if e.onSend != nil {
		e.onSend(calls)
	}
	return e.err
}
func (e *fakeExporter) Calls() int { e.mu.Lock(); defer e.mu.Unlock(); return e.calls }

type fakeReporter struct {
	mu       sync.Mutex
	statuses []PolicyStatus
}

type fakeComponentCollector struct {
	mu     sync.Mutex
	events *eventLog
	onRun  func()
	ran    bool
	runErr error
}

func (collector *fakeComponentCollector) Run(ctx context.Context) error {
	collector.mu.Lock()
	collector.ran = true
	collector.mu.Unlock()
	if collector.events != nil {
		collector.events.Add("component-run")
	}
	if collector.onRun != nil {
		collector.onRun()
	}
	if collector.runErr != nil {
		return collector.runErr
	}
	<-ctx.Done()
	return nil
}

func (collector *fakeComponentCollector) Close() error {
	if collector.events != nil {
		collector.events.Add("component-close")
	}
	return nil
}

func (collector *fakeComponentCollector) Ran() bool {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return collector.ran
}

func eventIndex(values []string, expected string) int {
	for index, value := range values {
		if value == expected {
			return index
		}
	}
	return len(values)
}

func (r *fakeReporter) Report(_ context.Context, status PolicyStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statuses = append(r.statuses, status)
	return nil
}
func (r *fakeReporter) States() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	states := make([]string, 0, len(r.statuses))
	for _, status := range r.statuses {
		states = append(states, status.State)
	}
	return states
}
func (r *fakeReporter) ErrorCodes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	codes := make([]string, 0, len(r.statuses))
	for _, status := range r.statuses {
		codes = append(codes, status.ErrorCode)
	}
	return codes
}

type eventLog struct {
	mu     sync.Mutex
	values []string
}

func (l *eventLog) Add(value string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.values = append(l.values, value)
}
func (l *eventLog) Values() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.values...)
}
