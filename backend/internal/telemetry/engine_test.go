package telemetry_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"github.com/stretchr/testify/require"
)

func TestApplyActivatesFirstHealthyCandidate(t *testing.T) {
	candidate := healthyCandidate(1)
	builder := newFakeBuilder(candidate)
	engine := telemetry.NewEngine(builder)

	result, err := engine.Apply(context.Background(), policyVersion(1))
	require.NoError(t, err)
	require.Equal(t, telemetry.ApplyActive, result.State)
	require.Equal(t, uint64(1), result.Version)
	require.Empty(t, result.ErrorCode)
	require.Equal(t, uint64(1), engine.ActiveVersion())
	require.Equal(t, 1, candidate.StartCalls())
	require.Equal(t, 1, candidate.HealthyCalls())
	require.False(t, candidate.Stopped())
}

func TestEmbeddedBuilderRejectsTypedNilSpool(t *testing.T) {
	var store *typedNilSpoolAppender
	cfg, err := telemetry.Compile(policyVersion(1), telemetry.NewCatalog())
	require.NoError(t, err)

	_, err = telemetry.NewEmbeddedBuilder(store).Build(context.Background(), cfg)

	require.ErrorContains(t, err, "requires a spool")
}

func TestEnginePublishesOnlyActivePolicyBatchLimit(t *testing.T) {
	first := healthyCandidate(1)
	rejected := unhealthyCandidate(2)
	third := healthyCandidate(3)
	engine := telemetry.NewEngine(newFakeBuilder(first, rejected, third))
	require.Zero(t, engine.BatchMaxBytes())

	result, err := engine.Apply(context.Background(), policyWithBatchLimit(1, 2048))
	require.NoError(t, err)
	require.Equal(t, telemetry.ApplyActive, result.State)
	require.Equal(t, int64(2048), engine.BatchMaxBytes())

	result, err = engine.Apply(context.Background(), policyWithBatchLimit(2, 1024))
	require.Error(t, err)
	require.Equal(t, telemetry.ApplyRolledBack, result.State)
	require.Equal(t, int64(2048), engine.BatchMaxBytes(), "failed activation must retain the active policy limit")

	result, err = engine.Apply(context.Background(), policyWithBatchLimit(3, 512))
	require.NoError(t, err)
	require.Equal(t, telemetry.ApplyActive, result.State)
	require.Equal(t, int64(512), engine.BatchMaxBytes())
	require.NoError(t, engine.Stop(context.Background()))
	require.Zero(t, engine.BatchMaxBytes())
}

type typedNilSpoolAppender struct{}

func (*typedNilSpoolAppender) Append(context.Context, spool.DataClass, spool.Batch) error { return nil }

func TestApplyRejectsBuildFailureWithoutAnActivePipeline(t *testing.T) {
	builder := newFakeBuilder()
	builder.buildErr = errors.New("cannot build pipeline")
	engine := telemetry.NewEngine(builder)

	result, err := engine.Apply(context.Background(), policyVersion(1))
	require.ErrorIs(t, err, builder.buildErr)
	require.Equal(t, telemetry.ApplyRejected, result.State)
	require.Equal(t, uint64(1), result.Version)
	require.Equal(t, telemetry.ErrorCodeBuildFailed, result.ErrorCode)
	require.Zero(t, engine.ActiveVersion())
}

func TestApplyKeepsOldPipelineWhenCandidateUnhealthy(t *testing.T) {
	oldCandidate := healthyCandidate(1)
	newCandidate := unhealthyCandidate(2)
	builder := newFakeBuilder(oldCandidate, newCandidate)
	engine := telemetry.NewEngine(builder)
	requireApplyActive(t, engine, 1)

	result, err := engine.Apply(context.Background(), policyVersion(2))
	require.ErrorIs(t, err, newCandidate.healthyErr)
	require.Equal(t, telemetry.ApplyRolledBack, result.State)
	require.Equal(t, uint64(2), result.Version)
	require.Equal(t, telemetry.ErrorCodeHealthCheckFailed, result.ErrorCode)
	require.Equal(t, uint64(1), engine.ActiveVersion())
	require.False(t, oldCandidate.Stopped())
	require.True(t, newCandidate.Stopped())
}

func TestApplyReplacesHealthyPipeline(t *testing.T) {
	oldCandidate := healthyCandidate(1)
	newCandidate := healthyCandidate(2)
	builder := newFakeBuilder(oldCandidate, newCandidate)
	engine := telemetry.NewEngine(builder)
	requireApplyActive(t, engine, 1)

	result, err := engine.Apply(context.Background(), policyVersion(2))
	require.NoError(t, err)
	require.Equal(t, telemetry.ApplyActive, result.State)
	require.Equal(t, uint64(2), result.Version)
	require.Empty(t, result.ErrorCode)
	require.Equal(t, uint64(2), engine.ActiveVersion())
	require.True(t, oldCandidate.Stopped())
	require.False(t, newCandidate.Stopped())
}

func TestApplyReplacesPipelineOnlyAfterNewCandidateIsHealthy(t *testing.T) {
	events := &eventLog{}
	oldCandidate := healthyCandidateWithEvents(1, events)
	newCandidate := healthyCandidateWithEvents(2, events)
	builder := newFakeBuilder(oldCandidate, newCandidate)
	engine := telemetry.NewEngine(builder)
	requireApplyActive(t, engine, 1)

	result, err := engine.Apply(context.Background(), policyVersion(2))
	require.NoError(t, err)
	require.Equal(t, telemetry.ApplyActive, result.State)
	require.Equal(t, uint64(2), engine.ActiveVersion())
	require.True(t, oldCandidate.Stopped())
	require.False(t, newCandidate.Stopped())
	require.Less(t, events.indexOf("2:healthy"), events.indexOf("1:stop"), "old pipeline stopped before the replacement was healthy")
}

func TestApplySameVersionIsIdempotent(t *testing.T) {
	candidate := healthyCandidate(1)
	builder := newFakeBuilder(candidate)
	engine := telemetry.NewEngine(builder)
	requireApplyActive(t, engine, 1)

	result, err := engine.Apply(context.Background(), policyVersion(1))
	require.NoError(t, err)
	require.Equal(t, telemetry.ApplyActive, result.State)
	require.Equal(t, uint64(1), result.Version)
	require.Equal(t, 1, builder.BuildCalls())
	require.Equal(t, 1, candidate.StartCalls())
	require.Equal(t, 1, candidate.HealthyCalls())
}

func TestApplyRejectsLowerPolicyVersion(t *testing.T) {
	candidate := healthyCandidate(2)
	builder := newFakeBuilder(candidate)
	engine := telemetry.NewEngine(builder)
	requireApplyActive(t, engine, 2)

	result, err := engine.Apply(context.Background(), policyVersion(1))
	require.ErrorIs(t, err, telemetry.ErrPolicyVersionRollback)
	require.Equal(t, telemetry.ApplyRejected, result.State)
	require.Equal(t, uint64(1), result.Version)
	require.Equal(t, telemetry.ErrorCodeVersionRejected, result.ErrorCode)
	require.Equal(t, uint64(2), engine.ActiveVersion())
	require.Equal(t, 1, builder.BuildCalls())
}

func TestStopRetiresTheActivePipeline(t *testing.T) {
	candidate := healthyCandidate(1)
	engine := telemetry.NewEngine(newFakeBuilder(candidate))
	requireApplyActive(t, engine, 1)

	require.NoError(t, engine.Stop(context.Background()))
	require.True(t, candidate.Stopped())
	require.Zero(t, engine.ActiveVersion())
}

func TestApplySerializesConcurrentLifecycleTransitions(t *testing.T) {
	firstCandidate := healthyCandidate(1)
	secondCandidate := healthyCandidate(2)
	builder := newFakeBuilder(firstCandidate, secondCandidate)
	builder.blockFirstBuild = true
	engine := telemetry.NewEngine(builder)

	firstDone := make(chan error, 1)
	go func() {
		_, err := engine.Apply(context.Background(), policyVersion(1))
		firstDone <- err
	}()
	<-builder.firstBuildEntered

	secondDone := make(chan error, 1)
	go func() {
		_, err := engine.Apply(context.Background(), policyVersion(2))
		secondDone <- err
	}()
	close(builder.releaseFirstBuild)

	require.NoError(t, <-firstDone)
	require.NoError(t, <-secondDone)
	require.Equal(t, int32(1), builder.MaxConcurrentBuilds())
	require.Equal(t, uint64(2), engine.ActiveVersion())
	require.True(t, firstCandidate.Stopped())
	require.False(t, secondCandidate.Stopped())
}

func requireApplyActive(t *testing.T, engine *telemetry.Engine, version uint64) {
	t.Helper()
	result, err := engine.Apply(context.Background(), policyVersion(version))
	require.NoError(t, err)
	require.Equal(t, telemetry.ApplyActive, result.State)
}

func policyVersion(version uint64) policy.Policy {
	return policy.Policy{
		AgentID: "engine-test-agent", Version: version,
		IssuedAt:  time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC),
		Sources:   []policy.Source{{ID: "host", Kind: policy.SourceHostMetrics, Interval: 5 * time.Second}},
		Limits:    policy.Limits{MaxSpoolBytes: 4 << 20, MaxBatchBytes: 1 << 20, MaxEventsPerSec: 100},
	}
}

func policyWithBatchLimit(version uint64, limit int64) policy.Policy {
	value := policyVersion(version)
	value.Limits.MaxBatchBytes = limit
	return value
}

type fakeBuilder struct {
	mu                sync.Mutex
	candidates        []*fakeCandidate
	buildErr          error
	buildCalls        int
	concurrentBuilds  atomic.Int32
	maxConcurrent     atomic.Int32
	blockFirstBuild   bool
	firstBuildEntered chan struct{}
	releaseFirstBuild chan struct{}
}

func newFakeBuilder(candidates ...*fakeCandidate) *fakeBuilder {
	return &fakeBuilder{
		candidates:        candidates,
		firstBuildEntered: make(chan struct{}),
		releaseFirstBuild: make(chan struct{}),
	}
}

func (b *fakeBuilder) Build(_ context.Context, _ telemetry.RuntimeConfig) (telemetry.Candidate, error) {
	concurrent := b.concurrentBuilds.Add(1)
	defer b.concurrentBuilds.Add(-1)
	for {
		maximum := b.maxConcurrent.Load()
		if concurrent <= maximum || b.maxConcurrent.CompareAndSwap(maximum, concurrent) {
			break
		}
	}

	b.mu.Lock()
	b.buildCalls++
	buildNumber := b.buildCalls
	buildErr := b.buildErr
	var candidate *fakeCandidate
	if len(b.candidates) > 0 {
		candidate = b.candidates[0]
		b.candidates = b.candidates[1:]
	}
	block := b.blockFirstBuild && buildNumber == 1
	b.mu.Unlock()

	if block {
		close(b.firstBuildEntered)
		<-b.releaseFirstBuild
	}
	if buildErr != nil {
		return nil, buildErr
	}
	if candidate == nil {
		return nil, errors.New("unexpected Build call")
	}
	return candidate, nil
}

func (b *fakeBuilder) BuildCalls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buildCalls
}

func (b *fakeBuilder) MaxConcurrentBuilds() int32 { return b.maxConcurrent.Load() }

type fakeCandidate struct {
	version    uint64
	startErr   error
	healthyErr error
	stopErr    error
	events     *eventLog
	started    atomic.Int32
	healthy    atomic.Int32
	stopped    atomic.Bool
}

func healthyCandidate(version uint64) *fakeCandidate { return &fakeCandidate{version: version} }

func healthyCandidateWithEvents(version uint64, events *eventLog) *fakeCandidate {
	return &fakeCandidate{version: version, events: events}
}

func unhealthyCandidate(version uint64) *fakeCandidate {
	return &fakeCandidate{version: version, healthyErr: errors.New("candidate is unhealthy")}
}

func (c *fakeCandidate) Start(context.Context) error {
	c.started.Add(1)
	c.record("start")
	return c.startErr
}

func (c *fakeCandidate) Healthy(context.Context) error {
	c.healthy.Add(1)
	c.record("healthy")
	return c.healthyErr
}

func (c *fakeCandidate) Stop(context.Context) error {
	c.stopped.Store(true)
	c.record("stop")
	return c.stopErr
}

func (c *fakeCandidate) Version() uint64   { return c.version }
func (c *fakeCandidate) StartCalls() int   { return int(c.started.Load()) }
func (c *fakeCandidate) HealthyCalls() int { return int(c.healthy.Load()) }
func (c *fakeCandidate) Stopped() bool     { return c.stopped.Load() }

func (c *fakeCandidate) record(action string) {
	if c.events != nil {
		c.events.add(strconv.FormatUint(c.version, 10) + ":" + action)
	}
}

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(event string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}

func (l *eventLog) indexOf(event string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for index, value := range l.events {
		if value == event {
			return index
		}
	}
	return -1
}
