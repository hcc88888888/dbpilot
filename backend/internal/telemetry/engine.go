package telemetry

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/receiver"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"
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

// SpoolAppender is the narrow durability boundary used by the concrete
// collector exporter. spool.Store satisfies it without exposing its segment
// representation to OTel components.
type SpoolAppender interface {
	Append(context.Context, spool.DataClass, spool.Batch) error
}

// EmbeddedBuilder instantiates only the receivers and processors in the
// DBPilot catalog and routes their output to the local durable spool.
type EmbeddedBuilder struct{ spool SpoolAppender }

func NewEmbeddedBuilder(store SpoolAppender) EmbeddedBuilder { return EmbeddedBuilder{spool: store} }

func (b EmbeddedBuilder) Build(ctx context.Context, cfg RuntimeConfig) (Candidate, error) {
	if b.spool == nil {
		return nil, errors.New("embedded collector requires a spool")
	}
	if err := validateEmbeddedGraph(cfg); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	candidate := &embeddedCandidate{
		version: cfg.PolicyVersion(),
		host:    embeddedHost{extensions: make(map[component.ID]component.Component)},
	}
	settings := component.TelemetrySettings{
		Logger:         zap.NewNop(),
		TracerProvider: tracenoop.NewTracerProvider(),
		MeterProvider:  metricnoop.NewMeterProvider(),
	}
	catalog := NewCatalog().(*catalog)
	if err := candidate.buildExtensions(ctx, cfg, catalog, settings); err != nil {
		return nil, err
	}
	if err := candidate.buildPipelines(ctx, cfg, catalog, settings, b.spool); err != nil {
		_ = candidate.Stop(context.Background())
		return nil, err
	}
	return candidate, nil
}

func validateEmbeddedGraph(cfg RuntimeConfig) error {
	if cfg.PolicyVersion() == 0 || len(cfg.receivers) == 0 || len(cfg.pipelines) == 0 {
		return errors.New("invalid embedded collector graph")
	}
	exporter, ok := cfg.Exporter("dbpilot")
	if !ok || exporter.MaxBatchBytes <= 0 {
		return errors.New("invalid DBPilot spool exporter")
	}
	for receiverID, source := range cfg.sources {
		receiver, ok := cfg.receivers[receiverID]
		if !ok || receiver.id != receiverID || receiver.kind == "" || source.PipelineID == "" {
			return fmt.Errorf("invalid receiver graph entry %q", receiverID)
		}
		pipeline, ok := cfg.pipelines[source.PipelineID]
		if !ok || !containsID(pipeline.receiverIDs, receiverID) || !containsID(pipeline.exporterIDs, "dbpilot") {
			return fmt.Errorf("receiver %q is not routed to DBPilot spool exporter", receiverID)
		}
		for _, processorID := range pipeline.processorIDs {
			if _, ok := cfg.processors[processorID]; !ok {
				return fmt.Errorf("pipeline %q references unknown processor %q", pipeline.id, processorID)
			}
		}
	}
	return nil
}

func containsID(ids []string, target string) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

type embeddedCandidate struct {
	version uint64
	host    embeddedHost

	mu         sync.Mutex
	started    bool
	stopped    bool
	extensions []extension.Extension
	processors []component.Component
	receivers  []component.Component
}

func (c *embeddedCandidate) Version() uint64 { return c.version }

func (c *embeddedCandidate) buildExtensions(ctx context.Context, cfg RuntimeConfig, allowed *catalog, settings component.TelemetrySettings) error {
	for _, extensionID := range sortedKeys(cfg.extensions) {
		entry := cfg.extensions[extensionID]
		if entry.kind != "file_storage" || allowed.fileStorageFactory() == nil {
			return fmt.Errorf("unsupported embedded extension %q", extensionID)
		}
		id, err := componentID(extensionID)
		if err != nil {
			return err
		}
		componentExtension, err := allowed.fileStorageFactory().Create(ctx, extension.Settings{ID: id, TelemetrySettings: settings}, entry.config)
		if err != nil {
			return fmt.Errorf("create extension %q: %w", extensionID, err)
		}
		c.extensions = append(c.extensions, componentExtension)
		c.host.extensions[id] = componentExtension
	}
	return nil
}

func (c *embeddedCandidate) buildPipelines(ctx context.Context, cfg RuntimeConfig, allowed *catalog, settings component.TelemetrySettings, store SpoolAppender) error {
	exporter, _ := cfg.Exporter("dbpilot")
	logNext, err := newSpoolLogsConsumer(store, exporter)
	if err != nil {
		return err
	}
	metricNext, err := newSpoolMetricsConsumer(store, exporter)
	if err != nil {
		return err
	}
	logProcessors, err := c.buildLogProcessors(ctx, cfg, allowed, settings, logNext)
	if err != nil {
		return err
	}
	metricProcessors, err := c.buildMetricProcessors(ctx, cfg, allowed, settings, metricNext)
	if err != nil {
		return err
	}
	for _, receiverID := range cfg.ReceiverIDs() {
		entry := cfg.receivers[receiverID]
		source := cfg.sources[receiverID]
		factory, ok := allowed.ReceiverFactory(entry.kind)
		if !ok {
			return fmt.Errorf("receiver %q is not in the embedded catalog", entry.kind)
		}
		id, err := componentID(receiverID)
		if err != nil {
			return err
		}
		receiverSettings := receiver.Settings{ID: id, TelemetrySettings: settings}
		switch source.PipelineID {
		case logsPipelineID:
			next, err := tagLogsConsumer(logProcessors, source.ResourceAttributes)
			if err != nil {
				return err
			}
			componentReceiver, err := factory.CreateLogs(ctx, receiverSettings, entry.config, next)
			if err != nil {
				return fmt.Errorf("create log receiver %q: %w", receiverID, err)
			}
			c.receivers = append(c.receivers, componentReceiver)
		case metricsPipelineID:
			next, err := tagMetricsConsumer(metricProcessors, source.ResourceAttributes)
			if err != nil {
				return err
			}
			componentReceiver, err := factory.CreateMetrics(ctx, receiverSettings, entry.config, next)
			if err != nil {
				return fmt.Errorf("create metrics receiver %q: %w", receiverID, err)
			}
			c.receivers = append(c.receivers, componentReceiver)
		default:
			return fmt.Errorf("unsupported pipeline %q", source.PipelineID)
		}
	}
	return nil
}

func (c *embeddedCandidate) buildLogProcessors(ctx context.Context, cfg RuntimeConfig, allowed *catalog, settings component.TelemetrySettings, next consumer.Logs) (consumer.Logs, error) {
	for index := len(cfg.ProcessorIDs()) - 1; index >= 0; index-- {
		processorID := cfg.ProcessorIDs()[index]
		entry := cfg.processors[processorID]
		factory, ok := allowed.ProcessorFactory(entry.kind)
		if !ok {
			return nil, fmt.Errorf("processor %q is not in the embedded catalog", entry.kind)
		}
		id, err := componentID(processorID)
		if err != nil {
			return nil, err
		}
		componentProcessor, err := factory.CreateLogs(ctx, processor.Settings{ID: id, TelemetrySettings: settings}, entry.config, next)
		if err != nil {
			return nil, fmt.Errorf("create log processor %q: %w", processorID, err)
		}
		c.processors = append(c.processors, componentProcessor)
		next = componentProcessor
	}
	return next, nil
}

func (c *embeddedCandidate) buildMetricProcessors(ctx context.Context, cfg RuntimeConfig, allowed *catalog, settings component.TelemetrySettings, next consumer.Metrics) (consumer.Metrics, error) {
	for index := len(cfg.ProcessorIDs()) - 1; index >= 0; index-- {
		processorID := cfg.ProcessorIDs()[index]
		entry := cfg.processors[processorID]
		factory, ok := allowed.ProcessorFactory(entry.kind)
		if !ok {
			return nil, fmt.Errorf("processor %q is not in the embedded catalog", entry.kind)
		}
		id, err := componentID(processorID)
		if err != nil {
			return nil, err
		}
		componentProcessor, err := factory.CreateMetrics(ctx, processor.Settings{ID: id, TelemetrySettings: settings}, entry.config, next)
		if err != nil {
			return nil, fmt.Errorf("create metrics processor %q: %w", processorID, err)
		}
		c.processors = append(c.processors, componentProcessor)
		next = componentProcessor
	}
	return next, nil
}

func componentID(raw string) (component.ID, error) {
	var id component.ID
	if err := id.UnmarshalText([]byte(raw)); err != nil {
		return component.ID{}, fmt.Errorf("invalid component ID %q: %w", raw, err)
	}
	return id, nil
}

func (c *embeddedCandidate) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started && !c.stopped {
		return nil
	}
	if c.stopped {
		return errors.New("embedded collector has been stopped")
	}
	if ctx == nil {
		return errors.New("embedded collector start requires a context")
	}
	for _, componentExtension := range c.extensions {
		if err := componentExtension.Start(ctx, &c.host); err != nil {
			c.shutdownLocked(context.Background())
			return fmt.Errorf("start embedded extension: %w", err)
		}
	}
	for _, componentProcessor := range c.processors {
		if err := componentProcessor.Start(ctx, &c.host); err != nil {
			c.shutdownLocked(context.Background())
			return fmt.Errorf("start embedded processor: %w", err)
		}
	}
	for _, componentReceiver := range c.receivers {
		if err := componentReceiver.Start(ctx, &c.host); err != nil {
			c.shutdownLocked(context.Background())
			return fmt.Errorf("start embedded receiver: %w", err)
		}
	}
	c.started = true
	return nil
}

func (c *embeddedCandidate) Healthy(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started || c.stopped || len(c.receivers) == 0 || len(c.processors) == 0 {
		return errors.New("embedded collector components are not running")
	}
	if err := c.host.failure(); err != nil {
		return fmt.Errorf("embedded collector component unhealthy: %w", err)
	}
	for _, componentReceiver := range c.receivers {
		if componentReceiver == nil {
			return errors.New("embedded collector receiver is unavailable")
		}
	}
	return nil
}

func (c *embeddedCandidate) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return nil
	}
	c.stopped = true
	return c.shutdownLocked(ctx)
}

func (c *embeddedCandidate) shutdownLocked(ctx context.Context) error {
	var errs []error
	for index := len(c.receivers) - 1; index >= 0; index-- {
		if err := c.receivers[index].Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	for index := len(c.processors) - 1; index >= 0; index-- {
		if err := c.processors[index].Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	for index := len(c.extensions) - 1; index >= 0; index-- {
		if err := c.extensions[index].Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type embeddedHost struct {
	mu         sync.Mutex
	extensions map[component.ID]component.Component
	fatal      error
}

func (h *embeddedHost) GetExtensions() map[component.ID]component.Component {
	return maps.Clone(h.extensions)
}

// Report receives OTel component status changes. Fatal, permanent, and
// unexpected stopped states make the candidate unhealthy until it is retired.
func (h *embeddedHost) Report(event *componentstatus.Event) {
	if event == nil {
		return
	}
	status := event.Status()
	if status != componentstatus.StatusFatalError && status != componentstatus.StatusPermanentError && status != componentstatus.StatusStopped {
		return
	}
	err := event.Err()
	if err == nil {
		err = fmt.Errorf("component status %s", status)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fatal == nil {
		h.fatal = err
	}
}

func (h *embeddedHost) failure() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fatal
}

func tagLogsConsumer(next consumer.Logs, attributes map[string]string) (consumer.Logs, error) {
	return consumer.NewLogs(func(ctx context.Context, logs plog.Logs) error {
		for index := 0; index < logs.ResourceLogs().Len(); index++ {
			resource := logs.ResourceLogs().At(index).Resource().Attributes()
			for key, value := range attributes {
				resource.PutStr(key, value)
			}
		}
		return next.ConsumeLogs(ctx, logs)
	})
}

func tagMetricsConsumer(next consumer.Metrics, attributes map[string]string) (consumer.Metrics, error) {
	return consumer.NewMetrics(func(ctx context.Context, metrics pmetric.Metrics) error {
		for index := 0; index < metrics.ResourceMetrics().Len(); index++ {
			resource := metrics.ResourceMetrics().At(index).Resource().Attributes()
			for key, value := range attributes {
				resource.PutStr(key, value)
			}
		}
		return next.ConsumeMetrics(ctx, metrics)
	})
}

type spoolLogsConsumer struct {
	store    SpoolAppender
	exporter ExporterConfig
}

func newSpoolLogsConsumer(store SpoolAppender, exporter ExporterConfig) (consumer.Logs, error) {
	c := &spoolLogsConsumer{store: store, exporter: exporter}
	return consumer.NewLogs(c.ConsumeLogs)
}

func (c *spoolLogsConsumer) ConsumeLogs(ctx context.Context, logs plog.Logs) error {
	for index := 0; index < logs.ResourceLogs().Len(); index++ {
		one := plog.NewLogs()
		logs.ResourceLogs().At(index).CopyTo(one.ResourceLogs().AppendEmpty())
		payload, err := (&plog.ProtoMarshaler{}).MarshalLogs(one)
		if err != nil {
			return err
		}
		if err := c.exporter.ValidateBatchBytes(int64(len(payload))); err != nil {
			return err
		}
		id, err := newSpoolBatchID()
		if err != nil {
			return err
		}
		if err := c.store.Append(ctx, spool.Log, spool.Batch{ID: id, SourceID: sourceID(one.ResourceLogs().At(0).Resource().Attributes()), CreatedAt: time.Now().UTC(), Priority: 1, Payload: payload}); err != nil {
			return err
		}
	}
	return nil
}

type spoolMetricsConsumer struct {
	store    SpoolAppender
	exporter ExporterConfig
}

func newSpoolMetricsConsumer(store SpoolAppender, exporter ExporterConfig) (consumer.Metrics, error) {
	c := &spoolMetricsConsumer{store: store, exporter: exporter}
	return consumer.NewMetrics(c.ConsumeMetrics)
}

func (c *spoolMetricsConsumer) ConsumeMetrics(ctx context.Context, metrics pmetric.Metrics) error {
	for index := 0; index < metrics.ResourceMetrics().Len(); index++ {
		one := pmetric.NewMetrics()
		metrics.ResourceMetrics().At(index).CopyTo(one.ResourceMetrics().AppendEmpty())
		payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(one)
		if err != nil {
			return err
		}
		if err := c.exporter.ValidateBatchBytes(int64(len(payload))); err != nil {
			return err
		}
		id, err := newSpoolBatchID()
		if err != nil {
			return err
		}
		if err := c.store.Append(ctx, spool.Metric, spool.Batch{ID: id, SourceID: sourceID(one.ResourceMetrics().At(0).Resource().Attributes()), CreatedAt: time.Now().UTC(), Priority: 1, Payload: payload}); err != nil {
			return err
		}
	}
	return nil
}

func newSpoolBatchID() (string, error) {
	var value [16]byte
	if _, err := cryptorand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate spool batch ID: %w", err)
	}
	return fmt.Sprintf("%x", value[:]), nil
}

func sourceID(attributes pcommon.Map) string {
	if value, ok := attributes.Get("dbpilot.source.id"); ok && value.Type() == pcommon.ValueTypeStr {
		return value.Str()
	}
	return "unknown"
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

// Stop retires the active pipeline during agent shutdown. Apply and Stop are
// serialized so a candidate cannot be published after shutdown begins.
func (e *Engine) Stop(ctx context.Context) error {
	e.transitionMu.Lock()
	defer e.transitionMu.Unlock()
	if e.active == nil {
		return nil
	}
	active := e.active
	e.active = nil
	return active.Stop(ctx)
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
