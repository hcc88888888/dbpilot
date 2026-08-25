package telemetry

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"

	"dbpilot.local/platform/internal/policy"
	"go.opentelemetry.io/collector/component"
)

var (
	// ErrUnsupportedSource means a signed policy requested a source that is not
	// part of this embedded collector build.
	ErrUnsupportedSource = errors.New("unsupported telemetry source")
	// ErrNoPipelines prevents an inert policy from reaching the runtime.
	ErrNoPipelines = errors.New("telemetry policy produces zero pipelines")
)

const (
	logsPipelineID    = "dbpilot/logs"
	metricsPipelineID = "dbpilot/metrics"
)

// RuntimeConfig is an immutable inspection view over the typed Collector
// configurations constructed from a policy. The actual component.Config
// values stay private so callers cannot mutate a compiled policy.
type RuntimeConfig struct {
	receivers  map[string]receiverConfig
	processors map[string]processorConfig
	exporters  map[string]exporterConfig
	extensions map[string]extensionConfig
	pipelines  map[string]pipelineConfig
	sources    map[string]SourceConfig
	limits     runtimeLimits
}

type receiverConfig struct {
	id     string
	kind   string
	config component.Config
}

type processorConfig struct {
	id     string
	kind   string
	config component.Config
}

type exporterConfig struct{ id string }

type extensionConfig struct {
	id     string
	kind   string
	config component.Config
}

type pipelineConfig struct {
	id           string
	receiverIDs  []string
	processorIDs []string
	exporterIDs  []string
}

type runtimeLimits struct {
	maxSpoolBytes     int64
	batchMaxBytes     int64
	memoryCheckEvents int64
}

// SourceConfig is an immutable source inspection record. Its fields describe
// typed receiver input settings without accepting or exposing raw YAML.
type SourceConfig struct {
	ID                 string
	Kind               policy.SourceKind
	PipelineID         string
	ResourceAttributes map[string]string
	FileLog            FileLogConfig
	Journald           JournaldConfig
	Prometheus         PrometheusConfig
}

// FileLogConfig describes the filelog settings permitted by DBPilot policy.
type FileLogConfig struct {
	Path                      string
	MultilineLineStartPattern string
	MultilineLineEndPattern   string
}

// JournaldConfig describes the fixed journald selector set.
type JournaldConfig struct{ Matches []string }

// PrometheusConfig describes the one static scrape target permitted by a
// DBPilot Prometheus source.
type PrometheusConfig struct {
	Target, TLSCAFile, TLSCertFile, TLSKeyFile, Username, Password string
}

// PipelineConfig is a copy-safe view of a compiled pipeline.
type PipelineConfig struct {
	ID, Signal                             string
	ReceiverIDs, ProcessorIDs, ExporterIDs []string
}

// Compile converts validated policy values into configurations for the closed
// catalog. It never interprets a configuration document or creates arbitrary
// Collector components.
func Compile(p policy.Policy, allowed Catalog) (RuntimeConfig, error) {
	if allowed == nil {
		return RuntimeConfig{}, fmt.Errorf("telemetry catalog is required")
	}

	cfg := RuntimeConfig{
		receivers:  make(map[string]receiverConfig, len(p.Sources)),
		processors: make(map[string]processorConfig, 2),
		exporters:  map[string]exporterConfig{"dbpilot": {id: "dbpilot"}},
		extensions: make(map[string]extensionConfig, 1),
		pipelines:  make(map[string]pipelineConfig, 2),
		sources:    make(map[string]SourceConfig, len(p.Sources)),
		limits: runtimeLimits{
			maxSpoolBytes:     p.Limits.MaxSpoolBytes,
			batchMaxBytes:     p.Limits.MaxBatchBytes,
			memoryCheckEvents: p.Limits.MaxEventsPerSec,
		},
	}

	if err := cfg.addProcessor("memory_limiter", allowed); err != nil {
		return RuntimeConfig{}, err
	}
	if err := cfg.addProcessor("batch", allowed); err != nil {
		return RuntimeConfig{}, err
	}
	cfg.addFileStorage(allowed)

	sources := slices.Clone(p.Sources)
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	for _, source := range sources {
		if err := cfg.addSource(p.AgentID, source, allowed); err != nil {
			return RuntimeConfig{}, err
		}
	}
	if len(cfg.receivers) == 0 {
		return RuntimeConfig{}, ErrNoPipelines
	}
	cfg.addPipelines()
	if len(cfg.pipelines) == 0 {
		return RuntimeConfig{}, ErrNoPipelines
	}
	return cfg, nil
}

func (cfg *RuntimeConfig) addSource(agentID string, source policy.Source, allowed Catalog) error {
	componentKind, pipelineID, ok := receiverFor(source.Kind)
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsupportedSource, source.Kind)
	}
	factory, ok := allowed.ReceiverFactory(componentKind)
	if !ok {
		return fmt.Errorf("%w: receiver %q is not catalogued", ErrUnsupportedSource, componentKind)
	}
	id := componentKind + "/" + source.ID
	if _, exists := cfg.receivers[id]; exists {
		return fmt.Errorf("%w: duplicate component ID %q", ErrUnsupportedSource, id)
	}
	cfg.receivers[id] = receiverConfig{id: id, kind: componentKind, config: factory.CreateDefaultConfig()}
	cfg.sources[id] = sourceInspection(agentID, source, pipelineID)
	return nil
}

func (cfg *RuntimeConfig) addProcessor(name string, allowed Catalog) error {
	factory, ok := allowed.ProcessorFactory(name)
	if !ok {
		return fmt.Errorf("processor %q is not catalogued", name)
	}
	cfg.processors[name] = processorConfig{id: name, kind: name, config: factory.CreateDefaultConfig()}
	return nil
}

func (cfg *RuntimeConfig) addFileStorage(allowed Catalog) {
	if c, ok := allowed.(*catalog); ok && c.fileStorageFactory() != nil {
		cfg.extensions["file_storage"] = extensionConfig{
			id: "file_storage", kind: "file_storage", config: c.fileStorageFactory().CreateDefaultConfig(),
		}
	}
}

func (cfg *RuntimeConfig) addPipelines() {
	logs, metrics := make([]string, 0), make([]string, 0)
	for id, source := range cfg.sources {
		switch source.PipelineID {
		case logsPipelineID:
			logs = append(logs, id)
		case metricsPipelineID:
			metrics = append(metrics, id)
		}
	}
	sort.Strings(logs)
	sort.Strings(metrics)
	processors, exporters := cfg.ProcessorIDs(), cfg.ExporterIDs()
	if len(logs) > 0 {
		cfg.pipelines[logsPipelineID] = pipelineConfig{id: logsPipelineID, receiverIDs: logs, processorIDs: processors, exporterIDs: exporters}
	}
	if len(metrics) > 0 {
		cfg.pipelines[metricsPipelineID] = pipelineConfig{id: metricsPipelineID, receiverIDs: metrics, processorIDs: processors, exporterIDs: exporters}
	}
}

func receiverFor(kind policy.SourceKind) (componentKind, pipelineID string, ok bool) {
	switch kind {
	case policy.SourceFileLog:
		return "file_log", logsPipelineID, true
	case policy.SourceJournald:
		return "journald", logsPipelineID, true
	case policy.SourceHostMetrics:
		return "host_metrics", metricsPipelineID, true
	case policy.SourcePrometheus:
		return "prometheus", metricsPipelineID, true
	default:
		return "", "", false
	}
}

func sourceInspection(agentID string, source policy.Source, pipelineID string) SourceConfig {
	result := SourceConfig{
		ID: source.ID, Kind: source.Kind, PipelineID: pipelineID,
		ResourceAttributes: maps.Clone(source.Labels),
	}
	if result.ResourceAttributes == nil {
		result.ResourceAttributes = make(map[string]string, 1)
	}
	result.ResourceAttributes["dbpilot.agent.id"] = agentID
	result.ResourceAttributes["dbpilot.source.id"] = source.ID
	switch source.Kind {
	case policy.SourceFileLog:
		result.FileLog = FileLogConfig{Path: source.Path, MultilineLineStartPattern: source.Params["multiline_line_start_pattern"], MultilineLineEndPattern: source.Params["multiline_line_end_pattern"]}
	case policy.SourceJournald:
		if unit := source.Params["unit"]; unit != "" {
			result.Journald.Matches = []string{"_SYSTEMD_UNIT=" + unit}
		}
	case policy.SourcePrometheus:
		result.Prometheus = PrometheusConfig{Target: source.Endpoint, TLSCAFile: source.Params["tls_ca_file"], TLSCertFile: source.Params["tls_cert_file"], TLSKeyFile: source.Params["tls_key_file"], Username: source.Params["username"], Password: source.Params["password"]}
	}
	return result
}

// ReceiverIDs returns sorted, stable component IDs.
func (cfg RuntimeConfig) ReceiverIDs() []string { return sortedKeys(cfg.receivers) }

// ProcessorIDs returns processors in pipeline order.
func (cfg RuntimeConfig) ProcessorIDs() []string {
	ids := make([]string, 0, len(cfg.processors))
	if _, ok := cfg.processors["memory_limiter"]; ok {
		ids = append(ids, "memory_limiter")
	}
	if _, ok := cfg.processors["batch"]; ok {
		ids = append(ids, "batch")
	}
	return ids
}

// ExporterIDs returns sorted exporter component IDs.
func (cfg RuntimeConfig) ExporterIDs() []string { return sortedKeys(cfg.exporters) }

// Source retrieves a copy of the compiled source record.
func (cfg RuntimeConfig) Source(id string) (SourceConfig, bool) {
	source, ok := cfg.sources[id]
	if !ok {
		return SourceConfig{}, false
	}
	source.ResourceAttributes = maps.Clone(source.ResourceAttributes)
	source.Journald.Matches = slices.Clone(source.Journald.Matches)
	return source, true
}

// Pipeline retrieves a copy of a pipeline by its stable ID.
func (cfg RuntimeConfig) Pipeline(id string) (PipelineConfig, bool) {
	pipeline, ok := cfg.pipelines[id]
	if !ok {
		return PipelineConfig{}, false
	}
	signal := "logs"
	if id == metricsPipelineID {
		signal = "metrics"
	}
	return PipelineConfig{ID: pipeline.id, Signal: signal, ReceiverIDs: slices.Clone(pipeline.receiverIDs), ProcessorIDs: slices.Clone(pipeline.processorIDs), ExporterIDs: slices.Clone(pipeline.exporterIDs)}, true
}

func (cfg RuntimeConfig) MaxSpoolBytes() int64 { return cfg.limits.maxSpoolBytes }
func (cfg RuntimeConfig) BatchMaxBytes() int64 { return cfg.limits.batchMaxBytes }
func (cfg RuntimeConfig) MemoryLimiterCheckIntervalEvents() int64 {
	return cfg.limits.memoryCheckEvents
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
