package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"dbpilot.local/platform/internal/policy"
	"github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza/operator/input/journald"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/journaldreceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/processor/batchprocessor"
	"go.opentelemetry.io/collector/processor/memorylimiterprocessor"
)

var (
	// ErrUnsupportedSource means a signed policy requested a source that is not
	// part of this embedded collector build.
	ErrUnsupportedSource = errors.New("unsupported telemetry source")
	// ErrNoPipelines prevents an inert policy from reaching the runtime.
	ErrNoPipelines = errors.New("telemetry policy produces zero pipelines")
	// ErrBatchExceedsLimit means a DBPilot exporter batch exceeded the signed
	// byte limit. Collector batchprocessor limits item counts, so it cannot
	// perform this check.
	ErrBatchExceedsLimit = errors.New("telemetry batch exceeds byte limit")
)

const (
	logsPipelineID             = "dbpilot/logs"
	metricsPipelineID          = "dbpilot/metrics"
	defaultMemoryLimitMiB      = 256
	defaultMemorySpikeLimitMiB = 64
)

// RuntimeConfig is an immutable inspection view over the typed Collector
// configurations constructed from a policy. The actual component.Config
// values stay private so callers cannot mutate a compiled policy.
type RuntimeConfig struct {
	policyVersion uint64
	receivers     map[string]receiverConfig
	processors    map[string]processorConfig
	exporters     map[string]exporterConfig
	extensions    map[string]extensionConfig
	pipelines     map[string]pipelineConfig
	sources       map[string]SourceConfig
	limits        runtimeLimits
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

type exporterConfig struct {
	id                       string
	maxBatchBytes            int64
	resourceAttributes       map[string]string
	sourceResourceAttributes map[string]map[string]string
}

type extensionConfig struct {
	id     string
	kind   string
	config component.Config
}

type pipelineConfig struct {
	id                       string
	receiverIDs              []string
	processorIDs             []string
	exporterIDs              []string
	sourceResourceAttributes map[string]map[string]string
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
	SourceResourceAttributes               map[string]map[string]string
}

// ExporterConfig describes DBPilot's typed exporter contract. MaxBatchBytes
// is enforced by the DBPilot spool/exporter boundary; it is deliberately not
// mapped to Collector batchprocessor item-count fields.
type ExporterConfig struct {
	ID                       string
	MaxBatchBytes            int64
	ResourceAttributes       map[string]string
	SourceResourceAttributes map[string]map[string]string
}

// Compile converts validated policy values into configurations for the closed
// catalog. It never interprets a configuration document or creates arbitrary
// Collector components.
func Compile(p policy.Policy, allowed Catalog) (RuntimeConfig, error) {
	if allowed == nil {
		return RuntimeConfig{}, fmt.Errorf("telemetry catalog is required")
	}

	cfg := RuntimeConfig{
		policyVersion: p.Version,
		receivers:     make(map[string]receiverConfig, len(p.Sources)),
		processors:    make(map[string]processorConfig, 2),
		exporters: map[string]exporterConfig{"dbpilot": {
			id:                       "dbpilot",
			maxBatchBytes:            p.Limits.MaxBatchBytes,
			resourceAttributes:       map[string]string{"dbpilot.agent.id": p.AgentID},
			sourceResourceAttributes: make(map[string]map[string]string, len(p.Sources)),
		}},
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
	storageID, hasStorage, err := cfg.addFileStorage(p.AgentID, p.Limits.MaxSpoolBytes, allowed)
	if err != nil {
		return RuntimeConfig{}, err
	}

	sources := slices.Clone(p.Sources)
	sort.Slice(sources, func(i, j int) bool { return sources[i].ID < sources[j].ID })
	for _, source := range sources {
		if err := cfg.addSource(p.AgentID, source, storageID, hasStorage, allowed); err != nil {
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

// PolicyVersion identifies the signed policy that produced this immutable
// configuration, allowing a concrete builder to return a matching Candidate.
func (cfg RuntimeConfig) PolicyVersion() uint64 { return cfg.policyVersion }

func (cfg *RuntimeConfig) addSource(agentID string, source policy.Source, storageID component.ID, hasStorage bool, allowed Catalog) error {
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
	collectorConfig, err := configureReceiver(source, factory.CreateDefaultConfig(), storageID, hasStorage)
	if err != nil {
		return err
	}
	cfg.receivers[id] = receiverConfig{id: id, kind: componentKind, config: collectorConfig}
	cfg.sources[id] = sourceInspection(agentID, source, pipelineID)
	exporter := cfg.exporters["dbpilot"]
	exporter.sourceResourceAttributes[id] = maps.Clone(cfg.sources[id].ResourceAttributes)
	cfg.exporters["dbpilot"] = exporter
	return nil
}

func (cfg *RuntimeConfig) addProcessor(name string, allowed Catalog) error {
	factory, ok := allowed.ProcessorFactory(name)
	if !ok {
		return fmt.Errorf("processor %q is not catalogued", name)
	}
	collectorConfig, err := configureProcessor(name, factory.CreateDefaultConfig())
	if err != nil {
		return err
	}
	cfg.processors[name] = processorConfig{id: name, kind: name, config: collectorConfig}
	return nil
}

func (cfg *RuntimeConfig) addFileStorage(agentID string, maxSpoolBytes int64, allowed Catalog) (component.ID, bool, error) {
	if c, ok := allowed.(*catalog); ok && c.fileStorageFactory() != nil {
		storageType, err := component.NewType("file_storage")
		if err != nil {
			return component.ID{}, false, err
		}
		storageID := component.NewIDWithName(storageType, "")
		storageConfig, ok := c.fileStorageFactory().CreateDefaultConfig().(*filestorage.Config)
		if !ok {
			return component.ID{}, false, fmt.Errorf("file storage factory returned an invalid configuration")
		}
		storageConfig.Directory = filepath.Join("dbpilot-spool", storageDirectory(agentID))
		storageConfig.MaxSize = maxSpoolBytes
		storageConfig.CreateDirectory = true
		storageConfig.FSync = true
		if err := storageConfig.Validate(); err != nil {
			return component.ID{}, false, fmt.Errorf("validate file storage configuration: %w", err)
		}
		cfg.extensions["file_storage"] = extensionConfig{
			id: "file_storage", kind: "file_storage", config: storageConfig,
		}
		return storageID, true, nil
	}
	return component.ID{}, false, nil
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
		cfg.pipelines[logsPipelineID] = pipelineConfig{id: logsPipelineID, receiverIDs: logs, processorIDs: processors, exporterIDs: exporters, sourceResourceAttributes: cfg.sourceAttributes(logs)}
	}
	if len(metrics) > 0 {
		cfg.pipelines[metricsPipelineID] = pipelineConfig{id: metricsPipelineID, receiverIDs: metrics, processorIDs: processors, exporterIDs: exporters, sourceResourceAttributes: cfg.sourceAttributes(metrics)}
	}
}

func (cfg *RuntimeConfig) sourceAttributes(receiverIDs []string) map[string]map[string]string {
	attributes := make(map[string]map[string]string, len(receiverIDs))
	for _, receiverID := range receiverIDs {
		attributes[receiverID] = maps.Clone(cfg.sources[receiverID].ResourceAttributes)
	}
	return attributes
}

func configureReceiver(source policy.Source, config component.Config, storageID component.ID, hasStorage bool) (component.Config, error) {
	switch source.Kind {
	case policy.SourceFileLog:
		fileConfig, ok := config.(*filelogreceiver.FileLogConfig)
		if !ok {
			return nil, fmt.Errorf("file_log factory returned %T", config)
		}
		fileConfig.InputConfig.Include = []string{source.Path}
		fileConfig.InputConfig.Exclude = splitList(source.Params["exclude"])
		if startAt := source.Params["start_at"]; startAt != "" {
			fileConfig.InputConfig.StartAt = startAt
		}
		if encoding := source.Params["encoding"]; encoding != "" {
			fileConfig.InputConfig.Encoding = encoding
		}
		fileConfig.InputConfig.SplitConfig.LineStartPattern = source.Params["multiline_line_start_pattern"]
		fileConfig.InputConfig.SplitConfig.LineEndPattern = source.Params["multiline_line_end_pattern"]
		if hasStorage {
			fileConfig.StorageID = &storageID
		}
		return fileConfig, nil
	case policy.SourceJournald:
		journalConfig, ok := config.(*journaldreceiver.JournaldConfig)
		if !ok {
			return nil, fmt.Errorf("journald factory returned %T", config)
		}
		journalConfig.InputConfig.Units = splitList(source.Params["unit"])
		matches, err := journaldMatches(source.Params["match"])
		if err != nil {
			return nil, err
		}
		journalConfig.InputConfig.Matches = matches
		if hasStorage {
			journalConfig.BaseConfig.StorageID = &storageID
		}
		return journalConfig, nil
	case policy.SourceHostMetrics:
		hostConfig, ok := config.(*hostmetricsreceiver.Config)
		if !ok {
			return nil, fmt.Errorf("host_metrics factory returned %T", config)
		}
		collectors, err := hostCollectors(source.Params["collectors"])
		if err != nil {
			return nil, err
		}
		raw := map[string]any{"collection_interval": source.Interval.String(), "scrapers": map[string]any{}}
		scrapers := raw["scrapers"].(map[string]any)
		for _, collector := range collectors {
			scrapers[collector] = map[string]any{}
		}
		if err := hostConfig.Unmarshal(confmap.NewFromStringMap(raw)); err != nil {
			return nil, fmt.Errorf("configure host_metrics: %w", err)
		}
		return hostConfig, nil
	case policy.SourcePrometheus:
		promConfig, ok := config.(*prometheusreceiver.Config)
		if !ok {
			return nil, fmt.Errorf("prometheus factory returned %T", config)
		}
		if err := configurePrometheus(promConfig, source); err != nil {
			return nil, err
		}
		return promConfig, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedSource, source.Kind)
	}
}

func configureProcessor(name string, config component.Config) (component.Config, error) {
	switch name {
	case "memory_limiter":
		memoryConfig, ok := config.(*memorylimiterprocessor.Config)
		if !ok {
			return nil, fmt.Errorf("memory_limiter factory returned %T", config)
		}
		memoryConfig.CheckInterval = time.Second
		// Collector memory pressure and on-disk spool capacity are independent
		// budgets. The latter is configured only on file_storage below.
		memoryConfig.MemoryLimitMiB = defaultMemoryLimitMiB
		memoryConfig.MemorySpikeLimitMiB = defaultMemorySpikeLimitMiB
		return memoryConfig, nil
	case "batch":
		batchConfig, ok := config.(*batchprocessor.Config)
		if !ok {
			return nil, fmt.Errorf("batch factory returned %T", config)
		}
		// batchprocessor sizes batches by telemetry item count, not bytes. Its
		// defaults remain intact; DBPilot's exporter owns MaxBatchBytes.
		return batchConfig, nil
	default:
		return nil, fmt.Errorf("processor %q is not configured", name)
	}
}

func configurePrometheus(config *prometheusreceiver.Config, source policy.Source) error {
	target, err := url.Parse(source.Endpoint)
	if err != nil || target.Host == "" {
		return fmt.Errorf("configure prometheus endpoint: %w", policy.ErrInvalidEndpoint)
	}
	timeout := source.Interval / 2
	if rawTimeout := source.Params["scrape_timeout"]; rawTimeout != "" {
		timeout, err = time.ParseDuration(rawTimeout)
		if err != nil || timeout <= 0 || timeout >= source.Interval {
			return fmt.Errorf("configure prometheus scrape timeout")
		}
	}
	scrape := map[string]any{
		"job_name": source.ID, "scrape_interval": source.Interval.String(), "scrape_timeout": timeout.String(),
		"metrics_path": target.EscapedPath(), "scheme": target.Scheme,
		"static_configs": []any{map[string]any{"targets": []string{target.Host}}},
	}
	if scrape["metrics_path"] == "" {
		scrape["metrics_path"] = "/metrics"
	}
	if tlsConfig := prometheusTLS(source.Params); len(tlsConfig) > 0 {
		scrape["tls_config"] = tlsConfig
	}
	if username := source.Params["username"]; username != "" {
		scrape["basic_auth"] = map[string]any{"username": username, "password": source.Params["password"]}
	}
	if err := config.PrometheusConfig.Unmarshal(confmap.NewFromStringMap(map[string]any{"scrape_configs": []any{scrape}})); err != nil {
		return fmt.Errorf("configure prometheus: %w", err)
	}
	return nil
}

func prometheusTLS(params map[string]string) map[string]any {
	result := make(map[string]any, 3)
	for policyName, collectorName := range map[string]string{"tls_ca_file": "ca_file", "tls_cert_file": "cert_file", "tls_key_file": "key_file"} {
		if value := params[policyName]; value != "" {
			result[collectorName] = value
		}
	}
	return result
}

func journaldMatches(raw string) ([]journald.MatchConfig, error) {
	if raw == "" {
		return nil, nil
	}
	result := make([]journald.MatchConfig, 0)
	for _, entry := range splitList(raw) {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" || value == "" {
			return nil, fmt.Errorf("invalid journald match %q", entry)
		}
		result = append(result, journald.MatchConfig{key: value})
	}
	return result, nil
}

func hostCollectors(raw string) ([]string, error) {
	collectors := splitList(raw)
	if len(collectors) == 0 {
		collectors = []string{"cpu", "memory", "disk", "filesystem", "network", "load"}
	}
	allowed := map[string]struct{}{"cpu": {}, "memory": {}, "disk": {}, "filesystem": {}, "network": {}, "load": {}, "processes": {}}
	for _, collector := range collectors {
		if _, ok := allowed[collector]; !ok {
			return nil, fmt.Errorf("unsupported hostmetrics collector %q", collector)
		}
	}
	return collectors, nil
}

func splitList(raw string) []string {
	if raw == "" {
		return nil
	}
	items := strings.Split(raw, ",")
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func storageDirectory(agentID string) string {
	digest := sha256.Sum256([]byte(agentID))
	return hex.EncodeToString(digest[:])
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
	return PipelineConfig{ID: pipeline.id, Signal: signal, ReceiverIDs: slices.Clone(pipeline.receiverIDs), ProcessorIDs: slices.Clone(pipeline.processorIDs), ExporterIDs: slices.Clone(pipeline.exporterIDs), SourceResourceAttributes: cloneSourceAttributes(pipeline.sourceResourceAttributes)}, true
}

// Exporter retrieves a copy of the DBPilot exporter contract for a stable ID.
func (cfg RuntimeConfig) Exporter(id string) (ExporterConfig, bool) {
	exporter, ok := cfg.exporters[id]
	if !ok {
		return ExporterConfig{}, false
	}
	return ExporterConfig{ID: exporter.id, MaxBatchBytes: exporter.maxBatchBytes, ResourceAttributes: maps.Clone(exporter.resourceAttributes), SourceResourceAttributes: cloneSourceAttributes(exporter.sourceResourceAttributes)}, true
}

// ValidateBatchBytes is the byte-boundary check used by DBPilot's spool and
// exporter implementation before it emits a batch.
func (cfg ExporterConfig) ValidateBatchBytes(bytes int64) error {
	if bytes < 0 || bytes > cfg.MaxBatchBytes {
		return fmt.Errorf("%w: %d > %d", ErrBatchExceedsLimit, bytes, cfg.MaxBatchBytes)
	}
	return nil
}

func cloneSourceAttributes(attributes map[string]map[string]string) map[string]map[string]string {
	result := make(map[string]map[string]string, len(attributes))
	for receiverID, resourceAttributes := range attributes {
		result[receiverID] = maps.Clone(resourceAttributes)
	}
	return result
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
