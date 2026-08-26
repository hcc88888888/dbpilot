package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/spool"
)

const dependencyCollectorSourceID = "hbase-dependencies"

// DependencyCollectorStore is the durable boundary used by the component
// collector. spool.Store implements it directly.
type DependencyCollectorStore interface {
	Append(context.Context, spool.DataClass, spool.Batch) error
	Checkpoint(string) ([]byte, error)
	PutCheckpoint(string, []byte) error
}

// DependencyCollectorConfig is trusted Agent configuration. Definitions may
// contain only fixed, read-only adapter endpoints and runtime secret refs.
type DependencyCollectorConfig struct {
	AgentID        string
	Definitions    []database.ComponentDefinition
	SecretResolver database.SecretResolver
	Store          DependencyCollectorStore

	Interval       time.Duration
	RequestTimeout time.Duration
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Now            func() time.Time
}

// ComponentCollectionStatus reports an adapter outcome without endpoint URLs,
// response bodies, credentials, or arbitrary error text.
type ComponentCollectionStatus struct {
	Cluster     string                 `json:"cluster"`
	Component   database.ComponentKind `json:"component"`
	State       string                 `json:"state"`
	ErrorCode   string                 `json:"error_code,omitempty"`
	Attempts    int                    `json:"attempts"`
	SampleCount int                    `json:"sample_count"`
}

// DependencyTelemetryEnvelope is the durable payload emitted to the existing
// metric spool. Evidence is correlation-only and contains no remediation.
type DependencyTelemetryEnvelope struct {
	BatchID     string                        `json:"batch_id"`
	Sequence    uint64                        `json:"sequence"`
	AgentID     string                        `json:"agent_id"`
	CollectedAt time.Time                     `json:"collected_at"`
	Samples     []database.MetricSample       `json:"samples"`
	Statuses    []ComponentCollectionStatus   `json:"statuses"`
	Health      []database.ComponentHealth    `json:"health"`
	Evidence    []database.DependencyEvidence `json:"evidence"`
}

// DependencyCollector owns the registered component adapters for one Agent.
type DependencyCollector struct {
	config    DependencyCollectorConfig
	topology  database.Topology
	registry  database.ComponentRegistry
	closeOnce sync.Once
	collectMu sync.Mutex
	closeErr  error
}

func NewDependencyCollector(config DependencyCollectorConfig) (*DependencyCollector, error) {
	if config.AgentID == "" || isNilDependencyBoundary(config.Store) || isNilDependencyBoundary(config.SecretResolver) || len(config.Definitions) == 0 {
		return nil, errors.New("invalid dependency collector configuration")
	}
	if config.Interval < 0 || config.RequestTimeout < 0 || config.MaxAttempts < 0 || config.InitialBackoff < 0 || config.MaxBackoff < 0 {
		return nil, errors.New("dependency collector durations and attempts must not be negative")
	}
	if config.Interval == 0 {
		config.Interval = time.Minute
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 30 * time.Second
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 3
	}
	if config.MaxAttempts > 5 || config.RequestTimeout > time.Minute {
		return nil, errors.New("dependency collector retry or timeout limit exceeded")
	}
	if config.InitialBackoff == 0 {
		config.InitialBackoff = 100 * time.Millisecond
	}
	if config.MaxBackoff == 0 {
		config.MaxBackoff = 2 * time.Second
	}
	if config.InitialBackoff > config.MaxBackoff || config.MaxBackoff > 30*time.Second {
		return nil, errors.New("invalid dependency collector backoff")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	definitions := cloneComponentDefinitions(config.Definitions)
	topology, err := database.ResolveTopology(definitions)
	if err != nil {
		return nil, err
	}
	registry := database.NewComponentRegistry()
	for _, kind := range []database.ComponentKind{database.HDFSComponent, database.ZooKeeperComponent, database.HBaseComponent} {
		for _, definition := range definitions {
			if definition.Kind != kind {
				continue
			}
			client := database.NewJMXClient(config.SecretResolver, database.JMXClientConfig{SecretRef: definition.SecretRef, Timeout: config.RequestTimeout, TLS: componentTLSConfig(definition)})
			switch kind {
			case database.HDFSComponent:
				err = database.RegisterHDFSAdapter(registry, definition, client)
			case database.ZooKeeperComponent:
				err = database.RegisterZooKeeperAdapter(registry, definition, client)
			case database.HBaseComponent:
				err = database.RegisterHBaseAdapter(registry, definition, client)
			}
			if err != nil {
				return nil, err
			}
		}
	}
	config.Definitions = definitions
	return &DependencyCollector{config: config, topology: topology, registry: registry}, nil
}

func isNilDependencyBoundary(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func componentTLSConfig(definition database.ComponentDefinition) database.TLSConfig {
	if definition.TLSRef == "" {
		return database.TLSConfig{}
	}
	return database.TLSConfig{Enabled: true, CASecretRef: definition.TLSRef}
}

func cloneComponentDefinitions(values []database.ComponentDefinition) []database.ComponentDefinition {
	result := make([]database.ComponentDefinition, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Endpoints = append([]database.Endpoint(nil), value.Endpoints...)
	}
	return result
}

// CollectOnce traverses every authorized adapter, preserves partial samples,
// correlates health/evidence, and appends one idempotent metric batch.
func (collector *DependencyCollector) CollectOnce(ctx context.Context) error {
	if collector == nil || ctx == nil {
		return errors.New("dependency collector context is required")
	}
	collector.collectMu.Lock()
	defer collector.collectMu.Unlock()
	sequence, err := collector.nextSequence()
	if err != nil {
		return fmt.Errorf("read dependency collection sequence: %w", err)
	}
	collectedAt := collector.config.Now().UTC()
	definitions := cloneComponentDefinitions(collector.config.Definitions)
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].ID < definitions[j].ID })

	samples := make([]database.MetricSample, 0)
	statuses := make([]ComponentCollectionStatus, 0, len(definitions))
	for _, definition := range definitions {
		adapter, ok := collector.registry.Adapter(definition.ID)
		if !ok {
			return fmt.Errorf("component adapter %q is not registered", definition.ID)
		}
		componentSamples, status := collector.collectWithRetry(ctx, definition, adapter)
		for index := range componentSamples {
			componentSamples[index].Timestamp = collectedAt
		}
		samples = append(samples, componentSamples...)
		statuses = append(statuses, status)
	}
	sortMetricSamples(samples)

	envelope := DependencyTelemetryEnvelope{
		AgentID: collector.config.AgentID, Sequence: sequence, CollectedAt: collectedAt, Samples: samples,
		Statuses: statuses, Health: database.AggregateHealth(collector.topology, samples),
		Evidence: database.BuildDependencyEvidence(collector.topology, samples),
	}
	id, err := dependencyEnvelopeID(envelope)
	if err != nil {
		return err
	}
	envelope.BatchID = id
	payload, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	if err := collector.config.Store.Append(ctx, spool.Metric, spool.Batch{ID: id, SourceID: dependencyCollectorSourceID, CreatedAt: collectedAt, Priority: 1, Payload: payload}); err != nil {
		return fmt.Errorf("append dependency telemetry: %w", err)
	}
	checkpoint := make([]byte, 8)
	binary.BigEndian.PutUint64(checkpoint, sequence)
	if err := collector.config.Store.PutCheckpoint(dependencyCollectorSourceID, checkpoint); err != nil {
		return fmt.Errorf("persist dependency collection sequence: %w", err)
	}
	return nil
}

func (collector *DependencyCollector) nextSequence() (uint64, error) {
	checkpoint, err := collector.config.Store.Checkpoint(dependencyCollectorSourceID)
	if errors.Is(err, spool.ErrNoCheckpoint) {
		return 1, nil
	}
	if err != nil {
		return 0, err
	}
	if len(checkpoint) != 8 {
		return 0, errors.New("invalid dependency collection checkpoint")
	}
	sequence := binary.BigEndian.Uint64(checkpoint)
	if sequence == ^uint64(0) {
		return 0, errors.New("dependency collection sequence exhausted")
	}
	return sequence + 1, nil
}

func (collector *DependencyCollector) collectWithRetry(ctx context.Context, definition database.ComponentDefinition, adapter database.ComponentAdapter) ([]database.MetricSample, ComponentCollectionStatus) {
	var samples []database.MetricSample
	var err error
	attempts := 0
	for attempts < collector.config.MaxAttempts {
		attempts++
		requestCtx, cancel := context.WithTimeout(ctx, collector.config.RequestTimeout)
		samples, err = adapter.Collect(requestCtx, database.MetricRequest{})
		cancel()
		if err == nil || attempts == collector.config.MaxAttempts || ctx.Err() != nil {
			break
		}
		if waitErr := waitDependencyBackoff(ctx, collector.backoff(attempts-1)); waitErr != nil {
			err = waitErr
			break
		}
	}
	status := ComponentCollectionStatus{Cluster: definition.ID, Component: definition.Kind, State: "ok", Attempts: attempts, SampleCount: len(samples)}
	if err != nil && len(samples) != 0 {
		status.State, status.ErrorCode = "partial", "COMPONENT_COLLECTION_PARTIAL"
	} else if err != nil {
		status.State, status.ErrorCode = "failed", "COMPONENT_COLLECTION_FAILED"
	}
	return samples, status
}

func (collector *DependencyCollector) backoff(attempt int) time.Duration {
	delay := collector.config.InitialBackoff
	for index := 0; index < attempt && delay < collector.config.MaxBackoff; index++ {
		delay *= 2
		if delay > collector.config.MaxBackoff {
			delay = collector.config.MaxBackoff
		}
	}
	return delay
}

func waitDependencyBackoff(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func dependencyEnvelopeID(envelope DependencyTelemetryEnvelope) (string, error) {
	// Identity deliberately excludes collection content and wall-clock time.
	// If append succeeds but its following checkpoint fails, the same sequence
	// is replayed after restart and the spool keeps the already-durable payload.
	payload, err := json.Marshal(struct {
		AgentID  string `json:"agent_id"`
		Sequence uint64 `json:"sequence"`
	}{AgentID: envelope.AgentID, Sequence: envelope.Sequence})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func sortMetricSamples(samples []database.MetricSample) {
	sort.Slice(samples, func(i, j int) bool {
		left, right := samples[i], samples[j]
		if left.Cluster != right.Cluster {
			return left.Cluster < right.Cluster
		}
		if left.Component != right.Component {
			return left.Component < right.Component
		}
		if left.Role != right.Role {
			return left.Role < right.Role
		}
		if left.Host != right.Host {
			return left.Host < right.Host
		}
		if left.Instance != right.Instance {
			return left.Instance < right.Instance
		}
		if left.MetricName != right.MetricName {
			return left.MetricName < right.MetricName
		}
		if left.Unit != right.Unit {
			return left.Unit < right.Unit
		}
		return left.Value < right.Value
	})
}

// Run collects immediately and then on a fixed interval until shutdown.
func (collector *DependencyCollector) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("dependency collector context is required")
	}
	if err := collector.CollectOnce(ctx); err != nil {
		return err
	}
	ticker := time.NewTicker(collector.config.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := collector.CollectOnce(ctx); err != nil {
				return err
			}
		}
	}
}

func (collector *DependencyCollector) Close() error {
	if collector == nil {
		return nil
	}
	collector.closeOnce.Do(func() {
		for _, definition := range collector.config.Definitions {
			if adapter, ok := collector.registry.Adapter(definition.ID); ok {
				collector.closeErr = errors.Join(collector.closeErr, adapter.Close())
			}
		}
	})
	return collector.closeErr
}

var _ ComponentCollector = (*DependencyCollector)(nil)
