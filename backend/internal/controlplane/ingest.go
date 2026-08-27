// Package controlplane connects authenticated telemetry ingestion to the
// tenant-scoped alert metric store.
package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

var (
	ErrMetricScopeClaim   = metricValidationError("metric payload scope claim is prohibited")
	ErrInvalidMetricBatch = metricValidationError("invalid metric batch")
	metricLabelKey        = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

type metricValidationError string

func (e metricValidationError) Error() string { return string(e) }

// IsMetricBatchValidation marks malformed and identity-claim payload errors
// without exposing control-plane implementation details to ingest.
func (metricValidationError) IsMetricBatchValidation() bool { return true }

// AgentScopeResolver derives the only permissible tenant/project assignment
// from authenticated Agent inventory.
type AgentScopeResolver interface {
	ScopeForAgent(context.Context, string) (alert.Scope, error)
}

// MetricConsumer decodes metric batch payloads only after ingest has verified
// the Agent identity, checksum, and batch de-duplication state.
type MetricConsumer struct {
	resolver AgentScopeResolver
	store    alert.MetricStore
}

func NewMetricConsumer(resolver AgentScopeResolver, store alert.MetricStore) *MetricConsumer {
	return &MetricConsumer{resolver: resolver, store: store}
}

// ConsumeMetricBatch accepts the documented envelope:
// {"samples":[{"name":"...","value":1.5,"sampled_at":"RFC3339","labels":{...}}]}.
// Tenant, project, and Agent identity fields are deliberately not accepted.
func (c *MetricConsumer) ConsumeMetricBatch(ctx context.Context, agentID string, payload []byte, receivedAt time.Time) error {
	samples, err := c.metricSamples(ctx, agentID, payload, receivedAt)
	if err != nil {
		return err
	}
	if err := c.store.Append(ctx, samples); err != nil {
		return err
	}
	return nil
}

// ConsumeMetricBatchOnce uses the repository's atomic batch primitive so the
// accepted acknowledgement cannot race or get ahead of durable metric state.
func (c *MetricConsumer) ConsumeMetricBatchOnce(ctx context.Context, agentID, batchID string, payload []byte, receivedAt time.Time) (bool, error) {
	samples, err := c.metricSamples(ctx, agentID, payload, receivedAt)
	if err != nil {
		return false, err
	}
	store, ok := c.store.(alert.AtomicMetricBatchStore)
	if !ok {
		return false, errors.New("atomic metric batch store is unavailable")
	}
	return store.AppendBatch(ctx, agentID, batchID, samples)
}

func (c *MetricConsumer) metricSamples(ctx context.Context, agentID string, payload []byte, receivedAt time.Time) ([]alert.MetricSample, error) {
	if c == nil || c.resolver == nil {
		return nil, errors.New("metric scope resolver is unavailable")
	}
	if c.store == nil {
		return nil, errors.New("metric store is unavailable")
	}
	scope, err := c.resolver.ScopeForAgent(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("resolve agent scope: %w", err)
	}
	if err := scope.Validate(); err != nil {
		return nil, fmt.Errorf("resolve agent scope: %w", err)
	}
	envelope, err := decodeMetricEnvelopeForAgent(payload, agentID, receivedAt)
	if err != nil {
		return nil, err
	}

	samples := make([]alert.MetricSample, 0, len(envelope.Samples))
	for _, input := range envelope.Samples {
		sampledAt, err := time.Parse(time.RFC3339, input.SampledAt)
		if err != nil || sampledAt.IsZero() {
			return nil, fmt.Errorf("%w: sampled_at must be RFC3339", ErrInvalidMetricBatch)
		}
		if sampledAt.After(receivedAt.Add(5 * time.Minute)) {
			return nil, fmt.Errorf("%w: sampled_at is too far in the future", ErrInvalidMetricBatch)
		}
		if strings.TrimSpace(input.Name) == "" || math.IsNaN(input.Value) || math.IsInf(input.Value, 0) {
			return nil, ErrInvalidMetricBatch
		}
		if input.Labels == nil || len(input.Labels) > 64 {
			return nil, fmt.Errorf("%w: labels", ErrInvalidMetricBatch)
		}
		for key := range input.Labels {
			if isIdentityClaim(key) {
				return nil, ErrMetricScopeClaim
			}
			if !metricLabelKey.MatchString(key) {
				return nil, fmt.Errorf("%w: invalid label key", ErrInvalidMetricBatch)
			}
		}
		labels := make(map[string]string, len(input.Labels))
		for key, value := range input.Labels {
			labels[key] = value
		}
		if err := alert.ValidateMetricLabels(labels); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidMetricBatch, err)
		}
		sample := alert.MetricSample{Scope: scope, AgentID: agentID, Name: strings.TrimSpace(input.Name), Labels: labels, Value: input.Value, SampledAt: sampledAt}
		populateIdentity(&sample)
		samples = append(samples, sample)
	}
	return samples, nil
}

type metricEnvelope struct {
	Samples []metricPayload `json:"samples"`
}

type metricPayload struct {
	Name      string            `json:"name"`
	Value     float64           `json:"value"`
	SampledAt string            `json:"sampled_at"`
	Labels    map[string]string `json:"labels"`
}

// decodeMetricEnvelope preserves the decoder's package-local legacy surface
// for callers that only need custom JSON decoding.
func decodeMetricEnvelope(payload []byte) (metricEnvelope, error) {
	return decodeMetricEnvelopeForAgent(payload, "", time.Time{})
}

// decodeMetricEnvelopeForAgent accepts the legacy documented JSON payload as well as
// the two wire formats emitted by production Agents. Identity is intentionally
// not part of the return value: MetricConsumer always assigns it from the
// authenticated ingest caller.
func decodeMetricEnvelopeForAgent(payload []byte, agentID string, receivedAt time.Time) (metricEnvelope, error) {
	if bytes.HasPrefix(bytes.TrimSpace(payload), []byte("{")) {
		return decodeJSONMetricEnvelope(payload)
	}
	return decodeOTLPMetricEnvelope(payload, agentID, receivedAt)
}

func decodeJSONMetricEnvelope(payload []byte) (metricEnvelope, error) {
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&fields); err != nil {
		return metricEnvelope{}, fmt.Errorf("%w: malformed JSON", ErrInvalidMetricBatch)
	}
	if err := ensureJSONEnd(decoder); err != nil {
		return metricEnvelope{}, err
	}
	if _, ok := fields["samples"]; !ok {
		return metricEnvelope{}, fmt.Errorf("%w: samples is required", ErrInvalidMetricBatch)
	}
	if isDependencyMetricEnvelope(fields) {
		return decodeDependencyMetricEnvelope(fields)
	}
	for key := range fields {
		if isIdentityClaim(key) {
			return metricEnvelope{}, ErrMetricScopeClaim
		}
		if key != "samples" {
			return metricEnvelope{}, fmt.Errorf("%w: unknown envelope field %q", ErrInvalidMetricBatch, key)
		}
	}

	if bytes.Equal(bytes.TrimSpace(fields["samples"]), []byte("null")) {
		return metricEnvelope{}, fmt.Errorf("%w: samples", ErrInvalidMetricBatch)
	}
	var rawSamples []json.RawMessage
	if err := json.Unmarshal(fields["samples"], &rawSamples); err != nil {
		return metricEnvelope{}, fmt.Errorf("%w: samples", ErrInvalidMetricBatch)
	}
	envelope := metricEnvelope{Samples: make([]metricPayload, 0, len(rawSamples))}
	for _, raw := range rawSamples {
		var sampleFields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &sampleFields); err != nil {
			return metricEnvelope{}, fmt.Errorf("%w: sample", ErrInvalidMetricBatch)
		}
		for key := range sampleFields {
			if isIdentityClaim(key) {
				return metricEnvelope{}, ErrMetricScopeClaim
			}
			if key != "name" && key != "value" && key != "sampled_at" && key != "labels" {
				return metricEnvelope{}, fmt.Errorf("%w: unknown sample field %q", ErrInvalidMetricBatch, key)
			}
		}
		if _, ok := sampleFields["name"]; !ok {
			return metricEnvelope{}, fmt.Errorf("%w: name is required", ErrInvalidMetricBatch)
		}
		if _, ok := sampleFields["value"]; !ok {
			return metricEnvelope{}, fmt.Errorf("%w: value is required", ErrInvalidMetricBatch)
		}
		if _, ok := sampleFields["sampled_at"]; !ok {
			return metricEnvelope{}, fmt.Errorf("%w: sampled_at is required", ErrInvalidMetricBatch)
		}
		if _, ok := sampleFields["labels"]; !ok {
			return metricEnvelope{}, fmt.Errorf("%w: labels is required", ErrInvalidMetricBatch)
		}
		var sample metricPayload
		strict := json.NewDecoder(bytes.NewReader(raw))
		strict.DisallowUnknownFields()
		if err := strict.Decode(&sample); err != nil {
			return metricEnvelope{}, fmt.Errorf("%w: sample", ErrInvalidMetricBatch)
		}
		envelope.Samples = append(envelope.Samples, sample)
	}
	return envelope, nil
}

// DependencyTelemetryEnvelope is deliberately decoded here rather than by
// importing agent: control-plane owns the untrusted wire boundary and the
// agent package must not become a production dependency of its receiver.
type dependencyMetricEnvelope struct {
	BatchID     string                  `json:"batch_id"`
	Sequence    uint64                  `json:"sequence"`
	AgentID     string                  `json:"agent_id"`
	CollectedAt time.Time               `json:"collected_at"`
	Samples     []database.MetricSample `json:"samples"`
}

func isDependencyMetricEnvelope(fields map[string]json.RawMessage) bool {
	if _, ok := fields["batch_id"]; ok {
		return true
	}
	if _, ok := fields["sequence"]; ok {
		return true
	}
	_, ok := fields["collected_at"]
	return ok
}

func decodeDependencyMetricEnvelope(fields map[string]json.RawMessage) (metricEnvelope, error) {
	for key := range fields {
		// The Agent records agent_id in its durable envelope for diagnostics.
		// It is untrusted metadata and is intentionally ignored; the caller's
		// authenticated Agent ID is the only identity used for persistence.
		if isScopeClaim(key) {
			return metricEnvelope{}, ErrMetricScopeClaim
		}
		switch key {
		case "batch_id", "sequence", "agent_id", "collected_at", "samples", "statuses", "health", "evidence":
		default:
			return metricEnvelope{}, fmt.Errorf("%w: unknown dependency envelope field %q", ErrInvalidMetricBatch, key)
		}
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return metricEnvelope{}, fmt.Errorf("%w: dependency envelope", ErrInvalidMetricBatch)
	}
	var envelope dependencyMetricEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil || envelope.Samples == nil {
		return metricEnvelope{}, fmt.Errorf("%w: dependency samples", ErrInvalidMetricBatch)
	}

	result := metricEnvelope{Samples: make([]metricPayload, 0, len(envelope.Samples))}
	for _, sample := range envelope.Samples {
		sampledAt := sample.Timestamp
		if sampledAt.IsZero() {
			sampledAt = envelope.CollectedAt
		}
		labels := map[string]string{
			"instance":  sample.Instance,
			"component": sample.Component,
			"role":      sample.Role,
			"host":      sample.Host,
			"engine":    sample.Component,
		}
		if sample.Cluster != "" {
			labels["cluster"] = sample.Cluster
		}
		if sample.Unit != "" {
			labels["unit"] = sample.Unit
		}
		result.Samples = append(result.Samples, metricPayload{
			Name: sample.MetricName, Value: sample.Value, SampledAt: sampledAt.UTC().Format(time.RFC3339Nano), Labels: labels,
		})
	}
	return result, nil
}

func decodeOTLPMetricEnvelope(payload []byte, agentID string, receivedAt time.Time) (metricEnvelope, error) {
	metrics, err := (&pmetric.ProtoUnmarshaler{}).UnmarshalMetrics(payload)
	if err != nil {
		return metricEnvelope{}, fmt.Errorf("%w: unsupported metric payload", ErrInvalidMetricBatch)
	}
	result := metricEnvelope{}
	resources := metrics.ResourceMetrics()
	for resourceIndex := 0; resourceIndex < resources.Len(); resourceIndex++ {
		resource := resources.At(resourceIndex)
		resourceAttributes := otelAttributes(resource.Resource().Attributes())
		if err := rejectOTLPScopeClaims(resourceAttributes); err != nil {
			return metricEnvelope{}, err
		}
		scopes := resource.ScopeMetrics()
		for scopeIndex := 0; scopeIndex < scopes.Len(); scopeIndex++ {
			metricList := scopes.At(scopeIndex).Metrics()
			for metricIndex := 0; metricIndex < metricList.Len(); metricIndex++ {
				metric := metricList.At(metricIndex)
				switch metric.Type() {
				case pmetric.MetricTypeGauge:
					if err := appendOTLPNumberPoints(&result, metric.Name(), resourceAttributes, metric.Gauge().DataPoints(), agentID, receivedAt); err != nil {
						return metricEnvelope{}, err
					}
				case pmetric.MetricTypeSum:
					if err := appendOTLPNumberPoints(&result, metric.Name(), resourceAttributes, metric.Sum().DataPoints(), agentID, receivedAt); err != nil {
						return metricEnvelope{}, err
					}
				}
			}
		}
	}
	if len(result.Samples) == 0 {
		return metricEnvelope{}, fmt.Errorf("%w: OTLP contains no numeric datapoints", ErrInvalidMetricBatch)
	}
	return result, nil
}

func appendOTLPNumberPoints(result *metricEnvelope, name string, resourceAttributes map[string]string, points pmetric.NumberDataPointSlice, agentID string, receivedAt time.Time) error {
	for pointIndex := 0; pointIndex < points.Len(); pointIndex++ {
		point := points.At(pointIndex)
		if point.ValueType() != pmetric.NumberDataPointValueTypeDouble && point.ValueType() != pmetric.NumberDataPointValueTypeInt {
			continue
		}
		attributes := mapsClone(resourceAttributes)
		for key, value := range otelAttributes(point.Attributes()) {
			attributes[key] = value
		}
		labels, err := canonicalOTLPLabels(attributes, agentID)
		if err != nil {
			return err
		}
		timestamp := point.Timestamp()
		if timestamp == 0 {
			timestamp = point.StartTimestamp()
		}
		sampledAt := receivedAt
		if timestamp != 0 {
			sampledAt = timestamp.AsTime()
		}
		if sampledAt.IsZero() {
			sampledAt = receivedAt
		}
		value := point.DoubleValue()
		if point.ValueType() == pmetric.NumberDataPointValueTypeInt {
			value = float64(point.IntValue())
		}
		result.Samples = append(result.Samples, metricPayload{
			Name: name, Value: value, SampledAt: sampledAt.UTC().Format(time.RFC3339Nano), Labels: labels,
		})
	}
	return nil
}

func otelAttributes(attributes pcommon.Map) map[string]string {
	result := make(map[string]string)
	attributes.Range(func(key string, value pcommon.Value) bool {
		switch value.Type() {
		case pcommon.ValueTypeStr:
			result[key] = value.Str()
		case pcommon.ValueTypeBool:
			result[key] = fmt.Sprintf("%t", value.Bool())
		case pcommon.ValueTypeInt:
			result[key] = fmt.Sprintf("%d", value.Int())
		case pcommon.ValueTypeDouble:
			result[key] = fmt.Sprintf("%g", value.Double())
		}
		return true
	})
	return result
}

func canonicalOTLPLabels(attributes map[string]string, agentID string) (map[string]string, error) {
	component := firstMetricAttribute(attributes, "component", "service.name", "db.system", "dbpilot.source.id")
	if component == "" {
		component = "telemetry"
	}
	engine := firstMetricAttribute(attributes, "engine", "db.system", "db_system")
	if engine == "" {
		engine = component
	}
	labels := map[string]string{
		"instance":  firstNonEmpty(firstMetricAttribute(attributes, "instance", "service.instance.id", "db.instance.id", "dbpilot.source.id", "service.name"), agentID),
		"component": component,
		"role":      firstNonEmpty(firstMetricAttribute(attributes, "role", "db.role", "service.role"), "collector"),
		"host":      firstNonEmpty(firstMetricAttribute(attributes, "host", "host.name", "server.address", "net.host.name"), agentID),
		"engine":    engine,
	}
	keys := make([]string, 0, len(attributes))
	for key := range attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if isOTLPScopeClaim(key) {
			return nil, ErrMetricScopeClaim
		}
		normalized := normalizeOTLPLabelKey(key)
		value := strings.TrimSpace(attributes[key])
		if normalized == "" || !metricLabelKey.MatchString(normalized) || isOTLPAgentClaim(key) || isUnsafeOTLPAttribute(normalized, value) {
			continue
		}
		if _, exists := labels[normalized]; exists || len(labels) >= 64 {
			continue
		}
		labels[normalized] = value
	}
	return labels, nil
}

func rejectOTLPScopeClaims(attributes map[string]string) error {
	for key := range attributes {
		if isOTLPScopeClaim(key) {
			return ErrMetricScopeClaim
		}
	}
	return nil
}

func isOTLPScopeClaim(key string) bool {
	normalized := normalizeOTLPLabelKey(key)
	return normalized == "tenant" || normalized == "tenant_id" || normalized == "project" || normalized == "project_id" || normalized == "scope" || strings.HasSuffix(normalized, "_tenant_id") || strings.HasSuffix(normalized, "_project_id")
}

func isOTLPAgentClaim(key string) bool {
	normalized := normalizeOTLPLabelKey(key)
	return normalized == "agent" || normalized == "agent_id" || strings.HasSuffix(normalized, "_agent_id")
}

func normalizeOTLPLabelKey(key string) string {
	var result strings.Builder
	separator := false
	for _, character := range strings.ToLower(strings.TrimSpace(key)) {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' {
			result.WriteRune(character)
			separator = false
			continue
		}
		if !separator && result.Len() > 0 {
			result.WriteByte('_')
			separator = true
		}
	}
	normalized := strings.Trim(result.String(), "_")
	if normalized == "" {
		return ""
	}
	if first := normalized[0]; first >= '0' && first <= '9' {
		normalized = "_" + normalized
	}
	return normalized
}

func isUnsafeOTLPAttribute(key, value string) bool {
	for _, marker := range []string{"password", "passwd", "secret", "token", "credential", "api_key", "authorization"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	normalized := strings.ToLower(value)
	for _, marker := range []string{"password=", "passwd=", "secret=", "token=", "bearer ", "authorization:", "postgres://", "postgresql://", "mysql://"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func firstMetricAttribute(attributes map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(attributes[key]); value != "" {
			return value
		}
	}
	return ""
}

func firstNonEmpty(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func mapsClone(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func ensureJSONEnd(decoder *json.Decoder) error {
	if decoder.More() {
		return fmt.Errorf("%w: trailing JSON", ErrInvalidMetricBatch)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON", ErrInvalidMetricBatch)
	}
	return nil
}

func isIdentityClaim(key string) bool {
	return isScopeClaim(key) || key == "agent_id" || key == "agent"
}

func isScopeClaim(key string) bool {
	switch key {
	case "tenant_id", "project_id", "tenant", "project", "scope":
		return true
	default:
		return false
	}
}

func populateIdentity(sample *alert.MetricSample) {
	sample.InstanceID = sample.Labels["instance"]
	sample.Component = sample.Labels["component"]
	sample.Role = sample.Labels["role"]
	sample.Host = sample.Labels["host"]
}
