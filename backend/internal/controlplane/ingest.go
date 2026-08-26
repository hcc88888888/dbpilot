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
	"strings"
	"time"

	"dbpilot.local/platform/internal/alert"
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
	if c == nil || c.resolver == nil {
		return errors.New("metric scope resolver is unavailable")
	}
	if c.store == nil {
		return errors.New("metric store is unavailable")
	}
	scope, err := c.resolver.ScopeForAgent(ctx, agentID)
	if err != nil {
		return fmt.Errorf("resolve agent scope: %w", err)
	}
	if err := scope.Validate(); err != nil {
		return fmt.Errorf("resolve agent scope: %w", err)
	}
	envelope, err := decodeMetricEnvelope(payload)
	if err != nil {
		return err
	}

	samples := make([]alert.MetricSample, 0, len(envelope.Samples))
	for _, input := range envelope.Samples {
		sampledAt, err := time.Parse(time.RFC3339, input.SampledAt)
		if err != nil || sampledAt.IsZero() {
			return fmt.Errorf("%w: sampled_at must be RFC3339", ErrInvalidMetricBatch)
		}
		if sampledAt.After(receivedAt.Add(5 * time.Minute)) {
			return fmt.Errorf("%w: sampled_at is too far in the future", ErrInvalidMetricBatch)
		}
		if strings.TrimSpace(input.Name) == "" || math.IsNaN(input.Value) || math.IsInf(input.Value, 0) {
			return ErrInvalidMetricBatch
		}
		if input.Labels == nil || len(input.Labels) > 64 {
			return fmt.Errorf("%w: labels", ErrInvalidMetricBatch)
		}
		for key := range input.Labels {
			if isIdentityClaim(key) {
				return ErrMetricScopeClaim
			}
			if !metricLabelKey.MatchString(key) {
				return fmt.Errorf("%w: invalid label key", ErrInvalidMetricBatch)
			}
		}
		labels := make(map[string]string, len(input.Labels))
		for key, value := range input.Labels {
			labels[key] = value
		}
		sample := alert.MetricSample{Scope: scope, AgentID: agentID, Name: strings.TrimSpace(input.Name), Labels: labels, Value: input.Value, SampledAt: sampledAt}
		populateIdentity(&sample)
		samples = append(samples, sample)
	}
	if err := c.store.Append(ctx, samples); err != nil {
		return err
	}
	return nil
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

func decodeMetricEnvelope(payload []byte) (metricEnvelope, error) {
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
	switch key {
	case "tenant_id", "project_id", "agent_id", "tenant", "project", "agent", "scope":
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
