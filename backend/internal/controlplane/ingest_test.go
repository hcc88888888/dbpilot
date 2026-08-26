package controlplane_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/controlplane"
	"github.com/stretchr/testify/require"
)

func TestMetricConsumerRejectsPayloadScopeClaim(t *testing.T) {
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), &recordingStore{})
	err := consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(`{"tenant_id":"other","samples":[]}`), time.Now().UTC())
	require.ErrorContains(t, err, "scope claim")
}

func TestMetricConsumerRejectsReservedIdentityClaimsAtEveryPayloadLevel(t *testing.T) {
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), &recordingStore{})
	now := time.Now().UTC()
	for _, name := range []string{"tenant_id", "project_id", "agent_id", "tenant", "project", "agent", "scope"} {
		for _, level := range []string{"envelope", "sample", "labels"} {
			t.Run(level+"/"+name, func(t *testing.T) {
				payload := identityClaimPayload(level, name)
				err := consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now)
				require.ErrorContains(t, err, "scope claim")
			})
		}
	}
}

func TestMetricConsumerResolvesScopeAndNormalizesMetricSample(t *testing.T) {
	store := &recordingStore{}
	now := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), store)

	err := consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(`{"samples":[{"name":"db.connections","value":12,"sampled_at":"2026-08-26T09:59:00Z","labels":{"instance":"db-1","component":"postgres","role":"primary","host":"db-1.internal"}}]}`), now)
	require.NoError(t, err)
	require.Len(t, store.samples, 1)
	require.Equal(t, alert.Scope{TenantID: "t1", ProjectID: "p1"}, store.samples[0].Scope)
	require.Equal(t, "agent-a", store.samples[0].AgentID)
	require.Equal(t, "db-1", store.samples[0].InstanceID)
}

func TestMetricConsumerRejectsInvalidEnvelopeAndUnknownAgentScope(t *testing.T) {
	now := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), &recordingStore{})
	err := consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(`{"samples":[{"name":"db.connections","value":12,"sampled_at":"2026-08-26T09:59:00Z","labels":{"bad-key":"x"}}]}`), now)
	require.Error(t, err)
	err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(`{"samples":null}`), now)
	require.Error(t, err)

	unknown := controlplane.NewMetricConsumer(resolverFor(), &recordingStore{})
	err = unknown.ConsumeMetricBatch(context.Background(), "agent-a", []byte(`{"samples":[]}`), now)
	require.Error(t, err)
}

func TestMetricConsumerDoesNotAppendWhenStoreIsUnavailable(t *testing.T) {
	store := &recordingStore{err: errors.New("store unavailable")}
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), store)
	err := consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(`{"samples":[]}`), time.Now().UTC())
	require.ErrorContains(t, err, "store unavailable")
	require.Empty(t, store.samples)
}

type recordingStore struct {
	samples []alert.MetricSample
	err     error
}

func (s *recordingStore) Append(_ context.Context, samples []alert.MetricSample) error {
	if s.err != nil {
		return s.err
	}
	s.samples = append(s.samples, samples...)
	return nil
}

func (*recordingStore) Query(context.Context, alert.MetricQuery) ([]alert.MetricSample, error) {
	return nil, nil
}

type agentResolver map[string]alert.Scope

func resolverFor(values ...any) agentResolver {
	resolver := agentResolver{}
	for index := 0; index < len(values); index += 2 {
		resolver[values[index].(string)] = values[index+1].(alert.Scope)
	}
	return resolver
}

func (r agentResolver) ScopeForAgent(_ context.Context, agentID string) (alert.Scope, error) {
	scope, ok := r[agentID]
	if !ok {
		return alert.Scope{}, errors.New("agent scope not found")
	}
	return scope, nil
}

func identityClaimPayload(level, name string) []byte {
	switch level {
	case "envelope":
		return []byte(fmt.Sprintf(`{"%s":"spoofed","samples":[]}`, name))
	case "sample":
		return []byte(fmt.Sprintf(`{"samples":[{"%s":"spoofed","name":"db.connections","value":1,"sampled_at":"2026-08-26T09:59:00Z","labels":{}}]}`, name))
	default:
		return []byte(fmt.Sprintf(`{"samples":[{"name":"db.connections","value":1,"sampled_at":"2026-08-26T09:59:00Z","labels":{"%s":"spoofed"}}]}`, name))
	}
}
