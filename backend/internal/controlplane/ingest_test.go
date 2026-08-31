package controlplane_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/controlplane"
	"dbpilot.local/platform/internal/database"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func TestMetricConsumerAcceptsTelemetryEngineOTLPProtobuf(t *testing.T) {
	now := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), store)

	metrics := pmetric.NewMetrics()
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	resourceAttributes := resourceMetrics.Resource().Attributes()
	resourceAttributes.PutStr("instance", "postgres-1")
	resourceAttributes.PutStr("component", "postgres")
	resourceAttributes.PutStr("role", "primary")
	resourceAttributes.PutStr("host.name", "postgres-1.internal")
	metric := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("host.cpu.utilization")
	point := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	point.SetDoubleValue(42.5)
	point.SetTimestamp(pcommon.NewTimestampFromTime(now.Add(-time.Minute)))
	payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(metrics)
	require.NoError(t, err)

	err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now)
	require.NoError(t, err)
	require.Len(t, store.samples, 1)
	require.Equal(t, alert.Scope{TenantID: "t1", ProjectID: "p1"}, store.samples[0].Scope)
	require.Equal(t, "agent-a", store.samples[0].AgentID)
	require.Equal(t, "postgres-1.internal", store.samples[0].Host)
}

func TestMetricConsumerAcceptsAgentNormalizedPluginOTLP(t *testing.T) {
	now := time.Date(2026, time.August, 31, 10, 0, 0, 0, time.UTC)
	batch := &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1", ConfigurationRevision: 4, TemplateId: "template-1", TemplateRevision: 1, Sequence: 1, CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: 12, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
	payload, _, err := plugingateway.NormalizeBatch(batch, plugingateway.MetricScope{TenantID: "t1", ProjectID: "p1", AgentID: "agent-a", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"template-1"}, DatabaseFamily: "mysql", PluginID: "mysql", PluginVersion: "1.0.0", ConfigurationRevision: 4, DatabaseVariant: "mysql", TemplateRevision: 1}, now)
	require.NoError(t, err)
	store := &recordingStore{}
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), store)
	require.NoError(t, consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now))
	require.Len(t, store.samples, 2)
	for _, sample := range store.samples {
		require.Equal(t, alert.Scope{TenantID: "t1", ProjectID: "p1"}, sample.Scope)
		require.Equal(t, "agent-a", sample.AgentID)
		require.Equal(t, "mysql-1", sample.InstanceID)
	}
	require.Equal(t, "dbpilot.plugin.collection.status", store.samples[0].Name)
	require.Equal(t, "succeeded", store.samples[0].Labels["status"])
}

func TestMetricConsumerRejectsOTLPScopeClaims(t *testing.T) {
	now := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), &recordingStore{})
	for _, location := range []string{"resource", "datapoint"} {
		t.Run(location, func(t *testing.T) {
			metrics := pmetric.NewMetrics()
			resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
			attributes := resourceMetrics.Resource().Attributes()
			attributes.PutStr("instance", "postgres-1")
			attributes.PutStr("component", "postgres")
			attributes.PutStr("role", "primary")
			attributes.PutStr("host", "postgres-1.internal")
			metric := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
			metric.SetName("host.cpu.utilization")
			point := metric.SetEmptyGauge().DataPoints().AppendEmpty()
			point.SetDoubleValue(42.5)
			point.SetTimestamp(pcommon.NewTimestampFromTime(now.Add(-time.Minute)))
			if location == "resource" {
				attributes.PutStr("tenant_id", "payload-scope")
			} else {
				point.Attributes().PutStr("project-id", "payload-scope")
			}
			payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(metrics)
			require.NoError(t, err)
			err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now)
			require.ErrorContains(t, err, "scope claim")
		})
	}
}

func TestMetricConsumerRejectsOTLPScopeClaimWithNonScalarValue(t *testing.T) {
	now := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), &recordingStore{})
	metrics := pmetric.NewMetrics()
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	attributes := resourceMetrics.Resource().Attributes()
	attributes.PutStr("instance", "postgres-1")
	attributes.PutStr("component", "postgres")
	attributes.PutStr("role", "primary")
	attributes.PutStr("host", "postgres-1.internal")
	attributes.PutEmptySlice("tenant-id")
	metric := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("host.cpu.utilization")
	point := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	point.SetDoubleValue(42.5)
	point.SetTimestamp(pcommon.NewTimestampFromTime(now.Add(-time.Minute)))
	payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(metrics)
	require.NoError(t, err)

	err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now)
	require.ErrorContains(t, err, "scope claim")
}

func TestMetricConsumerRejectsOTLPScopeClaimOnEmptyNumericDatapoint(t *testing.T) {
	now := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), &recordingStore{})
	metrics := pmetric.NewMetrics()
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	attributes := resourceMetrics.Resource().Attributes()
	attributes.PutStr("instance", "postgres-1")
	attributes.PutStr("component", "postgres")
	attributes.PutStr("role", "primary")
	attributes.PutStr("host", "postgres-1.internal")
	metric := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("host.cpu.utilization")
	metric.SetEmptyGauge().DataPoints().AppendEmpty().Attributes().PutEmptyMap("tenant-id")
	payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(metrics)
	require.NoError(t, err)

	err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now)
	require.ErrorContains(t, err, "scope claim")
}

func TestMetricConsumerRejectsOTLPNormalizedLabelKeyCollision(t *testing.T) {
	now := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), &recordingStore{})
	metrics := pmetric.NewMetrics()
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	attributes := resourceMetrics.Resource().Attributes()
	attributes.PutStr("instance", "postgres-1")
	attributes.PutStr("component", "postgres")
	attributes.PutStr("role", "primary")
	attributes.PutStr("host", "postgres-1.internal")
	metric := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("system.disk.io")
	point := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	point.SetDoubleValue(1)
	point.SetTimestamp(pcommon.NewTimestampFromTime(now))
	point.Attributes().PutStr("device.name", "sda")
	point.Attributes().PutStr("device-name", "sdb")
	payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(metrics)
	require.NoError(t, err)

	err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now)
	require.ErrorIs(t, err, controlplane.ErrInvalidMetricBatch)
}

func TestMetricConsumerPreservesSafeOTLPSumDimensionsAndUsesReceivedTimeForZeroTimestamp(t *testing.T) {
	now := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), store)
	metrics := pmetric.NewMetrics()
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	attributes := resourceMetrics.Resource().Attributes()
	attributes.PutStr("instance", "postgres-1")
	attributes.PutStr("component", "postgres")
	attributes.PutStr("role", "primary")
	attributes.PutStr("host", "postgres-1.internal")
	metric := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("system.disk.io")
	points := metric.SetEmptySum().DataPoints()
	for _, device := range []string{"sda", "sdb"} {
		point := points.AppendEmpty()
		point.SetIntValue(7)
		point.Attributes().PutStr("device.name", device)
		point.Attributes().PutStr("cpu-id", "0")
		point.Attributes().PutStr("agent_id", "untrusted-payload-agent")
		point.Attributes().PutStr("api.token", "secret-value")
	}
	payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(metrics)
	require.NoError(t, err)

	err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now)
	require.NoError(t, err)
	require.Len(t, store.samples, 2)
	require.Equal(t, float64(7), store.samples[0].Value)
	require.Equal(t, now, store.samples[0].SampledAt)
	require.Equal(t, "sda", store.samples[0].Labels["device_name"])
	require.Equal(t, "sdb", store.samples[1].Labels["device_name"])
	require.Equal(t, "0", store.samples[0].Labels["cpu_id"])
	require.NotContains(t, store.samples[0].Labels, "agent_id")
	require.NotContains(t, store.samples[0].Labels, "api_token")
	require.NotEqual(t, alert.SeriesFingerprint(store.samples[0].Labels), alert.SeriesFingerprint(store.samples[1].Labels))
}

func TestMetricConsumerLimitsOTLPAttributeLabels(t *testing.T) {
	now := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), store)
	metrics := pmetric.NewMetrics()
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	attributes := resourceMetrics.Resource().Attributes()
	attributes.PutStr("instance", "postgres-1")
	attributes.PutStr("component", "postgres")
	attributes.PutStr("role", "primary")
	attributes.PutStr("host", "postgres-1.internal")
	metric := resourceMetrics.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	metric.SetName("host.cpu.utilization")
	point := metric.SetEmptyGauge().DataPoints().AppendEmpty()
	point.SetDoubleValue(1)
	point.SetTimestamp(pcommon.NewTimestampFromTime(now))
	for index := 0; index < 70; index++ {
		point.Attributes().PutStr(fmt.Sprintf("dimension-%02d", index), "value")
	}
	payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(metrics)
	require.NoError(t, err)

	err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now)
	require.NoError(t, err)
	require.Len(t, store.samples, 1)
	require.Len(t, store.samples[0].Labels, 64)
}

func TestMetricConsumerAcceptsDependencyCollectorEnvelopeWithoutTrustingAgentID(t *testing.T) {
	now := time.Date(2026, time.August, 27, 10, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), store)
	payload, err := json.Marshal(agent.DependencyTelemetryEnvelope{
		BatchID: "dependency-batch-1", Sequence: 7, AgentID: "untrusted-payload-agent", CollectedAt: now.Add(-time.Minute),
		Samples: []database.MetricSample{{
			Cluster: "hbase-a", Component: "hbase", Role: "regionserver", Host: "rs-1.internal", Instance: "hbase-a-rs-1",
			MetricName: "hbase.flush.queue_length", Value: 3, Timestamp: now.Add(-time.Minute),
		}},
	})
	require.NoError(t, err)

	err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", payload, now)
	require.NoError(t, err)
	require.Len(t, store.samples, 1)
	require.Equal(t, alert.Scope{TenantID: "t1", ProjectID: "p1"}, store.samples[0].Scope)
	require.Equal(t, "agent-a", store.samples[0].AgentID)
	require.Equal(t, "hbase-a-rs-1", store.samples[0].InstanceID)
	require.Equal(t, "regionserver", store.samples[0].Role)

	err = consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(`{"batch_id":"dependency-batch-2","agent_id":"untrusted-payload-agent","tenant_id":"payload-scope","samples":[]}`), now)
	require.ErrorContains(t, err, "scope claim")
}

func TestMetricConsumerRejectsEachMissingCanonicalResourceDimension(t *testing.T) {
	now := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), &recordingStore{})
	for _, missing := range []string{"instance", "component", "role", "host"} {
		t.Run(missing, func(t *testing.T) {
			labels := map[string]string{"instance": "db-1", "component": "postgres", "role": "primary", "host": "db-1.internal"}
			delete(labels, missing)
			payload := fmt.Sprintf(`{"samples":[{"name":"db.connections","value":12,"sampled_at":"2026-08-26T09:59:00Z","labels":{"instance":%q,"component":%q,"role":%q,"host":%q}}]}`,
				labels["instance"], labels["component"], labels["role"], labels["host"])
			err := consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(payload), now)
			require.ErrorContains(t, err, missing)
		})
	}
}

func TestMetricConsumerRejectsSensitiveLabelsBeforePersistence(t *testing.T) {
	now := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)
	store := &recordingStore{}
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), store)
	for _, label := range []string{
		`"password":"hunter2"`,
		`"note":"token=abcdef"`,
	} {
		payload := fmt.Sprintf(`{"samples":[{"name":"db.connections","value":12,"sampled_at":"2026-08-26T09:59:00Z","labels":{"instance":"db-1","component":"postgres","role":"primary","host":"db-1.internal",%s}}]}`, label)
		err := consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(payload), now)
		require.Error(t, err)
	}
	require.Empty(t, store.samples)
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

func TestMetricConsumerAtomicallyStoresBatchIdentityWithSamples(t *testing.T) {
	store := &atomicRecordingStore{first: true}
	consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{TenantID: "t1", ProjectID: "p1"}), store)
	now := time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC)

	first, err := consumer.ConsumeMetricBatchOnce(context.Background(), "agent-a", "batch-a", []byte(`{"samples":[{"name":"db.connections","value":12,"sampled_at":"2026-08-26T09:59:00Z","labels":{"instance":"db-1","component":"postgres","role":"primary","host":"db-1.internal"}}]}`), now)
	require.NoError(t, err)
	require.True(t, first)
	require.Equal(t, "agent-a", store.agentID)
	require.Equal(t, "batch-a", store.batchID)
	require.Len(t, store.samples, 1)
}

type recordingStore struct {
	samples []alert.MetricSample
	err     error
}

type atomicRecordingStore struct {
	recordingStore
	agentID string
	batchID string
	first   bool
}

func (s *atomicRecordingStore) AppendBatch(_ context.Context, agentID, batchID string, samples []alert.MetricSample) (bool, error) {
	s.agentID = agentID
	s.batchID = batchID
	s.samples = append(s.samples, samples...)
	return s.first, s.err
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
