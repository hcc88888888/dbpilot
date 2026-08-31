package plugingateway

import (
	"math"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNormalizeBatchInjectsAuthoritativeScope(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	batch := &pluginv1.PluginMetricBatch{
		PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1",
		ConfigurationRevision: 4, TemplateId: "builtin", TemplateRevision: 1, Sequence: 1, CollectedAt: timestamppb.New(now),
		CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED,
		Samples:          []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: 12, Unit: "{connections}", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Labels: map[string]string{"role": "primary"}, SampledAt: timestamppb.New(now)}},
	}
	payload, id, err := normalizeBatch(batch, MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}, DatabaseFamily: "mysql", PluginID: "mysql", PluginVersion: "1.0.0", ConfigurationRevision: 4, DatabaseVariant: "mysql", TemplateRevision: 1}, now)
	require.NoError(t, err)
	require.NotEmpty(t, payload)
	require.Contains(t, id, "plugin-metrics-v1-")
}

func TestNormalizeBatchRejectsPluginScopeAndInvalidValues(t *testing.T) {
	now := time.Now().UTC()
	base := func() *pluginv1.PluginMetricBatch {
		return &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1", ConfigurationRevision: 4, TemplateId: "builtin", TemplateRevision: 1, Sequence: 1, CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: 1, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
	}
	scope := MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}, DatabaseFamily: "mysql", PluginID: "mysql", PluginVersion: "1.0.0", ConfigurationRevision: 4, DatabaseVariant: "mysql", TemplateRevision: 1}

	reserved := base()
	reserved.Samples[0].Labels = map[string]string{"tenant.id": "forged"}
	_, _, err := normalizeBatch(reserved, scope, now)
	require.Error(t, err)

	invalid := base()
	invalid.Samples[0].Value = math.NaN()
	_, _, err = normalizeBatch(invalid, scope, now)
	require.Error(t, err)

	future := base()
	future.Samples[0].SampledAt = timestamppb.New(now.Add(6 * time.Minute))
	_, _, err = normalizeBatch(future, scope, now)
	require.Error(t, err)
}

func TestNormalizeBatchRejectsEveryNormalizedAuthoritativeAlias(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	scope := MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}, DatabaseFamily: "mysql", PluginID: "mysql", PluginVersion: "1.0.0", ConfigurationRevision: 4, DatabaseVariant: "mysql", TemplateRevision: 1}
	aliases := []string{"tenant-id", "dbpilot.tenant.id", "project_id", "x-project-id", "agent-id", "host.name", "host_name", "service.instance.id", "assignment_id", "instance-id", "database.family", "db.system", "database_variant", "plugin-id", "plugin.version", "template_id", "template-revision", "configuration_revision", "plugin_sequence", "dbpilot.source.id", "service.name"}
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			batch := testBatch(now, 1, 1)
			batch.Samples[0].Labels = map[string]string{alias: "forged"}
			_, _, err := normalizeBatch(batch, scope, now)
			require.Error(t, err)
		})
	}
}

func TestNormalizeBatchCanonicalizesSampleOrder(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	scope := MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}, DatabaseFamily: "mysql", PluginID: "mysql", PluginVersion: "1.0.0", ConfigurationRevision: 4, DatabaseVariant: "mysql", TemplateRevision: 1}
	first := testBatch(now, 1, 1)
	first.Samples = append(first.Samples, &pluginv1.PluginMetricSample{MetricName: "mysql.connections.current", Value: 2, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Labels: map[string]string{"role": "replica"}, SampledAt: timestamppb.New(now.Add(-time.Second))})
	second := testBatch(now, 1, 1)
	second.Samples = []*pluginv1.PluginMetricSample{first.Samples[1], first.Samples[0]}
	payloadA, _, err := normalizeBatch(first, scope, now)
	require.NoError(t, err)
	payloadB, _, err := normalizeBatch(second, scope, now)
	require.NoError(t, err)
	require.Equal(t, payloadA, payloadB)
}

func TestNormalizeBatchRejectsContradictoryStatusMatrixAndUnknownEnums(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	scope := MetricScope{AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}, DatabaseFamily: "mysql", PluginID: "mysql", PluginVersion: "1.0.0", ConfigurationRevision: 4, DatabaseVariant: "mysql", TemplateRevision: 1}
	tests := map[string]func(*pluginv1.PluginMetricBatch){
		"unknown status":     func(value *pluginv1.PluginMetricBatch) { value.CollectionStatus = pluginv1.PluginCollectionStatus(99) },
		"success with error": func(value *pluginv1.PluginMetricBatch) { value.ErrorCode = "timeout" },
		"failed without reason": func(value *pluginv1.PluginMetricBatch) {
			value.CollectionStatus = pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_FAILED
			value.Samples = nil
		},
		"unknown metric type": func(value *pluginv1.PluginMetricBatch) { value.Samples[0].MetricType = pluginv1.PluginMetricType(99) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			batch := testBatch(now, 1, 1)
			mutate(batch)
			_, _, err := normalizeBatch(batch, scope, now)
			require.Error(t, err)
		})
	}
}

func TestNormalizeBatchPreservesFailedZeroSampleCollectionAsStatusMetric(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	batch := &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1", ConfigurationRevision: 4, TemplateId: "builtin", TemplateRevision: 1, Sequence: 1, CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_FAILED, ErrorCode: "instance_unreachable"}
	payload, _, err := NormalizeBatch(batch, MetricScope{AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}, DatabaseFamily: "mysql", PluginID: "mysql", PluginVersion: "1.0.0", ConfigurationRevision: 4, DatabaseVariant: "mysql", TemplateRevision: 1}, now)
	require.NoError(t, err)
	require.NotEmpty(t, payload)
}

func TestNormalizeBatchPreservesPartialAndStaleStatusMetrics(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	scope := MetricScope{AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}, DatabaseFamily: "mysql", PluginID: "mysql", PluginVersion: "1.0.0", ConfigurationRevision: 4, DatabaseVariant: "mysql", TemplateRevision: 1}
	for _, status := range []pluginv1.PluginCollectionStatus{pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_PARTIAL, pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_STALE} {
		batch := testBatch(now, uint64(status), 1)
		batch.CollectionStatus = status
		batch.ErrorCode = "timeout"
		if status == pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_STALE {
			batch.Samples = nil
		}
		payload, _, err := NormalizeBatch(batch, scope, now)
		require.NoError(t, err)
		require.NotEmpty(t, payload)
	}
}

func TestFixedPluginCodeNeverLeaksPluginVocabulary(t *testing.T) {
	require.Equal(t, "waiting_templates", fixedPluginCode("waiting_templates"))
	require.Equal(t, "plugin_failed", fixedPluginCode("plugin says: secret=do-not-log"))
}
