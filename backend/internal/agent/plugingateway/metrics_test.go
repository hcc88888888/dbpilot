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
	payload, id, err := normalizeBatch(batch, MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, DatabaseFamily: "mysql"}, now)
	require.NoError(t, err)
	require.NotEmpty(t, payload)
	require.Contains(t, id, "plugin-metrics-v1-")
}

func TestNormalizeBatchRejectsPluginScopeAndInvalidValues(t *testing.T) {
	now := time.Now().UTC()
	base := func() *pluginv1.PluginMetricBatch {
		return &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1", ConfigurationRevision: 4, TemplateId: "builtin", TemplateRevision: 1, Sequence: 1, CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: 1, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
	}
	scope := MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1", AssignmentID: "assignment-1", InstanceIDs: []string{"mysql-1"}, DatabaseFamily: "mysql"}

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
