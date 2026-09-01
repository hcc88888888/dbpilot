package plugincontract

import (
	"testing"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestBuiltinDescriptorsRequireCanonicalDigestOrderingBoundsAndNoCustomCollision(t *testing.T) {
	up := &pluginv1.BuiltinMetricTemplateDescriptor{TemplateId: "mysql.up", Revision: 1, CollectionIntervalSeconds: 10, Metrics: []*pluginv1.BuiltinMetricDescriptor{{MetricName: "mysql.up", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Unit: "1"}}}
	up.DefinitionDigest = BuiltinDescriptorDigest(up)
	uptime := &pluginv1.BuiltinMetricTemplateDescriptor{TemplateId: "mysql.uptime.seconds", Revision: 1, CollectionIntervalSeconds: 10, Metrics: []*pluginv1.BuiltinMetricDescriptor{{MetricName: "mysql.uptime.seconds", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_GAUGE, Unit: "s"}}}
	uptime.DefinitionDigest = BuiltinDescriptorDigest(uptime)
	validated, ok := ValidateBuiltinDescriptors([]*pluginv1.BuiltinMetricTemplateDescriptor{up, uptime}, []string{"custom-a"})
	require.True(t, ok)
	require.Len(t, validated, 2)

	for name, mutate := range map[string]func([]*pluginv1.BuiltinMetricTemplateDescriptor){
		"unsorted templates": func(values []*pluginv1.BuiltinMetricTemplateDescriptor) { values[0], values[1] = values[1], values[0] },
		"digest mismatch":    func(values []*pluginv1.BuiltinMetricTemplateDescriptor) { values[0].DefinitionDigest[0] ^= 0xff },
		"custom collision": func(values []*pluginv1.BuiltinMetricTemplateDescriptor) {
			values[0].TemplateId = "custom-a"
			values[0].DefinitionDigest = BuiltinDescriptorDigest(values[0])
		},
		"invalid interval": func(values []*pluginv1.BuiltinMetricTemplateDescriptor) {
			values[0].CollectionIntervalSeconds = 9
			values[0].DefinitionDigest = BuiltinDescriptorDigest(values[0])
		},
		"unsorted metrics": func(values []*pluginv1.BuiltinMetricTemplateDescriptor) {
			values[0].Metrics = []*pluginv1.BuiltinMetricDescriptor{{MetricName: "mysql.z", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Unit: "1"}, {MetricName: "mysql.a", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Unit: "1"}}
			values[0].DefinitionDigest = BuiltinDescriptorDigest(values[0])
		},
		"unknown fields": func(values []*pluginv1.BuiltinMetricTemplateDescriptor) {
			values[0].ProtoReflect().SetUnknown([]byte{0x98, 0x06, 0x01})
			values[0].DefinitionDigest = BuiltinDescriptorDigest(values[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			values := []*pluginv1.BuiltinMetricTemplateDescriptor{proto.Clone(up).(*pluginv1.BuiltinMetricTemplateDescriptor), proto.Clone(uptime).(*pluginv1.BuiltinMetricTemplateDescriptor)}
			mutate(values)
			_, ok := ValidateBuiltinDescriptors(values, []string{"custom-a"})
			require.False(t, ok)
		})
	}
}
