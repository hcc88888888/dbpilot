package plugincontract

import (
	"crypto/sha256"
	"crypto/subtle"
	"regexp"
	"strings"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"google.golang.org/protobuf/proto"
)

const (
	MaximumBuiltinTemplates = 128
	MaximumBuiltinMetrics   = 32
)

var (
	templatePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	metricPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)
	unitPattern     = regexp.MustCompile(`^[A-Za-z0-9%{}./_-]{1,32}$`)
)

func BuiltinDescriptorDigest(value *pluginv1.BuiltinMetricTemplateDescriptor) []byte {
	if value == nil {
		return nil
	}
	cloned := proto.Clone(value).(*pluginv1.BuiltinMetricTemplateDescriptor)
	cloned.DefinitionDigest = nil
	body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cloned)
	if err != nil {
		return nil
	}
	digest := sha256.Sum256(body)
	clear(body)
	return digest[:]
}

func ValidateBuiltinDescriptors(values []*pluginv1.BuiltinMetricTemplateDescriptor, customTemplateIDs []string) (map[string]*pluginv1.BuiltinMetricTemplateDescriptor, bool) {
	if len(values) > MaximumBuiltinTemplates {
		return nil, false
	}
	custom := make(map[string]struct{}, len(customTemplateIDs))
	for _, id := range customTemplateIDs {
		if !templatePattern.MatchString(id) {
			return nil, false
		}
		if _, duplicate := custom[id]; duplicate {
			return nil, false
		}
		custom[id] = struct{}{}
	}
	result := make(map[string]*pluginv1.BuiltinMetricTemplateDescriptor, len(values))
	previousTemplate := ""
	for _, value := range values {
		if value == nil || len(value.ProtoReflect().GetUnknown()) != 0 || !templatePattern.MatchString(value.GetTemplateId()) || value.GetRevision() == 0 || value.GetCollectionIntervalSeconds() < 10 || value.GetCollectionIntervalSeconds() > 86400 || len(value.GetDefinitionDigest()) != sha256.Size || len(value.GetMetrics()) == 0 || len(value.GetMetrics()) > MaximumBuiltinMetrics || previousTemplate != "" && value.GetTemplateId() <= previousTemplate {
			return nil, false
		}
		if _, collision := custom[value.GetTemplateId()]; collision {
			return nil, false
		}
		digest := BuiltinDescriptorDigest(value)
		if len(digest) != sha256.Size || subtle.ConstantTimeCompare(digest, value.GetDefinitionDigest()) != 1 {
			return nil, false
		}
		previousMetric := ""
		for _, metric := range value.GetMetrics() {
			if metric == nil || len(metric.ProtoReflect().GetUnknown()) != 0 || !metricPattern.MatchString(metric.GetMetricName()) || !validMetricType(metric.GetMetricType()) || !unitPattern.MatchString(metric.GetUnit()) || strings.TrimSpace(metric.GetUnit()) != metric.GetUnit() || previousMetric != "" && metric.GetMetricName() <= previousMetric {
				return nil, false
			}
			previousMetric = metric.GetMetricName()
		}
		result[value.GetTemplateId()] = proto.Clone(value).(*pluginv1.BuiltinMetricTemplateDescriptor)
		previousTemplate = value.GetTemplateId()
	}
	return result, true
}

func validMetricType(value pluginv1.PluginMetricType) bool {
	switch value {
	case pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_GAUGE, pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_COUNTER, pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER:
		return true
	}
	return false
}
