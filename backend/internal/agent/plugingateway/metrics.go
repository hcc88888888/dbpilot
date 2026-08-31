package plugingateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

const (
	maxPluginSamples     = 1024
	maxPluginLabels      = 16
	maxPluginLabelBytes  = 128
	maxMetricAge         = time.Hour
	maxMetricFutureSkew  = 5 * time.Minute
	pluginMetricSourceID = "plugin-runtime"
)

var (
	pluginMetricName = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)
	pluginLabelName  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	pluginUnit       = regexp.MustCompile(`^[A-Za-z0-9%{}./_-]{1,32}$`)
	reservedLabels   = map[string]struct{}{
		"tenant.id": {}, "project.id": {}, "agent.id": {}, "host.id": {}, "assignment.id": {}, "instance.id": {},
		"database.family": {}, "database.variant": {}, "dbpilot.tenant.id": {}, "dbpilot.project.id": {}, "dbpilot.agent.id": {},
		"dbpilot.host.id": {}, "dbpilot.assignment.id": {}, "dbpilot.instance.id": {},
	}
)

// MetricScope contains Agent-owned dimensions. Plugins are not allowed to set
// any of these values, including through labels.
type MetricScope struct {
	TenantID       string
	ProjectID      string
	AgentID        string
	HostID         string
	AssignmentID   string
	InstanceIDs    []string
	DatabaseFamily string
}

func (scope MetricScope) validate() error {
	if scope.validateAgent() != nil || !identifier(scope.AssignmentID) || !family(scope.DatabaseFamily) || len(scope.InstanceIDs) == 0 || len(scope.InstanceIDs) > maxAssignedInstances || !unique(scope.InstanceIDs) {
		return errInvalidMetric
	}
	return nil
}

func (scope MetricScope) validateAgent() error {
	if !identifier(scope.AgentID) || !identifier(scope.HostID) || (scope.TenantID != "" && !identifier(scope.TenantID)) || (scope.ProjectID != "" && !identifier(scope.ProjectID)) {
		return errInvalidMetric
	}
	return nil
}

func (scope MetricScope) permitsInstance(instanceID string) bool {
	for _, candidate := range scope.InstanceIDs {
		if candidate == instanceID {
			return true
		}
	}
	return false
}

var errInvalidMetric = errors.New("PLUGIN_METRIC_REJECTED")

// normalizeBatch converts only strictly validated plugin observations to an
// Agent-owned OTLP payload. The identifier is derived from canonical payload
// bytes, so the spool's (class,id) idempotency remains stable after reconnects.
func normalizeBatch(batch *pluginv1.PluginMetricBatch, scope MetricScope, now time.Time) ([]byte, string, error) {
	if batch == nil || scope.validate() != nil || !family(batch.GetPluginId()) || !family(batch.GetDatabaseFamily()) || batch.GetDatabaseFamily() != scope.DatabaseFamily || !version(batch.GetPluginVersion()) || !family(batch.GetDatabaseVariant()) || !scope.permitsInstance(batch.GetInstanceId()) || batch.GetConfigurationRevision() == 0 || !identifier(batch.GetTemplateId()) || batch.GetTemplateRevision() == 0 || batch.GetSequence() == 0 || len(batch.GetSamples()) == 0 || len(batch.GetSamples()) > maxPluginSamples || batch.GetCollectionStatus() == pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_UNSPECIFIED {
		return nil, "", errInvalidMetric
	}
	collectedAt := batch.GetCollectedAt()
	if collectedAt == nil || !collectedAt.IsValid() {
		return nil, "", errInvalidMetric
	}
	collected := collectedAt.AsTime().UTC()
	if collected.After(now.Add(maxMetricFutureSkew)) || collected.Before(now.Add(-maxMetricAge)) {
		return nil, "", errInvalidMetric
	}

	metrics := pmetric.NewMetrics()
	resourceMetrics := metrics.ResourceMetrics().AppendEmpty()
	resource := resourceMetrics.Resource().Attributes()
	resource.PutStr("tenant.id", scope.TenantID)
	resource.PutStr("project.id", scope.ProjectID)
	resource.PutStr("agent.id", scope.AgentID)
	resource.PutStr("host.id", scope.HostID)
	resource.PutStr("assignment.id", scope.AssignmentID)
	resource.PutStr("instance.id", batch.GetInstanceId())
	resource.PutStr("database.family", scope.DatabaseFamily)
	resource.PutStr("database.variant", batch.GetDatabaseVariant())
	resource.PutStr("plugin.id", batch.GetPluginId())
	resource.PutStr("plugin.version", batch.GetPluginVersion())
	resource.PutStr("template.id", batch.GetTemplateId())
	resource.PutInt("template.revision", int64(batch.GetTemplateRevision()))
	resource.PutInt("plugin.sequence", int64(batch.GetSequence()))
	scopeMetrics := resourceMetrics.ScopeMetrics().AppendEmpty()
	scopeMetrics.Scope().SetName("dbpilot.plugin-runtime")

	type sampleKey struct {
		name, unit string
		typ        pluginv1.PluginMetricType
	}
	groups := map[sampleKey][]*pluginv1.PluginMetricSample{}
	keys := make([]sampleKey, 0, len(batch.GetSamples()))
	seen := map[string]struct{}{}
	for _, sample := range batch.GetSamples() {
		if err := validateSample(sample, collected, now); err != nil {
			return nil, "", err
		}
		key := sampleKey{name: sample.GetMetricName(), unit: sample.GetUnit(), typ: sample.GetMetricType()}
		identity := sample.GetMetricName() + "\x00" + sample.GetUnit() + "\x00" + fmt.Sprint(sample.GetMetricType()) + "\x00" + canonicalLabels(sample.GetLabels())
		if _, duplicate := seen[identity]; duplicate {
			return nil, "", errInvalidMetric
		}
		seen[identity] = struct{}{}
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], sample)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return keys[i].name < keys[j].name
		}
		if keys[i].unit != keys[j].unit {
			return keys[i].unit < keys[j].unit
		}
		return keys[i].typ < keys[j].typ
	})
	for _, key := range keys {
		metric := scopeMetrics.Metrics().AppendEmpty()
		metric.SetName(key.name)
		metric.SetUnit(key.unit)
		isCounter := key.typ == pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_COUNTER || key.typ == pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER
		if isCounter {
			metric.SetEmptySum().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
			metric.Sum().SetIsMonotonic(key.typ == pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER)
		} else {
			metric.SetEmptyGauge()
		}
		for _, sample := range groups[key] {
			var point pmetric.NumberDataPoint
			if isCounter {
				point = metric.Sum().DataPoints().AppendEmpty()
			} else {
				point = metric.Gauge().DataPoints().AppendEmpty()
			}
			timestamp := sample.GetSampledAt().AsTime().UTC()
			point.SetTimestamp(pcommon.NewTimestampFromTime(timestamp))
			point.SetDoubleValue(sample.GetValue())
			labelKeys := make([]string, 0, len(sample.GetLabels()))
			for label := range sample.GetLabels() {
				labelKeys = append(labelKeys, label)
			}
			sort.Strings(labelKeys)
			for _, label := range labelKeys {
				point.Attributes().PutStr(label, sample.GetLabels()[label])
			}
		}
	}
	payload, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(metrics)
	if err != nil || len(payload) == 0 || len(payload) > maxRPCMessageBytes {
		return nil, "", errInvalidMetric
	}
	digest := sha256.Sum256(payload)
	return payload, "plugin-metrics-v1-" + hex.EncodeToString(digest[:]), nil
}

func validateSample(sample *pluginv1.PluginMetricSample, collected, now time.Time) error {
	if sample == nil || !pluginMetricName.MatchString(sample.GetMetricName()) || !pluginUnit.MatchString(sample.GetUnit()) || !finite(sample.GetValue()) || sample.GetMetricType() == pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_UNSPECIFIED || len(sample.GetLabels()) > maxPluginLabels {
		return errInvalidMetric
	}
	timestamp := sample.GetSampledAt()
	if timestamp == nil || !timestamp.IsValid() {
		return errInvalidMetric
	}
	observed := timestamp.AsTime().UTC()
	if observed.After(now.Add(maxMetricFutureSkew)) || observed.Before(now.Add(-maxMetricAge)) || observed.After(collected.Add(maxMetricFutureSkew)) || observed.Before(collected.Add(-maxMetricAge)) {
		return errInvalidMetric
	}
	for key, value := range sample.GetLabels() {
		if !pluginLabelName.MatchString(key) || len(value) == 0 || len(value) > maxPluginLabelBytes || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return errInvalidMetric
		}
		if _, reserved := reservedLabels[key]; reserved || strings.HasPrefix(key, "dbpilot.") {
			return errInvalidMetric
		}
	}
	return nil
}

func canonicalLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var value strings.Builder
	for _, key := range keys {
		value.WriteString(key)
		value.WriteByte('=')
		value.WriteString(labels[key])
		value.WriteByte(0)
	}
	return value.String()
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
