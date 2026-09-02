package plugingateway

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

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
	pluginMetricName         = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,127}$`)
	pluginLabelName          = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
	pluginUnit               = regexp.MustCompile(`^[A-Za-z0-9%{}./_-]{1,32}$`)
	reservedNormalizedLabels = map[string]struct{}{
		"tenant": {}, "tenant_id": {}, "project": {}, "project_id": {}, "scope": {}, "agent": {}, "agent_id": {},
		"host": {}, "host_id": {}, "host_name": {}, "assignment": {}, "assignment_id": {}, "instance": {}, "instance_id": {},
		"service_name": {}, "service_instance_id": {}, "database_family": {}, "database_variant": {}, "db_system": {},
		"plugin": {}, "plugin_id": {}, "plugin_version": {}, "template": {}, "template_id": {}, "template_revision": {},
		"configuration": {}, "configuration_revision": {}, "sequence": {}, "plugin_sequence": {}, "source": {}, "source_id": {}, "dbpilot_source_id": {},
	}
)

// MetricScope contains Agent-owned dimensions. Plugins are not allowed to set
// any of these values, including through labels.
type MetricScope struct {
	TenantID              string
	ProjectID             string
	AgentID               string
	HostID                string
	AssignmentID          string
	InstanceIDs           []string
	TemplateIDs           []string
	DatabaseFamily        string
	PluginID              string
	PluginVersion         string
	ConfigurationRevision uint64
	DatabaseVariant       string
	TemplateRevision      uint64
}

func (scope MetricScope) validate() error {
	if scope.validateAgent() != nil || !identifier(scope.AssignmentID) || !family(scope.DatabaseFamily) || !family(scope.PluginID) || !version(scope.PluginVersion) || scope.ConfigurationRevision == 0 || !family(scope.DatabaseVariant) || scope.TemplateRevision == 0 || len(scope.InstanceIDs) == 0 || len(scope.InstanceIDs) > maxGatewayMembers || !unique(scope.InstanceIDs) || len(scope.TemplateIDs) == 0 || len(scope.TemplateIDs) > maxGatewayMembers || !unique(scope.TemplateIDs) {
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

func (scope MetricScope) permitsTemplate(templateID string) bool {
	return contains(scope.TemplateIDs, templateID)
}

var errInvalidMetric = errors.New("PLUGIN_METRIC_REJECTED")

// normalizeBatch converts only strictly validated plugin observations to an
// Agent-owned OTLP payload. The identifier is derived from canonical payload
// bytes, so the spool's (class,id) idempotency remains stable after reconnects.
func normalizeBatch(batch *pluginv1.PluginMetricBatch, scope MetricScope, now time.Time) ([]byte, string, error) {
	if batch == nil || scope.validate() != nil || batch.GetPluginId() != scope.PluginID || batch.GetPluginVersion() != scope.PluginVersion || batch.GetDatabaseFamily() != scope.DatabaseFamily || batch.GetDatabaseVariant() != scope.DatabaseVariant || !scope.permitsInstance(batch.GetInstanceId()) || batch.GetConfigurationRevision() != scope.ConfigurationRevision || !identifier(batch.GetTemplateId()) || !scope.permitsTemplate(batch.GetTemplateId()) || batch.GetTemplateRevision() != scope.TemplateRevision || batch.GetSequence() == 0 || len(batch.GetSamples()) > maxPluginSamples || !validCollectionResult(batch.GetCollectionStatus(), batch.GetErrorCode(), len(batch.GetSamples())) {
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
	// The Server deliberately rejects tenant/project claims in telemetry. Scope
	// is resolved from the authenticated Agent envelope there; only the
	// allowlisted operational dimensions below are Agent-owned.
	resource.PutStr("host.name", scope.HostID)
	resource.PutStr("service.name", "dbpilot-plugin-"+scope.DatabaseFamily)
	resource.PutStr("service.instance.id", batch.GetInstanceId())
	resource.PutStr("db.system", scope.DatabaseFamily)
	resource.PutStr("dbpilot.source.id", pluginMetricSourceID+":"+scope.AssignmentID)
	resource.PutStr("assignment_id", scope.AssignmentID)
	resource.PutStr("configuration_revision", fmt.Sprintf("%d", scope.ConfigurationRevision))
	resource.PutStr("template_id", batch.GetTemplateId())
	resource.PutStr("template_revision", fmt.Sprintf("%d", scope.TemplateRevision))
	resource.PutStr("plugin_id", scope.PluginID)
	resource.PutStr("plugin_version", scope.PluginVersion)
	resource.PutStr("database_variant", scope.DatabaseVariant)
	resource.PutStr("plugin_sequence", fmt.Sprintf("%d", batch.GetSequence()))
	scopeMetrics := resourceMetrics.ScopeMetrics().AppendEmpty()
	scopeMetrics.Scope().SetName("dbpilot.plugin-runtime")
	statusMetric := scopeMetrics.Metrics().AppendEmpty()
	statusMetric.SetName("dbpilot.plugin.collection.status")
	statusMetric.SetUnit("1")
	statusPoint := statusMetric.SetEmptyGauge().DataPoints().AppendEmpty()
	statusPoint.SetTimestamp(pcommon.NewTimestampFromTime(collected))
	statusPoint.SetDoubleValue(1)
	statusPoint.Attributes().PutStr("status", collectionStatus(batch.GetCollectionStatus()))
	if errorCode := fixedPluginCode(batch.GetErrorCode()); errorCode != "" {
		statusPoint.Attributes().PutStr("error_code", errorCode)
	}

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
		sort.Slice(groups[key], func(left, right int) bool {
			leftSample, rightSample := groups[key][left], groups[key][right]
			leftTime, rightTime := leftSample.GetSampledAt().AsTime(), rightSample.GetSampledAt().AsTime()
			if !leftTime.Equal(rightTime) {
				return leftTime.Before(rightTime)
			}
			leftLabels, rightLabels := canonicalLabels(leftSample.GetLabels()), canonicalLabels(rightSample.GetLabels())
			if leftLabels != rightLabels {
				return leftLabels < rightLabels
			}
			return math.Float64bits(leftSample.GetValue()) < math.Float64bits(rightSample.GetValue())
		})
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
			if start := sample.GetStartTime(); start != nil {
				point.SetStartTimestamp(pcommon.NewTimestampFromTime(start.AsTime().UTC()))
			}
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
	return payload, canonicalBatchID(scope.AssignmentID, batch.GetConfigurationRevision(), batch.GetTemplateId(), batch.GetInstanceId(), batch.GetSequence()), nil
}

// NormalizeBatch is the Server-compatible, Agent-owned metric envelope
// boundary. It never carries tenant/project claims from a plugin.
func NormalizeBatch(batch *pluginv1.PluginMetricBatch, scope MetricScope, now time.Time) ([]byte, string, error) {
	return normalizeBatch(batch, scope, now)
}

func canonicalBatchID(assignmentID string, configurationRevision uint64, templateID, instanceID string, sequence uint64) string {
	return fmt.Sprintf("plugin-metrics-v1-%s-%d-%s-%s-%d", assignmentID, configurationRevision, templateID, instanceID, sequence)
}

func validateSample(sample *pluginv1.PluginMetricSample, collected, now time.Time) error {
	if sample == nil || !pluginMetricName.MatchString(sample.GetMetricName()) || !pluginUnit.MatchString(sample.GetUnit()) || !finite(sample.GetValue()) || !validMetricType(sample.GetMetricType()) || len(sample.GetLabels()) > maxPluginLabels {
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
	if start := sample.GetStartTime(); start != nil {
		if !start.IsValid() || start.AsTime().UTC().After(observed) {
			return errInvalidMetric
		}
	}
	for key, value := range sample.GetLabels() {
		if !pluginLabelName.MatchString(key) || len(value) == 0 || len(value) > maxPluginLabelBytes || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return errInvalidMetric
		}
		normalized := normalizeMetricLabelKey(key)
		_, reserved := reservedNormalizedLabels[normalized]
		if reserved || strings.HasSuffix(normalized, "_tenant_id") || strings.HasSuffix(normalized, "_project_id") || strings.HasSuffix(normalized, "_agent_id") || strings.HasPrefix(normalized, "dbpilot_") {
			return errInvalidMetric
		}
	}
	return nil
}

func validMetricType(value pluginv1.PluginMetricType) bool {
	switch value {
	case pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE,
		pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_GAUGE,
		pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_COUNTER,
		pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER:
		return true
	default:
		return false
	}
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

func collectionStatus(value pluginv1.PluginCollectionStatus) string {
	switch value {
	case pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED:
		return "succeeded"
	case pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_PARTIAL:
		return "partial"
	case pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_FAILED:
		return "failed"
	case pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_STALE:
		return "stale"
	default:
		return "invalid"
	}
}

func validCollectionResult(status pluginv1.PluginCollectionStatus, errorCode string, sampleCount int) bool {
	switch status {
	case pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED:
		return sampleCount > 0 && errorCode == ""
	case pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_PARTIAL:
		return sampleCount > 0 && errorCode != ""
	case pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_FAILED, pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_STALE:
		return errorCode != ""
	default:
		return false
	}
}

func normalizeMetricLabelKey(key string) string {
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
	return strings.Trim(result.String(), "_")
}

// fixedPluginCode prevents arbitrary plugin-provided error vocabulary from
// becoming Agent telemetry. Deferred definitions are explicit Task11/12
// states, all other plugin failures collapse to one stable operational code.
func fixedPluginCode(value string) string {
	switch value {
	case "":
		return ""
	case "waiting_credentials", "waiting_templates", "instance_unreachable", "authentication_failed", "timeout", "unsupported", "result_limit_exceeded", "high_cardinality":
		return value
	default:
		return "plugin_failed"
	}
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
