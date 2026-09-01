package mysqlplugin

import (
	"context"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
)

const builtinStatusQuery = "SELECT VARIABLE_NAME, VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME IN ('Threads_connected','Queries','Threads_running','Uptime')"

type CollectorOptions struct {
	Now              func() time.Time
	Timeout          time.Duration
	MaxConcurrent    int
	FailureThreshold int
	CircuitOpenFor   time.Duration
}

type circuitState struct {
	failures  int
	openUntil time.Time
}

type HealthStatus int

const (
	HealthHealthy HealthStatus = iota
	HealthDegraded
	HealthUnhealthy
)

type collectionHealth struct{ code string }

type Collector struct {
	runtime   *Runtime
	options   CollectorOptions
	semaphore chan struct{}
	mu        sync.Mutex
	circuits  map[string]circuitState
	queries   map[string]float64
	health    map[string]collectionHealth
}

func NewCollector(runtime *Runtime, options CollectorOptions) *Collector {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Timeout <= 0 {
		options.Timeout = 5 * time.Second
	}
	if options.MaxConcurrent <= 0 {
		options.MaxConcurrent = 8
	}
	if options.FailureThreshold <= 0 {
		options.FailureThreshold = 3
	}
	if options.CircuitOpenFor <= 0 {
		options.CircuitOpenFor = 30 * time.Second
	}
	return &Collector{runtime: runtime, options: options, semaphore: make(chan struct{}, options.MaxConcurrent), circuits: map[string]circuitState{}, queries: map[string]float64{}, health: map[string]collectionHealth{}}
}

func (collector *Collector) Collect(ctx context.Context, instanceID string, templateIDs []string) Batch {
	now := collector.options.Now().UTC()
	result := Batch{InstanceID: instanceID, CollectedAt: now, Status: CollectionFailed}
	defer func(){if result.Status==CollectionSucceeded{collector.succeeded(instanceID)}else if result.ErrorCode!=""{collector.observe(instanceID,result.ErrorCode)}}()
	if len(templateIDs) == 0 {
		result.ErrorCode = "template_unavailable"
		return result
	}
	for _, id := range templateIDs {
		if _, valid := builtinCatalog[id]; !valid {
			result.ErrorCode = "template_unavailable"
			return result
		}
	}
	instance, ok := collector.runtime.Instance(instanceID)
	if !ok || instance.Pool == nil {
		result.ErrorCode = "waiting_credentials"
		if containsTemplate(templateIDs, "mysql.up") {
			result.Samples = []Sample{upSample(now, 0)}
		}
		return result
	}
	if collector.circuitOpen(instanceID, now) {
		result.ErrorCode = "connection_unavailable"
		if containsTemplate(templateIDs, "mysql.up") {
			result.Samples = []Sample{upSample(now, 0)}
		}
		return result
	}
	select {
	case collector.semaphore <- struct{}{}:
		defer func() { <-collector.semaphore }()
	case <-ctx.Done():
		result.ErrorCode = "collection_timeout"
		return result
	}
	callContext, cancel := context.WithTimeout(ctx, collector.options.Timeout)
	defer cancel()
	if err := instance.Pool.PingContext(callContext); err != nil {
		collector.failed(instanceID, now, "connection_unavailable")
		result.ErrorCode = "connection_unavailable"
		if containsTemplate(templateIDs, "mysql.up") {
			result.Samples = []Sample{upSample(now, 0)}
		}
		return result
	}
	requested := map[string]struct{}{}
	needStatus := false
	for _, id := range templateIDs {
		if _, valid := builtinCatalog[id]; valid {
			requested[id] = struct{}{}
			if id != "mysql.up" {
				needStatus = true
			}
		}
	}
	if containsTemplate(templateIDs, "mysql.up") {
		result.Samples = append(result.Samples, upSample(now, 1))
	}
	values := map[string]float64{}
	if needStatus {
		rows, err := instance.Pool.QueryContext(callContext, builtinStatusQuery)
		if err != nil {
			collector.failed(instanceID, now, "query_failed")
			result.ErrorCode = "query_failed"
			if len(result.Samples) > 0 {
				result.Status = CollectionPartial
			}
			return result
		}
		defer rows.Close()
		for rows.Next() {
			var name, raw string
			if rows.Scan(&name, &raw) != nil {
				result.ErrorCode = "result_rejected"
				if len(result.Samples) > 0 {
					result.Status = CollectionPartial
				}
				return result
			}
			value, parseErr := strconv.ParseFloat(raw, 64)
			if parseErr != nil || math.IsNaN(value) || math.IsInf(value, 0) {
				result.ErrorCode = "result_rejected"
				if len(result.Samples) > 0 {
					result.Status = CollectionPartial
				}
				return result
			}
			values[strings.ToLower(name)] = value
		}
		if rows.Err() != nil {
			result.ErrorCode = "query_failed"
			if len(result.Samples) > 0 {
				result.Status = CollectionPartial
			}
			return result
		}
	}
	for _, id := range templateIDs {
		definition, wanted := builtinCatalog[id]
		if !wanted {
			continue
		}
		if id == "mysql.up" {
			continue
		}
		value := float64(1)
		var found bool
		value, found = values[strings.ToLower(definition.SourceName)]
		if !found {
			result.ErrorCode = "result_rejected"
			result.Status = CollectionPartial
			continue
		}
		sample := Sample{Name: id, Value: value, Unit: definition.Unit, MetricType: definition.MetricType, Labels: map[string]string{}, SampledAt: now}
		if id == "mysql.queries.total" {
			sample.CounterReset = collector.counterReset(instanceID, value)
		}
		result.Samples = append(result.Samples, sample)
	}
	if len(result.Samples) == len(requested) {
		result.Status = CollectionSucceeded
		result.ErrorCode = ""
	} else if len(result.Samples) > 0 {
		result.Status = CollectionPartial
	} else if result.ErrorCode == "" {
		result.ErrorCode = "template_unavailable"
	}
	return result
}

func (collector *Collector) CollectTemplate(ctx context.Context, instanceID string, template TemplateConfig) Batch {
	now := collector.options.Now().UTC()
	result := Batch{InstanceID: instanceID, TemplateID: template.ID, TemplateRevision: template.Revision, CollectedAt: now, Status: CollectionFailed}
	defer func(){if result.Status==CollectionSucceeded{collector.succeeded(instanceID)}else if result.ErrorCode!=""{collector.observe(instanceID,result.ErrorCode)}}()
	instance, ok := collector.runtime.Instance(instanceID)
	if !ok || instance.Pool == nil {
		result.ErrorCode = "waiting_credentials"
		return result
	}
	timeout := template.Timeout
	if timeout <= 0 || timeout > 30*time.Second {
		result.ErrorCode = "template_rejected"
		return result
	}
	select {
	case collector.semaphore <- struct{}{}:
		defer func() { <-collector.semaphore }()
	case <-ctx.Done():
		result.ErrorCode = "collection_timeout"
		return result
	}
	callContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	rows, err := instance.Pool.QueryContext(callContext, template.Statement)
	if err != nil {
		result.ErrorCode = "query_failed"
		return result
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil || len(columns) == 0 || len(columns) > int(template.MaxColumns) {
		result.ErrorCode = "result_rejected"
		return result
	}
	indexes := map[string]int{}
	for index, column := range columns {
		if _, duplicate := indexes[column]; duplicate {
			result.ErrorCode = "result_rejected"
			return result
		}
		indexes[column] = index
	}
	for _, mapping := range template.ValueMappings {
		if _, ok := indexes[mapping.GetSourceColumn()]; !ok {
			result.ErrorCode = "mapping_rejected"
			return result
		}
	}
	for _, mapping := range template.LabelMappings {
		if _, ok := indexes[mapping.GetSourceColumn()]; !ok {
			result.ErrorCode = "mapping_rejected"
			return result
		}
	}
	cardinality := map[string]struct{}{}
	cardinalityLimit := template.Cardinality
	if cardinalityLimit == 0 {
		cardinalityLimit = 10000
	}
	for rows.Next() {
		if result.RowCount >= template.MaxRows {
			result.ErrorCode = "result_limit_exceeded"
			return result
		}
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if rows.Scan(pointers...) != nil {
			result.ErrorCode = "result_rejected"
			return result
		}
		result.RowCount++
		labels := map[string]string{}
		labelKey := ""
		for _, mapping := range template.LabelMappings {
			value, valid := scalar(values[indexes[mapping.GetSourceColumn()]], 128)
			if !valid || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
				result.ErrorCode = "result_rejected"
				return result
			}
			labels[mapping.GetLabel()] = value
			labelKey += mapping.GetLabel() + "=" + value + "\x00"
		}
		for _, mapping := range template.ValueMappings {
			raw, valid := scalar(values[indexes[mapping.GetSourceColumn()]], 128)
			if !valid {
				result.ErrorCode = "result_rejected"
				return result
			}
			value, parseErr := strconv.ParseFloat(raw, 64)
			if parseErr != nil || math.IsNaN(value) || math.IsInf(value, 0) {
				result.ErrorCode = "result_rejected"
				return result
			}
			seriesKey := mapping.GetMetricName() + "\x00" + labelKey
			cardinality[seriesKey] = struct{}{}
			if len(cardinality) > int(cardinalityLimit) {
				result.ErrorCode = "cardinality_limit_exceeded"
				return result
			}
			result.Samples = append(result.Samples, Sample{Name: mapping.GetMetricName(), Value: value, Unit: mapping.GetUnit(), MetricType: wireMetricType(mapping.GetMetricType()), Labels: cloneLabels(labels), SampledAt: now})
		}
	}
	if rows.Err() != nil {
		result.ErrorCode = "query_failed"
		return result
	}
	result.ColumnCount = uint32(len(columns))
	result.Status = CollectionSucceeded
	return result
}

func scalar(value any, limit int) (string, bool) {
	var result string
	switch typed := value.(type) {
	case nil:
		return "", true
	case []byte:
		result = string(typed)
	case string:
		result = typed
	case int64:
		result = strconv.FormatInt(typed, 10)
	case uint64:
		result = strconv.FormatUint(typed, 10)
	case float64:
		result = strconv.FormatFloat(typed, 'g', -1, 64)
	default:
		return "", false
	}
	return result, len(result) <= limit
}
func wireMetricType(value string) pluginv1.PluginMetricType {
	switch value {
	case "gauge":
		return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE
	case "monotonic_gauge":
		return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_GAUGE
	case "counter":
		return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_COUNTER
	case "monotonic_counter":
		return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_MONOTONIC_COUNTER
	}
	return pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_UNSPECIFIED
}
func cloneLabels(value map[string]string) map[string]string {
	result := make(map[string]string, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}
func (collector *Collector) circuitOpen(id string, now time.Time) bool {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return collector.circuits[id].openUntil.After(now)
}
func (collector *Collector) failed(id string, now time.Time, code string) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	state := collector.circuits[id]
	state.failures++
	if state.failures >= collector.options.FailureThreshold {
		state.openUntil = now.Add(collector.options.CircuitOpenFor)
	}
	collector.circuits[id] = state
	collector.health[id] = collectionHealth{code: code}
}
func (collector *Collector) succeeded(id string) {
	collector.mu.Lock()
	delete(collector.circuits, id)
	collector.health[id] = collectionHealth{}
	collector.mu.Unlock()
}
func(collector *Collector)observe(id,code string){collector.mu.Lock();collector.health[id]=collectionHealth{code:code};collector.mu.Unlock()}
func (collector *Collector) Health(id string, now time.Time) (HealthStatus, string) {
	if collector == nil {
		return HealthDegraded, "collector_unavailable"
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	if collector.circuits[id].openUntil.After(now) {
		return HealthUnhealthy, "circuit_open"
	}
	if observation := collector.health[id]; observation.code != "" {
		return HealthDegraded, observation.code
	}
	return HealthHealthy, ""
}
func (collector *Collector) counterReset(id string, value float64) bool {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	previous, ok := collector.queries[id]
	collector.queries[id] = value
	return ok && value < previous
}
func containsTemplate(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func upSample(now time.Time, value float64) Sample {
	return Sample{Name: "mysql.up", Value: value, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Labels: map[string]string{}, SampledAt: now}
}
