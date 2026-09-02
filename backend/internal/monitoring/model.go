// Package monitoring defines storage-neutral, tenant-scoped monitoring query
// contracts. It deliberately exposes only normalized, redacted DTOs.
package monitoring

import (
	"errors"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
)

const (
	DefaultRange    = time.Hour
	DefaultStep     = time.Minute
	MaximumRange    = 7 * 24 * time.Hour
	MaximumBuckets  = 1000
	MaximumPageSize = 200
)

var (
	ErrInvalidRange     = errors.New("invalid monitoring range")
	ErrRangeTooLarge    = errors.New("monitoring range exceeds maximum")
	ErrTooManyBuckets   = errors.New("monitoring range has too many buckets")
	ErrInvalidQuery     = errors.New("invalid monitoring query")
	ErrInstanceNotFound = errors.New("monitoring instance not found")
)

var inlineSecretAssignment = regexp.MustCompile(`(?i)\b(?:password|secret|token|credential|authorization|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key|dsn)\b\s*(?:=|:)\s*\S+`)

// RangeQuery bounds any time series lookup. Validate normalizes the query in
// place so callers use the same UTC values that reach storage.
type RangeQuery struct {
	From time.Time     `json:"from"`
	To   time.Time     `json:"to"`
	Step time.Duration `json:"step"`
}

// Validate applies defaults and enforces the service-wide time and response
// size limits. now is an explicit parameter to keep defaulting deterministic
// in tests and at call sites that already own a request clock.
func (q *RangeQuery) Validate(now time.Time) error {
	if q == nil {
		return ErrInvalidRange
	}
	if now.IsZero() {
		return ErrInvalidRange
	}
	now = now.UTC()
	if q.To.IsZero() {
		q.To = now
	} else {
		q.To = q.To.UTC()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-DefaultRange)
	} else {
		q.From = q.From.UTC()
	}
	if q.Step == 0 {
		q.Step = DefaultStep
	}
	if q.Step < 0 || !q.From.Before(q.To) {
		return ErrInvalidRange
	}
	if q.To.Sub(q.From) > MaximumRange {
		return ErrRangeTooLarge
	}
	if bucketCount(q.From, q.To, q.Step) > MaximumBuckets {
		return ErrTooManyBuckets
	}
	return nil
}

func bucketCount(from, to time.Time, step time.Duration) int {
	if step <= 0 || from.After(to) {
		return 0
	}
	return int(to.Sub(from)/step) + 1
}

// Status describes freshness without treating old metric data as healthy.
type Status string

const (
	StatusHealthy Status = "healthy"
	StatusStale   Status = "stale"
	StatusOffline Status = "offline"
)

// ClassifySample accepts either (interval) for sample-only classification or
// (heartbeat, interval) when Agent liveness is available. A heartbeat older
// than two collection intervals takes precedence over a stale sample.
func ClassifySample(now, lastSample time.Time, values ...any) Status {
	var heartbeat time.Time
	var interval time.Duration
	switch len(values) {
	case 1:
		interval, _ = values[0].(time.Duration)
		heartbeat = now
	case 2:
		heartbeat, _ = values[0].(time.Time)
		interval, _ = values[1].(time.Duration)
	default:
		return StatusOffline
	}
	return classifyInstance(now, lastSample, heartbeat, interval)
}

// ClassifyInstance is the typed form for callers that have both timestamps.
func ClassifyInstance(now, lastSample, heartbeat time.Time, interval time.Duration) Status {
	return classifyInstance(now, lastSample, heartbeat, interval)
}

func classifyInstance(now, lastSample, heartbeat time.Time, interval time.Duration) Status {
	if now.IsZero() || interval <= 0 || heartbeat.IsZero() || lastSample.IsZero() {
		return StatusOffline
	}
	now = now.UTC()
	lastSample = lastSample.UTC()
	heartbeat = heartbeat.UTC()
	staleAfter := 2 * interval
	if now.Sub(heartbeat) > staleAfter {
		return StatusOffline
	}
	if now.Sub(lastSample) > staleAfter {
		return StatusStale
	}
	return StatusHealthy
}

// SamplePoint is a pre-aggregated input point for a display series.
type SamplePoint struct {
	At    time.Time
	Value float64
}

// Bucket always exists for each requested interval. Value is nil when no
// sample belongs to that bucket; clients must not infer a zero value.
type Bucket struct {
	At    time.Time `json:"at"`
	Value *float64  `json:"value"`
}

// MetricScope identifies the process boundary that owns a metric without
// allowing a plugin to assert tenant or project authorization scope.
type MetricScope string

const (
	MetricScopeHost     MetricScope = "host"
	MetricScopePlugin   MetricScope = "plugin"
	MetricScopeDatabase MetricScope = "database"
)

var mysqlBuiltinMetricIDs = []string{
	"mysql.connections.current",
	"mysql.queries.total",
	"mysql.threads.running",
	"mysql.up",
	"mysql.uptime.seconds",
}

// MySQLBuiltinMetricIDs returns the first production plugin's fixed catalog.
func MySQLBuiltinMetricIDs() []string {
	return append([]string(nil), mysqlBuiltinMetricIDs...)
}

// Series is a normalized metric response independent of its backing store.
type Series struct {
	Name               string        `json:"name"`
	Unit               string        `json:"unit,omitempty"`
	Aggregation        string        `json:"aggregation,omitempty"`
	Scope              MetricScope   `json:"scope"`
	Source             string        `json:"source"`
	Status             Status        `json:"status"`
	HostID             string        `json:"host_id,omitempty"`
	PluginAssignmentID string        `json:"plugin_assignment_id,omitempty"`
	InstanceID         string        `json:"instance_id,omitempty"`
	From               time.Time     `json:"from"`
	To                 time.Time     `json:"to"`
	Step               time.Duration `json:"step"`
	Buckets            []Bucket      `json:"buckets"`
}

// BuildSeries constructs every requested bucket and averages multiple points
// in one bucket. Points outside [from, to] and non-finite values are ignored.
func BuildSeries(name string, from, to time.Time, step time.Duration, points []SamplePoint) Series {
	series := Series{Name: strings.TrimSpace(name), From: from.UTC(), To: to.UTC(), Step: step, Aggregation: "avg"}
	count := bucketCount(series.From, series.To, step)
	if count == 0 || count > MaximumBuckets {
		return series
	}
	series.Buckets = make([]Bucket, count)
	for index := range series.Buckets {
		series.Buckets[index].At = series.From.Add(time.Duration(index) * step)
	}

	totals := make([]float64, count)
	counts := make([]int, count)
	for _, point := range points {
		at := point.At.UTC()
		if at.Before(series.From) || at.After(series.To) || math.IsNaN(point.Value) || math.IsInf(point.Value, 0) {
			continue
		}
		index := int(at.Sub(series.From) / step)
		if index >= count {
			index = count - 1
		}
		totals[index] += point.Value
		counts[index]++
	}
	for index, count := range counts {
		if count == 0 {
			continue
		}
		value := totals[index] / float64(count)
		series.Buckets[index].Value = &value
	}
	return series
}

// Overview summarizes instances in a scope for one bounded range.
type Overview struct {
	Source         string     `json:"source"`
	From           time.Time  `json:"from"`
	To             time.Time  `json:"to"`
	TotalInstances int        `json:"total_instances"`
	Healthy        int        `json:"healthy"`
	Stale          int        `json:"stale"`
	Offline        int        `json:"offline"`
	Instances      []Instance `json:"instances,omitempty"`
	Metrics        []Series   `json:"metrics,omitempty"`
	Trend          Series     `json:"trend"`
}

// Instance is a sanitized monitoring directory entry. RawPayload and Secret
// are kept only to permit safe conversion from internal representations; every
// QueryStore return path applies RedactInstance before returning it.
type Instance struct {
	ID              string                `json:"id"`
	Scope           alert.Scope           `json:"-"`
	Engine          database.EngineFamily `json:"engine,omitempty"`
	Version         string                `json:"version,omitempty"`
	Host            string                `json:"host,omitempty"`
	AgentID         string                `json:"agent_id,omitempty"`
	Labels          map[string]string     `json:"labels,omitempty"`
	Status          Status                `json:"status"`
	LastSampleAt    time.Time             `json:"last_sample_at,omitempty"`
	LastHeartbeatAt time.Time             `json:"last_heartbeat_at,omitempty"`
	CollectEvery    time.Duration         `json:"collect_every,omitempty"`
	Latest          map[string]*float64   `json:"latest,omitempty"`
	ErrorSummary    string                `json:"error_summary,omitempty"`
	RawPayload      string                `json:"-"`
	Secret          string                `json:"-"`
}

// InstanceDetail contains the selected entry plus the metric series used by
// the detail panel. Metrics remain empty until a store has observations.
type InstanceDetail struct {
	Instance Instance `json:"instance"`
	Metrics  []Series `json:"metrics,omitempty"`
}

// InstanceQuery controls bounded, stable pagination of scoped directory data.
type InstanceQuery struct {
	Status Status                `json:"status,omitempty"`
	Engine database.EngineFamily `json:"engine,omitempty"`
	Limit  int                   `json:"limit,omitempty"`
	Offset int                   `json:"offset,omitempty"`
}

type InstancePage struct {
	Items      []Instance `json:"items"`
	NextOffset int        `json:"next_offset"`
}

// SeriesQuery selects one metric on one instance within a validated range.
type SeriesQuery struct {
	InstanceID string     `json:"instance_id"`
	Metric     string     `json:"metric"`
	Range      RangeQuery `json:"range"`
}

// Capability is a redacted view of database adapter capability metadata.
type Capability struct {
	Engine        database.EngineFamily `json:"engine"`
	ReadOnlySQL   bool                  `json:"read_only_sql"`
	Metrics       bool                  `json:"metrics"`
	Explain       bool                  `json:"explain"`
	Transactions  bool                  `json:"transactions"`
	MetricIDs     []string              `json:"metric_ids,omitempty"`
	CustomMetrics bool                  `json:"custom_metrics"`
}

// CapabilityFromMatrix copies adapter metadata before it enters a DTO.
func CapabilityFromMatrix(engine database.EngineFamily, matrix database.CapabilityMatrix) Capability {
	return Capability{
		Engine: engine, ReadOnlySQL: matrix.ReadOnlySQL, Metrics: matrix.Metrics,
		Explain: matrix.Explain, Transactions: matrix.Transactions,
		MetricIDs: append([]string(nil), matrix.MetricIDs...), CustomMetrics: matrix.Metrics,
	}
}

// RedactInstance removes internal payload data and secret-bearing labels.
func RedactInstance(instance Instance) Instance {
	result := instance
	result.Scope = alert.Scope{}
	result.RawPayload = ""
	result.Secret = ""
	result.Labels = redactLabels(instance.Labels)
	result.Latest = copyLatest(instance.Latest)
	result.ErrorSummary = redactText(instance.ErrorSummary)
	return result
}

func redactLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	result := make(map[string]string, len(labels))
	for key, value := range labels {
		if sensitiveLabel(key) || containsSecret(value) {
			continue
		}
		result[key] = value
	}
	return result
}

func sensitiveLabel(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, word := range []string{"password", "secret", "token", "credential", "authorization", "dsn", "key"} {
		if normalized == word {
			return true
		}
		for _, separator := range []string{"_", "-", "."} {
			if strings.HasSuffix(normalized, separator+word) || strings.HasPrefix(normalized, word+separator) {
				return true
			}
		}
	}
	return false
}

func containsSecret(value string) bool {
	normalized := strings.ToLower(value)
	if strings.Contains(normalized, "secret://") || strings.Contains(normalized, "://") && strings.Contains(normalized, "@") {
		return true
	}
	if inlineSecretAssignment.MatchString(value) {
		return true
	}
	for _, key := range []string{"password", "secret", "token", "credential", "authorization", "api_key", "access_key", "client_secret", "private_key", "dsn"} {
		if strings.Contains(normalized, key+"=") || strings.Contains(normalized, key+":") || strings.Contains(normalized, "\""+key+"\"") {
			return true
		}
	}
	return false
}

func redactText(value string) string {
	if containsSecret(value) {
		return ""
	}
	return value
}

func copyLatest(values map[string]*float64) map[string]*float64 {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]*float64, len(values))
	for name, value := range values {
		if value == nil {
			result[name] = nil
			continue
		}
		copied := *value
		result[name] = &copied
	}
	return result
}

func copySeries(series Series) Series {
	result := series
	result.Buckets = make([]Bucket, len(series.Buckets))
	for index, bucket := range series.Buckets {
		result.Buckets[index].At = bucket.At
		if bucket.Value != nil {
			value := *bucket.Value
			result.Buckets[index].Value = &value
		}
	}
	return result
}

func copyCapabilities(capabilities []Capability) []Capability {
	result := make([]Capability, len(capabilities))
	for index, capability := range capabilities {
		result[index] = capability
		result[index].MetricIDs = append([]string(nil), capability.MetricIDs...)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Engine < result[right].Engine })
	return result
}
