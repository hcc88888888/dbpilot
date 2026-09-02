package monitoring

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
)

// QueryStore is the only boundary required by monitoring handlers. Production
// stores may use PostgreSQL or a metrics database without changing callers.
type QueryStore interface {
	Overview(context.Context, alert.Scope, RangeQuery) (Overview, error)
	ListInstances(context.Context, alert.Scope, InstanceQuery) (InstancePage, error)
	GetInstance(context.Context, alert.Scope, string, RangeQuery) (InstanceDetail, error)
	Series(context.Context, alert.Scope, SeriesQuery) (Series, error)
	Capabilities(context.Context, alert.Scope) ([]Capability, error)
}

// MemoryStore is a deterministic, concurrency-safe QueryStore for tests and
// local demo wiring. It owns deep copies of inputs and never leaks them.
type MemoryStore struct {
	mu           sync.RWMutex
	instances    []Instance
	samples      []alert.MetricSample
	capabilities []Capability
	source       string
	now          func() time.Time
}

// InMemoryStore is retained as a descriptive alias for callers that prefer
// the longer storage-adapter name.
type InMemoryStore = MemoryStore

func NewMemoryStore(instances []Instance, samples []alert.MetricSample, capabilities []Capability) *MemoryStore {
	store := &MemoryStore{source: "memory", now: time.Now}
	store.instances = copyInstances(instances)
	store.samples = copySamples(samples)
	store.capabilities = copyCapabilities(capabilities)
	return store
}

func NewInMemoryStore(instances []Instance, samples []alert.MetricSample, capabilities []Capability) *MemoryStore {
	return NewMemoryStore(instances, samples, capabilities)
}

// SetSource changes only the safe provenance label included in overview DTOs.
func (s *MemoryStore) SetSource(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.source = strings.TrimSpace(source)
}

// SetNow supplies a deterministic clock for default ranges and freshness.
func (s *MemoryStore) SetNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		s.now = time.Now
		return
	}
	s.now = now
}

func (s *MemoryStore) Overview(_ context.Context, scope alert.Scope, query RangeQuery) (Overview, error) {
	if err := validateScope(scope); err != nil {
		return Overview{}, err
	}
	now := s.currentTime()
	if err := query.Validate(now); err != nil {
		return Overview{}, err
	}

	s.mu.RLock()
	instances := s.scopedInstancesLocked(scope)
	samples := copySamples(s.samples)
	source := s.source
	s.mu.RUnlock()

	overview := Overview{Source: source, From: query.From, To: query.To, TotalInstances: len(instances), Instances: instances}
	for index := range overview.Instances {
		status := classifyForInstance(now, overview.Instances[index])
		overview.Instances[index].Status = status
		switch status {
		case StatusHealthy:
			overview.Healthy++
		case StatusStale:
			overview.Stale++
		default:
			overview.Offline++
		}
	}
	overview.Metrics = monitoringSeries(samples, scope, query, overview.Instances)
	return overview, nil
}

func (s *MemoryStore) ListInstances(_ context.Context, scope alert.Scope, query InstanceQuery) (InstancePage, error) {
	if err := validateScope(scope); err != nil {
		return InstancePage{}, err
	}
	if err := query.validate(); err != nil {
		return InstancePage{}, err
	}
	now := s.currentTime()

	s.mu.RLock()
	instances := s.scopedInstancesLocked(scope)
	s.mu.RUnlock()

	filtered := instances[:0]
	for _, instance := range instances {
		instance.Status = classifyForInstance(now, instance)
		if query.Status != "" && instance.Status != query.Status {
			continue
		}
		if query.Engine != "" && instance.Engine != query.Engine {
			continue
		}
		filtered = append(filtered, instance)
	}
	if query.Offset >= len(filtered) {
		return InstancePage{Items: []Instance{}, NextOffset: 0}, nil
	}
	end := query.Offset + query.Limit
	if end > len(filtered) {
		end = len(filtered)
	}
	page := InstancePage{Items: copyInstances(filtered[query.Offset:end])}
	if end < len(filtered) {
		page.NextOffset = end
	}
	return page, nil
}

func (s *MemoryStore) GetInstance(_ context.Context, scope alert.Scope, instanceID string, query RangeQuery) (InstanceDetail, error) {
	if err := validateScope(scope); err != nil {
		return InstanceDetail{}, err
	}
	now := s.currentTime()
	if err := query.Validate(now); err != nil {
		return InstanceDetail{}, err
	}

	s.mu.RLock()
	instance, found := s.instanceLocked(scope, instanceID)
	samples := copySamples(s.samples)
	s.mu.RUnlock()
	if !found {
		return InstanceDetail{}, ErrInstanceNotFound
	}
	instance.Status = classifyForInstance(now, instance)
	if instance.Latest == nil {
		instance.Latest = make(map[string]*float64)
	}
	metrics := metricNames(samples, scope, instance, query)
	detail := InstanceDetail{Instance: RedactInstance(instance), Metrics: make([]Series, 0, len(metrics))}
	for _, metric := range metrics {
		series := buildMetricSeries(samples, scope, instance, metric, query)
		series.Status = instance.Status
		detail.Metrics = append(detail.Metrics, series)
		instance.Latest[metric] = latestSeriesValue(series)
	}
	detail.Instance = RedactInstance(instance)
	return detail, nil
}

func (s *MemoryStore) Series(_ context.Context, scope alert.Scope, query SeriesQuery) (Series, error) {
	if err := validateScope(scope); err != nil {
		return Series{}, err
	}
	if strings.TrimSpace(query.InstanceID) == "" || strings.TrimSpace(query.Metric) == "" {
		return Series{}, ErrInvalidQuery
	}
	now := s.currentTime()
	if err := query.Range.Validate(now); err != nil {
		return Series{}, err
	}

	s.mu.RLock()
	instance, found := s.instanceLocked(scope, query.InstanceID)
	samples := copySamples(s.samples)
	s.mu.RUnlock()
	if !found {
		return Series{}, ErrInstanceNotFound
	}
	series := buildMetricSeries(samples, scope, instance, query.Metric, query.Range)
	series.Status = classifyForInstance(now, instance)
	return series, nil
}

func (s *MemoryStore) Capabilities(_ context.Context, scope alert.Scope) ([]Capability, error) {
	if err := validateScope(scope); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copyCapabilities(s.capabilities), nil
}

func (q *InstanceQuery) validate() error {
	if q == nil || q.Offset < 0 || q.Limit < 0 {
		return ErrInvalidQuery
	}
	if q.Limit == 0 {
		q.Limit = 50
	}
	if q.Limit > MaximumPageSize {
		return ErrInvalidQuery
	}
	switch q.Status {
	case "", StatusHealthy, StatusStale, StatusOffline:
	default:
		return ErrInvalidQuery
	}
	return nil
}

func (s *MemoryStore) currentTime() time.Time {
	s.mu.RLock()
	now := s.now
	s.mu.RUnlock()
	if now == nil {
		return time.Now().UTC()
	}
	return now().UTC()
}

func (s *MemoryStore) scopedInstancesLocked(scope alert.Scope) []Instance {
	result := make([]Instance, 0, len(s.instances))
	for _, instance := range s.instances {
		if instance.Scope == scope {
			result = append(result, RedactInstance(instance))
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

func (s *MemoryStore) instanceLocked(scope alert.Scope, instanceID string) (Instance, bool) {
	for _, instance := range s.instances {
		if instance.Scope == scope && instance.ID == instanceID {
			return copyInstances([]Instance{instance})[0], true
		}
	}
	return Instance{}, false
}

func validateScope(scope alert.Scope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	return nil
}

func classifyForInstance(now time.Time, instance Instance) Status {
	interval := instance.CollectEvery
	if interval <= 0 {
		interval = DefaultStep
	}
	return ClassifyInstance(now, instance.LastSampleAt, instance.LastHeartbeatAt, interval)
}

func metricNames(samples []alert.MetricSample, scope alert.Scope, instance Instance, query RangeQuery) []string {
	seen := make(map[string]struct{})
	for _, sample := range samples {
		if sample.Scope != scope || sampleInstanceID(sample) != instance.ID || sample.SampledAt.Before(query.From) || sample.SampledAt.After(query.To) {
			continue
		}
		seen[sample.Name] = struct{}{}
	}
	if (instance.Engine == database.MySQLFamily || instance.Labels["engine"] == string(database.MySQLFamily)) &&
		safeMetricIdentity(instance.Labels["plugin_id"]) != "" && safeMetricIdentity(instance.Labels["assignment_id"]) != "" {
		for _, name := range MySQLBuiltinMetricIDs() {
			seen[name] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func buildMetricSeries(samples []alert.MetricSample, scope alert.Scope, instance Instance, metric string, query RangeQuery) Series {
	points := make([]SamplePoint, 0)
	identity := alert.MetricSample{InstanceID: instance.ID, Host: instance.Host, Labels: copyStringMap(instance.Labels)}
	for _, sample := range samples {
		if sample.Scope != scope || sampleInstanceID(sample) != instance.ID || sample.Name != metric {
			continue
		}
		if identity.Name == "" || len(identity.Labels) == 0 {
			identity = sample
		}
		points = append(points, SamplePoint{At: sample.SampledAt, Value: sample.Value})
	}
	series := BuildSeries(metric, query.From, query.To, query.Step, points)
	series.Unit = metricUnit(metric)
	series.InstanceID = instance.ID
	series.HostID = safeMetricIdentity(firstNonEmptyString(identity.Labels["host"], identity.Host, instance.Host))
	pluginID := safeMetricIdentity(identity.Labels["plugin_id"])
	assignmentID := safeMetricIdentity(identity.Labels["assignment_id"])
	if pluginID == "" {
		series.Scope = MetricScopeHost
		series.Source = "agent-core"
		series.InstanceID = ""
		return series
	}
	series.Source = pluginID
	series.PluginAssignmentID = assignmentID
	if metric == "dbpilot.plugin.collection.status" {
		series.Scope = MetricScopePlugin
		series.InstanceID = ""
		return series
	}
	series.Scope = MetricScopeDatabase
	return series
}

func monitoringSeries(samples []alert.MetricSample, scope alert.Scope, query RangeQuery, instances []Instance) []Series {
	result := make([]Series, 0)
	for _, instance := range instances {
		for _, metric := range metricNames(samples, scope, instance, query) {
			series := buildMetricSeries(samples, scope, instance, metric, query)
			series.Status = instance.Status
			result = append(result, series)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Scope != result[right].Scope {
			return result[left].Scope < result[right].Scope
		}
		if result[left].InstanceID != result[right].InstanceID {
			return result[left].InstanceID < result[right].InstanceID
		}
		return result[left].Name < result[right].Name
	})
	return result
}

func metricUnit(name string) string {
	switch name {
	case "system.cpu.utilization", "system.memory.utilization":
		return "%"
	case "mysql.queries.total":
		return "{query}"
	case "mysql.uptime.seconds":
		return "s"
	case "mysql.connections.current", "mysql.threads.running", "mysql.up", "dbpilot.plugin.collection.status":
		return "1"
	default:
		return ""
	}
}

func safeMetricIdentity(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || strings.ContainsAny(value, "\x00\r\n") || containsSecret(value) {
		return ""
	}
	return value
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func sampleInstanceID(sample alert.MetricSample) string {
	if sample.InstanceID != "" {
		return sample.InstanceID
	}
	return sample.Labels["instance"]
}

func copyInstances(instances []Instance) []Instance {
	result := make([]Instance, len(instances))
	for index, instance := range instances {
		result[index] = instance
		result[index].Labels = copyStringMap(instance.Labels)
		result[index].Latest = copyLatest(instance.Latest)
	}
	return result
}

func copySamples(samples []alert.MetricSample) []alert.MetricSample {
	result := make([]alert.MetricSample, len(samples))
	for index, sample := range samples {
		result[index] = sample
		result[index].Labels = copyStringMap(sample.Labels)
	}
	return result
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func copyFloat(value *float64) *float64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func latestSeriesValue(series Series) *float64 {
	for index := len(series.Buckets) - 1; index >= 0; index-- {
		if series.Buckets[index].Value != nil {
			return copyFloat(series.Buckets[index].Value)
		}
	}
	return nil
}

var _ QueryStore = (*MemoryStore)(nil)
