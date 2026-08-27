package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
)

const (
	DefaultMaximumInstances     = MaximumPageSize
	DefaultMaximumMetrics       = 50
	DefaultMaximumLabels        = 32
	DefaultMaximumSamples       = 10000
	DefaultMaximumResponseBytes = 1 << 20
	HardMaximumInstances        = 1000
	HardMaximumMetrics          = 200
	HardMaximumLabels           = 64
	HardMaximumSamples          = 50000
	HardMaximumResponseBytes    = 4 << 20
	stateFields                 = "instance_id, agent_id, engine, host, labels, collect_every_ns, last_sample_at, last_heartbeat_at"
)

var ErrQueryLimit = errors.New("monitoring query exceeds configured limit")

const instancesSQL = "SELECT " + stateFields + " FROM monitoring_instances WHERE tenant_id = $1 AND project_id = $2 ORDER BY instance_id ASC LIMIT $3"
const instanceSQL = "SELECT " + stateFields + " FROM monitoring_instances WHERE tenant_id = $1 AND project_id = $2 AND instance_id = $3"
const instanceSamplesSQL = "SELECT agent_id, metric, labels, value, sampled_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND labels ->> 'instance' = $3 AND sampled_at >= $4 AND sampled_at <= $5 ORDER BY sampled_at ASC, agent_id ASC, metric ASC LIMIT $6"
const seriesSamplesSQL = "SELECT agent_id, metric, labels, value, sampled_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND labels ->> 'instance' = $3 AND metric = $4 AND sampled_at >= $5 AND sampled_at <= $6 ORDER BY sampled_at ASC, agent_id ASC LIMIT $7"
const scopeSamplesSQL = "SELECT agent_id, metric, labels, value, sampled_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND sampled_at >= $3 AND sampled_at <= $4 ORDER BY sampled_at ASC, agent_id ASC, metric ASC LIMIT $5"

// QueryLimits bounds storage reads before values enter memory or a response.
// Zero-valued fields use conservative defaults.
type QueryLimits struct {
	MaximumInstances, MaximumMetrics, MaximumLabels, MaximumSamples, MaximumResponseBytes int
}

func DefaultQueryLimits() QueryLimits {
	return QueryLimits{DefaultMaximumInstances, DefaultMaximumMetrics, DefaultMaximumLabels, DefaultMaximumSamples, DefaultMaximumResponseBytes}
}

// NormalizeQueryLimits applies the public defaults and hard safety caps.
func NormalizeQueryLimits(limits QueryLimits) QueryLimits {
	return limits.normalized()
}

func (limits QueryLimits) normalized() QueryLimits {
	defaults := DefaultQueryLimits()
	if limits.MaximumInstances <= 0 {
		limits.MaximumInstances = defaults.MaximumInstances
	}
	if limits.MaximumMetrics <= 0 {
		limits.MaximumMetrics = defaults.MaximumMetrics
	}
	if limits.MaximumLabels <= 0 {
		limits.MaximumLabels = defaults.MaximumLabels
	}
	if limits.MaximumSamples <= 0 {
		limits.MaximumSamples = defaults.MaximumSamples
	}
	if limits.MaximumResponseBytes <= 0 {
		limits.MaximumResponseBytes = defaults.MaximumResponseBytes
	}
	limits.MaximumInstances = min(limits.MaximumInstances, HardMaximumInstances)
	limits.MaximumMetrics = min(limits.MaximumMetrics, HardMaximumMetrics)
	limits.MaximumLabels = min(limits.MaximumLabels, HardMaximumLabels)
	limits.MaximumSamples = min(limits.MaximumSamples, HardMaximumSamples)
	limits.MaximumResponseBytes = min(limits.MaximumResponseBytes, HardMaximumResponseBytes)
	return limits
}

func ValidateQueryLimits(limits QueryLimits) error {
	for _, value := range []struct{ value, maximum int }{{limits.MaximumInstances, HardMaximumInstances}, {limits.MaximumMetrics, HardMaximumMetrics}, {limits.MaximumLabels, HardMaximumLabels}, {limits.MaximumSamples, HardMaximumSamples}, {limits.MaximumResponseBytes, HardMaximumResponseBytes}} {
		if value.value < 0 || value.value > value.maximum {
			return ErrQueryLimit
		}
	}
	return nil
}

// DefaultCapabilities exposes the built-in SQL adapter catalog without opening
// any database or resolving any secret.
func DefaultCapabilities() []Capability {
	return []Capability{
		CapabilityFromMatrix(database.MySQLFamily, database.NewMySQLFactory(nil, nil).Capabilities()),
		CapabilityFromMatrix(database.PostgresFamily, database.NewPostgresFactory(nil, nil).Capabilities()),
		CapabilityFromMatrix(database.OracleFamily, database.NewOracleFactory(nil, nil).Capabilities()),
	}
}

// PostgresStore uses persisted, authenticated instance state for identity and
// liveness; display-range samples never define whether an instance exists.
type PostgresStore struct {
	db           *sql.DB
	capabilities []Capability
	limits       QueryLimits
	mu           sync.RWMutex
	now          func() time.Time
}

func NewPostgresStore(db *sql.DB, capabilities []Capability) *PostgresStore {
	return NewPostgresStoreWithLimits(db, capabilities, DefaultQueryLimits())
}

func NewPostgresStoreWithLimits(db *sql.DB, capabilities []Capability, limits QueryLimits) *PostgresStore {
	return &PostgresStore{db: db, capabilities: copyCapabilities(capabilities), limits: limits.normalized(), now: time.Now}
}

func (s *PostgresStore) SetNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		s.now = time.Now
	} else {
		s.now = now
	}
}

func (s *PostgresStore) Overview(ctx context.Context, scope alert.Scope, query RangeQuery) (Overview, error) {
	if err := scope.Validate(); err != nil {
		return Overview{}, err
	}
	now := s.currentTime()
	if err := query.Validate(now); err != nil {
		return Overview{}, err
	}
	instances, err := s.instances(ctx, scope)
	if err != nil {
		return Overview{}, err
	}
	samples, err := s.scopeSamples(ctx, scope, query.From, query.To)
	if err != nil {
		return Overview{}, err
	}
	instances = instancesWithLatest(instances, samples)
	value, err := s.memory(instances, samples, now).Overview(ctx, scope, query)
	if err != nil {
		return Overview{}, err
	}
	value.Trend = trendFromSamples(query, samples)
	return value, s.ensureResponse(value)
}

func (s *PostgresStore) ListInstances(ctx context.Context, scope alert.Scope, query InstanceQuery) (InstancePage, error) {
	if err := scope.Validate(); err != nil {
		return InstancePage{}, err
	}
	if _, err := NewMemoryStore(nil, nil, nil).ListInstances(ctx, scope, query); err != nil {
		return InstancePage{}, err
	}
	instances, err := s.instances(ctx, scope)
	if err != nil {
		return InstancePage{}, err
	}
	now := s.currentTime()
	samples, err := s.scopeSamples(ctx, scope, now.Add(-MaximumRange), now)
	if err != nil {
		return InstancePage{}, err
	}
	instances = instancesWithLatest(instances, samples)
	value, err := s.memory(instances, samples, now).ListInstances(ctx, scope, query)
	if err != nil {
		return InstancePage{}, err
	}
	return value, s.ensureResponse(value)
}

func (s *PostgresStore) GetInstance(ctx context.Context, scope alert.Scope, id string, query RangeQuery) (InstanceDetail, error) {
	if err := scope.Validate(); err != nil {
		return InstanceDetail{}, err
	}
	now := s.currentTime()
	if err := query.Validate(now); err != nil {
		return InstanceDetail{}, err
	}
	instance, err := s.instance(ctx, scope, id)
	if err != nil {
		return InstanceDetail{}, err
	}
	samples, err := s.samples(ctx, instanceSamplesSQL, []any{scope.TenantID, scope.ProjectID, id, query.From.UTC(), query.To.UTC(), s.queryLimits().MaximumSamples + 1}, scope)
	if err != nil {
		return InstanceDetail{}, err
	}
	value, err := s.memory([]Instance{instance}, samples, now).GetInstance(ctx, scope, id, query)
	if err != nil {
		return InstanceDetail{}, err
	}
	return value, s.ensureResponse(value)
}

func (s *PostgresStore) Series(ctx context.Context, scope alert.Scope, query SeriesQuery) (Series, error) {
	if err := scope.Validate(); err != nil {
		return Series{}, err
	}
	if strings.TrimSpace(query.InstanceID) == "" || strings.TrimSpace(query.Metric) == "" {
		return Series{}, ErrInvalidQuery
	}
	now := s.currentTime()
	if err := query.Range.Validate(now); err != nil {
		return Series{}, err
	}
	instance, err := s.instance(ctx, scope, query.InstanceID)
	if err != nil {
		return Series{}, err
	}
	samples, err := s.samples(ctx, seriesSamplesSQL, []any{scope.TenantID, scope.ProjectID, query.InstanceID, query.Metric, query.Range.From.UTC(), query.Range.To.UTC(), s.queryLimits().MaximumSamples + 1}, scope)
	if err != nil {
		return Series{}, err
	}
	value, err := s.memory([]Instance{instance}, samples, now).Series(ctx, scope, query)
	if err != nil {
		return Series{}, err
	}
	return value, s.ensureResponse(value)
}

func (s *PostgresStore) Capabilities(ctx context.Context, scope alert.Scope) ([]Capability, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	values, err := NewMemoryStore(nil, nil, s.capabilityCopy()).Capabilities(ctx, scope)
	if err != nil {
		return nil, err
	}
	return values, s.ensureResponse(values)
}

func (s *PostgresStore) instances(ctx context.Context, scope alert.Scope) ([]Instance, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("monitoring PostgreSQL store is unavailable")
	}
	limits := s.queryLimits()
	rows, err := s.db.QueryContext(ctx, instancesSQL, scope.TenantID, scope.ProjectID, limits.MaximumInstances+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]Instance, 0, limits.MaximumInstances)
	for rows.Next() {
		if len(result) == limits.MaximumInstances {
			return nil, ErrQueryLimit
		}
		value, err := scanInstance(rows, scope, limits)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *PostgresStore) instance(ctx context.Context, scope alert.Scope, id string) (Instance, error) {
	if s == nil || s.db == nil || strings.TrimSpace(id) == "" {
		return Instance{}, ErrInstanceNotFound
	}
	value, err := scanInstance(s.db.QueryRowContext(ctx, instanceSQL, scope.TenantID, scope.ProjectID, id), scope, s.queryLimits())
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, ErrInstanceNotFound
	}
	return value, err
}

func (s *PostgresStore) samples(ctx context.Context, statement string, arguments []any, scope alert.Scope) ([]alert.MetricSample, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("monitoring PostgreSQL store is unavailable")
	}
	limits := s.queryLimits()
	rows, err := s.db.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]alert.MetricSample, 0, limits.MaximumSamples)
	metrics := make(map[string]struct{})
	for rows.Next() {
		if len(result) == limits.MaximumSamples {
			return nil, ErrQueryLimit
		}
		var sample alert.MetricSample
		var labels []byte
		if err := rows.Scan(&sample.AgentID, &sample.Name, &labels, &sample.Value, &sample.SampledAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(labels, &sample.Labels); err != nil {
			return nil, err
		}
		if len(sample.Labels) > limits.MaximumLabels {
			return nil, ErrQueryLimit
		}
		if _, exists := metrics[sample.Name]; !exists {
			if len(metrics) == limits.MaximumMetrics {
				return nil, ErrQueryLimit
			}
			metrics[sample.Name] = struct{}{}
		}
		sample.Scope = scope
		sample.InstanceID = sample.Labels["instance"]
		sample.Component = sample.Labels["component"]
		sample.Role = sample.Labels["role"]
		sample.Host = sample.Labels["host"]
		sample.SampledAt = sample.SampledAt.UTC()
		result = append(result, sample)
	}
	return result, rows.Err()
}

func (s *PostgresStore) scopeSamples(ctx context.Context, scope alert.Scope, from, to time.Time) ([]alert.MetricSample, error) {
	return s.samples(ctx, scopeSamplesSQL, []any{scope.TenantID, scope.ProjectID, from.UTC(), to.UTC(), s.queryLimits().MaximumSamples + 1}, scope)
}

func scanInstance(scanner interface{ Scan(...any) error }, scope alert.Scope, limits QueryLimits) (Instance, error) {
	var value Instance
	var labels []byte
	var every int64
	if err := scanner.Scan(&value.ID, &value.AgentID, &value.Engine, &value.Host, &labels, &every, &value.LastSampleAt, &value.LastHeartbeatAt); err != nil {
		return Instance{}, err
	}
	if err := json.Unmarshal(labels, &value.Labels); err != nil {
		return Instance{}, err
	}
	if len(value.Labels) > limits.MaximumLabels {
		return Instance{}, ErrQueryLimit
	}
	value.Scope = scope
	value.CollectEvery = time.Duration(every)
	if value.CollectEvery <= 0 {
		value.CollectEvery = DefaultStep
	}
	value.LastSampleAt = value.LastSampleAt.UTC()
	value.LastHeartbeatAt = value.LastHeartbeatAt.UTC()
	return value, nil
}

func (s *PostgresStore) memory(instances []Instance, samples []alert.MetricSample, now time.Time) *MemoryStore {
	store := NewMemoryStore(instances, samples, s.capabilityCopy())
	store.SetSource("postgres")
	store.SetNow(func() time.Time { return now })
	return store
}
func (s *PostgresStore) ensureResponse(value any) error {
	return s.ValidateResponse(value)
}

// ValidateResponse uses the exact JSON encoding size, including Encoder's
// trailing newline. HTTP handlers pass their complete response envelope here.
func (s *PostgresStore) ValidateResponse(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded)+1 > s.queryLimits().MaximumResponseBytes {
		return ErrQueryLimit
	}
	return nil
}

func instancesWithLatest(instances []Instance, samples []alert.MetricSample) []Instance {
	result := copyInstances(instances)
	byID := make(map[string]int, len(result))
	for index := range result {
		byID[result[index].ID] = index
		result[index].Latest = make(map[string]*float64)
	}
	latestAt := make(map[string]map[string]time.Time, len(result))
	for _, sample := range samples {
		index, found := byID[sampleInstanceID(sample)]
		if !found {
			continue
		}
		if latestAt[sampleInstanceID(sample)] == nil {
			latestAt[sampleInstanceID(sample)] = make(map[string]time.Time)
		}
		if at := latestAt[sampleInstanceID(sample)][sample.Name]; at.After(sample.SampledAt) {
			continue
		}
		value := sample.Value
		result[index].Latest[sample.Name] = &value
		latestAt[sampleInstanceID(sample)][sample.Name] = sample.SampledAt
	}
	return result
}

func trendFromSamples(query RangeQuery, samples []alert.MetricSample) Series {
	points := make([]SamplePoint, 0, len(samples))
	for _, sample := range samples {
		points = append(points, SamplePoint{At: sample.SampledAt, Value: sample.Value})
	}
	return BuildSeries("monitoring.sample_value", query.From, query.To, query.Step, points)
}
func (s *PostgresStore) currentTime() time.Time {
	s.mu.RLock()
	now := s.now
	s.mu.RUnlock()
	if now == nil {
		return time.Now().UTC()
	}
	return now().UTC()
}
func (s *PostgresStore) capabilityCopy() []Capability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return copyCapabilities(s.capabilities)
}
func (s *PostgresStore) queryLimits() QueryLimits {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.limits
}

var _ QueryStore = (*PostgresStore)(nil)
