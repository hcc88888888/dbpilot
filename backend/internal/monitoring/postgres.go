package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/database"
)

const postgresMetricSamplesSQL = "SELECT agent_id, metric, labels, value, sampled_at FROM metric_samples WHERE tenant_id = $1 AND project_id = $2 AND sampled_at >= $3 AND sampled_at <= $4 ORDER BY sampled_at ASC, agent_id ASC, metric ASC"

// PostgresStore projects the existing, scoped metric_samples table into the
// storage-neutral monitoring query model. It never accepts scope fields from
// database labels or samples.
type PostgresStore struct {
	db           *sql.DB
	capabilities []Capability
	mu           sync.RWMutex
	now          func() time.Time
}

func NewPostgresStore(db *sql.DB, capabilities []Capability) *PostgresStore {
	return &PostgresStore{db: db, capabilities: copyCapabilities(capabilities), now: time.Now}
}

func (s *PostgresStore) SetNow(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		s.now = time.Now
		return
	}
	s.now = now
}

func (s *PostgresStore) Overview(ctx context.Context, scope alert.Scope, query RangeQuery) (Overview, error) {
	if err := scope.Validate(); err != nil {
		return Overview{}, err
	}
	now := s.currentTime()
	if err := query.Validate(now); err != nil {
		return Overview{}, err
	}
	store, err := s.memoryForRange(ctx, scope, query.From, query.To, now)
	if err != nil {
		return Overview{}, err
	}
	return store.Overview(ctx, scope, query)
}

func (s *PostgresStore) ListInstances(ctx context.Context, scope alert.Scope, query InstanceQuery) (InstancePage, error) {
	if err := scope.Validate(); err != nil {
		return InstancePage{}, err
	}
	now := s.currentTime()
	// Validate before opening a database cursor so malformed pagination never
	// consumes storage work.
	if _, err := NewMemoryStore(nil, nil, nil).ListInstances(ctx, scope, query); err != nil {
		return InstancePage{}, err
	}
	store, err := s.memoryForRange(ctx, scope, now.Add(-MaximumRange), now, now)
	if err != nil {
		return InstancePage{}, err
	}
	return store.ListInstances(ctx, scope, query)
}

func (s *PostgresStore) GetInstance(ctx context.Context, scope alert.Scope, instanceID string, query RangeQuery) (InstanceDetail, error) {
	if err := scope.Validate(); err != nil {
		return InstanceDetail{}, err
	}
	now := s.currentTime()
	if err := query.Validate(now); err != nil {
		return InstanceDetail{}, err
	}
	store, err := s.memoryForRange(ctx, scope, query.From, query.To, now)
	if err != nil {
		return InstanceDetail{}, err
	}
	return store.GetInstance(ctx, scope, instanceID, query)
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
	store, err := s.memoryForRange(ctx, scope, query.Range.From, query.Range.To, now)
	if err != nil {
		return Series{}, err
	}
	return store.Series(ctx, scope, query)
}

func (s *PostgresStore) Capabilities(ctx context.Context, scope alert.Scope) ([]Capability, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	return NewMemoryStore(nil, nil, s.capabilityCopy()).Capabilities(ctx, scope)
}

func (s *PostgresStore) memoryForRange(ctx context.Context, scope alert.Scope, from, to, now time.Time) (*MemoryStore, error) {
	samples, err := s.samples(ctx, scope, from, to)
	if err != nil {
		return nil, err
	}
	instances := instancesFromSamples(scope, samples)
	store := NewMemoryStore(instances, samples, s.capabilityCopy())
	store.SetSource("postgres")
	store.SetNow(func() time.Time { return now })
	return store, nil
}

func (s *PostgresStore) samples(ctx context.Context, scope alert.Scope, from, to time.Time) ([]alert.MetricSample, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("monitoring PostgreSQL store is unavailable")
	}
	rows, err := s.db.QueryContext(ctx, postgresMetricSamplesSQL, scope.TenantID, scope.ProjectID, from.UTC(), to.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]alert.MetricSample, 0)
	for rows.Next() {
		var sample alert.MetricSample
		var labels []byte
		if err := rows.Scan(&sample.AgentID, &sample.Name, &labels, &sample.Value, &sample.SampledAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(labels, &sample.Labels); err != nil {
			return nil, err
		}
		sample.Scope = scope
		sample.InstanceID = sample.Labels["instance"]
		sample.Component = sample.Labels["component"]
		sample.Role = sample.Labels["role"]
		sample.Host = sample.Labels["host"]
		sample.SampledAt = sample.SampledAt.UTC()
		result = append(result, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func instancesFromSamples(scope alert.Scope, samples []alert.MetricSample) []Instance {
	byID := make(map[string]Instance)
	for _, sample := range samples {
		instanceID := strings.TrimSpace(sample.InstanceID)
		if instanceID == "" {
			continue
		}
		instance, exists := byID[instanceID]
		if !exists {
			instance = Instance{ID: instanceID, Scope: scope, AgentID: sample.AgentID, Host: sample.Host, Labels: copyStringMap(sample.Labels), Latest: make(map[string]*float64)}
			if engine := database.EngineFamily(strings.TrimSpace(sample.Labels["engine"])); engine != "" {
				instance.Engine = engine
			}
		}
		if sample.SampledAt.After(instance.LastSampleAt) {
			instance.LastSampleAt = sample.SampledAt
			// The compatible metric table has no dedicated heartbeat column. A
			// current metric proves collector liveness, but no label is trusted
			// as a separate scope or heartbeat authority.
			instance.LastHeartbeatAt = sample.SampledAt
		}
		value := sample.Value
		if current, ok := instance.Latest[sample.Name]; !ok || current == nil || sample.SampledAt.Equal(instance.LastSampleAt) {
			instance.Latest[sample.Name] = &value
		}
		byID[instanceID] = instance
	}
	result := make([]Instance, 0, len(byID))
	for _, instance := range byID {
		result = append(result, instance)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
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

var _ QueryStore = (*PostgresStore)(nil)
