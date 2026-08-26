package alert

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEvaluatorPromotesOnlyAfterForDuration(t *testing.T) {
	fx := newEvaluatorFixture(t, ruleWith(ForDuration(time.Minute)))
	fx.append(sampleAt(fx.now, 91))
	fx.evaluate()
	require.Equal(t, EventPending, fx.event("cpu").State)

	fx.now = fx.now.Add(time.Minute)
	fx.append(sampleAt(fx.now, 91))
	fx.evaluate()
	require.Equal(t, EventFiring, fx.event("cpu").State)
}

func TestEvaluatorMissingDataPolicies(t *testing.T) {
	tests := []struct {
		policy string
		want   EventState
	}{
		{policy: "alert", want: EventPending},
		{policy: "resolve", want: EventResolved},
	}
	for _, test := range tests {
		t.Run(test.policy, func(t *testing.T) {
			fx := newEvaluatorFixture(t, ruleWith(MissingPolicy(test.policy)))
			fx.evaluate()
			event := fx.event("cpu")
			require.Equal(t, test.want, event.State)
			require.Equal(t, "true", event.Evidence["missing"])
			require.Equal(t, "0", event.Evidence["samples"])
		})
	}
}

func TestEvaluatorResolvesGlobalMissingEventWhenDataReturns(t *testing.T) {
	fx := newEvaluatorFixture(t, ruleWith(MissingPolicy("alert")))
	fx.evaluate()
	missingEvent := fx.event("cpu")
	require.Equal(t, EventPending, missingEvent.State)

	fx.now = fx.now.Add(time.Minute)
	fx.append(sampleAt(fx.now, 1))
	fx.evaluate()
	events := fx.events()
	require.Len(t, events, 1)
	require.Equal(t, missingEvent.ID, events[0].ID)
	require.Equal(t, EventResolved, events[0].State)
	require.Equal(t, "false", events[0].Evidence["missing"])
}

func TestEvaluatorUsesSameEventForEquivalentLabelOrder(t *testing.T) {
	fx := newEvaluatorFixture(t, defaultRule())
	fx.append(sample(fx.now, 91, map[string]string{"host": "a", "role": "db"}))
	fx.evaluate()

	fx.now = fx.now.Add(time.Minute)
	fx.append(sample(fx.now, 91, map[string]string{"role": "db", "host": "a"}))
	fx.evaluate()
	require.Len(t, fx.events(), 1)
}

func TestEvaluatorResolvesTheExistingEvent(t *testing.T) {
	fx := newFiringEvaluatorFixture(t)
	eventID := fx.event("cpu").ID

	fx.now = fx.now.Add(time.Minute)
	fx.append(sampleAt(fx.now, 1))
	fx.evaluate()
	event := fx.event("cpu")
	require.Equal(t, eventID, event.ID)
	require.Equal(t, EventResolved, event.State)
	require.Equal(t, "46", event.Evidence["aggregate"])
}

func TestEvaluatorRestartsForDurationAfterResolvedConditionRecurs(t *testing.T) {
	fx := newFiringEvaluatorFixture(t)
	original := fx.event("cpu")

	fx.now = fx.now.Add(time.Minute)
	fx.append(sampleAt(fx.now, 1))
	fx.evaluate()
	require.Equal(t, EventResolved, fx.event("cpu").State)

	fx.now = fx.now.Add(time.Minute)
	fx.append(sampleAt(fx.now, 181))
	fx.evaluate()
	require.Equal(t, EventPending, fx.event("cpu").State)

	fx.now = fx.now.Add(30 * time.Second)
	fx.append(sampleAt(fx.now, 181))
	fx.evaluate()
	require.Equal(t, EventPending, fx.event("cpu").State, "the previous incident lifetime must not satisfy the new continuous For duration")

	fx.now = fx.now.Add(30 * time.Second)
	fx.append(sampleAt(fx.now, 181))
	fx.evaluate()
	recurred := fx.event("cpu")
	require.Equal(t, EventFiring, recurred.State)
	require.Equal(t, original.ID, recurred.ID)
	require.Equal(t, original.FirstSeen, recurred.FirstSeen)
}

func TestEvaluatorComputesRateFromFixedWindow(t *testing.T) {
	fx := newEvaluatorFixture(t, rateRule())
	fx.append(sampleAt(fx.now, 10))
	fx.append(sampleAt(fx.now.Add(10*time.Second), 30))
	fx.now = fx.now.Add(10 * time.Second)
	fx.evaluate()

	require.Equal(t, "2", fx.event("rate").Evidence["rate"])
	require.Equal(t, fx.now.Add(-time.Minute).Format(time.RFC3339Nano), fx.event("rate").Evidence["window_start"])
	require.Equal(t, fx.now.Format(time.RFC3339Nano), fx.event("rate").Evidence["window_end"])
}

func TestEvaluatorSupportsClosedAggregationSet(t *testing.T) {
	tests := []struct {
		kind string
		want float64
	}{
		{kind: "avg", want: 3},
		{kind: "max", want: 5},
		{kind: "min", want: 1},
		{kind: "sum", want: 9},
		{kind: "count", want: 3},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			got, err := aggregate(test.kind, []MetricSample{{Value: 1}, {Value: 3}, {Value: 5}})
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}

func TestCompareSupportsClosedOperatorSet(t *testing.T) {
	tests := []struct {
		operator  string
		value     float64
		threshold float64
		want      bool
	}{
		{operator: ">", value: 2, threshold: 1, want: true},
		{operator: ">=", value: 2, threshold: 2, want: true},
		{operator: "<", value: 1, threshold: 2, want: true},
		{operator: "<=", value: 2, threshold: 2, want: true},
		{operator: "==", value: 2, threshold: 2, want: true},
		{operator: "!=", value: 2, threshold: 3, want: true},
		{operator: "promql", value: 2, threshold: 1, want: false},
	}
	for _, test := range tests {
		t.Run(test.operator, func(t *testing.T) {
			require.Equal(t, test.want, compare(test.value, test.threshold, test.operator))
		})
	}
}

func TestEvaluatorAuditsEachLifecycleTransition(t *testing.T) {
	fx := newEvaluatorFixture(t, defaultRule())
	fx.append(sampleAt(fx.now, 91))
	fx.evaluate()

	fx.now = fx.now.Add(time.Minute)
	fx.append(sampleAt(fx.now, 91))
	fx.evaluate()

	fx.now = fx.now.Add(time.Minute)
	fx.append(sampleAt(fx.now, 1))
	fx.evaluate()

	require.Equal(t, []string{"event.pending", "event.firing", "event.resolved"}, fx.auditActions())
}

func TestEvaluatorIgnoresMissingDataWhenConfigured(t *testing.T) {
	fx := newEvaluatorFixture(t, ruleWith(MissingPolicy("ignore")))
	fx.evaluate()
	require.Empty(t, fx.events())
	require.Empty(t, fx.auditActions())
}

func TestEvaluatorHealthReportsLateAndFailedRunsWithoutStoppingOtherRules(t *testing.T) {
	invalid := defaultRule()
	invalid.ID = "invalid"
	invalid.Name = "invalid"
	invalid.Aggregation = "runtime-invalid"
	valid := defaultRule()
	valid.ID = "valid"
	valid.Name = "valid"
	fx := newEvaluatorFixture(t, invalid, valid)
	fx.append(sampleAt(fx.now, 91))

	summary, err := fx.evaluator.EvaluateScope(context.Background(), fx.scope, fx.now)
	require.NoError(t, err)
	require.Equal(t, 1, summary.FailedRules)
	require.Equal(t, EventPending, fx.event("valid").State)
	require.Contains(t, fx.auditActions(), "evaluation.failed")

	fx.now = fx.now.Add(3 * time.Minute)
	_, err = fx.evaluator.EvaluateScope(context.Background(), fx.scope, fx.now)
	require.NoError(t, err)
	health := fx.evaluator.Health()
	require.Equal(t, 1, health.FailedRules)
	require.Equal(t, uint64(1), health.LateRuns)
	require.NotEmpty(t, health.LastError)
	require.False(t, health.LastRunAt.IsZero())
	require.GreaterOrEqual(t, health.LastRunLatency, time.Duration(0))
	require.Equal(t, 0, health.QueueDepth)
}

func TestEvaluatorHealthDoesNotExposeDependencyErrorDetails(t *testing.T) {
	fx := newEvaluatorFixture(t, defaultRule())
	fx.metrics.queryError = errors.New("database password=hunter2")

	summary, err := fx.evaluator.EvaluateScope(context.Background(), fx.scope, fx.now)
	require.NoError(t, err)
	require.Equal(t, 1, summary.FailedRules)
	health := fx.evaluator.Health()
	require.Equal(t, "one or more alert rules failed", health.LastError)
	require.NotContains(t, health.LastError, "hunter2")
	require.NotContains(t, health.LastError, "password")
}

func TestEvaluatorFiltersQueryAndGroupsIndependentSeries(t *testing.T) {
	rule := defaultRule()
	rule.Labels = map[string]string{"role": "db"}
	fx := newEvaluatorFixture(t, rule)
	fx.append(
		sample(fx.now, 91, map[string]string{"host": "a", "role": "db"}),
		sample(fx.now, 92, map[string]string{"host": "b", "role": "db"}),
		sample(fx.now, 99, map[string]string{"host": "c", "role": "web"}),
	)
	fx.evaluate()

	require.Len(t, fx.events(), 2)
	require.Len(t, fx.metrics.queries, 1)
	query := fx.metrics.queries[0]
	require.Equal(t, fx.scope, query.Scope)
	require.Equal(t, "cpu", query.Name)
	require.Equal(t, map[string]string{"role": "db"}, query.Labels)
	require.Equal(t, fx.now.Add(-time.Minute), query.From)
	require.Equal(t, fx.now, query.To)
}

func TestEvaluatorKeepsTrustedAgentSeriesIndependent(t *testing.T) {
	fx := newEvaluatorFixture(t, defaultRule())
	first := sampleAt(fx.now, 91)
	second := sampleAt(fx.now, 92)
	second.AgentID = "agent-b"
	fx.append(first, second)

	fx.evaluate()
	events := fx.events()
	require.Len(t, events, 2)
	agents := []string{events[0].Labels["agent_id"], events[1].Labels["agent_id"]}
	sort.Strings(agents)
	require.Equal(t, []string{"agent-a", "agent-b"}, agents)
}

func TestEvaluatorDefensivelyFiltersMetricStoreResults(t *testing.T) {
	rule := defaultRule()
	rule.Labels = map[string]string{"role": "db"}
	fx := newEvaluatorFixture(t, rule)
	fx.metrics.ignoreQueryFilters = true
	fx.metrics.samples = []MetricSample{
		{Scope: fx.scope, AgentID: "agent-a", Name: "cpu", Labels: map[string]string{"host": "a", "role": "db"}, Value: 91, SampledAt: fx.now},
		{Scope: Scope{TenantID: "other", ProjectID: fx.scope.ProjectID}, AgentID: "agent-b", Name: "cpu", Labels: map[string]string{"host": "b", "role": "db"}, Value: 99, SampledAt: fx.now},
		{Scope: fx.scope, AgentID: "agent-c", Name: "memory", Labels: map[string]string{"host": "c", "role": "db"}, Value: 99, SampledAt: fx.now},
		{Scope: fx.scope, AgentID: "agent-d", Name: "cpu", Labels: map[string]string{"host": "d", "role": "web"}, Value: 99, SampledAt: fx.now},
		{Scope: fx.scope, AgentID: "agent-e", Name: "cpu", Labels: map[string]string{"host": "e", "role": "db"}, Value: 99, SampledAt: fx.now.Add(-2 * time.Minute)},
	}

	fx.evaluate()
	events := fx.events()
	require.Len(t, events, 1)
	require.Equal(t, "agent-a", events[0].Labels["agent_id"])
	require.Equal(t, "1", events[0].Evidence["samples"])
}

func TestEvaluatorRedactsSensitiveResourceLabels(t *testing.T) {
	fx := newEvaluatorFixture(t, defaultRule())
	fx.append(sample(fx.now, 91, map[string]string{"host": "a", "password": "do-not-store", "api_token": "secret"}))
	fx.evaluate()

	event := fx.event("cpu")
	require.Equal(t, "a", event.Labels["host"])
	require.Equal(t, RedactedValue, event.Labels["password"])
	require.Equal(t, RedactedValue, event.Labels["api_token"])
}

type evaluatorFixture struct {
	t         *testing.T
	now       time.Time
	scope     Scope
	repo      *memoryRepository
	metrics   *memoryMetricStore
	evaluator *Evaluator
}

func newEvaluatorFixture(t *testing.T, rules ...AlertRule) *evaluatorFixture {
	t.Helper()
	scope := Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	if len(rules) == 0 {
		rules = []AlertRule{defaultRule()}
	}
	for index := range rules {
		rules[index].Scope = scope
	}
	repo := &memoryRepository{rules: rules, eventsByFingerprint: map[string]AlertEvent{}}
	metrics := &memoryMetricStore{}
	return &evaluatorFixture{
		t:         t,
		now:       time.Date(2026, time.August, 26, 10, 0, 0, 0, time.UTC),
		scope:     scope,
		repo:      repo,
		metrics:   metrics,
		evaluator: NewEvaluator(repo, metrics),
	}
}

func newFiringEvaluatorFixture(t *testing.T) *evaluatorFixture {
	t.Helper()
	fx := newEvaluatorFixture(t, defaultRule())
	fx.append(sampleAt(fx.now, 91))
	fx.evaluate()
	fx.now = fx.now.Add(time.Minute)
	fx.append(sampleAt(fx.now, 91))
	fx.evaluate()
	require.Equal(t, EventFiring, fx.event("cpu").State)
	return fx
}

func (fx *evaluatorFixture) append(samples ...MetricSample) {
	fx.t.Helper()
	for index := range samples {
		samples[index].Scope = fx.scope
	}
	require.NoError(fx.t, fx.metrics.Append(context.Background(), samples))
}

func (fx *evaluatorFixture) evaluate() {
	fx.t.Helper()
	_, err := fx.evaluator.EvaluateScope(context.Background(), fx.scope, fx.now)
	require.NoError(fx.t, err)
}

func (fx *evaluatorFixture) events() []AlertEvent {
	fx.repo.mu.Lock()
	defer fx.repo.mu.Unlock()
	events := make([]AlertEvent, 0, len(fx.repo.eventsByFingerprint))
	for _, event := range fx.repo.eventsByFingerprint {
		events = append(events, event)
	}
	return events
}

func (fx *evaluatorFixture) event(ruleName string) AlertEvent {
	fx.t.Helper()
	ruleID := ""
	for _, rule := range fx.repo.rules {
		if rule.Name == ruleName {
			ruleID = rule.ID
			break
		}
	}
	for _, event := range fx.events() {
		if event.RuleID == ruleID {
			return event
		}
	}
	fx.t.Fatalf("event for rule %q not found", ruleName)
	return AlertEvent{}
}

func (fx *evaluatorFixture) auditActions() []string {
	fx.repo.mu.Lock()
	defer fx.repo.mu.Unlock()
	actions := make([]string, len(fx.repo.audits))
	for index, record := range fx.repo.audits {
		actions[index] = record.Action
	}
	return actions
}

type ruleOption func(*AlertRule)

func ForDuration(value time.Duration) ruleOption {
	return func(rule *AlertRule) { rule.For = value }
}

func MissingPolicy(value string) ruleOption {
	return func(rule *AlertRule) { rule.MissingData = value }
}

func ruleWith(options ...ruleOption) AlertRule {
	rule := defaultRule()
	for _, option := range options {
		option(&rule)
	}
	return rule
}

func defaultRule() AlertRule {
	return AlertRule{
		ID:              "cpu-rule",
		Name:            "cpu",
		Metric:          "cpu",
		Aggregation:     "avg",
		Operator:        ">",
		Threshold:       80,
		EvaluationEvery: time.Minute,
		For:             time.Minute,
		MissingData:     "ignore",
		Severity:        "critical",
		Enabled:         true,
	}
}

func rateRule() AlertRule {
	rule := defaultRule()
	rule.ID = "rate-rule"
	rule.Name = "rate"
	rule.Aggregation = "rate"
	rule.Threshold = 1
	return rule
}

func sampleAt(at time.Time, value float64) MetricSample {
	return sample(at, value, map[string]string{"host": "a"})
}

func sample(at time.Time, value float64, labels map[string]string) MetricSample {
	return MetricSample{AgentID: "agent-a", Name: "cpu", Labels: labels, Value: value, SampledAt: at}
}

type memoryMetricStore struct {
	mu                 sync.Mutex
	samples            []MetricSample
	queries            []MetricQuery
	queryError         error
	ignoreQueryFilters bool
}

func (store *memoryMetricStore) Append(_ context.Context, samples []MetricSample) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.samples = append(store.samples, samples...)
	return nil
}

func (store *memoryMetricStore) Query(_ context.Context, query MetricQuery) ([]MetricSample, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.queries = append(store.queries, query)
	if store.queryError != nil {
		return nil, store.queryError
	}
	if store.ignoreQueryFilters {
		return append([]MetricSample(nil), store.samples...), nil
	}
	var matches []MetricSample
	for _, sample := range store.samples {
		if sample.Scope != query.Scope || sample.Name != query.Name || sample.SampledAt.Before(query.From) || sample.SampledAt.After(query.To) || !labelsMatch(sample.Labels, query.Labels) {
			continue
		}
		matches = append(matches, sample)
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].SampledAt.Before(matches[j].SampledAt) })
	return matches, nil
}

type memoryRepository struct {
	mu                  sync.Mutex
	rules               []AlertRule
	eventsByFingerprint map[string]AlertEvent
	audits              []AuditRecord
	failedRuleID        string
	putFailure          error
}

func (repo *memoryRepository) CreateRule(_ context.Context, rule AlertRule) (AlertRule, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	repo.rules = append(repo.rules, rule)
	return rule, nil
}

func (repo *memoryRepository) UpdateRule(_ context.Context, rule AlertRule) (AlertRule, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	for index := range repo.rules {
		if repo.rules[index].ID == rule.ID && repo.rules[index].Scope == rule.Scope {
			repo.rules[index] = rule
			return rule, nil
		}
	}
	return AlertRule{}, ErrNotFound
}

func (repo *memoryRepository) ListRules(_ context.Context, scope Scope) ([]AlertRule, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	var rules []AlertRule
	for _, rule := range repo.rules {
		if rule.Scope == scope {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func (repo *memoryRepository) GetRule(_ context.Context, scope Scope, id string) (AlertRule, error) {
	for _, rule := range repo.rules {
		if rule.Scope == scope && rule.ID == id {
			return rule, nil
		}
	}
	return AlertRule{}, ErrNotFound
}

func (repo *memoryRepository) PutEvent(_ context.Context, event AlertEvent) (AlertEvent, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.putFailure != nil {
		return AlertEvent{}, repo.putFailure
	}
	if existing, ok := repo.eventsByFingerprint[event.Fingerprint]; ok {
		event.ID = existing.ID
		event.FirstSeen = existing.FirstSeen
	}
	repo.eventsByFingerprint[event.Fingerprint] = event
	return event, nil
}

func (repo *memoryRepository) PutEventAndAudit(_ context.Context, event AlertEvent, record AuditRecord) (AlertEvent, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.putFailure != nil {
		return AlertEvent{}, repo.putFailure
	}
	if existing, ok := repo.eventsByFingerprint[event.Fingerprint]; ok {
		event.ID = existing.ID
		event.FirstSeen = existing.FirstSeen
	}
	repo.eventsByFingerprint[event.Fingerprint] = event
	repo.audits = append(repo.audits, record)
	return event, nil
}

func (repo *memoryRepository) FindEventByFingerprint(_ context.Context, scope Scope, fingerprint string) (AlertEvent, bool, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	event, found := repo.eventsByFingerprint[fingerprint]
	if found && event.Scope != scope {
		return AlertEvent{}, false, nil
	}
	return event, found, nil
}

func (repo *memoryRepository) ListEvents(_ context.Context, scope Scope, _ EventFilter) ([]AlertEvent, error) {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	var events []AlertEvent
	for _, event := range repo.eventsByFingerprint {
		if event.Scope == scope {
			events = append(events, event)
		}
	}
	return events, nil
}

func (repo *memoryRepository) AppendAudit(_ context.Context, record AuditRecord) error {
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if repo.failedRuleID != "" && record.TargetID == repo.failedRuleID {
		return errors.New("audit failure for " + strconv.Quote(repo.failedRuleID))
	}
	repo.audits = append(repo.audits, record)
	return nil
}
