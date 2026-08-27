package alert

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnsupportedAggregation     = errors.New("unsupported alert aggregation")
	ErrInvalidRateWindow          = errors.New("rate requires two samples at different timestamps")
	ErrEvaluationAuditPersistence = errors.New("alert evaluation audit persistence failed")
)

const conditionSinceEvidenceKey = "condition_since"

const (
	systemFindingLabelKey = "dbpilot_system_finding"
	systemFindingFailure  = "failure"
	systemFindingNoData   = "no_data"
	systemFindingDelay    = "delay"
	systemFindingBacklog  = "backlog"
	maxDueRulesPerPass    = 100
	ruleEvaluationLease   = 5 * time.Minute
)

type EvaluationEvidence struct {
	WindowStart       time.Time
	WindowEnd         time.Time
	Samples           int
	Aggregate         *float64
	Missing           bool
	Rate              *float64
	MissingDimensions []string
}

type EvaluationSummary struct {
	Rules          int
	EvaluatedRules int
	FailedRules    int
	EventsUpdated  int
	StartedAt      time.Time
	CompletedAt    time.Time
}

type EvaluatorHealth struct {
	LastRunAt      time.Time
	LastRunLatency time.Duration
	LastError      string
	FailedRules    int
	LateRuns       uint64
	QueueDepth     int
}

type Evaluator struct {
	repository Repository
	metrics    MetricStore
	idSource   io.Reader
	workerID   string

	mu            sync.RWMutex
	healthByScope map[string]EvaluatorHealth
	localNextDue  map[string]time.Time
}

func NewEvaluator(repository Repository, metrics MetricStore) *Evaluator {
	workerID, err := newControlPlaneID("evaluator", rand.Reader)
	if err != nil {
		workerID = "evaluator-process"
	}
	return &Evaluator{
		repository:    repository,
		metrics:       metrics,
		idSource:      rand.Reader,
		workerID:      workerID,
		healthByScope: make(map[string]EvaluatorHealth),
		localNextDue:  make(map[string]time.Time),
	}
}

func (e *Evaluator) Health() EvaluatorHealth {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var aggregate EvaluatorHealth
	for _, health := range e.healthByScope {
		if health.LastRunAt.After(aggregate.LastRunAt) {
			aggregate.LastRunAt = health.LastRunAt
		}
		if health.LastRunLatency > aggregate.LastRunLatency {
			aggregate.LastRunLatency = health.LastRunLatency
		}
		aggregate.FailedRules += health.FailedRules
		aggregate.LateRuns += health.LateRuns
		aggregate.QueueDepth += health.QueueDepth
		if aggregate.LastError == "" && health.LastError != "" {
			aggregate.LastError = health.LastError
		}
	}
	return aggregate
}

func (e *Evaluator) HealthForScope(scope Scope) EvaluatorHealth {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.healthByScope[scope.Key()]
}

func (e *Evaluator) EvaluateScope(ctx context.Context, scope Scope, now time.Time) (summary EvaluationSummary, returnedErr error) {
	started := time.Now()
	summary.StartedAt = now
	defer func() {
		summary.CompletedAt = now
		e.finishRun(scope, now, time.Since(started), summary.FailedRules, returnedErr)
	}()
	if err := scope.Validate(); err != nil {
		return summary, err
	}
	if now.IsZero() {
		return summary, errors.New("evaluation time is required")
	}

	dueRules, queueDepth, err := e.claimDueRules(ctx, scope, now)
	if err != nil {
		return summary, err
	}
	summary.Rules = len(dueRules)
	e.setQueueDepth(scope, queueDepth)

	auditPersistenceFailed := false
	latePass := false
	for _, due := range dueRules {
		rule := due.Rule
		late := !due.DueAt.IsZero() && now.Sub(due.DueAt) > rule.EvaluationEvery
		if late {
			latePass = true
		}
		updated, hasData, evaluationErr := e.evaluateRule(ctx, scope, rule, now)
		if completionErr := e.completeRuleEvaluation(ctx, scope, rule, now); completionErr != nil {
			evaluationErr = errors.Join(evaluationErr, completionErr)
		}
		if evaluationErr != nil {
			summary.FailedRules++
			if findingErr := e.appendFailureFinding(ctx, scope, rule.ID, now); findingErr != nil {
				auditPersistenceFailed = true
			}
			continue
		}
		for _, finding := range []struct {
			kind        string
			failureKind string
			active      bool
		}{
			{systemFindingFailure, "rule_evaluation", false},
			{systemFindingNoData, "no_data", !hasData},
			{systemFindingDelay, "evaluation_delay", late},
		} {
			if findingErr := e.reconcileSystemFinding(ctx, rule, finding.kind, finding.failureKind, finding.active, now); findingErr != nil {
				summary.FailedRules++
				auditPersistenceFailed = true
				break
			}
		}
		summary.EvaluatedRules++
		summary.EventsUpdated += updated
	}
	if latePass {
		e.recordLateRun(scope)
	}
	if findingErr := e.reconcileBacklogFinding(ctx, scope, dueRules, queueDepth, now); findingErr != nil {
		summary.FailedRules++
		auditPersistenceFailed = true
	}
	if auditPersistenceFailed {
		return summary, ErrEvaluationAuditPersistence
	}
	return summary, nil
}

func (e *Evaluator) evaluateRule(ctx context.Context, scope Scope, rule AlertRule, now time.Time) (int, bool, error) {
	if rule.Scope != scope || rule.Validate() != nil {
		return 0, false, ErrInvalidRule
	}
	windowStart := now.Add(-rule.EffectiveLookbackWindow())
	selector := canonicalRuleSelector(rule.Labels)
	samples, err := e.metrics.Query(ctx, MetricQuery{Scope: scope, Name: rule.Metric, Labels: storageMetricSelector(rule.Labels), From: windowStart, To: now})
	if err != nil {
		return 0, false, err
	}
	samples, missingDimensions := filterEvaluationSamples(samples, scope, rule.Metric, selector, windowStart, now)

	groups := make(map[string][]MetricSample)
	groupLabels := make(map[string]map[string]string)
	for _, sample := range samples {
		resourceLabels := canonicalResourceLabels(sample)
		key := SeriesFingerprint(resourceLabels)
		groups[key] = append(groups[key], sample)
		if _, exists := groupLabels[key]; !exists {
			groupLabels[key] = resourceLabels
		}
	}

	updated := 0
	seenFingerprints := make(map[string]struct{}, len(groups))
	for key, series := range groups {
		labels := groupLabels[key]
		fingerprint := EventFingerprint(scope, rule.ID, labels)
		seenFingerprints[fingerprint] = struct{}{}
		evidence := EvaluationEvidence{WindowStart: windowStart, WindowEnd: now, Samples: len(series)}
		var value float64
		if rule.Aggregation == "rate" {
			value, err = rate(series)
			evidence.Rate = floatPointer(value)
		} else {
			value, err = aggregate(rule.Aggregation, series)
		}
		if err != nil {
			return updated, len(groups) > 0, err
		}
		evidence.Aggregate = floatPointer(value)
		condition := compare(value, rule.Threshold, rule.Operator)
		changed, err := e.applyResult(ctx, rule, fingerprint, labels, evidence, condition, false, now)
		if err != nil {
			return updated, len(groups) > 0, err
		}
		if changed {
			updated++
		}
	}

	existing, err := e.listAllRuleEvents(ctx, scope, rule.ID)
	if err != nil {
		return updated, len(groups) > 0, err
	}
	missingEvidence := EvaluationEvidence{WindowStart: windowStart, WindowEnd: now, Missing: true, MissingDimensions: missingDimensions}
	globalMissingFingerprint := EventFingerprint(scope, rule.ID, selector)
	hadExisting := false
	for _, event := range existing {
		if _, seen := seenFingerprints[event.Fingerprint]; seen {
			continue
		}
		hadExisting = true
		if len(groups) > 0 && event.Fingerprint == globalMissingFingerprint {
			recoveryEvidence := EvaluationEvidence{WindowStart: windowStart, WindowEnd: now, Samples: len(samples)}
			changed, err := e.applyResult(ctx, rule, event.Fingerprint, event.Labels, recoveryEvidence, false, false, now)
			if err != nil {
				return updated, len(groups) > 0, err
			}
			if changed {
				updated++
			}
			continue
		}
		changed, err := e.applyMissing(ctx, rule, event.Fingerprint, event.Labels, missingEvidence, now)
		if err != nil {
			return updated, len(groups) > 0, err
		}
		if changed {
			updated++
		}
	}
	if len(groups) == 0 && !hadExisting && rule.MissingData != "ignore" {
		changed, err := e.applyMissing(ctx, rule, globalMissingFingerprint, selector, missingEvidence, now)
		if err != nil {
			return updated, false, err
		}
		if changed {
			updated++
		}
	}
	return updated, len(groups) > 0, nil
}

func (e *Evaluator) applyMissing(ctx context.Context, rule AlertRule, fingerprint string, labels map[string]string, evidence EvaluationEvidence, now time.Time) (bool, error) {
	switch rule.MissingData {
	case "ignore":
		return false, nil
	case "alert":
		return e.applyResult(ctx, rule, fingerprint, labels, evidence, true, false, now)
	case "resolve":
		return e.applyResult(ctx, rule, fingerprint, labels, evidence, false, true, now)
	default:
		return false, ErrInvalidRule
	}
}

func (e *Evaluator) applyResult(ctx context.Context, rule AlertRule, fingerprint string, labels map[string]string, evidence EvaluationEvidence, condition, createResolved bool, now time.Time) (bool, error) {
	event, found, err := e.repository.FindEventByFingerprint(ctx, rule.Scope, fingerprint)
	if err != nil {
		return false, err
	}
	evidenceMap := evidence.asMap()
	sanitizedLabels := sanitizeDetails(labels)

	if !found {
		if !condition && !createResolved {
			return false, nil
		}
		state := EventPending
		action := "event.pending"
		eventID, idErr := newControlPlaneID("event", e.idSource)
		if idErr != nil {
			return false, idErr
		}
		event = AlertEvent{ID: eventID, Scope: rule.Scope, RuleID: rule.ID, Fingerprint: fingerprint, Labels: sanitizedLabels, Evidence: evidenceMap, State: state, FirstSeen: now, LastSeen: now, LastActor: "system:evaluator"}
		if createResolved {
			event.State = EventResolved
			event.ResolvedAt = now
			action = "event.resolved"
		} else {
			event.Evidence[conditionSinceEvidenceKey] = now.UTC().Format(time.RFC3339Nano)
		}
		return e.writeTransition(ctx, event, action, now)
	}

	previousEvidence := event.Evidence
	event.Labels = sanitizedLabels
	event.LastActor = "system:evaluator"
	if condition {
		switch event.State {
		case EventResolved:
			event.State = EventPending
			event.LastSeen = now
			event.FiringAt = time.Time{}
			event.AcknowledgedAt = time.Time{}
			event.ResolvedAt = time.Time{}
			evidenceMap[conditionSinceEvidenceKey] = now.UTC().Format(time.RFC3339Nano)
			event.Evidence = evidenceMap
			return e.writeTransition(ctx, event, "event.pending", now)
		case EventPending:
			conditionSince := event.FirstSeen
			if encoded := previousEvidence[conditionSinceEvidenceKey]; encoded != "" {
				if parsed, parseErr := time.Parse(time.RFC3339Nano, encoded); parseErr == nil && !parsed.After(now) {
					conditionSince = parsed
				}
			}
			evidenceMap[conditionSinceEvidenceKey] = conditionSince.UTC().Format(time.RFC3339Nano)
			if now.Sub(conditionSince) >= rule.For {
				event, err = event.Transition(EventFiring, now, "system:evaluator")
				if err != nil {
					return false, err
				}
				event.Evidence = evidenceMap
				event.Labels = sanitizedLabels
				return e.writeTransition(ctx, event, "event.firing", now)
			}
		case EventFiring, EventAcknowledged:
			if encoded := previousEvidence[conditionSinceEvidenceKey]; encoded != "" {
				evidenceMap[conditionSinceEvidenceKey] = encoded
			}
		default:
			return false, ErrInvalidEvent
		}
		event.LastSeen = now
		event.Evidence = evidenceMap
		_, err = e.repository.PutEvent(ctx, event)
		return err == nil, err
	}

	if event.State == EventResolved {
		return false, nil
	}
	event, err = event.Transition(EventResolved, now, "system:evaluator")
	if err != nil {
		return false, err
	}
	event.Evidence = evidenceMap
	event.Labels = sanitizedLabels
	return e.writeTransition(ctx, event, "event.resolved", now)
}

func (e *Evaluator) writeTransition(ctx context.Context, event AlertEvent, action string, now time.Time) (bool, error) {
	details := cloneMap(event.Evidence)
	details["state"] = string(event.State)
	auditID, err := newControlPlaneID("audit", e.idSource)
	if err != nil {
		return false, err
	}
	record := AuditRecord{ID: auditID, Scope: event.Scope, Actor: "system:evaluator", Action: action, TargetID: event.ID, OccurredAt: now, Details: details}
	_, err = e.repository.PutEventAndAudit(ctx, event, record)
	return err == nil, err
}

func (e *Evaluator) appendFailureFinding(ctx context.Context, scope Scope, ruleID string, now time.Time) error {
	auditID, err := newControlPlaneID("audit", e.idSource)
	if err != nil {
		return err
	}
	if err := e.repository.AppendAudit(ctx, AuditRecord{ID: auditID, Scope: scope, Actor: "system:evaluator", Action: "evaluation.failed", TargetID: ruleID, OccurredAt: now, Details: map[string]string{"failure_kind": "rule_evaluation"}}); err != nil {
		return err
	}
	rule, err := e.repository.GetRule(ctx, scope, ruleID)
	if err != nil {
		return err
	}
	return e.reconcileSystemFinding(ctx, rule, systemFindingFailure, "rule_evaluation", true, now)
}

func (e *Evaluator) reconcileSystemFinding(ctx context.Context, rule AlertRule, kind, failureKind string, active bool, now time.Time) error {
	// PostgreSQL stores timestamps at microsecond precision. A system finding is
	// intentionally written through pending and firing in one pass, so normalize
	// the shared transition time before the first write instead of letting the
	// database round the pending timestamp past the subsequent firing timestamp.
	now = now.UTC().Truncate(time.Microsecond)
	labels := systemFindingLabels(kind)
	fingerprint := EventFingerprint(rule.Scope, rule.ID, labels)
	event, found, err := e.repository.FindEventByFingerprint(ctx, rule.Scope, fingerprint)
	if err != nil {
		return err
	}
	if !active {
		if !found || event.State == EventResolved {
			return nil
		}
		event, err = event.Transition(EventResolved, now, "system:evaluator")
		if err != nil {
			return err
		}
		event.Evidence = map[string]string{"failure_kind": failureKind}
		_, err = e.writeTransition(ctx, event, "event.resolved", now)
		return err
	}
	if !found {
		eventID, idErr := newControlPlaneID("event", e.idSource)
		if idErr != nil {
			return idErr
		}
		event = AlertEvent{ID: eventID, Scope: rule.Scope, RuleID: rule.ID, Fingerprint: fingerprint, Labels: labels, Evidence: map[string]string{"failure_kind": failureKind}, State: EventPending, FirstSeen: now, LastSeen: now, LastActor: "system:evaluator"}
		if _, err = e.writeTransition(ctx, event, "event.pending", now); err != nil {
			return err
		}
		event, found, err = e.repository.FindEventByFingerprint(ctx, rule.Scope, fingerprint)
		if err != nil {
			return err
		}
		if !found {
			return ErrInvalidEvent
		}
	} else if event.State == EventResolved {
		event.State = EventPending
		event.LastSeen = now
		event.FiringAt = time.Time{}
		event.AcknowledgedAt = time.Time{}
		event.ResolvedAt = time.Time{}
		event.LastActor = "system:evaluator"
		event.Labels = labels
		event.Evidence = map[string]string{"failure_kind": failureKind}
		if _, err = e.writeTransition(ctx, event, "event.pending", now); err != nil {
			return err
		}
	} else if event.State == EventFiring || event.State == EventAcknowledged {
		event.LastSeen = now
		event.Evidence = map[string]string{"failure_kind": failureKind}
		_, err = e.repository.PutEvent(ctx, event)
		return err
	}
	event, err = event.Transition(EventFiring, now, "system:evaluator")
	if err != nil {
		return err
	}
	event.Labels = labels
	event.Evidence = map[string]string{"failure_kind": failureKind}
	_, err = e.writeTransition(ctx, event, "event.firing", now)
	return err
}

func (e *Evaluator) reconcileBacklogFinding(ctx context.Context, scope Scope, dueRules []DueAlertRule, queueDepth int, now time.Time) error {
	desiredFingerprint := ""
	if queueDepth > 0 && len(dueRules) > 0 {
		rule := dueRules[0].Rule
		desiredFingerprint = EventFingerprint(scope, rule.ID, systemFindingLabels(systemFindingBacklog))
		if err := e.reconcileSystemFinding(ctx, rule, systemFindingBacklog, "queue_backlog", true, now); err != nil {
			return err
		}
	}
	cursor := ""
	for {
		events, err := e.repository.ListEvents(ctx, scope, EventFilter{Limit: 500, AfterID: cursor, OrderByID: true})
		if err != nil {
			return err
		}
		for _, event := range events {
			if event.Labels[systemFindingLabelKey] != systemFindingBacklog || event.Fingerprint == desiredFingerprint || event.State == EventResolved {
				continue
			}
			rule, err := e.repository.GetRule(ctx, scope, event.RuleID)
			if err != nil {
				return err
			}
			if err := e.reconcileSystemFinding(ctx, rule, systemFindingBacklog, "queue_backlog", false, now); err != nil {
				return err
			}
		}
		if len(events) < 500 {
			return nil
		}
		cursor = events[len(events)-1].ID
	}
}

func systemFindingLabels(kind string) map[string]string {
	return map[string]string{
		systemFindingLabelKey: kind,
		"instance":            "controlplane",
		"component":           "evaluator",
		"role":                "system",
		"host":                "controlplane",
	}
}

func (e *Evaluator) listAllRuleEvents(ctx context.Context, scope Scope, ruleID string) ([]AlertEvent, error) {
	const pageSize = 500
	all := make([]AlertEvent, 0)
	for offset := 0; ; offset += pageSize {
		page, err := e.repository.ListRuleEvents(ctx, scope, ruleID, EventFilter{Limit: pageSize, Offset: offset})
		if err != nil {
			return nil, err
		}
		for _, event := range page {
			if event.Labels[systemFindingLabelKey] == "" {
				all = append(all, event)
			}
		}
		if len(page) < pageSize {
			return all, nil
		}
	}
}

func (e *Evaluator) claimDueRules(ctx context.Context, scope Scope, now time.Time) ([]DueAlertRule, int, error) {
	if scheduler, ok := e.repository.(RuleScheduleRepository); ok {
		return scheduler.ClaimDueRules(ctx, scope, now, e.workerID, now.Add(ruleEvaluationLease), maxDueRulesPerPass)
	}
	rules, err := e.repository.ListRules(ctx, scope)
	if err != nil {
		return nil, 0, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	due := make([]DueAlertRule, 0, len(rules))
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		key := scope.Key() + canonicalParts(rule.ID)
		dueAt := e.localNextDue[key]
		if !dueAt.IsZero() && now.Before(dueAt) {
			continue
		}
		due = append(due, DueAlertRule{Rule: rule, DueAt: dueAt})
		e.localNextDue[key] = now.Add(rule.EvaluationEvery)
	}
	return due, 0, nil
}

func (e *Evaluator) completeRuleEvaluation(ctx context.Context, scope Scope, rule AlertRule, now time.Time) error {
	if scheduler, ok := e.repository.(RuleScheduleRepository); ok {
		return scheduler.CompleteRuleEvaluation(ctx, scope, rule.ID, e.workerID, now, now.Add(rule.EvaluationEvery))
	}
	return nil
}

func (e *Evaluator) setQueueDepth(scope Scope, queueDepth int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	health := e.healthByScope[scope.Key()]
	health.QueueDepth = queueDepth
	e.healthByScope[scope.Key()] = health
}

func (e *Evaluator) recordLateRun(scope Scope) {
	e.mu.Lock()
	defer e.mu.Unlock()
	health := e.healthByScope[scope.Key()]
	health.LateRuns++
	e.healthByScope[scope.Key()] = health
}

func (e *Evaluator) finishRun(scope Scope, now time.Time, latency time.Duration, failedRules int, runErr error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	health := e.healthByScope[scope.Key()]
	health.LastRunAt = now
	health.LastRunLatency = latency
	health.FailedRules = failedRules
	if errors.Is(runErr, ErrEvaluationAuditPersistence) {
		health.LastError = ErrEvaluationAuditPersistence.Error()
	} else if runErr != nil {
		health.LastError = "alert evaluation failed"
	} else if failedRules > 0 {
		health.LastError = "one or more alert rules failed"
	} else {
		health.LastError = ""
	}
	e.healthByScope[scope.Key()] = health
}

func aggregate(kind string, samples []MetricSample) (float64, error) {
	if len(samples) == 0 {
		return 0, ErrUnsupportedAggregation
	}
	switch kind {
	case "count":
		return float64(len(samples)), nil
	case "sum", "avg":
		var total float64
		for _, sample := range samples {
			total += sample.Value
		}
		if kind == "avg" {
			return total / float64(len(samples)), nil
		}
		return total, nil
	case "max", "min":
		value := samples[0].Value
		for _, sample := range samples[1:] {
			if (kind == "max" && sample.Value > value) || (kind == "min" && sample.Value < value) {
				value = sample.Value
			}
		}
		return value, nil
	default:
		return 0, fmt.Errorf("%w: %s", ErrUnsupportedAggregation, kind)
	}
}

func rate(samples []MetricSample) (float64, error) {
	if len(samples) < 2 {
		return 0, ErrInvalidRateWindow
	}
	ordered := append([]MetricSample(nil), samples...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].SampledAt.Before(ordered[j].SampledAt) })
	elapsed := ordered[len(ordered)-1].SampledAt.Sub(ordered[0].SampledAt).Seconds()
	if elapsed <= 0 {
		return 0, ErrInvalidRateWindow
	}
	return (ordered[len(ordered)-1].Value - ordered[0].Value) / elapsed, nil
}

func compare(value, threshold float64, operator string) bool {
	switch operator {
	case ">":
		return value > threshold
	case ">=":
		return value >= threshold
	case "<":
		return value < threshold
	case "<=":
		return value <= threshold
	case "==":
		return value == threshold
	case "!=":
		return value != threshold
	default:
		return false
	}
}

func (evidence EvaluationEvidence) asMap() map[string]string {
	values := map[string]string{
		"window_start": evidence.WindowStart.UTC().Format(time.RFC3339Nano),
		"window_end":   evidence.WindowEnd.UTC().Format(time.RFC3339Nano),
		"samples":      strconv.Itoa(evidence.Samples),
		"missing":      strconv.FormatBool(evidence.Missing),
	}
	if evidence.Aggregate != nil {
		values["aggregate"] = strconv.FormatFloat(*evidence.Aggregate, 'g', -1, 64)
	}
	if evidence.Rate != nil {
		values["rate"] = strconv.FormatFloat(*evidence.Rate, 'g', -1, 64)
	}
	if len(evidence.MissingDimensions) > 0 {
		values["missing_dimensions"] = strings.Join(evidence.MissingDimensions, ",")
	}
	return values
}

func cloneMap(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func canonicalResourceLabels(sample MetricSample) map[string]string {
	labels := sanitizeDetails(sample.Labels)
	labels["agent_id"] = sample.AgentID
	return labels
}

func filterEvaluationSamples(samples []MetricSample, scope Scope, metric string, selector map[string]string, from, to time.Time) ([]MetricSample, []string) {
	filtered := make([]MetricSample, 0, len(samples))
	missingSet := make(map[string]struct{})
	for _, sample := range samples {
		if sample.Scope != scope || sample.Name != metric || sample.SampledAt.Before(from) || sample.SampledAt.After(to) {
			continue
		}
		for _, dimension := range MissingResourceDimensions(sample.Labels) {
			missingSet[dimension] = struct{}{}
		}
		if validateMetricSample(sample) != nil || !labelsMatch(canonicalResourceLabels(sample), selector) {
			continue
		}
		filtered = append(filtered, sample)
	}
	missing := make([]string, 0, len(missingSet))
	for _, dimension := range canonicalResourceDimensions {
		if _, ok := missingSet[dimension]; ok {
			missing = append(missing, dimension)
		}
	}
	return filtered, missing
}

func canonicalRuleSelector(selector map[string]string) map[string]string {
	return sanitizeDetails(selector)
}

func storageMetricSelector(selector map[string]string) map[string]string {
	filtered := make(map[string]string, len(selector))
	for key, value := range selector {
		if key != "agent_id" && !sensitiveField(key) {
			filtered[key] = value
		}
	}
	return filtered
}

func floatPointer(value float64) *float64 { return &value }
