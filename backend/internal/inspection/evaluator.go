package inspection

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

const maxEvidenceSamples = 1000

var ErrInvalidEvaluation = errors.New("invalid inspection evaluation input")

// EvidenceStore is the storage boundary for bounded metric observations. The
// target identifier, tenant/project scope, metric names, time range, and
// limit are all supplied by the immutable item/run snapshot.
type EvidenceStore interface {
	Samples(context.Context, platformscope.Scope, string, []string, time.Time, time.Time, int) ([]Observation, error)
}

type Evaluator struct {
	Evidence EvidenceStore
	Now      func() time.Time
}

// EvaluateTarget produces one finding per immutable item version. It does
// not infer health from unknown, stale, malformed, or unsupported evidence.
func (e *Evaluator) EvaluateTarget(ctx context.Context, snapshot RunSnapshot, target TargetRun) ([]Finding, error) {
	if snapshot.Validate() != nil || target.Validate() != nil || !snapshotHasTarget(snapshot, target.TargetID) {
		return nil, ErrInvalidEvaluation
	}
	now := e.now()
	if !isUTC(now) {
		return nil, ErrInvalidEvaluation
	}
	items := cloneItems(snapshot.Items)
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Version < items[j].Version
	})
	findings := make([]Finding, 0, len(items))
	for _, item := range items {
		finding, err := e.evaluateItem(ctx, snapshot, target, item, now)
		if err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].TargetID != findings[j].TargetID {
			return findings[i].TargetID < findings[j].TargetID
		}
		if findings[i].ItemID != findings[j].ItemID {
			return findings[i].ItemID < findings[j].ItemID
		}
		return findings[i].ItemVersion < findings[j].ItemVersion
	})
	return findings, nil
}

func (e *Evaluator) evaluateItem(ctx context.Context, snapshot RunSnapshot, target TargetRun, item Item, now time.Time) (Finding, error) {
	if !advertises(target, item.SourceType) || !hasCapabilities(target, item.RequiredCapabilities) {
		return baseFinding(snapshot, target, item, LevelUnsupported, now, map[string]string{"reason": "source_unsupported"}), nil
	}
	switch item.SourceType {
	case SourceMetric:
		return e.evaluateMetric(ctx, snapshot, target, item, now)
	case SourceMetadata:
		return evaluateMetadata(snapshot, target, item, now), nil
	case SourceLogSummary:
		return evaluateLogSummary(snapshot, target, item, now), nil
	default:
		return Finding{}, ErrInvalidEvaluation
	}
}

func (e *Evaluator) evaluateMetric(ctx context.Context, snapshot RunSnapshot, target TargetRun, item Item, now time.Time) (Finding, error) {
	rule := *item.MetricRule
	if e.Evidence == nil {
		return baseFinding(snapshot, target, item, LevelMissingData, now, map[string]string{"metric": rule.MetricName, "samples": "0"}), nil
	}
	from := now.Add(-rule.Window)
	observations, err := e.Evidence.Samples(ctx, snapshot.Scope, target.TargetID, []string{rule.MetricName}, from, now, maxEvidenceSamples)
	if err != nil {
		return Finding{}, err
	}
	if len(observations) > maxEvidenceSamples {
		observations = observations[:maxEvidenceSamples]
	}
	usable, malformed := usableMetricObservations(observations, target.TargetID, rule, from, now)
	if malformed || len(usable) == 0 {
		return baseFinding(snapshot, target, item, LevelMissingData, now, map[string]string{"metric": rule.MetricName, "samples": strconv.Itoa(len(usable))}), nil
	}
	value := aggregateObservations(rule.Aggregation, usable)
	level := metricLevel(value, rule)
	observedAt := usable[len(usable)-1].ObservedAt.UTC()
	return thresholdFinding(snapshot, target, item, level, observedAt, rule, value, len(usable)), nil
}

func evaluateMetadata(snapshot RunSnapshot, target TargetRun, item Item, now time.Time) Finding {
	if item.ID == "database.process.presence" && !target.TrustedProcessAllowlist {
		return baseFinding(snapshot, target, item, LevelUnsupported, now, map[string]string{"reason": "process_allowlist_unconfigured"})
	}
	name := map[string]string{
		"host.oom.evidence":         "dbpilot.inspection.host.oom.count",
		"host.time.synchronization": "dbpilot.inspection.host.time.synchronized",
		"database.process.presence": "dbpilot.inspection.host.database.required_process_count",
	}[item.ID]
	if name == "" {
		return baseFinding(snapshot, target, item, LevelMissingData, now, map[string]string{"samples": "0"})
	}
	observation, ok := latestObservation(target.Observations, target.TargetID, SourceMetadata, name, now.Add(-5*time.Minute), now)
	if !ok {
		return baseFinding(snapshot, target, item, LevelMissingData, now, map[string]string{"metric": name, "samples": "0"})
	}
	level := LevelHealthy
	switch item.ID {
	case "host.oom.evidence":
		if observation.Value >= 1 {
			level = LevelCritical
		}
	case "host.time.synchronization":
		if observation.Value != 1 {
			level = LevelCritical
		}
	case "database.process.presence":
		if observation.Value <= 0 {
			level = LevelCritical
		}
	}
	return baseFinding(snapshot, target, item, level, observation.ObservedAt.UTC(), map[string]string{
		"metric": name, "value": formatFloat(observation.Value), "observed_at": observation.ObservedAt.UTC().Format(time.RFC3339Nano), "samples": "1",
	})
}

func evaluateLogSummary(snapshot RunSnapshot, target TargetRun, item Item, now time.Time) Finding {
	from := now.Add(-5 * time.Minute)
	errorsObservation, errorsOK := latestObservation(target.Observations, target.TargetID, SourceLogSummary, "dbpilot.inspection.host.log.error_count", from, now)
	warningsObservation, warningsOK := latestObservation(target.Observations, target.TargetID, SourceLogSummary, "dbpilot.inspection.host.log.warning_count", from, now)
	if !errorsOK || !warningsOK {
		return baseFinding(snapshot, target, item, LevelMissingData, now, map[string]string{"samples": "0"})
	}
	level := LevelHealthy
	if errorsObservation.Value >= 1 {
		level = LevelCritical
	} else if warningsObservation.Value >= 1 {
		level = LevelWarning
	}
	observedAt := errorsObservation.ObservedAt
	if warningsObservation.ObservedAt.After(observedAt) {
		observedAt = warningsObservation.ObservedAt
	}
	return baseFinding(snapshot, target, item, level, observedAt.UTC(), map[string]string{
		"error_count": formatFloat(errorsObservation.Value), "warning_count": formatFloat(warningsObservation.Value), "observed_at": observedAt.UTC().Format(time.RFC3339Nano), "samples": "2",
	})
}

func usableMetricObservations(input []Observation, targetID string, rule MetricRule, from, to time.Time) ([]Observation, bool) {
	usable := make([]Observation, 0, len(input))
	malformed := false
	for _, observation := range input {
		if observation.TargetID != targetID || observation.Name != rule.MetricName || observation.SourceType != SourceMetric {
			continue
		}
		if !isUTC(observation.ObservedAt) || !finite(observation.Value) || observation.ID == "" {
			malformed = true
			continue
		}
		if observation.ObservedAt.Before(from) || observation.ObservedAt.After(to) || !labelsMatch(observation.Labels, rule.Labels) {
			continue
		}
		usable = append(usable, observation)
	}
	sort.Slice(usable, func(i, j int) bool { return observationLess(usable[i], usable[j]) })
	deduplicated := usable[:0]
	seen := make(map[string]struct{}, len(usable))
	for _, observation := range usable {
		if _, exists := seen[observation.ID]; exists {
			continue
		}
		seen[observation.ID] = struct{}{}
		deduplicated = append(deduplicated, observation)
	}
	return deduplicated, malformed
}

func latestObservation(input []Observation, targetID string, source SourceType, name string, from, to time.Time) (Observation, bool) {
	filtered := make([]Observation, 0, len(input))
	for _, observation := range input {
		if observation.TargetID != targetID || observation.SourceType != source || observation.Name != name || !isUTC(observation.ObservedAt) || !finite(observation.Value) || observation.ObservedAt.Before(from) || observation.ObservedAt.After(to) {
			continue
		}
		filtered = append(filtered, observation)
	}
	if len(filtered) == 0 {
		return Observation{}, false
	}
	sort.Slice(filtered, func(i, j int) bool { return observationLess(filtered[i], filtered[j]) })
	return filtered[len(filtered)-1], true
}

func thresholdFinding(snapshot RunSnapshot, target TargetRun, item Item, level FindingLevel, observedAt time.Time, rule MetricRule, value float64, samples int) Finding {
	warning, critical := rule.WarningThreshold, rule.CriticalThreshold
	finding := baseFinding(snapshot, target, item, level, observedAt, map[string]string{
		"metric": rule.MetricName, "value": formatFloat(value), "observed_at": observedAt.UTC().Format(time.RFC3339Nano), "samples": strconv.Itoa(samples),
		"warning_threshold": formatFloat(warning), "critical_threshold": formatFloat(critical),
	})
	finding.WarningThreshold = &warning
	finding.CriticalThreshold = &critical
	return finding
}

func baseFinding(snapshot RunSnapshot, target TargetRun, item Item, level FindingLevel, observedAt time.Time, evidence map[string]string) Finding {
	return Finding{Scope: snapshot.Scope, RunID: snapshot.ID, TargetID: target.TargetID, ItemID: item.ID, ItemVersion: item.Version, Level: level, ObservedAt: observedAt.UTC(), Evidence: evidence}
}

func aggregateObservations(aggregation Aggregation, observations []Observation) float64 {
	switch aggregation {
	case AggregationLatest:
		return observations[len(observations)-1].Value
	case AggregationAverage:
		var sum float64
		for _, observation := range observations {
			sum += observation.Value
		}
		return sum / float64(len(observations))
	case AggregationMaximum:
		value := observations[0].Value
		for _, observation := range observations[1:] {
			if observation.Value > value {
				value = observation.Value
			}
		}
		return value
	case AggregationMinimum:
		value := observations[0].Value
		for _, observation := range observations[1:] {
			if observation.Value < value {
				value = observation.Value
			}
		}
		return value
	default:
		return 0
	}
}

func metricLevel(value float64, rule MetricRule) FindingLevel {
	switch rule.Operator {
	case OperatorGT:
		if value > rule.CriticalThreshold {
			return LevelCritical
		}
		if value > rule.WarningThreshold {
			return LevelWarning
		}
	case OperatorGTE:
		if value >= rule.CriticalThreshold {
			return LevelCritical
		}
		if value >= rule.WarningThreshold {
			return LevelWarning
		}
	case OperatorLT:
		if value < rule.CriticalThreshold {
			return LevelCritical
		}
		if value < rule.WarningThreshold {
			return LevelWarning
		}
	case OperatorLTE:
		if value <= rule.CriticalThreshold {
			return LevelCritical
		}
		if value <= rule.WarningThreshold {
			return LevelWarning
		}
	}
	return LevelHealthy
}

func observationLess(left, right Observation) bool {
	if !left.ObservedAt.Equal(right.ObservedAt) {
		return left.ObservedAt.Before(right.ObservedAt)
	}
	if left.ID != right.ID {
		return left.ID < right.ID
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	if labelIdentity(left.Labels) != labelIdentity(right.Labels) {
		return labelIdentity(left.Labels) < labelIdentity(right.Labels)
	}
	return formatFloat(left.Value) < formatFloat(right.Value)
}

func labelIdentity(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var builder strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&builder, "%d:%s%d:%s", len(key), key, len(labels[key]), labels[key])
	}
	return builder.String()
}

func labelsMatch(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func advertises(target TargetRun, source SourceType) bool {
	for _, advertised := range target.AdvertisedSources {
		if advertised == source {
			return true
		}
	}
	return false
}

func hasCapabilities(target TargetRun, required []string) bool {
	if len(required) == 0 {
		return true
	}
	have := make(map[string]struct{}, len(target.Capabilities))
	for _, capability := range target.Capabilities {
		have[capability] = struct{}{}
	}
	for _, capability := range required {
		if _, exists := have[capability]; !exists {
			return false
		}
	}
	return true
}

func snapshotHasTarget(snapshot RunSnapshot, targetID string) bool {
	for _, target := range snapshot.Targets {
		if target.TargetID == targetID {
			return true
		}
	}
	return false
}

func (e *Evaluator) now() time.Time {
	if e.Now == nil {
		return time.Now().UTC()
	}
	return e.Now().UTC()
}

func formatFloat(value float64) string { return strconv.FormatFloat(value, 'g', -1, 64) }
