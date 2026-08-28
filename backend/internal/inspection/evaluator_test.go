package inspection

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

type memoryEvidenceStore struct {
	observations []Observation
	limit        int
}

func (s *memoryEvidenceStore) Samples(_ context.Context, _ platformscope.Scope, _ string, _ []string, _, _ time.Time, limit int) ([]Observation, error) {
	s.limit = limit
	return append([]Observation(nil), s.observations...), nil
}

func TestEvaluatorClassifiesFilesystemThresholdEquality(t *testing.T) {
	// Break caught: classifying equality below warning/critical changes the published >= v1 rule.
	now := testTime()
	for _, tc := range []struct {
		value float64
		want  FindingLevel
	}{
		{79.9, LevelHealthy}, {80, LevelWarning}, {89.9, LevelWarning}, {90, LevelCritical},
	} {
		t.Run(tc.want.String(), func(t *testing.T) {
			store := &memoryEvidenceStore{observations: []Observation{metricObservation("sample-1", "target-1", "system.filesystem.utilization", tc.value, now)}}
			findings, err := (&Evaluator{Evidence: store, Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), metricSnapshot(AggregationLatest), metricTarget())
			if err != nil {
				t.Fatal(err)
			}
			if got := findings[0].Level; got != tc.want {
				t.Fatalf("level for %v = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

func TestEvaluatorAggregatesSortedMetricSeries(t *testing.T) {
	// Break caught: using insertion order or the wrong aggregation changes deterministic findings.
	now := testTime()
	for _, tc := range []struct {
		aggregation Aggregation
		want        FindingLevel
	}{
		{AggregationLatest, LevelWarning}, {AggregationAverage, LevelWarning}, {AggregationMaximum, LevelWarning}, {AggregationMinimum, LevelHealthy},
	} {
		t.Run(string(tc.aggregation), func(t *testing.T) {
			store := &memoryEvidenceStore{observations: []Observation{
				metricObservation("b", "target-1", "system.filesystem.utilization", 8, now.Add(-time.Minute)),
				metricObservation("a", "target-1", "system.filesystem.utilization", 2, now.Add(-2*time.Minute)),
			}}
			snapshot := metricSnapshot(tc.aggregation)
			snapshot.Items[0].MetricRule.WarningThreshold = 5
			snapshot.Items[0].MetricRule.CriticalThreshold = 9
			findings, err := (&Evaluator{Evidence: store, Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
			if err != nil || findings[0].Level != tc.want {
				t.Fatalf("aggregate %s = %#v, %v; want %q", tc.aggregation, findings, err, tc.want)
			}
		})
	}
}

func TestEvaluatorTreatsMalformedOrInapplicableMetricEvidenceAsMissing(t *testing.T) {
	// Break caught: stale, malformed, unmatched, or absent samples must never become a healthy finding.
	now := testTime()
	for _, tc := range []struct {
		name         string
		observations []Observation
		wantSamples  string
	}{
		{"stale", []Observation{metricObservation("old", "target-1", "system.filesystem.utilization", 1, now.Add(-6*time.Minute))}, "0"},
		{"nan", []Observation{metricObservation("nan", "target-1", "system.filesystem.utilization", math.NaN(), now)}, "0"},
		{"infinity", []Observation{metricObservation("inf", "target-1", "system.filesystem.utilization", math.Inf(1), now)}, "0"},
		{"label mismatch", []Observation{{ID: "wrong-label", TargetID: "target-1", Name: "system.filesystem.utilization", SourceType: SourceMetric, Labels: map[string]string{"mount": "/other"}, Value: 99, ObservedAt: now}}, "0"},
		{"missing series", nil, "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &memoryEvidenceStore{observations: tc.observations}
			snapshot := metricSnapshot(AggregationLatest)
			snapshot.Items[0].MetricRule.Labels = map[string]string{"mount": "/data"}
			findings, err := (&Evaluator{Evidence: store, Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
			if err != nil {
				t.Fatal(err)
			}
			if got := findings[0].Level; got != LevelMissingData || findings[0].Evidence["samples"] != tc.wantSamples {
				t.Fatalf("finding = %#v, want missing data with %s usable samples", findings[0], tc.wantSamples)
			}
		})
	}
}

func TestEvaluatorDeduplicatesSamplesAndDoesNotLeakLabels(t *testing.T) {
	// Break caught: duplicate ingestion must not skew aggregates and labels must not enter report evidence.
	now := testTime()
	store := &memoryEvidenceStore{observations: []Observation{
		{ID: "same", TargetID: "target-1", Name: "system.filesystem.utilization", SourceType: SourceMetric, Labels: map[string]string{"mount": "/data", "api_token": "do-not-copy"}, Value: 90, ObservedAt: now},
		{ID: "same", TargetID: "target-1", Name: "system.filesystem.utilization", SourceType: SourceMetric, Labels: map[string]string{"mount": "/data", "api_token": "do-not-copy"}, Value: 90, ObservedAt: now},
	}}
	snapshot := metricSnapshot(AggregationAverage)
	snapshot.Items[0].MetricRule.Labels = map[string]string{"mount": "/data"}
	findings, err := (&Evaluator{Evidence: store, Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
	if err != nil {
		t.Fatal(err)
	}
	if got := findings[0].Evidence["samples"]; got != "1" {
		t.Fatalf("deduplicated sample count = %q, want 1", got)
	}
	if _, leaked := findings[0].Evidence["api_token"]; leaked {
		t.Fatal("secret-bearing label leaked into finding evidence")
	}
}

func TestEvaluatorMarksUnadvertisedSourceUnsupported(t *testing.T) {
	// Break caught: a target cannot be called healthy when its Agent never advertised the required source.
	now := testTime()
	snapshot := metricSnapshot(AggregationLatest)
	snapshot.Targets[0].AdvertisedSources = nil
	findings, err := (&Evaluator{Evidence: &memoryEvidenceStore{}, Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
	if err != nil {
		t.Fatal(err)
	}
	if got := findings[0].Level; got != LevelUnsupported {
		t.Fatalf("unadvertised source level = %q, want %q", got, LevelUnsupported)
	}
}

func TestEvaluatorUsesBuiltinMetadataAndLogSemantics(t *testing.T) {
	// Break caught: absence, unsupported prerequisites, and boolean/count facts must remain distinct.
	now := testTime()
	snapshot := RunSnapshot{
		ID: "run-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, CreatedAt: now,
		Items: []Item{
			builtinItem("host.oom.evidence"), builtinItem("host.time.synchronization"), builtinItem("database.process.presence"), builtinItem("host.log.error_summary"),
		},
		Targets: []TargetRun{{TargetID: "target-1", AgentID: "agent-1", Status: TargetPending}},
	}
	canonicalTarget := TargetRun{
		TargetID: "target-1", AgentID: "agent-1", Status: TargetEvaluating, TrustedProcessAllowlist: false,
		AdvertisedSources: []SourceType{SourceMetadata, SourceLogSummary},
		Observations: []Observation{
			metadataObservation("oom", "dbpilot.inspection.host.oom.count", 1, now),
			metadataObservation("sync", "dbpilot.inspection.host.time.synchronized", 0, now),
			metadataObservation("process", "dbpilot.inspection.host.database.required_process_count", 0, now),
			{ID: "errors", TargetID: "target-1", Name: "dbpilot.inspection.host.log.error_count", SourceType: SourceLogSummary, Value: 0, ObservedAt: now},
			{ID: "warnings", TargetID: "target-1", Name: "dbpilot.inspection.host.log.warning_count", SourceType: SourceLogSummary, Value: 1, ObservedAt: now},
			{ID: "critical", TargetID: "target-1", Name: "dbpilot.inspection.host.log.critical_count", SourceType: SourceLogSummary, Value: 0, ObservedAt: now},
		},
	}
	snapshot.Targets = []TargetRun{canonicalTarget}
	findings, err := (&Evaluator{Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]FindingLevel{"host.oom.evidence": LevelCritical, "host.time.synchronization": LevelCritical, "database.process.presence": LevelUnsupported, "host.log.error_summary": LevelWarning}
	for _, finding := range findings {
		if finding.Level != want[finding.ItemID] {
			t.Fatalf("%s = %q, want %q", finding.ItemID, finding.Level, want[finding.ItemID])
		}
	}
}

func TestEvaluatorReturnsFindingsInItemVersionOrder(t *testing.T) {
	// Break caught: map iteration can make otherwise identical report output reorder across runs.
	now := testTime()
	first := metricSnapshot(AggregationLatest).Items[0]
	first.ID = "z.item"
	second := first
	second.ID = "a.item"
	second.Version = 2
	snapshot := metricSnapshot(AggregationLatest)
	snapshot.Items = []Item{first, second}
	store := &memoryEvidenceStore{observations: []Observation{metricObservation("sample", "target-1", "system.filesystem.utilization", 1, now)}}
	findings, err := (&Evaluator{Evidence: store, Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 || findings[0].ItemID != "a.item" || findings[0].ItemVersion != 2 || findings[1].ItemID != "z.item" {
		t.Fatalf("finding order = %#v", findings)
	}
	if store.limit <= 0 || store.limit > 1000 {
		t.Fatalf("evidence read limit = %d, want a bounded limit", store.limit)
	}
}

func TestEvaluatorUsesOnlyTheCanonicalSnapshotTarget(t *testing.T) {
	// Break caught: caller-provided sources or observations must not replace the immutable target snapshot.
	now := testTime()
	snapshot := metadataSnapshot("host.oom.evidence", []Observation{metadataObservation("canonical", "dbpilot.inspection.host.oom.count", 0, now)})
	forged := TargetRun{
		TargetID: "target-1", AgentID: "agent-1", Status: TargetEvaluating, AdvertisedSources: []SourceType{SourceMetadata},
		Observations: []Observation{metadataObservation("forged", "dbpilot.inspection.host.oom.count", 1, now)},
	}
	findings, err := (&Evaluator{Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, forged)
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Level != LevelHealthy {
		t.Fatalf("forged evidence changed canonical finding to %q", findings[0].Level)
	}
	forged.AgentID = "agent-2"
	if _, err := (&Evaluator{Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, forged); err == nil {
		t.Fatal("same target id with a different agent id must be rejected")
	}
}

func TestEvaluatorIgnoresMalformedSiblingEvidence(t *testing.T) {
	// Break caught: evaluating one bounded target must not be blocked by unrelated sibling evidence.
	now := testTime()
	snapshot := metricSnapshot(AggregationLatest)
	snapshot.Targets = append(snapshot.Targets, TargetRun{
		TargetID: "target-2", AgentID: "agent-2", Status: TargetPending, AdvertisedSources: []SourceType{SourceMetadata},
		Observations: []Observation{{ID: "bad", TargetID: "target-2", Name: "bad.name", SourceType: SourceMetadata, Value: math.NaN(), ObservedAt: now}},
	})
	store := &memoryEvidenceStore{observations: []Observation{metricObservation("good", "target-1", "system.filesystem.utilization", 1, now)}}
	findings, err := (&Evaluator{Evidence: store, Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Level != LevelHealthy {
		t.Fatalf("selected target finding = %q, want healthy", findings[0].Level)
	}
}

func TestEvaluatorTreatsMalformedMetadataEvidenceAsMissingData(t *testing.T) {
	// Break caught: malformed count/boolean metadata must not abort a target or be treated as healthy.
	now := testTime()
	invalidTime := now.In(time.FixedZone("CST", 8*60*60))
	for _, tc := range []struct {
		name    string
		itemID  string
		trusted bool
		observe Observation
	}{
		{"negative oom count", "host.oom.evidence", false, metadataObservation("oom-negative", "dbpilot.inspection.host.oom.count", -1, now)},
		{"fractional oom count", "host.oom.evidence", false, metadataObservation("oom-fraction", "dbpilot.inspection.host.oom.count", 0.5, now)},
		{"invalid time sync value", "host.time.synchronization", false, metadataObservation("sync-invalid", "dbpilot.inspection.host.time.synchronized", 2, now)},
		{"fractional time sync value", "host.time.synchronization", false, metadataObservation("sync-fraction", "dbpilot.inspection.host.time.synchronized", 0.5, now)},
		{"negative process count", "database.process.presence", true, metadataObservation("process-negative", "dbpilot.inspection.host.database.required_process_count", -1, now)},
		{"fractional process count", "database.process.presence", true, metadataObservation("process-fraction", "dbpilot.inspection.host.database.required_process_count", 0.5, now)},
		{"non utc metadata", "host.oom.evidence", false, metadataObservation("oom-time", "dbpilot.inspection.host.oom.count", 0, invalidTime)},
		{"wrong metadata source", "host.oom.evidence", false, Observation{ID: "oom-source", TargetID: "target-1", Name: "dbpilot.inspection.host.oom.count", SourceType: SourceMetric, Labels: map[string]string{}, Value: 0, ObservedAt: now}},
		{"wrong metadata name", "host.oom.evidence", false, metadataObservation("oom-name", "dbpilot.inspection.host.unknown_count", 0, now)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := metadataSnapshot(tc.itemID, []Observation{tc.observe})
			snapshot.Targets[0].TrustedProcessAllowlist = tc.trusted
			findings, err := (&Evaluator{Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
			if err != nil {
				t.Fatal(err)
			}
			if findings[0].Level != LevelMissingData {
				t.Fatalf("malformed metadata level = %q, want missing_data", findings[0].Level)
			}
		})
	}
}

func TestEvaluatorRequiresStructurallyValidMetadataObservation(t *testing.T) {
	// Break caught: a structurally malformed matching metadata observation must not classify as healthy.
	now := testTime()
	for _, tc := range []struct {
		name string
		edit func(*Observation)
	}{
		{"invalid id", func(observation *Observation) { observation.ID = "" }},
		{"invalid label key", func(observation *Observation) { observation.Labels = map[string]string{"bad key": "value"} }},
		{"invalid label value", func(observation *Observation) { observation.Labels = map[string]string{"host": "api_token"} }},
		{"nonfinite value", func(observation *Observation) { observation.Value = math.Inf(1) }},
		{"non utc timestamp", func(observation *Observation) { observation.ObservedAt = now.In(time.FixedZone("CST", 8*60*60)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := metadataObservation("oom", "dbpilot.inspection.host.oom.count", 0, now)
			tc.edit(&observation)
			findings, err := (&Evaluator{Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), metadataSnapshot("host.oom.evidence", []Observation{observation}), metricTarget())
			if err != nil {
				t.Fatal(err)
			}
			if findings[0].Level != LevelMissingData {
				t.Fatalf("malformed metadata level = %q, want missing_data", findings[0].Level)
			}
		})
	}
}

func TestEvaluatorAppliesFullLogWindowSemantics(t *testing.T) {
	// Break caught: a missing or malformed log counter must not masquerade as a healthy window.
	now := testTime()
	for _, tc := range []struct {
		name         string
		observations []Observation
		want         FindingLevel
	}{
		{"all zero healthy", logObservations(now, 0, 0, 0), LevelHealthy},
		{"warning only", logObservations(now, 1, 0, 0), LevelWarning},
		{"error critical", logObservations(now, 0, 1, 0), LevelCritical},
		{"critical critical", logObservations(now, 0, 0, 1), LevelCritical},
		{"missing critical counter", logObservations(now, 0, 0, 0)[:2], LevelMissingData},
		{"negative warning counter", logObservations(now, -1, 0, 0), LevelMissingData},
		{"fractional error counter", logObservations(now, 0, 0.5, 0), LevelMissingData},
		{"wrong counter source", []Observation{{ID: "warning", TargetID: "target-1", Name: "dbpilot.inspection.host.log.warning_count", SourceType: SourceMetadata, Value: 0, ObservedAt: now}, logObservations(now, 0, 0, 0)[1], logObservations(now, 0, 0, 0)[2]}, LevelMissingData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := metadataSnapshot("host.log.error_summary", tc.observations)
			findings, err := (&Evaluator{Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
			if err != nil {
				t.Fatal(err)
			}
			if findings[0].Level != tc.want {
				t.Fatalf("log level = %q, want %q", findings[0].Level, tc.want)
			}
		})
	}
}

func TestEvaluatorRequiresStructurallyValidLogObservation(t *testing.T) {
	// Break caught: a malformed matching log counter must invalidate the full observation window.
	now := testTime()
	for _, tc := range []struct {
		name string
		edit func(*Observation)
	}{
		{"invalid id", func(observation *Observation) { observation.ID = "" }},
		{"invalid label key", func(observation *Observation) { observation.Labels = map[string]string{"bad key": "value"} }},
		{"invalid label value", func(observation *Observation) { observation.Labels = map[string]string{"host": "password"} }},
		{"nonfinite value", func(observation *Observation) { observation.Value = math.NaN() }},
		{"non utc timestamp", func(observation *Observation) { observation.ObservedAt = now.In(time.FixedZone("CST", 8*60*60)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observations := logObservations(now, 0, 0, 0)
			tc.edit(&observations[0])
			findings, err := (&Evaluator{Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), metadataSnapshot("host.log.error_summary", observations), metricTarget())
			if err != nil {
				t.Fatal(err)
			}
			if findings[0].Level != LevelMissingData {
				t.Fatalf("malformed log level = %q, want missing_data", findings[0].Level)
			}
		})
	}
}

func TestEvaluatorHonorsLowSideThresholdEquality(t *testing.T) {
	// Break caught: low-side rules must classify their lower critical boundary before warning.
	now := testTime()
	for _, tc := range []struct {
		value float64
		want  FindingLevel
	}{
		{10.1, LevelHealthy}, {10, LevelWarning}, {5.1, LevelWarning}, {5, LevelCritical},
	} {
		t.Run(formatFloat(tc.value), func(t *testing.T) {
			snapshot := lowSideMetricSnapshot()
			store := &memoryEvidenceStore{observations: []Observation{metricObservation("sample", "target-1", "dbpilot.inspection.host.free_ratio", tc.value, now)}}
			findings, err := (&Evaluator{Evidence: store, Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
			if err != nil {
				t.Fatal(err)
			}
			if findings[0].Level != tc.want {
				t.Fatalf("low-side %v = %q, want %q", tc.value, findings[0].Level, tc.want)
			}
		})
	}
}

func TestEvaluatorAveragesMaxFiniteValuesWithoutOverflow(t *testing.T) {
	// Break caught: summing finite max-float samples can overflow and emit non-finite evidence.
	now := testTime()
	snapshot := metricSnapshot(AggregationAverage)
	snapshot.Items[0].MetricRule.WarningThreshold = math.MaxFloat64 / 3
	snapshot.Items[0].MetricRule.CriticalThreshold = math.MaxFloat64 / 2
	store := &memoryEvidenceStore{observations: []Observation{
		metricObservation("first", "target-1", "system.filesystem.utilization", math.MaxFloat64, now.Add(-time.Minute)),
		metricObservation("second", "target-1", "system.filesystem.utilization", math.MaxFloat64, now),
	}}
	findings, err := (&Evaluator{Evidence: store, Now: func() time.Time { return now }}).EvaluateTarget(context.Background(), snapshot, metricTarget())
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].Level != LevelCritical || findings[0].Evidence["value"] == "+Inf" || findings[0].Evidence["value"] == "NaN" {
		t.Fatalf("overflow-safe average finding = %#v", findings[0])
	}
}

func TestAverageAggregationHandlesExtremeAndSubnormalFiniteValues(t *testing.T) {
	// Break caught: divide-first averaging loses subnormal values and naive deltas overflow at opposite extremes.
	for _, tc := range []struct {
		name   string
		values []float64
		want   float64
	}{
		{"three max floats", []float64{math.MaxFloat64, math.MaxFloat64, math.MaxFloat64}, math.MaxFloat64},
		{"equal smallest subnormals", []float64{math.SmallestNonzeroFloat64, math.SmallestNonzeroFloat64, math.SmallestNonzeroFloat64}, math.SmallestNonzeroFloat64},
		{"opposite extremes", []float64{-math.MaxFloat64, math.MaxFloat64}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observations := make([]Observation, len(tc.values))
			for index, value := range tc.values {
				observations[index] = metricObservation(fmt.Sprintf("sample-%d", index), "target-1", "system.filesystem.utilization", value, testTime().Add(time.Duration(index)*time.Second))
			}
			got, ok := aggregateObservations(AggregationAverage, observations)
			if !ok || !finite(got) || got != tc.want {
				t.Fatalf("average = %v, ok=%t; want %v", got, ok, tc.want)
			}
		})
	}
	if _, ok := aggregateObservations(AggregationAverage, []Observation{{Value: math.Inf(1)}}); ok {
		t.Fatal("impossible nonfinite aggregate must be rejected")
	}
}

func testTime() time.Time { return time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC) }

func metricSnapshot(aggregation Aggregation) RunSnapshot {
	return RunSnapshot{
		ID: "run-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, CreatedAt: testTime(),
		Items:   []Item{{ID: "custom.filesystem.utilization", Version: 1, ScopeType: ScopeHost, SourceType: SourceMetric, EvidenceSelector: []string{"value"}, MetricRule: &MetricRule{MetricName: "system.filesystem.utilization", Labels: map[string]string{}, Window: 5 * time.Minute, Aggregation: aggregation, Operator: OperatorGTE, WarningThreshold: 80, CriticalThreshold: 90}}},
		Targets: []TargetRun{{TargetID: "target-1", AgentID: "agent-1", Status: TargetPending, AdvertisedSources: []SourceType{SourceMetric}}},
	}
}

func metricTarget() TargetRun {
	return TargetRun{TargetID: "target-1", AgentID: "agent-1"}
}

func metadataSnapshot(itemID string, observations []Observation) RunSnapshot {
	return RunSnapshot{
		ID: "run-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, CreatedAt: testTime(),
		Items:   []Item{builtinItem(itemID)},
		Targets: []TargetRun{{TargetID: "target-1", AgentID: "agent-1", Status: TargetPending, AdvertisedSources: []SourceType{SourceMetadata, SourceLogSummary}, Observations: observations}},
	}
}

func lowSideMetricSnapshot() RunSnapshot {
	return RunSnapshot{
		ID: "run-1", Scope: platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}, CreatedAt: testTime(),
		Items:   []Item{{ID: "custom.free_ratio", Version: 1, ScopeType: ScopeHost, SourceType: SourceMetric, EvidenceSelector: []string{"value"}, MetricRule: &MetricRule{MetricName: "dbpilot.inspection.host.free_ratio", Labels: map[string]string{}, Window: 5 * time.Minute, Aggregation: AggregationLatest, Operator: OperatorLTE, WarningThreshold: 10, CriticalThreshold: 5}}},
		Targets: []TargetRun{{TargetID: "target-1", AgentID: "agent-1", Status: TargetPending, AdvertisedSources: []SourceType{SourceMetric}}},
	}
}

func logObservations(now time.Time, warning, errors, critical float64) []Observation {
	return []Observation{
		{ID: "warning", TargetID: "target-1", Name: "dbpilot.inspection.host.log.warning_count", SourceType: SourceLogSummary, Value: warning, ObservedAt: now},
		{ID: "error", TargetID: "target-1", Name: "dbpilot.inspection.host.log.error_count", SourceType: SourceLogSummary, Value: errors, ObservedAt: now},
		{ID: "critical", TargetID: "target-1", Name: "dbpilot.inspection.host.log.critical_count", SourceType: SourceLogSummary, Value: critical, ObservedAt: now},
	}
}

func metricObservation(id, targetID, name string, value float64, observedAt time.Time) Observation {
	return Observation{ID: id, TargetID: targetID, Name: name, SourceType: SourceMetric, Labels: map[string]string{}, Value: value, ObservedAt: observedAt}
}

func metadataObservation(id, name string, value float64, observedAt time.Time) Observation {
	return Observation{ID: id, TargetID: "target-1", Name: name, SourceType: SourceMetadata, Labels: map[string]string{}, Value: value, ObservedAt: observedAt}
}

func builtinItem(id string) Item {
	for _, item := range BuiltinHostItems() {
		if item.ID == id {
			return item
		}
	}
	panic("missing built-in item " + id)
}

func (l FindingLevel) String() string { return string(l) }
