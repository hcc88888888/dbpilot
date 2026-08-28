package inspection

import (
	"fmt"
	"testing"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

func TestTransitionAllowsOnlyForwardRunStates(t *testing.T) {
	// Break caught: allowing a terminal run to re-enter evaluation would rewrite immutable history.
	if err := ValidateRunTransition(RunQueued, RunCollecting); err != nil {
		t.Fatalf("queued -> collecting: %v", err)
	}
	if err := ValidateRunTransition(RunGeneratingReport, RunPartial); err != nil {
		t.Fatalf("generating_report -> partial: %v", err)
	}
	if err := ValidateRunTransition(RunCompleted, RunEvaluating); err == nil {
		t.Fatal("completed run must not re-enter evaluation")
	}
}

func TestAggregateRunStatusDoesNotHideTargetFailure(t *testing.T) {
	// Break caught: treating mixed or wholly unsuccessful targets as completed would report a false success.
	if got := AggregateRunStatus([]TargetStatus{TargetSucceeded, TargetFailed}); got != RunPartial {
		t.Fatalf("mixed target statuses = %q, want %q", got, RunPartial)
	}
	if got := AggregateRunStatus([]TargetStatus{TargetFailed, TargetUnsupported}); got != RunFailed {
		t.Fatalf("unsuccessful target statuses = %q, want %q", got, RunFailed)
	}
	for _, status := range []TargetStatus{TargetPending, TargetCollecting, TargetEvaluating} {
		if got := AggregateRunStatus([]TargetStatus{TargetSucceeded, status}); got != RunEvaluating {
			t.Fatalf("nonterminal target %q produced %q, want %q", status, got, RunEvaluating)
		}
	}
}

func TestModelRejectsMutableOrUnboundedRunSnapshots(t *testing.T) {
	utc := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
	base := RunSnapshot{
		ID:        "run-1",
		Scope:     platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		CreatedAt: utc,
		Items: []Item{{
			ID: "cpu.utilization", Version: 1, ScopeType: ScopeHost, SourceType: SourceMetric,
			EvidenceSelector: []string{"value"},
			MetricRule:       &MetricRule{MetricName: "system.cpu.utilization", Window: time.Minute, Aggregation: AggregationLatest, Operator: OperatorGTE, WarningThreshold: 80, CriticalThreshold: 90},
		}},
		Targets: []TargetRun{{TargetID: "target-1", AgentID: "agent-1", Status: TargetPending}},
	}
	cases := []struct {
		name string
		edit func(*RunSnapshot)
	}{
		{"duplicate item version", func(v *RunSnapshot) { v.Items = append(v.Items, v.Items[0]) }},
		{"duplicate target", func(v *RunSnapshot) { v.Targets = append(v.Targets, v.Targets[0]) }},
		{"empty scope", func(v *RunSnapshot) { v.Scope.TenantID = "" }},
		{"too many items", func(v *RunSnapshot) {
			for i := 0; i < 200; i++ {
				v.Items = append(v.Items, Item{ID: "item-" + string(rune('a'+i%26)), Version: i + 2, ScopeType: ScopeHost, SourceType: SourceMetadata, EvidenceSelector: []string{"value"}})
			}
		}},
		{"too many targets", func(v *RunSnapshot) {
			for i := 0; i < 10000; i++ {
				v.Targets = append(v.Targets, TargetRun{TargetID: fmt.Sprintf("target-%d", i), AgentID: "agent", Status: TargetPending})
			}
		}},
		{"non UTC created at", func(v *RunSnapshot) { v.CreatedAt = utc.In(time.FixedZone("CST", 8*60*60)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := base
			snapshot.Items = append([]Item(nil), base.Items...)
			snapshot.Targets = append([]TargetRun(nil), base.Targets...)
			tc.edit(&snapshot)
			if err := snapshot.Validate(); err == nil {
				t.Fatal("snapshot validation unexpectedly succeeded")
			}
		})
	}
}

func TestFindingRejectsEvidenceLargerThan64KiB(t *testing.T) {
	// Break caught: oversized evidence can make immutable report snapshots unbounded.
	finding := Finding{
		Scope:       platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		RunID:       "run-1",
		TargetID:    "target-1",
		ItemID:      "cpu.utilization",
		ItemVersion: 1,
		Level:       LevelWarning,
		ObservedAt:  time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC),
		Evidence:    map[string]string{"value": string(make([]byte, 64*1024+1))},
	}
	if err := finding.Validate(); err == nil {
		t.Fatal("finding with oversized evidence must be rejected")
	}
}

func TestModelRequiresStructuredEvidenceSelectorForCustomMetricItems(t *testing.T) {
	// Break caught: a custom metric rule without a bounded selector can create an untraceable finding.
	item := Item{
		ID: "custom.disk.utilization", Version: 1, ScopeType: ScopeHost, SourceType: SourceMetric,
		MetricRule: &MetricRule{MetricName: "system.filesystem.utilization", Labels: map[string]string{}, Window: time.Minute, Aggregation: AggregationLatest, Operator: OperatorGTE, WarningThreshold: 80, CriticalThreshold: 90},
	}
	if err := item.Validate(); err == nil {
		t.Fatal("custom metric item without evidence selector must be rejected")
	}
}

func TestMetricRuleRequiresCriticalThresholdOnTheSevereSide(t *testing.T) {
	// Break caught: reversed low-side thresholds make a critical condition unreachable or misclassified.
	validLowSide := MetricRule{MetricName: "dbpilot.inspection.host.free_ratio", Labels: map[string]string{}, Window: time.Minute, Aggregation: AggregationLatest, Operator: OperatorLTE, WarningThreshold: 10, CriticalThreshold: 5}
	if err := validLowSide.Validate(); err != nil {
		t.Fatalf("valid low-side rule: %v", err)
	}
	invalidLowSide := validLowSide
	invalidLowSide.CriticalThreshold = 10
	if err := invalidLowSide.Validate(); err == nil {
		t.Fatal("low-side critical threshold above warning must be rejected")
	}
}

func TestSystemItemsMustExactlyMatchTheCanonicalCatalog(t *testing.T) {
	// Break caught: accepting a spoofed system item would let a caller rewrite a version-one decision.
	canonical := builtinItem("host.filesystem.utilization")
	cases := []struct {
		name string
		edit func(*Item)
	}{
		{"unknown system id", func(item *Item) { item.ID = "host.unreviewed.utilization" }},
		{"wrong system version", func(item *Item) { item.Version = 2 }},
		{"mutated threshold", func(item *Item) { item.MetricRule.WarningThreshold = 79 }},
		{"mutated selector", func(item *Item) { item.EvidenceSelector = []string{"value"} }},
		{"mutated capability", func(item *Item) { item.RequiredCapabilities = []string{"host.metrics"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			item := cloneItems([]Item{canonical})[0]
			tc.edit(&item)
			if err := item.Validate(); err == nil {
				t.Fatal("spoofed system item must be rejected")
			}
		})
	}
	custom := cloneItems([]Item{canonical})[0]
	custom.System = false
	custom.EvidenceSelector = []string{"value"}
	if err := custom.Validate(); err == nil {
		t.Fatal("custom item must not reuse a built-in id")
	}
}

func TestSnapshotBoundsEmbeddedObservations(t *testing.T) {
	// Break caught: unbounded normalized evidence can exhaust evaluator memory before a finding is produced.
	base := metricSnapshot(AggregationLatest)
	for index := 0; index < 257; index++ {
		base.Targets[0].Observations = append(base.Targets[0].Observations, Observation{ID: fmt.Sprintf("sample-%d", index), TargetID: "target-1", Name: "dbpilot.inspection.host.oom.count", SourceType: SourceMetadata, Value: 0, ObservedAt: testTime()})
	}
	if err := base.Validate(); err == nil {
		t.Fatal("target with more than 256 observations must be rejected")
	}

	total := metricSnapshot(AggregationLatest)
	total.Targets = nil
	for targetIndex := 0; targetIndex < 40; targetIndex++ {
		target := TargetRun{TargetID: fmt.Sprintf("target-%d", targetIndex), AgentID: "agent-1", Status: TargetPending}
		for observationIndex := 0; observationIndex < 256; observationIndex++ {
			target.Observations = append(target.Observations, Observation{ID: fmt.Sprintf("sample-%d", observationIndex), TargetID: target.TargetID, Name: "dbpilot.inspection.host.oom.count", SourceType: SourceMetadata, Value: 0, ObservedAt: testTime()})
		}
		total.Targets = append(total.Targets, target)
	}
	if err := total.Validate(); err == nil {
		t.Fatal("snapshot with more than 10000 observations must be rejected")
	}
}

func TestSnapshotAcceptsExactlyTenThousandTargetsAndRejectsOneMore(t *testing.T) {
	// Break caught: changing the target-count guard would admit an unbounded run snapshot.
	snapshot := metricSnapshot(AggregationLatest)
	for index := 0; index < 9999; index++ {
		snapshot.Targets = append(snapshot.Targets, TargetRun{TargetID: fmt.Sprintf("target-%d", index+2), AgentID: "agent-1", Status: TargetPending})
	}
	if len(snapshot.Targets) != 10000 || snapshot.Validate() != nil {
		t.Fatalf("exactly 10000 valid targets must be accepted, got %d", len(snapshot.Targets))
	}
	snapshot.Targets = append(snapshot.Targets, TargetRun{TargetID: "target-10001", AgentID: "agent-1", Status: TargetPending})
	if err := snapshot.Validate(); err == nil {
		t.Fatal("10001 valid unique targets must be rejected")
	}
}
