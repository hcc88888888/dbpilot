package inspection

import (
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
}

func TestModelRejectsMutableOrUnboundedRunSnapshots(t *testing.T) {
	utc := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
	base := RunSnapshot{
		ID:        "run-1",
		Scope:     platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"},
		CreatedAt: utc,
		Items: []Item{{
			ID: "cpu.utilization", Version: 1, ScopeType: ScopeHost, SourceType: SourceMetric,
			MetricRule: &MetricRule{MetricName: "system.cpu.utilization", Window: time.Minute, Aggregation: AggregationLatest, Operator: OperatorGTE, WarningThreshold: 80, CriticalThreshold: 90},
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
				v.Targets = append(v.Targets, TargetRun{TargetID: "target-" + string(rune(i+1)), AgentID: "agent", Status: TargetPending})
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
