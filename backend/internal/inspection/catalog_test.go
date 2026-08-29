package inspection

import (
	"strings"
	"testing"
)

func TestBuiltinHostCatalogPublishesVersionOneThresholds(t *testing.T) {
	// Break caught: an accidental catalog threshold change would silently alter v1 findings.
	items := BuiltinHostItems()
	if len(items) != 13 {
		t.Fatalf("builtin item count = %d, want 13", len(items))
	}
	byID := make(map[string]Item, len(items))
	for _, item := range items {
		if item.Version != 1 || !item.System || item.Validate() != nil {
			t.Fatalf("invalid built-in item %#v", item)
		}
		if strings.TrimSpace(item.RecommendationTemplate) == "" || len(item.RecommendationTemplate) > 4000 {
			t.Fatalf("built-in item %q has no bounded operator recommendation", item.ID)
		}
		byID[item.ID] = item
	}
	for _, check := range []struct {
		id       string
		warning  float64
		critical float64
	}{
		{"host.cpu.utilization", 80, 90},
		{"host.memory.utilization", 80, 90},
		{"host.filesystem.utilization", 80, 90},
		{"host.filesystem.inode_utilization", 80, 90},
		{"host.load.per_cpu", 1, 2},
		{"host.swap.utilization", 25, 50},
		{"agent.spool.utilization", 70, 90},
	} {
		item, ok := byID[check.id]
		if !ok || item.MetricRule == nil {
			t.Fatalf("missing metric catalog item %q", check.id)
		}
		if item.MetricRule.WarningThreshold != check.warning || item.MetricRule.CriticalThreshold != check.critical {
			t.Fatalf("%s thresholds = %v/%v, want %v/%v", check.id, item.MetricRule.WarningThreshold, item.MetricRule.CriticalThreshold, check.warning, check.critical)
		}
	}
	for _, id := range []string{"agent.heartbeat.freshness", "agent.metric.freshness", "host.oom.evidence", "host.time.synchronization", "database.process.presence", "host.log.error_summary"} {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing catalog item %q", id)
		}
	}
	if byID["host.time.synchronization"].SourceType != SourceMetadata || byID["database.process.presence"].SourceType != SourceMetadata || byID["host.log.error_summary"].SourceType != SourceLogSummary {
		t.Fatal("metadata and log-summary catalog sources must remain explicit")
	}
	logSelector := byID["host.log.error_summary"].EvidenceSelector
	if len(logSelector) != 3 || logSelector[0] != "warning_count" || logSelector[1] != "error_count" || logSelector[2] != "critical_count" {
		t.Fatalf("log selector = %#v, want warning/error/critical counters", logSelector)
	}
}

func TestBuiltinHostCatalogReturnsIndependentItemValues(t *testing.T) {
	// Break caught: a caller mutation must not rewrite a later run's versioned system-item definition.
	first := BuiltinHostItems()
	first[0].MetricRule.Labels["changed"] = "yes"
	second := BuiltinHostItems()
	if _, exists := second[0].MetricRule.Labels["changed"]; exists {
		t.Fatal("catalog exposed mutable rule labels")
	}
}
