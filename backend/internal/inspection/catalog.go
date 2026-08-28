package inspection

import "time"

// BuiltinHostItems returns independent copies of the immutable version-one
// system catalog. Threshold changes require a new item version rather than a
// mutation of the historical decision definition.
func BuiltinHostItems() []Item {
	metric := func(id, name, metric string, warning, critical float64) Item {
		return Item{
			ID: id, Version: 1, Name: name, Category: "host", ScopeType: ScopeHost, SourceType: SourceMetric, System: true,
			MetricRule: &MetricRule{MetricName: metric, Labels: map[string]string{}, Window: 5 * time.Minute, Aggregation: AggregationLatest, Operator: OperatorGTE, WarningThreshold: warning, CriticalThreshold: critical},
		}
	}
	items := []Item{
		metric("host.cpu.utilization", "CPU utilization", "system.cpu.utilization", 80, 90),
		metric("host.load.per_cpu", "Load per logical CPU", "system.cpu.load_average.1m_per_cpu", 1, 2),
		metric("host.memory.utilization", "Memory utilization", "system.memory.utilization", 80, 90),
		metric("host.swap.utilization", "Swap utilization", "system.swap.utilization", 25, 50),
		metric("host.filesystem.utilization", "Filesystem utilization", "system.filesystem.utilization", 80, 90),
		metric("host.filesystem.inode_utilization", "Filesystem inode utilization", "system.filesystem.inode_utilization", 80, 90),
		metric("agent.heartbeat.freshness", "Agent heartbeat freshness", "dbpilot.inspection.host.agent.heartbeat_age_seconds", 300, 600),
		metric("agent.metric.freshness", "Metric freshness", "dbpilot.inspection.host.metric.age_seconds", 300, 600),
		metric("agent.spool.utilization", "Agent spool utilization", "dbpilot.inspection.host.spool.utilization", 70, 90),
		{
			ID: "host.oom.evidence", Version: 1, Name: "OOM evidence", Category: "host", ScopeType: ScopeHost, SourceType: SourceMetadata, System: true,
			EvidenceSelector: []string{"oom_count"},
		},
		{
			ID: "host.time.synchronization", Version: 1, Name: "Time synchronization", Category: "host", ScopeType: ScopeHost, SourceType: SourceMetadata, System: true,
			EvidenceSelector: []string{"synchronized"},
		},
		{
			ID: "database.process.presence", Version: 1, Name: "Required database process", Category: "database", ScopeType: ScopeHost, SourceType: SourceMetadata, System: true,
			EvidenceSelector: []string{"required_process_count"},
		},
		{
			ID: "host.log.error_summary", Version: 1, Name: "Error log summary", Category: "host", ScopeType: ScopeHost, SourceType: SourceLogSummary, System: true,
			EvidenceSelector: []string{"warning_count", "error_count", "critical_count"},
		},
	}
	return cloneItems(items)
}

func cloneItems(items []Item) []Item {
	result := make([]Item, len(items))
	for index, item := range items {
		result[index] = item
		result[index].EvidenceSelector = append([]string(nil), item.EvidenceSelector...)
		result[index].RequiredCapabilities = append([]string(nil), item.RequiredCapabilities...)
		if item.MetricRule != nil {
			rule := *item.MetricRule
			rule.Labels = make(map[string]string, len(item.MetricRule.Labels))
			for key, value := range item.MetricRule.Labels {
				rule.Labels[key] = value
			}
			result[index].MetricRule = &rule
		}
	}
	return result
}
