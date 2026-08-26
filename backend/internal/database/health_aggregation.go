package database

import (
	"sort"
	"strings"
	"time"
)

// HealthState separates a local component failure from a failure in an
// authorized dependency, and from insufficient collection data.
type HealthState string

const (
	HealthHealthy           HealthState = "healthy"
	HealthComponentFailure  HealthState = "component_failure"
	HealthDependencyFailure HealthState = "dependency_failure"
	HealthDataIncomplete    HealthState = "data_incomplete"
)

const (
	writeLatencyThresholdMS       = 1000.0
	requestBacklogThreshold       = 100.0
	diskPressureRatio             = 0.90
	zooKeeperOutstandingThreshold = 100.0
	zooKeeperLatencyThresholdMS   = 1000.0
)

// ComponentHealth is a role-and-host-level, deterministic health result. State always
// describes the closest known cause: the component itself, an authorized
// dependency, or incomplete collection data.
type ComponentHealth struct {
	Cluster    string
	Component  ComponentKind
	Role       string
	State      HealthState
	Host       string
	SampleTime time.Time
}

// EvidenceRule identifies one read-only, correlation-only dependency rule.
type EvidenceRule string

const (
	EvidenceHBaseWriteLatencyHDFS        EvidenceRule = "hbase_write_latency_hdfs_dependency"
	EvidenceRegionServerBacklogZooKeeper EvidenceRule = "regionserver_backlog_zookeeper_dependency"
	EvidenceHDFSWALFlushRisk             EvidenceRule = "hdfs_replication_capacity_hbase_wal_flush_risk"
	EvidenceZooKeeperFailoverRisk        EvidenceRule = "zookeeper_regionserver_failover_risk"
)

// DependencyEvidence records correlation only. It contains no command,
// credentials, or remediation action.
type DependencyEvidence struct {
	Rule                 EvidenceRule
	State                HealthState
	DedupKey             string
	Cluster              string
	Component            ComponentKind
	Role                 string
	DependencyCluster    string
	Host                 string
	SampleTime           time.Time
	DependencyHost       string
	DependencySampleTime time.Time
}

// AggregateHealth computes component-local health before propagating
// authorized dependency failures to HBase. Unknown, missing, or uncollected
// samples become data_incomplete rather than a component failure.
func AggregateHealth(topology Topology, samples []MetricSample, statuses ...ComponentCollectionStatus) []ComponentHealth {
	byCluster := samplesByAuthorizedComponent(topology, samples)
	incomplete := incompleteHealthScopes(topology, statuses)
	health := make([]ComponentHealth, 0)
	for _, node := range topology.nodes {
		for _, scope := range componentHealthScopes(node, byCluster[node.ID], incomplete[node.ID]) {
			local := samplesForHealthScope(byCluster[node.ID][scope.role], scope.host)
			state, dimensions := localHealthDetails(node.Kind, scope.role, local)
			if incomplete[node.ID][scope] && state != HealthComponentFailure {
				state = HealthDataIncomplete
			}
			_, sampleTime := sampleDimensions(dimensions)
			health = append(health, ComponentHealth{Cluster: node.ID, Component: node.Kind, Role: scope.role, State: state, Host: scope.host, SampleTime: sampleTime})
		}
	}

	for index := range health {
		current := &health[index]
		if current.Component != HBaseComponent || current.State == HealthComponentFailure {
			continue
		}
		dependencyFailure, dependencyIncomplete := false, false
		for _, kind := range []ComponentKind{HDFSComponent, ZooKeeperComponent} {
			dependencyID, exists := topology.dependencyID(current.Cluster, kind)
			if !exists {
				dependencyIncomplete = true
				continue
			}
			state := aggregateComponentState(health, dependencyID, kind)
			if state == HealthComponentFailure || state == HealthDependencyFailure {
				dependencyFailure = true
			}
			if state == HealthDataIncomplete || state == "" {
				dependencyIncomplete = true
			}
		}
		if dependencyFailure {
			current.State = HealthDependencyFailure
		} else if current.State == HealthDataIncomplete || dependencyIncomplete {
			current.State = HealthDataIncomplete
		}
	}

	sort.Slice(health, func(i, j int) bool {
		if health[i].Cluster != health[j].Cluster {
			return health[i].Cluster < health[j].Cluster
		}
		if health[i].Component != health[j].Component {
			return health[i].Component < health[j].Component
		}
		if health[i].Role != health[j].Role {
			return health[i].Role < health[j].Role
		}
		return health[i].Host < health[j].Host
	})
	return health
}

type healthScope struct {
	role string
	host string
}

func incompleteHealthScopes(topology Topology, statuses []ComponentCollectionStatus) map[string]map[healthScope]bool {
	result := make(map[string]map[healthScope]bool, len(topology.nodes))
	for _, node := range topology.nodes {
		result[node.ID] = make(map[healthScope]bool)
	}
	for _, status := range statuses {
		node, exists := topology.node(status.Cluster)
		if !exists || status.Component != node.Kind {
			continue
		}
		for _, endpoint := range status.IncompleteEndpoints {
			role, err := canonicalHealthRole(node.Kind, endpoint.Role)
			if err == nil {
				result[node.ID][healthScope{role: role, host: endpoint.Host}] = true
			}
		}
		if status.State == "failed" && len(status.IncompleteEndpoints) == 0 {
			roles := node.Roles
			if node.Kind == ZooKeeperComponent || len(roles) == 0 {
				roles = []string{"unknown"}
			}
			for _, role := range roles {
				result[node.ID][healthScope{role: role}] = true
			}
		}
	}
	return result
}

func componentHealthScopes(node TopologyNode, roles map[string][]MetricSample, incomplete map[healthScope]bool) []healthScope {
	set := make(map[healthScope]struct{})
	for role, samples := range roles {
		for _, sample := range samples {
			set[healthScope{role: role, host: sample.Host}] = struct{}{}
		}
	}
	for scope := range incomplete {
		set[scope] = struct{}{}
	}
	if node.Kind == ZooKeeperComponent {
		if len(set) == 0 {
			set[healthScope{role: "unknown"}] = struct{}{}
		}
	} else {
		for _, role := range node.Roles {
			found := false
			for scope := range set {
				if scope.role == role {
					found = true
					break
				}
			}
			if !found {
				set[healthScope{role: role}] = struct{}{}
			}
		}
	}
	result := make([]healthScope, 0, len(set))
	for scope := range set {
		result = append(result, scope)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].role != result[j].role {
			return result[i].role < result[j].role
		}
		return result[i].host < result[j].host
	})
	return result
}

func samplesForHealthScope(samples []MetricSample, host string) []MetricSample {
	result := make([]MetricSample, 0)
	for _, sample := range samples {
		if sample.Host == host {
			result = append(result, sample)
		}
	}
	return result
}

// BuildDependencyEvidence evaluates the four initial correlation rules using
// authorized topology and normalized metrics. It never performs remediation.
func BuildDependencyEvidence(topology Topology, samples []MetricSample) []DependencyEvidence {
	byCluster := samplesByAuthorizedComponent(topology, samples)
	evidence := make(map[string]DependencyEvidence)
	for _, node := range topology.nodes {
		if node.Kind != HBaseComponent {
			continue
		}
		hdfsID, hasHDFS := topology.dependencyID(node.ID, HDFSComponent)
		zooKeeperID, hasZooKeeper := topology.dependencyID(node.ID, ZooKeeperComponent)
		roles := node.Roles
		if len(roles) == 0 {
			continue
		}

		if hasHDFS && hdfsDataNodeDiskOrIOPressure(byCluster[hdfsID]) {
			for _, role := range roles {
				writeSamples := elevatedWriteLatencySamples(byCluster[node.ID][role])
				if len(writeSamples) != 0 {
					addEvidence(evidence, node.ID, role, EvidenceHBaseWriteLatencyHDFS, hdfsID, writeSamples, hdfsDataNodePressureSamples(byCluster[hdfsID]))
				}
			}
		}
		if hasZooKeeper && zooKeeperBacklogRisk(byCluster[zooKeeperID]) {
			for _, role := range roles {
				backlog := requestBacklogSamples(byCluster[node.ID][role])
				if role == hbaseRoleRegionServer && len(backlog) != 0 {
					addEvidence(evidence, node.ID, role, EvidenceRegionServerBacklogZooKeeper, zooKeeperID, backlog, zooKeeperBacklogSamples(byCluster[zooKeeperID]))
				}
			}
		}
		if hasHDFS {
			walFlushRisk := hdfsWALFlushRiskSamples(byCluster[hdfsID])
			if len(walFlushRisk) != 0 {
				for _, role := range roles {
					addEvidence(evidence, node.ID, role, EvidenceHDFSWALFlushRisk, hdfsID, nil, walFlushRisk)
				}
			}
		}
		if hasZooKeeper {
			failoverRisk := zooKeeperFailoverSamples(byCluster[zooKeeperID])
			if len(failoverRisk) != 0 {
				for _, role := range roles {
					if role == hbaseRoleRegionServer {
						addEvidence(evidence, node.ID, role, EvidenceZooKeeperFailoverRisk, zooKeeperID, nil, failoverRisk)
					}
				}
			}
		}
	}

	result := make([]DependencyEvidence, 0, len(evidence))
	for _, value := range evidence {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].DedupKey < result[j].DedupKey })
	return result
}

func addEvidence(records map[string]DependencyEvidence, cluster, role string, rule EvidenceRule, dependency string, componentSamples, dependencySamples []MetricSample) {
	key := strings.Join([]string{cluster, string(HBaseComponent), role, string(rule)}, "/")
	host, sampleTime := sampleDimensions(componentSamples)
	dependencyHost, dependencySampleTime := sampleDimensions(dependencySamples)
	records[key] = DependencyEvidence{Rule: rule, State: HealthDependencyFailure, DedupKey: key, Cluster: cluster, Component: HBaseComponent, Role: role, DependencyCluster: dependency, Host: host, SampleTime: sampleTime, DependencyHost: dependencyHost, DependencySampleTime: dependencySampleTime}
}

func samplesByAuthorizedComponent(topology Topology, samples []MetricSample) map[string]map[string][]MetricSample {
	result := make(map[string]map[string][]MetricSample, len(topology.nodes))
	for _, node := range topology.nodes {
		result[node.ID] = make(map[string][]MetricSample)
	}
	for _, sample := range samples {
		node, exists := topology.node(sample.Cluster)
		if !exists || sample.Component != string(node.Kind) {
			continue
		}
		role, err := canonicalHealthRole(node.Kind, sample.Role)
		if err != nil || (node.Kind != ZooKeeperComponent && !nodeHasRole(node, role)) {
			continue
		}
		result[node.ID][role] = append(result[node.ID][role], sample)
	}
	return result
}

func canonicalHealthRole(kind ComponentKind, role string) (string, error) {
	if kind == ZooKeeperComponent && strings.EqualFold(strings.TrimSpace(role), "unknown") {
		return "unknown", nil
	}
	return canonicalComponentRole(kind, role)
}

func aggregateComponentState(values []ComponentHealth, cluster string, kind ComponentKind) HealthState {
	state := HealthHealthy
	found := false
	for _, value := range values {
		if value.Cluster != cluster || value.Component != kind {
			continue
		}
		found = true
		if value.State == HealthComponentFailure || value.State == HealthDependencyFailure {
			return value.State
		}
		if value.State == HealthDataIncomplete {
			state = HealthDataIncomplete
		}
	}
	if !found {
		return HealthDataIncomplete
	}
	return state
}

func localHealth(kind ComponentKind, role string, samples []MetricSample) HealthState {
	state, _ := localHealthDetails(kind, role, samples)
	return state
}

func localHealthDetails(kind ComponentKind, role string, samples []MetricSample) (HealthState, []MetricSample) {
	if !hasRequiredHealthInputs(kind, role, samples) {
		return HealthDataIncomplete, samples
	}
	switch kind {
	case HBaseComponent:
		if triggers := metricSamplesGreaterThan(samples, "hbase.master.dead_region_servers", 0); len(triggers) != 0 {
			return HealthComponentFailure, triggers
		}
	case HDFSComponent:
		triggers := make([]MetricSample, 0)
		for _, name := range []string{"hdfs.namenode.missing_blocks", "hdfs.namenode.corrupt_files", "hdfs.datanode.failed_volumes"} {
			triggers = append(triggers, metricSamplesGreaterThan(samples, name, 0)...)
		}
		triggers = append(triggers, capacityPressureSamples(samples, "hdfs.namenode.capacity_used", "hdfs.namenode.capacity_total")...)
		if len(triggers) != 0 {
			return HealthComponentFailure, triggers
		}
	case ZooKeeperComponent:
		triggers := append(zooKeeperBacklogSamples(map[string][]MetricSample{"role": samples}), zooKeeperFailoverSamples(map[string][]MetricSample{"role": samples})...)
		if len(triggers) != 0 {
			return HealthComponentFailure, triggers
		}
	}
	return HealthHealthy, samples
}

func metricGreaterThan(samples []MetricSample, name string, threshold float64) bool {
	return len(metricSamplesGreaterThan(samples, name, threshold)) != 0
}

func metricSamplesGreaterThan(samples []MetricSample, name string, threshold float64) []MetricSample {
	result := make([]MetricSample, 0)
	for _, sample := range samples {
		if sample.MetricName == name && sample.Value > threshold {
			result = append(result, sample)
		}
	}
	return result
}

func hasElevatedWriteLatency(samples []MetricSample) bool {
	return len(elevatedWriteLatencySamples(samples)) != 0
}

func elevatedWriteLatencySamples(samples []MetricSample) []MetricSample {
	result := make([]MetricSample, 0)
	for _, name := range []string{"hbase.wal.append_time", "hbase.wal.sync_time", "hbase.request.total_time"} {
		for _, sample := range samples {
			if sample.MetricName == name && sample.Value > writeLatencyThresholdMS {
				result = append(result, sample)
			}
		}
	}
	return result
}

func hasRequestBacklog(samples []MetricSample) bool {
	return len(requestBacklogSamples(samples)) != 0
}

func requestBacklogSamples(samples []MetricSample) []MetricSample {
	result := make([]MetricSample, 0)
	for _, sample := range samples {
		if (sample.MetricName == "hbase.flush.queue_length" || sample.MetricName == "hbase.compaction.queue_length") && sample.Value > requestBacklogThreshold || sample.MetricName == "hbase.request.queue_time" && sample.Value > writeLatencyThresholdMS {
			result = append(result, sample)
		}
	}
	return result
}

func hdfsDataNodeDiskOrIOPressure(roles map[string][]MetricSample) bool {
	return len(hdfsDataNodePressureSamples(roles)) != 0
}

func hdfsDataNodePressureSamples(roles map[string][]MetricSample) []MetricSample {
	result := make([]MetricSample, 0)
	for role, samples := range roles {
		if role != hdfsRoleDataNode {
			continue
		}
		for _, sample := range samples {
			if (sample.MetricName == "hdfs.datanode.failed_volumes" && sample.Value > 0) || (sample.MetricName == "hdfs.datanode.xceiver_count" && sample.Value > requestBacklogThreshold) {
				result = append(result, sample)
			}
		}
		if capacityPressure(samples, "hdfs.datanode.used", "hdfs.datanode.capacity") {
			result = append(result, capacityPressureSamples(samples, "hdfs.datanode.used", "hdfs.datanode.capacity")...)
		}
	}
	return result
}

func hdfsWALFlushRisk(roles map[string][]MetricSample) bool {
	return len(hdfsWALFlushRiskSamples(roles)) != 0
}

func hdfsWALFlushRiskSamples(roles map[string][]MetricSample) []MetricSample {
	result := make([]MetricSample, 0)
	for role, samples := range roles {
		if role != hdfsRoleNameNode {
			continue
		}
		for _, sample := range samples {
			if (sample.MetricName == "hdfs.namenode.under_replicated_blocks" || sample.MetricName == "hdfs.namenode.missing_blocks" || sample.MetricName == "hdfs.namenode.corrupt_files") && sample.Value > 0 {
				result = append(result, sample)
			}
		}
		if capacityPressure(samples, "hdfs.namenode.capacity_used", "hdfs.namenode.capacity_total") {
			result = append(result, capacityPressureSamples(samples, "hdfs.namenode.capacity_used", "hdfs.namenode.capacity_total")...)
		}
	}
	return result
}

func zooKeeperBacklogRisk(roles map[string][]MetricSample) bool {
	return len(zooKeeperBacklogSamples(roles)) != 0
}

func zooKeeperBacklogSamples(roles map[string][]MetricSample) []MetricSample {
	result := make([]MetricSample, 0)
	for _, samples := range roles {
		for _, sample := range samples {
			if (sample.MetricName == "zookeeper.sessions" && sample.Value <= 0) || (sample.MetricName == "zookeeper.quorum.members" && sample.Value <= 1) {
				result = append(result, sample)
			}
		}
	}
	return result
}

func zooKeeperFailoverRisk(roles map[string][]MetricSample) bool {
	return len(zooKeeperFailoverSamples(roles)) != 0
}

func zooKeeperFailoverSamples(roles map[string][]MetricSample) []MetricSample {
	result := make([]MetricSample, 0)
	for _, samples := range roles {
		for _, sample := range samples {
			switch sample.MetricName {
			case "zookeeper.sessions":
				if sample.Value <= 0 {
					result = append(result, sample)
				}
			case "zookeeper.outstanding_requests":
				if sample.Value > zooKeeperOutstandingThreshold {
					result = append(result, sample)
				}
			case "zookeeper.transaction_log.sync_time":
				if sample.Value > zooKeeperLatencyThresholdMS {
					result = append(result, sample)
				}
			}
		}
	}
	return result
}

func zooKeeperComponentFailure(roles map[string][]MetricSample) bool {
	return zooKeeperBacklogRisk(roles) || zooKeeperFailoverRisk(roles)
}

func hasRequiredHealthInputs(kind ComponentKind, role string, samples []MetricSample) bool {
	switch kind {
	case HBaseComponent:
		return hasAnyMetric(samples, hbaseHealthMetricNames)
	case HDFSComponent:
		if role == hdfsRoleNameNode {
			return hasAnyMetric(samples, hdfsNameNodeHealthMetricNames) || hasMetricPair(samples, "hdfs.namenode.capacity_used", "hdfs.namenode.capacity_total")
		}
		if role == hdfsRoleDataNode {
			return hasAnyMetric(samples, hdfsDataNodeHealthMetricNames) || hasMetricPair(samples, "hdfs.datanode.used", "hdfs.datanode.capacity")
		}
	case ZooKeeperComponent:
		return role != "unknown" && hasAnyMetric(samples, zooKeeperHealthMetricNames)
	}
	return false
}

var hbaseHealthMetricNames = map[string]struct{}{
	"hbase.master.dead_region_servers": {}, "hbase.request.queue_time": {}, "hbase.request.processing_time": {}, "hbase.request.total_time": {}, "hbase.request.open_connections": {}, "hbase.wal.append_time": {}, "hbase.wal.sync_time": {}, "hbase.wal.slow_appends": {}, "hbase.flush.queue_length": {}, "hbase.flush.time": {}, "hbase.flush.count": {}, "hbase.compaction.queue_length": {}, "hbase.compaction.time": {}, "hbase.compaction.count": {},
}

var hdfsNameNodeHealthMetricNames = map[string]struct{}{
	"hdfs.namenode.under_replicated_blocks": {}, "hdfs.namenode.missing_blocks": {}, "hdfs.namenode.corrupt_files": {},
}

var hdfsDataNodeHealthMetricNames = map[string]struct{}{
	"hdfs.datanode.failed_volumes": {}, "hdfs.datanode.xceiver_count": {},
}

var zooKeeperHealthMetricNames = map[string]struct{}{
	"zookeeper.sessions": {}, "zookeeper.quorum.members": {}, "zookeeper.outstanding_requests": {}, "zookeeper.transaction_log.sync_time": {},
}

func hasAnyMetric(samples []MetricSample, allowed map[string]struct{}) bool {
	for _, sample := range samples {
		if _, exists := allowed[sample.MetricName]; exists {
			return true
		}
	}
	return false
}

func hasMetricPair(samples []MetricSample, first, second string) bool {
	firstFound, secondFound := false, false
	for _, sample := range samples {
		if sample.MetricName == first {
			firstFound = true
		}
		if sample.MetricName == second {
			secondFound = true
		}
	}
	return firstFound && secondFound
}

func nodeHasRole(node TopologyNode, role string) bool {
	for _, declared := range node.Roles {
		if declared == role {
			return true
		}
	}
	return false
}

func flattenSamples(roles map[string][]MetricSample) []MetricSample {
	result := make([]MetricSample, 0)
	for _, samples := range roles {
		result = append(result, samples...)
	}
	sort.Slice(result, func(i, j int) bool { return metricSampleLess(result[i], result[j]) })
	return result
}

func sampleDimensions(samples []MetricSample) (string, time.Time) {
	var selected MetricSample
	for _, sample := range samples {
		if selected.Timestamp.IsZero() || sample.Timestamp.After(selected.Timestamp) || (sample.Timestamp.Equal(selected.Timestamp) && metricSampleLess(sample, selected)) {
			selected = sample
		}
	}
	return selected.Host, selected.Timestamp
}

func metricSampleLess(left, right MetricSample) bool {
	if !left.Timestamp.Equal(right.Timestamp) {
		return left.Timestamp.Before(right.Timestamp)
	}
	if left.Host != right.Host {
		return left.Host < right.Host
	}
	if left.Instance != right.Instance {
		return left.Instance < right.Instance
	}
	if left.MetricName != right.MetricName {
		return left.MetricName < right.MetricName
	}
	return left.Value < right.Value
}

func capacityPressure(samples []MetricSample, usedName, totalName string) bool {
	return len(capacityPressureSamples(samples, usedName, totalName)) != 0
}

func capacityPressureSamples(samples []MetricSample, usedName, totalName string) []MetricSample {
	type capacityPair struct {
		used, total       MetricSample
		hasUsed, hasTotal bool
	}
	pairs := make(map[string]capacityPair)
	for _, sample := range samples {
		key := sample.Host + "\x00" + sample.Instance + "\x00" + sample.Timestamp.UTC().Format(time.RFC3339Nano)
		pair := pairs[key]
		switch sample.MetricName {
		case usedName:
			pair.used, pair.hasUsed = sample, true
		case totalName:
			pair.total, pair.hasTotal = sample, true
		}
		pairs[key] = pair
	}
	result := make([]MetricSample, 0)
	for _, pair := range pairs {
		if pair.hasUsed && pair.hasTotal && pair.total.Value > 0 && pair.used.Value/pair.total.Value >= diskPressureRatio {
			result = append(result, pair.used, pair.total)
		}
	}
	sort.Slice(result, func(i, j int) bool { return metricSampleLess(result[i], result[j]) })
	return result
}
