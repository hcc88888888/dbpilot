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
	dataNodeIOPressureBytes       = float64(1 << 30)
)

// ComponentHealth is a role-level, deterministic health result. State always
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
func AggregateHealth(topology Topology, samples []MetricSample) []ComponentHealth {
	byCluster := samplesByAuthorizedComponent(topology, samples)
	health := make([]ComponentHealth, 0)
	for _, node := range topology.nodes {
		roles := node.Roles
		if len(roles) == 0 {
			roles = []string{"unknown"}
		}
		for _, role := range roles {
			local := byCluster[node.ID][role]
			host, sampleTime := sampleDimensions(local)
			health = append(health, ComponentHealth{Cluster: node.ID, Component: node.Kind, Role: role, State: localHealth(node.Kind, role, local), Host: host, SampleTime: sampleTime})
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
		return health[i].Role < health[j].Role
	})
	return health
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
				if hasElevatedWriteLatency(byCluster[node.ID][role]) {
					addEvidence(evidence, node.ID, role, EvidenceHBaseWriteLatencyHDFS, hdfsID, byCluster[node.ID][role], flattenSamples(byCluster[hdfsID]))
				}
			}
		}
		if hasZooKeeper && zooKeeperBacklogRisk(byCluster[zooKeeperID]) {
			for _, role := range roles {
				if role == hbaseRoleRegionServer && hasRequestBacklog(byCluster[node.ID][role]) {
					addEvidence(evidence, node.ID, role, EvidenceRegionServerBacklogZooKeeper, zooKeeperID, byCluster[node.ID][role], flattenSamples(byCluster[zooKeeperID]))
				}
			}
		}
		if hasHDFS && hdfsWALFlushRisk(byCluster[hdfsID]) {
			for _, role := range roles {
				addEvidence(evidence, node.ID, role, EvidenceHDFSWALFlushRisk, hdfsID, byCluster[node.ID][role], flattenSamples(byCluster[hdfsID]))
			}
		}
		if hasZooKeeper && zooKeeperFailoverRisk(byCluster[zooKeeperID]) {
			for _, role := range roles {
				if role == hbaseRoleRegionServer {
					addEvidence(evidence, node.ID, role, EvidenceZooKeeperFailoverRisk, zooKeeperID, byCluster[node.ID][role], flattenSamples(byCluster[zooKeeperID]))
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
		role, err := canonicalComponentRole(node.Kind, sample.Role)
		if err != nil || !nodeHasRole(node, role) {
			continue
		}
		result[node.ID][role] = append(result[node.ID][role], sample)
	}
	return result
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
	if !hasRequiredHealthInputs(kind, role, samples) {
		return HealthDataIncomplete
	}
	switch kind {
	case HBaseComponent:
		if metricGreaterThan(samples, "hbase.master.dead_region_servers", 0) {
			return HealthComponentFailure
		}
	case HDFSComponent:
		if metricGreaterThan(samples, "hdfs.namenode.missing_blocks", 0) || metricGreaterThan(samples, "hdfs.namenode.corrupt_files", 0) || metricGreaterThan(samples, "hdfs.datanode.failed_volumes", 0) || capacityPressure(samples, "hdfs.namenode.capacity_used", "hdfs.namenode.capacity_total") {
			return HealthComponentFailure
		}
	case ZooKeeperComponent:
		if zooKeeperComponentFailure(map[string][]MetricSample{"role": samples}) {
			return HealthComponentFailure
		}
	}
	return HealthHealthy
}

func metricGreaterThan(samples []MetricSample, name string, threshold float64) bool {
	for _, sample := range samples {
		if sample.MetricName == name && sample.Value > threshold {
			return true
		}
	}
	return false
}

func hasElevatedWriteLatency(samples []MetricSample) bool {
	for _, name := range []string{"hbase.wal.append_time", "hbase.wal.sync_time", "hbase.request.total_time"} {
		if metricGreaterThan(samples, name, writeLatencyThresholdMS) {
			return true
		}
	}
	return false
}

func hasRequestBacklog(samples []MetricSample) bool {
	return metricGreaterThan(samples, "hbase.flush.queue_length", requestBacklogThreshold) || metricGreaterThan(samples, "hbase.compaction.queue_length", requestBacklogThreshold) || metricGreaterThan(samples, "hbase.request.queue_time", writeLatencyThresholdMS)
}

func hdfsDataNodeDiskOrIOPressure(roles map[string][]MetricSample) bool {
	for role, samples := range roles {
		if role == hdfsRoleDataNode && (metricGreaterThan(samples, "hdfs.datanode.failed_volumes", 0) || capacityPressure(samples, "hdfs.datanode.used", "hdfs.datanode.capacity") || metricGreaterThan(samples, "hdfs.datanode.xceiver_count", requestBacklogThreshold) || metricGreaterThan(samples, "hdfs.datanode.io.bytes_read", dataNodeIOPressureBytes) || metricGreaterThan(samples, "hdfs.datanode.io.bytes_written", dataNodeIOPressureBytes)) {
			return true
		}
	}
	return false
}

func hdfsWALFlushRisk(roles map[string][]MetricSample) bool {
	for role, samples := range roles {
		if role == hdfsRoleNameNode && (metricGreaterThan(samples, "hdfs.namenode.under_replicated_blocks", 0) || metricGreaterThan(samples, "hdfs.namenode.missing_blocks", 0) || metricGreaterThan(samples, "hdfs.namenode.corrupt_files", 0) || capacityPressure(samples, "hdfs.namenode.capacity_used", "hdfs.namenode.capacity_total")) {
			return true
		}
	}
	return false
}

func zooKeeperBacklogRisk(roles map[string][]MetricSample) bool {
	for _, samples := range roles {
		for _, sample := range samples {
			if (sample.MetricName == "zookeeper.sessions" && sample.Value <= 0) || (sample.MetricName == "zookeeper.quorum.members" && sample.Value <= 1) {
				return true
			}
		}
	}
	return false
}

func zooKeeperFailoverRisk(roles map[string][]MetricSample) bool {
	for _, samples := range roles {
		for _, sample := range samples {
			switch sample.MetricName {
			case "zookeeper.sessions":
				if sample.Value <= 0 {
					return true
				}
			case "zookeeper.outstanding_requests":
				if sample.Value > zooKeeperOutstandingThreshold {
					return true
				}
			case "zookeeper.transaction_log.sync_time":
				if sample.Value > zooKeeperLatencyThresholdMS {
					return true
				}
			}
		}
	}
	return false
}

func zooKeeperComponentFailure(roles map[string][]MetricSample) bool {
	return zooKeeperBacklogRisk(roles) || zooKeeperFailoverRisk(roles)
}

func hasRequiredHealthInputs(kind ComponentKind, role string, samples []MetricSample) bool {
	for _, sample := range samples {
		switch kind {
		case HBaseComponent:
			if strings.HasPrefix(sample.MetricName, "hbase.request.") || strings.HasPrefix(sample.MetricName, "hbase.wal.") || strings.HasPrefix(sample.MetricName, "hbase.flush.") || strings.HasPrefix(sample.MetricName, "hbase.compaction.") || sample.MetricName == "hbase.master.dead_region_servers" {
				return true
			}
		case HDFSComponent:
			if role == hdfsRoleNameNode && (sample.MetricName == "hdfs.namenode.under_replicated_blocks" || sample.MetricName == "hdfs.namenode.missing_blocks" || sample.MetricName == "hdfs.namenode.corrupt_files" || sample.MetricName == "hdfs.namenode.capacity_used" || sample.MetricName == "hdfs.namenode.capacity_total") {
				return true
			}
			if role == hdfsRoleDataNode && (sample.MetricName == "hdfs.datanode.failed_volumes" || sample.MetricName == "hdfs.datanode.capacity" || sample.MetricName == "hdfs.datanode.used" || sample.MetricName == "hdfs.datanode.xceiver_count" || strings.HasPrefix(sample.MetricName, "hdfs.datanode.io.")) {
				return true
			}
		case ZooKeeperComponent:
			if sample.MetricName == "zookeeper.sessions" || sample.MetricName == "zookeeper.quorum.members" || sample.MetricName == "zookeeper.outstanding_requests" || sample.MetricName == "zookeeper.transaction_log.sync_time" {
				return true
			}
		}
	}
	return false
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
	return result
}

func sampleDimensions(samples []MetricSample) (string, time.Time) {
	var selected MetricSample
	for _, sample := range samples {
		if selected.Timestamp.IsZero() || sample.Timestamp.After(selected.Timestamp) {
			selected = sample
		}
	}
	return selected.Host, selected.Timestamp
}

func capacityPressure(samples []MetricSample, usedName, totalName string) bool {
	used, total := 0.0, 0.0
	for _, sample := range samples {
		switch sample.MetricName {
		case usedName:
			if sample.Value > used {
				used = sample.Value
			}
		case totalName:
			if sample.Value > total {
				total = sample.Value
			}
		}
	}
	return total > 0 && used/total >= diskPressureRatio
}
