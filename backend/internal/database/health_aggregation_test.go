package database

import (
	"testing"
	"time"
)

func TestAggregateHealthMarksHBaseDependencySamplesIncomplete(t *testing.T) {
	topology := mustTopology(t, "master")
	health := AggregateHealth(topology, []MetricSample{
		sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 25),
	})

	got, ok := findHealth(health, "hbase-prod", HBaseComponent, "master")
	if !ok {
		t.Fatalf("AggregateHealth() = %#v, missing HBase master", health)
	}
	if got.State != HealthDataIncomplete {
		t.Fatalf("HBase master state = %q, want %q", got.State, HealthDataIncomplete)
	}
}

func TestAggregateHealthPreservesComponentAndDependencyFailureBoundaries(t *testing.T) {
	topology := mustTopology(t, "master")
	health := AggregateHealth(topology, []MetricSample{
		sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 25),
		sample("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.missing_blocks", 1),
		sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 5),
	})

	hdfs, ok := findHealth(health, "hdfs-prod", HDFSComponent, "namenode")
	if !ok || hdfs.State != HealthComponentFailure {
		t.Fatalf("HDFS health = %#v, want component_failure", hdfs)
	}
	hbase, ok := findHealth(health, "hbase-prod", HBaseComponent, "master")
	if !ok || hbase.State != HealthDependencyFailure {
		t.Fatalf("HBase health = %#v, want dependency_failure", hbase)
	}
}

func TestAggregateHealthMarksUnrelatedSamplesIncompleteAndRejectsUndeclaredRoles(t *testing.T) {
	topology := mustTopology(t, "master")
	health := AggregateHealth(topology, []MetricSample{
		sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 25),
		sample("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.files", 100),
		sample("hdfs-prod", HDFSComponent, "worker", "hdfs.namenode.missing_blocks", 1),
		sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 5),
	})

	hdfs, ok := findHealth(health, "hdfs-prod", HDFSComponent, "namenode")
	if !ok || hdfs.State != HealthDataIncomplete {
		t.Fatalf("HDFS health = %#v, want data_incomplete when required inputs are absent", hdfs)
	}
	hbase, ok := findHealth(health, "hbase-prod", HBaseComponent, "master")
	if !ok || hbase.State != HealthDataIncomplete {
		t.Fatalf("HBase health = %#v, want data_incomplete when dependency inputs are absent", hbase)
	}
}

func TestAggregateHealthRequiresExactMetricInputsAndCompleteCapacityPairs(t *testing.T) {
	for _, test := range []struct {
		name    string
		samples []MetricSample
		cluster string
		kind    ComponentKind
		role    string
	}{
		{
			name: "unknown HBase request metric is incomplete",
			samples: []MetricSample{
				sample("hbase-prod", HBaseComponent, "master", "hbase.request.unknown", 1),
				sample("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.missing_blocks", 0),
				sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 1),
			},
			cluster: "hbase-prod", kind: HBaseComponent, role: "master",
		},
		{
			name: "unknown DataNode I/O metric is incomplete",
			samples: []MetricSample{
				sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 1),
				sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.io.unknown", 1),
				sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 1),
			},
			cluster: "hdfs-prod", kind: HDFSComponent, role: "datanode",
		},
		{
			name: "partial NameNode capacity pair is incomplete",
			samples: []MetricSample{
				sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 1),
				sample("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.capacity_used", 90),
				sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 1),
			},
			cluster: "hdfs-prod", kind: HDFSComponent, role: "namenode",
		},
		{
			name: "partial DataNode capacity pair is incomplete",
			samples: []MetricSample{
				sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 1),
				sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.capacity", 100),
				sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 1),
			},
			cluster: "hdfs-prod", kind: HDFSComponent, role: "datanode",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := findHealth(AggregateHealth(mustTopology(t, "master"), test.samples), test.cluster, test.kind, test.role)
			if !ok || got.State != HealthDataIncomplete {
				t.Fatalf("health = %#v, want data_incomplete", got)
			}
		})
	}
}

func TestBuildDependencyEvidenceDeduplicatesAlertKeys(t *testing.T) {
	topology := mustTopology(t, "master")
	evidence := BuildDependencyEvidence(topology, []MetricSample{
		sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 2000),
		sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 3000),
		sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.capacity", 100),
		sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.used", 95),
		sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 4),
	})

	if len(evidence) != 1 {
		t.Fatalf("evidence = %#v, want one deduplicated record", evidence)
	}
	got := evidence[0]
	if got.Rule != EvidenceHBaseWriteLatencyHDFS || got.DedupKey != "hbase-prod/hbase/master/hbase_write_latency_hdfs_dependency" {
		t.Fatalf("evidence = %#v, want stable cluster/component/role/rule key", got)
	}
}

func TestBuildDependencyEvidenceUsesDataNodeIOAndPreservesDimensions(t *testing.T) {
	topology := mustTopology(t, "master")
	stamp := testTimestamp()
	write := sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 2000)
	write.Host, write.Timestamp = "hbase-1", stamp
	io := sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.io.bytes_written", dataNodeIOPressureBytes+1)
	io.Host, io.Timestamp = "datanode-1", stamp.Add(1)
	evidence := BuildDependencyEvidence(topology, []MetricSample{write, io})
	if len(evidence) != 1 || evidence[0].Rule != EvidenceHBaseWriteLatencyHDFS {
		t.Fatalf("BuildDependencyEvidence() = %#v, want DataNode I/O evidence", evidence)
	}
	if evidence[0].Host != "hbase-1" || evidence[0].SampleTime != stamp || evidence[0].DependencyHost != "datanode-1" || evidence[0].DependencySampleTime != stamp.Add(1) {
		t.Fatalf("evidence dimensions = %#v, want component and dependency host/sample time", evidence[0])
	}
}

func TestBuildDependencyEvidenceUsesTriggerDimensionsDeterministically(t *testing.T) {
	topology := mustTopology(t, "master")
	write := sample("hbase-prod", HBaseComponent, "master", "hbase.wal.sync_time", 2000)
	write.Host, write.Timestamp = "trigger-hbase", testTimestamp()
	unrelatedHBase := sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 1)
	unrelatedHBase.Host, unrelatedHBase.Timestamp = "later-hbase", testTimestamp().Add(time.Hour)
	io := sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.io.bytes_read", dataNodeIOPressureBytes+1)
	io.Host, io.Timestamp = "trigger-datanode", testTimestamp()
	unrelatedHDFS := sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.xceiver_count", 1)
	unrelatedHDFS.Host, unrelatedHDFS.Timestamp = "later-datanode", testTimestamp().Add(time.Hour)

	evidence := BuildDependencyEvidence(topology, []MetricSample{unrelatedHDFS, unrelatedHBase, io, write})
	if len(evidence) != 1 || evidence[0].Host != "trigger-hbase" || evidence[0].DependencyHost != "trigger-datanode" || evidence[0].SampleTime != testTimestamp() || evidence[0].DependencySampleTime != testTimestamp() {
		t.Fatalf("BuildDependencyEvidence() = %#v, want deterministic triggering dimensions", evidence)
	}
}

func TestBuildDependencyEvidenceRejectsUnknownDataNodeIO(t *testing.T) {
	evidence := BuildDependencyEvidence(mustTopology(t, "master"), []MetricSample{
		sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 2000),
		sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.io.unknown", dataNodeIOPressureBytes+1),
	})
	if hasRule(evidence, EvidenceHBaseWriteLatencyHDFS) {
		t.Fatalf("BuildDependencyEvidence() = %#v, must ignore unknown DataNode I/O metrics", evidence)
	}
}

func TestBuildDependencyEvidenceRejectsUndeclaredDependencyRole(t *testing.T) {
	topology := mustTopology(t, "master")
	evidence := BuildDependencyEvidence(topology, []MetricSample{
		sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 2000),
		sample("hdfs-prod", HDFSComponent, "worker", "hdfs.datanode.io.bytes_written", dataNodeIOPressureBytes+1),
	})
	if hasRule(evidence, EvidenceHBaseWriteLatencyHDFS) {
		t.Fatalf("BuildDependencyEvidence() = %#v, must reject samples from undeclared roles", evidence)
	}
}

func TestBuildDependencyEvidenceSeparatesZooKeeperRuleInputs(t *testing.T) {
	topology := mustTopology(t, "regionserver")
	backlog := sample("hbase-prod", HBaseComponent, "regionserver", "hbase.flush.queue_length", 101)

	for _, test := range []struct {
		name    string
		samples []MetricSample
		absent  EvidenceRule
		present EvidenceRule
	}{
		{
			name:    "outstanding requests are only failover evidence",
			samples: []MetricSample{backlog, sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.outstanding_requests", 101)},
			absent:  EvidenceRegionServerBacklogZooKeeper,
			present: EvidenceZooKeeperFailoverRisk,
		},
		{
			name:    "quorum is only backlog evidence",
			samples: []MetricSample{backlog, sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.quorum.members", 1)},
			absent:  EvidenceZooKeeperFailoverRisk,
			present: EvidenceRegionServerBacklogZooKeeper,
		},
		{
			name:    "request latency is neither initial ZooKeeper evidence rule",
			samples: []MetricSample{backlog, sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.request.latency", 2000)},
			absent:  EvidenceRegionServerBacklogZooKeeper,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := BuildDependencyEvidence(topology, test.samples)
			if hasRule(evidence, test.absent) {
				t.Fatalf("BuildDependencyEvidence() = %#v, unexpectedly emitted %q", evidence, test.absent)
			}
			if test.present != "" && !hasRule(evidence, test.present) {
				t.Fatalf("BuildDependencyEvidence() = %#v, want %q", evidence, test.present)
			}
		})
	}
}

func TestBuildDependencyEvidenceAppliesInitialDependencyRules(t *testing.T) {
	for _, test := range []struct {
		name    string
		role    string
		samples []MetricSample
		rule    EvidenceRule
	}{
		{
			name: "hbase write latency with HDFS DataNode disk pressure",
			role: "master",
			samples: []MetricSample{
				sample("hbase-prod", HBaseComponent, "master", "hbase.wal.sync_time", 1500),
				sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.capacity", 100),
				sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.used", 95),
			},
			rule: EvidenceHBaseWriteLatencyHDFS,
		},
		{
			name: "RegionServer backlog with ZooKeeper session or quorum anomaly",
			role: "regionserver",
			samples: []MetricSample{
				sample("hbase-prod", HBaseComponent, "regionserver", "hbase.flush.queue_length", 101),
				sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.quorum.members", 1),
			},
			rule: EvidenceRegionServerBacklogZooKeeper,
		},
		{
			name: "HDFS replication risk threatens HBase WAL and flush",
			role: "master",
			samples: []MetricSample{
				sample("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.under_replicated_blocks", 1),
			},
			rule: EvidenceHDFSWALFlushRisk,
		},
		{
			name: "ZooKeeper failure risk threatens RegionServer failover",
			role: "regionserver",
			samples: []MetricSample{
				sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 0),
			},
			rule: EvidenceZooKeeperFailoverRisk,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			evidence := BuildDependencyEvidence(mustTopology(t, test.role), test.samples)
			if !hasRule(evidence, test.rule) {
				t.Fatalf("BuildDependencyEvidence() = %#v, want rule %q", evidence, test.rule)
			}
		})
	}
}

func mustTopology(t *testing.T, hbaseRole string) Topology {
	t.Helper()
	definitions := []ComponentDefinition{
		{ID: "hdfs-prod", Kind: HDFSComponent, SecretRef: "secret://runtime/hdfs-prod", Endpoints: []Endpoint{{URL: "https://hdfs.example.test/jmx", Role: "namenode"}, {URL: "https://datanode.example.test/jmx", Role: "datanode"}}},
		componentDefinition("zk-prod", ZooKeeperComponent, "leader"),
		{
			ID:        "hbase-prod",
			Kind:      HBaseComponent,
			SecretRef: "secret://runtime/hbase-prod",
			Endpoints: []Endpoint{{URL: "https://hbase.example.test/jmx", Role: hbaseRole}},
			Dependencies: DependencyRef{
				HDFSClusterID:      "hdfs-prod",
				ZooKeeperClusterID: "zk-prod",
			},
		},
	}
	topology, err := ResolveTopology(definitions)
	if err != nil {
		t.Fatalf("ResolveTopology() error = %v", err)
	}
	return topology
}

func testTimestamp() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func sample(cluster string, component ComponentKind, role, metric string, value float64) MetricSample {
	return MetricSample{Cluster: cluster, Component: string(component), Role: role, MetricName: metric, Value: value}
}

func findHealth(values []ComponentHealth, cluster string, component ComponentKind, role string) (ComponentHealth, bool) {
	for _, value := range values {
		if value.Cluster == cluster && value.Component == component && value.Role == role {
			return value, true
		}
	}
	return ComponentHealth{}, false
}

func hasRule(values []DependencyEvidence, rule EvidenceRule) bool {
	for _, value := range values {
		if value.Rule == rule {
			return true
		}
	}
	return false
}
