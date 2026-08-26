package database

import "testing"

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
			name: "RegionServer backlog with ZooKeeper pressure",
			role: "regionserver",
			samples: []MetricSample{
				sample("hbase-prod", HBaseComponent, "regionserver", "hbase.flush.queue_length", 101),
				sample("zk-prod", ZooKeeperComponent, "leader", "zookeeper.outstanding_requests", 101),
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
		componentDefinition("hdfs-prod", HDFSComponent, "namenode"),
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
