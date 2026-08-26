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

func TestAggregateHealthSeparatesHostsAndUsesFailureTriggerTime(t *testing.T) {
	stamp := testTimestamp()
	topology := mustTopology(t, "master")
	samples := healthyDependencySamples()
	samples = append(samples,
		metricWithDimensions("hbase-prod", HBaseComponent, "master", "hbase.master.dead_region_servers", 1, "master-a", stamp),
		metricWithDimensions("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 1, "master-a", stamp.Add(time.Hour)),
		metricWithDimensions("hbase-prod", HBaseComponent, "master", "hbase.master.dead_region_servers", 0, "master-b", stamp.Add(2*time.Hour)),
	)

	health := AggregateHealth(topology, samples)
	failed, ok := findHealthHost(health, "hbase-prod", HBaseComponent, "master", "master-a")
	if !ok || failed.State != HealthComponentFailure || failed.SampleTime != stamp {
		t.Fatalf("master-a health = %#v, want component_failure at triggering sample time", failed)
	}
	healthy, ok := findHealthHost(health, "hbase-prod", HBaseComponent, "master", "master-b")
	if !ok || healthy.State != HealthHealthy {
		t.Fatalf("master-b health = %#v, want independent healthy host", healthy)
	}
}

func TestAggregateHealthPropagatesPartialEndpointStatus(t *testing.T) {
	stamp := testTimestamp()
	samples := append(healthyDependencySamples(), metricWithDimensions("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 1, "master-a", stamp))
	status := ComponentCollectionStatus{
		Cluster: "hbase-prod", Component: HBaseComponent, State: "partial",
		IncompleteEndpoints: []ComponentEndpointStatus{{Role: "master", Host: "master-b"}},
	}

	health := AggregateHealth(mustTopology(t, "master"), samples, status)
	complete, ok := findHealthHost(health, "hbase-prod", HBaseComponent, "master", "master-a")
	if !ok || complete.State != HealthHealthy {
		t.Fatalf("master-a health = %#v, want healthy independent endpoint", complete)
	}
	incomplete, ok := findHealthHost(health, "hbase-prod", HBaseComponent, "master", "master-b")
	if !ok || incomplete.State != HealthDataIncomplete {
		t.Fatalf("master-b health = %#v, want data_incomplete from partial endpoint status", incomplete)
	}
}

func TestAggregateHealthUsesObservedZooKeeperRoleAndTreatsUnknownAsIncomplete(t *testing.T) {
	topology := mustTopology(t, "master")
	observed := metricWithDimensions("zk-prod", ZooKeeperComponent, "follower", "zookeeper.sessions", 2, "zk-a", testTimestamp())
	health, ok := findHealthHost(AggregateHealth(topology, []MetricSample{observed}), "zk-prod", ZooKeeperComponent, "follower", "zk-a")
	if !ok || health.State != HealthHealthy {
		t.Fatalf("observed follower health = %#v, want healthy follower despite configured leader hint", health)
	}

	unknown := observed
	unknown.Role = "unknown"
	health, ok = findHealthHost(AggregateHealth(topology, []MetricSample{unknown}), "zk-prod", ZooKeeperComponent, "unknown", "zk-a")
	if !ok || health.State != HealthDataIncomplete {
		t.Fatalf("unknown ZooKeeper health = %#v, want data_incomplete", health)
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

func TestBuildDependencyEvidenceRejectsCumulativeDataNodeIOCounters(t *testing.T) {
	topology := mustTopology(t, "master")
	stamp := testTimestamp()
	write := sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 2000)
	write.Host, write.Timestamp = "hbase-1", stamp
	io := sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.io.bytes_written", float64(1<<50))
	io.Host, io.Timestamp = "datanode-1", stamp.Add(1)
	evidence := BuildDependencyEvidence(topology, []MetricSample{write, io})
	if hasRule(evidence, EvidenceHBaseWriteLatencyHDFS) {
		t.Fatalf("BuildDependencyEvidence() = %#v, cumulative byte counters must not imply I/O pressure", evidence)
	}
}

func TestBuildDependencyEvidenceUsesTriggerDimensionsDeterministically(t *testing.T) {
	topology := mustTopology(t, "master")
	write := sample("hbase-prod", HBaseComponent, "master", "hbase.wal.sync_time", 2000)
	write.Host, write.Timestamp = "trigger-hbase", testTimestamp()
	unrelatedHBase := sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 1)
	unrelatedHBase.Host, unrelatedHBase.Timestamp = "later-hbase", testTimestamp().Add(time.Hour)
	io := sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.xceiver_count", requestBacklogThreshold+1)
	io.Host, io.Timestamp = "trigger-datanode", testTimestamp()
	unrelatedHDFS := sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.xceiver_count", 1)
	unrelatedHDFS.Host, unrelatedHDFS.Timestamp = "later-datanode", testTimestamp().Add(time.Hour)

	evidence := BuildDependencyEvidence(topology, []MetricSample{unrelatedHDFS, unrelatedHBase, io, write})
	if len(evidence) != 1 || evidence[0].Host != "trigger-hbase" || evidence[0].DependencyHost != "trigger-datanode" || evidence[0].SampleTime != testTimestamp() || evidence[0].DependencySampleTime != testTimestamp() {
		t.Fatalf("BuildDependencyEvidence() = %#v, want deterministic triggering dimensions", evidence)
	}
}

func TestBuildDependencyEvidenceUsesTriggerDimensionsForRemainingRules(t *testing.T) {
	stamp := testTimestamp()
	for _, test := range []struct {
		name        string
		role        string
		samples     []MetricSample
		rule        EvidenceRule
		wantHost    string
		wantDepHost string
	}{
		{
			name: "ZooKeeper backlog", role: "regionserver", rule: EvidenceRegionServerBacklogZooKeeper, wantHost: "rs-trigger", wantDepHost: "zk-trigger",
			samples: []MetricSample{metricWithDimensions("hbase-prod", HBaseComponent, "regionserver", "hbase.flush.queue_length", 101, "rs-trigger", stamp), metricWithDimensions("hbase-prod", HBaseComponent, "regionserver", "hbase.request.total_time", 1, "rs-later", stamp.Add(time.Hour)), metricWithDimensions("zk-prod", ZooKeeperComponent, "leader", "zookeeper.quorum.members", 1, "zk-trigger", stamp), metricWithDimensions("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 1, "zk-later", stamp.Add(time.Hour))},
		},
		{
			name: "HDFS WAL flush", role: "master", rule: EvidenceHDFSWALFlushRisk, wantHost: "", wantDepHost: "nn-trigger",
			samples: []MetricSample{metricWithDimensions("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.under_replicated_blocks", 1, "nn-trigger", stamp), metricWithDimensions("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.missing_blocks", 0, "nn-later", stamp.Add(time.Hour))},
		},
		{
			name: "ZooKeeper failover", role: "regionserver", rule: EvidenceZooKeeperFailoverRisk, wantHost: "", wantDepHost: "zk-trigger",
			samples: []MetricSample{metricWithDimensions("zk-prod", ZooKeeperComponent, "leader", "zookeeper.outstanding_requests", 101, "zk-trigger", stamp), metricWithDimensions("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 1, "zk-later", stamp.Add(time.Hour))},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, evidence := range BuildDependencyEvidence(mustTopology(t, test.role), test.samples) {
				if evidence.Rule == test.rule {
					if evidence.Host != test.wantHost || evidence.DependencyHost != test.wantDepHost || (test.wantHost != "" && evidence.SampleTime != stamp) || evidence.DependencySampleTime != stamp {
						t.Fatalf("evidence = %#v, want triggering dimensions", evidence)
					}
					return
				}
			}
			t.Fatalf("BuildDependencyEvidence() missing %q", test.rule)
		})
	}
}

func TestBuildDependencyEvidenceDependencyOnlyRulesExcludeUnrelatedHBaseSamples(t *testing.T) {
	stamp := testTimestamp()
	for _, test := range []struct {
		name    string
		role    string
		rule    EvidenceRule
		samples []MetricSample
	}{
		{
			name: "HDFS WAL flush", role: "master", rule: EvidenceHDFSWALFlushRisk,
			samples: []MetricSample{
				metricWithDimensions("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.under_replicated_blocks", 1, "nn-trigger", stamp),
				metricWithDimensions("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 1, "hbase-later", stamp.Add(time.Hour)),
			},
		},
		{
			name: "ZooKeeper failover", role: "regionserver", rule: EvidenceZooKeeperFailoverRisk,
			samples: []MetricSample{
				metricWithDimensions("zk-prod", ZooKeeperComponent, "leader", "zookeeper.outstanding_requests", 101, "zk-trigger", stamp),
				metricWithDimensions("hbase-prod", HBaseComponent, "regionserver", "hbase.request.total_time", 1, "hbase-later", stamp.Add(time.Hour)),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, evidence := range BuildDependencyEvidence(mustTopology(t, test.role), test.samples) {
				if evidence.Rule != test.rule {
					continue
				}
				if evidence.Host != "" || !evidence.SampleTime.IsZero() || evidence.DependencySampleTime != stamp {
					t.Fatalf("evidence = %#v, want only dependency triggering dimensions", evidence)
				}
				return
			}
			t.Fatalf("BuildDependencyEvidence() missing %q", test.rule)
		})
	}
}

func TestBuildDependencyEvidenceCapacityEvidenceUsesTriggerPairDimensions(t *testing.T) {
	stamp := testTimestamp()
	for _, test := range []struct {
		name     string
		role     string
		rule     EvidenceRule
		samples  []MetricSample
		wantHost string
	}{
		{
			name: "DataNode pressure", role: "master", rule: EvidenceHBaseWriteLatencyHDFS, wantHost: "datanode-trigger",
			samples: []MetricSample{
				metricWithDimensions("hbase-prod", HBaseComponent, "master", "hbase.wal.sync_time", 2000, "hbase-trigger", stamp),
				metricWithDimensions("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.used", 95, "datanode-trigger", stamp),
				metricWithDimensions("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.capacity", 100, "datanode-trigger", stamp),
				metricWithDimensions("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.used", 89, "datanode-later", stamp.Add(time.Hour)),
				metricWithDimensions("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.capacity", 100, "datanode-later", stamp.Add(time.Hour)),
			},
		},
		{
			name: "NameNode WAL flush risk", role: "master", rule: EvidenceHDFSWALFlushRisk, wantHost: "namenode-trigger",
			samples: []MetricSample{
				metricWithDimensions("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.capacity_used", 95, "namenode-trigger", stamp),
				metricWithDimensions("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.capacity_total", 100, "namenode-trigger", stamp),
				metricWithDimensions("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.capacity_used", 89, "namenode-later", stamp.Add(time.Hour)),
				metricWithDimensions("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.capacity_total", 100, "namenode-later", stamp.Add(time.Hour)),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, evidence := range BuildDependencyEvidence(mustTopology(t, test.role), test.samples) {
				if evidence.Rule != test.rule {
					continue
				}
				if evidence.DependencyHost != test.wantHost || evidence.DependencySampleTime != stamp {
					t.Fatalf("evidence = %#v, want triggering capacity pair dimensions", evidence)
				}
				return
			}
			t.Fatalf("BuildDependencyEvidence() missing %q", test.rule)
		})
	}
}

func TestCapacityPressureRequiresOneHostInstanceTimestampPair(t *testing.T) {
	stamp := testTimestamp()
	used := metricWithDimensions("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.used", 95, "a", stamp)
	totalDifferentHost := metricWithDimensions("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.capacity", 100, "b", stamp)
	if capacityPressure([]MetricSample{used, totalDifferentHost}, "hdfs.datanode.used", "hdfs.datanode.capacity") {
		t.Fatal("capacityPressure() matched capacity samples from different hosts")
	}
	total := metricWithDimensions("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.capacity", 100, "a", stamp)
	if !capacityPressure([]MetricSample{used, total}, "hdfs.datanode.used", "hdfs.datanode.capacity") {
		t.Fatal("capacityPressure() did not match one host/instance/timestamp pair")
	}
}

func TestBuildDependencyEvidenceRejectsUnknownDataNodeIO(t *testing.T) {
	evidence := BuildDependencyEvidence(mustTopology(t, "master"), []MetricSample{
		sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 2000),
		sample("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.io.unknown", float64(1<<50)),
	})
	if hasRule(evidence, EvidenceHBaseWriteLatencyHDFS) {
		t.Fatalf("BuildDependencyEvidence() = %#v, must ignore unknown DataNode I/O metrics", evidence)
	}
}

func TestBuildDependencyEvidenceRejectsUndeclaredDependencyRole(t *testing.T) {
	topology := mustTopology(t, "master")
	evidence := BuildDependencyEvidence(topology, []MetricSample{
		sample("hbase-prod", HBaseComponent, "master", "hbase.request.total_time", 2000),
		sample("hdfs-prod", HDFSComponent, "worker", "hdfs.datanode.io.bytes_written", float64(1<<50)),
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

func metricWithDimensions(cluster string, component ComponentKind, role, metric string, value float64, host string, timestamp time.Time) MetricSample {
	valueSample := sample(cluster, component, role, metric, value)
	valueSample.Host, valueSample.Timestamp = host, timestamp
	return valueSample
}

func findHealth(values []ComponentHealth, cluster string, component ComponentKind, role string) (ComponentHealth, bool) {
	for _, value := range values {
		if value.Cluster == cluster && value.Component == component && value.Role == role {
			return value, true
		}
	}
	return ComponentHealth{}, false
}

func findHealthHost(values []ComponentHealth, cluster string, component ComponentKind, role, host string) (ComponentHealth, bool) {
	for _, value := range values {
		if value.Cluster == cluster && value.Component == component && value.Role == role && value.Host == host {
			return value, true
		}
	}
	return ComponentHealth{}, false
}

func healthyDependencySamples() []MetricSample {
	stamp := testTimestamp()
	return []MetricSample{
		metricWithDimensions("hdfs-prod", HDFSComponent, "namenode", "hdfs.namenode.missing_blocks", 0, "namenode-a", stamp),
		metricWithDimensions("hdfs-prod", HDFSComponent, "datanode", "hdfs.datanode.failed_volumes", 0, "datanode-a", stamp),
		metricWithDimensions("zk-prod", ZooKeeperComponent, "leader", "zookeeper.sessions", 2, "zk-a", stamp),
	}
}

func hasRule(values []DependencyEvidence, rule EvidenceRule) bool {
	for _, value := range values {
		if value.Rule == rule {
			return true
		}
	}
	return false
}
