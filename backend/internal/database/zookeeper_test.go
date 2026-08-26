package database

import (
	"context"
	"errors"
	"testing"
)

func TestZooKeeperAdapterCollectsLeaderAndFollowerFixtures(t *testing.T) {
	definition := zooKeeperTestDefinition()
	client := &fixtureJMXClient{fixtures: map[string][]JMXBean{
		definition.Endpoints[0].URL: decodeHBaseFixture(t, `{"beans":[{"name":"org.apache.ZooKeeperService:name0=ReplicatedServer_id1,name1=replica.1","AvgRequestLatency":2,"OutstandingRequests":4,"NumAliveConnections":8,"QuorumSize":3,"ZnodeCount":21,"WatchCount":5,"TxnLogElapsedSyncTime":7,"SnapshotTime":9}]}`),
		definition.Endpoints[1].URL: decodeHBaseFixture(t, `{"beans":[{"name":"org.apache.ZooKeeperService:name0=ReplicatedServer_id3,name1=replica.3","AvgRequestLatency":3,"PacketsReceived":10,"PacketsSent":11,"NumAliveConnections":6}]}`),
	}}
	adapter, err := NewZooKeeperAdapter(definition, client)
	if err != nil {
		t.Fatalf("NewZooKeeperAdapter() error = %v", err)
	}

	samples, err := adapter.Collect(context.Background(), MetricRequest{})
	allowZooKeeperParseIssues(t, err)
	assertComponentSample(t, samples, "zookeeper.request.latency", "zookeeper", "leader", 2)
	assertComponentSample(t, samples, "zookeeper.outstanding_requests", "zookeeper", "leader", 4)
	assertComponentSample(t, samples, "zookeeper.quorum.members", "zookeeper", "leader", 3)
	assertComponentSample(t, samples, "zookeeper.requests.received", "zookeeper", "follower", 10)
	if !containsString(client.allowlistedProperties(), "AvgRequestLatency") || containsString(client.allowlistedProperties(), "unsafe") {
		t.Fatalf("JMX allowlist properties = %v, want fixed ZooKeeper properties only", client.allowlistedProperties())
	}
}

func TestZooKeeperAdapterReportsOptionalFieldsAndRedactsEndpointFailure(t *testing.T) {
	definition := zooKeeperTestDefinition()
	client := &fixtureJMXClient{
		fixtures: map[string][]JMXBean{definition.Endpoints[0].URL: decodeHBaseFixture(t, `{"beans":[{"name":"org.apache.ZooKeeperService:name0=ReplicatedServer_id1,name1=replica.1","AvgRequestLatency":2}]}`)},
		errors:   map[string]error{definition.Endpoints[1].URL: errors.New("token=top-secret")},
	}
	adapter, err := NewZooKeeperAdapter(definition, client)
	if err != nil {
		t.Fatalf("NewZooKeeperAdapter() error = %v", err)
	}

	samples, err := adapter.Collect(context.Background(), MetricRequest{})
	assertComponentSample(t, samples, "zookeeper.request.latency", "zookeeper", "leader", 2)
	if err == nil || containsString([]string{err.Error()}, "top-secret") {
		t.Fatalf("Collect() error = %v, want redacted endpoint status", err)
	}
	var parseIssues *ZooKeeperParseIssues
	if !errors.As(err, &parseIssues) {
		t.Fatalf("Collect() error = %v, want optional-field parse status alongside endpoint failure", err)
	}
}

func TestZooKeeperAdapterAllowsOnlyJMXOrExplicitCompatibilityPath(t *testing.T) {
	definition := zooKeeperTestDefinition()
	definition.Endpoints[0].URL = "https://zk-1.example.test:8080/commands/monitor"
	if _, err := NewZooKeeperAdapter(definition, &fixtureJMXClient{}); err != nil {
		t.Fatalf("NewZooKeeperAdapter() compatibility endpoint error = %v", err)
	}
	definition.Endpoints[0].URL = "https://zk-1.example.test:8080/commands/reconfig"
	if _, err := NewZooKeeperAdapter(definition, &fixtureJMXClient{}); err == nil {
		t.Fatal("NewZooKeeperAdapter() error = nil, want mutation management path rejected")
	}
}

func zooKeeperTestDefinition() ComponentDefinition {
	return ComponentDefinition{ID: "zk-prod", Kind: ZooKeeperComponent, SecretRef: "secret://runtime/zk", Endpoints: []Endpoint{
		{URL: "https://zk-1.example.test:8080/jmx", Role: "leader"},
		{URL: "https://zk-2.example.test:8080/jmx", Role: "follower"},
	}}
}

func allowZooKeeperParseIssues(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var issues *ZooKeeperParseIssues
	if !errors.As(err, &issues) {
		t.Fatalf("Collect() error = %v, want only ZooKeeper parse issue status", err)
	}
}

func assertComponentSample(t *testing.T, samples []MetricSample, name, component, role string, value float64) {
	t.Helper()
	for _, sample := range samples {
		if sample.MetricName == name && sample.Component == component && sample.Role == role && sample.Value == value {
			return
		}
	}
	t.Fatalf("samples = %#v, want %s/%s/%s=%v", samples, component, role, name, value)
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
