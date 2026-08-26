package database

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
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

func TestZooKeeperMonitorCompatibilityUsesRuntimeTLSAndAuthorization(t *testing.T) {
	called := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != zooKeeperCompatibilityPath {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer runtime-token" {
			t.Fatalf("Authorization = %q", got)
		}
		_, _ = w.Write([]byte("zk_avg_latency\t2\nzk_num_alive_connections\t8\n"))
	}))
	defer server.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if _, err := x509.ParseCertificate(server.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
	definition := zooKeeperTestDefinition()
	definition.Endpoints = []Endpoint{{URL: server.URL + zooKeeperCompatibilityPath, Role: "leader"}}
	definition.TLSRef = "secret://runtime/zk-ca"
	adapter, err := NewZooKeeperAdapterWithRuntime(definition, StaticSecretResolver{definition.SecretRef: []byte("runtime-token"), definition.TLSRef: ca})
	if err != nil {
		t.Fatal(err)
	}
	samples, err := adapter.Collect(context.Background(), MetricRequest{})
	allowZooKeeperParseIssues(t, err)
	if !called {
		t.Fatal("monitor endpoint was not called")
	}
	assertComponentSample(t, samples, "zookeeper.request.latency", "zookeeper", "leader", 2)
	assertComponentSample(t, samples, "zookeeper.sessions", "zookeeper", "leader", 8)
}

func TestZooKeeperMonitorParsesJSONAndRedactsFailures(t *testing.T) {
	values, err := parseZooKeeperMonitor([]byte(`{"zk_avg_latency":2,"zk_num_alive_connections":8,"unsafe":"x"}`))
	if err != nil || string(values["zk_avg_latency"]) != "2" {
		t.Fatalf("parseZooKeeperMonitor() = %#v, %v", values, err)
	}
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "token=top-secret", http.StatusInternalServerError)
	}))
	defer server.Close()
	definition := zooKeeperTestDefinition()
	definition.Endpoints = []Endpoint{{URL: server.URL + zooKeeperCompatibilityPath, Role: "leader"}}
	adapter, err := NewZooKeeperAdapterWithRuntime(definition, StaticSecretResolver{definition.SecretRef: []byte("top-secret")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Collect(context.Background(), MetricRequest{})
	if !called || err == nil || containsString([]string{err.Error()}, "top-secret") {
		t.Fatalf("Collect() error = %v, want redacted monitor failure", err)
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
