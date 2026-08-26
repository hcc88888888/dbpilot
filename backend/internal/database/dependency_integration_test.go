package database_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"github.com/stretchr/testify/require"
)

func TestDependencyCollectorPersistsRealJMXSamplesEvidenceAndRestartSafeID(t *testing.T) {
	const secretRef = "secret://fixture/reader"
	hbaseURL, failingHBaseURL, hdfsURL, zooKeeperURL, token := dependencyFixtureEndpoints(t)
	definitions := []database.ComponentDefinition{
		{ID: "hdfs-prod", Kind: database.HDFSComponent, Endpoints: []database.Endpoint{{URL: hdfsURL, Role: "datanode"}}, SecretRef: secretRef},
		{ID: "zk-prod", Kind: database.ZooKeeperComponent, Endpoints: []database.Endpoint{{URL: zooKeeperURL, Role: "leader"}}, SecretRef: secretRef},
		{ID: "hbase-prod", Kind: database.HBaseComponent, Endpoints: []database.Endpoint{{URL: hbaseURL, Role: "regionserver"}, {URL: failingHBaseURL, Role: "regionserver"}}, SecretRef: secretRef, Dependencies: database.DependencyRef{HDFSClusterID: "hdfs-prod", ZooKeeperClusterID: "zk-prod"}},
	}
	fixedTime := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	restartTime := fixedTime.Add(time.Minute)
	root := filepath.Join(t.TempDir(), "spool")

	firstReporter, firstErr := runDependencyRuntime(t, root, fixedTime, definitions, token, true)
	require.ErrorContains(t, firstErr, "persist dependency collection sequence")
	require.True(t, firstReporter.has("DEGRADED", "COMPONENT_COLLECTOR_FAILED"))
	first := readDependencyBatches(t, root)
	require.Len(t, first, 1, "append must remain durable when the following checkpoint fails")

	secondReporter, secondErr := runDependencyRuntime(t, root, restartTime, definitions, token, false)
	require.NoError(t, secondErr)
	require.False(t, secondReporter.has("DEGRADED", "COMPONENT_COLLECTOR_FAILED"))
	second := readDependencyBatches(t, root)
	require.Len(t, second, 1, "restart replay of an uncheckpointed collection must reuse its ID")
	require.Equal(t, first[0].ID, second[0].ID)

	_, thirdErr := runDependencyRuntime(t, root, restartTime, definitions, token, false)
	require.NoError(t, thirdErr)
	batches := readDependencyBatches(t, root)
	require.Len(t, batches, 2, "a completed same-clock recollection must receive a fresh ID")
	require.NotEqual(t, batches[0].ID, batches[1].ID)

	var envelope agent.DependencyTelemetryEnvelope
	require.NoError(t, json.Unmarshal(batches[1].Payload, &envelope))
	require.Equal(t, uint64(2), envelope.Sequence)
	requireMetric(t, envelope.Samples, "hbase-prod", "hbase.request.queue_time")
	requireMetric(t, envelope.Samples, "hdfs-prod", "hdfs.datanode.capacity")
	requireMetric(t, envelope.Samples, "zk-prod", "zookeeper.sessions")
	requireStatus(t, envelope.Statuses, "hbase-prod", "partial", "COMPONENT_COLLECTION_PARTIAL", 2)
	require.NotEmpty(t, envelope.Health)
	requireEvidence(t, envelope.Evidence, database.EvidenceHBaseWriteLatencyHDFS)
	requireEvidence(t, envelope.Evidence, database.EvidenceRegionServerBacklogZooKeeper)
	require.Equal(t, restartTime, envelope.CollectedAt)
	require.Equal(t, batches[1].ID, envelope.BatchID)
}

func runDependencyRuntime(t *testing.T, root string, now time.Time, definitions []database.ComponentDefinition, token string, failCheckpoint bool) (*integrationReporter, error) {
	t.Helper()
	store, err := spool.Open(root, spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	wrapped := &integrationStore{Store: store, cancel: cancel, failCheckpoint: failCheckpoint}
	collector, err := agent.NewDependencyCollector(agent.DependencyCollectorConfig{
		AgentID: "agent-integration", Definitions: definitions, Store: wrapped,
		SecretResolver: database.StaticSecretResolver{"secret://fixture/reader": []byte(token)},
		Interval:       time.Hour, RequestTimeout: 200 * time.Millisecond, MaxAttempts: 2,
		InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	reporter := &integrationReporter{}
	envelope := policy.SignatureEnvelope{Policy: policy.Policy{AgentID: "agent-integration", Version: 1, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Sources: []policy.Source{{ID: "host", Kind: policy.SourceHostMetrics, Interval: time.Hour}}, Limits: policy.Limits{MaxSpoolBytes: 1 << 20, MaxBatchBytes: 1 << 16, MaxEventsPerSec: 100}}}
	runtime := agent.NewRuntime(agent.Dependencies{
		AgentID: "agent-integration", PolicySource: integrationPolicySource{envelope}, PolicyVerifier: integrationVerifier{},
		Engine: &integrationEngine{}, Store: wrapped, Exporter: integrationExporter{}, HealthReporter: reporter,
		ComponentCollector: collector, PollInterval: time.Hour, ExportInterval: time.Hour,
		ShutdownTimeout: time.Second, OperationTimeout: time.Second, Now: func() time.Time { return now },
	})
	return reporter, runtime.Run(ctx)
}

type integrationStore struct {
	*spool.Store
	cancel         context.CancelFunc
	failCheckpoint bool
}

func (store *integrationStore) PutCheckpoint(source string, value []byte) error {
	if store.failCheckpoint {
		store.failCheckpoint = false
		return errors.New("fixture checkpoint failure")
	}
	err := store.Store.PutCheckpoint(source, value)
	if err == nil {
		store.cancel()
	}
	return err
}

type integrationPolicySource struct{ envelope policy.SignatureEnvelope }

func (source integrationPolicySource) Fetch(context.Context) (policy.SignatureEnvelope, error) {
	return source.envelope, nil
}

type integrationVerifier struct{}

func (integrationVerifier) Verify(_ context.Context, envelope policy.SignatureEnvelope) (policy.Policy, error) {
	return envelope.Policy, nil
}

type integrationEngine struct{ active uint64 }

func (engine *integrationEngine) Apply(_ context.Context, value policy.Policy) (telemetry.ApplyResult, error) {
	engine.active = value.Version
	return telemetry.ApplyResult{Version: value.Version, State: telemetry.ApplyActive}, nil
}
func (engine *integrationEngine) ActiveVersion() uint64 { return engine.active }
func (*integrationEngine) Stop(context.Context) error   { return nil }

type integrationExporter struct{}

func (integrationExporter) SendPending(context.Context) error { return nil }

type integrationReporter struct {
	mu       sync.Mutex
	statuses []agent.PolicyStatus
}

func (reporter *integrationReporter) Report(_ context.Context, status agent.PolicyStatus) error {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.statuses = append(reporter.statuses, status)
	return nil
}
func (reporter *integrationReporter) has(state, code string) bool {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	for _, status := range reporter.statuses {
		if status.State == state && status.ErrorCode == code {
			return true
		}
	}
	return false
}

func readDependencyBatches(t *testing.T, root string) []spool.Batch {
	t.Helper()
	store, err := spool.Open(root, spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	require.NoError(t, err)
	batches, err := store.Pending(context.Background(), spool.Metric, 10)
	require.NoError(t, err)
	require.NoError(t, store.Close())
	return batches
}

func dependencyFixtureEndpoints(t *testing.T) (string, string, string, string, string) {
	t.Helper()
	if os.Getenv("DBPILOT_HBASE_DEPENDENCY_INTEGRATION") == "1" {
		values := []string{os.Getenv("DBPILOT_HBASE_JMX_URL"), os.Getenv("DBPILOT_HBASE_FAILING_JMX_URL"), os.Getenv("DBPILOT_HDFS_JMX_URL"), os.Getenv("DBPILOT_ZOOKEEPER_JMX_URL"), os.Getenv("DBPILOT_HBASE_DEPENDENCY_TOKEN")}
		for _, value := range values {
			require.NotEmpty(t, value, "Docker fixture environment is incomplete")
		}
		return values[0], values[1], values[2], values[3], values[4]
	}
	hbase := fixtureJMXServer(t, `{"beans":[{"name":"Hadoop:service=HBase,name=RegionServer,sub=Server","regionCount":12,"storeCount":4,"storeFileCount":8,"blockCacheCount":40,"blockCacheSize":4096,"blockCacheFreeSize":1024,"blockCacheHitCount":90,"blockCacheMissCount":10,"blockCacheEvictionCount":1,"flushQueueLength":11,"compactionQueueLength":12},{"name":"Hadoop:service=HBase,name=RegionServer,sub=IPC","queueCallTime":1500,"processingCallTime":20,"totalCallTime":1700,"numOpenConnections":6}]}`)
	hdfs := fixtureJMXServer(t, `{"beans":[{"name":"Hadoop:service=DataNode,name=FSDatasetState","Capacity":1000,"DfsUsed":950,"Remaining":50,"NumFailedVolumes":0,"NumBlocks":80},{"name":"Hadoop:service=DataNode,name=DataNodeInfo","xceiverCount":4},{"name":"Hadoop:service=DataNode,name=DataNodeActivity-port50010","BytesRead":100,"BytesWritten":200}]}`)
	zookeeper := fixtureJMXServer(t, `{"beans":[{"name":"org.apache.ZooKeeperService:name0=ReplicatedServer_id1,name1=replica.1","AvgRequestLatency":2,"OutstandingRequests":101,"PacketsReceived":1000,"PacketsSent":999,"NumAliveConnections":0,"QuorumSize":3,"ZnodeCount":21,"WatchCount":5,"TxnLogElapsedSyncTime":7,"SnapshotTime":9}]}`)
	failing := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "fixture unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(failing.Close)
	return hbase.URL + "/jmx", failing.URL + "/jmx", hdfs.URL + "/jmx", zookeeper.URL + "/jmx", "fixture-read-only-token"
}

func fixtureJMXServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, http.MethodGet, request.Method)
		require.Equal(t, "/jmx", request.URL.Path)
		require.Equal(t, "Bearer fixture-read-only-token", request.Header.Get("Authorization"))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server
}

func requireMetric(t *testing.T, samples []database.MetricSample, cluster, name string) {
	t.Helper()
	for _, sample := range samples {
		if sample.Cluster == cluster && sample.MetricName == name {
			require.NotEmpty(t, sample.Component)
			require.NotEmpty(t, sample.Role)
			require.NotEmpty(t, sample.Host)
			require.NotEmpty(t, sample.Instance)
			return
		}
	}
	t.Fatalf("metric %s/%s was not spooled", cluster, name)
}
func requireEvidence(t *testing.T, evidence []database.DependencyEvidence, rule database.EvidenceRule) {
	t.Helper()
	for _, item := range evidence {
		if item.Rule == rule {
			require.NotEmpty(t, item.DedupKey)
			return
		}
	}
	t.Fatalf("dependency evidence %s was not spooled", rule)
}
func requireStatus(t *testing.T, statuses []agent.ComponentCollectionStatus, cluster, state, code string, attempts int) {
	t.Helper()
	for _, status := range statuses {
		if status.Cluster == cluster {
			require.Equal(t, state, status.State)
			require.Equal(t, code, status.ErrorCode)
			require.Equal(t, attempts, status.Attempts)
			require.NotZero(t, status.SampleCount)
			return
		}
	}
	t.Fatalf("component status %s was not spooled", cluster)
}
