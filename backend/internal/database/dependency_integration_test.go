package database_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
)

func TestDependencyCollectorPersistsRealJMXSamplesEvidenceAndRestartSafeID(t *testing.T) {
	const secretRef = "secret://fixture/reader"
	hbaseURL, hdfsURL, zooKeeperURL, token := dependencyFixtureEndpoints(t)

	definitions := []database.ComponentDefinition{
		{ID: "hdfs-prod", Kind: database.HDFSComponent, Endpoints: []database.Endpoint{{URL: hdfsURL, Role: "datanode"}}, SecretRef: secretRef},
		{ID: "zk-prod", Kind: database.ZooKeeperComponent, Endpoints: []database.Endpoint{{URL: zooKeeperURL, Role: "leader"}}, SecretRef: secretRef},
		{ID: "hbase-prod", Kind: database.HBaseComponent, Endpoints: []database.Endpoint{{URL: hbaseURL, Role: "regionserver"}}, SecretRef: secretRef, Dependencies: database.DependencyRef{HDFSClusterID: "hdfs-prod", ZooKeeperClusterID: "zk-prod"}},
	}
	fixedTime := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	root := filepath.Join(t.TempDir(), "spool")

	firstID := collectDependencyBatch(t, root, fixedTime, definitions, token)
	secondID := collectDependencyBatch(t, root, fixedTime, definitions, token)
	require.Equal(t, firstID, secondID)
}

func collectDependencyBatch(t *testing.T, root string, now time.Time, definitions []database.ComponentDefinition, token string) string {
	t.Helper()
	store, err := spool.Open(root, spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	require.NoError(t, err)
	collector, err := agent.NewDependencyCollector(agent.DependencyCollectorConfig{
		AgentID: "agent-integration", Definitions: definitions, Store: store,
		SecretResolver: database.StaticSecretResolver{"secret://fixture/reader": []byte(token)},
		Interval:       time.Hour, RequestTimeout: time.Second, MaxAttempts: 2,
		InitialBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond,
		Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, collector.CollectOnce(context.Background()))
	require.NoError(t, store.Seal())
	batches, err := store.Pending(context.Background(), spool.Metric, 10)
	require.NoError(t, err)
	require.Len(t, batches, 1, "restart replay must be deduplicated by a stable batch ID")

	var envelope agent.DependencyTelemetryEnvelope
	require.NoError(t, json.Unmarshal(batches[0].Payload, &envelope))
	requireMetric(t, envelope.Samples, "hbase-prod", "hbase.request.queue_time")
	requireMetric(t, envelope.Samples, "hdfs-prod", "hdfs.datanode.capacity")
	requireMetric(t, envelope.Samples, "zk-prod", "zookeeper.sessions")
	require.Len(t, envelope.Statuses, 3)
	require.NotEmpty(t, envelope.Health)
	requireEvidence(t, envelope.Evidence, database.EvidenceHBaseWriteLatencyHDFS)
	requireEvidence(t, envelope.Evidence, database.EvidenceRegionServerBacklogZooKeeper)
	require.Equal(t, now, envelope.CollectedAt)
	require.Equal(t, batches[0].ID, envelope.BatchID)
	require.NoError(t, store.Close())
	return batches[0].ID
}

func dependencyFixtureEndpoints(t *testing.T) (string, string, string, string) {
	t.Helper()
	if os.Getenv("DBPILOT_HBASE_DEPENDENCY_INTEGRATION") == "1" {
		values := []string{os.Getenv("DBPILOT_HBASE_JMX_URL"), os.Getenv("DBPILOT_HDFS_JMX_URL"), os.Getenv("DBPILOT_ZOOKEEPER_JMX_URL"), os.Getenv("DBPILOT_HBASE_DEPENDENCY_TOKEN")}
		for _, value := range values {
			require.NotEmpty(t, value, "Docker fixture environment is incomplete")
		}
		return values[0], values[1], values[2], values[3]
	}
	hbase := fixtureJMXServer(t, `{"beans":[{"name":"Hadoop:service=HBase,name=RegionServer,sub=Server","regionCount":12,"storeCount":4,"storeFileCount":8,"blockCacheCount":40,"blockCacheSize":4096,"blockCacheFreeSize":1024,"blockCacheHitCount":90,"blockCacheMissCount":10,"blockCacheEvictionCount":1,"flushQueueLength":11,"compactionQueueLength":12},{"name":"Hadoop:service=HBase,name=RegionServer,sub=IPC","queueCallTime":1500,"processingCallTime":20,"totalCallTime":1700,"numOpenConnections":6}]}`)
	hdfs := fixtureJMXServer(t, `{"beans":[{"name":"Hadoop:service=DataNode,name=FSDatasetState","Capacity":1000,"DfsUsed":950,"Remaining":50,"NumFailedVolumes":0,"NumBlocks":80},{"name":"Hadoop:service=DataNode,name=DataNodeInfo","xceiverCount":4},{"name":"Hadoop:service=DataNode,name=DataNodeActivity-port50010","BytesRead":100,"BytesWritten":200}]}`)
	zookeeper := fixtureJMXServer(t, `{"beans":[{"name":"org.apache.ZooKeeperService:name0=ReplicatedServer_id1,name1=replica.1","AvgRequestLatency":2,"OutstandingRequests":101,"PacketsReceived":1000,"PacketsSent":999,"NumAliveConnections":0,"QuorumSize":3,"ZnodeCount":21,"WatchCount":5,"TxnLogElapsedSyncTime":7,"SnapshotTime":9}]}`)
	return hbase.URL + "/jmx", hdfs.URL + "/jmx", zookeeper.URL + "/jmx", "fixture-read-only-token"
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
