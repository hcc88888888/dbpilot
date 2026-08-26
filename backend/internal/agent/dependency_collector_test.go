package agent

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
)

func TestDependencyCollectorRetryMergesIndependentSamples(t *testing.T) {
	collector := &DependencyCollector{config: DependencyCollectorConfig{MaxAttempts: 2, RequestTimeout: time.Second, InitialBackoff: time.Nanosecond, MaxBackoff: time.Nanosecond}}
	definition := database.ComponentDefinition{ID: "hbase-prod", Kind: database.HBaseComponent}
	adapter := &scriptedComponentAdapter{results: []scriptedCollection{
		{
			samples: []database.MetricSample{{Cluster: "hbase-prod", Component: "hbase", Role: "regionserver", Host: "rs-a", Instance: "hbase-prod", MetricName: "hbase.flush.queue_length", Value: 1, Unit: "count"}},
			err:     &database.HBaseEndpointErrors{Failures: []database.HBaseEndpointFailure{{Endpoint: database.Endpoint{Role: "regionserver"}, Host: "rs-b"}}},
		},
		{
			samples: []database.MetricSample{{Cluster: "hbase-prod", Component: "hbase", Role: "regionserver", Host: "rs-b", Instance: "hbase-prod", MetricName: "hbase.flush.queue_length", Value: 2, Unit: "count"}},
			err:     &database.HBaseEndpointErrors{Failures: []database.HBaseEndpointFailure{{Endpoint: database.Endpoint{Role: "regionserver"}, Host: "rs-a"}}},
		},
	}}

	samples, status := collector.collectWithRetry(context.Background(), definition, adapter)
	if len(samples) != 2 || !slices.ContainsFunc(samples, func(sample database.MetricSample) bool { return sample.Host == "rs-a" }) || !slices.ContainsFunc(samples, func(sample database.MetricSample) bool { return sample.Host == "rs-b" }) {
		t.Fatalf("collectWithRetry() samples = %#v, want valid samples retained from both attempts", samples)
	}
	if status.State != "partial" || status.SampleCount != 2 || len(status.IncompleteEndpoints) != 1 || status.IncompleteEndpoints[0].Host != "rs-a" {
		t.Fatalf("collectWithRetry() status = %#v, want final partial endpoint scope", status)
	}
}

type scriptedCollection struct {
	samples []database.MetricSample
	err     error
}

type scriptedComponentAdapter struct {
	results []scriptedCollection
	next    int
}

func (*scriptedComponentAdapter) Component() database.ComponentKind { return database.HBaseComponent }
func (*scriptedComponentAdapter) Capabilities() database.CapabilityMatrix {
	return database.CapabilityMatrix{Metrics: true}
}
func (*scriptedComponentAdapter) Ping(context.Context) error { return nil }
func (adapter *scriptedComponentAdapter) Collect(context.Context, database.MetricRequest) ([]database.MetricSample, error) {
	result := adapter.results[adapter.next]
	adapter.next++
	return result.samples, result.err
}
func (*scriptedComponentAdapter) Close() error { return nil }

func TestNewDependencyCollectorRejectsInvalidRuntimeBoundaries(t *testing.T) {
	valid := DependencyCollectorConfig{
		AgentID: "agent-a",
		Definitions: []database.ComponentDefinition{{
			ID: "hdfs-a", Kind: database.HDFSComponent,
			Endpoints: []database.Endpoint{{URL: "http://127.0.0.1:9870/jmx", Role: "namenode"}},
			SecretRef: "secret://test/reader",
		}},
		SecretResolver: database.StaticSecretResolver{"secret://test/reader": []byte("token")},
		Store:          discardDependencyStore{},
	}
	var typedNilStore *nilDependencyStore
	var typedNilResolver *nilDependencyResolver

	tests := map[string]func(*DependencyCollectorConfig){
		"missing secret resolver":  func(config *DependencyCollectorConfig) { config.SecretResolver = nil },
		"typed nil resolver":       func(config *DependencyCollectorConfig) { config.SecretResolver = typedNilResolver },
		"typed nil store":          func(config *DependencyCollectorConfig) { config.Store = typedNilStore },
		"negative interval":        func(config *DependencyCollectorConfig) { config.Interval = -time.Second },
		"negative timeout":         func(config *DependencyCollectorConfig) { config.RequestTimeout = -time.Second },
		"negative attempts":        func(config *DependencyCollectorConfig) { config.MaxAttempts = -1 },
		"negative initial backoff": func(config *DependencyCollectorConfig) { config.InitialBackoff = -time.Second },
		"negative maximum backoff": func(config *DependencyCollectorConfig) { config.MaxBackoff = -time.Second },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			collector, err := NewDependencyCollector(config)
			require.Error(t, err)
			require.Nil(t, collector)
		})
	}
}

type discardDependencyStore struct{}

func (discardDependencyStore) Append(context.Context, spool.DataClass, spool.Batch) error { return nil }
func (discardDependencyStore) Checkpoint(string) ([]byte, error)                          { return nil, spool.ErrNoCheckpoint }
func (discardDependencyStore) PutCheckpoint(string, []byte) error                         { return nil }

type nilDependencyStore struct{}

func (*nilDependencyStore) Append(context.Context, spool.DataClass, spool.Batch) error { return nil }
func (*nilDependencyStore) Checkpoint(string) ([]byte, error)                          { return nil, spool.ErrNoCheckpoint }
func (*nilDependencyStore) PutCheckpoint(string, []byte) error                         { return nil }

type nilDependencyResolver struct{}

func (*nilDependencyResolver) ResolveSecret(context.Context, string) ([]byte, error) { return nil, nil }

func TestDependencyCollectorReturnsAppendAndCheckpointFailures(t *testing.T) {
	definition := []database.ComponentDefinition{{
		ID: "hdfs-a", Kind: database.HDFSComponent,
		Endpoints: []database.Endpoint{{URL: "http://127.0.0.1:1/jmx", Role: "namenode"}},
		SecretRef: "secret://test/reader",
	}}
	store := &failureDependencyStore{appendErr: errors.New("spool unavailable")}
	collector, err := NewDependencyCollector(DependencyCollectorConfig{
		AgentID: "agent-a", Definitions: definition, Store: store,
		SecretResolver: database.StaticSecretResolver{"secret://test/reader": []byte("token")},
		RequestTimeout: time.Millisecond, MaxAttempts: 1,
	})
	require.NoError(t, err)
	require.ErrorContains(t, collector.CollectOnce(context.Background()), "spool unavailable")

	store.appendErr = nil
	store.checkpointErr = errors.New("checkpoint unavailable")
	require.ErrorContains(t, collector.CollectOnce(context.Background()), "checkpoint unavailable")
}

type failureDependencyStore struct {
	appendErr     error
	checkpointErr error
}

func (store *failureDependencyStore) Append(context.Context, spool.DataClass, spool.Batch) error {
	return store.appendErr
}
func (*failureDependencyStore) Checkpoint(string) ([]byte, error)        { return nil, spool.ErrNoCheckpoint }
func (store *failureDependencyStore) PutCheckpoint(string, []byte) error { return store.checkpointErr }
