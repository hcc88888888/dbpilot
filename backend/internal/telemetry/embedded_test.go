package telemetry_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/plog"
)

// Removing real component start/stop calls would make this lifecycle test fail.
func TestEmbeddedBuilderLifecycleOwnsConcreteComponents(t *testing.T) {
	store := openEmbeddedStore(t)
	cfg := compileEmbeddedFileConfig(t, filepath.Join(t.TempDir(), "application.log"))
	builder := telemetry.NewEmbeddedBuilder(store)

	candidate, err := builder.Build(context.Background(), cfg)
	require.NoError(t, err)
	require.NoError(t, candidate.Start(context.Background()))
	require.NoError(t, candidate.Healthy(context.Background()))
	require.NoError(t, candidate.Stop(context.Background()))
	require.Error(t, candidate.Healthy(context.Background()))
	require.NoError(t, candidate.Stop(context.Background()))
}

// Removing graph validation would make an empty, non-runnable configuration
// look like a valid candidate.
func TestEmbeddedBuilderRejectsInvalidGraph(t *testing.T) {
	builder := telemetry.NewEmbeddedBuilder(openEmbeddedStore(t))
	_, err := builder.Build(context.Background(), telemetry.RuntimeConfig{})
	require.Error(t, err)
}

// Replacing the receiver-to-spool adapter with a no-op would leave the real
// file receiver's output absent from the durable spool.
func TestEmbeddedBuilderFileReceiverPersistsSpoolBatchWithSourceMetadata(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "application.log")
	require.NoError(t, os.WriteFile(path, []byte("runtime collection "+time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600))
	store := openEmbeddedStore(t)
	cfg := compileEmbeddedFileConfig(t, path)
	candidate, err := telemetry.NewEmbeddedBuilder(store).Build(context.Background(), cfg)
	require.NoError(t, err)
	require.NoError(t, candidate.Start(context.Background()))
	t.Cleanup(func() { require.NoError(t, candidate.Stop(context.Background())) })

	require.Eventually(t, func() bool {
		batches, pendingErr := store.Pending(context.Background(), spool.Log, 1)
		return pendingErr == nil && len(batches) == 1
	}, 5*time.Second, 20*time.Millisecond)

	batches, err := store.Pending(context.Background(), spool.Log, 1)
	require.NoError(t, err)
	logs, err := (&plog.ProtoUnmarshaler{}).UnmarshalLogs(batches[0].Payload)
	require.NoError(t, err)
	resources := logs.ResourceLogs()
	require.Equal(t, 1, resources.Len())
	attributes := resources.At(0).Resource().Attributes()
	sourceID, ok := attributes.Get("dbpilot.source.id")
	require.True(t, ok)
	require.Equal(t, "application", sourceID.Str())
	agentID, ok := attributes.Get("dbpilot.agent.id")
	require.True(t, ok)
	require.Equal(t, "embedded-test-agent", agentID.Str())
}

// Resetting the in-memory exporter sequence on an Agent restart must not turn
// a new record into a spool deduplication no-op.
func TestEmbeddedBuilderRestartUsesDistinctSpoolBatchIDs(t *testing.T) {
	directory := t.TempDir()
	spoolRoot := filepath.Join(directory, "spool")
	collect := func(name string, expected int) {
		path := filepath.Join(directory, name+".log")
		require.NoError(t, os.WriteFile(path, []byte(name+" "+time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600))
		store, err := spool.Open(spoolRoot, spool.Limits{MaxBytes: 4 << 20, SegmentBytes: 1 << 20})
		require.NoError(t, err)
		candidate, err := telemetry.NewEmbeddedBuilder(store).Build(context.Background(), compileEmbeddedFileConfig(t, path))
		require.NoError(t, err)
		require.NoError(t, candidate.Start(context.Background()))
		require.Eventually(t, func() bool {
			batches, pendingErr := store.Pending(context.Background(), spool.Log, 0)
			return pendingErr == nil && len(batches) == expected
		}, 5*time.Second, 20*time.Millisecond)
		require.NoError(t, candidate.Stop(context.Background()))
		require.NoError(t, store.Close())
	}

	collect("before-restart", 1)
	collect("after-restart", 2)
	store, err := spool.Open(spoolRoot, spool.Limits{MaxBytes: 4 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	defer store.Close()
	batches, err := store.Pending(context.Background(), spool.Log, 0)
	require.NoError(t, err)
	require.Len(t, batches, 2)
	require.NotEqual(t, batches[0].ID, batches[1].ID)
}

func openEmbeddedStore(t *testing.T) *spool.Store {
	t.Helper()
	t.Cleanup(func() { require.NoError(t, os.RemoveAll("dbpilot-spool")) })
	store, err := spool.Open(filepath.Join(t.TempDir(), "spool"), spool.Limits{MaxBytes: 4 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store
}

func compileEmbeddedFileConfig(t *testing.T, path string) telemetry.RuntimeConfig {
	t.Helper()
	cfg, err := telemetry.Compile(policy.Policy{
		AgentID: "embedded-test-agent", Version: 1,
		IssuedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		Sources: []policy.Source{{ID: "application", Kind: policy.SourceFileLog, Path: path, Interval: time.Second, Params: map[string]string{"start_at": "beginning"}}},
		Limits:  policy.Limits{MaxSpoolBytes: 4 << 20, MaxBatchBytes: 1 << 20, MaxEventsPerSec: 100},
	}, telemetry.NewCatalog())
	require.NoError(t, err)
	return cfg
}
