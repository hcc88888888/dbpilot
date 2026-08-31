package plugingateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCursorStorePersistsSequenceAndRejectsPayloadConflictAfterRestart(t *testing.T) {
	root := t.TempDir()
	key := cursorKey{AssignmentID: "assignment-1", ConfigurationRevision: 4, TemplateID: "builtin", InstanceID: "mysql-1"}
	first := sha256.Sum256([]byte("first"))
	store, err := NewCursorStore(root)
	require.NoError(t, err)
	require.NoError(t, store.Commit(key, 7, first[:], time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)))

	restarted, err := NewCursorStore(root)
	require.NoError(t, err)
	state, err := restarted.Load(key)
	require.NoError(t, err)
	require.Equal(t, uint64(7), state.Sequence)
	require.Equal(t, first[:], state.Digest)
	second := sha256.Sum256([]byte("second"))
	require.Error(t, restarted.Commit(key, 7, second[:], time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)))
	require.Error(t, restarted.Commit(key, 6, first[:], time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)))
}

func TestOpenRejectsNonCanonicalRuntimePaths(t *testing.T) {
	root := t.TempDir()
	client, err := NewClient(ClientConfig{RuntimeRoot: root, CursorRoot: filepath.Join(root, "state"), Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}})
	require.NoError(t, err)
	_, err = client.Open(ExpectedPlugin{RuntimeDirectory: "/tmp/not-under-runtime", AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ConfigurationRevision: 1, OperationRevision: 1, InstanceIDs: []string{"mysql-1"}})
	require.Error(t, err)
}

func TestConfigurationRequiresTheCompleteAssignedInstanceSet(t *testing.T) {
	expected := ExpectedPlugin{AssignmentID: "assignment-1", ConfigurationRevision: 4, InstanceIDs: []string{"mysql-1", "mysql-2"}}
	valid := func(instanceID string) *pluginv1.PluginInstanceConfiguration {
		return &pluginv1.PluginInstanceConfiguration{InstanceId: instanceID, DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}
	}
	require.Error(t, PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{valid("mysql-1")}}.validate(expected))
	require.Error(t, PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{valid("mysql-1"), valid("mysql-1")}}.validate(expected))
	require.NoError(t, PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{valid("mysql-1"), valid("mysql-2")}}.validate(expected))
}

func TestConfigurationRejectsTemplateOutsideExpectedAllowlist(t *testing.T) {
	expected := ExpectedPlugin{AssignmentID: "assignment-1", ConfigurationRevision: 4, InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}}
	configuration := PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{{InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", Templates: []*pluginv1.MetricTemplateConfiguration{{TemplateId: "not-allowed", Revision: 1}}}}}
	require.Error(t, configuration.validate(expected))
}

func TestSessionRejectsApplyBeforeHandshake(t *testing.T) {
	root := t.TempDir()
	client, err := NewClient(ClientConfig{RuntimeRoot: root, CursorRoot: filepath.Join(root, "state"), Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}})
	require.NoError(t, err)
	session, err := client.Open(ExpectedPlugin{PID: 10, ExpectedUserID: 1000, ExpectedGroupID: 1000, RuntimeDirectory: filepath.Join(root, "mysql"), ExecutablePath: filepath.Join(root, "plugin"), ExecutableSHA256: bytes.Repeat([]byte{1}, 32), LaunchNonce: bytes.Repeat([]byte{2}, 32), AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ConfigurationRevision: 1, OperationRevision: 1, InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"template-1"}})
	require.NoError(t, err)
	require.Error(t, session.ApplyConfiguration(context.Background(), PluginConfiguration{}))
}

func TestAppendBatchSerializesSameLogicalSequenceAndMakesExactRetryIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	client, err := NewClient(ClientConfig{RuntimeRoot: root, CursorRoot: filepath.Join(root, "state"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := &Session{client: client, expected: ExpectedPlugin{AssignmentID: "assignment-1", PluginID: "mysql", Version: "1.0.0", DatabaseFamily: "mysql", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}}, configurationRevision: 4, instances: map[string]*pluginv1.PluginInstanceConfiguration{"mysql-1": {InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", Templates: []*pluginv1.MetricTemplateConfiguration{{TemplateId: "builtin", Revision: 1}}}}}
	batch := func(value float64) *pluginv1.PluginMetricBatch {
		return &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1", ConfigurationRevision: 4, TemplateId: "builtin", TemplateRevision: 1, Sequence: 7, CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: value, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
	}
	sink := &recordingMetricSink{}
	require.NoError(t, session.appendBatch(context.Background(), batch(1), sink))
	require.NoError(t, session.appendBatch(context.Background(), batch(1), sink))
	require.Len(t, sink.batches, 1)
	require.Error(t, session.appendBatch(context.Background(), batch(2), sink))
}

func TestAppendBatchRepairsCursorAfterSpoolAppendCrashAndRejectsDifferentReplay(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	spoolStore, err := spool.Open(filepath.Join(root, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spoolStore.Close()) })
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), CursorRoot: filepath.Join(root, "state", "gateway-cursors"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: spoolStore, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	batch := testBatch(now, 7, 1)
	payload, id, err := normalizeBatch(batch, session.metricScope(batch), now)
	require.NoError(t, err)
	require.NoError(t, spoolStore.Append(context.Background(), spool.Metric, spool.Batch{ID: id, SourceID: "plugin-runtime:assignment-1:mysql-1", CreatedAt: now, Payload: payload}))

	restartedClient, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), CursorRoot: filepath.Join(root, "state", "gateway-cursors"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: spoolStore, Now: func() time.Time { return now }})
	require.NoError(t, err)
	restarted := configuredTestSession(restartedClient)
	require.NoError(t, restarted.appendBatch(context.Background(), batch, spoolStore))
	conflicting := testBatch(now, 7, 2)
	require.Error(t, restarted.appendBatch(context.Background(), conflicting, spoolStore))
	found, matches, err := spoolStore.Lookup(context.Background(), spool.Metric, id, payload)
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, matches)
}

func TestAppendBatchRejectsForgedPluginDimensions(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), CursorRoot: filepath.Join(root, "state", "gateway-cursors"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	forged := testBatch(now, 7, 1)
	forged.PluginVersion = "9.9.9"
	require.Error(t, session.appendBatch(context.Background(), forged, &recordingMetricSink{}))
}

func configuredTestSession(client *Client) *Session {
	return &Session{client: client, expected: ExpectedPlugin{AssignmentID: "assignment-1", PluginID: "mysql", Version: "1.0.0", DatabaseFamily: "mysql", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}}, configurationRevision: 4, instances: map[string]*pluginv1.PluginInstanceConfiguration{"mysql-1": {InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", Templates: []*pluginv1.MetricTemplateConfiguration{{TemplateId: "builtin", Revision: 1}}}}}
}

func testBatch(now time.Time, sequence uint64, value float64) *pluginv1.PluginMetricBatch {
	return &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1", ConfigurationRevision: 4, TemplateId: "builtin", TemplateRevision: 1, Sequence: sequence, CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: value, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
}

type recordingMetricSink struct{ batches []spool.Batch }

func (sink *recordingMetricSink) Append(_ context.Context, _ spool.DataClass, batch spool.Batch) error {
	sink.batches = append(sink.batches, batch)
	return nil
}
