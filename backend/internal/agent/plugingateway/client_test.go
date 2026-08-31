package plugingateway

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestOpenRejectsNonCanonicalRuntimePaths(t *testing.T) {
	client, err := NewClient(ClientConfig{RuntimeRoot: t.TempDir(), Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}})
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

func TestSessionRejectsApplyBeforeHandshake(t *testing.T) {
	root := t.TempDir()
	client, err := NewClient(ClientConfig{RuntimeRoot: root, Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}})
	require.NoError(t, err)
	session, err := client.Open(ExpectedPlugin{PID: 10, ExpectedUserID: 1000, ExpectedGroupID: 1000, RuntimeDirectory: filepath.Join(root, "mysql"), ExecutablePath: filepath.Join(root, "plugin"), ExecutableSHA256: bytes.Repeat([]byte{1}, 32), LaunchNonce: bytes.Repeat([]byte{2}, 32), AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ConfigurationRevision: 1, OperationRevision: 1, InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"template-1"}})
	require.NoError(t, err)
	require.Error(t, session.ApplyConfiguration(context.Background(), PluginConfiguration{}))
}

func TestAppendBatchSerializesSameLogicalSequenceAndMakesExactRetryIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	client, err := NewClient(ClientConfig{RuntimeRoot: t.TempDir(), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := &Session{client: client, expected: ExpectedPlugin{AssignmentID: "assignment-1", DatabaseFamily: "mysql", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}}, configurationRevision: 4, instances: map[string]*pluginv1.PluginInstanceConfiguration{"mysql-1": {InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}}, lastSequence: map[string]uint64{}, lastTimestamp: map[string]time.Time{}, lastDigest: map[string]string{}}
	batch := func(value float64) *pluginv1.PluginMetricBatch {
		return &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1", ConfigurationRevision: 4, TemplateId: "builtin", TemplateRevision: 1, Sequence: 7, CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: value, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
	}
	sink := &recordingMetricSink{}
	require.NoError(t, session.appendBatch(context.Background(), batch(1), sink))
	require.NoError(t, session.appendBatch(context.Background(), batch(1), sink))
	require.Len(t, sink.batches, 1)
	require.Error(t, session.appendBatch(context.Background(), batch(2), sink))
}

type recordingMetricSink struct{ batches []spool.Batch }

func (sink *recordingMetricSink) Append(_ context.Context, _ spool.DataClass, batch spool.Batch) error {
	sink.batches = append(sink.batches, batch)
	return nil
}
