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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestOpenRejectsNonCanonicalRuntimePaths(t *testing.T) {
	root := t.TempDir()
	client, err := NewClient(ClientConfig{RuntimeRoot: root, Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}})
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

func TestConfigurationRequiresCompleteImmutableTemplateCoverage(t *testing.T) {
	expected := ExpectedPlugin{AssignmentID: "assignment-1", ConfigurationRevision: 4, InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}}
	instance := &pluginv1.PluginInstanceConfiguration{InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}
	require.Error(t, PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{instance}}.validate(expected))
	instance.Templates = []*pluginv1.MetricTemplateConfiguration{{TemplateId: "builtin", Revision: 1, QueryDigest: bytes.Repeat([]byte{1}, 32), QueryKind: "sql", ReadOnlyStatement: "SELECT value", CollectionIntervalSeconds: 10, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, ValueMappings: []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: "mysql.connections.current", MetricType: "gauge", Unit: "1"}}, LabelMappings: []*pluginv1.MetricLabelMapping{{SourceColumn: "role", Label: "role"}}}}
	expected.TemplateConfigurations = cloneTemplateConfigurations(instance.Templates)
	require.NoError(t, PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{instance}}.validate(expected))
	instance.Templates[0].QueryDigest[0] ^= 0xff
	require.Error(t, PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{instance}}.validate(expected))
}

func TestSignedManifestProjectionMustExactlyMatchHandshake(t *testing.T) {
	expected := ExpectedPlugin{SupportedVariants: []string{"mysql"}, SignedCapabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1}
	response := &pluginv1.PluginHandshakeResponse{SupportedVariants: []string{"mysql"}, Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1}
	require.True(t, matchesSignedManifest(response, expected))
	response.Capabilities = []string{"metrics.collect", "admin.execute"}
	require.False(t, matchesSignedManifest(response, expected))
	response.Capabilities = []string{"metrics.collect"}
	response.SupportedVariants = []string{"postgres"}
	require.False(t, matchesSignedManifest(response, expected))
}

func TestValidationResultRequiresCanonicalSecretSafeTextAndExactInvariants(t *testing.T) {
	valid := &pluginv1.ValidatePluginInstanceResponse{InstanceId: "mysql-1", Valid: true, DatabaseVersion: "8.4.0", DatabaseEdition: "community", Capabilities: []string{"metrics.collect"}}
	require.True(t, validValidationResponse(valid, "mysql-1", []string{"metrics.collect"}))
	for name, mutate := range map[string]func(*pluginv1.ValidatePluginInstanceResponse){
		"valid with error": func(value *pluginv1.ValidatePluginInstanceResponse) { value.ErrorCode = "timeout" },
		"raw DSN version": func(value *pluginv1.ValidatePluginInstanceResponse) {
			value.DatabaseVersion = "mysql://user:password@host/db"
		},
		"whitespace edition":  func(value *pluginv1.ValidatePluginInstanceResponse) { value.DatabaseEdition = " community " },
		"unsigned capability": func(value *pluginv1.ValidatePluginInstanceResponse) { value.Capabilities = []string{"admin.execute"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := proto.Clone(valid).(*pluginv1.ValidatePluginInstanceResponse)
			mutate(candidate)
			require.False(t, validValidationResponse(candidate, "mysql-1", []string{"metrics.collect"}))
		})
	}
}

func TestAppendBatchRequiresExactTemplateMetricAndLabelMappings(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store, err := spool.Open(filepath.Join(root, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: store, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	template := session.instances["mysql-1"].Templates[0]
	template.QueryDigest = bytes.Repeat([]byte{1}, 32)
	template.QueryKind = "sql"
	template.ReadOnlyStatement = "SELECT value"
	template.CollectionIntervalSeconds = 10
	template.TimeoutSeconds = 5
	template.MaxRows = 1
	template.MaxColumns = 2
	template.ValueMappings = []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: "mysql.connections.current", MetricType: "gauge", Unit: "1"}}
	template.LabelMappings = []*pluginv1.MetricLabelMapping{{SourceColumn: "role", Label: "role"}}

	wrongName := testBatch(now, 1, 1)
	wrongName.Samples[0].MetricName = "mysql.forged"
	require.Error(t, session.appendBatch(context.Background(), wrongName, store))
	wrongLabel := testBatch(now, 1, 1)
	wrongLabel.Samples[0].Labels = map[string]string{"cluster": "forged"}
	require.Error(t, session.appendBatch(context.Background(), wrongLabel, store))
	validBatch := testBatch(now, 1, 1)
	validBatch.Samples[0].Labels = map[string]string{"role": "primary"}
	require.NoError(t, session.appendBatch(context.Background(), validBatch, store))
}

func TestResumeCursorsComeOnlyFromDurableSpoolReceipts(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store, err := spool.Open(filepath.Join(root, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: store, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	require.NoError(t, session.appendBatch(context.Background(), testBatch(now, 7, 1), store))
	require.NoError(t, store.Ack(context.Background(), spool.Metric, "plugin-metrics-v1-assignment-1-4-builtin-mysql-1-7"))

	cursors, err := session.resumeCursors(context.Background(), store)
	require.NoError(t, err)
	require.Equal(t, []*pluginv1.PluginMetricCursor{{InstanceId: "mysql-1", TemplateId: "builtin", Sequence: 7}}, cursors)
	require.True(t, validAckResponse(&pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: cursors}, cursors))
	require.False(t, validAckResponse(&pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: []*pluginv1.PluginMetricCursor{{InstanceId: "mysql-1", TemplateId: "builtin", Sequence: 6}}}, cursors))
}

func TestSessionRejectsApplyBeforeHandshake(t *testing.T) {
	root := t.TempDir()
	client, err := NewClient(ClientConfig{RuntimeRoot: root, Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}})
	require.NoError(t, err)
	expected := ExpectedPlugin{PID: 10, ExpectedUserID: 1000, ExpectedGroupID: 1000, RuntimeDirectory: filepath.Join(root, "mysql"), ExecutablePath: filepath.Join(root, "plugin"), ExecutableSHA256: bytes.Repeat([]byte{1}, 32), LaunchNonce: bytes.Repeat([]byte{2}, 32), AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ConfigurationRevision: 1, OperationRevision: 1, InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"template-1"}}
	_, err = client.Open(expected)
	require.Error(t, err, "production sessions require a reverified signed manifest projection")
	expected.SupportedVariants = []string{"mysql"}
	expected.SignedCapabilities = []string{"metrics.collect"}
	expected.MetricTemplateSchemaVersion = 1
	session, err := client.Open(expected)
	require.NoError(t, err)
	require.Error(t, session.ApplyConfiguration(context.Background(), PluginConfiguration{}))
}

func TestAppendBatchSerializesSameLogicalSequenceAndMakesExactRetryIdempotent(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	spoolStore, err := spool.Open(filepath.Join(root, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spoolStore.Close()) })
	client, err := NewClient(ClientConfig{RuntimeRoot: root, Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: spoolStore, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	batch := func(value float64) *pluginv1.PluginMetricBatch {
		return &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1", ConfigurationRevision: 4, TemplateId: "builtin", TemplateRevision: 1, Sequence: 7, CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: value, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
	}
	require.NoError(t, session.appendBatch(context.Background(), batch(1), spoolStore))
	require.NoError(t, session.appendBatch(context.Background(), batch(1), spoolStore))
	pending, err := spoolStore.Pending(context.Background(), spool.Metric, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Error(t, session.appendBatch(context.Background(), batch(2), spoolStore))
}

func TestAppendBatchReceiptSurvivesExporterAckGatewayStateLossAndRestart(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	spoolStore, err := spool.Open(filepath.Join(root, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spoolStore.Close()) })
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: spoolStore, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	batch := testBatch(now, 7, 1)
	require.NoError(t, session.appendBatch(context.Background(), batch, spoolStore))
	payload, id, err := normalizeBatch(batch, session.metricScope(batch), now)
	require.NoError(t, err)
	require.NoError(t, spoolStore.Ack(context.Background(), spool.Metric, id))

	restartedClient, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: spoolStore, Now: func() time.Time { return now }})
	require.NoError(t, err)
	restarted := configuredTestSession(restartedClient)
	require.NoError(t, restarted.appendBatch(context.Background(), batch, spoolStore))
	conflicting := testBatch(now, 7, 2)
	require.Error(t, restarted.appendBatch(context.Background(), conflicting, spoolStore))
	found, matches, err := spoolStore.Lookup(context.Background(), spool.Metric, id, payload)
	require.NoError(t, err)
	require.False(t, found)
	require.False(t, matches)
}

func TestAppendBatchRejectsForgedPluginDimensions(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	forged := testBatch(now, 7, 1)
	forged.PluginVersion = "9.9.9"
	require.Error(t, session.appendBatch(context.Background(), forged, &recordingMetricSink{}))
}

func configuredTestSession(client *Client) *Session {
	template := &pluginv1.MetricTemplateConfiguration{TemplateId: "builtin", Revision: 1, QueryDigest: bytes.Repeat([]byte{1}, 32), QueryKind: "sql", ReadOnlyStatement: "SELECT value", CollectionIntervalSeconds: 10, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, ValueMappings: []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: "mysql.connections.current", MetricType: "gauge", Unit: "1"}}, LabelMappings: []*pluginv1.MetricLabelMapping{{SourceColumn: "role", Label: "role"}}}
	return &Session{client: client, expected: ExpectedPlugin{AssignmentID: "assignment-1", PluginID: "mysql", Version: "1.0.0", DatabaseFamily: "mysql", InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}}, configurationRevision: 4, instances: map[string]*pluginv1.PluginInstanceConfiguration{"mysql-1": {InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", Templates: []*pluginv1.MetricTemplateConfiguration{template}}}}
}

func testBatch(now time.Time, sequence uint64, value float64) *pluginv1.PluginMetricBatch {
	return &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-1", ConfigurationRevision: 4, TemplateId: "builtin", TemplateRevision: 1, Sequence: sequence, CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: value, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
}

type recordingMetricSink struct{ batches []spool.Batch }

func (sink *recordingMetricSink) AppendWithCursor(_ context.Context, _ spool.DataClass, batch spool.Batch, _ spool.CursorReceipt) (spool.CursorAppendResult, error) {
	sink.batches = append(sink.batches, batch)
	return spool.CursorAppendStored, nil
}

func (sink *recordingMetricSink) Cursor(context.Context, string) (spool.CursorReceipt, bool, error) {
	return spool.CursorReceipt{}, false, nil
}
