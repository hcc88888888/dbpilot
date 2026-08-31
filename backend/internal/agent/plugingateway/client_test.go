package plugingateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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
	require.Len(t, cursors, 1)
	require.True(t, proto.Equal(&pluginv1.PluginMetricCursor{InstanceId: "mysql-1", TemplateId: "builtin", Sequence: 7}, cursors[0]))
	require.True(t, validAckResponse(&pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: cursors}, cursors))
	require.False(t, validAckResponse(&pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: []*pluginv1.PluginMetricCursor{{InstanceId: "mysql-1", TemplateId: "builtin", Sequence: 6}}}, cursors))
}

func TestPerKeyLaneKeepsConcurrentDurableACKsMonotonic(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store, err := spool.Open(filepath.Join(root, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: store, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	ackClient := newOrderedACKClient(7)
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() {
		firstDone <- session.appendAndAcknowledge(context.Background(), testBatch(now, 7, 1), store, ackClient)
	}()
	select {
	case <-ackClient.blocked:
	case err := <-firstDone:
		t.Fatalf("sequence 7 failed before ACK: %v", err)
	case <-time.After(time.Second):
		t.Fatal("sequence 7 did not reach ACK")
	}
	go func() {
		secondDone <- session.appendAndAcknowledge(context.Background(), testBatch(now, 8, 2), store, ackClient)
	}()
	select {
	case sequence := <-ackClient.called:
		t.Fatalf("ACK %d overtook blocked ACK 7", sequence)
	case <-time.After(50 * time.Millisecond):
	}
	close(ackClient.release)
	require.NoError(t, <-firstDone)
	require.NoError(t, <-secondDone)
	require.Equal(t, []uint64{7, 8}, ackClient.sequences())
}

func TestACKFailureRetainsReceiptAndExactRestartRetryReACKsWithoutAppend(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	limits := spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20}
	store, err := spool.Open(filepath.Join(root, "spool"), limits)
	require.NoError(t, err)
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: store, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	ackClient := newOrderedACKClient(0)
	ackClient.failNext = true
	require.Error(t, session.appendAndAcknowledge(context.Background(), testBatch(now, 7, 1), store, ackClient))
	require.NoError(t, store.Close())

	store, err = spool.Open(filepath.Join(root, "spool"), limits)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	restartedClient, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: store, Now: func() time.Time { return now }})
	require.NoError(t, err)
	restarted := configuredTestSession(restartedClient)
	require.NoError(t, restarted.appendAndAcknowledge(context.Background(), testBatch(now, 7, 1), store, ackClient))
	pending, err := store.Pending(context.Background(), spool.Metric, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1, "lost ACK retry must not append the durable sequence again")
	require.NoError(t, restarted.appendAndAcknowledge(context.Background(), testBatch(now, 8, 2), store, ackClient))
	require.Equal(t, []uint64{7, 7, 8}, ackClient.sequences())
}

func TestFailedACKDurablyFencesAlreadyQueuedNextSequence(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	store, err := spool.Open(filepath.Join(root, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: store, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	ackClient := newPendingFenceACKClient()
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	go func() {
		firstDone <- session.appendAndAcknowledge(context.Background(), testBatch(now, 7, 1), store, ackClient)
	}()
	<-ackClient.firstBlocked
	go func() {
		secondDone <- session.appendAndAcknowledge(context.Background(), testBatch(now, 8, 2), store, ackClient)
	}()
	close(ackClient.firstRelease)
	require.Error(t, <-firstDone)
	<-ackClient.retryBlocked
	pending, err := store.Pending(context.Background(), spool.Metric, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Contains(t, pending[0].ID, "-7")
	receipt, found, err := store.Cursor(context.Background(), "assignment-1\x004\x00builtin\x00mysql-1")
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, receipt.ACKPending)
	select {
	case sequence := <-ackClient.laterACK:
		t.Fatalf("ACK %d advanced while durable ACK 7 was pending", sequence)
	case <-time.After(50 * time.Millisecond):
	}
	close(ackClient.retryRelease)
	require.NoError(t, <-secondDone)
	require.Equal(t, []uint64{7, 7, 8}, ackClient.sequences())
	pending, err = store.Pending(context.Background(), spool.Metric, 10)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	receipt, found, err = store.Cursor(context.Background(), "assignment-1\x004\x00builtin\x00mysql-1")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(8), receipt.Sequence)
	require.False(t, receipt.ACKPending)
}

func TestCrashWindowAfterPluginACKBeforeDurableMarkSafelyReACKs(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	limits := spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20}
	store, err := spool.Open(filepath.Join(root, "spool"), limits)
	require.NoError(t, err)
	failingSink := &markFailingSink{Store: store, fail: true}
	client, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: failingSink, Now: func() time.Time { return now }})
	require.NoError(t, err)
	session := configuredTestSession(client)
	ackClient := newOrderedACKClient(0)
	require.Error(t, session.appendAndAcknowledge(context.Background(), testBatch(now, 7, 1), failingSink, ackClient))
	receipt, found, err := store.Cursor(context.Background(), "assignment-1\x004\x00builtin\x00mysql-1")
	require.NoError(t, err)
	require.True(t, found)
	require.True(t, receipt.ACKPending)
	require.NoError(t, store.Close())

	store, err = spool.Open(filepath.Join(root, "spool"), limits)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	restartedClient, err := NewClient(ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: store, Now: func() time.Time { return now }})
	require.NoError(t, err)
	restarted := configuredTestSession(restartedClient)
	require.NoError(t, restarted.appendAndAcknowledge(context.Background(), testBatch(now, 7, 1), store, ackClient))
	require.Equal(t, []uint64{7, 7}, ackClient.sequences())
	pending, err := store.Pending(context.Background(), spool.Metric, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
}

type markFailingSink struct {
	*spool.Store
	fail bool
}

func (sink *markFailingSink) MarkCursorAcknowledged(ctx context.Context, key string, sequence uint64) error {
	if sink.fail {
		sink.fail = false
		return errors.New("injected durable ACK mark failure")
	}
	return sink.Store.MarkCursorAcknowledged(ctx, key, sequence)
}

type pendingFenceACKClient struct {
	orderedACKClient
	firstBlocked chan struct{}
	firstRelease chan struct{}
	retryBlocked chan struct{}
	retryRelease chan struct{}
	laterACK     chan uint64
}

func newPendingFenceACKClient() *pendingFenceACKClient {
	return &pendingFenceACKClient{orderedACKClient: *newOrderedACKClient(0), firstBlocked: make(chan struct{}), firstRelease: make(chan struct{}), retryBlocked: make(chan struct{}), retryRelease: make(chan struct{}), laterACK: make(chan uint64, 1)}
}

func (client *pendingFenceACKClient) AcknowledgeMetrics(_ context.Context, request *pluginv1.AcknowledgePluginMetricsRequest, _ ...grpc.CallOption) (*pluginv1.AcknowledgePluginMetricsResponse, error) {
	sequence := request.GetCursors()[0].GetSequence()
	client.mu.Lock()
	client.acks = append(client.acks, sequence)
	call := len(client.acks)
	client.mu.Unlock()
	switch call {
	case 1:
		close(client.firstBlocked)
		<-client.firstRelease
		return nil, errors.New("injected ACK response loss")
	case 2:
		close(client.retryBlocked)
		<-client.retryRelease
	default:
		client.laterACK <- sequence
	}
	return &pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: request.GetCursors()}, nil
}

type orderedACKClient struct {
	mu            sync.Mutex
	acks          []uint64
	blockSequence uint64
	blocked       chan struct{}
	release       chan struct{}
	called        chan uint64
	failNext      bool
}

func newOrderedACKClient(block uint64) *orderedACKClient {
	return &orderedACKClient{blockSequence: block, blocked: make(chan struct{}), release: make(chan struct{}), called: make(chan uint64, 8)}
}
func (client *orderedACKClient) AcknowledgeMetrics(_ context.Context, request *pluginv1.AcknowledgePluginMetricsRequest, _ ...grpc.CallOption) (*pluginv1.AcknowledgePluginMetricsResponse, error) {
	sequence := request.GetCursors()[0].GetSequence()
	client.mu.Lock()
	client.acks = append(client.acks, sequence)
	fail := client.failNext
	client.failNext = false
	client.mu.Unlock()
	if sequence == client.blockSequence {
		close(client.blocked)
		<-client.release
	} else {
		client.called <- sequence
	}
	if fail {
		return nil, errors.New("injected ACK loss")
	}
	return &pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: request.GetCursors()}, nil
}
func (client *orderedACKClient) sequences() []uint64 {
	client.mu.Lock()
	defer client.mu.Unlock()
	return append([]uint64(nil), client.acks...)
}
func (*orderedACKClient) Handshake(context.Context, *pluginv1.PluginHandshakeRequest, ...grpc.CallOption) (*pluginv1.PluginHandshakeResponse, error) {
	return nil, errors.New("unused")
}
func (*orderedACKClient) ApplyConfiguration(context.Context, *pluginv1.ApplyPluginConfigurationRequest, ...grpc.CallOption) (*pluginv1.ApplyPluginConfigurationResponse, error) {
	return nil, errors.New("unused")
}
func (*orderedACKClient) ValidateInstance(context.Context, *pluginv1.ValidatePluginInstanceRequest, ...grpc.CallOption) (*pluginv1.ValidatePluginInstanceResponse, error) {
	return nil, errors.New("unused")
}
func (*orderedACKClient) CollectNow(context.Context, *pluginv1.CollectPluginMetricsRequest, ...grpc.CallOption) (*pluginv1.CollectPluginMetricsResponse, error) {
	return nil, errors.New("unused")
}
func (*orderedACKClient) StreamMetrics(context.Context, *pluginv1.StreamPluginMetricsRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[pluginv1.PluginMetricBatch], error) {
	return nil, errors.New("unused")
}
func (*orderedACKClient) GetHealth(context.Context, *pluginv1.GetPluginHealthRequest, ...grpc.CallOption) (*pluginv1.PluginHealth, error) {
	return nil, errors.New("unused")
}
func (*orderedACKClient) Shutdown(context.Context, *pluginv1.ShutdownPluginRequest, ...grpc.CallOption) (*pluginv1.ShutdownPluginResponse, error) {
	return nil, errors.New("unused")
}

func TestResumeCursorsSupportsCanonicalPairCapacityDeterministically(t *testing.T) {
	for _, dimensions := range [][2]int{{2, 65}, {128, 128}} {
		t.Run(fmt.Sprintf("%dx%d", dimensions[0], dimensions[1]), func(t *testing.T) {
			instances, templates := canonicalPairFixture(dimensions[0], dimensions[1])
			session := &Session{expected: ExpectedPlugin{AssignmentID: "assignment-1", InstanceIDs: mapInstanceIDs(instances), TemplateIDs: mapTemplateIDs(templates)}, configurationRevision: 4, instances: instances}
			cursors, err := session.resumeCursors(context.Background(), allCursorSink{})
			require.NoError(t, err)
			require.Len(t, cursors, dimensions[0]*dimensions[1])
			require.Equal(t, "instance-000", cursors[0].GetInstanceId())
			require.Equal(t, "template-000", cursors[0].GetTemplateId())
			last := cursors[len(cursors)-1]
			require.Equal(t, fmt.Sprintf("instance-%03d", dimensions[0]-1), last.GetInstanceId())
			require.Equal(t, fmt.Sprintf("template-%03d", dimensions[1]-1), last.GetTemplateId())
			request := &pluginv1.StreamPluginMetricsRequest{AssignmentId: "assignment-1", ConfigurationRevision: 4, ResumeCursors: cursors}
			require.LessOrEqual(t, proto.Size(request), maxRPCMessageBytes)
		})
	}
}

func TestConfigurationSupportsCanonical128x128AndRejectsOverByteProjection(t *testing.T) {
	instances, templates := canonicalPairFixture(128, 128)
	expected := ExpectedPlugin{AssignmentID: "assignment-1", ConfigurationRevision: 4, InstanceIDs: mapInstanceIDs(instances), TemplateIDs: mapTemplateIDs(templates), TemplateConfigurations: templates}
	configuration := PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: mapInstances(instances)}
	require.NoError(t, configuration.validate(expected))
	request := canonicalApplyRequest(configuration)
	require.LessOrEqual(t, proto.Size(request), maxRPCMessageBytes)

	oversizedInstancesBase, oversizedTemplates := canonicalPairFixture(2, 65)
	for _, template := range oversizedTemplates {
		template.ReadOnlyStatement = "SELECT '" + string(bytes.Repeat([]byte{'x'}, 40<<10)) + "'"
	}
	oversizedInstances := make(map[string]*pluginv1.PluginInstanceConfiguration, len(oversizedInstancesBase))
	for id, instance := range oversizedInstancesBase {
		copy := proto.Clone(instance).(*pluginv1.PluginInstanceConfiguration)
		copy.Templates = cloneTemplateConfigurations(oversizedTemplates)
		oversizedInstances[id] = copy
	}
	expected.InstanceIDs = mapInstanceIDs(oversizedInstances)
	expected.TemplateIDs = mapTemplateIDs(oversizedTemplates)
	expected.TemplateConfigurations = oversizedTemplates
	require.Error(t, (PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: mapInstances(oversizedInstances)}).validate(expected))
}

func TestCollectEnvelopeSupportsCanonicalMaximumAndRejectsOverByteBeforeAdmission(t *testing.T) {
	instances, templates := canonicalPairFixture(128, 128)
	instanceIDs, templateIDs := mapInstanceIDs(instances), mapTemplateIDs(templates)
	sort.Sort(sort.Reverse(sort.StringSlice(instanceIDs)))
	sort.Sort(sort.Reverse(sort.StringSlice(templateIDs)))
	request := canonicalCollectRequest("assignment-1", 4, instanceIDs, templateIDs)
	require.Equal(t, "instance-000", request.GetInstanceIds()[0])
	require.Equal(t, "template-000", request.GetTemplateIds()[0])
	require.LessOrEqual(t, proto.Size(request), maxRPCMessageBytes)

	response := &pluginv1.CollectPluginMetricsResponse{Batches: make([]*pluginv1.PluginMetricBatch, 0, maxConfiguredPairs)}
	for _, instanceID := range request.GetInstanceIds() {
		for _, templateID := range request.GetTemplateIds() {
			response.Batches = append(response.Batches, &pluginv1.PluginMetricBatch{InstanceId: instanceID, TemplateId: templateID, Sequence: 1})
		}
	}
	require.True(t, validCollectResponseEnvelope(response, maxConfiguredPairs))
	require.LessOrEqual(t, proto.Size(response), maxRPCMessageBytes)
	response.Batches[0].ErrorCode = string(bytes.Repeat([]byte{'x'}, maxRPCMessageBytes))
	require.False(t, validCollectResponseEnvelope(response, maxConfiguredPairs), "oversized response must be rejected before any spool append")
}

type allCursorSink struct{}

func (allCursorSink) AppendWithCursor(context.Context, spool.DataClass, spool.Batch, spool.CursorReceipt) (spool.CursorAppendResult, error) {
	return spool.CursorAppendStored, nil
}
func (allCursorSink) Cursor(_ context.Context, key string) (spool.CursorReceipt, bool, error) {
	return spool.CursorReceipt{Key: key, Sequence: 1, Digest: bytes.Repeat([]byte{1}, 32), CollectedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}, true, nil
}
func (allCursorSink) MarkCursorAcknowledged(context.Context, string, uint64) error { return nil }

func canonicalPairFixture(instanceCount, templateCount int) (map[string]*pluginv1.PluginInstanceConfiguration, []*pluginv1.MetricTemplateConfiguration) {
	templates := make([]*pluginv1.MetricTemplateConfiguration, templateCount)
	for index := range templates {
		templates[index] = &pluginv1.MetricTemplateConfiguration{TemplateId: fmt.Sprintf("template-%03d", index), Revision: 1, QueryDigest: bytes.Repeat([]byte{byte(index + 1)}, 32), QueryKind: "sql", ReadOnlyStatement: "SELECT value", CollectionIntervalSeconds: 10, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, ValueMappings: []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: fmt.Sprintf("mysql.metric_%03d", index), MetricType: "gauge", Unit: "1"}}}
	}
	instances := make(map[string]*pluginv1.PluginInstanceConfiguration, instanceCount)
	for index := 0; index < instanceCount; index++ {
		id := fmt.Sprintf("instance-%03d", index)
		instances[id] = &pluginv1.PluginInstanceConfiguration{InstanceId: id, DatabaseVariant: "mysql", Endpoint: fmt.Sprintf("127.0.0.1:%d", 3306+index), Templates: cloneTemplateConfigurations(templates)}
	}
	return instances, templates
}

func mapInstanceIDs(values map[string]*pluginv1.PluginInstanceConfiguration) []string {
	result := make([]string, 0, len(values))
	for id := range values {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}
func mapTemplateIDs(values []*pluginv1.MetricTemplateConfiguration) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.GetTemplateId()
	}
	return result
}
func mapInstances(values map[string]*pluginv1.PluginInstanceConfiguration) []*pluginv1.PluginInstanceConfiguration {
	ids := mapInstanceIDs(values)
	result := make([]*pluginv1.PluginInstanceConfiguration, len(ids))
	for index, id := range ids {
		result[index] = values[id]
	}
	return result
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

func TestCredentialConfigurationIsScrubbedAndNeverRetainedInSessionState(t *testing.T) {
	secret := []byte("fixture-password")
	instances := []*pluginv1.PluginInstanceConfiguration{{InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", CredentialLease: &pluginv1.CredentialLease{LeaseId: "lease-1", CredentialRevision: 9, Username: "monitor", SecretBytes: secret, ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}}}
	request := &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: "assignment-1", ConfigurationRevision: 5, Instances: cloneInstances(instances)}
	retained := cloneInstancesWithoutCredentials(instances)
	require.Nil(t, retained[0].GetCredentialLease())
	wireBuffer := request.GetInstances()[0].GetCredentialLease().GetSecretBytes()
	clearConfigurationSecrets(request)
	require.Equal(t, make([]byte, len(wireBuffer)), wireBuffer)
	require.Empty(t, request.GetInstances()[0].GetCredentialLease().GetSecretBytes())
	require.Empty(t, request.GetInstances()[0].GetCredentialLease().GetUsername())
	require.True(t, validCredentialLease(instances[0].GetCredentialLease()))
	instances[0].CredentialLease.SecretBytes = bytes.Repeat([]byte{'x'}, (64<<10)+1)
	require.False(t, validCredentialLease(instances[0].GetCredentialLease()))
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
	return &Session{client: client, expected: ExpectedPlugin{AssignmentID: "assignment-1", PluginID: "mysql", Version: "1.0.0", DatabaseFamily: "mysql", ConfigurationRevision: 4, InstanceIDs: []string{"mysql-1"}, TemplateIDs: []string{"builtin"}}, configurationRevision: 4, instances: map[string]*pluginv1.PluginInstanceConfiguration{"mysql-1": {InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", Templates: []*pluginv1.MetricTemplateConfiguration{template}}}}
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
func (sink *recordingMetricSink) MarkCursorAcknowledged(context.Context, string, uint64) error {
	return nil
}
