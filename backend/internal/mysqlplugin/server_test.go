package mysqlplugin

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"dbpilot.local/platform/internal/plugincontract"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestServerApplyValidateHealthAndCredentialRemovalRecovery(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", OperationRevision: 9, Runtime: NewRuntime(&fakePoolFactory{}, RuntimeOptions{}), Parser: NewMySQLStatementParser(), Now: func() time.Time { return now }})
	request := &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{fixtureInstance("mysql-a", "127.0.0.1:33061", "monitor-a", []byte("secret-a"), now.Add(time.Minute)), fixtureInstance("mysql-b", "127.0.0.1:33062", "monitor-b", []byte("secret-b"), now.Add(time.Minute))}}
	response, err := server.ApplyConfiguration(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, uint64(4), response.GetActiveConfigurationRevision())
	require.Len(t, response.GetResults(), 2)
	require.Equal(t, make([]byte, len("secret-a")), request.Instances[0].CredentialLease.SecretBytes)
	health, err := server.GetHealth(context.Background(), &pluginv1.GetPluginHealthRequest{AssignmentId: "assignment-a"})
	require.NoError(t, err)
	require.Equal(t, uint32(2), health.GetBoundInstanceCount())

	remove := &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{{InstanceId: "mysql-a", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:33061"}, fixtureInstance("mysql-b", "127.0.0.1:33062", "monitor-b", []byte("secret-b"), now.Add(time.Minute))}}
	_, err = server.ApplyConfiguration(context.Background(), remove)
	require.NoError(t, err)
	validation, err := server.ValidateInstance(context.Background(), &pluginv1.ValidatePluginInstanceRequest{AssignmentId: "assignment-a", InstanceId: "mysql-a", ConfigurationRevision: 4})
	require.NoError(t, err)
	require.False(t, validation.GetValid())
	require.Equal(t, "waiting_credentials", validation.GetErrorCode())

	recoverRequest := &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{fixtureInstance("mysql-a", "127.0.0.1:33061", "monitor-a", []byte("new-secret"), now.Add(time.Minute)), fixtureInstance("mysql-b", "127.0.0.1:33062", "monitor-b", []byte("secret-b"), now.Add(time.Minute))}}
	_, err = server.ApplyConfiguration(context.Background(), recoverRequest)
	require.NoError(t, err)
	validation, err = server.ValidateInstance(context.Background(), &pluginv1.ValidatePluginInstanceRequest{AssignmentId: "assignment-a", InstanceId: "mysql-a", ConfigurationRevision: 4})
	require.NoError(t, err)
	require.True(t, validation.GetValid())
}

func TestServerHandshakeAdvertisesFiveDigestVerifiedBuiltinDescriptorsWithoutSQL(t *testing.T) {
	nonce := make([]byte, sha256.Size)
	challenge := make([]byte, sha256.Size)
	digest := make([]byte, sha256.Size)
	for index := range nonce {
		nonce[index] = 1
		challenge[index] = 2
		digest[index] = 3
	}
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", Version: "1.0.0", ConfigurationRevision: 4, OperationRevision: 9, ExpectedInstanceIDs: []string{"mysql-a"}, ExecutableDigest: digest, LaunchNonce: nonce})
	response, err := server.Handshake(context.Background(), &pluginv1.PluginHandshakeRequest{ExpectedPluginId: "mysql", ExpectedDatabaseFamily: "mysql", ExpectedVersion: "1.0.0", ExpectedProtocolVersion: "v1", LaunchNonceChallenge: challenge})
	require.NoError(t, err)
	require.Len(t, response.GetBuiltinTemplates(), 5)
	validated, ok := plugincontract.ValidateBuiltinDescriptors(response.GetBuiltinTemplates(), nil)
	require.True(t, ok)
	require.Len(t, validated, 5)
	require.Equal(t, pluginsupervisor.LaunchProof(nonce, challenge, "assignment-a", "1.0.0", 4, 9, []string{"mysql-a"}), response.GetLaunchNonceProof())
	require.NotContains(t, response.String(), "SELECT")
	require.NotContains(t, response.String(), "statement")
}

func TestServerTrialUsesDedicatedBoundedPathAndReturnsOnlyMappedMetrics(t *testing.T) {
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 4}, map[string]InstanceRuntime{"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "monitor"), Pool: &trialPool{}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", OperationRevision: 9, Runtime: runtime, Parser: NewMySQLStatementParser(), Now: func() time.Time { return now }})
	statement := []byte("SELECT 7 AS value, 'primary' AS role_name")
	digest := sha256.Sum256(statement)
	response, err := server.TrialMetricTemplate(context.Background(), &pluginv1.TrialMetricTemplateRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, OperationRevision: 9, InstanceId: "mysql-a", Template: &pluginv1.TrialMetricTemplateDefinition{TemplateId: "custom-a", Revision: 2, QueryDigest: digest[:], QueryKind: "sql", ReadOnlyStatement: statement, CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, CardinalityLimit: 10, ValueMappings: []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}, LabelMappings: []*pluginv1.MetricLabelMapping{{SourceColumn: "role_name", Label: "role"}}}})
	require.NoError(t, err)
	require.True(t, response.GetSucceeded())
	require.Equal(t, uint32(1), response.GetRowCount())
	require.Equal(t, uint32(2), response.GetColumnCount())
	require.Len(t, response.GetCandidateMetrics(), 1)
	require.Equal(t, "mysql.custom.value", response.GetCandidateMetrics()[0].GetMetricName())
	require.Equal(t, map[string]string{"role": "primary"}, response.GetCandidateMetrics()[0].GetLabels())
	require.NotContains(t, response.String(), "primary AS")
}

func TestStreamTreatsResumeAsAuthoritativeAndAckIsAtomicForBoundPairs(t *testing.T) {
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 4}, map[string]InstanceRuntime{"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "monitor"), Pool: &statusPool{}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", ConfigurationRevision: 4, OperationRevision: 9, Runtime: runtime, StreamInterval: time.Millisecond})
	cursors := make([]*pluginv1.PluginMetricCursor, 0, 5)
	for _, id := range SortedBuiltinTemplateIDs(BuiltinCatalog()) {
		cursors = append(cursors, &pluginv1.PluginMetricCursor{InstanceId: "mysql-a", TemplateId: id, Sequence: 41})
	}
	ctx, cancel := context.WithCancel(context.Background())
	stream := &captureMetricStream{ctx: ctx, cancel: cancel, want: 5}
	err := server.StreamMetrics(&pluginv1.StreamPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, ResumeCursors: cursors}, stream)
	require.ErrorIs(t, err, context.Canceled)
	require.Len(t, stream.batches, 5)
	for _, batch := range stream.batches {
		require.Equal(t, uint64(42), batch.GetSequence())
	}
	lagging := make([]*pluginv1.PluginMetricCursor, 0, len(cursors))
	for _, cursor := range cursors {
		lagging = append(lagging, &pluginv1.PluginMetricCursor{InstanceId: cursor.GetInstanceId(), TemplateId: cursor.GetTemplateId(), Sequence: 40})
	}
	err = server.StreamMetrics(&pluginv1.StreamPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, ResumeCursors: lagging}, &captureMetricStream{ctx: context.Background()})
	require.EqualError(t, err, "stream_rejected")

	valid := &pluginv1.PluginMetricCursor{InstanceId: "mysql-a", TemplateId: "mysql.up", Sequence: 42}
	invalid := &pluginv1.PluginMetricCursor{InstanceId: "mysql-a", TemplateId: "unbound", Sequence: 0}
	response, err := server.AcknowledgeMetrics(context.Background(), &pluginv1.AcknowledgePluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, Cursors: []*pluginv1.PluginMetricCursor{valid, invalid}})
	require.NoError(t, err)
	require.Equal(t, "cursor_rejected", response.GetErrorCode())
	require.Equal(t, uint64(41), server.acknowledged[cursorKey("mysql-a", "mysql.up")])
	response, err = server.AcknowledgeMetrics(context.Background(), &pluginv1.AcknowledgePluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, Cursors: []*pluginv1.PluginMetricCursor{valid}})
	require.NoError(t, err)
	require.Empty(t, response.GetErrorCode())
	require.Equal(t, uint64(42), server.acknowledged[cursorKey("mysql-a", "mysql.up")])
}

func TestCollectNowRejectsUnboundAndDuplicatePairsWithoutGrowingPending(t *testing.T) {
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "monitor"), Pool: &statusPool{}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", Runtime: runtime})
	for index := 0; index < 100; index++ {
		_, err := server.CollectNow(context.Background(), &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, InstanceIds: []string{"mysql-a"}, TemplateIds: []string{fmt.Sprintf("unknown-%d", index)}})
		require.Error(t, err)
	}
	_, err := server.CollectNow(context.Background(), &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, InstanceIds: []string{"mysql-a", "mysql-a"}, TemplateIds: []string{"mysql.up"}})
	require.Error(t, err)
	server.mu.Lock()
	defer server.mu.Unlock()
	require.Empty(t, server.pending)
	require.Empty(t, server.sequences)
}

func TestPerPairPendingBacklogReplaysExactPayloadAcrossLostAppendAndResume(t *testing.T) {
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 4}, map[string]InstanceRuntime{"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "monitor"), Pool: &statusPool{}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", ConfigurationRevision: 4, Runtime: runtime})
	request := &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, InstanceIds: []string{"mysql-a"}, TemplateIds: []string{"mysql.up"}}
	first, err := server.CollectNow(context.Background(), request)
	require.NoError(t, err)
	require.Len(t, first.GetBatches(), 1)
	retry, err := server.CollectNow(context.Background(), request)
	require.NoError(t, err)
	require.True(t, proto.Equal(first.GetBatches()[0], retry.GetBatches()[0]), "Append-before-ACK retry must replay exact payload")
	resume := make([]*pluginv1.PluginMetricCursor, 0, 5)
	for _, id := range SortedBuiltinTemplateIDs(BuiltinCatalog()) {
		sequence := uint64(0)
		if id == "mysql.up" {
			sequence = first.GetBatches()[0].GetSequence() - 1
		}
		resume = append(resume, &pluginv1.PluginMetricCursor{InstanceId: "mysql-a", TemplateId: id, Sequence: sequence})
	}
	replay, err := server.prepareResume(resume)
	require.NoError(t, err)
	require.Len(t, replay, 1)
	require.True(t, proto.Equal(first.GetBatches()[0], replay[0]))
	durable := proto.Clone(resume[3]).(*pluginv1.PluginMetricCursor)
	for _, cursor := range resume {
		if cursor.GetTemplateId() == "mysql.up" {
			cursor.Sequence = first.GetBatches()[0].GetSequence()
		}
	}
	replay, err = server.prepareResume(resume)
	require.NoError(t, err)
	require.Empty(t, replay)
	_, err = server.prepareResume(append([]*pluginv1.PluginMetricCursor(nil), durable))
	require.Error(t, err)
	ack := &pluginv1.AcknowledgePluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, Cursors: []*pluginv1.PluginMetricCursor{{InstanceId: "mysql-a", TemplateId: "mysql.up", Sequence: first.GetBatches()[0].GetSequence()}}}
	response, err := server.AcknowledgeMetrics(context.Background(), ack)
	require.NoError(t, err)
	require.Empty(t, response.GetErrorCode())
	response, err = server.AcknowledgeMetrics(context.Background(), ack)
	require.NoError(t, err)
	require.Empty(t, response.GetErrorCode(), "lost ACK response retry must be idempotent")
	next, err := server.CollectNow(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, first.GetBatches()[0].GetSequence()+1, next.GetBatches()[0].GetSequence())
	apply := &pluginv1.ApplyPluginConfigurationRequest{AssignmentId: "assignment-a", ConfigurationRevision: 5, Instances: []*pluginv1.PluginInstanceConfiguration{fixtureInstance("mysql-a", "127.0.0.1:3306", "monitor", []byte("rotated"), time.Now().Add(time.Minute))}}
	applied, err := server.ApplyConfiguration(context.Background(), apply)
	require.NoError(t, err)
	require.Empty(t, applied.GetErrorCode())
	server.mu.Lock()
	require.Empty(t, server.pending, "configuration revision change must prune old backlog")
	server.mu.Unlock()
}

func TestPendingBacklogBoundsOversizeLegalShapeAndMultiBatchEnvelope(t *testing.T) {
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	instance := fixtureDecodedInstance("mysql-a", "monitor")
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{"mysql-a": {Config: instance, Pool: &statusPool{}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", Runtime: runtime})
	labels := map[string]string{}
	for index := 0; index < 16; index++ {
		labels[fmt.Sprintf("label_%02d", index)] = strings.Repeat("x", 128)
	}
	samples := make([]Sample, 0, 100*32)
	for row := 0; row < 100; row++ {
		for mapping := 0; mapping < 32; mapping++ {
			samples = append(samples, Sample{Name: fmt.Sprintf("mysql.custom.metric_%02d", mapping), Value: float64(row), Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Labels: labels, SampledAt: time.Now().UTC()})
		}
	}
	oversize := server.wireBatch(runtime.values["mysql-a"], "mysql.up", 1, Batch{InstanceID: "mysql-a", Samples: samples, Status: CollectionSucceeded, CollectedAt: time.Now().UTC()}, CollectionSucceeded, "")
	require.Less(t, proto.Size(oversize), maxPluginBatchBytes)
	require.Empty(t, oversize.GetSamples())
	require.Equal(t, pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_FAILED, oversize.GetCollectionStatus())
	require.Equal(t, "result_limit_exceeded", oversize.GetErrorCode())
	require.LessOrEqual(t, server.pendingBytes, maxPendingBytes)
	retry := server.pendingBatch("mysql-a", "mysql.up")
	require.True(t, proto.Equal(oversize, retry))
	server.mu.Lock()
	server.pending = map[string]*pluginv1.PluginMetricBatch{}
	server.pendingBytes = 0
	server.sequences = map[string]uint64{}
	server.mu.Unlock()
	large := func(template string) *pluginv1.PluginMetricBatch {
		batch := &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: "mysql-a", ConfigurationRevision: 1, TemplateId: template, TemplateRevision: 1, CollectedAt: timestamppb.Now(), Sequence: 1, CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED}
		for proto.Size(batch) < (5<<20)/2 {
			for index := 0; index < 1024; index++ {
				batch.Samples = append(batch.Samples, &pluginv1.PluginMetricSample{MetricName: "mysql.up", Value: 1, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Labels: map[string]string{"payload": strings.Repeat("x", 128)}, SampledAt: timestamppb.Now()})
			}
		}
		require.Less(t, proto.Size(batch), maxPluginBatchBytes)
		return batch
	}
	first, second := large("mysql.up"), large("mysql.connections.current")
	server.mu.Lock()
	server.pending[cursorKey("mysql-a", "mysql.up")] = first
	server.pending[cursorKey("mysql-a", "mysql.connections.current")] = second
	server.sequences[cursorKey("mysql-a", "mysql.up")] = 1
	server.sequences[cursorKey("mysql-a", "mysql.connections.current")] = 1
	server.pendingBytes = proto.Size(first) + proto.Size(second)
	before := server.pendingBytes
	server.mu.Unlock()
	_, err := server.CollectNow(context.Background(), &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, InstanceIds: []string{"mysql-a"}, TemplateIds: []string{"mysql.up", "mysql.connections.current"}})
	require.Error(t, err)
	server.mu.Lock()
	require.Equal(t, before, server.pendingBytes)
	require.Len(t, server.pending, 2)
	server.mu.Unlock()
	for _, template := range []string{"mysql.up", "mysql.connections.current"} {
		response, collectErr := server.CollectNow(context.Background(), &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, InstanceIds: []string{"mysql-a"}, TemplateIds: []string{template}})
		require.NoError(t, collectErr)
		require.Len(t, response.GetBatches(), 1)
		require.Less(t, proto.Size(response), maxPluginRPCMessageBytes)
	}
}

func TestOversizeCollectResponseRollsBackOnlyNewPendingBytes(t *testing.T) {
	columns := make([]string, 0, 26)
	valueMappings := make([]*pluginv1.MetricValueMapping, 0, 10)
	labelMappings := make([]*pluginv1.MetricLabelMapping, 0, 16)
	for index := 0; index < 10; index++ {
		name := fmt.Sprintf("value_%02d", index)
		columns = append(columns, name)
		valueMappings = append(valueMappings, &pluginv1.MetricValueMapping{SourceColumn: name, MetricName: fmt.Sprintf("mysql.custom.metric_%02d", index), MetricType: "gauge", Unit: "1"})
	}
	for index := 0; index < 16; index++ {
		name := fmt.Sprintf("label_%02d", index)
		columns = append(columns, name)
		labelMappings = append(labelMappings, &pluginv1.MetricLabelMapping{SourceColumn: name, Label: name})
	}
	values := make([][]any, 100)
	for row := range values {
		values[row] = make([]any, len(columns))
		for index := 0; index < 10; index++ {
			values[row][index] = []byte(strconv.Itoa(row + index + 1))
		}
		for index := 10; index < len(columns); index++ {
			values[row][index] = []byte(strings.Repeat("x", 128))
		}
	}
	template := func(id string) TemplateConfig {
		return TemplateConfig{ID: id, Revision: 1, Statement: "SELECT bounded", Timeout: time.Second, MaxRows: 100, MaxColumns: 32, Cardinality: 10000, ValueMappings: valueMappings, LabelMappings: labelMappings}
	}
	instance := fixtureDecodedInstance("mysql-a", "monitor")
	instance.Templates = map[string]TemplateConfig{"custom-a": template("custom-a"), "custom-b": template("custom-b")}
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{"mysql-a": {Config: instance, Pool: &customRowsPool{columns: columns, values: values}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", Runtime: runtime})
	_, err := server.CollectNow(context.Background(), &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, InstanceIds: []string{"mysql-a"}, TemplateIds: []string{"custom-a", "custom-b"}})
	require.Error(t, err)
	server.mu.Lock()
	defer server.mu.Unlock()
	require.Empty(t, server.pending)
	require.Zero(t, server.pendingBytes)
	require.Zero(t, server.sequences[cursorKey("mysql-a", "custom-a")])
	require.Zero(t, server.sequences[cursorKey("mysql-a", "custom-b")])
}

func TestShutdownStopsActiveStreamsBeforeClosingRuntime(t *testing.T) {
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 4}, map[string]InstanceRuntime{"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "monitor"), Pool: &statusPool{}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", ConfigurationRevision: 4, OperationRevision: 9, Runtime: runtime, StreamInterval: time.Hour})
	cursors := make([]*pluginv1.PluginMetricCursor, 0, 5)
	for _, id := range SortedBuiltinTemplateIDs(BuiltinCatalog()) {
		cursors = append(cursors, &pluginv1.PluginMetricCursor{InstanceId: "mysql-a", TemplateId: id})
	}
	stream := &captureMetricStream{ctx: context.Background(), header: make(chan struct{})}
	streamDone := make(chan error, 1)
	go func() {
		streamDone <- server.StreamMetrics(&pluginv1.StreamPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 4, ResumeCursors: cursors}, stream)
	}()
	<-stream.header
	response, err := server.Shutdown(context.Background(), &pluginv1.ShutdownPluginRequest{AssignmentId: "assignment-a", DrainTimeoutSeconds: 1})
	require.NoError(t, err)
	require.True(t, response.GetDrained())
	require.NoError(t, <-(streamDone))
	require.Empty(t, runtime.Instances())
}

func TestValidateInstanceAcceptsOnlyMySQLEight(t *testing.T) {
	tests := []struct {
		name, version, edition, code string
		valid                        bool
	}{{"mysql8", "8.4.0", "MySQL Community Server", "", true}, {"mysql5", "5.7.44", "MySQL Community Server", "unsupported_database", false}, {"mariadb", "8.0.0-MariaDB", "MariaDB Server", "unsupported_database", false}, {"tidb", "8.0.11-TiDB-v8.5.0", "TiDB Server", "unsupported_database", false}, {"oceanbase", "8.0.30-OceanBase", "OceanBase", "unsupported_database", false}}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
			runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "monitor"), Pool: &versionPool{version: test.version, edition: test.edition}}})
			server := NewServer(ServerConfig{AssignmentID: "assignment-a", OperationRevision: 1, Runtime: runtime})
			response, err := server.ValidateInstance(context.Background(), &pluginv1.ValidatePluginInstanceRequest{AssignmentId: "assignment-a", InstanceId: "mysql-a", ConfigurationRevision: 1})
			require.NoError(t, err)
			require.Equal(t, test.valid, response.GetValid())
			require.Equal(t, test.code, response.GetErrorCode())
		})
	}
}

func TestCollectNowKeepsSuccessfulUpBatchWhenStatusQueryFails(t *testing.T) {
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "monitor"), Pool: &queryFailurePool{}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", Runtime: runtime})
	response, err := server.CollectNow(context.Background(), &pluginv1.CollectPluginMetricsRequest{AssignmentId: "assignment-a", ConfigurationRevision: 1, InstanceIds: []string{"mysql-a"}, TemplateIds: []string{"mysql.up", "mysql.connections.current"}})
	require.NoError(t, err)
	require.Len(t, response.GetBatches(), 2)
	byID := map[string]*pluginv1.PluginMetricBatch{}
	for _, batch := range response.GetBatches() {
		byID[batch.GetTemplateId()] = batch
	}
	require.Equal(t, pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, byID["mysql.up"].GetCollectionStatus())
	require.Empty(t, byID["mysql.up"].GetErrorCode())
	require.Equal(t, float64(1), byID["mysql.up"].GetSamples()[0].GetValue())
	require.NotEqual(t, pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, byID["mysql.connections.current"].GetCollectionStatus())
}

func TestHealthReflectsLastCollectionAndPerInstanceCircuit(t *testing.T) {
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{"mysql-a": {Config: fixtureDecodedInstance("mysql-a", "monitor"), Pool: &fakePool{pingErr: errors.New("down")}}, "mysql-b": {Config: fixtureDecodedInstance("mysql-b", "monitor"), Pool: &statusPool{}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", Runtime: runtime, Collector: NewCollector(runtime, CollectorOptions{FailureThreshold: 1, CircuitOpenFor: time.Minute})})
	server.collector.Collect(context.Background(), "mysql-a", []string{"mysql.up"})
	server.collector.Collect(context.Background(), "mysql-b", []string{"mysql.up"})
	health, err := server.GetHealth(context.Background(), &pluginv1.GetPluginHealthRequest{AssignmentId: "assignment-a"})
	require.NoError(t, err)
	byID := map[string]*pluginv1.PluginInstanceHealth{}
	for _, instance := range health.GetInstances() {
		byID[instance.GetInstanceId()] = instance
	}
	require.Equal(t, pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_UNHEALTHY, byID["mysql-a"].GetState())
	require.Equal(t, "circuit_open", byID["mysql-a"].GetErrorCode())
	require.Equal(t, pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY, byID["mysql-b"].GetState())
	require.Equal(t, pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_UNHEALTHY, health.GetState())
}

func TestTemplateScheduleUsesBuiltinAndPerInstanceCustomIntervals(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	instance := fixtureDecodedInstance("mysql-a", "monitor")
	instance.Templates = map[string]TemplateConfig{"custom-a": {ID: "custom-a", Revision: 1, Interval: 60 * time.Second}}
	runtime := NewRuntime(&fakePoolFactory{}, RuntimeOptions{})
	runtime.replaceForTest(Config{AssignmentID: "assignment-a", Revision: 1}, map[string]InstanceRuntime{"mysql-a": {Config: instance, Pool: &statusPool{}}})
	server := NewServer(ServerConfig{AssignmentID: "assignment-a", Runtime: runtime})
	require.ElementsMatch(t, append(SortedBuiltinTemplateIDs(BuiltinCatalog()), "custom-a"), server.dueTemplateIDs(instance, now))
	server.markScheduled(instance, append(SortedBuiltinTemplateIDs(BuiltinCatalog()), "custom-a"), now)
	require.Empty(t, server.dueTemplateIDs(instance, now.Add(9*time.Second)))
	require.ElementsMatch(t, SortedBuiltinTemplateIDs(BuiltinCatalog()), server.dueTemplateIDs(instance, now.Add(10*time.Second)))
	require.Contains(t, server.dueTemplateIDs(instance, now.Add(60*time.Second)), "custom-a")
}

type versionPool struct{ version, edition string }

func (*versionPool) PingContext(context.Context) error { return nil }
func (pool *versionPool) QueryContext(context.Context, string, ...any) (Rows, error) {
	return &staticRows{rows: [][]string{{pool.version, pool.edition}}}, nil
}
func (*versionPool) Close() error { return nil }

type captureMetricStream struct {
	pluginv1.PluginRuntime_StreamMetricsServer
	ctx     context.Context
	cancel  context.CancelFunc
	want    int
	mu      sync.Mutex
	batches []*pluginv1.PluginMetricBatch
	header  chan struct{}
}

func (stream *captureMetricStream) Context() context.Context { return stream.ctx }
func (stream *captureMetricStream) SendHeader(metadata.MD) error {
	if stream.header != nil {
		close(stream.header)
	}
	return nil
}
func (*captureMetricStream) SetHeader(metadata.MD) error { return nil }
func (*captureMetricStream) SetTrailer(metadata.MD)      {}
func (stream *captureMetricStream) Send(batch *pluginv1.PluginMetricBatch) error {
	stream.mu.Lock()
	stream.batches = append(stream.batches, batch)
	done := stream.want > 0 && len(stream.batches) >= stream.want
	stream.mu.Unlock()
	if done && stream.cancel != nil {
		stream.cancel()
	}
	return nil
}
func (*captureMetricStream) SendMsg(any) error { return nil }
func (*captureMetricStream) RecvMsg(any) error { return io.EOF }

type trialPool struct{}

func (*trialPool) PingContext(context.Context) error { return nil }
func (*trialPool) QueryContext(context.Context, string, ...any) (Rows, error) {
	return &staticCustomRows{}, nil
}
func (*trialPool) Close() error { return nil }

type staticCustomRows struct{ done bool }

func (rows *staticCustomRows) Next() bool { return !rows.done }
func (rows *staticCustomRows) Scan(dest ...any) error {
	rows.done = true
	*(dest[0].(*any)) = []byte("7")
	*(dest[1].(*any)) = []byte("primary")
	return nil
}
func (*staticCustomRows) Columns() ([]string, error) { return []string{"value", "role_name"}, nil }
func (*staticCustomRows) Err() error                 { return nil }
func (*staticCustomRows) Close() error               { return nil }
