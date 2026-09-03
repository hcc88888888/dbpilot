//go:build linux

package pluginsupervisor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/metrictemplatelease"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/plugincontract"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestGRPCHealthCheckerRequiresExactPrivateHandshakeAndAssignmentHealth(t *testing.T) {
	runtimeDir := t.TempDir()
	socket := filepath.Join(runtimeDir, "plugin.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(socket, 0o600))
	server := grpc.NewServer()
	executable, err := os.Executable()
	require.NoError(t, err)
	digest := sha256.Sum256(requireReadFile(t, executable))
	nonce := bytesOf(7, 32)
	pluginv1.RegisterPluginRuntimeServer(server, exactHealthFixtureServer{nonce: nonce, digest: digest[:]})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	checker := NewGRPCHealthChecker(GRPCHealthCheckerConfig{Timeout: time.Second})
	request := HealthRequest{AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ExecutableSHA256: digest[:], ExecutablePath: executable, ConfigurationRevision: 4, OperationRevision: 8, InstanceIDs: []string{"mysql-1", "mysql-2"}, RuntimeDirectory: runtimeDir, LaunchNonce: nonce, ExpectedUserID: uint32(os.Geteuid()), ExpectedGroupID: uint32(os.Getegid())}
	err = checker.Handshake(context.Background(), &fakeProcess{pid: os.Getpid(), started: time.Now().UTC()}, request)
	require.NoError(t, err)
	wrongUID := request
	wrongUID.ExpectedUserID++
	require.ErrorIs(t, checker.Handshake(context.Background(), &fakeProcess{pid: os.Getpid(), started: time.Now().UTC()}, wrongUID), ErrHealthHandshake)
	wrongNonce := request
	wrongNonce.LaunchNonce = bytesOf(8, 32)
	require.ErrorIs(t, checker.Handshake(context.Background(), &fakeProcess{pid: os.Getpid(), started: time.Now().UTC()}, wrongNonce), ErrHealthHandshake)
	require.ErrorIs(t, checker.Handshake(context.Background(), &fakeProcess{pid: os.Getpid() + 100000, started: time.Now().UTC()}, request), ErrHealthHandshake)
}

func TestGatewayHealthCheckerAppliesOnlyPerInstanceLeasedTemplates(t *testing.T) {
	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	require.NoError(t, os.Mkdir(runtimeRoot, 0o700))
	runtimeDir := filepath.Join(runtimeRoot, "mysql")
	require.NoError(t, os.Mkdir(runtimeDir, 0o700))
	socket := filepath.Join(runtimeDir, "plugin.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(socket, 0o600))
	executable, err := os.Executable()
	require.NoError(t, err)
	digest := sha256.Sum256(requireReadFile(t, executable))
	nonce := bytesOf(7, 32)
	applied := make(chan *pluginv1.ApplyPluginConfigurationRequest, 1)
	fixture := &exactHealthFixtureServer{nonce: nonce, digest: digest[:], applied: applied}
	server := grpc.NewServer()
	pluginv1.RegisterPluginRuntimeServer(server, fixture)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	client, err := plugingateway.NewClient(plugingateway.ClientConfig{RuntimeRoot: runtimeRoot, Scope: plugingateway.MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}, Timeout: time.Second})
	require.NoError(t, err)
	now := time.Now().UTC()
	refA := templateReferenceFor("template-a", "revision-a", "SELECT a")
	refB := templateReferenceFor("template-b", "revision-b", "SELECT b")
	materialA := templateMaterial(now, refA, "mysql-1", "SELECT a")
	materialB := templateMaterial(now, refB, "mysql-2", "SELECT b")
	for _, material := range []*metrictemplatelease.Material{&materialA, &materialB} {
		material.AssignmentID = "assignment-1"
		material.ConfigurationRevision = 4
		material.OperationRevision = 8
	}
	leaser := &gatewayHealthLeaseFixture{materials: map[string]metrictemplatelease.Material{"revision-a": materialA, "revision-b": materialB}, now: now}
	checker := NewGatewayHealthCheckerWithCredentials(client, leaser)
	request := HealthRequest{
		AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1",
		ExecutableSHA256: digest[:], ExecutablePath: executable, ConfigurationRevision: 4, OperationRevision: 8,
		InstanceIDs: []string{"mysql-1", "mysql-2"}, RuntimeDirectory: runtimeDir, LaunchNonce: nonce,
		ExpectedUserID: uint32(os.Geteuid()), ExpectedGroupID: uint32(os.Getegid()), SupportedVariants: []string{"mysql"},
		SignedCapabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1,
		InstanceDescriptors:    []InstanceDescriptor{{InstanceID: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}, {InstanceID: "mysql-2", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3307"}},
		TemplateLeaseCommandID: "command-1", TemplateIDs: []string{"template-a", "template-b"}, TemplateReferences: []TemplateReference{refA, refB},
		InstanceTemplateRefs: []InstanceTemplateReferences{{InstanceID: "mysql-1", Templates: []TemplateReference{refA}}, {InstanceID: "mysql-2", Templates: []TemplateReference{refB}}},
	}
	require.NoError(t, checker.Handshake(context.Background(), &fakeProcess{pid: os.Getpid(), started: now}, request))
	wire := <-applied
	require.Len(t, wire.GetInstances(), 2)
	require.Equal(t, "template-a", wire.GetInstances()[0].GetTemplates()[0].GetTemplateId())
	require.Equal(t, "SELECT a", wire.GetInstances()[0].GetTemplates()[0].GetReadOnlyStatement())
	require.Equal(t, "template-b", wire.GetInstances()[1].GetTemplates()[0].GetTemplateId())
	require.Equal(t, "SELECT b", wire.GetInstances()[1].GetTemplates()[0].GetReadOnlyStatement())
	require.NotContains(t, wire.GetInstances()[0].GetTemplates()[0].GetTemplateId(), "revision-a")
	checker.CleanupUnexpectedExit(&fakeProcess{pid: os.Getpid(), started: now})
}

func TestGatewayHealthCheckerCommitsLiveConfigurationOnlyAfterProbeAndNewStream(t *testing.T) {
	checker, fixture, process, initial := newTransactionalGatewayHealthFixture(t, 0)
	candidate := initial
	candidate.ConfigurationRevision = 5
	candidate.OperationRevision = 9
	candidate.InstanceDescriptors = []InstanceDescriptor{{InstanceID: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:4306"}, {InstanceID: "mysql-2", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:4307"}}

	require.NoError(t, checker.ApplyConfiguration(context.Background(), process, candidate))

	fixture.mu.Lock()
	require.Equal(t, []uint64{4, 5}, fixture.appliedRevisions)
	require.ElementsMatch(t, []string{"5/mysql-1", "5/mysql-2"}, fixture.validationsForRevision(5))
	require.ElementsMatch(t, []string{"5/mysql-1/mysql.up", "5/mysql-2/mysql.up"}, fixture.collectionsForRevision(5))
	require.Equal(t, []uint64{4, 5}, fixture.streamStarts)
	require.Contains(t, fixture.streamStops, uint64(4))
	fixture.mu.Unlock()
	require.False(t, process.stopped, "a same-version configuration update must retain the accepted process")
	require.Equal(t, uint64(5), checker.sessions[process.pid].ConfigurationRevision())
	require.Equal(t, uint64(9), checker.sessions[process.pid].OperationRevision())
	require.Equal(t, uint64(5), checker.activeCredentials[process.pid].configuration.ConfigurationRevision)
	checker.CleanupUnexpectedExit(process)
}

func TestGatewayHealthCheckerRollsBackFailedLiveProbeAndReopensOldStream(t *testing.T) {
	checker, fixture, process, initial := newTransactionalGatewayHealthFixture(t, 5)
	candidate := initial
	candidate.ConfigurationRevision = 5
	candidate.OperationRevision = 9
	candidate.InstanceDescriptors = []InstanceDescriptor{{InstanceID: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:4306"}, {InstanceID: "mysql-2", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:4307"}}

	require.ErrorIs(t, checker.ApplyConfiguration(context.Background(), process, candidate), ErrHealthHandshake)

	fixture.mu.Lock()
	require.Equal(t, []uint64{4, 5, 4}, fixture.appliedRevisions, "the failed candidate must be followed by the exact previous configuration")
	require.ElementsMatch(t, []string{"5/mysql-1", "5/mysql-2"}, fixture.validationsForRevision(5))
	require.Empty(t, fixture.collectionsForRevision(5), "collection starts only after every candidate instance validates")
	require.Equal(t, []uint64{4, 4}, fixture.streamStarts, "the quiesced previous stream must be reopened")
	require.Contains(t, fixture.streamStops, uint64(4))
	fixture.mu.Unlock()
	require.False(t, process.stopped, "a recoverable candidate failure must preserve the accepted PID")
	require.Equal(t, uint64(4), checker.sessions[process.pid].ConfigurationRevision())
	require.Equal(t, uint64(8), checker.sessions[process.pid].OperationRevision())
	require.Equal(t, uint64(4), checker.activeCredentials[process.pid].configuration.ConfigurationRevision)
	checker.CleanupUnexpectedExit(process)
}

func newTransactionalGatewayHealthFixture(t *testing.T, failValidationRevision uint64) (*GatewayHealthChecker, *transactionalHealthFixtureServer, *fakeProcess, HealthRequest) {
	t.Helper()
	root, err := os.MkdirTemp("", "dbptxn-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(root)) })
	runtimeRoot := filepath.Join(root, "runtime")
	require.NoError(t, os.Mkdir(runtimeRoot, 0o700))
	runtimeDir := filepath.Join(runtimeRoot, "mysql")
	require.NoError(t, os.Mkdir(runtimeDir, 0o700))
	listener, err := net.Listen("unix", filepath.Join(runtimeDir, "plugin.sock"))
	require.NoError(t, err)
	require.NoError(t, os.Chmod(filepath.Join(runtimeDir, "plugin.sock"), 0o600))
	executable, err := os.Executable()
	require.NoError(t, err)
	digest := sha256.Sum256(requireReadFile(t, executable))
	nonce := bytesOf(17, 32)
	fixture := &transactionalHealthFixtureServer{nonce: nonce, digest: digest[:], activeRevision: 4, failValidationRevision: failValidationRevision, pending: make(map[uint64][]*pluginv1.PluginMetricBatch), sequences: make(map[string]uint64)}
	server := grpc.NewServer()
	pluginv1.RegisterPluginRuntimeServer(server, fixture)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	store, err := spool.Open(filepath.Join(root, "spool"), spool.Limits{MaxBytes: 4 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	client, err := plugingateway.NewClient(plugingateway.ClientConfig{RuntimeRoot: runtimeRoot, Scope: plugingateway.MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}, Store: store, Timeout: 2 * time.Second})
	require.NoError(t, err)
	now := time.Now().UTC()
	checker := NewGatewayHealthCheckerWithCredentials(client, &gatewayHealthLeaseFixture{now: now})
	process := &fakeProcess{pid: os.Getpid(), started: now}
	request := HealthRequest{
		AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1",
		ExecutableSHA256: digest[:], ExecutablePath: executable, ConfigurationRevision: 4, OperationRevision: 8,
		InstanceIDs: []string{"mysql-1", "mysql-2"}, RuntimeDirectory: runtimeDir, LaunchNonce: nonce,
		ExpectedUserID: uint32(os.Geteuid()), ExpectedGroupID: uint32(os.Getegid()), SupportedVariants: []string{"mysql"},
		SignedCapabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, CredentialsComplete: true,
		InstanceDescriptors: []InstanceDescriptor{{InstanceID: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}, {InstanceID: "mysql-2", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3307"}},
	}
	require.NoError(t, checker.Handshake(context.Background(), process, request))
	return checker, fixture, process, request
}

type transactionalHealthFixtureServer struct {
	pluginv1.UnimplementedPluginRuntimeServer
	mu                     sync.Mutex
	nonce                  []byte
	digest                 []byte
	activeRevision         uint64
	failValidationRevision uint64
	appliedRevisions       []uint64
	validations            []string
	collections            []string
	streamStarts           []uint64
	streamStops            []uint64
	pending                map[uint64][]*pluginv1.PluginMetricBatch
	sequences              map[string]uint64
}

func (server *transactionalHealthFixtureServer) Handshake(_ context.Context, request *pluginv1.PluginHandshakeRequest) (*pluginv1.PluginHandshakeResponse, error) {
	builtin := &pluginv1.BuiltinMetricTemplateDescriptor{TemplateId: "mysql.up", Revision: 1, CollectionIntervalSeconds: 10, Metrics: []*pluginv1.BuiltinMetricDescriptor{{MetricName: "mysql.up", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, Unit: "1"}}}
	builtin.DefinitionDigest = plugincontract.BuiltinDescriptorDigest(builtin)
	proof := LaunchProof(server.nonce, request.GetLaunchNonceChallenge(), "assignment-1", "1.0.0", 4, 8, []string{"mysql-1", "mysql-2"})
	return &pluginv1.PluginHandshakeResponse{PluginId: request.GetExpectedPluginId(), DatabaseFamily: request.GetExpectedDatabaseFamily(), Version: request.GetExpectedVersion(), ProtocolVersion: request.GetExpectedProtocolVersion(), SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, ExecutableDigest: server.digest, LaunchNonceProof: proof, BuiltinTemplates: []*pluginv1.BuiltinMetricTemplateDescriptor{builtin}}, nil
}

func (server *transactionalHealthFixtureServer) ApplyConfiguration(_ context.Context, request *pluginv1.ApplyPluginConfigurationRequest) (*pluginv1.ApplyPluginConfigurationResponse, error) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.activeRevision = request.GetConfigurationRevision()
	server.appliedRevisions = append(server.appliedRevisions, request.GetConfigurationRevision())
	results := make([]*pluginv1.PluginInstanceConfigurationResult, 0, len(request.GetInstances()))
	for _, instance := range request.GetInstances() {
		results = append(results, &pluginv1.PluginInstanceConfigurationResult{InstanceId: instance.GetInstanceId(), Applied: true})
	}
	return &pluginv1.ApplyPluginConfigurationResponse{ActiveConfigurationRevision: request.GetConfigurationRevision(), Results: results}, nil
}

func (server *transactionalHealthFixtureServer) ValidateInstance(_ context.Context, request *pluginv1.ValidatePluginInstanceRequest) (*pluginv1.ValidatePluginInstanceResponse, error) {
	server.mu.Lock()
	server.validations = append(server.validations, revisionInstance(request.GetConfigurationRevision(), request.GetInstanceId()))
	fail := request.GetConfigurationRevision() == server.failValidationRevision && request.GetInstanceId() == "mysql-2"
	server.mu.Unlock()
	if fail {
		return &pluginv1.ValidatePluginInstanceResponse{InstanceId: request.GetInstanceId(), ErrorCode: "connection_rejected"}, nil
	}
	return &pluginv1.ValidatePluginInstanceResponse{InstanceId: request.GetInstanceId(), Valid: true, DatabaseVersion: "8.4.0", DatabaseEdition: "community", Capabilities: []string{"metrics.collect"}}, nil
}

func (server *transactionalHealthFixtureServer) CollectNow(_ context.Context, request *pluginv1.CollectPluginMetricsRequest) (*pluginv1.CollectPluginMetricsResponse, error) {
	server.mu.Lock()
	defer server.mu.Unlock()
	batches := make([]*pluginv1.PluginMetricBatch, 0, len(request.GetInstanceIds())*len(request.GetTemplateIds()))
	for _, instanceID := range request.GetInstanceIds() {
		for _, templateID := range request.GetTemplateIds() {
			server.collections = append(server.collections, revisionInstanceTemplate(request.GetConfigurationRevision(), instanceID, templateID))
			key := revisionInstanceTemplate(request.GetConfigurationRevision(), instanceID, templateID)
			server.sequences[key]++
			now := time.Now().UTC()
			batch := &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: instanceID, ConfigurationRevision: request.GetConfigurationRevision(), TemplateId: templateID, TemplateRevision: 1, Sequence: server.sequences[key], CollectedAt: timestamppb.New(now), CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.up", Value: 1, Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(now)}}}
			batches = append(batches, batch)
			server.pending[request.GetConfigurationRevision()] = append(server.pending[request.GetConfigurationRevision()], proto.Clone(batch).(*pluginv1.PluginMetricBatch))
		}
	}
	return &pluginv1.CollectPluginMetricsResponse{Batches: batches}, nil
}

func (server *transactionalHealthFixtureServer) StreamMetrics(request *pluginv1.StreamPluginMetricsRequest, stream grpc.ServerStreamingServer[pluginv1.PluginMetricBatch]) error {
	if err := stream.SendHeader(metadata.MD{}); err != nil {
		return err
	}
	server.mu.Lock()
	server.streamStarts = append(server.streamStarts, request.GetConfigurationRevision())
	pending := make([]*pluginv1.PluginMetricBatch, len(server.pending[request.GetConfigurationRevision()]))
	for index, batch := range server.pending[request.GetConfigurationRevision()] {
		pending[index] = proto.Clone(batch).(*pluginv1.PluginMetricBatch)
	}
	server.mu.Unlock()
	for _, batch := range pending {
		if err := stream.Send(batch); err != nil {
			return err
		}
	}
	<-stream.Context().Done()
	server.mu.Lock()
	server.streamStops = append(server.streamStops, request.GetConfigurationRevision())
	server.mu.Unlock()
	return stream.Context().Err()
}

func (server *transactionalHealthFixtureServer) AcknowledgeMetrics(_ context.Context, request *pluginv1.AcknowledgePluginMetricsRequest) (*pluginv1.AcknowledgePluginMetricsResponse, error) {
	server.mu.Lock()
	defer server.mu.Unlock()
	accepted := make([]*pluginv1.PluginMetricCursor, len(request.GetCursors()))
	for index, cursor := range request.GetCursors() {
		accepted[index] = proto.Clone(cursor).(*pluginv1.PluginMetricCursor)
	}
	server.pending[request.GetConfigurationRevision()] = nil
	return &pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: accepted}, nil
}

func (server *transactionalHealthFixtureServer) GetHealth(context.Context, *pluginv1.GetPluginHealthRequest) (*pluginv1.PluginHealth, error) {
	server.mu.Lock()
	revision := server.activeRevision
	server.mu.Unlock()
	return &pluginv1.PluginHealth{AssignmentId: "assignment-1", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY, ActiveConfigurationRevision: revision, BoundInstanceCount: 2, Instances: []*pluginv1.PluginInstanceHealth{{InstanceId: "mysql-1", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY}, {InstanceId: "mysql-2", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY}}, ObservedAt: timestamppb.Now()}, nil
}

func (server *transactionalHealthFixtureServer) validationsForRevision(revision uint64) []string {
	prefix := revisionString(revision) + "/"
	result := make([]string, 0)
	for _, value := range server.validations {
		if len(value) >= len(prefix) && value[:len(prefix)] == prefix {
			result = append(result, value)
		}
	}
	return result
}

func (server *transactionalHealthFixtureServer) collectionsForRevision(revision uint64) []string {
	prefix := revisionString(revision) + "/"
	result := make([]string, 0)
	for _, value := range server.collections {
		if len(value) >= len(prefix) && value[:len(prefix)] == prefix {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func revisionString(value uint64) string { return fmt.Sprintf("%d", value) }
func revisionInstance(revision uint64, instance string) string {
	return revisionString(revision) + "/" + instance
}
func revisionInstanceTemplate(revision uint64, instance, template string) string {
	return revisionInstance(revision, instance) + "/" + template
}

type exactHealthFixtureServer struct {
	pluginv1.UnimplementedPluginRuntimeServer
	nonce   []byte
	digest  []byte
	applied chan *pluginv1.ApplyPluginConfigurationRequest
}

func (server exactHealthFixtureServer) Handshake(_ context.Context, request *pluginv1.PluginHandshakeRequest) (*pluginv1.PluginHandshakeResponse, error) {
	proof := LaunchProof(server.nonce, request.GetLaunchNonceChallenge(), "assignment-1", "1.0.0", 4, 8, []string{"mysql-1", "mysql-2"})
	return &pluginv1.PluginHandshakeResponse{PluginId: request.GetExpectedPluginId(), DatabaseFamily: request.GetExpectedDatabaseFamily(), Version: request.GetExpectedVersion(), ProtocolVersion: request.GetExpectedProtocolVersion(), SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, ExecutableDigest: server.digest, LaunchNonceProof: proof}, nil
}
func (exactHealthFixtureServer) GetHealth(context.Context, *pluginv1.GetPluginHealthRequest) (*pluginv1.PluginHealth, error) {
	return &pluginv1.PluginHealth{AssignmentId: "assignment-1", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY, ActiveConfigurationRevision: 4, BoundInstanceCount: 2, Instances: []*pluginv1.PluginInstanceHealth{{InstanceId: "mysql-1", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY}, {InstanceId: "mysql-2", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY}}, ObservedAt: timestamppb.Now()}, nil
}

func (server exactHealthFixtureServer) ApplyConfiguration(_ context.Context, request *pluginv1.ApplyPluginConfigurationRequest) (*pluginv1.ApplyPluginConfigurationResponse, error) {
	if server.applied != nil {
		server.applied <- proto.Clone(request).(*pluginv1.ApplyPluginConfigurationRequest)
	}
	results := make([]*pluginv1.PluginInstanceConfigurationResult, 0, len(request.GetInstances()))
	for _, instance := range request.GetInstances() {
		results = append(results, &pluginv1.PluginInstanceConfigurationResult{InstanceId: instance.GetInstanceId(), Applied: true})
	}
	return &pluginv1.ApplyPluginConfigurationResponse{ActiveConfigurationRevision: request.GetConfigurationRevision(), Results: results}, nil
}

func (exactHealthFixtureServer) ValidateInstance(_ context.Context, request *pluginv1.ValidatePluginInstanceRequest) (*pluginv1.ValidatePluginInstanceResponse, error) {
	return &pluginv1.ValidatePluginInstanceResponse{InstanceId: request.GetInstanceId(), Valid: true, DatabaseVersion: "8.4.0", DatabaseEdition: "community", Capabilities: []string{"metrics.collect"}}, nil
}

type gatewayHealthLeaseFixture struct {
	materials map[string]metrictemplatelease.Material
	now       time.Time
}

func (fixture *gatewayHealthLeaseFixture) LeaseCredential(_ context.Context, request CredentialLeaseRequest) (CredentialLease, error) {
	return CredentialLease{LeaseID: "credential-" + request.InstanceID, AssignmentID: request.AssignmentID, InstanceID: request.InstanceID, DatabaseFamily: request.DatabaseFamily, CredentialRevision: request.ConfigurationRevision, ConfigurationRevision: request.ConfigurationRevision, OperationRevision: request.OperationRevision, ExpiresAt: fixture.now.Add(time.Minute), ValidFor: time.Minute, Username: "monitor", SecretBytes: []byte("fixture-secret")}, nil
}

func (fixture *gatewayHealthLeaseFixture) LeaseMetricTemplate(_ context.Context, request metrictemplatelease.Request) (metrictemplatelease.Material, error) {
	value := fixture.materials[request.RevisionID]
	value.StatementBytes = append([]byte(nil), value.StatementBytes...)
	return value, nil
}
