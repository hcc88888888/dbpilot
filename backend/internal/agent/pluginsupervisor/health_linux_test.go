//go:build linux

package pluginsupervisor

import (
	"context"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/metrictemplatelease"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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
	return CredentialLease{LeaseID: "credential-" + request.InstanceID, AssignmentID: request.AssignmentID, InstanceID: request.InstanceID, DatabaseFamily: request.DatabaseFamily, CredentialRevision: 1, ConfigurationRevision: request.ConfigurationRevision, OperationRevision: request.OperationRevision, ExpiresAt: fixture.now.Add(time.Minute), ValidFor: time.Minute, Username: "monitor", SecretBytes: []byte("fixture-secret")}, nil
}

func (fixture *gatewayHealthLeaseFixture) LeaseMetricTemplate(_ context.Context, request metrictemplatelease.Request) (metrictemplatelease.Material, error) {
	value := fixture.materials[request.RevisionID]
	value.StatementBytes = append([]byte(nil), value.StatementBytes...)
	return value, nil
}
