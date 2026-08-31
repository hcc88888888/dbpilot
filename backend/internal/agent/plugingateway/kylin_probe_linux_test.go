//go:build linux

package plugingateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestKylinPrivatePluginGatewayProbe(t *testing.T) {
	if os.Getenv("DBPILOT_KYLIN_PLUGIN_GATEWAY_PROBE") != "1" {
		t.Skip("Kylin gateway probe is disabled")
	}
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Fatal("gateway probe must run as a non-root user")
	}
	now := time.Now().UTC()
	root := t.TempDir()
	runtimeRoot := filepath.Join(root, "runtime")
	require.NoError(t, os.Mkdir(runtimeRoot, 0o700))
	runtimeDirectory := filepath.Join(runtimeRoot, "mysql")
	require.NoError(t, os.Mkdir(runtimeDirectory, 0o700))
	socket := filepath.Join(runtimeDirectory, "plugin.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(socket, 0o600))
	t.Cleanup(func() { _ = listener.Close() })
	executable, err := os.Executable()
	require.NoError(t, err)
	body, err := os.ReadFile(executable)
	require.NoError(t, err)
	digest := sha256.Sum256(body)
	nonce := make([]byte, sha256.Size)
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	server := &gatewayFixture{nonce: nonce, digest: digest[:], now: now}
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginRuntimeServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	store, err := spool.Open(filepath.Join(t.TempDir(), "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 16})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	client, err := NewClient(ClientConfig{RuntimeRoot: runtimeRoot, CursorRoot: filepath.Join(root, "state", "gateway-cursors"), Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}, Store: store, Timeout: 3 * time.Second, Now: func() time.Time { return now }})
	require.NoError(t, err)
	expected := ExpectedPlugin{PID: os.Getpid(), ExpectedUserID: uint32(os.Geteuid()), ExpectedGroupID: uint32(os.Getegid()), RuntimeDirectory: runtimeDirectory, AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ExecutablePath: executable, ExecutableSHA256: digest[:], LaunchNonce: nonce, ConfigurationRevision: 4, OperationRevision: 8, InstanceIDs: []string{"mysql-1", "mysql-2"}, TemplateIDs: []string{"template-1", "template-2"}}
	session, err := client.Open(expected)
	require.NoError(t, err)
	_, err = session.Handshake(context.Background(), expected)
	require.NoError(t, err)
	configuration := PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{{InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", Templates: []*pluginv1.MetricTemplateConfiguration{{TemplateId: "template-1", Revision: 1}, {TemplateId: "template-2", Revision: 1}}}, {InstanceId: "mysql-2", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3307", Templates: []*pluginv1.MetricTemplateConfiguration{{TemplateId: "template-1", Revision: 1}, {TemplateId: "template-2", Revision: 1}}}}}
	require.NoError(t, session.ApplyConfiguration(context.Background(), configuration))
	require.NoError(t, session.CollectNow(context.Background(), []string{"mysql-1", "mysql-2"}, []string{"template-1", "template-2"}))
	require.Error(t, session.RunMetricStream(context.Background(), store), "an unexpected completed metric stream must surface to Supervisor")
	stats, err := store.Stats()
	require.NoError(t, err)
	require.Equal(t, 5, stats.PendingBatches)
	require.NoError(t, session.Shutdown(context.Background(), time.Second))

	badPeer := expected
	badPeer.ExpectedUserID++
	badSession, err := client.Open(badPeer)
	require.NoError(t, err)
	_, err = badSession.Handshake(context.Background(), badPeer)
	require.Error(t, err)
	badDigest := expected
	badDigest.ExecutableSHA256 = make([]byte, sha256.Size)
	digestSession, err := client.Open(badDigest)
	require.NoError(t, err)
	_, err = digestSession.Handshake(context.Background(), badDigest)
	require.Error(t, err)
	badNonce := expected
	badNonce.LaunchNonce = make([]byte, sha256.Size)
	nonceSession, err := client.Open(badNonce)
	require.NoError(t, err)
	_, err = nonceSession.Handshake(context.Background(), badNonce)
	require.Error(t, err)
	badProtocol := expected
	badProtocol.ProtocolVersion = "v2"
	_, err = client.Open(badProtocol)
	require.Error(t, err)

	grpcServer.Stop()
	_ = listener.Close()
	if removeErr := os.Remove(socket); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		require.NoError(t, removeErr)
	}
	require.NoError(t, os.Symlink(filepath.Join(runtimeDirectory, "missing.sock"), socket))
	symlinkSession, err := client.Open(expected)
	require.NoError(t, err)
	_, err = symlinkSession.Handshake(context.Background(), expected)
	require.Error(t, err)
}

type gatewayFixture struct {
	pluginv1.UnimplementedPluginRuntimeServer
	nonce, digest []byte
	now           time.Time
}

func (fixture *gatewayFixture) Handshake(_ context.Context, request *pluginv1.PluginHandshakeRequest) (*pluginv1.PluginHandshakeResponse, error) {
	if request.GetExpectedProtocolVersion() != "v1" {
		return nil, errors.New("protocol mismatch")
	}
	return &pluginv1.PluginHandshakeResponse{PluginId: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ExecutableDigest: fixture.digest, LaunchNonceProof: launchProof(fixture.nonce, request.GetLaunchNonceChallenge(), "assignment-1", "1.0.0", 4, 8, []string{"mysql-1", "mysql-2"})}, nil
}
func (*gatewayFixture) ApplyConfiguration(_ context.Context, request *pluginv1.ApplyPluginConfigurationRequest) (*pluginv1.ApplyPluginConfigurationResponse, error) {
	return &pluginv1.ApplyPluginConfigurationResponse{ActiveConfigurationRevision: request.GetConfigurationRevision(), Results: []*pluginv1.PluginInstanceConfigurationResult{{InstanceId: "mysql-1", Applied: true}, {InstanceId: "mysql-2", Applied: true}}}, nil
}
func (fixture *gatewayFixture) CollectNow(_ context.Context, request *pluginv1.CollectPluginMetricsRequest) (*pluginv1.CollectPluginMetricsResponse, error) {
	return &pluginv1.CollectPluginMetricsResponse{Batches: []*pluginv1.PluginMetricBatch{fixture.batch("mysql-1", "template-1", 1), fixture.batch("mysql-1", "template-2", 1), fixture.batch("mysql-2", "template-1", 1), fixture.batch("mysql-2", "template-2", 1)}}, nil
}
func (fixture *gatewayFixture) StreamMetrics(_ *pluginv1.StreamPluginMetricsRequest, stream pluginv1.PluginRuntime_StreamMetricsServer) error {
	if err := stream.Send(fixture.batch("mysql-1", "template-1", 2)); err != nil {
		return err
	}
	return nil
}
func (*gatewayFixture) Shutdown(context.Context, *pluginv1.ShutdownPluginRequest) (*pluginv1.ShutdownPluginResponse, error) {
	return &pluginv1.ShutdownPluginResponse{Drained: true}, nil
}
func (fixture *gatewayFixture) batch(instanceID, templateID string, sequence uint64) *pluginv1.PluginMetricBatch {
	return &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: instanceID, ConfigurationRevision: 4, TemplateId: templateID, TemplateRevision: 1, CollectedAt: timestamppb.New(fixture.now), Sequence: sequence, CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: float64(sequence), Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(fixture.now)}}}
}
