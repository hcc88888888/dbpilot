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
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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

type exactHealthFixtureServer struct {
	pluginv1.UnimplementedPluginRuntimeServer
	nonce  []byte
	digest []byte
}

func (server exactHealthFixtureServer) Handshake(_ context.Context, request *pluginv1.PluginHandshakeRequest) (*pluginv1.PluginHandshakeResponse, error) {
	proof := LaunchProof(server.nonce, request.GetLaunchNonceChallenge(), "assignment-1", "1.0.0", 4, 8, []string{"mysql-1", "mysql-2"})
	return &pluginv1.PluginHandshakeResponse{PluginId: request.GetExpectedPluginId(), DatabaseFamily: request.GetExpectedDatabaseFamily(), Version: request.GetExpectedVersion(), ProtocolVersion: request.GetExpectedProtocolVersion(), SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, ExecutableDigest: server.digest, LaunchNonceProof: proof}, nil
}
func (exactHealthFixtureServer) GetHealth(context.Context, *pluginv1.GetPluginHealthRequest) (*pluginv1.PluginHealth, error) {
	return &pluginv1.PluginHealth{AssignmentId: "assignment-1", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY, ActiveConfigurationRevision: 4, BoundInstanceCount: 2, Instances: []*pluginv1.PluginInstanceHealth{{InstanceId: "mysql-1", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY}, {InstanceId: "mysql-2", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY}}, ObservedAt: timestamppb.Now()}, nil
}
