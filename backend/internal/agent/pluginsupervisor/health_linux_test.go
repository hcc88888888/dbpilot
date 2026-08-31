//go:build linux

package pluginsupervisor

import (
	"context"
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
	pluginv1.RegisterPluginRuntimeServer(server, exactHealthFixtureServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })

	checker := NewGRPCHealthChecker(GRPCHealthCheckerConfig{Timeout: time.Second})
	err = checker.Handshake(context.Background(), &fakeProcess{pid: 10, started: time.Now().UTC()}, HealthRequest{AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ExecutableSHA256: bytesOf(6, 32), ConfigurationRevision: 4, OperationRevision: 8, InstanceIDs: []string{"mysql-1", "mysql-2"}, RuntimeDirectory: runtimeDir})
	require.NoError(t, err)
}

type exactHealthFixtureServer struct {
	pluginv1.UnimplementedPluginRuntimeServer
}

func (exactHealthFixtureServer) Handshake(_ context.Context, request *pluginv1.PluginHandshakeRequest) (*pluginv1.PluginHandshakeResponse, error) {
	return &pluginv1.PluginHandshakeResponse{PluginId: request.GetExpectedPluginId(), DatabaseFamily: request.GetExpectedDatabaseFamily(), Version: request.GetExpectedVersion(), ProtocolVersion: request.GetExpectedProtocolVersion(), SupportedVariants: []string{"mysql"}, DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, ExecutableDigest: bytesOf(6, 32), LaunchNonceProof: append([]byte(nil), request.GetLaunchNonceChallenge()...)}, nil
}
func (exactHealthFixtureServer) GetHealth(context.Context, *pluginv1.GetPluginHealthRequest) (*pluginv1.PluginHealth, error) {
	return &pluginv1.PluginHealth{AssignmentId: "assignment-1", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY, ActiveConfigurationRevision: 4, BoundInstanceCount: 2, Instances: []*pluginv1.PluginInstanceHealth{{InstanceId: "mysql-1", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY}, {InstanceId: "mysql-2", State: pluginv1.PluginHealthState_PLUGIN_HEALTH_STATE_HEALTHY}}, ObservedAt: timestamppb.Now()}, nil
}
