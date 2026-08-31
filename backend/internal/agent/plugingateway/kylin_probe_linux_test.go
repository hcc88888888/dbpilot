//go:build linux

package plugingateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
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
	client, err := NewClient(ClientConfig{RuntimeRoot: runtimeRoot, Scope: MetricScope{TenantID: "tenant-1", ProjectID: "project-1", AgentID: "agent-1", HostID: "host-1"}, Store: store, Timeout: time.Second, Now: func() time.Time { return now }})
	require.NoError(t, err)
	expected := ExpectedPlugin{PID: os.Getpid(), ExpectedUserID: uint32(os.Geteuid()), ExpectedGroupID: uint32(os.Getegid()), RuntimeDirectory: runtimeDirectory, AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", ExecutablePath: executable, ExecutableSHA256: digest[:], LaunchNonce: nonce, ConfigurationRevision: 4, OperationRevision: 8, InstanceIDs: []string{"mysql-1", "mysql-2"}, TemplateIDs: []string{"template-1", "template-2"}, SupportedVariants: []string{"mysql"}, SignedCapabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, TemplateConfigurations: []*pluginv1.MetricTemplateConfiguration{probeTemplate("template-1"), probeTemplate("template-2")}}
	session, err := client.Open(expected)
	require.NoError(t, err)
	_, err = session.Handshake(context.Background(), expected)
	require.NoError(t, err)
	secret := []byte("kylin-task11-memory-only-credential")
	lease := func(revision uint64, value []byte) *pluginv1.CredentialLease {
		return &pluginv1.CredentialLease{LeaseId: "lease-task11", CredentialRevision: revision, Username: "monitor", SecretBytes: append([]byte(nil), value...), ExpiresAt: timestamppb.New(now.Add(time.Minute))}
	}
	configuration := PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{{InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", CredentialLease: lease(9, secret), Templates: []*pluginv1.MetricTemplateConfiguration{probeTemplate("template-1"), probeTemplate("template-2")}}, {InstanceId: "mysql-2", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3307", CredentialLease: lease(9, secret), Templates: []*pluginv1.MetricTemplateConfiguration{probeTemplate("template-1"), probeTemplate("template-2")}}}}
	require.NoError(t, session.ApplyConfiguration(context.Background(), configuration))
	require.Equal(t, string(secret), server.lastCredential)
	firstWireBuffer := configuration.Instances[0].CredentialLease.SecretBytes
	configuration.Release()
	require.Equal(t, make([]byte, len(firstWireBuffer)), firstWireBuffer)
	rotated := PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{{InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", CredentialLease: lease(10, []byte("kylin-task11-rotated-credential")), Templates: []*pluginv1.MetricTemplateConfiguration{probeTemplate("template-1"), probeTemplate("template-2")}}, {InstanceId: "mysql-2", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3307", CredentialLease: lease(10, []byte("kylin-task11-rotated-credential")), Templates: []*pluginv1.MetricTemplateConfiguration{probeTemplate("template-1"), probeTemplate("template-2")}}}}
	require.NoError(t, session.ApplyConfiguration(context.Background(), rotated))
	require.Equal(t, "kylin-task11-rotated-credential", server.lastCredential)
	rotated.Release()
	require.NoError(t, session.RemoveCredentials(context.Background()))
	require.Equal(t, 1, server.credentialClears)
	oversizedInstances, oversizedTemplates := canonicalPairFixture(2, 65)
	for _, template := range oversizedTemplates {
		template.ReadOnlyStatement = "SELECT '" + strings.Repeat("x", 40<<10) + "'"
	}
	for _, instance := range oversizedInstances {
		instance.Templates = cloneTemplateConfigurations(oversizedTemplates)
	}
	oversizedExpected := expected
	oversizedExpected.InstanceIDs = mapInstanceIDs(oversizedInstances)
	oversizedExpected.TemplateIDs = mapTemplateIDs(oversizedTemplates)
	oversizedExpected.TemplateConfigurations = oversizedTemplates
	require.Error(t, (PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: mapInstances(oversizedInstances)}).validate(oversizedExpected), "oversized protocol configuration must fail before RPC side effects")
	require.NoError(t, session.CollectNow(context.Background(), []string{"mysql-1", "mysql-2"}, []string{"template-1", "template-2"}))
	require.Error(t, session.RunMetricStream(context.Background(), store), "an unexpected completed metric stream must surface to Supervisor")
	stats, err := store.Stats()
	require.NoError(t, err)
	require.Equal(t, 5, stats.PendingBatches)
	require.Equal(t, 5, server.acks, "Agent ACKs only after each durable append")
	require.NoError(t, session.Shutdown(context.Background(), time.Second))
	restartSession, err := client.Open(expected)
	require.NoError(t, err)
	_, err = restartSession.Handshake(context.Background(), expected)
	require.NoError(t, err)
	require.Error(t, restartSession.CollectNow(context.Background(), expected.InstanceIDs, expected.TemplateIDs), "Agent restart must not restore a credential lease or configured session")
	releasedAfterRestart := PluginConfiguration{AssignmentID: "assignment-1", ConfigurationRevision: 4, Instances: []*pluginv1.PluginInstanceConfiguration{{InstanceId: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306", CredentialLease: lease(11, secret), Templates: []*pluginv1.MetricTemplateConfiguration{probeTemplate("template-1"), probeTemplate("template-2")}}, {InstanceId: "mysql-2", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3307", CredentialLease: lease(11, secret), Templates: []*pluginv1.MetricTemplateConfiguration{probeTemplate("template-1"), probeTemplate("template-2")}}}}
	require.NoError(t, restartSession.ApplyConfiguration(context.Background(), releasedAfterRestart))
	releasedAfterRestart.Release()
	require.NoError(t, restartSession.Shutdown(context.Background(), time.Second))
	assertCredentialAbsentFromKylinArtifacts(t, root, "kylin-task11-memory-only-credential", "kylin-task11-rotated-credential")

	badPeer := expected
	badPeer.ExpectedUserID++
	badSession, err := client.Open(badPeer)
	require.NoError(t, err)
	_, err = badSession.Handshake(context.Background(), badPeer)
	require.Error(t, err)
	badGroup := expected
	badGroup.ExpectedGroupID++
	groupSession, err := client.Open(badGroup)
	require.NoError(t, err)
	_, err = groupSession.Handshake(context.Background(), badGroup)
	require.Error(t, err)
	badPID := expected
	badPID.PID++
	pidSession, err := client.Open(badPID)
	require.NoError(t, err)
	_, err = pidSession.Handshake(context.Background(), badPID)
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
	nonce, digest    []byte
	now              time.Time
	acks             int
	lastCredential   string
	credentialClears int
}

func (fixture *gatewayFixture) Handshake(_ context.Context, request *pluginv1.PluginHandshakeRequest) (*pluginv1.PluginHandshakeResponse, error) {
	if request.GetExpectedProtocolVersion() != "v1" {
		return nil, errors.New("protocol mismatch")
	}
	return &pluginv1.PluginHandshakeResponse{PluginId: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", ProtocolVersion: "v1", SupportedVariants: []string{"mysql"}, Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1, ExecutableDigest: fixture.digest, LaunchNonceProof: launchProof(fixture.nonce, request.GetLaunchNonceChallenge(), "assignment-1", "1.0.0", 4, 8, []string{"mysql-1", "mysql-2"})}, nil
}
func (fixture *gatewayFixture) ApplyConfiguration(_ context.Context, request *pluginv1.ApplyPluginConfigurationRequest) (*pluginv1.ApplyPluginConfigurationResponse, error) {
	results := make([]*pluginv1.PluginInstanceConfigurationResult, 0, len(request.GetInstances()))
	hasCredential := false
	for _, instance := range request.GetInstances() {
		if lease := instance.GetCredentialLease(); lease != nil {
			if lease.GetUsername() != "monitor" || len(lease.GetSecretBytes()) == 0 {
				return nil, errors.New("credential lease rejected")
			}
			hasCredential = true
			fixture.lastCredential = string(append([]byte(nil), lease.GetSecretBytes()...))
		}
		results = append(results, &pluginv1.PluginInstanceConfigurationResult{InstanceId: instance.GetInstanceId(), Applied: true})
	}
	if !hasCredential {
		fixture.credentialClears++
		fixture.lastCredential = ""
	}
	return &pluginv1.ApplyPluginConfigurationResponse{ActiveConfigurationRevision: request.GetConfigurationRevision(), Results: results}, nil
}

func assertCredentialAbsentFromKylinArtifacts(t *testing.T, root string, secrets ...string) {
	t.Helper()
	for _, processPath := range []string{"/proc/self/cmdline", "/proc/self/environ"} {
		body, err := os.ReadFile(processPath)
		require.NoError(t, err)
		for _, secret := range secrets {
			require.NotContains(t, string(body), secret)
		}
	}
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Type()&os.ModeSocket != 0 {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, secret := range secrets {
			require.NotContains(t, string(body), secret, "credential leaked to %s", path)
		}
		return nil
	}))
}
func (fixture *gatewayFixture) CollectNow(_ context.Context, request *pluginv1.CollectPluginMetricsRequest) (*pluginv1.CollectPluginMetricsResponse, error) {
	return &pluginv1.CollectPluginMetricsResponse{Batches: []*pluginv1.PluginMetricBatch{fixture.batch("mysql-1", "template-1", 1), fixture.batch("mysql-1", "template-2", 1), fixture.batch("mysql-2", "template-1", 1), fixture.batch("mysql-2", "template-2", 1)}}, nil
}
func (fixture *gatewayFixture) StreamMetrics(request *pluginv1.StreamPluginMetricsRequest, stream pluginv1.PluginRuntime_StreamMetricsServer) error {
	if len(request.GetResumeCursors()) != 4 {
		return errors.New("resume cursor coverage mismatch")
	}
	if err := stream.SendHeader(metadata.MD{}); err != nil {
		return err
	}
	time.Sleep(1500 * time.Millisecond)
	if err := stream.Send(fixture.batch("mysql-1", "template-1", 2)); err != nil {
		return err
	}
	return nil
}

func probeTemplate(id string) *pluginv1.MetricTemplateConfiguration {
	return &pluginv1.MetricTemplateConfiguration{TemplateId: id, Revision: 1, QueryDigest: make([]byte, sha256.Size), QueryKind: "sql", ReadOnlyStatement: "SELECT value", CollectionIntervalSeconds: 10, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, ValueMappings: []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: "mysql.connections.current", MetricType: "gauge", Unit: "1"}}}
}
func (fixture *gatewayFixture) AcknowledgeMetrics(_ context.Context, request *pluginv1.AcknowledgePluginMetricsRequest) (*pluginv1.AcknowledgePluginMetricsResponse, error) {
	fixture.acks += len(request.GetCursors())
	return &pluginv1.AcknowledgePluginMetricsResponse{AcceptedCursors: request.GetCursors()}, nil
}
func (*gatewayFixture) Shutdown(context.Context, *pluginv1.ShutdownPluginRequest) (*pluginv1.ShutdownPluginResponse, error) {
	return &pluginv1.ShutdownPluginResponse{Drained: true}, nil
}
func (fixture *gatewayFixture) batch(instanceID, templateID string, sequence uint64) *pluginv1.PluginMetricBatch {
	return &pluginv1.PluginMetricBatch{PluginId: "mysql", PluginVersion: "1.0.0", DatabaseFamily: "mysql", DatabaseVariant: "mysql", InstanceId: instanceID, ConfigurationRevision: 4, TemplateId: templateID, TemplateRevision: 1, CollectedAt: timestamppb.New(fixture.now), Sequence: sequence, CollectionStatus: pluginv1.PluginCollectionStatus_PLUGIN_COLLECTION_STATUS_SUCCEEDED, Samples: []*pluginv1.PluginMetricSample{{MetricName: "mysql.connections.current", Value: float64(sequence), Unit: "1", MetricType: pluginv1.PluginMetricType_PLUGIN_METRIC_TYPE_GAUGE, SampledAt: timestamppb.New(fixture.now)}}}
}
