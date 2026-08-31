//go:build linux

package pluginsupervisor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	pluginv1 "dbpilot.local/platform/gen/plugin/v1"
	"dbpilot.local/platform/internal/agent/plugingateway"
	"dbpilot.local/platform/internal/agent/pluginstate"
	"dbpilot.local/platform/internal/plugincatalog"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
)

func TestKylinPluginSupervisorLifecycleProbe(t *testing.T) {
	if os.Getenv("DBPILOT_KYLIN_SUPERVISOR_PROBE") != "1" {
		t.Skip("set DBPILOT_KYLIN_SUPERVISOR_PROBE=1 inside the exact Kylin verifier")
	}
	fixturePath := os.Getenv("DBPILOT_PLUGIN_PROCESS_FIXTURE")
	require.NotEmpty(t, fixturePath)
	binary := requireReadFile(t, fixturePath)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	stable := buildProbePackage(t, binary, privateKey, "1.0.0")
	failing := buildProbePackage(t, binary, privateKey, "1.1.0")
	crashing := buildProbePackage(t, binary, privateKey, "1.2.0")

	root := t.TempDir()
	for _, directory := range []string{"plugins", "runtime", "state"} {
		require.NoError(t, os.Mkdir(filepath.Join(root, directory), 0o700))
	}
	publishers, err := plugincatalog.NewStaticPublisherKeyStore([]plugincatalog.PublisherKey{{PublisherID: "fixture-publisher", KeyID: "fixture-key", PublicKey: publicKey}})
	require.NoError(t, err)
	installer, err := NewInstaller(InstallerConfig{Root: filepath.Join(root, "plugins"), Publishers: publishers, OperatingSystem: "linux", Architecture: "amd64", Limits: plugincatalog.DefaultPackageLimits()})
	require.NoError(t, err)
	stateStore, err := pluginstate.NewFileStore(filepath.Join(root, "state"))
	require.NoError(t, err)
	spoolStore, err := spool.Open(filepath.Join(root, "spool"), spool.Limits{MaxBytes: 16 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, spoolStore.Close()) })
	metricSpool := &probeMetricSpool{Store: spoolStore}
	uid, gid, nonRoot := CurrentProcessIdentity()
	require.True(t, nonRoot)
	leasing := &probeLeaseClient{packages: map[string]probePackage{"artifact-1": stable, "artifact-2": failing, "artifact-3": crashing}}
	processRunner := NewOSProcessRunner(OSProcessRunnerConfig{OutputLimit: 1024})
	gateway, gatewayErr := plugingateway.NewClient(plugingateway.ClientConfig{RuntimeRoot: filepath.Join(root, "runtime"), Scope: plugingateway.MetricScope{AgentID: "agent-1", HostID: "host-1"}, Store: metricSpool, Timeout: time.Second})
	require.NoError(t, gatewayErr)
	newSupervisor := func() *PluginSupervisor {
		supervisor, supervisorErr := NewPluginSupervisor(PluginSupervisorConfig{AgentID: "agent-1", HostID: "host-1", RuntimeRoot: filepath.Join(root, "runtime"), Store: stateStore, Installer: installer, Leases: leasing, Downloader: leasing, Processes: processRunner, Health: NewGatewayHealthChecker(gateway), UserID: uid, GroupID: gid, DrainTimeout: 3 * time.Second, FailureWindow: 10 * time.Minute, FailureThreshold: 5, RestartBase: 20 * time.Millisecond, RestartMaximum: 50 * time.Millisecond})
		require.NoError(t, supervisorErr)
		return supervisor
	}
	supervisor := newSupervisor()
	request := probeRequest(stable, "artifact-1", "1.0.0", 1)
	prepared, err := supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	commandContext, cancelCommand := context.WithCancel(context.Background())
	running, err := supervisor.Start(commandContext, prepared, validFence())
	require.NoError(t, err)
	cancelCommand()
	time.Sleep(50 * time.Millisecond)
	require.Equal(t, pluginstate.ProcessRunning, running.State.ProcessState)
	require.Equal(t, uint32(2), running.State.BoundInstanceCount)
	firstPID := running.State.ProcessID
	require.True(t, processExists(firstPID), "terminal command context must not own the healthy plugin lifetime")
	require.Zero(t, linuxCapabilityValue(t, firstPID, "CapEff:"))
	require.Zero(t, linuxCapabilityValue(t, firstPID, "CapAmb:"))
	assertProbeLaunch(t, filepath.Join(root, "runtime", "mysql", "launch.json"), int(uid))
	require.Eventually(t, func() bool {
		return strings.Contains(string(requireReadFile(t, filepath.Join(root, "runtime", "mysql", "protocol.log"))), "stream:2")
	}, time.Second, 20*time.Millisecond)

	metricSpool.failNext.Store(true)
	var streamRecovered pluginstate.FamilyState
	var receipt spool.CursorReceipt
	require.Eventually(t, func() bool {
		var ok bool
		streamRecovered, ok = stateStore.Get("mysql")
		var found bool
		receipt, found, _ = spoolStore.Cursor(context.Background(), "assignment-1\x001\x00template-1\x00mysql-1")
		return ok && streamRecovered.ProcessState == pluginstate.ProcessRunning && streamRecovered.ProcessID > 0 && streamRecovered.ProcessID != firstPID && found && receipt.Sequence == 2
	}, 8*time.Second, 20*time.Millisecond)
	require.False(t, processExists(firstPID), "spool failure must terminate the monitored plugin process")
	require.Equal(t, uint64(2), receipt.Sequence, "restart must resume the exact failed stream cursor")
	protocolEvidence := string(requireReadFile(t, filepath.Join(root, "runtime", "mysql", "protocol.log")))
	for _, evidence := range []string{"apply", "validate:mysql-1", "validate:mysql-2", "collect", "stream:2", "ack:1", "ack:2"} {
		require.Contains(t, protocolEvidence, evidence)
	}
	require.Contains(t, protocolEvidence, "stream:2:1")
	require.Contains(t, protocolEvidence, "stream:2:2", "lost spool write must restart from the exact durable sequence")
	firstPID = streamRecovered.ProcessID

	upgrade := probeRequest(failing, "artifact-2", "1.1.0", 2)
	prepared, err = supervisor.Prepare(context.Background(), upgrade)
	require.NoError(t, err)
	rolledBack, err := supervisor.Start(context.Background(), prepared, validFence())
	require.ErrorIs(t, err, ErrHealthHandshake)
	require.Equal(t, "1.0.0", rolledBack.State.InstalledVersion)
	require.Equal(t, pluginstate.ProcessRunning, rolledBack.State.ProcessState)
	require.NotEqual(t, firstPID, rolledBack.State.ProcessID)
	require.False(t, processExists(firstPID))

	require.NoError(t, supervisor.Stop(context.Background()))
	require.False(t, processExists(rolledBack.State.ProcessID))
	restartedSupervisor := newSupervisor()
	var restarted pluginstate.FamilyState
	require.Eventually(t, func() bool {
		var ok bool
		restarted, ok = stateStore.Get("mysql")
		return ok && restarted.ProcessState == pluginstate.ProcessRunning && restarted.ProcessID > 0
	}, 5*time.Second, 20*time.Millisecond)
	require.True(t, processExists(restarted.ProcessID), "desired-running plugin must self-recover after Agent restart without a new command")

	stoppedRequest := probeRequest(stable, "artifact-1", "1.0.0", 3)
	stoppedRequest.DesiredState = DesiredStopped
	prepared, err = restartedSupervisor.Prepare(context.Background(), stoppedRequest)
	require.NoError(t, err)
	stopped, err := restartedSupervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.ProcessStopped, stopped.State.ProcessState)
	require.False(t, processExists(restarted.ProcessID))

	absentRequest := probeRequest(stable, "artifact-1", "1.0.0", 4)
	absentRequest.DesiredState = DesiredAbsent
	absentRequest.DesiredVersion, absentRequest.ArtifactID = "", ""
	absentRequest.ArtifactSHA256, absentRequest.ManifestDigest = nil, nil
	prepared, err = restartedSupervisor.Prepare(context.Background(), absentRequest)
	require.NoError(t, err)
	absent, err := restartedSupervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.ProcessAbsent, absent.State.ProcessState)
	require.NoDirExists(t, filepath.Join(root, "plugins", "mysql"))
	require.Eventually(t, func() bool {
		_, statErr := os.Lstat(filepath.Join(root, "runtime", "mysql", "plugin.sock"))
		return errors.Is(statErr, os.ErrNotExist)
	}, time.Second, 10*time.Millisecond)

	crashRequest := probeRequest(crashing, "artifact-3", "1.2.0", 5)
	prepared, err = restartedSupervisor.Prepare(context.Background(), crashRequest)
	require.NoError(t, err)
	_, err = restartedSupervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		state, ok := stateStore.Get("mysql")
		return ok && state.CircuitState == pluginstate.CircuitOpen && state.ProcessState == pluginstate.ProcessCircuitOpen
	}, 5*time.Second, 20*time.Millisecond)
}

type probePackage struct {
	archive        []byte
	artifactDigest [sha256.Size]byte
	manifestDigest [sha256.Size]byte
}

type probeLeaseClient struct {
	packages map[string]probePackage
	current  string
}

func (client *probeLeaseClient) LeasePluginArtifact(_ context.Context, request ArtifactLeaseRequest) (ArtifactLease, error) {
	if _, ok := client.packages[request.ArtifactID]; !ok {
		return ArtifactLease{}, ErrArtifactLease
	}
	client.current = request.ArtifactID
	return ArtifactLease{LeaseID: "lease-1", AssignmentID: request.AssignmentID, ArtifactID: request.ArtifactID, OperationRevision: request.OperationRevision, ExpiresAt: time.Now().Add(time.Minute), DownloadURL: "https://dbpilot.internal/plugin"}, nil
}
func (client *probeLeaseClient) Download(_ context.Context, lease ArtifactLease) (DownloadedArtifact, error) {
	value, ok := client.packages[lease.ArtifactID]
	if !ok {
		return DownloadedArtifact{}, ErrArtifactDownload
	}
	return DownloadedArtifact{Body: io.NopCloser(bytes.NewReader(value.archive)), Size: int64(len(value.archive))}, nil
}

func buildProbePackage(t *testing.T, executable []byte, privateKey ed25519.PrivateKey, version string) probePackage {
	t.Helper()
	executableDigest := sha256.Sum256(executable)
	binaryPath := "plugin-package/bin/linux-amd64/dbpilot-plugin-mysql"
	manifest := map[string]any{"plugin_id": "mysql", "database_family": "mysql", "version": version, "protocol_version": "v1", "publisher_id": "fixture-publisher", "signing_key_id": "fixture-key", "minimum_agent_protocol_version": "v1", "maximum_agent_protocol_version": "v1", "supported_variants": []string{"mysql"}, "database_version_range": ">=8 <9", "capabilities": []string{"metrics.collect"}, "metric_template_schema_version": 1, "binaries": []map[string]any{{"operating_system": "linux", "architecture": "amd64", "path": binaryPath, "sha256": hex.EncodeToString(executableDigest[:]), "size_bytes": len(executable)}}, "files": []map[string]any{{"path": binaryPath, "sha256": hex.EncodeToString(executableDigest[:]), "size_bytes": len(executable)}}}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestDigest := sha256.Sum256(manifestBytes)
	regular := map[string][]byte{"plugin-package/manifest.json": manifestBytes, binaryPath: executable}
	contentDigest := probeContentDigest(regular)
	message := []byte("dbpilot-plugin-signature-v1\nmanifest-sha256:" + hex.EncodeToString(manifestDigest[:]) + "\ncontent-sha256:" + hex.EncodeToString(contentDigest[:]) + "\n")
	signature := ed25519.Sign(privateKey, message)
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	entries := []struct {
		name string
		body []byte
		mode int64
	}{{"plugin-package/manifest.json", manifestBytes, 0o400}, {binaryPath, executable, 0o500}, {"plugin-package/SIGNATURE.ed25519", signature, 0o400}}
	for _, entry := range entries {
		require.NoError(t, tarWriter.WriteHeader(&tar.Header{Name: entry.name, Typeflag: tar.TypeReg, Mode: entry.mode, Size: int64(len(entry.body)), ModTime: time.Unix(0, 0).UTC()}))
		_, err = tarWriter.Write(entry.body)
		require.NoError(t, err)
	}
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())
	artifactDigest := sha256.Sum256(compressed.Bytes())
	return probePackage{archive: compressed.Bytes(), artifactDigest: artifactDigest, manifestDigest: manifestDigest}
}

func probeContentDigest(entries map[string][]byte) [sha256.Size]byte {
	paths := make([]string, 0, len(entries))
	for name := range entries {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	hash := sha256.New()
	_, _ = io.WriteString(hash, "dbpilot-plugin-content-v1\n")
	for _, name := range paths {
		digest := sha256.Sum256(entries[name])
		for _, value := range []string{name, strconv.Itoa(len(entries[name])), hex.EncodeToString(digest[:])} {
			_, _ = io.WriteString(hash, strconv.Itoa(len(value))+":"+value)
		}
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func probeRequest(value probePackage, artifactID, version string, operation uint64) ReconcileRequest {
	template := &pluginv1.MetricTemplateConfiguration{TemplateId: "template-1", Revision: 1, QueryDigest: bytes.Repeat([]byte{1}, sha256.Size), QueryKind: "sql", ReadOnlyStatement: "SELECT value", CollectionIntervalSeconds: 10, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, ValueMappings: []*pluginv1.MetricValueMapping{{SourceColumn: "value", MetricName: "mysql.connections.current", MetricType: "gauge", Unit: "1"}}}
	return ReconcileRequest{AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", DesiredVersion: version, DesiredState: DesiredRunning, ArtifactID: artifactID, ArtifactSHA256: append([]byte(nil), value.artifactDigest[:]...), ManifestDigest: append([]byte(nil), value.manifestDigest[:]...), ConfigurationRevision: operation, OperationRevision: operation, InstanceIDs: []string{"mysql-1", "mysql-2"}, InstanceDescriptors: []InstanceDescriptor{{InstanceID: "mysql-1", DatabaseVariant: "mysql", Endpoint: "127.0.0.1:3306"}, {InstanceID: "mysql-2", DatabaseVariant: "mysql", UnixSocket: "/run/mysql-2.sock"}}, TemplateIDs: []string{"template-1"}, TemplateConfigurations: []*pluginv1.MetricTemplateConfiguration{template}, CredentialsComplete: true}
}

type probeMetricSpool struct {
	*spool.Store
	failNext atomic.Bool
}

func (value *probeMetricSpool) AppendWithCursor(ctx context.Context, class spool.DataClass, batch spool.Batch, receipt spool.CursorReceipt) (spool.CursorAppendResult, error) {
	if value.failNext.Swap(false) {
		return 0, errors.New("injected spool failure")
	}
	return value.Store.AppendWithCursor(ctx, class, batch, receipt)
}

func linuxCapabilityValue(t *testing.T, pid int, name string) uint64 {
	t.Helper()
	body := requireReadFile(t, filepath.Join("/proc", strconv.Itoa(pid), "status"))
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, name) {
			value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, name)), 16, 64)
			require.NoError(t, err)
			return value
		}
	}
	t.Fatalf("missing %s for pid %d", name, pid)
	return 0
}

func processExists(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func assertProbeLaunch(t *testing.T, path string, uid int) {
	t.Helper()
	var value struct {
		UID         int               `json:"uid"`
		InstanceIDs []string          `json:"instance_ids"`
		Environment map[string]string `json:"environment"`
		Args        []string          `json:"args"`
	}
	require.NoError(t, json.Unmarshal(requireReadFile(t, path), &value))
	require.Equal(t, uid, value.UID)
	require.Equal(t, []string{"mysql-1", "mysql-2"}, value.InstanceIDs)
	require.NotContains(t, value.Environment, "DBPILOT_SECRET_SENTINEL")
	require.NotContains(t, strings.Join(value.Args, " "), "/bin/sh")
}
