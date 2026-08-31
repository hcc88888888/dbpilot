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
	"syscall"
	"testing"
	"time"

	"dbpilot.local/platform/internal/agent/pluginstate"
	"dbpilot.local/platform/internal/plugincatalog"
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
	uid, gid, nonRoot := CurrentProcessIdentity()
	require.True(t, nonRoot)
	leasing := &probeLeaseClient{packages: map[string]probePackage{"artifact-1": stable, "artifact-2": failing}}
	processRunner := NewOSProcessRunner(OSProcessRunnerConfig{OutputLimit: 1024})
	newSupervisor := func() *PluginSupervisor {
		supervisor, supervisorErr := NewPluginSupervisor(PluginSupervisorConfig{AgentID: "agent-1", HostID: "host-1", RuntimeRoot: filepath.Join(root, "runtime"), Store: stateStore, Installer: installer, Leases: leasing, Downloader: leasing, Processes: processRunner, Health: NewGRPCHealthChecker(GRPCHealthCheckerConfig{Timeout: 5 * time.Second}), UserID: uid, GroupID: gid, DrainTimeout: 3 * time.Second, FailureWindow: 10 * time.Minute, FailureThreshold: 5})
		require.NoError(t, supervisorErr)
		return supervisor
	}
	supervisor := newSupervisor()
	request := probeRequest(stable, "artifact-1", "1.0.0", 1)
	prepared, err := supervisor.Prepare(context.Background(), request)
	require.NoError(t, err)
	running, err := supervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.ProcessRunning, running.State.ProcessState)
	require.Equal(t, uint32(2), running.State.BoundInstanceCount)
	firstPID := running.State.ProcessID
	require.Zero(t, linuxCapabilityValue(t, firstPID, "CapEff:"))
	require.Zero(t, linuxCapabilityValue(t, firstPID, "CapAmb:"))
	assertProbeLaunch(t, filepath.Join(root, "runtime", "mysql", "launch.json"), int(uid))

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
	restartRequest := probeRequest(stable, "artifact-1", "1.0.0", 3)
	prepared, err = restartedSupervisor.Prepare(context.Background(), restartRequest)
	require.NoError(t, err)
	restarted, err := restartedSupervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.ProcessRunning, restarted.State.ProcessState)
	require.True(t, processExists(restarted.State.ProcessID))

	stoppedRequest := restartRequest
	stoppedRequest.OperationRevision = 4
	stoppedRequest.DesiredState = DesiredStopped
	prepared, err = restartedSupervisor.Prepare(context.Background(), stoppedRequest)
	require.NoError(t, err)
	stopped, err := restartedSupervisor.Start(context.Background(), prepared, validFence())
	require.NoError(t, err)
	require.Equal(t, pluginstate.ProcessStopped, stopped.State.ProcessState)
	require.False(t, processExists(restarted.State.ProcessID))

	absentRequest := restartRequest
	absentRequest.OperationRevision = 5
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
	return ReconcileRequest{AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", DesiredVersion: version, DesiredState: DesiredRunning, ArtifactID: artifactID, ArtifactSHA256: append([]byte(nil), value.artifactDigest[:]...), ManifestDigest: append([]byte(nil), value.manifestDigest[:]...), ConfigurationRevision: operation, OperationRevision: operation, InstanceIDs: []string{"mysql-1", "mysql-2"}, TemplateIDs: []string{"template-1"}}
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
