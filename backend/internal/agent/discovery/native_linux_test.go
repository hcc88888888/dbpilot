//go:build linux

package discovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	domain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/require"
)

func TestProcReaderDetectsMySQLPortAndRedactsCredentialArguments(t *testing.T) {
	root := t.TempDir()
	writeProcProcess(t, root, "4242", "/usr/sbin/mysqld", "mysqld", "/spoofed/argv0\x00--port=3307\x00--password=hunter2\x00", "12345")
	pidRoot := filepath.Join(root, "4242")
	require.NoError(t, os.Symlink("socket:[777]", filepath.Join(pidRoot, "fd", "8")))
	require.NoError(t, os.Symlink("socket:[888]", filepath.Join(pidRoot, "fd", "9")))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "net"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "tcp"), []byte("  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n   0: 0100007F:0CEB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 27 0 777 1\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "unix"), []byte("Num RefCount Protocol Flags Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 888 /run/mysqld/mysql.sock\n"), 0o600))

	reader := NewProcReader(root, nil)
	detector := NewNativeDetector(reader)
	candidates, err := detector.Discover(context.Background(), []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3306}, UnixSocketPatterns: []string{`^/run/mysqld/[^/]+\.sock$`}}})
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, "127.0.0.1:3307", candidates[0].NormalizedEndpoint)
	require.Equal(t, "/run/mysqld/mysql.sock", candidates[0].UnixSocket)
	require.Equal(t, "/usr/sbin/mysqld", candidates[0].ProcessIdentity)
	encoded := candidates[0].ProcessIdentity
	for _, evidence := range candidates[0].Evidence {
		encoded += evidence.Value
	}
	require.NotContains(t, encoded, "hunter2")
	require.NotContains(t, encoded, "password")
	require.NotContains(t, encoded, "/spoofed/argv0")
}

func TestProcReaderRejectsSpoofedCommAndArgvZero(t *testing.T) {
	root := t.TempDir()
	writeProcProcess(t, root, "4242", "/usr/bin/not-a-database", "mysqld", "/usr/sbin/mysqld\x00--port=3307\x00", "12345")
	require.NoError(t, os.MkdirAll(filepath.Join(root, "net"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "tcp"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "unix"), nil, 0o600))

	candidates, err := NewNativeDetector(NewProcReader(root, nil)).Discover(context.Background(), []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3307}}})
	require.NoError(t, err)
	require.Empty(t, candidates)
}

func TestProcReaderRejectsPIDReuseAcrossSnapshot(t *testing.T) {
	root := t.TempDir()
	writeProcProcess(t, root, "4242", "/usr/sbin/mysqld", "mysqld", "/usr/sbin/mysqld\x00--port=3307\x00", "12345")
	reader := NewProcReader(root, nil)
	originalRead := reader.readFile
	statReads := 0
	reader.readFile = func(path string, maximum int64) ([]byte, error) {
		value, err := originalRead(path, maximum)
		if filepath.Base(path) == "stat" {
			statReads++
			if statReads == 2 {
				return []byte(procStat("4242", "mysqld", "67890")), nil
			}
		}
		return value, err
	}

	processes, err := reader.Processes(context.Background())
	require.NoError(t, err)
	require.Empty(t, processes)
}

func TestProcReaderReturnsExplicitPermissionCapabilityError(t *testing.T) {
	root := t.TempDir()
	writeProcProcess(t, root, "4242", "/usr/sbin/mysqld", "mysqld", "/usr/sbin/mysqld\x00--port=3307\x00", "12345")
	reader := NewProcReader(root, nil)
	reader.readLink = func(string, int) (string, error) { return "", syscall.EACCES }

	_, err := reader.Processes(context.Background())
	require.ErrorIs(t, err, ErrNativeDiscoveryPermissionDenied)
	require.ErrorContains(t, err, "permission_denied")
}

func TestProcReaderRejectsOversizedProcFile(t *testing.T) {
	root := t.TempDir()
	writeProcProcess(t, root, "4242", "/usr/sbin/mysqld", "mysqld", strings.Repeat("x", maximumCmdlineBytes+1), "12345")

	_, err := NewProcReader(root, nil).Processes(context.Background())
	require.ErrorIs(t, err, ErrNativeDiscoveryDataTooLarge)
}

func TestDetectorEnforcesSignedSocketPatternForArgument(t *testing.T) {
	reader := &fakeNativeReader{processes: []ProcessObservation{{PID: 42, Name: "mysqld", Executable: "/usr/sbin/mysqld", RequestedSocket: "/tmp/unsigned.sock", StartTime: 7}}}
	candidates, err := NewNativeDetector(reader).Discover(context.Background(), []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, UnixSocketPatterns: []string{`^/run/mysqld/[^/]+\.sock$`}}})
	require.NoError(t, err)
	require.Empty(t, candidates)
}

func TestDetectorReturnsExplicitPermissionCapabilityErrorForFDInspection(t *testing.T) {
	reader := &fakeNativeReader{processes: []ProcessObservation{{PID: 42, Name: "mysqld", Executable: "/usr/sbin/mysqld", StartTime: 7}}, endpointsErr: syscall.EPERM}
	_, err := NewNativeDetector(reader).Discover(context.Background(), []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3306}}})
	require.ErrorIs(t, err, ErrNativeDiscoveryPermissionDenied)
}

func TestDetectorRejectsPIDReuseAfterSystemdAndEndpointCollection(t *testing.T) {
	reader := &fakeNativeReader{
		processes: []ProcessObservation{{PID: 42, Name: "mysqld", Executable: "/usr/sbin/mysqld", StartTime: 7}},
		endpoints: []EndpointObservation{{Network: "tcp", Address: "127.0.0.1:3306"}},
		startTime: 8,
	}
	candidates, err := NewNativeDetector(reader).Discover(context.Background(), []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3306}}})
	require.NoError(t, err)
	require.Empty(t, candidates)
	require.True(t, reader.systemdRead)
	require.True(t, reader.endpointsRead)
	require.True(t, reader.finalStartRead)
}

func TestPIDFDFallbackReportsLegacyKernelCapabilityRequirement(t *testing.T) {
	originalOpen := pidfdOpen
	originalLegacy := legacySocketInodeReader
	pidfdOpen = func(int, int) (int, error) { return -1, syscall.ENOSYS }
	legacySocketInodeReader = func(int, int) (map[string]struct{}, error) {
		return nil, fmt.Errorf("%w: legacy_proc_helper_unavailable", ErrNativeDiscoveryPermissionDenied)
	}
	t.Cleanup(func() { pidfdOpen = originalOpen; legacySocketInodeReader = originalLegacy })

	_, err := socketInodesViaPIDFD(42, 16)
	require.ErrorIs(t, err, ErrNativeDiscoveryPermissionDenied)
	require.ErrorContains(t, err, "legacy_proc_helper_unavailable")
}

func TestPIDFDFallbackUsesFixedLegacyHelper(t *testing.T) {
	originalOpen := pidfdOpen
	originalLegacy := legacySocketInodeReader
	pidfdOpen = func(int, int) (int, error) { return -1, syscall.ENOSYS }
	legacySocketInodeReader = func(pid, maximum int) (map[string]struct{}, error) {
		require.Equal(t, 42, pid)
		require.Equal(t, 16, maximum)
		return map[string]struct{}{"777": {}}, nil
	}
	t.Cleanup(func() { pidfdOpen = originalOpen; legacySocketInodeReader = originalLegacy })

	inodes, err := socketInodesViaPIDFD(42, 16)
	require.NoError(t, err)
	require.Equal(t, map[string]struct{}{"777": {}}, inodes)
}

func TestProcReaderIgnoresNonAllowlistedProcFiles(t *testing.T) {
	root := t.TempDir()
	writeProcProcess(t, root, "4242", "/usr/sbin/mysqld", "mysqld", "/usr/sbin/mysqld\x00--port=3307\x00", "12345")
	require.NoError(t, os.WriteFile(filepath.Join(root, "4242", "environ"), []byte("TOKEN=secret"), 0o000))

	processes, err := NewProcReader(root, nil).Processes(context.Background())
	require.NoError(t, err)
	require.Len(t, processes, 1)
}

func writeProcProcess(t *testing.T, root, pid, executable, comm, cmdline, startTime string) {
	t.Helper()
	pidRoot := filepath.Join(root, pid)
	require.NoError(t, os.MkdirAll(filepath.Join(pidRoot, "fd"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "comm"), []byte(comm+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "cmdline"), []byte(cmdline), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "stat"), []byte(procStat(pid, comm, startTime)), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "status"), []byte("Name:\t"+comm+"\nUid:\t27\t27\t27\t27\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "cgroup"), []byte("0::/user.slice/test.scope\n"), 0o600))
	require.NoError(t, os.Symlink(executable, filepath.Join(pidRoot, "exe")))
}

func procStat(pid, comm, startTime string) string {
	return pid + " (" + comm + ") S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 " + startTime + " 0 0"
}

type fakeNativeReader struct {
	processes      []ProcessObservation
	endpoints      []EndpointObservation
	endpointsErr   error
	startTime      uint64
	systemdRead    bool
	endpointsRead  bool
	finalStartRead bool
}

func (reader *fakeNativeReader) Processes(context.Context) ([]ProcessObservation, error) {
	return reader.processes, nil
}
func (reader *fakeNativeReader) ListeningEndpoints(context.Context, int) ([]EndpointObservation, error) {
	reader.endpointsRead = true
	return reader.endpoints, reader.endpointsErr
}
func (reader *fakeNativeReader) SystemdUnit(context.Context, int) (string, bool, error) {
	reader.systemdRead = true
	return "", false, nil
}
func (reader *fakeNativeReader) ProcessStartTime(context.Context, int) (uint64, error) {
	reader.finalStartRead = true
	if reader.startTime != 0 {
		return reader.startTime, nil
	}
	for _, process := range reader.processes {
		return process.StartTime, nil
	}
	return 0, os.ErrNotExist
}
