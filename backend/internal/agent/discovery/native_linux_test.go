//go:build linux

package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	domain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/require"
)

func TestProcReaderDetectsMySQLPortAndRedactsCredentialArguments(t *testing.T) {
	root := t.TempDir()
	pidRoot := filepath.Join(root, "4242")
	require.NoError(t, os.MkdirAll(filepath.Join(pidRoot, "fd"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "comm"), []byte("mysqld\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "cmdline"), []byte("/usr/sbin/mysqld\x00--port=3307\x00--password=hunter2\x00"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "stat"), []byte("4242 (mysqld) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 12345 0 0"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "status"), []byte("Name:\tmysqld\nUid:\t27\t27\t27\t27\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pidRoot, "cgroup"), []byte("0::/system.slice/mysqld.service\n"), 0o600))
	require.NoError(t, os.Symlink("socket:[777]", filepath.Join(pidRoot, "fd", "8")))
	require.NoError(t, os.Symlink("socket:[888]", filepath.Join(pidRoot, "fd", "9")))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "net"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "tcp"), []byte("  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n   0: 0100007F:0CEB 00000000:0000 0A 00000000:00000000 00:00000000 00000000 27 0 777 1\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "net", "unix"), []byte("Num RefCount Protocol Flags Type St Inode Path\n0000000000000000: 00000002 00000000 00010000 0001 01 888 /run/mysqld/mysql.sock\n"), 0o600))

	reader := NewProcReader(root, nil)
	detector := NewNativeDetector(reader)
	candidates, err := detector.Discover(context.Background(), []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", SystemdUnits: []string{"mysqld.service"}, DefaultPorts: []uint16{3306}, UnixSocketPatterns: []string{`^/run/mysqld/[^/]+\.sock$`}}})
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, "127.0.0.1:3307", candidates[0].NormalizedEndpoint)
	require.Equal(t, "/run/mysqld/mysql.sock", candidates[0].UnixSocket)
	for _, evidence := range candidates[0].Evidence {
		require.NotContains(t, evidence.Value, "hunter2")
		require.NotContains(t, evidence.Value, "password")
	}
}

func TestProcReaderIgnoresNonAllowlistedProcFiles(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "self-environ"), []byte("TOKEN=secret"), 0o600))
	reader := NewProcReader(root, nil)
	_, err := reader.Processes(context.Background())
	require.NoError(t, err)
}
