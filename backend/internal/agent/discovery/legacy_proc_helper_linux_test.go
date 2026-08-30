//go:build linux

package discovery

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLegacyProcHelperReturnsOnlyBoundedSocketInodes(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyHelper(t, socketPath, uint32(os.Getuid()), uint32(os.Getgid()), currentProcessName(t))
	defer func() { cancel(); require.NoError(t, <-done) }()

	inodes, err := requestLegacySocketInodesAt(socketPath, os.Getpid(), maximumFDEntries)
	require.NoError(t, err)
	require.NotEmpty(t, inodes)
}

func TestLegacyProcHelperRejectsWrongPeer(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyHelper(t, socketPath, uint32(os.Getuid()+1), uint32(os.Getgid()), currentProcessName(t))
	defer func() { cancel(); require.NoError(t, <-done) }()
	_, err := requestLegacySocketInodesAt(socketPath, os.Getpid(), 16)
	require.Error(t, err)
}

func TestLegacyProcHelperRejectsWrongGID(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyPeerListener(t, socketPath, uint32(os.Getuid()), uint32(os.Getgid()+1), currentProcessName(t))
	defer func() { cancel(); require.NoError(t, <-done) }()
	_, err := requestLegacySocketInodesAt(socketPath, os.Getpid(), 16)
	require.Error(t, err)
}

func TestLegacyProcHelperRejectsMalformedOversizeAndForbiddenOperation(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyHelper(t, socketPath, uint32(os.Getuid()), uint32(os.Getgid()), currentProcessName(t))
	defer func() { cancel(); require.NoError(t, <-done) }()

	for _, mutate := range []func([]byte){
		func(request []byte) { binary.BigEndian.PutUint32(request[12:16], maximumFDEntries+1) },
		func(request []byte) { binary.BigEndian.PutUint16(request[6:8], 99) },
		func(request []byte) { copy(request[:4], []byte("PATH")) },
	} {
		connection, err := net.DialTimeout("unix", socketPath, time.Second)
		require.NoError(t, err)
		request := validLegacyRequest(os.Getpid(), 16)
		mutate(request)
		_, err = connection.Write(request)
		require.NoError(t, err)
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		_, err = io.ReadAll(io.LimitReader(connection, 64))
		require.NoError(t, err)
		require.NoError(t, connection.Close())
	}
}

func startLegacyPeerListener(t *testing.T, socketPath string, uid, gid uint32, allowedNames ...string) (context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	allowed := make(map[string]struct{}, len(allowedNames))
	for _, name := range allowedNames {
		allowed[name] = struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveLegacyConnections(ctx, listener, uid, gid, allowed) }()
	return cancel, done
}

func TestProcHelperRejectsFactsAndFDsForNonDatabaseProcess(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyHelper(t, socketPath, uint32(os.Getuid()), uint32(os.Getgid()), "mysqld")
	defer func() { cancel(); require.NoError(t, <-done) }()

	_, err := requestLegacyProcessAt(socketPath, os.Getpid())
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = requestLegacySocketInodesAt(socketPath, os.Getpid(), maximumFDEntries)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestProcHelperReturnsBoundedFactsForLocallyAllowlistedDatabaseProcess(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyHelper(t, socketPath, uint32(os.Getuid()), uint32(os.Getgid()), currentProcessName(t))
	defer func() { cancel(); require.NoError(t, <-done) }()

	process, err := requestLegacyProcessAt(socketPath, os.Getpid())
	require.NoError(t, err)
	require.Equal(t, os.Getpid(), process.PID)
	require.NotEmpty(t, process.Executable)
	require.NotContains(t, process.Executable, "docker.sock")
}

func validLegacyRequest(pid, maximum int) []byte {
	request := make([]byte, 16)
	copy(request[:4], legacyMagic[:])
	binary.BigEndian.PutUint16(request[4:6], 1)
	binary.BigEndian.PutUint16(request[6:8], 1)
	binary.BigEndian.PutUint32(request[8:12], uint32(pid))
	binary.BigEndian.PutUint32(request[12:16], uint32(maximum))
	return request
}

func startLegacyHelper(t *testing.T, socketPath string, uid, gid uint32, allowedNames ...string) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveLegacyProcHelperAt(ctx, socketPath, uid, gid, allowedNames) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Lstat(socketPath); err == nil {
			return cancel, done
		}
		if time.Now().After(deadline) {
			cancel()
			require.FailNow(t, "legacy helper socket was not created")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func currentProcessName(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	require.NoError(t, err)
	return strings.TrimSuffix(filepath.Base(executable), " (deleted)")
}
