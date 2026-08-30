//go:build linux

package discovery

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLegacyProcHelperReturnsOnlyBoundedSocketInodes(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyHelper(t, socketPath, uint32(os.Getuid()), uint32(os.Getgid()))
	defer func() { cancel(); require.NoError(t, <-done) }()

	inodes, err := requestLegacySocketInodesAt(socketPath, os.Getpid(), maximumFDEntries)
	require.NoError(t, err)
	require.NotEmpty(t, inodes)
}

func TestLegacyProcHelperRejectsWrongPeer(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyHelper(t, socketPath, uint32(os.Getuid()+1), uint32(os.Getgid()))
	defer func() { cancel(); require.NoError(t, <-done) }()
	_, err := requestLegacySocketInodesAt(socketPath, os.Getpid(), 16)
	require.Error(t, err)
}

func TestLegacyProcHelperRejectsWrongGID(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyHelper(t, socketPath, uint32(os.Getuid()), uint32(os.Getgid()+1))
	defer func() { cancel(); require.NoError(t, <-done) }()
	_, err := requestLegacySocketInodesAt(socketPath, os.Getpid(), 16)
	require.Error(t, err)
}

func TestLegacyProcHelperRejectsMalformedOversizeAndForbiddenOperation(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "proc-helper.sock")
	cancel, done := startLegacyHelper(t, socketPath, uint32(os.Getuid()), uint32(os.Getgid()))
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

func validLegacyRequest(pid, maximum int) []byte {
	request := make([]byte, 16)
	copy(request[:4], legacyMagic[:])
	binary.BigEndian.PutUint16(request[4:6], 1)
	binary.BigEndian.PutUint16(request[6:8], 1)
	binary.BigEndian.PutUint32(request[8:12], uint32(pid))
	binary.BigEndian.PutUint32(request[12:16], uint32(maximum))
	return request
}

func startLegacyHelper(t *testing.T, socketPath string, uid, gid uint32) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveLegacyProcHelperAt(ctx, socketPath, uid, gid) }()
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
