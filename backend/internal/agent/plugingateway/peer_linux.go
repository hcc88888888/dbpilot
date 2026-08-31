//go:build linux

package plugingateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func verifyPrivateRuntimeRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errGateway
	}
	return nil
}

func dialVerifiedPlugin(ctx context.Context, root string, expected ExpectedPlugin) (*grpc.ClientConn, error) {
	if ctx == nil || validateExpected(root, expected) != nil || verifyPrivateRuntimeRoot(root) != nil || verifyExecutable(expected.PID, expected.ExecutablePath, expected.ExecutableSHA256) != nil {
		return nil, errGateway
	}
	runtimeDirectory := filepath.Join(root, expected.DatabaseFamily)
	if runtimeDirectory != expected.RuntimeDirectory || verifyPrivateDirectory(runtimeDirectory) != nil {
		return nil, errGateway
	}
	socket := filepath.Join(runtimeDirectory, "plugin.sock")
	if waitForPrivateSocket(ctx, socket) != nil {
		return nil, errGateway
	}
	connection, err := grpc.DialContext(ctx, "passthrough:///dbpilot-private-plugin", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock(), grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(maxRPCMessageBytes), grpc.MaxCallRecvMsgSize(maxRPCMessageBytes)), grpc.WithContextDialer(func(dialContext context.Context, _ string) (net.Conn, error) {
		if verifySocket(socket) != nil {
			return nil, errGateway
		}
		connection, dialErr := (&net.Dialer{}).DialContext(dialContext, "unix", socket)
		if dialErr != nil {
			return nil, dialErr
		}
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok || verifyPeer(unixConnection, expected) != nil || verifySocket(socket) != nil || verifyExecutable(expected.PID, expected.ExecutablePath, expected.ExecutableSHA256) != nil {
			_ = connection.Close()
			return nil, errGateway
		}
		return connection, nil
	}))
	if err != nil {
		return nil, errGateway
	}
	return connection, nil
}

func waitForPrivateSocket(ctx context.Context, socket string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		info, err := os.Lstat(socket)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
				return errGateway
			}
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return errGateway
		}
		select {
		case <-ctx.Done():
			return errGateway
		case <-ticker.C:
		}
	}
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errGateway
	}
	return nil
}

func verifySocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return errGateway
	}
	return nil
}

func verifyPeer(connection *net.UnixConn, expected ExpectedPlugin) error {
	raw, err := connection.SyscallConn()
	if err != nil {
		return errGateway
	}
	var credential *unix.Ucred
	var credentialErr error
	if err = raw.Control(func(fd uintptr) {
		credential, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credentialErr != nil || credential == nil || int(credential.Pid) != expected.PID || credential.Uid != expected.ExpectedUserID || credential.Gid != expected.ExpectedGroupID || credential.Uid == 0 || credential.Gid == 0 {
		return errGateway
	}
	return nil
}

func verifyExecutable(pid int, expectedPath string, expectedDigest []byte) error {
	if pid <= 0 || len(expectedDigest) != sha256.Size {
		return errGateway
	}
	actualPath, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return errGateway
	}
	actualInfo, err := os.Stat(actualPath)
	if err != nil {
		return errGateway
	}
	expectedInfo, err := os.Stat(expectedPath)
	if err != nil || !os.SameFile(actualInfo, expectedInfo) {
		return errGateway
	}
	file, err := os.Open(actualPath)
	if err != nil {
		return errGateway
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, io.LimitReader(file, 512<<20+1)); err != nil || hex.EncodeToString(hash.Sum(nil)) != hex.EncodeToString(expectedDigest) {
		return errGateway
	}
	return nil
}
