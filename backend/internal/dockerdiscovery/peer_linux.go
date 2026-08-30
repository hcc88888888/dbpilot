//go:build linux

package dockerdiscovery

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func peerCredentials(connection net.Conn) (uint32, uint32, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("Docker discovery peer is not AF_UNIX")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var uid, gid uint32
	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			credentialErr = err
			return
		}
		uid, gid = credentials.Uid, credentials.Gid
	}); err != nil {
		return 0, 0, err
	}
	return uid, gid, credentialErr
}
