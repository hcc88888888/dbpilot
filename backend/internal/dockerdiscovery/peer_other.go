//go:build !linux

package dockerdiscovery

import (
	"errors"
	"net"
)

func peerCredentials(net.Conn) (uint32, uint32, error) {
	return 0, 0, errors.New("SO_PEERCRED is supported only on Linux")
}
