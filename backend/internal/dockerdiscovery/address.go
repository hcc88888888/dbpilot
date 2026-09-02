package dockerdiscovery

import "net"

// IsSafeInternalIP permits only unicast addresses that identify one reachable
// container endpoint. It deliberately excludes wildcard, loopback, link-local,
// and multicast address classes.
func IsSafeInternalIP(address net.IP) bool {
	return address != nil && address.IsGlobalUnicast()
}
