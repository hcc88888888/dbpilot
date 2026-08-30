package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDockerHelperRejectsZeroPeerIdentityBeforeOpeningSockets(t *testing.T) {
	var stderr bytes.Buffer
	exit := run([]string{"--docker-socket", "/var/run/docker.sock", "--agent-socket", "/run/dbpilot-agent/docker-discovery.sock", "--allowed-uid", "0", "--allowed-gid", "1001", "--allowed-labels", "dbpilot.discovery.family"}, &stderr)
	require.Equal(t, 2, exit)
	require.Contains(t, stderr.String(), "nonzero")
}

func TestDockerHelperRejectsUnboundedOrUnsafeLabelAllowlist(t *testing.T) {
	for _, labels := range []string{"dbpilot.discovery.family,password/bad", ",", "dbpilot.discovery.family,dbpilot.discovery.family"} {
		var stderr bytes.Buffer
		exit := run([]string{"--docker-socket", "/var/run/docker.sock", "--agent-socket", "/run/dbpilot-agent/docker-discovery.sock", "--allowed-uid", "1001", "--allowed-gid", "1001", "--allowed-labels", labels}, &stderr)
		require.Equal(t, 2, exit, labels)
	}
}
