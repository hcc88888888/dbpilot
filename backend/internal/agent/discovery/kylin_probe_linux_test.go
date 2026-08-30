//go:build linux

package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	domain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/require"
)

func TestKylinNativeDiscoveryProbe(t *testing.T) {
	if os.Getenv("DBPILOT_KYLIN_DISCOVERY_PROBE") != "1" {
		t.Skip("Kylin probe is disabled")
	}
	port, err := strconv.ParseUint(os.Getenv("DBPILOT_KYLIN_DISCOVERY_PORT"), 10, 16)
	require.NoError(t, err)
	capabilitySets := map[string]string{}
	for _, field := range []string{"CapBnd:", "CapAmb:", "CapEff:"} {
		value, err := selfCapability(field)
		require.NoError(t, err)
		require.Equal(t, "0000000000080000", value)
		capabilitySets[field] = value
	}
	detector := NewNativeDetector(NewProcReader("/proc", nil))
	candidates, err := detector.Discover(context.Background(), []domain.Rule{{ID: "mysql-kylin", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld-dbp"}, DefaultPorts: []uint16{uint16(port)}}})
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, fmt.Sprintf("127.0.0.1:%d", port), candidates[0].NormalizedEndpoint)
	require.Equal(t, "/probe/mysqld-dbp", candidates[0].ProcessIdentity)
	encoded, err := json.Marshal(candidates)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "dbpilot-probe-secret")
	t.Logf("CAP_BND=%s CAP_AMB=%s CAP_EFF=%s CANDIDATES=%s", capabilitySets["CapBnd:"], capabilitySets["CapAmb:"], capabilitySets["CapEff:"], string(encoded))
}

func TestKylinNativeDiscoveryPermissionDenied(t *testing.T) {
	if os.Getenv("DBPILOT_KYLIN_DISCOVERY_PERMISSION_PROBE") != "1" {
		t.Skip("Kylin permission probe is disabled")
	}
	capEff, err := selfCapability("CapEff:")
	require.NoError(t, err)
	require.Equal(t, "0000000000000000", capEff)
	_, err = NewProcReader("/proc", nil).Processes(context.Background())
	require.ErrorIs(t, err, ErrNativeDiscoveryPermissionDenied)
	t.Logf("CAP_EFF=%s CAPABILITY_STATE=unavailable REASON=permission_denied", capEff)
}

func selfCapability(prefix string) (string, error) {
	status, err := readBoundedFile("/proc/self/status", maximumStatusBytes)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, prefix) {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				return fields[1], nil
			}
		}
	}
	return "", errors.New("capability field is unavailable")
}
