//go:build linux

package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
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
	detector := NewNativeDetector(NewProcReader("/proc", nil))
	candidates, err := detector.Discover(context.Background(), []domain.Rule{{ID: "mysql-kylin", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld-dbp"}, DefaultPorts: []uint16{uint16(port)}}})
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, fmt.Sprintf("127.0.0.1:%d", port), candidates[0].NormalizedEndpoint)
	encoded, err := json.Marshal(candidates)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "dbpilot-probe-secret")
	t.Log(string(encoded))
}
