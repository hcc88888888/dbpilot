//go:build linux

package discovery

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	"dbpilot.local/platform/internal/dockerdiscovery"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestLocalHelperBoundaryDeniesAgentProcessAndDockerSocketEscalation(t *testing.T) {
	pidRaw := os.Getenv("DBPILOT_BOUNDARY_DOCKER_HELPER_PID")
	if pidRaw == "" {
		t.Skip("container boundary fixture is not configured")
	}
	pid, err := strconv.Atoi(pidRaw)
	require.NoError(t, err)
	require.Positive(t, pid)

	selfStatus := readProcStatus(t, "/proc/self/status")
	require.Equal(t, "0000000000000000", selfStatus["CapEff"])
	require.Equal(t, "0000000000000000", selfStatus["CapAmb"])
	helperStatus := readProcStatus(t, filepath.Join("/proc", pidRaw, "status"))
	require.NotEqual(t, firstStatusID(t, selfStatus["Uid"]), firstStatusID(t, helperStatus["Uid"]))

	_, err = os.Open(filepath.Join("/proc", pidRaw, "mem"))
	require.Error(t, err)
	_, err = os.ReadDir(filepath.Join("/proc", pidRaw, "fd"))
	require.Error(t, err)
	require.Error(t, unix.PtraceAttach(pid))
	buffer := []byte{0}
	local := []unix.Iovec{{Base: &buffer[0], Len: 1}}
	remote := []unix.RemoteIovec{{Base: 0, Len: 1}}
	_, err = unix.ProcessVMReadv(pid, local, remote, 0)
	require.Error(t, err)
	if pidfd, openErr := unix.PidfdOpen(pid, 0); openErr == nil {
		defer unix.Close(pidfd)
		_, err = unix.PidfdGetfd(pidfd, 0, 0)
		require.Error(t, err)
	}

	_, err = os.Open("/var/run/docker.sock")
	require.Error(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := dockerdiscovery.Dial(ctx, os.Getenv("DBPILOT_DOCKER_HELPER_SOCKET"))
	require.NoError(t, err)
	defer connection.Close()
	response, err := discoveryv1.NewDockerDiscoveryClient(connection).Snapshot(ctx, &discoveryv1.DockerSnapshotRequest{RuleRevision: 1, AllowedLabelKeys: []string{"dbpilot.discovery.family", "dbpilot.run"}})
	require.NoError(t, err)
	require.NotEmpty(t, response.GetContainers())

	_, err = requestLegacyProcessAt(os.Getenv("DBPILOT_PROC_HELPER_SOCKET"), pid)
	require.Error(t, err, "proc helper must not return facts or descriptors for the Docker helper PID")
}

func readProcStatus(t *testing.T, path string) map[string]string {
	t.Helper()
	file, err := os.Open(path)
	require.NoError(t, err)
	defer file.Close()
	result := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if ok {
			result[key] = strings.TrimSpace(value)
		}
	}
	require.NoError(t, scanner.Err())
	return result
}

func firstStatusID(t *testing.T, value string) uint64 {
	t.Helper()
	fields := strings.Fields(value)
	require.NotEmpty(t, fields)
	parsed, err := strconv.ParseUint(fields[0], 10, 32)
	require.NoError(t, err)
	return parsed
}
