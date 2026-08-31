//go:build linux

package pluginsupervisor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dbpilot.local/platform/internal/agent/pluginstate"
	"github.com/stretchr/testify/require"
)

func TestLinuxProcessRunnerDirectExecUsesFixedArgvCleanEnvironmentAndBoundedOutput(t *testing.T) {
	fixture := os.Getenv("DBPILOT_PLUGIN_PROCESS_FIXTURE")
	if fixture == "" {
		t.Skip("DBPILOT_PLUGIN_PROCESS_FIXTURE is required for the exact Linux process probe")
	}
	runtimeDir := t.TempDir()
	executable := filepath.Join(runtimeDir, "dbpilot-plugin-mysql")
	body, err := os.ReadFile(fixture)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(executable, body, 0o500))
	digest := sha256.Sum256(body)
	t.Setenv("DBPILOT_SECRET_SENTINEL", "must-not-leak")

	var failureStage string
	var failureDetail error
	runner := NewOSProcessRunner(OSProcessRunnerConfig{OutputLimit: 1024, FailureObserver: func(stage string, detail error) { failureStage, failureDetail = stage, detail }})
	process, err := runner.Start(context.Background(), Executable{Path: executable, SHA256: hex.EncodeToString(digest[:])}, LaunchConfiguration{
		AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", Slot: pluginstate.SlotA,
		ConfigurationRevision: 7, OperationRevision: 9, InstanceIDs: []string{"mysql-1", "mysql-2"}, TemplateIDs: []string{"template-1"}, RuntimeDirectory: runtimeDir,
		UserID: uint32(os.Geteuid()), GroupID: uint32(os.Getegid()),
	})
	require.NoError(t, err, "stage=%s detail=%v", failureStage, failureDetail)
	require.Positive(t, process.PID())
	require.Positive(t, process.StartTicks())

	require.Eventually(t, func() bool {
		_, statErr := os.Stat(filepath.Join(runtimeDir, "launch.json"))
		return statErr == nil
	}, 3*time.Second, 10*time.Millisecond)
	var launch struct {
		Args        []string          `json:"args"`
		Env         map[string]string `json:"env"`
		UID         int               `json:"uid"`
		InstanceIDs []string          `json:"instance_ids"`
	}
	require.NoError(t, json.Unmarshal(requireReadFile(t, filepath.Join(runtimeDir, "launch.json")), &launch))
	require.NotContains(t, launch.Env, "DBPILOT_SECRET_SENTINEL")
	require.Equal(t, []string{"mysql-1", "mysql-2"}, launch.InstanceIDs)
	require.NotContains(t, launch.Args, "/bin/sh")
	require.Equal(t, os.Geteuid(), launch.UID)

	stopContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, process.Drain(stopContext))
	require.NoError(t, process.Wait())
	if observed, ok := process.(interface{ Output() (string, string) }); ok {
		stdout, stderr := observed.Output()
		require.LessOrEqual(t, len(stdout), 1024)
		require.LessOrEqual(t, len(stderr), 1024)
		require.NotContains(t, stdout+stderr, "must-not-leak")
	}
}

func TestLinuxProcessRunnerRejectsUnverifiedExecutableAndRootWithoutDedicatedUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root credential boundary requires a root test process")
	}
	runner := NewOSProcessRunner(OSProcessRunnerConfig{})
	_, err := runner.Start(context.Background(), Executable{Path: "/bin/false", SHA256: "bad"}, LaunchConfiguration{AssignmentID: "assignment-1", PluginID: "mysql", DatabaseFamily: "mysql", Version: "1.0.0", Slot: pluginstate.SlotA, ConfigurationRevision: 1, OperationRevision: 1, RuntimeDirectory: t.TempDir()})
	require.ErrorIs(t, err, ErrProcessStart)
}
