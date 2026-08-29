package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const exactNginxImage = "nginx:1.29.1-alpine"

func TestExactNginxHealthUsesGeneratedTrustAndRejectsInvalidTLS(t *testing.T) {
	if os.Getenv("DBPILOT_FULL_STACK_NGINX_PROBE") != "1" {
		t.Skip("set DBPILOT_FULL_STACK_NGINX_PROBE=1 to run exact-image TLS health probe")
	}
	docker, err := exec.LookPath("docker")
	require.NoError(t, err)
	root := filepath.Join(t.TempDir(), "acceptance")
	options := validBootstrapOptions(root)
	options.Now = time.Now().UTC()
	manifest, err := GenerateBootstrap(context.Background(), options)
	require.NoError(t, err)
	require.FileExists(t, manifest.Files["frontend_ca_bundle"])

	untrustedRoot := filepath.Join(t.TempDir(), "untrusted")
	require.NoError(t, os.MkdirAll(untrustedRoot, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(untrustedRoot, "ca-certificates.crt"), mustRead(t, manifest.Files["untrusted_ca_cert"]), 0o644))
	frontendRoot := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(frontendRoot, "index.html"), []byte("acceptance\n"), 0o644))
	nginxConfig, err := filepath.Abs(filepath.Join("..", "..", "..", "docker", "full-stack", "nginx.conf"))
	require.NoError(t, err)

	runID := fmt.Sprintf("dbpilot-nginx-probe-%d-%s", os.Getpid(), strings.ToLower(time.Now().Format("150405.000000000")))
	runID = strings.ReplaceAll(runID, ".", "")
	networkName := runID + "-network"
	serverName := runID + "-server"
	clientNames := make([]string, 0, 8)
	networkID := ""
	serverID := ""
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, name := range clientNames {
			if id, inspectErr := dockerProbe(cleanupCtx, docker, "container", "inspect", "--format", "{{.Id}}", name); inspectErr == nil {
				_, _ = dockerProbe(cleanupCtx, docker, "rm", "-f", strings.TrimSpace(id))
				t.Errorf("probe client %s was not removed automatically", name)
			}
		}
		if serverID != "" {
			_, _ = dockerProbe(cleanupCtx, docker, "rm", "-f", serverID)
		}
		if networkID != "" {
			_, _ = dockerProbe(cleanupCtx, docker, "network", "rm", networkID)
		}
		for kind, command := range map[string][]string{
			"container": {"ps", "-aq", "--filter", "label=dbpilot.run=" + runID},
			"network":   {"network", "ls", "-q", "--filter", "label=dbpilot.run=" + runID},
		} {
			remaining, auditErr := dockerProbe(cleanupCtx, docker, command...)
			if auditErr != nil || strings.TrimSpace(remaining) != "" {
				t.Errorf("%s cleanup audit failed for %s: %v %s", kind, runID, auditErr, remaining)
			}
		}
	})

	probeCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	networkID, err = dockerProbe(probeCtx, docker, "network", "create", "--label", "dbpilot.verifier=full-stack-compose", "--label", "dbpilot.run="+runID, networkName)
	require.NoError(t, err)
	networkID = strings.TrimSpace(networkID)

	serverID, err = dockerProbe(probeCtx, docker,
		"run", "-d", "--pull", "never", "--name", serverName, "--hostname", "frontend",
		"--network", networkName, "--network-alias", "frontend", "--network-alias", "wrong-host", "--network-alias", "controlplane",
		"--user", "10001:10001", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--label", "dbpilot.verifier=full-stack-compose", "--label", "dbpilot.run="+runID,
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=32m,mode=1777",
		"--mount", probeBind(frontendRoot, "/srv/dbpilot/frontend"),
		"--mount", probeBind(nginxConfig, "/etc/nginx/nginx.conf"),
		"--mount", probeBind(filepath.Join(root, "config"), "/acceptance/config"),
		"--mount", probeBind(filepath.Join(root, "config"), "/etc/ssl/certs"),
		"--mount", probeBind(filepath.Join(root, "secrets"), "/acceptance/secrets"),
		"--entrypoint", "nginx", exactNginxImage, "-g", "daemon off;")
	require.NoError(t, err)
	serverID = strings.TrimSpace(serverID)
	require.NotEmpty(t, serverID)

	runClient := func(suffix, trustRoot, rawURL string) (string, error) {
		name := runID + "-" + suffix
		clientNames = append(clientNames, name)
		return dockerProbe(probeCtx, docker,
			"run", "--rm", "--pull", "never", "--name", name, "--network", networkName,
			"--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
			"--label", "dbpilot.verifier=full-stack-compose", "--label", "dbpilot.run="+runID,
			"--mount", probeBind(trustRoot, "/etc/ssl/certs"),
			"--entrypoint", "/bin/sh", exactNginxImage, "-ec", "wget -q --spider "+rawURL)
	}

	var trustedErr error
	var trustedOutput string
	for attempt := 0; attempt < 20; attempt++ {
		trustedOutput, trustedErr = runClient(fmt.Sprintf("trusted-%d", attempt), filepath.Join(root, "config"), "https://frontend:8443/healthz")
		if trustedErr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if trustedErr != nil {
		logs, _ := dockerProbe(probeCtx, docker, "logs", serverID)
		require.NoError(t, trustedErr, trustedOutput+"\n"+logs)
	}
	_, err = runClient("untrusted", untrustedRoot, "https://frontend:8443/healthz")
	require.Error(t, err)
	_, err = runClient("wrong-host", filepath.Join(root, "config"), "https://wrong-host:8443/healthz")
	require.Error(t, err)

	labels, err := dockerProbe(probeCtx, docker, "container", "inspect", "--format", `{{index .Config.Labels "dbpilot.run"}}`, serverID)
	require.NoError(t, err)
	require.Equal(t, runID, strings.TrimSpace(labels))
}

func probeBind(source, target string) string {
	return "type=bind,src=" + source + ",dst=" + target + ",readonly"
}

func dockerProbe(ctx context.Context, docker string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, docker, arguments...)
	output, err := command.CombinedOutput()
	return string(output), err
}
