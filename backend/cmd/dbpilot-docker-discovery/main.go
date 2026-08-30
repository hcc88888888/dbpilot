package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"dbpilot.local/platform/internal/dockerdiscovery"
)

var safeLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("dbpilot-docker-discovery", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dockerSocket := flags.String("docker-socket", "/var/run/docker.sock", "local Docker Engine Unix socket")
	agentSocket := flags.String("agent-socket", "/run/dbpilot-agent/docker-discovery.sock", "private Agent Unix socket")
	uid := flags.Uint64("allowed-uid", 0, "exact dbpilot Agent uid")
	gid := flags.Uint64("allowed-gid", 0, "exact dbpilot Agent gid")
	labels := flags.String("allowed-labels", "dbpilot.discovery.family,dbpilot.run", "comma-separated local label allowlist")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if *uid == 0 || *gid == 0 || *uid > uint64(^uint32(0)) || *gid > uint64(^uint32(0)) {
		fmt.Fprintln(stderr, "--allowed-uid and --allowed-gid must be nonzero uint32 values")
		return 2
	}
	if !filepath.IsAbs(*dockerSocket) || !filepath.IsAbs(*agentSocket) || *dockerSocket == *agentSocket || strings.ContainsAny(*dockerSocket+*agentSocket, "\x00\r\n") {
		fmt.Fprintln(stderr, "Docker and Agent sockets must be distinct absolute paths")
		return 2
	}
	allowed, err := parseLabels(*labels)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	engine, err := dockerdiscovery.NewClient(*dockerSocket)
	if err != nil {
		fmt.Fprintln(stderr, "configure Docker Engine client:", err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := dockerdiscovery.Serve(ctx, dockerdiscovery.ServerConfig{SocketPath: *agentSocket, AllowedUID: uint32(*uid), AllowedGID: uint32(*gid), Engine: engine, AllowedLabelKeys: allowed}); err != nil {
		fmt.Fprintln(stderr, "serve Docker discovery helper:", err)
		return 1
	}
	return 0
}

func parseLabels(raw string) ([]string, error) {
	values := strings.Split(raw, ",")
	if len(values) == 0 || len(values) > 32 {
		return nil, fmt.Errorf("allowed label list must contain 1..32 values")
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !safeLabel.MatchString(value) {
			return nil, fmt.Errorf("invalid allowed label %q", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, fmt.Errorf("duplicate allowed label %q", value)
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result, nil
}
