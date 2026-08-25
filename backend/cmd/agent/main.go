package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"
)

var (
	version = "dev"
	commit  = "unknown"
)

type agentConfig struct {
	AgentID               string   `yaml:"agent_id"`
	ServerAddress         string   `yaml:"server_address"`
	CAFile                string   `yaml:"ca_file"`
	CertFile              string   `yaml:"cert_file"`
	KeyFile               string   `yaml:"key_file"`
	PolicyPublicKeyFile   string   `yaml:"policy_public_key_file"`
	DataDirectory         string   `yaml:"data_directory"`
	AllowedLogRoots       []string `yaml:"allowed_log_roots"`
	FileCollectionEnabled bool     `yaml:"file_collection_enabled"`
}

// startRuntime is deliberately a narrow seam: the signed-policy control-plane
// source is supplied by the later enrollment/control-plane integration. The
// Agent refuses to claim it is collecting when that source is unavailable.
var startRuntime = func(context.Context, agentConfig) error {
	return errors.New("signed DBPilot policy source is not configured")
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dbpilot-agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print version and exit")
	config := flags.String("config", "", "path to the Agent configuration file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if strings.TrimSpace(*config) == "" {
		fmt.Fprintln(stderr, "--config is required")
		return 2
	}

	settings, err := loadConfig(*config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := startRuntime(ctx, settings); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func loadConfig(path string) (agentConfig, error) {
	if !filepath.IsAbs(path) {
		return agentConfig{}, errors.New("--config must be an absolute path")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return agentConfig{}, fmt.Errorf("read configuration: %w", err)
	}
	var settings agentConfig
	if err := yaml.Unmarshal(body, &settings); err != nil {
		return agentConfig{}, fmt.Errorf("parse configuration: %w", err)
	}
	if strings.TrimSpace(settings.AgentID) == "" || strings.TrimSpace(settings.ServerAddress) == "" {
		return agentConfig{}, errors.New("agent_id and server_address are required")
	}
	for _, secret := range []string{settings.CAFile, settings.CertFile, settings.KeyFile, settings.PolicyPublicKeyFile} {
		if !filepath.IsAbs(secret) {
			return agentConfig{}, errors.New("TLS and policy-key paths must be absolute")
		}
		info, err := os.Stat(secret)
		if err != nil || info.IsDir() {
			return agentConfig{}, fmt.Errorf("required TLS or policy material is unavailable: %s", secret)
		}
	}
	if !filepath.IsAbs(settings.DataDirectory) {
		return agentConfig{}, errors.New("data_directory must be an absolute path")
	}
	info, err := os.Stat(settings.DataDirectory)
	if err != nil || !info.IsDir() {
		return agentConfig{}, errors.New("data_directory must exist and be a directory")
	}
	if runtime.GOOS == "linux" && info.Mode().Perm()&0o002 != 0 {
		return agentConfig{}, errors.New("data_directory must not be world-writable")
	}
	if settings.FileCollectionEnabled && len(settings.AllowedLogRoots) == 0 {
		return agentConfig{}, errors.New("allowed_log_roots is required when file collection is enabled")
	}
	for _, root := range settings.AllowedLogRoots {
		if !filepath.IsAbs(root) {
			return agentConfig{}, errors.New("allowed_log_roots entries must be absolute")
		}
	}
	return settings, nil
}
