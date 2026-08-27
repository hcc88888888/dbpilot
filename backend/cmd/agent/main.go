package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
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
	"time"

	telemetryv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/agent/commandjournal"
	"dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/exporter"
	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v3"
)

var (
	version = "dev"
	commit  = "unknown"
)

type agentConfig struct {
	AgentID               string                         `yaml:"agent_id"`
	ServerAddress         string                         `yaml:"server_address"`
	CAFile                string                         `yaml:"ca_file"`
	CertFile              string                         `yaml:"cert_file"`
	KeyFile               string                         `yaml:"key_file"`
	PolicyPublicKeyFile   string                         `yaml:"policy_public_key_file"`
	PolicyFile            string                         `yaml:"policy_file"`
	DataDirectory         string                         `yaml:"data_directory"`
	AllowedLogRoots       []string                       `yaml:"allowed_log_roots"`
	FileCollectionEnabled bool                           `yaml:"file_collection_enabled"`
	Components            []database.ComponentDefinition `yaml:"components"`
	ComponentSecrets      componentSecretConfig          `yaml:"component_secrets"`
	ComponentCollection   componentCollectionConfig      `yaml:"component_collection"`
	Control               agentControlConfig             `yaml:"control"`
}

type agentControlConfig struct {
	PublicKeyFile     string        `yaml:"public_key_file"`
	JournalPath       string        `yaml:"journal_path"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	ReconnectBackoff  time.Duration `yaml:"reconnect_backoff"`
}

type componentSecretConfig struct {
	Provider string `yaml:"provider"`
}
type componentCollectionConfig struct {
	IntervalSeconds            int `yaml:"interval_seconds"`
	RequestTimeoutSeconds      int `yaml:"request_timeout_seconds"`
	MaxAttempts                int `yaml:"max_attempts"`
	InitialBackoffMilliseconds int `yaml:"initial_backoff_milliseconds"`
	MaxBackoffMilliseconds     int `yaml:"max_backoff_milliseconds"`
}

func (c componentCollectionConfig) interval() time.Duration {
	return time.Duration(c.IntervalSeconds) * time.Second
}
func (c componentCollectionConfig) requestTimeout() time.Duration {
	return time.Duration(c.RequestTimeoutSeconds) * time.Second
}
func (c componentCollectionConfig) initialBackoff() time.Duration {
	return time.Duration(c.InitialBackoffMilliseconds) * time.Millisecond
}
func (c componentCollectionConfig) maxBackoff() time.Duration {
	return time.Duration(c.MaxBackoffMilliseconds) * time.Millisecond
}

// startRuntime is deliberately a narrow seam: the signed-policy control-plane
// source is supplied by the later enrollment/control-plane integration. The
// Agent refuses to claim it is collecting when that source is unavailable.
var startRuntime = runRuntime

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
	for _, secret := range []string{settings.CAFile, settings.CertFile, settings.KeyFile, settings.PolicyPublicKeyFile, settings.PolicyFile} {
		if !filepath.IsAbs(secret) {
			return agentConfig{}, errors.New("TLS and policy-key paths must be absolute")
		}
		info, err := os.Lstat(secret)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return agentConfig{}, fmt.Errorf("required TLS or policy material is unavailable: %s", secret)
		}
		if runtime.GOOS == "linux" && secret == settings.KeyFile && info.Mode().Perm()&0o077 != 0 {
			return agentConfig{}, errors.New("key_file must not be group/world accessible")
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
	if strings.TrimSpace(settings.Control.PublicKeyFile) == "" {
		settings.Control.PublicKeyFile = settings.PolicyPublicKeyFile
	}
	if strings.TrimSpace(settings.Control.JournalPath) == "" {
		settings.Control.JournalPath = filepath.Join(settings.DataDirectory, "command-journal.db")
	}
	if !filepath.IsAbs(settings.Control.PublicKeyFile) || !filepath.IsAbs(settings.Control.JournalPath) {
		return agentConfig{}, errors.New("control public-key and journal paths must be absolute")
	}
	controlKeyInfo, err := os.Lstat(settings.Control.PublicKeyFile)
	if err != nil || !controlKeyInfo.Mode().IsRegular() || controlKeyInfo.Mode()&os.ModeSymlink != 0 {
		return agentConfig{}, errors.New("control public key is unavailable")
	}
	journalParent, err := os.Stat(filepath.Dir(settings.Control.JournalPath))
	if err != nil || !journalParent.IsDir() {
		return agentConfig{}, errors.New("control journal parent must exist and be a directory")
	}
	if journalInfo, journalErr := os.Lstat(settings.Control.JournalPath); journalErr == nil {
		if !journalInfo.Mode().IsRegular() || journalInfo.Mode()&os.ModeSymlink != 0 {
			return agentConfig{}, errors.New("control journal must be a regular non-symlink file")
		}
	} else if !errors.Is(journalErr, os.ErrNotExist) {
		return agentConfig{}, errors.New("control journal path is unavailable")
	}
	if settings.Control.HeartbeatInterval < 0 || settings.Control.ReconnectBackoff < 0 {
		return agentConfig{}, errors.New("control heartbeat interval and reconnect backoff must not be negative")
	}
	if settings.FileCollectionEnabled && len(settings.AllowedLogRoots) == 0 {
		return agentConfig{}, errors.New("allowed_log_roots is required when file collection is enabled")
	}
	for _, root := range settings.AllowedLogRoots {
		if !filepath.IsAbs(root) {
			return agentConfig{}, errors.New("allowed_log_roots entries must be absolute")
		}
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || filepath.Clean(root) == string(filepath.Separator) {
			return agentConfig{}, errors.New("allowed_log_roots entries must exist and must not be a filesystem root")
		}
	}
	if len(settings.Components) > 0 && settings.ComponentSecrets.Provider != "environment" {
		return agentConfig{}, errors.New("component_secrets.provider must be environment when components are configured")
	}
	if settings.ComponentCollection.IntervalSeconds < 0 || settings.ComponentCollection.RequestTimeoutSeconds < 0 || settings.ComponentCollection.MaxAttempts < 0 || settings.ComponentCollection.InitialBackoffMilliseconds < 0 || settings.ComponentCollection.MaxBackoffMilliseconds < 0 {
		return agentConfig{}, errors.New("component_collection values must not be negative")
	}
	return settings, nil
}

func runRuntime(ctx context.Context, settings agentConfig) error {
	publicKey, err := loadPublicKey(settings.PolicyPublicKeyFile)
	if err != nil {
		return err
	}
	controlPublicKey, err := loadPublicKey(settings.Control.PublicKeyFile)
	if err != nil {
		return fmt.Errorf("load control-plane command public key: %w", err)
	}
	tlsConfig, err := clientTLSConfig(settings)
	if err != nil {
		return err
	}
	connection, err := grpc.DialContext(ctx, settings.ServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer connection.Close()
	store, err := spool.Open(settings.DataDirectory, spool.Limits{MaxBytes: 1 << 30, SegmentBytes: 16 << 20})
	if err != nil {
		return err
	}
	client := telemetryv1.NewTelemetryIngestClient(connection)
	verifier := agent.Verifier{PublicKey: publicKey, Environment: policy.ValidationEnvironment{AllowedRoots: settings.AllowedLogRoots, ForbiddenRoots: []string{"/proc", "/sys", "/etc"}, ResolvePath: filepath.EvalSymlinks}}
	var componentCollector agent.ComponentCollector
	if len(settings.Components) > 0 {
		componentCollector, err = agent.NewDependencyCollector(agent.DependencyCollectorConfig{
			AgentID: settings.AgentID, Definitions: settings.Components, SecretResolver: database.EnvironmentSecretResolver{}, Store: store,
			Interval: settings.ComponentCollection.interval(), RequestTimeout: settings.ComponentCollection.requestTimeout(), MaxAttempts: settings.ComponentCollection.MaxAttempts,
			InitialBackoff: settings.ComponentCollection.initialBackoff(), MaxBackoff: settings.ComponentCollection.maxBackoff(),
		})
		if err != nil {
			_ = store.Close()
			return fmt.Errorf("configure component collector: %w", err)
		}
	}
	journal, err := commandjournal.Open(settings.Control.JournalPath)
	if err != nil {
		_ = store.Close()
		return err
	}
	defer journal.Close()
	executors := agent.NewExecutorRegistry()
	commandVerifier, err := agent.NewCommandVerifier(settings.AgentID, controlPublicKey, executors.Capabilities())
	if err != nil {
		_ = store.Close()
		return err
	}
	controlAPI := telemetryv1.NewAgentControlClient(connection)
	controlClient, err := agent.NewControlClient(agent.ControlClientConfig{
		AgentID: settings.AgentID, AgentVersion: version, StreamOpener: func(streamContext context.Context) (agent.ControlStream, error) {
			return controlAPI.Connect(streamContext)
		}, Journal: journal, Verifier: commandVerifier, Executors: executors,
		HeartbeatInterval: settings.Control.HeartbeatInterval, ReconnectBackoff: settings.Control.ReconnectBackoff,
	})
	if err != nil {
		_ = store.Close()
		return err
	}
	agentRuntime := agent.NewRuntime(agent.Dependencies{AgentID: settings.AgentID, PolicySource: agent.FilePolicySource{Path: settings.PolicyFile}, PolicyVerifier: verifier, Engine: telemetry.NewEngine(telemetry.NewEmbeddedBuilder(store)), Store: store, Exporter: exporter.NewClient(client, store, settings.AgentID), HealthReporter: agent.GRPCHealthReporter{Client: client}, ComponentCollector: componentCollector})
	serviceContext, cancelServices := context.WithCancel(ctx)
	defer cancelServices()
	results := make(chan error, 2)
	go func() { results <- agentRuntime.Run(serviceContext) }()
	go func() { results <- controlClient.Run(serviceContext) }()
	first := <-results
	cancelServices()
	second := <-results
	if first != nil && !errors.Is(first, context.Canceled) {
		return first
	}
	if second != nil && !errors.Is(second, context.Canceled) {
		return second
	}
	return nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New("policy public key must be PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("policy public key must be Ed25519")
	}
	return key, nil
}

func clientTLSConfig(settings agentConfig) (*tls.Config, error) {
	ca, err := os.ReadFile(settings.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("CA file contains no certificates")
	}
	certificate, err := tls.LoadX509KeyPair(settings.CertFile, settings.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, nil
}
