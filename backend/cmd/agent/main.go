package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	agentdiscovery "dbpilot.local/platform/internal/agent/discovery"
	"dbpilot.local/platform/internal/database"
	discoverydomain "dbpilot.local/platform/internal/discovery"
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
	HostID                string                         `yaml:"host_id,omitempty"`
	ServerAddress         string                         `yaml:"server_address"`
	CAFile                string                         `yaml:"ca_file"`
	CertFile              string                         `yaml:"cert_file"`
	KeyFile               string                         `yaml:"key_file"`
	PolicyPublicKeyFile   string                         `yaml:"policy_public_key_file"`
	PolicyFile            string                         `yaml:"policy_file"`
	DiscoveryRuleSetFile  string                         `yaml:"discovery_rule_set_file,omitempty"`
	LegacyProcHelper      bool                           `yaml:"legacy_proc_helper,omitempty"`
	DockerDiscovery       bool                           `yaml:"docker_discovery,omitempty"`
	DockerDiscoverySocket string                         `yaml:"docker_discovery_socket,omitempty"`
	DataDirectory         string                         `yaml:"data_directory"`
	AllowedLogRoots       []string                       `yaml:"allowed_log_roots"`
	FileCollectionEnabled bool                           `yaml:"file_collection_enabled"`
	DatabaseProcessNames  []string                       `yaml:"database_process_names"`
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
	if len(args) > 0 && args[0] == "proc-helper" {
		return runProcHelper(args[1:], stderr)
	}
	if len(args) > 0 && args[0] == "enroll" {
		return runEnroll(args[1:], stdout, stderr)
	}
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
	if (settings.HostID == "") != (settings.DiscoveryRuleSetFile == "") {
		return agentConfig{}, errors.New("host_id and discovery_rule_set_file must be configured together")
	}
	if settings.HostID != "" && (!filepath.IsAbs(settings.DiscoveryRuleSetFile) || runtime.GOOS != "linux") {
		return agentConfig{}, errors.New("native discovery requires Linux and an absolute discovery_rule_set_file")
	}
	if settings.LegacyProcHelper && (settings.DiscoveryRuleSetFile == "" || runtime.GOOS != "linux") {
		return agentConfig{}, errors.New("legacy_proc_helper requires Linux native discovery")
	}
	if settings.DockerDiscovery && settings.DiscoveryRuleSetFile == "" {
		return agentConfig{}, errors.New("docker discovery requires host enrollment and signed discovery rules")
	}
	if settings.DockerDiscovery {
		if settings.DockerDiscoverySocket == "" {
			settings.DockerDiscoverySocket = "/run/dbpilot-agent/docker-discovery.sock"
		}
		if runtime.GOOS != "linux" || !filepath.IsAbs(settings.DockerDiscoverySocket) || strings.ContainsAny(settings.DockerDiscoverySocket, "\x00\r\n") {
			return agentConfig{}, errors.New("docker discovery requires Linux and an absolute helper socket")
		}
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
	settings.DatabaseProcessNames, err = agent.NormalizeDatabaseProcessNames(settings.DatabaseProcessNames)
	if err != nil {
		return agentConfig{}, err
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
	logSummaries := telemetry.NewLogSummaryIndex()
	telemetryEngine := telemetry.NewEngine(telemetry.NewEmbeddedBuilder(store, logSummaries))
	hostCollector := newHostSnapshotCollector(settings, store, telemetryEngine, logSummaries)
	var dependencyCollector *agent.DependencyCollector
	var componentCollector agent.ComponentCollector
	if len(settings.Components) > 0 {
		dependencyCollector, err = agent.NewDependencyCollector(agent.DependencyCollectorConfig{
			AgentID: settings.AgentID, Definitions: settings.Components, SecretResolver: database.EnvironmentSecretResolver{}, Store: store,
			Interval: settings.ComponentCollection.interval(), RequestTimeout: settings.ComponentCollection.requestTimeout(), MaxAttempts: settings.ComponentCollection.MaxAttempts,
			InitialBackoff: settings.ComponentCollection.initialBackoff(), MaxBackoff: settings.ComponentCollection.maxBackoff(),
		})
		if err != nil {
			_ = store.Close()
			return fmt.Errorf("configure component collector: %w", err)
		}
		componentCollector = dependencyCollector
	}
	journal, err := commandjournal.Open(settings.Control.JournalPath)
	if err != nil {
		_ = store.Close()
		return err
	}
	defer journal.Close()
	var discoveryCoordinator *agentdiscovery.Coordinator
	var dockerDiscoveryConnection *grpc.ClientConn
	var controlClient *agent.ControlClient
	if settings.DiscoveryRuleSetFile != "" {
		ruleState, stateErr := agentdiscovery.NewRuleStateStore(filepath.Join(settings.DataDirectory, "discovery-rule-state"))
		if stateErr != nil {
			_ = store.Close()
			return fmt.Errorf("open discovery rule state: %w", stateErr)
		}
		ruleSet, attestation, loadErr := loadDiscoveryRuleSet(settings.DiscoveryRuleSetFile, publicKey, time.Now().UTC(), ruleState)
		if loadErr != nil {
			_ = store.Close()
			return loadErr
		}
		revisionStore, storeErr := agentdiscovery.NewFileRevisionStore(filepath.Join(settings.DataDirectory, "discovery-observation-revision"))
		if storeErr != nil {
			_ = store.Close()
			return fmt.Errorf("open discovery revision state: %w", storeErr)
		}
		reportStore, storeErr := agentdiscovery.NewFileReportStore(filepath.Join(settings.DataDirectory, "discovery-pending-report.pb"))
		if storeErr != nil {
			_ = store.Close()
			return fmt.Errorf("open discovery report state: %w", storeErr)
		}
		if storeErr = revisionStore.EnsureAtLeast(ctx, reportStore.RetiredRevision()); storeErr != nil {
			_ = store.Close()
			return fmt.Errorf("migrate discovery pending revision: %w", storeErr)
		}
		if storeErr = reportStore.ConsumeRetirement(ctx); storeErr != nil {
			_ = store.Close()
			return fmt.Errorf("consume discovery pending retirement: %w", storeErr)
		}
		reader := agentdiscovery.NewProcReader("/proc", nil)
		if settings.LegacyProcHelper {
			reader = agentdiscovery.NewLegacyProcReader("/proc", nil)
		}
		var dockerDetector agentdiscovery.Detector
		if settings.DockerDiscovery {
			var detector *agentdiscovery.DockerDetector
			detector, dockerDiscoveryConnection, loadErr = agentdiscovery.NewDockerDetectorAt(ctx, settings.DockerDiscoverySocket, ruleSet.Revision, agentdiscovery.DockerAllowedLabelKeys(ruleSet.Rules))
			if loadErr != nil {
				_ = store.Close()
				return fmt.Errorf("configure Docker discovery: %w", loadErr)
			}
			dockerDetector = detector
		}
		if dockerDiscoveryConnection != nil {
			defer dockerDiscoveryConnection.Close()
		}
		discoveryCoordinator, loadErr = agentdiscovery.NewCoordinator(agentdiscovery.CoordinatorConfig{HostID: settings.HostID, AgentID: settings.AgentID, Detector: agentdiscovery.NewNativeDetector(reader), DockerDetector: dockerDetector, RuleSet: ruleSet, Attestation: attestation, RevisionStore: revisionStore, ReportStore: reportStore, InitialUnavailable: reportStore.Unavailable(), Compatibility: func() agentdiscovery.CompatibilityState {
			if controlClient == nil {
				return agentdiscovery.CompatibilityUnknown
			}
			switch controlClient.DiscoveryCompatibility() {
			case agent.DiscoveryCompatibilityCompatible:
				return agentdiscovery.CompatibilityCompatible
			case agent.DiscoveryCompatibilityIncompatible:
				return agentdiscovery.CompatibilityIncompatible
			default:
				return agentdiscovery.CompatibilityUnknown
			}
		}, Reporter: func(reportContext context.Context, report *telemetryv1.DiscoveryReport) error {
			if controlClient == nil {
				return agent.ErrControlStreamDisconnected
			}
			return controlClient.ReportDiscovery(reportContext, report)
		}})
		if loadErr != nil {
			_ = store.Close()
			return fmt.Errorf("configure native discovery: %w", loadErr)
		}
	}
	executors, err := configuredCommandExecutors(hostCollector, dependencyCollector, discoveryCoordinator)
	if err != nil {
		_ = store.Close()
		return err
	}
	commandVerifier, err := agent.NewCommandVerifier(settings.AgentID, controlPublicKey, executors.Capabilities())
	if err != nil {
		_ = store.Close()
		return err
	}
	controlAPI := telemetryv1.NewAgentControlClient(connection)
	controlClient, err = agent.NewControlClient(agent.ControlClientConfig{
		AgentID: settings.AgentID, AgentVersion: version, StreamOpener: func(streamContext context.Context) (agent.ControlStream, error) {
			return controlAPI.Connect(streamContext)
		}, Journal: journal, Verifier: commandVerifier, Executors: executors,
		HeartbeatInterval: settings.Control.HeartbeatInterval, ReconnectBackoff: settings.Control.ReconnectBackoff,
	})
	if err != nil {
		_ = store.Close()
		return err
	}
	agentRuntime := agent.NewRuntime(agent.Dependencies{AgentID: settings.AgentID, PolicySource: agent.FilePolicySource{Path: settings.PolicyFile}, PolicyVerifier: verifier, Engine: telemetryEngine, Store: store, Exporter: exporter.NewClient(client, store, settings.AgentID), HealthReporter: agent.GRPCHealthReporter{Client: client}, ComponentCollector: componentCollector})
	serviceContext, cancelServices := context.WithCancel(ctx)
	defer cancelServices()
	serviceCount := 2
	if discoveryCoordinator != nil {
		serviceCount++
	}
	results := make(chan error, serviceCount)
	go func() { results <- agentRuntime.Run(serviceContext) }()
	go func() { results <- controlClient.Run(serviceContext) }()
	if discoveryCoordinator != nil {
		go func() {
			discoveryErr := discoveryCoordinator.Run(serviceContext)
			if discoveryErr == nil && serviceContext.Err() == nil {
				<-serviceContext.Done()
			}
			results <- discoveryErr
		}()
	}
	first := <-results
	cancelServices()
	remaining := make([]error, 0, serviceCount-1)
	for index := 1; index < serviceCount; index++ {
		remaining = append(remaining, <-results)
	}
	if first != nil && !errors.Is(first, context.Canceled) {
		return first
	}
	for _, serviceErr := range remaining {
		if serviceErr != nil && !errors.Is(serviceErr, context.Canceled) {
			return serviceErr
		}
	}
	return nil
}

func runProcHelper(arguments []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("proc-helper", flag.ContinueOnError)
	flags.SetOutput(stderr)
	allowedUID := flags.Uint("allowed-uid", 0, "numeric dbpilot Agent uid")
	allowedGID := flags.Uint("allowed-gid", 0, "numeric dbpilot Agent gid")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if *allowedUID == 0 || *allowedGID == 0 || uint64(*allowedUID) > uint64(^uint32(0)) || uint64(*allowedGID) > uint64(^uint32(0)) {
		fmt.Fprintln(stderr, "--allowed-uid and --allowed-gid are required uint32 values")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := agentdiscovery.RunLegacyProcHelper(ctx, uint32(*allowedUID), uint32(*allowedGID)); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func newHostSnapshotCollector(settings agentConfig, store agent.HostSnapshotStore, limits agent.BatchLimitProvider, logs agent.LogSummaryProvider) *agent.HostSnapshotCollector {
	return &agent.HostSnapshotCollector{
		AgentID: settings.AgentID, Store: store, Reader: agent.NewGopsutilHostReader(), Logs: logs, BatchLimits: limits,
		ProcessNames: settings.DatabaseProcessNames,
	}
}

func configuredCommandExecutors(host agent.Collector, collector *agent.DependencyCollector, discoveryRunners ...agent.DiscoveryCommandRunner) (*agent.ExecutorRegistry, error) {
	executors := agent.NewExecutorRegistry()
	if len(discoveryRunners) > 1 {
		return nil, errors.New("only one native discovery coordinator is allowed")
	}
	if len(discoveryRunners) == 1 && discoveryRunners[0] != nil {
		if err := executors.Register(agent.CommandKindDiscoverDatabases, agent.DiscoveryCommandExecutor{Runner: discoveryRunners[0]}); err != nil {
			return nil, fmt.Errorf("register DiscoverDatabases executor: %w", err)
		}
	}
	coordinator := &agent.CollectionCoordinator{Host: host, Dependencies: agent.NewDependencyCollectionAdapter(collector)}
	if !coordinator.Available() {
		return executors, nil
	}
	executor, err := agent.NewCollectNowExecutor(coordinator)
	if err != nil {
		return nil, fmt.Errorf("configure CollectNow executor: %w", err)
	}
	if err := executors.Register(agent.CommandKindCollectNow, executor); err != nil {
		return nil, fmt.Errorf("register CollectNow executor: %w", err)
	}
	return executors, nil
}

func loadDiscoveryRuleSet(path string, publicKey ed25519.PublicKey, now time.Time, state *agentdiscovery.RuleStateStore) (discoverydomain.RuleSet, discoverydomain.RuleAttestation, error) {
	file, err := os.Open(path)
	if err != nil {
		return discoverydomain.RuleSet{}, discoverydomain.RuleAttestation{}, errors.New("discovery rule set is unavailable")
	}
	defer file.Close()
	openedInfo, openedErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if openedErr != nil || pathErr != nil || !openedInfo.Mode().IsRegular() || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return discoverydomain.RuleSet{}, discoverydomain.RuleAttestation{}, errors.New("discovery rule set is unavailable")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var envelope discoverydomain.SignedRuleSet
	if err := decoder.Decode(&envelope); err != nil {
		return discoverydomain.RuleSet{}, discoverydomain.RuleAttestation{}, errors.New("parse discovery rule set")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return discoverydomain.RuleSet{}, discoverydomain.RuleAttestation{}, errors.New("parse discovery rule set")
	}
	rules, err := discoverydomain.VerifyRuleSet(publicKey, envelope, now, 0)
	if err != nil {
		return discoverydomain.RuleSet{}, discoverydomain.RuleAttestation{}, errors.New("verify discovery rule set")
	}
	attestation, err := discoverydomain.AttestationFor(envelope)
	if err != nil {
		return discoverydomain.RuleSet{}, discoverydomain.RuleAttestation{}, errors.New("verify discovery rule set")
	}
	if state == nil || state.Accept(context.Background(), rules.Revision, attestation.Digest) != nil {
		return discoverydomain.RuleSet{}, discoverydomain.RuleAttestation{}, errors.New("persist discovery rule state")
	}
	return rules, attestation, nil
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
