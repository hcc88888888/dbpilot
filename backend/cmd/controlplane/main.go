package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	telemetryv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent"
	"dbpilot.local/platform/internal/agentcontrol"
	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/capability"
	"dbpilot.local/platform/internal/commandvalidation"
	"dbpilot.local/platform/internal/controlplane"
	"dbpilot.local/platform/internal/controlplanemigrations"
	"dbpilot.local/platform/internal/credentiallease"
	platformdatabase "dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/ingest"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/metrictemplate"
	"dbpilot.local/platform/internal/monitoring"
	"dbpilot.local/platform/internal/mysqlplugin"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"dbpilot.local/platform/internal/plugincatalog"
	"dbpilot.local/platform/internal/reconciliation"
	"dbpilot.local/platform/internal/rediscovery"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v3"
)

var version = "dev"

type TLSMaterial struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientCAFile string `yaml:"client_ca_file,omitempty"`
}

type ListenerConfig struct {
	Address string      `yaml:"address"`
	TLS     TLSMaterial `yaml:"tls"`
}

type AgentAssignment struct {
	TenantID    string            `yaml:"tenant_id"`
	ProjectID   string            `yaml:"project_id"`
	DisplayName string            `yaml:"display_name"`
	Host        string            `yaml:"host"`
	Labels      map[string]string `yaml:"labels,omitempty"`
}

type EvaluationScopeSettings struct {
	TenantID  string `yaml:"tenant_id"`
	ProjectID string `yaml:"project_id"`
}

type SMTPSettings struct {
	Address     string `yaml:"address"`
	ServerName  string `yaml:"server_name"`
	Username    string `yaml:"username"`
	From        string `yaml:"from"`
	ImplicitTLS bool   `yaml:"implicit_tls"`
}

type MonitoringSettings struct {
	MaximumInstances     int `yaml:"maximum_instances,omitempty"`
	MaximumMetrics       int `yaml:"maximum_metrics,omitempty"`
	MaximumLabels        int `yaml:"maximum_labels,omitempty"`
	MaximumSamples       int `yaml:"maximum_samples,omitempty"`
	MaximumResponseBytes int `yaml:"maximum_response_bytes,omitempty"`
}

type CommandSettings struct {
	SigningPrivateKeyRef string `yaml:"signing_private_key_ref"`
	ExecutionTokenKeyRef string `yaml:"execution_token_key_ref"`
}

type ArtifactSettings struct {
	StorageRoot       string `yaml:"storage_root"`
	SigningKeyRef     string `yaml:"signing_key_ref"`
	PluginLeaseKeyRef string `yaml:"plugin_lease_key_ref,omitempty"`
	PluginLeaseOrigin string `yaml:"plugin_lease_origin,omitempty"`
}

type PluginPublisherSettings struct {
	PublisherID string `yaml:"publisher_id"`
	KeyID       string `yaml:"key_id"`
	PublicKey   string `yaml:"public_key"`
}

type PluginCatalogSettings struct {
	Enabled bool `yaml:"enabled"`
}

type mysqlMetricTemplateDialect struct{}

func (mysqlMetricTemplateDialect) ValidateReadOnly(ctx context.Context, definition metrictemplate.TemplateDefinition) (metrictemplate.ValidatedDefinition, error) {
	if ctx == nil || ctx.Err() != nil || definition.DatabaseFamily != "mysql" {
		return metrictemplate.ValidatedDefinition{}, metrictemplate.ErrDialectRejected
	}
	validated, err := metrictemplate.ValidateDefinition(definition)
	if err != nil || mysqlplugin.NewMySQLStatementParser().Validate(definition.ReadOnlyStatement) != nil {
		return metrictemplate.ValidatedDefinition{}, metrictemplate.ErrDialectRejected
	}
	return validated, nil
}

type CredentialLeaseSettings struct {
	Enabled     bool                                         `yaml:"enabled"`
	TTL         time.Duration                                `yaml:"ttl,omitempty"`
	Environment map[string]CredentialLeaseEnvironmentBinding `yaml:"environment,omitempty"`
}

type CredentialLeaseEnvironmentBinding struct {
	Username string `yaml:"username"`
	Variable string `yaml:"variable"`
	Revision uint64 `yaml:"revision"`
}

type DiscoveryRulePolicySettings struct {
	KeyID              string        `yaml:"key_id"`
	Revision           uint64        `yaml:"revision"`
	Digest             string        `yaml:"digest"`
	IssuedAt           time.Time     `yaml:"issued_at"`
	ExpiresAt          time.Time     `yaml:"expires_at"`
	DisappearanceGrace time.Duration `yaml:"disappearance_grace"`
}

type EnrollmentSettings struct {
	Listener                   ListenerConfig               `yaml:"listener"`
	AgentCA                    TLSMaterial                  `yaml:"agent_ca"`
	CertificateLifetime        time.Duration                `yaml:"certificate_lifetime,omitempty"`
	MaximumPendingHosts        int                          `yaml:"maximum_pending_hosts,omitempty"`
	ObservationDeliveryTimeout time.Duration                `yaml:"observation_delivery_timeout,omitempty"`
	GenerationZeroImport       GenerationZeroImportSettings `yaml:"generation_zero_import,omitempty"`
}

type GenerationZeroImportSettings struct {
	Enabled bool                                          `yaml:"enabled"`
	Targets map[string]GenerationZeroImportTargetSettings `yaml:"targets,omitempty"`
}

type GenerationZeroImportTargetSettings struct {
	TenantID  string `yaml:"tenant_id"`
	ProjectID string `yaml:"project_id"`
	HostID    string `yaml:"host_id"`
}

var generationZeroImportIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func (settings MonitoringSettings) limits() monitoring.QueryLimits {
	return monitoring.QueryLimits{MaximumInstances: settings.MaximumInstances, MaximumMetrics: settings.MaximumMetrics, MaximumLabels: settings.MaximumLabels, MaximumSamples: settings.MaximumSamples, MaximumResponseBytes: settings.MaximumResponseBytes}
}

type IdentitySettings struct {
	Mode       string                       `yaml:"mode"`
	Issuer     string                       `yaml:"issuer,omitempty"`
	Audience   string                       `yaml:"audience,omitempty"`
	Principals map[string]PrincipalSettings `yaml:"principals,omitempty"`
}

type PrincipalSettings struct {
	Subject       string            `yaml:"subject"`
	PlatformAdmin bool              `yaml:"platform_admin"`
	Projects      []AgentAssignment `yaml:"projects,omitempty"`
}

type Config struct {
	DatabaseURL           string                        `yaml:"database_url"`
	WebhookAllowlist      []string                      `yaml:"webhook_allowlist"`
	HTTP                  ListenerConfig                `yaml:"http"`
	GRPC                  ListenerConfig                `yaml:"grpc"`
	Agents                map[string]AgentAssignment    `yaml:"agents"`
	SMTP                  SMTPSettings                  `yaml:"smtp"`
	Monitoring            MonitoringSettings            `yaml:"monitoring,omitempty"`
	Identity              IdentitySettings              `yaml:"identity"`
	EventURLBase          string                        `yaml:"event_url_base"`
	EvaluationScopes      []EvaluationScopeSettings     `yaml:"evaluation_scopes,omitempty"`
	EvaluationEvery       time.Duration                 `yaml:"evaluation_every,omitempty"`
	RetryEvery            time.Duration                 `yaml:"retry_every,omitempty"`
	Command               CommandSettings               `yaml:"command"`
	Artifact              ArtifactSettings              `yaml:"artifact"`
	PluginCatalog         PluginCatalogSettings         `yaml:"plugin_catalog,omitempty"`
	CredentialLeases      CredentialLeaseSettings       `yaml:"credential_leases,omitempty"`
	PluginPublishers      []PluginPublisherSettings     `yaml:"plugin_publishers,omitempty"`
	DiscoveryRuleKeys     map[string]string             `yaml:"discovery_rule_keys,omitempty"`
	DiscoveryRulePolicies []DiscoveryRulePolicySettings `yaml:"discovery_rule_policies,omitempty"`
	Enrollment            EnrollmentSettings            `yaml:"enrollment,omitempty"`

	HTTPServerTLS           *tls.Config                                `yaml:"-"`
	GRPCServerTLS           *tls.Config                                `yaml:"-"`
	Database                *sql.DB                                    `yaml:"-"`
	Ping                    func(context.Context) error                `yaml:"-"`
	Migrate                 func(context.Context) error                `yaml:"-"`
	Listen                  func(string, string) (net.Listener, error) `yaml:"-"`
	PrincipalResolver       controlplane.PrincipalResolver             `yaml:"-"`
	OIDCTokenVerifier       controlplane.TokenVerifier                 `yaml:"-"`
	SecretResolver          alert.SecretResolver                       `yaml:"-"`
	Channels                []alert.DeliveryChannel                    `yaml:"-"`
	AgentRegistry           *agentcontrol.Registry                     `yaml:"-"`
	CommandObserver         agentcontrol.Observer                      `yaml:"-"`
	CommandSigner           job.CommandSigner                          `yaml:"-"`
	CommandTokenProtector   job.TokenProtector                         `yaml:"-"`
	ArtifactDownloadHandler http.Handler                               `yaml:"-"`
	ArtifactSecretResolver  platformdatabase.SecretResolver            `yaml:"-"`
	CommandTargetAuthorizer commandvalidation.TargetAuthorizer         `yaml:"-"`
	PluginCatalogService    plugincatalog.CatalogService               `yaml:"-"`
	EnrollmentServerTLS     *tls.Config                                `yaml:"-"`
	EnrollmentService       *enrollment.ApplicationService             `yaml:"-"`
	HostObservationSink     agentcontrol.HostObservationSink           `yaml:"-"`
	DiscoveryReportSink     agentcontrol.DiscoveryReportSink           `yaml:"-"`
	PluginObservationSink   agentcontrol.PluginObservationSink         `yaml:"-"`
	CredentialLeaseProvider credentiallease.SecretProvider             `yaml:"-"`
}

type Server struct {
	config                  Config
	database                *sql.DB
	ownsDatabase            bool
	repository              *alert.PostgresRepository
	evaluator               *alert.Evaluator
	dispatcher              *alert.Dispatcher
	httpServer              *http.Server
	grpcServer              *grpc.Server
	enrollmentGRPCServer    *grpc.Server
	httpTLS                 *tls.Config
	grpcTLS                 *tls.Config
	enrollmentTLS           *tls.Config
	ping                    func(context.Context) error
	migrate                 func(context.Context) error
	importPreflight         func(context.Context) error
	listen                  func(string, string) (net.Listener, error)
	scopes                  []alert.Scope
	ready                   *atomic.Bool
	evaluateScope           func(context.Context, alert.Scope, time.Time) (alert.EvaluationSummary, error)
	listEvents              func(context.Context, alert.Scope, alert.EventFilter) ([]alert.AlertEvent, error)
	dispatch                func(context.Context, alert.AlertEvent, alert.EventState) error
	retryDue                func(context.Context, time.Time) error
	agentRegistry           *agentcontrol.Registry
	commandObserver         agentcontrol.Observer
	commandLifecycle        *job.CommandLifecycle
	dispatchCommands        func(context.Context, time.Time) error
	idempotency             *idempotency.Service
	artifactBlobs           *artifact.LocalBlobStore
	inspectionService       *inspection.Service
	hostInventoryService    *hostinventory.ApplicationService
	hostObservations        *agentcontrol.HostObservationDispatcher
	discoveryObservations   *agentcontrol.DiscoveryDispatcher
	pluginObservations      *agentcontrol.PluginObservationDispatcher
	credentialLeases        *credentiallease.ApplicationService
	metricTemplateLeases    *metrictemplate.LeaseService
	inspectionWorker        *inspection.Worker
	scheduleInspections     func(context.Context, time.Time) error
	processInspections      func(context.Context, time.Time) error
	reconcilePluginCatalog  func(context.Context, time.Time) error
	reconcilePlugins        func(context.Context, time.Time) error
	repairPluginAssignments func(context.Context, time.Time) error
	failMetricTrials        func(context.Context, time.Time) error
	workers                 sync.WaitGroup
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dbpilot-controlplane", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "control-plane YAML configuration")
	showVersion := flags.Bool("version", false, "print version and exit")
	checkConfig := flags.Bool("check-config", false, "validate configuration without opening the database or listeners")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if strings.TrimSpace(*configPath) == "" {
		fmt.Fprintln(stderr, "--config is required")
		return 2
	}
	config, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *checkConfig {
		if err := validateConfig(config); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintln(stdout, "configuration valid")
		return 0
	}
	server, err := NewServer(config)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func loadConfig(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()
	decoder := yaml.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	return config, nil
}

func NewServer(config Config) (*Server, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if config.CredentialLeases.Enabled && config.CredentialLeaseProvider == nil {
		provider, providerErr := credentialLeaseProviderForConfig(config)
		if providerErr != nil {
			return nil, errors.New("credential lease provider configuration failed")
		}
		config.CredentialLeaseProvider = provider
	}
	httpTLS := config.HTTPServerTLS
	if httpTLS == nil {
		loaded, err := loadServerTLS(config.HTTP.TLS, config.PrincipalResolver == nil && config.Identity.Mode == "mtls")
		if err != nil {
			return nil, fmt.Errorf("load HTTP TLS: %w", err)
		}
		httpTLS = loaded
	}
	httpTLS = httpTLS.Clone()
	if httpTLS.MinVersion < tls.VersionTLS12 {
		httpTLS.MinVersion = tls.VersionTLS12
	}
	if config.PrincipalResolver == nil && config.Identity.Mode == "mtls" {
		httpTLS.ClientAuth = tls.RequireAndVerifyClientCert
	}
	grpcTLS := config.GRPCServerTLS
	if grpcTLS == nil {
		loaded, err := loadServerTLS(config.GRPC.TLS, true)
		if err != nil {
			return nil, fmt.Errorf("load gRPC TLS: %w", err)
		}
		grpcTLS = loaded
	}
	grpcTLS = grpcTLS.Clone()
	if grpcTLS.MinVersion < tls.VersionTLS12 {
		grpcTLS.MinVersion = tls.VersionTLS12
	}
	grpcTLS.ClientAuth = tls.RequireAndVerifyClientCert
	if config.PluginCatalog.Enabled {
		if config.GRPC.TLS.ClientCAFile != "" {
			combinedPool := x509.NewCertPool()
			for _, caPath := range []string{config.HTTP.TLS.ClientCAFile, config.GRPC.TLS.ClientCAFile} {
				if caPath == "" {
					continue
				}
				caPEM, readErr := os.ReadFile(caPath)
				if readErr != nil || !combinedPool.AppendCertsFromPEM(caPEM) {
					return nil, errors.New("plugin artifact HTTPS client CA is invalid")
				}
			}
			httpTLS.ClientCAs = combinedPool
		} else if httpTLS.ClientCAs == nil {
			httpTLS.ClientCAs = grpcTLS.ClientCAs
		}
		if httpTLS.ClientCAs == nil {
			return nil, errors.New("plugin artifact HTTPS requires Agent client CA trust")
		}
		if httpTLS.ClientAuth == tls.NoClientCert {
			httpTLS.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	var enrollmentTLS *tls.Config
	if config.Enrollment.Listener.Address != "" {
		enrollmentTLS = config.EnrollmentServerTLS
		if enrollmentTLS == nil {
			loaded, err := loadServerTLS(config.Enrollment.Listener.TLS, false)
			if err != nil {
				return nil, fmt.Errorf("load enrollment TLS: %w", err)
			}
			enrollmentTLS = loaded
		}
		enrollmentTLS = enrollmentTLS.Clone()
		if enrollmentTLS.MinVersion < tls.VersionTLS12 {
			enrollmentTLS.MinVersion = tls.VersionTLS12
		}
		enrollmentTLS.ClientAuth = tls.NoClientCert
		enrollmentTLS.ClientCAs = nil
	}
	secrets := config.SecretResolver
	if secrets == nil {
		secrets = environmentSecretResolver{}
	}
	commandSigner, err := commandSignerForConfig(context.Background(), config, secrets)
	if err != nil {
		return nil, err
	}
	commandTokenProtector, err := commandTokenProtectorForConfig(context.Background(), config, secrets)
	if err != nil {
		return nil, err
	}
	database := config.Database
	ownsDatabase := false
	if database == nil {
		var err error
		database, err = sql.Open("postgres", config.DatabaseURL)
		if err != nil {
			return nil, fmt.Errorf("open database: %w", err)
		}
		ownsDatabase = true
	}
	repository := alert.NewPostgresRepository(database)
	hostRepository := hostinventory.NewPostgresRepository(database)
	agentCredentialRepository := enrollment.NewPostgresRepository(database)
	if config.Enrollment.GenerationZeroImport.Enabled {
		agentIDs := make([]string, 0, len(config.Enrollment.GenerationZeroImport.Targets))
		for agentID := range config.Enrollment.GenerationZeroImport.Targets {
			agentIDs = append(agentIDs, agentID)
		}
		sort.Strings(agentIDs)
		for _, agentID := range agentIDs {
			target := config.Enrollment.GenerationZeroImport.Targets[agentID]
			if err := agentCredentialRepository.ConfigureGenerationZeroImport(agentID, platformscope.Scope{TenantID: target.TenantID, ProjectID: target.ProjectID}, target.HostID); err != nil {
				return nil, errors.New("configure generation-zero credential import")
			}
		}
	}
	resolver := runtimeAgentResolver{configured: buildConfiguredAgentResolver(config.Agents), enrolled: hostRepository}
	metricConsumer := controlplane.NewMetricConsumer(resolver, repository)
	ingestService := ingest.NewDurableService(resolver, postgresLogBatchDeduplicator{database: database}, metricConsumer)
	ingestService.SetPolicyStatusObserver(ingest.PolicyStatusObserverFunc(func(status ingest.PolicyStatusMetadata) {
		log.Printf("dbpilot authenticated policy status accepted agent_id=%q version=%d", status.AgentID, status.Version)
	}))
	evaluator := alert.NewEvaluator(repository, repository)
	channels := config.Channels
	if len(channels) == 0 {
		allowlist := buildExactWebhookAllowlist(config.WebhookAllowlist)
		channels = []alert.DeliveryChannel{alert.InAppChannel{Writer: repository}, alert.NewWebhookChannel(allowlist, nil, secrets)}
		if strings.TrimSpace(config.SMTP.Address) != "" {
			channels = append(channels, alert.NewSMTPChannel(alert.SMTPConfig{Address: config.SMTP.Address, ServerName: config.SMTP.ServerName, Username: config.SMTP.Username, From: config.SMTP.From, ImplicitTLS: config.SMTP.ImplicitTLS}, secrets, nil))
		}
	}
	dispatcher := alert.NewDispatcher(repository, channels, time.Now, func(event alert.AlertEvent) string {
		return strings.TrimRight(config.EventURLBase, "/") + "/api/v1/tenants/" + url.PathEscape(event.Scope.TenantID) + "/projects/" + url.PathEscape(event.Scope.ProjectID) + "/alerts/" + url.PathEscape(event.ID)
	})
	principalResolver, err := principalResolverForConfig(config)
	if err != nil {
		if ownsDatabase {
			_ = database.Close()
		}
		return nil, err
	}
	ping := config.Ping
	if ping == nil {
		ping = database.PingContext
	}
	migrate := config.Migrate
	if migrate == nil {
		options := controlplanemigrations.Options{
			PluginCatalogEnabled:    config.PluginCatalog.Enabled,
			CredentialLeasesEnabled: config.CredentialLeases.Enabled,
			InspectionScopes:        configuredScopes(config),
			Now:                     time.Now,
		}
		migrate = func(ctx context.Context) error { return controlplanemigrations.Run(ctx, database, options) }
	}
	listen := config.Listen
	if listen == nil {
		listen = net.Listen
	}
	ready := &atomic.Bool{}
	monitoringLimits := monitoring.NormalizeQueryLimits(config.Monitoring.limits())
	targetAuthorizer := config.CommandTargetAuthorizer
	if targetAuthorizer == nil {
		targetAuthorizer = pluginassignment.InstanceTargetAuthorizer{Database: database}
	}
	jobRepository := job.NewPostgresRepositoryWithTargetAuthorizer(database, targetAuthorizer)
	auditService := audit.NewService(audit.NewPostgresStore(database))
	idempotencyService := idempotency.NewService(idempotency.NewPostgresStore(database))
	artifactSecrets := config.ArtifactSecretResolver
	if artifactSecrets == nil {
		artifactSecrets = platformdatabase.EnvironmentSecretResolver{}
	}
	artifactSigner, err := artifact.NewHMACDownloadSigner(strings.TrimRight(config.EventURLBase, "/")+"/api/v1/artifact-downloads", config.Artifact.SigningKeyRef, artifactSecrets)
	if err != nil {
		if ownsDatabase {
			_ = database.Close()
		}
		return nil, fmt.Errorf("configure artifact downloads: %w", err)
	}
	if err := artifactSigner.Ready(context.Background()); err != nil {
		if ownsDatabase {
			_ = database.Close()
		}
		return nil, fmt.Errorf("resolve artifact signing key: %w", err)
	}
	artifactContent := config.ArtifactDownloadHandler
	var artifactBlobs *artifact.LocalBlobStore
	if artifactContent == nil || config.PluginCatalog.Enabled {
		blobStore := artifact.NewLocalBlobStore(config.Artifact.StorageRoot)
		if err := blobStore.Ready(); err != nil {
			if ownsDatabase {
				_ = database.Close()
			}
			return nil, fmt.Errorf("validate artifact storage root: %w", err)
		}
		artifactBlobs = blobStore
	}
	artifactStore := artifact.NewPostgresStore(database)
	if artifactBlobs != nil {
		artifactStore = artifact.NewPostgresStore(database, artifactBlobs)
	}
	artifactService := artifact.NewService(artifactStore, artifactSigner)
	pluginCatalogService := config.PluginCatalogService
	if !config.PluginCatalog.Enabled {
		pluginCatalogService = nil
	}
	if config.PluginCatalog.Enabled && pluginCatalogService == nil && artifactBlobs != nil {
		publisherKeys, keyErr := publisherKeysForConfig(config)
		if keyErr != nil {
			_ = artifactBlobs.Close()
			if ownsDatabase {
				_ = database.Close()
			}
			return nil, fmt.Errorf("configure plugin publishers: %w", keyErr)
		}
		packageVerifier, verifierErr := plugincatalog.NewStreamingPackageVerifier(plugincatalog.PackageVerifierConfig{
			Publishers: publisherKeys, TemporaryDirectory: config.Artifact.StorageRoot, Limits: plugincatalog.DefaultPackageLimits(),
		})
		if verifierErr != nil {
			_ = artifactBlobs.Close()
			if ownsDatabase {
				_ = database.Close()
			}
			return nil, fmt.Errorf("configure plugin package verification: %w", verifierErr)
		}
		pluginCatalogService, err = plugincatalog.NewService(plugincatalog.NewPostgresRepository(database), artifactStore, packageVerifier, time.Now)
		if err != nil {
			_ = artifactBlobs.Close()
			if ownsDatabase {
				_ = database.Close()
			}
			return nil, fmt.Errorf("configure plugin catalog: %w", err)
		}
	}
	if artifactContent == nil {
		blobStore := artifactBlobs
		artifactContent, err = artifact.NewDownloadHandler(artifactService, artifactSigner, blobStore)
		if err != nil {
			_ = blobStore.Close()
			if ownsDatabase {
				_ = database.Close()
			}
			return nil, fmt.Errorf("configure artifact content route: %w", err)
		}
	}
	agentRegistry := config.AgentRegistry
	if agentRegistry == nil {
		agentRegistry = agentcontrol.NewRegistry(64)
	}
	configuredTargets, err := inspection.NewConfiguredTargetResolver(configuredInspectionTargets(config.Agents))
	if err != nil {
		if artifactBlobs != nil {
			_ = artifactBlobs.Close()
		}
		if ownsDatabase {
			_ = database.Close()
		}
		return nil, fmt.Errorf("configure inspection targets: %w", err)
	}
	inspectionTargets := liveInspectionTargetResolver{configured: configuredTargets, registry: agentRegistry}
	hostInventoryService := hostinventory.NewService(hostRepository, hostRepository)
	discoveryRepository := discovery.NewPostgresRepository(database)
	discoveryService := discovery.NewService(discoveryRepository)
	discoveryKeys, keyErr := discoveryRuleKeysForConfig(config)
	if keyErr != nil {
		return nil, keyErr
	}
	discoveryService.RuleKeys = discoveryKeys
	discoveryPolicies, policyErr := discoveryRulePoliciesForConfig(config)
	if policyErr != nil {
		return nil, policyErr
	}
	discoveryService.Policies = discovery.StaticRulePolicyRegistry{Allowed: discoveryPolicies}
	hostRediscovery := &rediscovery.RediscoveryCoordinator{Hosts: hostInventoryService, Jobs: jobRepository, Capabilities: agentRegistry, Policies: discoveryPolicies, RuleKeys: discoveryKeys, Now: func() time.Time { return time.Now().UTC() }}
	var assignmentRepository *pluginassignment.PostgresRepository
	var assignmentService *pluginassignment.ApplicationService
	var pluginReconciler *reconciliation.PluginReconciler
	var metricRepository *metrictemplate.PostgresRepository
	var metricTemplateService *metrictemplate.ApplicationService
	var metricTemplateLeases *metrictemplate.LeaseService
	var metricTemplateLeaseWire agentcontrol.MetricTemplateLeaseIssueService
	var acceptanceProvisioner databaseinstance.AcceptanceProvisioner = databaseinstance.AcceptanceProvisionerFunc(func(context.Context, *sql.Tx, databaseinstance.Instance, databaseinstance.MutationAudit) (databaseinstance.AssignmentBinding, error) {
		return databaseinstance.AssignmentBinding{}, databaseinstance.ErrPluginMissing
	})
	if config.PluginCatalog.Enabled {
		assignmentRepository = pluginassignment.NewPostgresRepository(database, jobRepository)
		assignmentService = pluginassignment.NewService(assignmentRepository)
		metricRepository = metrictemplate.NewPostgresRepository(database, jobRepository)
		pluginReconciler = reconciliation.NewPluginReconcilerWithTemplateLoader(assignmentRepository, metricRepository, agentRegistry)
		metricDialect := mysqlMetricTemplateDialect{}
		metricTemplateService = metrictemplate.NewService(metricRepository, metricDialect, metricRepository, time.Now)
		metricTemplateLeases, err = metrictemplate.NewLeaseService(metrictemplate.LeaseConfig{Authorizer: metrictemplate.PostgresLeaseAuthorizer{Database: database, Fences: agentRegistry, Now: time.Now}, Audit: metrictemplate.PostgresLeaseAuditRecorder{Database: database}, Now: time.Now})
		if err != nil {
			return nil, errors.New("configure metric template leases")
		}
		metricTemplateLeaseWire = metricTemplateLeaseIssuer{Service: metricTemplateLeases}
		acceptanceProvisioner = assignmentRepository
	}
	var pluginArtifactLeaseIssuer *agentcontrol.PluginArtifactLeaseIssuer
	var pluginArtifactContent http.Handler
	if config.PluginCatalog.Enabled {
		leaseKeyRef := strings.TrimSpace(config.Artifact.PluginLeaseKeyRef)
		if leaseKeyRef == "" {
			leaseKeyRef = config.Artifact.SigningKeyRef
		}
		leaseKey, leaseKeyErr := artifactSecrets.ResolveSecret(context.Background(), leaseKeyRef)
		if leaseKeyErr != nil || len(leaseKey) < sha256.Size {
			return nil, errors.New("configure plugin artifact lease key")
		}
		authorizer := livePluginArtifactAuthorizer{AgentScopes: hostRepository, Assignments: assignmentService, Versions: pluginCatalogService, Artifacts: artifactService, ExecutionFences: agentRegistry, Now: time.Now}
		pluginArtifactLeaseIssuer, err = agentcontrol.NewPluginArtifactLeaseIssuer(agentcontrol.PluginArtifactLeaseIssuerConfig{Origin: strings.TrimRight(config.Artifact.PluginLeaseOrigin, "/"), HMACKey: leaseKey, TTL: time.Minute, MaximumLeases: 4096, Authorizer: authorizer})
		for index := range leaseKey {
			leaseKey[index] = 0
		}
		if err != nil {
			return nil, fmt.Errorf("configure plugin artifact leases: %w", err)
		}
		pluginArtifactContent, err = agentcontrol.NewPluginArtifactLeaseHTTPHandler(pluginArtifactLeaseIssuer, artifactBlobs, agentCredentialRepository)
		if err != nil {
			return nil, fmt.Errorf("configure plugin artifact content: %w", err)
		}
	}
	databaseInstanceRepository := databaseinstance.NewPostgresRepositoryWithRuntime(database, acceptanceProvisioner, jobRepository)
	databaseInstanceService := databaseinstance.NewService(databaseInstanceRepository)
	var credentialLeaseIssuer agentcontrol.CredentialLeaseIssueService
	var leaseService *credentiallease.ApplicationService
	if config.CredentialLeases.Enabled {
		if !config.PluginCatalog.Enabled {
			return nil, errors.New("credential leasing requires plugin catalog")
		}
		var leaseErr error
		postgresLeaseAuthorizer := credentiallease.PostgresAuthorizer{Database: database, Fences: agentRegistry}
		leaseService, leaseErr = credentiallease.NewService(credentiallease.Config{Authorizer: postgresLeaseAuthorizer, Renewals: postgresLeaseAuthorizer, Provider: config.CredentialLeaseProvider, Clock: credentiallease.PostgresClock{Database: database}, Audit: credentiallease.PostgresAuditRecorder{Database: database}, TTL: config.CredentialLeases.TTL, Random: rand.Reader})
		if leaseErr != nil {
			return nil, errors.New("configure credential leases")
		}
		credentialLeaseIssuer = agentcontrol.CredentialLeaseIssuer{Service: leaseService}
	}
	hostSink := config.HostObservationSink
	if hostSink == nil {
		hostSink = persistedHostObservationSink{service: hostInventoryService}
	}
	maximumPendingHosts := config.Enrollment.MaximumPendingHosts
	if maximumPendingHosts == 0 {
		maximumPendingHosts = 1024
	}
	observationDeliveryTimeout := config.Enrollment.ObservationDeliveryTimeout
	if observationDeliveryTimeout == 0 {
		observationDeliveryTimeout = 5 * time.Second
	}
	hostObservations, err := agentcontrol.NewHostObservationDispatcher(hostSink, agentcontrol.HostObservationDispatcherConfig{
		MaximumPendingHosts: maximumPendingHosts, DeliveryTimeout: observationDeliveryTimeout,
		OnError: func(err error) { log.Printf("host observation persistence failed: %v", err) },
	})
	if err != nil {
		if artifactBlobs != nil {
			_ = artifactBlobs.Close()
		}
		if ownsDatabase {
			_ = database.Close()
		}
		return nil, fmt.Errorf("configure Host observation delivery: %w", err)
	}
	discoverySink := config.DiscoveryReportSink
	if discoverySink == nil {
		discoverySink = discovery.ProtoSink{Service: discoveryService}
	}
	discoveryObservations, err := agentcontrol.NewDiscoveryDispatcher(discoverySink, agentcontrol.DiscoveryDispatcherConfig{
		MaximumPendingAgents: maximumPendingHosts, DeliveryTimeout: observationDeliveryTimeout,
		OnError:     func(err error) { log.Printf("discovery report persistence failed: %v", err) },
		Acknowledge: agentRegistry.AcknowledgeDiscovery,
		SourceResultsSupported: func(agentID string) bool {
			return agentRegistry.Supports(agentID, agentcontrol.CapabilityDiscoverySourceResultsV1)
		},
	})
	if err != nil {
		if artifactBlobs != nil {
			_ = artifactBlobs.Close()
		}
		if ownsDatabase {
			_ = database.Close()
		}
		return nil, fmt.Errorf("configure discovery report delivery: %w", err)
	}
	pluginSink := config.PluginObservationSink
	if pluginSink == nil && assignmentService != nil {
		pluginSink = pluginassignment.ProtoSink{Service: assignmentService, AgentScopes: hostRepository}
	}
	var pluginObservations *agentcontrol.PluginObservationDispatcher
	if pluginSink != nil {
		pluginObservations, err = agentcontrol.NewPluginObservationDispatcher(pluginSink, agentcontrol.PluginObservationDispatcherConfig{MaximumPendingAgents: maximumPendingHosts, DeliveryTimeout: observationDeliveryTimeout, OnError: func(err error) { log.Printf("plugin observation persistence failed: %v", err) }})
		if err != nil {
			return nil, fmt.Errorf("configure plugin observation delivery: %w", err)
		}
	}
	enrollmentService := config.EnrollmentService
	if enrollmentService == nil && config.Enrollment.Listener.Address != "" {
		certificateLifetime := config.Enrollment.CertificateLifetime
		if certificateLifetime == 0 {
			certificateLifetime = 24 * time.Hour
		}
		issuer, err := loadEnrollmentIssuer(config.Enrollment.AgentCA, certificateLifetime)
		if err != nil {
			if artifactBlobs != nil {
				_ = artifactBlobs.Close()
			}
			if ownsDatabase {
				_ = database.Close()
			}
			return nil, err
		}
		if err := issuer.ValidateAgentControlTrust(grpcTLS.ClientCAs); err != nil {
			if artifactBlobs != nil {
				_ = artifactBlobs.Close()
			}
			if ownsDatabase {
				_ = database.Close()
			}
			return nil, fmt.Errorf("validate enrollment CA against AgentControl trust: %w", err)
		}
		enrollmentService = &enrollment.ApplicationService{
			Tokens: agentCredentialRepository, Certificates: issuer, Sessions: agentRegistry,
			Now: func() time.Time { return time.Now().UTC() },
		}
	}
	inspectionRepository := inspection.NewPostgresRepository(database, jobRepository)
	inspectionService := &inspection.Service{Repository: inspectionRepository, Targets: inspectionTargets}
	inspectionWorker := &inspection.Worker{Runs: inspectionRepository, Jobs: jobRepository, Evaluator: &inspection.Evaluator{Evidence: inspectionRepository}, Artifacts: artifactStore, Audit: auditService}
	inspectionApplication, err := controlplane.NewInspectionApplicationService(inspectionRepository, inspectionService, inspectionTargets, jobRepository, artifactService, auditService, idempotencyService, time.Now)
	if err != nil {
		if artifactBlobs != nil {
			_ = artifactBlobs.Close()
		}
		if ownsDatabase {
			_ = database.Close()
		}
		return nil, fmt.Errorf("configure inspection application: %w", err)
	}
	services := controlplane.Services{
		Repository: repository, Evaluator: evaluator,
		Monitoring: monitoring.NewPostgresStoreWithLimits(database, monitoring.DefaultCapabilities(), monitoringLimits), MonitoringResponseBytes: monitoringLimits.MaximumResponseBytes,
		Jobs: jobRepository, Artifacts: artifactService, Audit: auditService, ArtifactContent: artifactContent, AgentPluginArtifactContent: pluginArtifactContent,
		Capabilities: capability.NewService(capability.FoundationCatalog()),
		CapabilityInput: func(_ context.Context, scope platformscope.Scope) capability.Input {
			input := foundationCapabilityInput(scope, config.Agents, agentRegistry)
			input.DeploymentFlags["plugin_catalog"] = config.PluginCatalog.Enabled
			return input
		},
		Idempotency: idempotencyService, Inspection: inspectionApplication,
		Hosts:                      hostInventoryService,
		Enrollment:                 enrollmentService,
		Discovery:                  discoveryService,
		HostRediscovery:            hostRediscovery,
		AgentSessions:              agentRegistry,
		DatabaseInstances:          databaseInstanceService,
		PluginCatalog:              pluginCatalogService,
		PluginAssignments:          assignmentService,
		PluginReconciler:           pluginReconciler,
		MetricTemplates:            metricTemplateService,
		PluginUploadCleanupFailure: func(error) { log.Printf("plugin upload temporary cleanup failed") },
		Ready: func(ctx context.Context) error {
			if !ready.Load() {
				return errors.New("a successful all-scope evaluation pass has not completed")
			}
			if err := ping(ctx); err != nil {
				return err
			}
			if config.PluginCatalog.Enabled {
				readyService, ok := pluginCatalogService.(interface{ Ready(context.Context) error })
				if !ok || readyService.Ready(ctx) != nil {
					return errors.New("plugin catalog is not ready")
				}
				if assignmentRepository == nil {
					return errors.New("plugin assignments are not ready")
				}
				if err := assignmentRepository.Ready(ctx); err != nil {
					return err
				}
				if metricRepository == nil || metricRepository.Ready(ctx) != nil {
					return errors.New("metric templates are not ready")
				}
			}
			return nil
		},
	}
	httpServer := &http.Server{Handler: controlplane.NewHTTPHandler(services, principalResolver), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: controlplane.PluginUploadReadTimeout, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcTLS.Clone())), grpc.MaxRecvMsgSize(max(ingest.MaxBatchPayloadBytes+(64<<10), discovery.MaximumAgentControlMessageBytes)))
	telemetryv1.RegisterTelemetryIngestServer(grpcServer, ingestService)
	var enrollmentGRPCServer *grpc.Server
	if enrollmentTLS != nil {
		enrollmentGRPCServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(enrollmentTLS.Clone())), grpc.MaxRecvMsgSize(1<<20))
		telemetryv1.RegisterAgentEnrollmentServer(enrollmentGRPCServer, enrollment.NewGRPCServer(enrollmentService))
	}
	commandLifecycle, err := job.NewCommandLifecycle(job.CommandLifecycleConfig{
		DispatchRepository: jobRepository, Jobs: jobRepository, Agents: agentRegistry, Signer: commandSigner, Audit: auditService,
		TargetAuthorizer: targetAuthorizer, TokenProtector: commandTokenProtector,
		TypedResultRecorder:     metricTrialResultRecorder{Store: metricRepository},
		DatabaseInstanceResults: databaseInstanceResultRecorder{Store: databaseInstanceRepository},
		OnError:                 func(err error) { log.Printf("command lifecycle event failed: %v", err) },
	})
	if err != nil {
		if artifactBlobs != nil {
			_ = artifactBlobs.Close()
		}
		if ownsDatabase {
			_ = database.Close()
		}
		return nil, fmt.Errorf("configure command lifecycle: %w", err)
	}
	commandObserver := config.CommandObserver
	if commandObserver == nil {
		commandObserver = commandLifecycle
	}
	telemetryv1.RegisterAgentControlServer(grpcServer, agentcontrol.NewServer(agentRegistry, commandObserver, agentcontrol.WithHostObserver(hostObservations), agentcontrol.WithDiscoveryObserver(discoveryObservations), agentcontrol.WithPluginObserver(pluginObservations), agentcontrol.WithPluginArtifactLeaseIssuer(pluginArtifactLeaseIssuer), agentcontrol.WithCredentialLeaseIssuer(credentialLeaseIssuer), agentcontrol.WithMetricTemplateLeaseIssuer(metricTemplateLeaseWire), agentcontrol.WithAgentCredentialAuthorizer(agentCredentialRepository)))
	importPreflight := func(context.Context) error { return nil }
	if config.Enrollment.GenerationZeroImport.Enabled {
		importPreflight = agentCredentialRepository.ValidateGenerationZeroImports
	}
	return &Server{config: config, database: database, ownsDatabase: ownsDatabase, repository: repository, evaluator: evaluator, dispatcher: dispatcher, httpServer: httpServer, grpcServer: grpcServer, enrollmentGRPCServer: enrollmentGRPCServer, httpTLS: httpTLS.Clone(), grpcTLS: grpcTLS.Clone(), enrollmentTLS: enrollmentTLS, ping: ping, migrate: migrate, importPreflight: importPreflight, listen: listen, scopes: configuredScopes(config), ready: ready, evaluateScope: evaluator.EvaluateScope, listEvents: repository.ListEvents, dispatch: dispatcher.Dispatch, retryDue: dispatcher.RetryDue, agentRegistry: agentRegistry, commandObserver: commandObserver, commandLifecycle: commandLifecycle, hostObservations: hostObservations, credentialLeases: leaseService, metricTemplateLeases: metricTemplateLeases, failMetricTrials: func(ctx context.Context, at time.Time) error {
		if metricRepository == nil {
			return nil
		}
		_, err := metricRepository.FailTerminalTrials(ctx, 128, at.UTC())
		return err
	}, dispatchCommands: func(ctx context.Context, at time.Time) error {
		_, err := commandLifecycle.DispatchPending(ctx, at)
		return err
	}, idempotency: idempotencyService, artifactBlobs: artifactBlobs,
		inspectionService: inspectionService, inspectionWorker: inspectionWorker, hostInventoryService: hostInventoryService, discoveryObservations: discoveryObservations, pluginObservations: pluginObservations,
		scheduleInspections: func(ctx context.Context, at time.Time) error {
			_, err := inspectionService.ScheduleDue(ctx, at.UTC())
			return err
		},
		processInspections: func(ctx context.Context, at time.Time) error {
			_, err := inspectionWorker.Process(ctx, at.UTC(), 10)
			return err
		},
		reconcilePluginCatalog: func(ctx context.Context, at time.Time) error {
			if !config.PluginCatalog.Enabled {
				return nil
			}
			reconciler, ok := pluginCatalogService.(interface {
				ReconcileExpiredUploadOperations(context.Context, time.Time, int) (plugincatalog.OperationReconcileResult, error)
				ListUnreconciledCommittedOperations(context.Context, int) ([]plugincatalog.OperationSnapshot, error)
				MarkOperationCompletionReconciled(context.Context, plugincatalog.OperationKey, time.Time) error
			})
			if !ok {
				return errors.New("plugin catalog reconciler is unavailable")
			}
			if _, err := reconciler.ReconcileExpiredUploadOperations(ctx, at.UTC(), 25); err != nil {
				return err
			}
			operations, err := reconciler.ListUnreconciledCommittedOperations(ctx, 25)
			if err != nil {
				return err
			}
			for _, operation := range operations {
				if err := controlplane.ReconcilePluginCatalogOperation(ctx, idempotencyService, auditService, operation); err != nil {
					return err
				}
				if err := reconciler.MarkOperationCompletionReconciled(ctx, operation.Key, at.UTC()); err != nil {
					return err
				}
			}
			return nil
		},
		reconcilePlugins: func(ctx context.Context, at time.Time) error {
			if pluginReconciler == nil {
				return nil
			}
			_, err := pluginReconciler.Reconcile(ctx, at.UTC(), 25)
			return err
		},
		repairPluginAssignments: func(ctx context.Context, _ time.Time) error {
			if assignmentRepository == nil {
				return nil
			}
			_, err := assignmentRepository.RepairUnassigned(ctx, 25)
			return err
		},
	}, nil
}

func credentialLeaseProviderForConfig(config Config) (credentiallease.SecretProvider, error) {
	if !config.CredentialLeases.Enabled || len(config.CredentialLeases.Environment) == 0 {
		return nil, credentiallease.ErrLeaseRejected
	}
	bindings := make(map[string]credentiallease.EnvironmentBinding, len(config.CredentialLeases.Environment))
	variables := make(map[string]struct{}, len(config.CredentialLeases.Environment))
	for reference, binding := range config.CredentialLeases.Environment {
		if _, duplicate := variables[binding.Variable]; duplicate {
			return nil, credentiallease.ErrLeaseRejected
		}
		variables[binding.Variable] = struct{}{}
		bindings[reference] = credentiallease.EnvironmentBinding{Username: binding.Username, Variable: binding.Variable, Revision: binding.Revision}
	}
	provider, err := credentiallease.NewEnvironmentProvider(bindings, os.LookupEnv)
	if err != nil {
		return nil, credentiallease.ErrLeaseRejected
	}
	for reference := range bindings {
		credential, resolveErr := provider.Resolve(context.Background(), reference)
		if resolveErr != nil {
			return nil, credentiallease.ErrLeaseRejected
		}
		credential.Release()
	}
	return provider, nil
}

func publisherKeysForConfig(config Config) (*plugincatalog.StaticPublisherKeyStore, error) {
	keys := make([]plugincatalog.PublisherKey, len(config.PluginPublishers))
	for index, configured := range config.PluginPublishers {
		decoded, err := base64.StdEncoding.DecodeString(configured.PublicKey)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != configured.PublicKey || len(decoded) != ed25519.PublicKeySize {
			return nil, plugincatalog.ErrInvalid
		}
		keys[index] = plugincatalog.PublisherKey{PublisherID: configured.PublisherID, KeyID: configured.KeyID, PublicKey: ed25519.PublicKey(decoded)}
	}
	return plugincatalog.NewStaticPublisherKeyStore(keys)
}

func discoveryRuleKeysForConfig(config Config) (map[string]ed25519.PublicKey, error) {
	result := make(map[string]ed25519.PublicKey, len(config.DiscoveryRuleKeys))
	for keyID, encoded := range config.DiscoveryRuleKeys {
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded || len(decoded) != ed25519.PublicKeySize || strings.TrimSpace(keyID) != keyID || keyID == "" || len(keyID) > 128 {
			return nil, errors.New("discovery_rule_keys contains an invalid Ed25519 public key")
		}
		result[keyID] = ed25519.PublicKey(decoded)
	}
	return result, nil
}

func discoveryRulePoliciesForConfig(config Config) ([]discovery.RuleAttestation, error) {
	result := make([]discovery.RuleAttestation, len(config.DiscoveryRulePolicies))
	seen := make(map[string]struct{}, len(result))
	for index, value := range config.DiscoveryRulePolicies {
		digest, err := hex.DecodeString(value.Digest)
		if err != nil || len(digest) != 32 || value.Revision == 0 || value.KeyID == "" || value.IssuedAt.Location() != time.UTC || value.ExpiresAt.Location() != time.UTC || !value.ExpiresAt.After(value.IssuedAt) || value.DisappearanceGrace < time.Minute || value.DisappearanceGrace > 24*time.Hour {
			return nil, errors.New("discovery_rule_policies contains an invalid current policy")
		}
		if strings.ToLower(value.Digest) != value.Digest {
			return nil, errors.New("discovery_rule_policies digest must be canonical lowercase hex")
		}
		attestation := discovery.RuleAttestation{Version: discovery.RuleAttestationVersion, Algorithm: discovery.RuleAttestationAlgorithm, KeyID: value.KeyID, Revision: value.Revision, IssuedAt: value.IssuedAt, ExpiresAt: value.ExpiresAt, DisappearanceGrace: value.DisappearanceGrace}
		copy(attestation.Digest[:], digest)
		identity := value.KeyID + ":" + fmt.Sprint(value.Revision) + ":" + value.Digest
		if _, duplicate := seen[identity]; duplicate {
			return nil, errors.New("discovery_rule_policies contains a duplicate")
		}
		seen[identity] = struct{}{}
		result[index] = attestation
	}
	return result, nil
}

func validateConfig(config Config) error {
	parsed, err := url.Parse(config.DatabaseURL)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" || strings.Trim(parsed.Path, "/") == "" {
		return errors.New("database_url must be a PostgreSQL URL with host and database")
	}
	if len(config.WebhookAllowlist) == 0 {
		return errors.New("webhook_allowlist must contain at least one hostname")
	}
	eventBase, err := url.Parse(config.EventURLBase)
	if err != nil || eventBase.Scheme != "https" || eventBase.Host == "" || eventBase.User != nil || eventBase.RawQuery != "" || eventBase.Fragment != "" {
		return errors.New("event_url_base must be a canonical HTTPS URL")
	}
	if config.CommandSigner == nil && alert.ValidateSecretReference(config.Command.SigningPrivateKeyRef) != nil {
		return errors.New("command.signing_private_key_ref must be a Credential Reference")
	}
	if config.CommandTokenProtector == nil && alert.ValidateSecretReference(config.Command.ExecutionTokenKeyRef) != nil {
		return errors.New("command.execution_token_key_ref must be a Credential Reference")
	}
	if strings.TrimSpace(config.Artifact.SigningKeyRef) == "" {
		return errors.New("artifact.signing_key_ref is required")
	}
	if config.ArtifactDownloadHandler == nil && strings.TrimSpace(config.Artifact.StorageRoot) == "" {
		return errors.New("artifact.storage_root is required")
	}
	if config.PluginCatalog.Enabled && strings.TrimSpace(config.Artifact.StorageRoot) == "" {
		return errors.New("artifact.storage_root is required when plugin catalog is enabled")
	}
	if config.PluginCatalog.Enabled {
		pluginOrigin, parseErr := url.Parse(config.Artifact.PluginLeaseOrigin)
		if parseErr != nil || pluginOrigin.Scheme != "https" || pluginOrigin.Host == "" || pluginOrigin.User != nil || pluginOrigin.RawQuery != "" || pluginOrigin.Fragment != "" || strings.TrimRight(pluginOrigin.Path, "/") != "" {
			return errors.New("artifact.plugin_lease_origin must be a canonical HTTPS origin when plugin catalog is enabled")
		}
	}
	if err := monitoring.ValidateQueryLimits(config.Monitoring.limits()); err != nil {
		return errors.New("monitoring limits are invalid")
	}
	for _, host := range config.WebhookAllowlist {
		if host == "" || host != strings.ToLower(strings.TrimSpace(host)) || strings.ContainsAny(host, "/:@") {
			return errors.New("webhook_allowlist contains an invalid hostname")
		}
	}
	if strings.TrimSpace(config.HTTP.Address) == "" || strings.TrimSpace(config.GRPC.Address) == "" {
		return errors.New("HTTP and gRPC addresses are required")
	}
	if config.Enrollment.MaximumPendingHosts < 0 || config.Enrollment.ObservationDeliveryTimeout < 0 {
		return errors.New("enrollment Host observation delivery settings are invalid")
	}
	importSettings := config.Enrollment.GenerationZeroImport
	if !importSettings.Enabled && len(importSettings.Targets) != 0 {
		return errors.New("enrollment generation-zero import targets require an enabled migration window")
	}
	if importSettings.Enabled {
		if len(importSettings.Targets) == 0 || len(importSettings.Targets) > 1024 {
			return errors.New("enrollment generation-zero import window requires bounded explicit targets")
		}
		for agentID, target := range importSettings.Targets {
			scope := platformscope.Scope{TenantID: target.TenantID, ProjectID: target.ProjectID}
			configured, exists := config.Agents[agentID]
			if !generationZeroImportIdentifierPattern.MatchString(agentID) || !generationZeroImportIdentifierPattern.MatchString(target.HostID) || scope.Validate() != nil || !exists || configured.TenantID != target.TenantID || configured.ProjectID != target.ProjectID {
				return errors.New("enrollment generation-zero import target is invalid or does not match the configured Agent scope")
			}
		}
	}
	if config.Enrollment.Listener.Address != "" {
		if config.Enrollment.Listener.Address != strings.TrimSpace(config.Enrollment.Listener.Address) || config.Enrollment.Listener.Address == config.HTTP.Address || config.Enrollment.Listener.Address == config.GRPC.Address {
			return errors.New("enrollment listener must use a separate canonical address")
		}
		if config.EnrollmentServerTLS == nil && (config.Enrollment.Listener.TLS.CertFile == "" || config.Enrollment.Listener.TLS.KeyFile == "") {
			return errors.New("enrollment server-auth TLS certificate and key references are required")
		}
		if config.EnrollmentService == nil && (config.Enrollment.AgentCA.CertFile == "" || config.Enrollment.AgentCA.KeyFile == "") {
			return errors.New("enrollment Agent CA certificate and key references are required")
		}
		if config.Enrollment.CertificateLifetime < 0 || config.Enrollment.CertificateLifetime > 365*24*time.Hour {
			return errors.New("enrollment certificate lifetime is invalid")
		}
	}
	if config.HTTPServerTLS == nil && (config.HTTP.TLS.CertFile == "" || config.HTTP.TLS.KeyFile == "") {
		return errors.New("HTTP TLS certificate and key references are required")
	}
	if config.GRPCServerTLS == nil && (config.GRPC.TLS.CertFile == "" || config.GRPC.TLS.KeyFile == "" || config.GRPC.TLS.ClientCAFile == "") {
		return errors.New("gRPC mTLS certificate, key, and client CA references are required")
	}
	if config.PrincipalResolver == nil {
		switch config.Identity.Mode {
		case "local_headers":
			if !loopbackAddress(config.HTTP.Address) {
				return errors.New("local header identity requires a loopback HTTP listener")
			}
		case "mtls":
			if len(config.Identity.Principals) == 0 {
				return errors.New("mTLS identity requires configured principals")
			}
			if config.HTTPServerTLS == nil && config.HTTP.TLS.ClientCAFile == "" {
				return errors.New("mTLS identity requires an HTTP client CA reference")
			}
			if config.HTTPServerTLS != nil && config.HTTPServerTLS.ClientCAs == nil {
				return errors.New("mTLS identity requires HTTP client CAs")
			}
			if _, err := configuredCertificatePrincipals(config.Identity.Principals); err != nil {
				return err
			}
		case "oidc":
			issuer, err := url.Parse(config.Identity.Issuer)
			if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
				return errors.New("OIDC issuer must be a canonical HTTPS URL")
			}
			if config.Identity.Audience == "" || config.Identity.Audience != strings.TrimSpace(config.Identity.Audience) || strings.ContainsAny(config.Identity.Audience, "\r\n\t") {
				return errors.New("OIDC audience is required")
			}
		default:
			return errors.New("trusted HTTP identity adapter is required")
		}
	}
	for id, assignment := range config.Agents {
		if strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) || (alert.Scope{TenantID: assignment.TenantID, ProjectID: assignment.ProjectID}).Validate() != nil || assignment.DisplayName == "" || assignment.DisplayName != strings.TrimSpace(assignment.DisplayName) || assignment.Host == "" || assignment.Host != strings.TrimSpace(assignment.Host) {
			return errors.New("agents contains an invalid assignment")
		}
	}
	if _, err := inspection.NewConfiguredTargetResolver(configuredInspectionTargets(config.Agents)); err != nil {
		return errors.New("agents contains invalid inspection target metadata")
	}
	seenScopes := make(map[string]struct{}, len(config.EvaluationScopes))
	for _, configured := range config.EvaluationScopes {
		scope := alert.Scope{TenantID: configured.TenantID, ProjectID: configured.ProjectID}
		if scope.Validate() != nil {
			return errors.New("evaluation scope is invalid")
		}
		if _, duplicate := seenScopes[scope.Key()]; duplicate {
			return errors.New("evaluation scope is duplicated")
		}
		seenScopes[scope.Key()] = struct{}{}
	}
	if len(configuredScopes(config)) == 0 {
		return errors.New("at least one evaluation scope is required")
	}
	if _, err := publisherKeysForConfig(config); err != nil {
		return errors.New("plugin_publishers contains an invalid Ed25519 public key")
	}
	keys, err := discoveryRuleKeysForConfig(config)
	if err != nil {
		return err
	}
	policies, err := discoveryRulePoliciesForConfig(config)
	if err != nil {
		return err
	}
	for _, policy := range policies {
		if _, ok := keys[policy.KeyID]; !ok {
			return errors.New("discovery_rule_policies references an unknown key_id")
		}
	}
	if config.PluginCatalog.Enabled && len(config.PluginPublishers) == 0 {
		return errors.New("plugin catalog enabled requires at least one publisher")
	}
	return nil
}

func principalResolverForConfig(config Config) (controlplane.PrincipalResolver, error) {
	if config.PrincipalResolver != nil {
		return config.PrincipalResolver, nil
	}
	switch config.Identity.Mode {
	case "local_headers":
		return controlplane.HeaderPrincipalResolver{}, nil
	case "mtls":
		principals, err := configuredCertificatePrincipals(config.Identity.Principals)
		if err != nil {
			return nil, err
		}
		return controlplane.CertificatePrincipalResolver{Principals: principals}, nil
	case "oidc":
		verifier := config.OIDCTokenVerifier
		if verifier == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var err error
			verifier, err = controlplane.NewOIDCTokenVerifier(ctx, config.Identity.Issuer, config.Identity.Audience)
			if err != nil {
				return nil, fmt.Errorf("initialize OIDC provider: %w", err)
			}
		}
		return controlplane.BearerPrincipalResolver{Verifier: verifier}, nil
	default:
		return nil, errors.New("trusted HTTP identity adapter is required")
	}
}

func configuredCertificatePrincipals(settings map[string]PrincipalSettings) (map[string]controlplane.Principal, error) {
	principals := make(map[string]controlplane.Principal, len(settings))
	for rawURI, configured := range settings {
		identityURI, err := url.Parse(rawURI)
		if err != nil || !identityURI.IsAbs() || identityURI.Host == "" || identityURI.User != nil || identityURI.RawQuery != "" || identityURI.Fragment != "" {
			return nil, errors.New("identity principals contains an invalid certificate URI")
		}
		if configured.Subject == "" || configured.Subject != strings.TrimSpace(configured.Subject) {
			return nil, errors.New("identity principals contains an invalid subject")
		}
		projects := make(map[string]struct{}, len(configured.Projects))
		for _, assignment := range configured.Projects {
			scope := platformscope.Scope{TenantID: assignment.TenantID, ProjectID: assignment.ProjectID}
			if scope.Validate() != nil {
				return nil, errors.New("identity principals contains an invalid project scope")
			}
			if _, duplicate := projects[scope.Key()]; duplicate {
				return nil, errors.New("identity principals contains a duplicate project scope")
			}
			projects[scope.Key()] = struct{}{}
		}
		if !configured.PlatformAdmin && len(projects) == 0 {
			return nil, errors.New("identity principal requires a project scope")
		}
		principals[identityURI.String()] = controlplane.Principal{Subject: configured.Subject, PlatformAdmin: configured.PlatformAdmin, Projects: projects}
	}
	return principals, nil
}

type pluginArtifactAssignmentReader interface {
	Get(context.Context, platformscope.Scope, string) (pluginassignment.Assignment, error)
}

type pluginArtifactVersionReader interface {
	ListVersions(context.Context, platformscope.Scope, plugincatalog.VersionFilter) (plugincatalog.VersionPage, error)
}

type pluginArtifactMetadataReader interface {
	Get(context.Context, platformscope.Scope, string) (artifact.Artifact, error)
}

type pluginArtifactExecutionFence interface {
	ExecutionLeaseActive(string, string, time.Time) bool
}

type livePluginArtifactAuthorizer struct {
	AgentScopes     pluginassignment.AgentScopeResolver
	Assignments     pluginArtifactAssignmentReader
	Versions        pluginArtifactVersionReader
	Artifacts       pluginArtifactMetadataReader
	ExecutionFences pluginArtifactExecutionFence
	Now             func() time.Time
}

func (authorizer livePluginArtifactAuthorizer) AuthorizePluginArtifact(ctx context.Context, agentID, assignmentID, artifactID string, operationRevision uint64) (agentcontrol.PluginArtifactGrant, error) {
	if ctx == nil || ctx.Err() != nil || authorizer.AgentScopes == nil || authorizer.Assignments == nil || authorizer.Versions == nil || authorizer.Artifacts == nil || authorizer.ExecutionFences == nil || authorizer.Now == nil || agentID == "" || assignmentID == "" || artifactID == "" || operationRevision == 0 {
		return agentcontrol.PluginArtifactGrant{}, agentcontrol.ErrPluginArtifactLeaseRejected
	}
	scope, err := authorizer.AgentScopes.ScopeForAgent(ctx, agentID)
	if err != nil || scope.Validate() != nil {
		return agentcontrol.PluginArtifactGrant{}, agentcontrol.ErrPluginArtifactLeaseRejected
	}
	assignment, err := authorizer.Assignments.Get(ctx, scope, assignmentID)
	if err != nil || assignment.Validate() != nil || assignment.AgentID != agentID || assignment.ID != assignmentID || assignment.ArtifactID != artifactID || assignment.OperationRevision != operationRevision || assignment.DesiredState == pluginassignment.DesiredAbsent || assignment.ConfigurationRevision == 0 {
		return agentcontrol.PluginArtifactGrant{}, agentcontrol.ErrPluginArtifactLeaseRejected
	}
	identity := fmt.Sprintf("%s:%d:%d", assignment.ID, assignment.ConfigurationRevision, assignment.OperationRevision)
	commandID := pluginassignment.DeterministicID("command-plugin-", assignment.Scope.Key(), identity)
	if !authorizer.ExecutionFences.ExecutionLeaseActive(agentID, commandID, authorizer.Now().UTC()) {
		return agentcontrol.PluginArtifactGrant{}, agentcontrol.ErrPluginArtifactLeaseRejected
	}
	page, err := authorizer.Versions.ListVersions(ctx, scope, plugincatalog.VersionFilter{VersionID: assignment.DesiredVersionID, Limit: 2})
	if err != nil || len(page.Items) != 1 {
		return agentcontrol.PluginArtifactGrant{}, agentcontrol.ErrPluginArtifactLeaseRejected
	}
	pluginVersion := page.Items[0]
	if pluginVersion.Validate() != nil || pluginVersion.Status != plugincatalog.StatusAvailable || pluginVersion.ID != assignment.DesiredVersionID || pluginVersion.PluginID != assignment.PluginID || pluginVersion.Version != assignment.DesiredVersion || pluginVersion.ArtifactID != assignment.ArtifactID || pluginVersion.PackageSHA256 != assignment.ArtifactSHA256 || pluginVersion.ManifestDigest != assignment.ManifestDigest {
		return agentcontrol.PluginArtifactGrant{}, agentcontrol.ErrPluginArtifactLeaseRejected
	}
	value, err := authorizer.Artifacts.Get(ctx, scope, artifactID)
	if err != nil || value.ID != artifactID || value.Scope != scope || value.Kind != "plugin-package" || value.ContentType != "application/gzip" || value.SizeBytes <= 0 || value.SizeBytes > 256<<20 || value.Checksum != "sha256:"+assignment.ArtifactSHA256 || value.SourceResource.ResourceType != "plugin_catalog_operation" || !validPluginCatalogOperationID(value.SourceResource.ResourceID) || value.StorageReference == "" {
		return agentcontrol.PluginArtifactGrant{}, agentcontrol.ErrPluginArtifactLeaseRejected
	}
	return agentcontrol.PluginArtifactGrant{AgentID: agentID, AssignmentID: assignmentID, ArtifactID: artifactID, OperationRevision: operationRevision, Artifact: value}, nil
}

func validPluginCatalogOperationID(value string) bool {
	const prefix = "plugin-operation-"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(digest) == 16
}

var _ agentcontrol.PluginArtifactAuthorizer = livePluginArtifactAuthorizer{}

func loopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed := net.ParseIP(host)
	return parsed != nil && parsed.IsLoopback()
}

func loadServerTLS(material TLSMaterial, requireClient bool) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(material.CertFile, material.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate/key: %w", err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	if requireClient {
		pem, err := os.ReadFile(material.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("read client CA: no certificates")
		}
		config.ClientCAs, config.ClientAuth = pool, tls.RequireAndVerifyClientCert
	}
	return config, nil
}

func loadEnrollmentIssuer(material TLSMaterial, lifetime time.Duration) (*enrollment.AgentCertificateIssuer, error) {
	if !filepath.IsAbs(material.CertFile) || !filepath.IsAbs(material.KeyFile) {
		return nil, errors.New("enrollment Agent CA paths must be absolute")
	}
	for _, path := range []string{material.CertFile, material.KeyFile} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("enrollment Agent CA material is unavailable")
		}
		if runtime.GOOS == "linux" && path == material.KeyFile && info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("enrollment Agent CA private key must not be group/world accessible")
		}
	}
	certificatePEM, err := os.ReadFile(material.CertFile)
	if err != nil {
		return nil, errors.New("read enrollment Agent CA certificate")
	}
	privateKeyPEM, err := os.ReadFile(material.KeyFile)
	if err != nil {
		return nil, errors.New("read enrollment Agent CA private key")
	}
	defer func() {
		for index := range privateKeyPEM {
			privateKeyPEM[index] = 0
		}
	}()
	issuer, err := enrollment.NewAgentCertificateIssuer(certificatePEM, privateKeyPEM, lifetime, func() time.Time { return time.Now().UTC() }, nil)
	if err != nil {
		return nil, errors.New("configure enrollment Agent certificate issuer")
	}
	return issuer, nil
}

func (server *Server) Run(ctx context.Context) error {
	if server == nil {
		return errors.New("control-plane server is nil")
	}
	if err := ctx.Err(); err != nil {
		server.closeResources()
		return err
	}
	if err := server.ping(ctx); err != nil {
		server.closeResources()
		return fmt.Errorf("database readiness: %w", err)
	}
	if err := server.migrate(ctx); err != nil {
		server.closeResources()
		return fmt.Errorf("run migrations: %w", err)
	}
	if server.importPreflight != nil {
		if err := server.importPreflight(ctx); err != nil {
			server.closeResources()
			return errors.New("generation-zero credential import preflight failed")
		}
	}
	httpListener, err := server.listen("tcp", server.config.HTTP.Address)
	if err != nil {
		server.closeResources()
		return fmt.Errorf("listen HTTP: %w", err)
	}
	grpcListener, err := server.listen("tcp", server.config.GRPC.Address)
	if err != nil {
		_ = httpListener.Close()
		server.closeResources()
		return fmt.Errorf("listen gRPC: %w", err)
	}
	var enrollmentListener net.Listener
	if server.enrollmentGRPCServer != nil {
		enrollmentListener, err = server.listen("tcp", server.config.Enrollment.Listener.Address)
		if err != nil {
			_ = httpListener.Close()
			_ = grpcListener.Close()
			server.closeResources()
			return fmt.Errorf("listen enrollment gRPC: %w", err)
		}
	}
	if err := server.hostObservations.Start(context.Background()); err != nil {
		_ = httpListener.Close()
		_ = grpcListener.Close()
		if enrollmentListener != nil {
			_ = enrollmentListener.Close()
		}
		server.closeResources()
		return fmt.Errorf("start Host observation delivery: %w", err)
	}
	httpTLSListener := tls.NewListener(httpListener, server.httpTLS.Clone())
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	server.httpServer.BaseContext = func(net.Listener) context.Context { return runCtx }
	server.startLoops(runCtx)
	errorsChannel := make(chan error, 3)
	go func() { errorsChannel <- server.httpServer.Serve(httpTLSListener) }()
	go func() { errorsChannel <- server.grpcServer.Serve(grpcListener) }()
	if enrollmentListener != nil {
		go func() { errorsChannel <- server.enrollmentGRPCServer.Serve(enrollmentListener) }()
	}
	select {
	case <-ctx.Done():
		cancel()
		stopErr := server.stop(httpTLSListener, grpcListener, enrollmentListener)
		workerErr := server.waitWorkers()
		server.closeResources()
		if stopErr != nil {
			return stopErr
		}
		if workerErr != nil {
			return workerErr
		}
		return ctx.Err()
	case serveErr := <-errorsChannel:
		cancel()
		stopErr := server.stop(httpTLSListener, grpcListener, enrollmentListener)
		workerErr := server.waitWorkers()
		server.closeResources()
		if stopErr != nil {
			return stopErr
		}
		if workerErr != nil {
			return workerErr
		}
		if errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("serve control plane: %w", serveErr)
	}
}

func (server *Server) stop(httpListener, grpcListener, enrollmentListener net.Listener) error {
	server.ready.Store(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.httpServer.Shutdown(shutdownCtx)
	server.grpcServer.Stop()
	if server.enrollmentGRPCServer != nil {
		server.enrollmentGRPCServer.Stop()
	}
	_ = httpListener.Close()
	_ = grpcListener.Close()
	if enrollmentListener != nil {
		_ = enrollmentListener.Close()
	}
	if server.hostObservations != nil {
		report, err := server.hostObservations.Close(shutdownCtx)
		if err != nil {
			return fmt.Errorf("close Host observation delivery: %w", err)
		}
		if report.TotalDiscarded() != 0 {
			return fmt.Errorf("close Host observation delivery: discarded observation=%d hello=%d heartbeat=%d", report.ObservationDiscarded, report.HelloDiscarded, report.HeartbeatDiscarded)
		}
	}
	if server.discoveryObservations != nil {
		server.discoveryObservations.Close()
	}
	if server.pluginObservations != nil {
		server.pluginObservations.Close()
	}
	return nil
}

func (server *Server) closeDatabase() {
	if server.ownsDatabase && server.database != nil {
		_ = server.database.Close()
		server.ownsDatabase = false
	}
}

func (server *Server) closeResources() {
	if server.metricTemplateLeases != nil {
		server.metricTemplateLeases.Close()
		server.metricTemplateLeases = nil
	}
	if server.credentialLeases != nil {
		server.credentialLeases.Close()
		server.credentialLeases = nil
	}
	if server.artifactBlobs != nil {
		_ = server.artifactBlobs.Close()
		server.artifactBlobs = nil
	}
	server.closeDatabase()
}

func (server *Server) startLoops(ctx context.Context) {
	evaluationEvery := server.config.EvaluationEvery
	if evaluationEvery <= 0 {
		evaluationEvery = 15 * time.Second
	}
	retryEvery := server.config.RetryEvery
	if retryEvery <= 0 {
		retryEvery = time.Minute
	}
	server.workers.Add(9)
	go func() {
		defer server.workers.Done()
		periodic(ctx, evaluationEvery, func(at time.Time) { _ = server.evaluateAndDispatch(ctx, at) })
	}()
	go func() {
		defer server.workers.Done()
		periodic(ctx, retryEvery, func(at time.Time) { _ = server.retryDue(ctx, at) })
	}()
	go func() {
		defer server.workers.Done()
		periodic(ctx, time.Second, func(at time.Time) { _ = server.dispatchCommands(ctx, at) })
	}()
	go func() {
		defer server.workers.Done()
		periodic(ctx, 30*time.Second, func(at time.Time) {
			if err := server.scheduleInspections(ctx, at); err != nil && ctx.Err() == nil {
				log.Printf("inspection scheduler pass failed: %v", err)
			}
		})
	}()
	go func() {
		defer server.workers.Done()
		periodic(ctx, time.Second, func(at time.Time) {
			if err := server.processInspections(ctx, at); err != nil && ctx.Err() == nil {
				log.Printf("inspection worker pass failed: %v", err)
			}
		})
	}()
	go func() {
		defer server.workers.Done()
		periodic(ctx, time.Minute, func(at time.Time) {
			if err := server.reconcilePluginCatalog(ctx, at); err != nil && ctx.Err() == nil {
				log.Printf("plugin catalog reconciliation pass failed: %v", err)
			}
		})
	}()
	go func() {
		defer server.workers.Done()
		periodic(ctx, 2*time.Second, func(at time.Time) {
			if err := server.reconcilePlugins(ctx, at); err != nil && ctx.Err() == nil {
				log.Printf("plugin assignment reconciliation pass failed: %v", err)
			}
		})
	}()
	go func() {
		defer server.workers.Done()
		periodic(ctx, 5*time.Second, func(at time.Time) {
			if err := server.repairPluginAssignments(ctx, at); err != nil && ctx.Err() == nil {
				log.Printf("plugin assignment repair pass failed: %v", err)
			}
		})
	}()
	go func() {
		defer server.workers.Done()
		periodic(ctx, 5*time.Second, func(at time.Time) {
			if server.failMetricTrials != nil {
				if err := server.failMetricTrials(ctx, at); err != nil && ctx.Err() == nil {
					log.Printf("metric template trial terminal reconciliation failed: %v", err)
				}
			}
		})
	}()
}

func (server *Server) waitWorkers() error {
	done := make(chan struct{})
	go func() {
		server.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("control-plane workers did not stop before shutdown deadline")
	}
}

func periodic(ctx context.Context, every time.Duration, action func(time.Time)) {
	action(time.Now().UTC())
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case at := <-ticker.C:
			action(at.UTC())
		}
	}
}

func (server *Server) evaluateAndDispatch(ctx context.Context, at time.Time) error {
	var scopeErrors []error
	for _, scope := range server.scopes {
		if ctx.Err() != nil {
			server.ready.Store(false)
			return ctx.Err()
		}
		summary, err := server.evaluateScope(ctx, scope, at)
		if err != nil {
			scopeErrors = append(scopeErrors, fmt.Errorf("%s evaluation: %w", scope.Key(), err))
			continue
		}
		if summary.FailedRules > 0 {
			scopeErrors = append(scopeErrors, fmt.Errorf("%s evaluation: %d failed rules", scope.Key(), summary.FailedRules))
		}
		cursor := ""
		for {
			events, listErr := server.listEvents(ctx, scope, alert.EventFilter{Limit: 500, AfterID: cursor, OrderByID: true})
			if listErr != nil {
				scopeErrors = append(scopeErrors, fmt.Errorf("%s event listing: %w", scope.Key(), listErr))
				break
			}
			for _, event := range events {
				if dispatchErr := server.dispatch(ctx, event, event.State); dispatchErr != nil {
					scopeErrors = append(scopeErrors, fmt.Errorf("%s event %s dispatch: %w", scope.Key(), event.ID, dispatchErr))
				}
			}
			if len(events) < 500 {
				break
			}
			cursor = events[len(events)-1].ID
		}
	}
	err := errors.Join(scopeErrors...)
	server.ready.Store(err == nil)
	return err
}

type configuredAgentResolver map[string]alert.Scope

func (resolver configuredAgentResolver) KnownAgent(_ context.Context, id string) bool {
	_, ok := resolver[id]
	return ok
}
func (resolver configuredAgentResolver) ScopeForAgent(_ context.Context, id string) (alert.Scope, error) {
	scope, ok := resolver[id]
	if !ok {
		return alert.Scope{}, errors.New("agent assignment not found")
	}
	return scope, nil
}
func (resolver configuredAgentResolver) HostForAgent(_ context.Context, id string) (string, error) {
	if _, ok := resolver[id]; !ok {
		return "", errors.New("agent assignment not found")
	}
	return id, nil
}
func configuredAgentResolverFrom(assignments map[string]AgentAssignment) configuredAgentResolver {
	result := make(configuredAgentResolver, len(assignments))
	for id, a := range assignments {
		result[id] = alert.Scope{TenantID: a.TenantID, ProjectID: a.ProjectID}
	}
	return result
}

type enrolledAgentScopeResolver interface {
	ScopeForAgent(context.Context, string) (platformscope.Scope, error)
}

type enrolledAgentHostResolver interface {
	HostForAgent(context.Context, string) (string, error)
}

// runtimeAgentResolver trusts persisted enrollment first and keeps static
// assignments only as a compatibility fallback for pre-enrollment Agents.
type runtimeAgentResolver struct {
	configured configuredAgentResolver
	enrolled   enrolledAgentScopeResolver
}

func (resolver runtimeAgentResolver) KnownAgent(ctx context.Context, agentID string) bool {
	_, err := resolver.ScopeForAgent(ctx, agentID)
	return err == nil
}

func (resolver runtimeAgentResolver) ScopeForAgent(ctx context.Context, agentID string) (alert.Scope, error) {
	if resolver.enrolled != nil {
		scope, err := resolver.enrolled.ScopeForAgent(ctx, agentID)
		if err == nil {
			return alert.Scope{TenantID: scope.TenantID, ProjectID: scope.ProjectID}, nil
		}
		if !errors.Is(err, hostinventory.ErrNotFound) {
			return alert.Scope{}, err
		}
	}
	return resolver.configured.ScopeForAgent(ctx, agentID)
}

func (resolver runtimeAgentResolver) HostForAgent(ctx context.Context, agentID string) (string, error) {
	if enrolled, ok := resolver.enrolled.(enrolledAgentHostResolver); ok {
		hostID, err := enrolled.HostForAgent(ctx, agentID)
		if err == nil {
			return hostID, nil
		}
		if !errors.Is(err, hostinventory.ErrNotFound) {
			return "", err
		}
	}
	return resolver.configured.HostForAgent(ctx, agentID)
}

type persistedHostObservationSink struct {
	service *hostinventory.ApplicationService
}

func (sink persistedHostObservationSink) RecordObservation(ctx context.Context, agentID string, provided *telemetryv1.HostObservation) error {
	if sink.service == nil || provided == nil || provided.GetAgentId() != agentID || provided.GetObservedAt() == nil || provided.GetObservedAt().CheckValid() != nil {
		return hostinventory.ErrInvalid
	}
	filesystems := make([]hostinventory.FilesystemSummary, len(provided.GetFilesystems()))
	for index, filesystem := range provided.GetFilesystems() {
		if filesystem == nil {
			return hostinventory.ErrInvalid
		}
		filesystems[index] = hostinventory.FilesystemSummary{MountPoint: filesystem.GetMountPoint(), CapacityBytes: filesystem.GetCapacityBytes(), AvailableBytes: filesystem.GetAvailableBytes()}
	}
	_, err := sink.service.RecordObservation(ctx, hostinventory.Observation{
		HostID: provided.GetHostId(), AgentID: agentID, Revision: provided.GetObservationRevision(), AgentVersion: provided.GetAgentVersion(),
		Hostname: provided.GetHostname(), OS: provided.GetOperatingSystem(), OSVersion: provided.GetOperatingSystemVersion(), Kernel: provided.GetKernelVersion(),
		Architecture: provided.GetArchitecture(), LogicalCPUCount: provided.GetLogicalCpuCount(), MemoryCapacityBytes: provided.GetMemoryCapacityBytes(),
		Filesystems: filesystems, NetworkAddresses: append([]string(nil), provided.GetNetworkAddresses()...),
		Capabilities: append([]string(nil), provided.GetCapabilities()...), ObservedAt: provided.GetObservedAt().AsTime().UTC(),
	})
	return err
}

func (sink persistedHostObservationSink) RecordHello(ctx context.Context, agentID string, at time.Time) error {
	if sink.service == nil {
		return hostinventory.ErrInvalid
	}
	_, err := sink.service.RecordHello(ctx, agentID, at)
	return err
}

func (sink persistedHostObservationSink) RecordHeartbeat(ctx context.Context, agentID string, at time.Time) error {
	if sink.service == nil {
		return hostinventory.ErrInvalid
	}
	_, err := sink.service.RecordHeartbeat(ctx, agentID, at)
	return err
}

var _ agentcontrol.HostObservationSink = persistedHostObservationSink{}

func configuredInspectionTargets(assignments map[string]AgentAssignment) []inspection.HostTarget {
	result := make([]inspection.HostTarget, 0, len(assignments))
	for id, assignment := range assignments {
		result = append(result, inspection.HostTarget{
			Scope:   platformscope.Scope{TenantID: assignment.TenantID, ProjectID: assignment.ProjectID},
			AgentID: id, DisplayName: assignment.DisplayName, Host: assignment.Host,
			Labels: assignment.Labels, Connectivity: "unknown", Capabilities: []string{}, AdvertisedSources: []inspection.SourceType{},
		})
	}
	return result
}

type inspectionSessionRegistry interface {
	Session(string) (agentcontrol.SessionInfo, bool)
}

type liveInspectionTargetResolver struct {
	configured inspection.TargetResolver
	registry   inspectionSessionRegistry
}

func (resolver liveInspectionTargetResolver) Resolve(ctx context.Context, scope platformscope.Scope, selector inspection.TargetSelector) ([]inspection.HostTarget, error) {
	if resolver.configured == nil {
		return nil, inspection.ErrInvalid
	}
	targets, err := resolver.configured.Resolve(ctx, scope, selector)
	if err != nil {
		return nil, err
	}
	return resolver.withSessions(targets), nil
}

func (resolver liveInspectionTargetResolver) List(ctx context.Context, scope platformscope.Scope) ([]inspection.HostTarget, error) {
	if resolver.configured == nil {
		return nil, inspection.ErrInvalid
	}
	targets, err := resolver.configured.List(ctx, scope)
	if err != nil {
		return nil, err
	}
	return resolver.withSessions(targets), nil
}

func (resolver liveInspectionTargetResolver) withSessions(targets []inspection.HostTarget) []inspection.HostTarget {
	for index := range targets {
		targets[index].Connectivity = "offline"
		targets[index].AgentControlHeartbeatAt = time.Time{}
		targets[index].Capabilities = []string{}
		targets[index].AdvertisedSources = []inspection.SourceType{}
		if resolver.registry == nil {
			continue
		}
		session, ok := resolver.registry.Session(targets[index].AgentID)
		if !ok || session.AgentID != targets[index].AgentID {
			continue
		}
		targets[index].Connectivity = "online"
		targets[index].AgentControlHeartbeatAt = session.LastHeartbeat.UTC()
		targets[index].Capabilities = append([]string(nil), session.Capabilities...)
		for _, capability := range session.Capabilities {
			if capability == agent.CapabilityCollectNowHostV1 {
				targets[index].AdvertisedSources = []inspection.SourceType{inspection.SourceMetric, inspection.SourceMetadata, inspection.SourceLogSummary}
				break
			}
		}
	}
	return targets
}

func configuredScopes(config Config) []alert.Scope {
	byKey := make(map[string]alert.Scope)
	for _, configured := range config.EvaluationScopes {
		scope := alert.Scope{TenantID: configured.TenantID, ProjectID: configured.ProjectID}
		byKey[scope.Key()] = scope
	}
	for _, a := range config.Agents {
		scope := alert.Scope{TenantID: a.TenantID, ProjectID: a.ProjectID}
		if scope.Validate() == nil {
			byKey[scope.Key()] = scope
		}
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]alert.Scope, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}
	return result
}

func foundationCapabilityInput(scope platformscope.Scope, assignments map[string]AgentAssignment, registry *agentcontrol.Registry) capability.Input {
	input := capability.Input{DeploymentFlags: capability.FoundationDeploymentFlags(), AgentCapabilities: make(map[string]bool)}
	if registry == nil {
		return input
	}
	for agentID, assignment := range assignments {
		if assignment.TenantID != scope.TenantID || assignment.ProjectID != scope.ProjectID {
			continue
		}
		session, ok := registry.Session(agentID)
		if !ok {
			continue
		}
		for _, advertised := range session.Capabilities {
			input.AgentCapabilities[advertised] = true
		}
	}
	return input
}

type exactWebhookAllowlist map[string]struct{}

func (allowlist exactWebhookAllowlist) Allows(host string) bool {
	_, ok := allowlist[strings.ToLower(strings.TrimSuffix(host, "."))]
	return ok
}
func exactWebhookAllowlistFrom(values []string) exactWebhookAllowlist {
	result := make(exactWebhookAllowlist, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

type environmentSecretResolver struct{}

func (environmentSecretResolver) Resolve(_ context.Context, ref string) ([]byte, error) {
	if err := alert.ValidateSecretReference(ref); err != nil {
		return nil, errors.New("invalid secret reference")
	}
	name := strings.TrimPrefix(ref, "env://")
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil, errors.New("secret is unavailable")
	}
	return []byte(value), nil
}

func commandSignerForConfig(ctx context.Context, config Config, resolver alert.SecretResolver) (job.CommandSigner, error) {
	if config.CommandSigner != nil {
		return config.CommandSigner, nil
	}
	contents, err := resolver.Resolve(ctx, config.Command.SigningPrivateKeyRef)
	if err != nil {
		return nil, fmt.Errorf("resolve command signing private key: %w", err)
	}
	defer func() {
		for index := range contents {
			contents[index] = 0
		}
	}()
	signer, err := job.NewEd25519CommandSignerPEM(contents)
	if err != nil {
		return nil, fmt.Errorf("configure command signing private key: %w", err)
	}
	return signer, nil
}

func commandTokenProtectorForConfig(ctx context.Context, config Config, resolver alert.SecretResolver) (job.TokenProtector, error) {
	if config.CommandTokenProtector != nil {
		return config.CommandTokenProtector, nil
	}
	key, err := resolver.Resolve(ctx, config.Command.ExecutionTokenKeyRef)
	if err != nil {
		return nil, fmt.Errorf("resolve command execution token key: %w", err)
	}
	defer func() {
		for index := range key {
			key[index] = 0
		}
	}()
	protector, err := job.NewAES256GCMTokenProtector(key)
	if err != nil {
		return nil, fmt.Errorf("configure command execution token protection: %w", err)
	}
	return protector, nil
}

type postgresLogBatchDeduplicator struct{ database *sql.DB }

func (dedup postgresLogBatchDeduplicator) AcceptBatchOnce(ctx context.Context, agentID, batchID string) (bool, error) {
	var state string
	err := dedup.database.QueryRowContext(ctx, "INSERT INTO ingest_batch_dedup (agent_id, batch_id, state, accepted_at) VALUES ($1, $2, 'accepted', NOW()) ON CONFLICT DO NOTHING RETURNING state", agentID, batchID).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if state != "accepted" {
		return false, errors.New("unexpected log batch reservation state")
	}
	return true, nil
}

var _ ingest.AgentIdentityResolver = runtimeAgentResolver{}
var _ controlplane.AgentScopeResolver = runtimeAgentResolver{}
var _ controlplane.AgentHostResolver = runtimeAgentResolver{}
var _ ingest.DurableBatchDeduplicator = postgresLogBatchDeduplicator{}

// Small constructor aliases keep the configuration-to-runtime mapping explicit.
func buildConfiguredAgentResolver(assignments map[string]AgentAssignment) configuredAgentResolver {
	return configuredAgentResolverFrom(assignments)
}
func buildExactWebhookAllowlist(values []string) exactWebhookAllowlist {
	return exactWebhookAllowlistFrom(values)
}
