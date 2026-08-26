package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	telemetryv1 "dbpilot.local/platform/gen/telemetry/v1"
	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/controlplane"
	"dbpilot.local/platform/internal/ingest"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gopkg.in/yaml.v3"
)

const version = "dev"

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

type Config struct {
	DatabaseURL      string                     `yaml:"database_url"`
	WebhookAllowlist []string                   `yaml:"webhook_allowlist"`
	HTTP             ListenerConfig             `yaml:"http"`
	GRPC             ListenerConfig             `yaml:"grpc"`
	Agents           map[string]AgentAssignment `yaml:"agents"`
	SMTP             SMTPSettings               `yaml:"smtp"`
	EventURLBase     string                     `yaml:"event_url_base"`
	EvaluationScopes []alert.Scope              `yaml:"evaluation_scopes,omitempty"`
	EvaluationEvery  time.Duration              `yaml:"evaluation_every,omitempty"`
	RetryEvery       time.Duration              `yaml:"retry_every,omitempty"`

	HTTPServerTLS     *tls.Config                                `yaml:"-"`
	GRPCServerTLS     *tls.Config                                `yaml:"-"`
	Database          *sql.DB                                    `yaml:"-"`
	Ping              func(context.Context) error                `yaml:"-"`
	Migrate           func(context.Context) error                `yaml:"-"`
	Listen            func(string, string) (net.Listener, error) `yaml:"-"`
	PrincipalResolver controlplane.PrincipalResolver             `yaml:"-"`
	SecretResolver    alert.SecretResolver                       `yaml:"-"`
	Channels          []alert.DeliveryChannel                    `yaml:"-"`
}

type Server struct {
	config       Config
	database     *sql.DB
	ownsDatabase bool
	repository   *alert.PostgresRepository
	evaluator    *alert.Evaluator
	dispatcher   *alert.Dispatcher
	httpServer   *http.Server
	grpcServer   *grpc.Server
	httpTLS      *tls.Config
	grpcTLS      *tls.Config
	ping         func(context.Context) error
	migrate      func(context.Context) error
	listen       func(string, string) (net.Listener, error)
	scopes       []alert.Scope
	ready        *atomic.Bool
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dbpilot-controlplane", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "", "control-plane YAML configuration")
	showVersion := flags.Bool("version", false, "print version and exit")
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
	httpTLS := config.HTTPServerTLS
	if httpTLS == nil {
		loaded, err := loadServerTLS(config.HTTP.TLS, false)
		if err != nil {
			return nil, fmt.Errorf("load HTTP TLS: %w", err)
		}
		httpTLS = loaded
	}
	httpTLS = httpTLS.Clone()
	if httpTLS.MinVersion < tls.VersionTLS12 {
		httpTLS.MinVersion = tls.VersionTLS12
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
	resolver := buildConfiguredAgentResolver(config.Agents)
	metricConsumer := controlplane.NewMetricConsumer(resolver, repository)
	deduplicator := postgresBatchDeduplicator{database: database}
	ingestService := ingest.NewService(resolver, deduplicator, metricConsumer)
	evaluator := alert.NewEvaluator(repository, repository)
	secrets := config.SecretResolver
	if secrets == nil {
		secrets = environmentSecretResolver{}
	}
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
	principalResolver := config.PrincipalResolver
	if principalResolver == nil {
		principalResolver = controlplane.HeaderPrincipalResolver{}
	}
	ping := config.Ping
	if ping == nil {
		ping = database.PingContext
	}
	migrate := config.Migrate
	if migrate == nil {
		migrate = func(ctx context.Context) error { return alert.RunMigrations(ctx, database) }
	}
	listen := config.Listen
	if listen == nil {
		listen = net.Listen
	}
	ready := &atomic.Bool{}
	services := controlplane.Services{Repository: repository, Evaluator: evaluator, Ready: func(ctx context.Context) error {
		if !ready.Load() {
			return errors.New("migrations are not complete")
		}
		return ping(ctx)
	}}
	httpServer := &http.Server{Handler: controlplane.NewHTTPHandler(services, principalResolver), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcTLS.Clone())), grpc.MaxRecvMsgSize(ingest.MaxBatchPayloadBytes+(64<<10)))
	telemetryv1.RegisterTelemetryIngestServer(grpcServer, ingestService)
	return &Server{config: config, database: database, ownsDatabase: ownsDatabase, repository: repository, evaluator: evaluator, dispatcher: dispatcher, httpServer: httpServer, grpcServer: grpcServer, httpTLS: httpTLS.Clone(), grpcTLS: grpcTLS.Clone(), ping: ping, migrate: migrate, listen: listen, scopes: configuredScopes(config), ready: ready}, nil
}

func validateConfig(config Config) error {
	parsed, err := url.Parse(config.DatabaseURL)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" || strings.Trim(parsed.Path, "/") == "" {
		return errors.New("database_url must be a PostgreSQL URL with host and database")
	}
	if len(config.WebhookAllowlist) == 0 {
		return errors.New("webhook_allowlist must contain at least one hostname")
	}
	for _, host := range config.WebhookAllowlist {
		if host == "" || host != strings.ToLower(strings.TrimSpace(host)) || strings.ContainsAny(host, "/:@") {
			return errors.New("webhook_allowlist contains an invalid hostname")
		}
	}
	if strings.TrimSpace(config.HTTP.Address) == "" || strings.TrimSpace(config.GRPC.Address) == "" {
		return errors.New("HTTP and gRPC addresses are required")
	}
	if config.HTTPServerTLS == nil && (config.HTTP.TLS.CertFile == "" || config.HTTP.TLS.KeyFile == "") {
		return errors.New("HTTP TLS certificate and key references are required")
	}
	if config.GRPCServerTLS == nil && (config.GRPC.TLS.CertFile == "" || config.GRPC.TLS.KeyFile == "" || config.GRPC.TLS.ClientCAFile == "") {
		return errors.New("gRPC mTLS certificate, key, and client CA references are required")
	}
	for id, assignment := range config.Agents {
		if strings.TrimSpace(id) == "" || (alert.Scope{TenantID: assignment.TenantID, ProjectID: assignment.ProjectID}).Validate() != nil {
			return errors.New("agents contains an invalid assignment")
		}
	}
	return nil
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

func (server *Server) Run(ctx context.Context) error {
	if server == nil {
		return errors.New("control-plane server is nil")
	}
	if err := ctx.Err(); err != nil {
		server.closeDatabase()
		return err
	}
	if err := server.ping(ctx); err != nil {
		server.closeDatabase()
		return fmt.Errorf("database readiness: %w", err)
	}
	if err := server.migrate(ctx); err != nil {
		server.closeDatabase()
		return fmt.Errorf("run migrations: %w", err)
	}
	server.ready.Store(true)
	httpListener, err := server.listen("tcp", server.config.HTTP.Address)
	if err != nil {
		server.closeDatabase()
		return fmt.Errorf("listen HTTP: %w", err)
	}
	grpcListener, err := server.listen("tcp", server.config.GRPC.Address)
	if err != nil {
		_ = httpListener.Close()
		server.closeDatabase()
		return fmt.Errorf("listen gRPC: %w", err)
	}
	httpTLSListener := tls.NewListener(httpListener, server.httpTLS.Clone())
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	server.httpServer.BaseContext = func(net.Listener) context.Context { return runCtx }
	server.startLoops(runCtx)
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- server.httpServer.Serve(httpTLSListener) }()
	go func() { errorsChannel <- server.grpcServer.Serve(grpcListener) }()
	select {
	case <-ctx.Done():
		server.stop(httpTLSListener, grpcListener)
		server.closeDatabase()
		return ctx.Err()
	case serveErr := <-errorsChannel:
		server.stop(httpTLSListener, grpcListener)
		server.closeDatabase()
		if errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) {
			return nil
		}
		return fmt.Errorf("serve control plane: %w", serveErr)
	}
}

func (server *Server) stop(httpListener, grpcListener net.Listener) {
	server.ready.Store(false)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.httpServer.Shutdown(shutdownCtx)
	server.grpcServer.Stop()
	_ = httpListener.Close()
	_ = grpcListener.Close()
}

func (server *Server) closeDatabase() {
	if server.ownsDatabase && server.database != nil {
		_ = server.database.Close()
		server.ownsDatabase = false
	}
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
	go periodic(ctx, evaluationEvery, func(at time.Time) { server.evaluateAndDispatch(ctx, at) })
	go periodic(ctx, retryEvery, func(at time.Time) { _ = server.dispatcher.RetryDue(ctx, at) })
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

func (server *Server) evaluateAndDispatch(ctx context.Context, at time.Time) {
	for _, scope := range server.scopes {
		if ctx.Err() != nil {
			return
		}
		_, _ = server.evaluator.EvaluateScope(ctx, scope, at)
		events, err := server.repository.ListEvents(ctx, scope, alert.EventFilter{Limit: 500})
		if err != nil {
			continue
		}
		for _, event := range events {
			_ = server.dispatcher.Dispatch(ctx, event, event.State)
		}
	}
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
func configuredAgentResolverFrom(assignments map[string]AgentAssignment) configuredAgentResolver {
	result := make(configuredAgentResolver, len(assignments))
	for id, a := range assignments {
		result[id] = alert.Scope{TenantID: a.TenantID, ProjectID: a.ProjectID}
	}
	return result
}

func configuredScopes(config Config) []alert.Scope {
	byKey := make(map[string]alert.Scope)
	for _, scope := range config.EvaluationScopes {
		if scope.Validate() == nil {
			byKey[scope.Key()] = scope
		}
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
	const prefix = "env://"
	if !strings.HasPrefix(ref, prefix) {
		return nil, errors.New("unsupported secret reference")
	}
	name := strings.TrimPrefix(ref, prefix)
	if name == "" || strings.ContainsAny(name, "=\x00") {
		return nil, errors.New("invalid secret reference")
	}
	value, ok := os.LookupEnv(name)
	if !ok {
		return nil, errors.New("secret is unavailable")
	}
	return []byte(value), nil
}

type postgresBatchDeduplicator struct{ database *sql.DB }

func (dedup postgresBatchDeduplicator) Lookup(agentID, batchID string) (*telemetryv1.BatchAck, bool) {
	if dedup.database == nil {
		return nil, false
	}
	ack := &telemetryv1.BatchAck{BatchId: batchID}
	err := dedup.database.QueryRow("SELECT accepted, retryable, error_code FROM ingest_batch_dedup WHERE agent_id = $1 AND batch_id = $2", agentID, batchID).Scan(&ack.Accepted, &ack.Retryable, &ack.ErrorCode)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false
	}
	if err != nil {
		return &telemetryv1.BatchAck{BatchId: batchID, Retryable: true, ErrorCode: "DEDUP_UNAVAILABLE"}, true
	}
	return ack, true
}
func (dedup postgresBatchDeduplicator) Remember(agentID, batchID string, ack *telemetryv1.BatchAck) {
	if dedup.database == nil || ack == nil {
		return
	}
	_, _ = dedup.database.Exec("INSERT INTO ingest_batch_dedup (agent_id, batch_id, accepted, retryable, error_code) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (agent_id, batch_id) DO NOTHING", agentID, batchID, ack.Accepted, ack.Retryable, ack.ErrorCode)
}

var _ ingest.AgentIdentityResolver = configuredAgentResolver{}
var _ controlplane.AgentScopeResolver = configuredAgentResolver{}
var _ ingest.BatchDeduplicator = postgresBatchDeduplicator{}

// Small constructor aliases keep the configuration-to-runtime mapping explicit.
func buildConfiguredAgentResolver(assignments map[string]AgentAssignment) configuredAgentResolver {
	return configuredAgentResolverFrom(assignments)
}
func buildExactWebhookAllowlist(values []string) exactWebhookAllowlist {
	return exactWebhookAllowlistFrom(values)
}
