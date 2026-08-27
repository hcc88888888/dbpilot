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
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
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

type IdentitySettings struct {
	Mode       string                       `yaml:"mode"`
	Principals map[string]PrincipalSettings `yaml:"principals,omitempty"`
}

type PrincipalSettings struct {
	Subject       string            `yaml:"subject"`
	PlatformAdmin bool              `yaml:"platform_admin"`
	Projects      []AgentAssignment `yaml:"projects,omitempty"`
}

type Config struct {
	DatabaseURL      string                     `yaml:"database_url"`
	WebhookAllowlist []string                   `yaml:"webhook_allowlist"`
	HTTP             ListenerConfig             `yaml:"http"`
	GRPC             ListenerConfig             `yaml:"grpc"`
	Agents           map[string]AgentAssignment `yaml:"agents"`
	SMTP             SMTPSettings               `yaml:"smtp"`
	Identity         IdentitySettings           `yaml:"identity"`
	EventURLBase     string                     `yaml:"event_url_base"`
	EvaluationScopes []EvaluationScopeSettings  `yaml:"evaluation_scopes,omitempty"`
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
	config        Config
	database      *sql.DB
	ownsDatabase  bool
	repository    *alert.PostgresRepository
	evaluator     *alert.Evaluator
	dispatcher    *alert.Dispatcher
	httpServer    *http.Server
	grpcServer    *grpc.Server
	httpTLS       *tls.Config
	grpcTLS       *tls.Config
	ping          func(context.Context) error
	migrate       func(context.Context) error
	listen        func(string, string) (net.Listener, error)
	scopes        []alert.Scope
	ready         *atomic.Bool
	evaluateScope func(context.Context, alert.Scope, time.Time) (alert.EvaluationSummary, error)
	listEvents    func(context.Context, alert.Scope, alert.EventFilter) ([]alert.AlertEvent, error)
	dispatch      func(context.Context, alert.AlertEvent, alert.EventState) error
	retryDue      func(context.Context, time.Time) error
	workers       sync.WaitGroup
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
	ingestService := ingest.NewDurableService(resolver, postgresLogBatchDeduplicator{database: database}, metricConsumer)
	ingestService.SetPolicyStatusObserver(ingest.PolicyStatusObserverFunc(func(status ingest.PolicyStatusMetadata) {
		log.Printf("dbpilot authenticated policy status accepted agent_id=%q version=%d", status.AgentID, status.Version)
	}))
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
		migrate = func(ctx context.Context) error { return alert.RunMigrations(ctx, database) }
	}
	listen := config.Listen
	if listen == nil {
		listen = net.Listen
	}
	ready := &atomic.Bool{}
	services := controlplane.Services{Repository: repository, Evaluator: evaluator, Ready: func(ctx context.Context) error {
		if !ready.Load() {
			return errors.New("a successful all-scope evaluation pass has not completed")
		}
		return ping(ctx)
	}}
	httpServer := &http.Server{Handler: controlplane.NewHTTPHandler(services, principalResolver), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(grpcTLS.Clone())), grpc.MaxRecvMsgSize(ingest.MaxBatchPayloadBytes+(64<<10)))
	telemetryv1.RegisterTelemetryIngestServer(grpcServer, ingestService)
	return &Server{config: config, database: database, ownsDatabase: ownsDatabase, repository: repository, evaluator: evaluator, dispatcher: dispatcher, httpServer: httpServer, grpcServer: grpcServer, httpTLS: httpTLS.Clone(), grpcTLS: grpcTLS.Clone(), ping: ping, migrate: migrate, listen: listen, scopes: configuredScopes(config), ready: ready, evaluateScope: evaluator.EvaluateScope, listEvents: repository.ListEvents, dispatch: dispatcher.Dispatch, retryDue: dispatcher.RetryDue}, nil
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
		default:
			return errors.New("trusted HTTP identity adapter is required")
		}
	}
	for id, assignment := range config.Agents {
		if strings.TrimSpace(id) == "" || (alert.Scope{TenantID: assignment.TenantID, ProjectID: assignment.ProjectID}).Validate() != nil {
			return errors.New("agents contains an invalid assignment")
		}
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
	default:
		return nil, errors.New("trusted HTTP identity adapter is required")
	}
}

func configuredCertificatePrincipals(settings map[string]PrincipalSettings) (map[string]alert.Principal, error) {
	principals := make(map[string]alert.Principal, len(settings))
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
			scope := alert.Scope{TenantID: assignment.TenantID, ProjectID: assignment.ProjectID}
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
		principals[identityURI.String()] = alert.Principal{Subject: configured.Subject, PlatformAdmin: configured.PlatformAdmin, Projects: projects}
	}
	return principals, nil
}

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
		cancel()
		server.stop(httpTLSListener, grpcListener)
		workerErr := server.waitWorkers()
		server.closeDatabase()
		if workerErr != nil {
			return workerErr
		}
		return ctx.Err()
	case serveErr := <-errorsChannel:
		cancel()
		server.stop(httpTLSListener, grpcListener)
		workerErr := server.waitWorkers()
		server.closeDatabase()
		if workerErr != nil {
			return workerErr
		}
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
	server.workers.Add(2)
	go func() {
		defer server.workers.Done()
		periodic(ctx, evaluationEvery, func(at time.Time) { _ = server.evaluateAndDispatch(ctx, at) })
	}()
	go func() {
		defer server.workers.Done()
		periodic(ctx, retryEvery, func(at time.Time) { _ = server.retryDue(ctx, at) })
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
		if _, err := server.evaluateScope(ctx, scope, at); err != nil {
			scopeErrors = append(scopeErrors, fmt.Errorf("%s evaluation: %w", scope.Key(), err))
			continue
		}
		events, err := server.listEvents(ctx, scope, alert.EventFilter{Limit: 500})
		if err != nil {
			scopeErrors = append(scopeErrors, fmt.Errorf("%s event listing: %w", scope.Key(), err))
			continue
		}
		for _, event := range events {
			if err := server.dispatch(ctx, event, event.State); err != nil {
				scopeErrors = append(scopeErrors, fmt.Errorf("%s event %s dispatch: %w", scope.Key(), event.ID, err))
			}
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
func configuredAgentResolverFrom(assignments map[string]AgentAssignment) configuredAgentResolver {
	result := make(configuredAgentResolver, len(assignments))
	for id, a := range assignments {
		result[id] = alert.Scope{TenantID: a.TenantID, ProjectID: a.ProjectID}
	}
	return result
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

var _ ingest.AgentIdentityResolver = configuredAgentResolver{}
var _ controlplane.AgentScopeResolver = configuredAgentResolver{}
var _ ingest.DurableBatchDeduplicator = postgresLogBatchDeduplicator{}

// Small constructor aliases keep the configuration-to-runtime mapping explicit.
func buildConfiguredAgentResolver(assignments map[string]AgentAssignment) configuredAgentResolver {
	return configuredAgentResolverFrom(assignments)
}
func buildExactWebhookAllowlist(values []string) exactWebhookAllowlist {
	return exactWebhookAllowlistFrom(values)
}
