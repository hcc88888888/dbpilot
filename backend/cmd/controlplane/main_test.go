package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agentcontrol"
	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/controlplane"
	platformdatabase "dbpilot.local/platform/internal/database"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/plugincatalog"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestExampleConfigurationStrictlyDecodes(t *testing.T) {
	config, err := loadConfig(filepath.Join("..", "..", "config", "controlplane.yaml.example"))
	require.NoError(t, err)
	require.Equal(t, 15*time.Second, config.EvaluationEvery)
	require.Equal(t, time.Minute, config.RetryEvery)
	require.Contains(t, config.Agents, "spiffe-agent-id")
	require.Equal(t, "Production database host", config.Agents["spiffe-agent-id"].DisplayName)
	require.Equal(t, "db-1.example.com", config.Agents["spiffe-agent-id"].Host)
	require.Equal(t, map[string]string{"role": "database", "environment": "production"}, config.Agents["spiffe-agent-id"].Labels)
	require.Equal(t, "oidc", config.Identity.Mode)
	require.Equal(t, "https://identity.example.com", config.Identity.Issuer)
	require.Equal(t, "dbpilot-control-plane", config.Identity.Audience)
	require.Equal(t, "0.0.0.0:10443", config.Enrollment.Listener.Address)
	require.Equal(t, "/run/secrets/agent_enrollment_ca", config.Enrollment.AgentCA.CertFile)
	require.Equal(t, "/run/secrets/agent_enrollment_ca_key", config.Enrollment.AgentCA.KeyFile)
	require.Equal(t, 24*time.Hour, config.Enrollment.CertificateLifetime)
	require.Equal(t, "env://DBPILOT_COMMAND_SIGNING_PRIVATE_KEY", config.Command.SigningPrivateKeyRef)
	require.Equal(t, "env://DBPILOT_COMMAND_EXECUTION_TOKEN_KEY", config.Command.ExecutionTokenKeyRef)
}

func TestPublisherKeysForConfigDecodesOnlyCanonicalEd25519PublicKeys(t *testing.T) {
	// Break caught: malformed or duplicate configured trust roots must stop
	// startup rather than silently disabling package signature verification.
	public := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	config := Config{PluginPublishers: []PluginPublisherSettings{{
		PublisherID: "publisher-1", KeyID: "key-1", PublicKey: base64.StdEncoding.EncodeToString(public),
	}}}
	store, err := publisherKeysForConfig(config)
	require.NoError(t, err)
	got, err := store.PublicKey(context.Background(), "publisher-1", "key-1")
	require.NoError(t, err)
	require.Equal(t, public, got)

	config.PluginPublishers[0].PublicKey = "not-base64"
	_, err = publisherKeysForConfig(config)
	require.Error(t, err)
	config.PluginPublishers = []PluginPublisherSettings{
		{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: base64.StdEncoding.EncodeToString(public)},
		{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: base64.StdEncoding.EncodeToString(public)},
	}
	_, err = publisherKeysForConfig(config)
	require.ErrorIs(t, err, plugincatalog.ErrInvalid)
}

func TestPluginCatalogEnablementRequiresTrustRootAndArtifactReadiness(t *testing.T) {
	public := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	config := validServerConfig()
	config.PluginCatalog.Enabled = true
	config.Artifact.StorageRoot = t.TempDir()
	require.ErrorContains(t, validateConfig(config), "publisher")

	config.PluginPublishers = []PluginPublisherSettings{{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: base64.StdEncoding.EncodeToString(public)}}
	require.NoError(t, validateConfig(config))
	config.Artifact.StorageRoot = ""
	require.ErrorContains(t, validateConfig(config), "storage_root")

	disabled := validServerConfig()
	disabled.PluginCatalog.Enabled = false
	require.NoError(t, validateConfig(disabled))
}

func TestDefaultCompositionRunsPluginCatalogMigrationsWhenEnabled(t *testing.T) {
	if os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_PLUGIN_CATALOG_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_PLUGIN_CATALOG_POSTGRES_DSN is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	require.NoError(t, admin.PingContext(ctx))
	schema := fmt.Sprintf("plugin_catalog_composition_%d", time.Now().UnixNano())
	quotedSchema := pq.QuoteIdentifier(schema)
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, cleanupErr := admin.ExecContext(cleanupContext, "DROP SCHEMA "+quotedSchema+" CASCADE")
		require.NoError(t, cleanupErr)
		require.NoError(t, admin.Close())
	})
	parsed, err := url.Parse(dsn)
	require.NoError(t, err)
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	database, err := sql.Open("postgres", parsed.String())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })

	public := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	config := validServerConfig()
	config.Database = database
	config.Ping = database.PingContext
	config.PluginCatalog.Enabled = true
	config.PluginPublishers = []PluginPublisherSettings{{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: base64.StdEncoding.EncodeToString(public)}}
	config.Artifact.StorageRoot = t.TempDir()
	config.Migrate = nil
	server, err := NewServer(config)
	require.NoError(t, err)
	if server.artifactBlobs != nil {
		t.Cleanup(func() { require.NoError(t, server.artifactBlobs.Close()) })
	}
	require.NoError(t, server.migrate(ctx))
	for _, table := range []string{"plugin_definitions", "plugin_versions", "plugin_catalog_operations"} {
		var actual string
		require.NoError(t, database.QueryRowContext(ctx, "SELECT $1::regclass::text", table).Scan(&actual))
		require.Equal(t, table, actual)
	}
	var applied int
	require.NoError(t, database.QueryRowContext(ctx, "SELECT count(*) FROM dbpilot_schema_migrations WHERE name LIKE $1", "plugincatalog/%").Scan(&applied))
	require.Equal(t, 4, applied)
	configured := server.config.PluginCatalog.Enabled && len(server.config.PluginPublishers) == 1 && strings.TrimSpace(server.config.Artifact.StorageRoot) != ""
	require.True(t, configured)
}

func TestFullStackFixtureGeneratedConfigPassesProductionValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := filepath.Join(t.TempDir(), "acceptance")
	fixture, err := filepath.Abs(filepath.Join("..", "..", "test", "fixtures", "fullstack"))
	require.NoError(t, err)
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		goBinary += ".exe"
	}
	command := exec.CommandContext(ctx, goBinary, "run", fixture, "bootstrap", "--root", root)
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
	config, err := loadConfig(filepath.Join(root, "secrets", "controlplane.yaml"))
	require.NoError(t, err)
	require.Equal(t, "https://frontend:8443", config.EventURLBase)
	require.NoError(t, validateConfig(config))
}

func TestNewServerRejectsExecutionTokenProtectionKeysOtherThan32RawBytes(t *testing.T) {
	for _, size := range []int{31, 33} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			resolver := &recordingCommandSecretResolver{value: bytes.Repeat([]byte{0x44}, size)}
			config := validServerConfig()
			config.CommandTokenProtector = nil
			config.Command.ExecutionTokenKeyRef = "env://DBPILOT_COMMAND_EXECUTION_TOKEN_KEY"
			config.SecretResolver = resolver

			server, err := NewServer(config)
			require.Nil(t, server)
			require.ErrorContains(t, err, "exactly 32 bytes")
			require.Equal(t, []string{"env://DBPILOT_COMMAND_EXECUTION_TOKEN_KEY"}, resolver.references)
		})
	}
}

func TestNewServerResolvesExactExecutionTokenProtectionKeyOnce(t *testing.T) {
	resolver := &recordingCommandSecretResolver{value: bytes.Repeat([]byte{0x45}, 32)}
	config := validServerConfig()
	config.CommandTokenProtector = nil
	config.Command.ExecutionTokenKeyRef = "env://DBPILOT_COMMAND_EXECUTION_TOKEN_KEY"
	config.SecretResolver = resolver

	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server.commandLifecycle)
	require.Equal(t, []string{"env://DBPILOT_COMMAND_EXECUTION_TOKEN_KEY"}, resolver.references)
}

func TestNewServerRejectsInvalidProductionConfiguration(t *testing.T) {
	valid := validServerConfig()
	tests := map[string]func(*Config){
		"invalid database URL":             func(config *Config) { config.DatabaseURL = "mysql://db/controlplane" },
		"absent webhook allowlist":         func(config *Config) { config.WebhookAllowlist = nil },
		"missing HTTP TLS reference":       func(config *Config) { config.HTTPServerTLS = nil; config.HTTP.TLS.CertFile = "" },
		"missing gRPC client CA reference": func(config *Config) { config.GRPCServerTLS = nil; config.GRPC.TLS.ClientCAFile = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := valid

			mutate(&config)
			server, err := NewServer(config)
			require.Nil(t, server)
			require.Error(t, err)
		})
	}
}

func TestNewServerRejectsMissingTrustedHTTPIdentityAdapter(t *testing.T) {
	config := validServerConfig()
	config.PrincipalResolver = nil
	config.Identity = IdentitySettings{}

	server, err := NewServer(config)
	require.Nil(t, server)
	require.ErrorContains(t, err, "identity")
}

func TestLocalHeaderIdentityRequiresExplicitModeAndLoopbackListener(t *testing.T) {
	config := validServerConfig()
	config.PrincipalResolver = nil
	config.Identity.Mode = "local_headers"
	config.HTTP.Address = "0.0.0.0:8443"
	server, err := NewServer(config)
	require.Nil(t, server)
	require.ErrorContains(t, err, "loopback")

	config.HTTP.Address = "127.0.0.1:8443"
	server, err = NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server)
}

func TestMTLSIdentityModeBuildsConfiguredPrincipalAdapter(t *testing.T) {
	config := validServerConfig()
	config.PrincipalResolver = nil
	config.Identity = IdentitySettings{Mode: "mtls", Principals: map[string]PrincipalSettings{
		"spiffe://dbpilot.example/operators/alice": {Subject: "alice", PlatformAdmin: true},
	}}
	config.HTTPServerTLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: x509.NewCertPool()}

	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server)
	require.Equal(t, tls.RequireAndVerifyClientCert, server.httpTLS.ClientAuth)
}

func TestOIDCIdentityModeBuildsInjectedBearerResolver(t *testing.T) {
	config := validServerConfig()
	config.PrincipalResolver = nil
	config.Identity = IdentitySettings{Mode: "oidc", Issuer: "https://identity.example.com", Audience: "dbpilot-control-plane"}
	config.OIDCTokenVerifier = staticOIDCTokenVerifier{claims: controlplane.OIDCClaims{Subject: "operator", PlatformAdmin: true}}

	resolver, err := principalResolverForConfig(config)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("Authorization", "Bearer verified-token")
	principal, err := resolver.ResolvePrincipal(request)

	require.NoError(t, err)
	require.Equal(t, "operator", principal.Subject)
	require.True(t, principal.PlatformAdmin)
}

func TestOIDCIdentityModeRequiresIssuerAndAudience(t *testing.T) {
	for name, identity := range map[string]IdentitySettings{
		"missing issuer":   {Mode: "oidc", Audience: "dbpilot-control-plane"},
		"missing audience": {Mode: "oidc", Issuer: "https://identity.example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			config := validServerConfig()
			config.PrincipalResolver = nil
			config.Identity = identity
			config.OIDCTokenVerifier = staticOIDCTokenVerifier{}

			server, err := NewServer(config)

			require.Nil(t, server)
			require.ErrorContains(t, err, "OIDC")
		})
	}
}

func TestNewServerExposesNonemptyFoundationCapabilityCatalog(t *testing.T) {
	config := validServerConfig()
	server, err := NewServer(config)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-a/projects/project-a/capabilities", nil)
	response := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var body struct {
		Capabilities []struct {
			Name       string `json:"name"`
			Enabled    bool   `json:"enabled"`
			ReasonCode string `json:"reason_code"`
		} `json:"capabilities"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	require.Len(t, body.Capabilities, 5)
	seenAgent, seenCatalog := false, false
	for _, value := range body.Capabilities {
		if value.Name == "agent.control" {
			require.False(t, value.Enabled)
			require.Equal(t, "agent_unsupported", value.ReasonCode)
			seenAgent = true
		}
		if value.Name == "platform.plugin_catalog" {
			require.False(t, value.Enabled)
			require.Equal(t, "deployment_disabled", value.ReasonCode)
			seenCatalog = true
		}
	}
	require.True(t, seenAgent)
	require.True(t, seenCatalog)
}

func TestConfigStrictlyDecodesSnakeCaseEvaluationScopes(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "controlplane.yaml")
	require.NoError(t, os.WriteFile(path, []byte("evaluation_scopes:\n  - tenant_id: tenant-a\n    project_id: project-a\n"), 0o600))

	config, err := loadConfig(path)
	require.NoError(t, err)
	require.Equal(t, []EvaluationScopeSettings{{TenantID: "tenant-a", ProjectID: "project-a"}}, config.EvaluationScopes)
}

func TestNewServerWiresCoreMonitoringCapabilities(t *testing.T) {
	server, err := NewServer(validServerConfig())
	require.NoError(t, err)
	response := httptest.NewRecorder()
	server.httpServer.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-a/projects/project-a/monitoring/capabilities", nil))
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	for _, engine := range []string{"mysql", "postgres", "oracle"} {
		require.Contains(t, response.Body.String(), `"engine":"`+engine+`"`)
	}
}

func TestNewServerRegistersAgentControlBesideTelemetryIngest(t *testing.T) {
	server, err := NewServer(validServerConfig())
	require.NoError(t, err)

	services := server.grpcServer.GetServiceInfo()
	require.Contains(t, services, "dbpilot.agent.v1.TelemetryIngest")
	require.Contains(t, services, "dbpilot.agent.v1.AgentControl")
}

func TestNewServerRetainsInjectedAgentControlDependencies(t *testing.T) {
	registry := agentcontrol.NewRegistry(7)
	observer := &testCommandObserver{}
	config := validServerConfig()
	config.AgentRegistry = registry
	config.CommandObserver = observer

	server, err := NewServer(config)

	require.NoError(t, err)
	require.Same(t, registry, server.agentRegistry)
	require.Same(t, observer, server.commandObserver)
	require.Contains(t, server.grpcServer.GetServiceInfo(), "dbpilot.agent.v1.AgentControl")
}

func TestNewServerWiresDefaultCommandLifecycleToRegistryAndWorker(t *testing.T) {
	registry := agentcontrol.NewRegistry(7)
	config := validServerConfig()
	config.AgentRegistry = registry
	config.CommandObserver = nil

	server, err := NewServer(config)

	require.NoError(t, err)
	require.NotNil(t, server.commandLifecycle)
	require.Same(t, server.commandLifecycle, server.commandObserver)
	require.NotNil(t, server.dispatchCommands)
	require.NotNil(t, server.hostInventoryService)
}

func TestNewServerResolvesCommandSigningCredentialOnce(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	resolver := &recordingCommandSecretResolver{value: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded})}
	config := validServerConfig()
	config.CommandSigner = nil
	config.Command.SigningPrivateKeyRef = "env://DBPILOT_COMMAND_SIGNING_PRIVATE_KEY"
	config.SecretResolver = resolver

	server, err := NewServer(config)

	require.NoError(t, err)
	require.NotNil(t, server.commandLifecycle)
	require.Equal(t, []string{"env://DBPILOT_COMMAND_SIGNING_PRIVATE_KEY"}, resolver.references)
}

func TestNewServerWiresDurablePlatformIdempotency(t *testing.T) {
	server, err := NewServer(validServerConfig())
	require.NoError(t, err)
	require.NotNil(t, server.idempotency)
}

func TestReadinessRejectsMissingArtifactRootAndSigningKeyAtConstruction(t *testing.T) {
	t.Run("missing storage root", func(t *testing.T) {
		config := validServerConfig()
		config.ArtifactDownloadHandler = nil
		config.Artifact.StorageRoot = filepath.Join(t.TempDir(), "missing")
		config.ArtifactSecretResolver = platformdatabase.StaticSecretResolver{
			config.Artifact.SigningKeyRef: bytes.Repeat([]byte{0x42}, 32),
		}

		server, err := NewServer(config)

		require.Nil(t, server)
		require.ErrorContains(t, err, "artifact")
	})

	t.Run("missing signing key", func(t *testing.T) {
		config := validServerConfig()
		config.ArtifactSecretResolver = platformdatabase.StaticSecretResolver{}

		server, err := NewServer(config)

		require.Nil(t, server)
		require.ErrorContains(t, err, "artifact")
	})
}

func TestNewServerRejectsMissingInvalidAndDuplicateEvaluationScopes(t *testing.T) {
	for name, scopes := range map[string][]EvaluationScopeSettings{
		"missing":   nil,
		"invalid":   {{TenantID: "", ProjectID: "project-a"}},
		"duplicate": {{TenantID: "tenant-a", ProjectID: "project-a"}, {TenantID: "tenant-a", ProjectID: "project-a"}},
	} {
		t.Run(name, func(t *testing.T) {
			config := validServerConfig()
			config.EvaluationScopes = scopes
			server, err := NewServer(config)
			require.Nil(t, server)
			require.ErrorContains(t, err, "evaluation scope")
		})
	}
}

func TestReadinessWaitsForSuccessfulAllScopePassAndRecovers(t *testing.T) {
	config := validServerConfig()
	config.EvaluationScopes = []EvaluationScopeSettings{{TenantID: "tenant-a", ProjectID: "project-a"}, {TenantID: "tenant-b", ProjectID: "project-b"}}
	server, err := NewServer(config)
	require.NoError(t, err)
	require.False(t, server.ready.Load())

	failing := true
	server.evaluateScope = func(_ context.Context, scope alert.Scope, _ time.Time) (alert.EvaluationSummary, error) {
		if failing && scope.TenantID == "tenant-a" {
			return alert.EvaluationSummary{}, errors.New("tenant-a unavailable")
		}
		return alert.EvaluationSummary{}, nil
	}
	server.listEvents = func(context.Context, alert.Scope, alert.EventFilter) ([]alert.AlertEvent, error) { return nil, nil }
	err = server.evaluateAndDispatch(context.Background(), time.Now().UTC())
	require.ErrorContains(t, err, "tenant-a")
	require.False(t, server.ready.Load(), "a later successful scope must not hide an earlier failure")

	failing = false
	require.NoError(t, server.evaluateAndDispatch(context.Background(), time.Now().UTC()))
	require.True(t, server.ready.Load())
}

func TestReadinessFailsClosedWhenRuleFailureReturnsNoTopLevelError(t *testing.T) {
	config := validServerConfig()
	server, err := NewServer(config)
	require.NoError(t, err)
	server.evaluateScope = func(context.Context, alert.Scope, time.Time) (alert.EvaluationSummary, error) {
		return alert.EvaluationSummary{FailedRules: 1}, nil
	}
	server.listEvents = func(context.Context, alert.Scope, alert.EventFilter) ([]alert.AlertEvent, error) { return nil, nil }

	err = server.evaluateAndDispatch(context.Background(), time.Now().UTC())
	require.ErrorContains(t, err, "failed rules")
	require.False(t, server.ready.Load())
}

func TestEvaluateAndDispatchUsesStableCursorForEveryEvent(t *testing.T) {
	config := validServerConfig()
	server, err := NewServer(config)
	require.NoError(t, err)
	server.evaluateScope = func(context.Context, alert.Scope, time.Time) (alert.EvaluationSummary, error) {
		return alert.EvaluationSummary{}, nil
	}
	events := make([]alert.AlertEvent, 501)
	for index := range events {
		events[index] = alert.AlertEvent{ID: fmt.Sprintf("event-%04d", index)}
	}
	var filters []alert.EventFilter
	server.listEvents = func(_ context.Context, _ alert.Scope, filter alert.EventFilter) ([]alert.AlertEvent, error) {
		filters = append(filters, filter)
		start := 0
		if filter.AfterID != "" {
			for start < len(events) && events[start].ID <= filter.AfterID {
				start++
			}
		}
		end := start + filter.Limit
		if end > len(events) {
			end = len(events)
		}
		return events[start:end], nil
	}
	dispatched := 0
	server.dispatch = func(context.Context, alert.AlertEvent, alert.EventState) error {
		dispatched++
		return nil
	}

	require.NoError(t, server.evaluateAndDispatch(context.Background(), time.Now().UTC()))
	require.Equal(t, 501, dispatched)
	require.Len(t, filters, 2)
	require.True(t, filters[0].OrderByID)
	require.Equal(t, "event-0499", filters[1].AfterID)
}

func TestRunMigrationFailureOccursBeforeListeners(t *testing.T) {
	config := validServerConfig()
	want := errors.New("migration unavailable")
	listens := 0
	config.Ping = func(context.Context) error { return nil }
	config.Migrate = func(context.Context) error { return want }
	config.Listen = func(string, string) (net.Listener, error) { listens++; return newBlockingListener(), nil }
	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Run(context.Background())
	require.ErrorIs(t, err, want)
	require.Zero(t, listens)
}

func TestDefaultMigrationSequenceRunsHostBeforeInspectionAndStopsOnHostFailure(t *testing.T) {
	var order []string
	steps := defaultMigrationSteps{
		alert:      func(context.Context) error { order = append(order, "alert"); return nil },
		job:        func(context.Context) error { order = append(order, "job"); return nil },
		platform:   func(context.Context) error { order = append(order, "platform"); return nil },
		enrollment: func(context.Context) error { order = append(order, "enrollment"); return nil },
		host:       func(context.Context) error { order = append(order, "host"); return nil },
		inspection: func(context.Context) error { order = append(order, "inspection"); return nil },
	}
	migrate := composeDefaultMigrations(steps)

	require.NoError(t, migrate(context.Background()))
	require.Equal(t, []string{"alert", "job", "platform", "enrollment", "host", "inspection"}, order)

	want := errors.New("host migration failed")
	order = nil
	steps.host = func(context.Context) error { order = append(order, "host"); return want }
	migrate = composeDefaultMigrations(steps)
	require.ErrorIs(t, migrate(context.Background()), want)
	require.Equal(t, []string{"alert", "job", "platform", "enrollment", "host"}, order)
}

func TestDefaultHostMigrationFailurePreventsListenersAndReadiness(t *testing.T) {
	want := errors.New("host migration failed")
	listens := 0
	config := validServerConfig()
	config.Ping = func(context.Context) error { return nil }
	config.Migrate = composeDefaultMigrations(defaultMigrationSteps{
		alert:      func(context.Context) error { return nil },
		job:        func(context.Context) error { return nil },
		platform:   func(context.Context) error { return nil },
		enrollment: func(context.Context) error { return nil },
		host:       func(context.Context) error { return want },
		inspection: func(context.Context) error { t.Fatal("inspection migration ran after Host failure"); return nil },
	})
	config.Listen = func(string, string) (net.Listener, error) { listens++; return newBlockingListener(), nil }
	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Run(context.Background())
	require.ErrorIs(t, err, want)
	require.Zero(t, listens)
	require.False(t, server.ready.Load())
}

func TestConfigRequiresValidatedInspectionTargetMetadata(t *testing.T) {
	valid := AgentAssignment{TenantID: "tenant-a", ProjectID: "project-a", DisplayName: "Primary DB host", Host: "db-1.example", Labels: map[string]string{"role": "database"}}
	tests := map[string]AgentAssignment{
		"missing display name": {TenantID: valid.TenantID, ProjectID: valid.ProjectID, Host: valid.Host, Labels: valid.Labels},
		"missing host":         {TenantID: valid.TenantID, ProjectID: valid.ProjectID, DisplayName: valid.DisplayName, Labels: valid.Labels},
		"invalid label":        {TenantID: valid.TenantID, ProjectID: valid.ProjectID, DisplayName: valid.DisplayName, Host: valid.Host, Labels: map[string]string{"bad key": "database"}},
	}
	for name, assignment := range tests {
		t.Run(name, func(t *testing.T) {
			config := validServerConfig()
			config.Agents = map[string]AgentAssignment{"agent-1": assignment}
			server, err := NewServer(config)
			require.Nil(t, server)
			require.ErrorContains(t, err, "agent")
		})
	}
	config := validServerConfig()
	config.Agents = map[string]AgentAssignment{"agent-1": valid}
	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server.inspectionService)
	require.NotNil(t, server.inspectionWorker)
}

func TestInspectionCatalogSeedIsScopedAndIdempotent(t *testing.T) {
	store := &memoryInspectionCatalog{items: map[string]inspection.Item{}}
	now := time.Date(2026, 8, 29, 9, 0, 0, 0, time.UTC)
	scopes := []alert.Scope{{TenantID: "tenant-a", ProjectID: "project-a"}, {TenantID: "tenant-b", ProjectID: "project-b"}}
	require.NoError(t, seedInspectionCatalog(context.Background(), store, scopes, now))
	require.Len(t, store.items, len(inspection.BuiltinHostItems())*2)
	for _, item := range store.items {
		require.NotEmpty(t, item.Scope.TenantID)
		require.True(t, item.Enabled)
		require.Equal(t, now, item.CreatedAt)
		require.Equal(t, now, item.UpdatedAt)
	}
	created := store.creates
	require.NoError(t, seedInspectionCatalog(context.Background(), store, scopes, now.Add(time.Hour)))
	require.Equal(t, created, store.creates, "restart must not create a second catalog version")
}

func TestLiveInspectionTargetsReflectAuthenticatedAgentConnectivityAndCapabilities(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	configured, err := inspection.NewConfiguredTargetResolver([]inspection.HostTarget{{Scope: scope, AgentID: "agent-1", DisplayName: "Primary", Host: "db-1.example", Labels: map[string]string{"role": "database"}, Connectivity: "unknown", Capabilities: []string{}}})
	require.NoError(t, err)
	registry := &staticInspectionSessionRegistry{sessions: map[string]agentcontrol.SessionInfo{}}
	resolver := liveInspectionTargetResolver{configured: configured, registry: registry}

	offline, err := resolver.List(context.Background(), scope)
	require.NoError(t, err)
	require.Equal(t, "offline", offline[0].Connectivity)
	require.Empty(t, offline[0].Capabilities)
	require.Empty(t, offline[0].AdvertisedSources)
	require.True(t, offline[0].AgentControlHeartbeatAt.IsZero())

	registry.sessions["agent-1"] = agentcontrol.SessionInfo{AgentID: "agent-1", Capabilities: []string{"host.inspect"}}
	withoutCollectNow, err := resolver.List(context.Background(), scope)
	require.NoError(t, err)
	require.Equal(t, "online", withoutCollectNow[0].Connectivity)
	require.Empty(t, withoutCollectNow[0].AdvertisedSources)

	registry.sessions["agent-1"] = agentcontrol.SessionInfo{AgentID: "agent-1", Capabilities: []string{"collect_now", "host.inspect"}}
	rollingOld, err := resolver.List(context.Background(), scope)
	require.NoError(t, err)
	require.Equal(t, "online", rollingOld[0].Connectivity)
	require.Equal(t, []string{"collect_now", "host.inspect"}, rollingOld[0].Capabilities)
	require.Empty(t, rollingOld[0].AdvertisedSources, "generic rolling Agent capability must not overclaim host sources")

	heartbeatAt := time.Date(2026, 8, 29, 10, 1, 0, 0, time.UTC)
	registry.sessions["agent-1"] = agentcontrol.SessionInfo{AgentID: "agent-1", Capabilities: []string{"collect_now", "collect_now.host.v1", "host.inspect"}, LastHeartbeat: heartbeatAt}
	online, err := resolver.List(context.Background(), scope)
	require.NoError(t, err)
	require.Equal(t, []inspection.SourceType{inspection.SourceMetric, inspection.SourceMetadata, inspection.SourceLogSummary}, online[0].AdvertisedSources)
	require.Equal(t, heartbeatAt, online[0].AgentControlHeartbeatAt)
}

func TestLiveInspectionResolverCreateRunEvaluatorKeepsCollectNowSources(t *testing.T) {
	scope := platformscope.Scope{TenantID: "tenant-a", ProjectID: "project-a"}
	now := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	configured, err := inspection.NewConfiguredTargetResolver([]inspection.HostTarget{{Scope: scope, AgentID: "agent-1", DisplayName: "Primary", Host: "db-1.example", Labels: map[string]string{"role": "database"}, Connectivity: "unknown", Capabilities: []string{}}})
	require.NoError(t, err)
	registry := &staticInspectionSessionRegistry{sessions: map[string]agentcontrol.SessionInfo{"agent-1": {AgentID: "agent-1", Capabilities: []string{"collect_now", "collect_now.host.v1"}}}}
	resolver := liveInspectionTargetResolver{configured: configured, registry: registry}
	selected := make([]inspection.Item, 0, 3)
	for _, item := range inspection.BuiltinHostItems() {
		if item.ID == "host.cpu.utilization" || item.ID == "host.oom.evidence" || item.ID == "host.log.error_summary" {
			item.Scope, item.Enabled, item.CreatedAt, item.UpdatedAt = scope, true, now, now
			selected = append(selected, item)
		}
	}
	require.Len(t, selected, 3)
	repository := &inspectionWorkflowRepository{items: selected}
	ids := []string{"run-1", "job-1", "command-1"}
	service := &inspection.Service{Repository: repository, Targets: resolver, Now: func() time.Time { return now }, NewID: func() (string, error) { id := ids[0]; ids = ids[1:]; return id, nil }}
	versions := make([]inspection.PolicyItem, len(selected))
	for index, item := range selected {
		versions[index] = inspection.PolicyItem{ItemID: item.ID, Version: item.Version}
	}
	run, err := service.CreateRun(context.Background(), inspection.CreateRunRequest{Scope: scope, Selector: inspection.TargetSelector{AgentIDs: []string{"agent-1"}}, Items: versions, TargetTimeout: time.Minute, MaxConcurrency: 1, IdempotencyKey: "run-key", InitiatedBy: "operator", RequestID: "request-1", Trigger: inspection.RunTriggerManual})
	require.NoError(t, err)
	require.Equal(t, []inspection.SourceType{inspection.SourceMetric, inspection.SourceMetadata, inspection.SourceLogSummary}, repository.targets[0].AdvertisedSources)

	observedAt := now.Add(-time.Minute)
	target := repository.targets[0]
	target.Observations = []inspection.Observation{
		{ID: "oom-1", TargetID: target.TargetID, Name: "dbpilot.inspection.host.oom.count", SourceType: inspection.SourceMetadata, Labels: map[string]string{}, Value: 0, ObservedAt: observedAt},
		{ID: "warn-1", TargetID: target.TargetID, Name: "dbpilot.inspection.host.log.warning_count", SourceType: inspection.SourceLogSummary, Labels: map[string]string{}, Value: 0, ObservedAt: observedAt},
		{ID: "error-1", TargetID: target.TargetID, Name: "dbpilot.inspection.host.log.error_count", SourceType: inspection.SourceLogSummary, Labels: map[string]string{}, Value: 0, ObservedAt: observedAt},
		{ID: "critical-1", TargetID: target.TargetID, Name: "dbpilot.inspection.host.log.critical_count", SourceType: inspection.SourceLogSummary, Labels: map[string]string{}, Value: 0, ObservedAt: observedAt},
	}
	evaluator := &inspection.Evaluator{
		Evidence: inspectionEvidenceStore{samples: []inspection.Observation{{ID: "cpu-1", TargetID: target.TargetID, Name: "system.cpu.utilization", SourceType: inspection.SourceMetric, Labels: map[string]string{}, Value: 20, ObservedAt: now}}},
		Now:      func() time.Time { return now },
	}
	findings, err := evaluator.EvaluateTarget(context.Background(), inspection.RunSnapshot{ID: run.ID, Scope: scope, CreatedAt: run.CreatedAt, Items: run.ItemSnapshot, Targets: []inspection.TargetRun{target}}, target)
	require.NoError(t, err)
	require.Len(t, findings, 3)
	for _, finding := range findings {
		require.NotEqual(t, inspection.LevelUnsupported, finding.Level, finding.ItemID)
		require.NotEqual(t, inspection.LevelMissingData, finding.Level, finding.ItemID)
	}
}

type staticInspectionSessionRegistry struct {
	sessions map[string]agentcontrol.SessionInfo
}

func TestRuntimeAgentResolverAcceptsPersistedEnrollmentAndFallsBackToLegacyConfiguration(t *testing.T) {
	persisted := platformscope.Scope{TenantID: "tenant-enrolled", ProjectID: "project-enrolled"}
	resolver := runtimeAgentResolver{
		configured: configuredAgentResolver{"legacy-agent": {TenantID: "tenant-legacy", ProjectID: "project-legacy"}, "decommissioned-agent": {TenantID: "tenant-legacy", ProjectID: "project-legacy"}},
		enrolled: fixedEnrolledAgentScopes{
			scopes: map[string]platformscope.Scope{"dynamic-agent": persisted},
			errors: map[string]error{"decommissioned-agent": hostinventory.ErrDecommissioned},
		},
	}

	scope, err := resolver.ScopeForAgent(context.Background(), "dynamic-agent")
	require.NoError(t, err)
	require.Equal(t, alert.Scope{TenantID: persisted.TenantID, ProjectID: persisted.ProjectID}, scope)
	require.True(t, resolver.KnownAgent(context.Background(), "dynamic-agent"))
	legacy, err := resolver.ScopeForAgent(context.Background(), "legacy-agent")
	require.NoError(t, err)
	require.Equal(t, alert.Scope{TenantID: "tenant-legacy", ProjectID: "project-legacy"}, legacy)
	require.False(t, resolver.KnownAgent(context.Background(), "unknown-agent"))
	_, err = resolver.ScopeForAgent(context.Background(), "decommissioned-agent")
	require.ErrorIs(t, err, hostinventory.ErrDecommissioned, "static fallback must not resurrect a decommissioned enrollment")
	require.False(t, resolver.KnownAgent(context.Background(), "decommissioned-agent"))
}

type fixedEnrolledAgentScopes struct {
	scopes map[string]platformscope.Scope
	errors map[string]error
}

func (resolver fixedEnrolledAgentScopes) ScopeForAgent(_ context.Context, agentID string) (platformscope.Scope, error) {
	if err := resolver.errors[agentID]; err != nil {
		return platformscope.Scope{}, err
	}
	if scope, ok := resolver.scopes[agentID]; ok {
		return scope, nil
	}
	return platformscope.Scope{}, hostinventory.ErrNotFound
}

func (registry *staticInspectionSessionRegistry) Session(agentID string) (agentcontrol.SessionInfo, bool) {
	value, ok := registry.sessions[agentID]
	return value, ok
}

type inspectionEvidenceStore struct{ samples []inspection.Observation }

func (store inspectionEvidenceStore) Samples(context.Context, platformscope.Scope, string, []string, time.Time, time.Time, int) ([]inspection.Observation, error) {
	return append([]inspection.Observation(nil), store.samples...), nil
}

type inspectionWorkflowRepository struct {
	items   []inspection.Item
	targets []inspection.TargetRun
}

func (*inspectionWorkflowRepository) CreateItem(context.Context, inspection.Item) error { return nil }
func (repository *inspectionWorkflowRepository) ListItems(_ context.Context, _ platformscope.Scope, filter inspection.ItemFilter) (inspection.ItemPage, error) {
	wanted := map[string]struct{}{}
	for _, version := range filter.Versions {
		wanted[fmt.Sprintf("%s:%d", version.ItemID, version.Version)] = struct{}{}
	}
	page := inspection.ItemPage{}
	for _, item := range repository.items {
		if _, ok := wanted[fmt.Sprintf("%s:%d", item.ID, item.Version)]; ok {
			page.Items = append(page.Items, item)
		}
	}
	return page, nil
}
func (*inspectionWorkflowRepository) CreatePolicy(context.Context, inspection.Policy) error {
	return nil
}
func (*inspectionWorkflowRepository) ListPolicies(context.Context, platformscope.Scope, inspection.PolicyFilter) (inspection.PolicyPage, error) {
	return inspection.PolicyPage{}, nil
}
func (*inspectionWorkflowRepository) GetPolicy(context.Context, platformscope.Scope, string) (inspection.Policy, error) {
	return inspection.Policy{}, inspection.ErrNotFound
}
func (*inspectionWorkflowRepository) UpdatePolicy(context.Context, inspection.Policy, int64) (inspection.Policy, error) {
	return inspection.Policy{}, inspection.ErrNotFound
}
func (*inspectionWorkflowRepository) ClaimDuePolicies(context.Context, time.Time, int, time.Duration) ([]inspection.Policy, error) {
	return nil, nil
}
func (repository *inspectionWorkflowRepository) CreateRunWithJob(_ context.Context, _ inspection.Run, targets []inspection.TargetRun, _ job.Job, _ []job.OutboxMessage) error {
	repository.targets = append([]inspection.TargetRun(nil), targets...)
	return nil
}
func (*inspectionWorkflowRepository) CreateClaimedRunWithJob(context.Context, inspection.Policy, inspection.Run, []inspection.TargetRun, job.Job, []job.OutboxMessage) (inspection.Run, error) {
	return inspection.Run{}, nil
}
func (*inspectionWorkflowRepository) GetRun(context.Context, platformscope.Scope, string) (inspection.RunDetail, error) {
	return inspection.RunDetail{}, inspection.ErrNotFound
}
func (*inspectionWorkflowRepository) GetRunByIdempotency(context.Context, platformscope.Scope, inspection.RunIdempotency) (inspection.Run, error) {
	return inspection.Run{}, inspection.ErrNotFound
}
func (*inspectionWorkflowRepository) ListRuns(context.Context, platformscope.Scope, inspection.RunFilter) (inspection.RunPage, error) {
	return inspection.RunPage{}, nil
}
func (*inspectionWorkflowRepository) GetReport(context.Context, platformscope.Scope, string) (inspection.ReportSnapshot, error) {
	return inspection.ReportSnapshot{}, inspection.ErrNotFound
}
func (*inspectionWorkflowRepository) ListReports(context.Context, platformscope.Scope, inspection.ReportFilter) (inspection.ReportPage, error) {
	return inspection.ReportPage{}, nil
}

type memoryInspectionCatalog struct {
	items   map[string]inspection.Item
	creates int
}

func (store *memoryInspectionCatalog) CreateItem(_ context.Context, value inspection.Item) error {
	store.creates++
	store.items[value.Scope.Key()+"\x00"+value.ID] = value
	return nil
}
func (store *memoryInspectionCatalog) ListItems(_ context.Context, scope platformscope.Scope, filter inspection.ItemFilter) (inspection.ItemPage, error) {
	result := inspection.ItemPage{}
	for _, requested := range filter.Versions {
		if value, ok := store.items[scope.Key()+"\x00"+requested.ItemID]; ok && value.Version == requested.Version {
			result.Items = append(result.Items, value)
		}
	}
	return result, nil
}

func TestRunCanceledContextReturnsWithoutMigrationOrListeners(t *testing.T) {
	config := validServerConfig()
	migrations, listens := 0, 0
	config.Ping = func(context.Context) error { return nil }
	config.Migrate = func(context.Context) error { migrations++; return nil }
	config.Listen = func(string, string) (net.Listener, error) { listens++; return newBlockingListener(), nil }
	server, err := NewServer(config)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = server.Run(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, migrations)
	require.Zero(t, listens)
}

func TestRunCanceledContextClosesRetainedArtifactRoot(t *testing.T) {
	config := validServerConfig()
	config.ArtifactDownloadHandler = nil
	config.Artifact.StorageRoot = t.TempDir()
	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server.artifactBlobs)
	root := server.artifactBlobs
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = server.Run(ctx)

	require.ErrorIs(t, err, context.Canceled)
	_, err = root.Open(context.Background(), artifact.Artifact{StorageReference: "missing.bin"})
	require.ErrorIs(t, err, artifact.ErrInvalid)
}

func TestRunClosesFirstListenerWhenSecondBindFails(t *testing.T) {
	config := validServerConfig()
	first := newBlockingListener()
	want := errors.New("grpc bind failed")
	calls := 0
	config.Ping = func(context.Context) error { return nil }
	config.Migrate = func(context.Context) error { return nil }
	config.Listen = func(string, string) (net.Listener, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return nil, want
	}
	server, err := NewServer(config)
	require.NoError(t, err)

	err = server.Run(context.Background())
	require.ErrorIs(t, err, want)
	require.True(t, first.isClosed())
}

func TestRunCancellationStopsBothListeners(t *testing.T) {
	config := validServerConfig()
	listeners := []*blockingListener{newBlockingListener(), newBlockingListener()}
	next := 0
	config.Ping = func(context.Context) error { return nil }
	config.Migrate = func(context.Context) error { return nil }
	config.Listen = func(string, string) (net.Listener, error) { listener := listeners[next]; next++; return listener, nil }
	server, err := NewServer(config)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	require.Eventually(t, func() bool { return next == 2 }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.True(t, listeners[0].isClosed())
	require.True(t, listeners[1].isClosed())
}

func TestEnrollmentUsesSeparateTLSOnlyListenerAndOwnedHostDispatcher(t *testing.T) {
	config := validServerConfig()
	config.Enrollment = EnrollmentSettings{Listener: ListenerConfig{Address: "127.0.0.1:10443"}}
	config.EnrollmentServerTLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool()}
	config.EnrollmentService = &enrollment.ApplicationService{}
	config.HostObservationSink = &recordingHostObservationSink{}
	server, err := NewServer(config)
	require.NoError(t, err)
	require.NotNil(t, server.enrollmentGRPCServer)
	require.NotSame(t, server.grpcServer, server.enrollmentGRPCServer)
	require.Equal(t, tls.NoClientCert, server.enrollmentTLS.ClientAuth, "enrollment accepts unauthenticated Agents only on its server-auth listener")
	require.Nil(t, server.enrollmentTLS.ClientCAs)
	require.Equal(t, tls.RequireAndVerifyClientCert, server.grpcTLS.ClientAuth, "AgentControl remains mTLS-only")
	require.NotNil(t, server.hostObservations)
}

func TestRunCancellationStopsEnrollmentListenerAndClosesHostDispatcher(t *testing.T) {
	config := validServerConfig()
	config.Enrollment = EnrollmentSettings{Listener: ListenerConfig{Address: "127.0.0.1:10443"}}
	config.EnrollmentServerTLS = &tls.Config{MinVersion: tls.VersionTLS12}
	config.EnrollmentService = &enrollment.ApplicationService{}
	config.HostObservationSink = &recordingHostObservationSink{}
	listeners := []*blockingListener{newBlockingListener(), newBlockingListener(), newBlockingListener()}
	next := 0
	config.Ping = func(context.Context) error { return nil }
	config.Migrate = func(context.Context) error { return nil }
	config.Listen = func(string, string) (net.Listener, error) { listener := listeners[next]; next++; return listener, nil }
	server, err := NewServer(config)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	require.Eventually(t, func() bool { return next == 3 }, time.Second, time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	for _, listener := range listeners {
		require.True(t, listener.isClosed())
	}
	require.ErrorIs(t, server.hostObservations.SubmitHeartbeat("agent-1", time.Now().UTC()), agentcontrol.ErrHostObservationClosed)
}

func TestRunCancellationWaitsForWorkersToExit(t *testing.T) {
	config := validServerConfig()
	listeners := []*blockingListener{newBlockingListener(), newBlockingListener()}
	next := 0
	config.Ping = func(context.Context) error { return nil }
	config.Migrate = func(context.Context) error { return nil }
	config.Listen = func(string, string) (net.Listener, error) { listener := listeners[next]; next++; return listener, nil }
	server, err := NewServer(config)
	require.NoError(t, err)
	started := make(chan struct{})
	exited := make(chan struct{})
	server.evaluateScope = func(ctx context.Context, _ alert.Scope, _ time.Time) (alert.EvaluationSummary, error) {
		close(started)
		<-ctx.Done()
		close(exited)
		return alert.EvaluationSummary{}, ctx.Err()
	}
	server.retryDue = func(context.Context, time.Time) error { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	<-started
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	select {
	case <-exited:
	default:
		t.Fatal("Run returned before evaluator worker exited")
	}
}

func TestRunCancellationWaitsForInspectionSchedulerAndWorker(t *testing.T) {
	config := validServerConfig()
	listeners := []*blockingListener{newBlockingListener(), newBlockingListener()}
	next := 0
	config.Ping = func(context.Context) error { return nil }
	config.Migrate = func(context.Context) error { return nil }
	config.Listen = func(string, string) (net.Listener, error) { listener := listeners[next]; next++; return listener, nil }
	server, err := NewServer(config)
	require.NoError(t, err)
	started := make(chan string, 2)
	exited := make(chan string, 2)
	server.scheduleInspections = func(ctx context.Context, _ time.Time) error {
		started <- "scheduler"
		<-ctx.Done()
		exited <- "scheduler"
		return ctx.Err()
	}
	server.processInspections = func(ctx context.Context, _ time.Time) error {
		started <- "worker"
		<-ctx.Done()
		exited <- "worker"
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	require.ElementsMatch(t, []string{"scheduler", "worker"}, []string{<-started, <-started})
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	require.ElementsMatch(t, []string{"scheduler", "worker"}, []string{<-exited, <-exited})
}

func validServerConfig() Config {
	return Config{
		DatabaseURL:             "postgres://dbpilot:password@localhost/dbpilot?sslmode=require",
		WebhookAllowlist:        []string{"hooks.example.com"},
		EventURLBase:            "https://control.example",
		HTTP:                    ListenerConfig{Address: "127.0.0.1:8443", TLS: TLSMaterial{CertFile: "unused", KeyFile: "unused"}},
		GRPC:                    ListenerConfig{Address: "127.0.0.1:9443", TLS: TLSMaterial{CertFile: "unused", KeyFile: "unused", ClientCAFile: "unused"}},
		HTTPServerTLS:           &tls.Config{MinVersion: tls.VersionTLS12},
		GRPCServerTLS:           &tls.Config{MinVersion: tls.VersionTLS12},
		PrincipalResolver:       trustedTestPrincipalResolver{},
		EvaluationScopes:        []EvaluationScopeSettings{{TenantID: "tenant-a", ProjectID: "project-a"}},
		CommandSigner:           testCommandSigner{},
		CommandTokenProtector:   testCommandTokenProtector{},
		Artifact:                ArtifactSettings{SigningKeyRef: "secret://controlplane/artifact-download"},
		ArtifactSecretResolver:  platformdatabase.StaticSecretResolver{"secret://controlplane/artifact-download": bytes.Repeat([]byte{0x42}, 32)},
		ArtifactDownloadHandler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	}
}

type trustedTestPrincipalResolver struct{}

func (trustedTestPrincipalResolver) ResolvePrincipal(*http.Request) (controlplane.Principal, error) {
	return controlplane.Principal{Subject: "trusted-test", PlatformAdmin: true}, nil
}

type staticOIDCTokenVerifier struct {
	claims controlplane.OIDCClaims
	err    error
}

func (verifier staticOIDCTokenVerifier) Verify(context.Context, string) (json.RawMessage, error) {
	if verifier.err != nil {
		return nil, verifier.err
	}
	return json.Marshal(verifier.claims)
}

type testCommandObserver struct{}

type recordingHostObservationSink struct{}

func (*recordingHostObservationSink) RecordObservation(context.Context, string, *agentv1.HostObservation) error {
	return nil
}
func (*recordingHostObservationSink) RecordHello(context.Context, string, time.Time) error {
	return nil
}
func (*recordingHostObservationSink) RecordHeartbeat(context.Context, string, time.Time) error {
	return nil
}

func (*testCommandObserver) Connected(context.Context, agentcontrol.SessionInfo)                   {}
func (*testCommandObserver) Heartbeat(context.Context, string, *agentv1.Heartbeat)                 {}
func (*testCommandObserver) Acknowledged(context.Context, string, *agentv1.CommandAcknowledgement) {}
func (*testCommandObserver) Progress(context.Context, string, *agentv1.CommandProgress)            {}
func (*testCommandObserver) Result(_ context.Context, _ string, result *agentv1.CommandResult) (agentcontrol.ResultPersistence, error) {
	return agentcontrol.ResultPersistence{CommandID: result.GetCommandId(), Persisted: true}, nil
}

type testCommandSigner struct{}

func (testCommandSigner) Sign(_ context.Context, envelope *agentv1.CommandEnvelope) error {
	envelope.Signature = bytes.Repeat([]byte{0x42}, ed25519.SignatureSize)
	return nil
}

type testCommandTokenProtector struct{}

func (testCommandTokenProtector) Protect(_ context.Context, token []byte) ([]byte, error) {
	return append([]byte("test:"), token...), nil
}

func (testCommandTokenProtector) Unprotect(_ context.Context, ciphertext []byte) ([]byte, error) {
	if !bytes.HasPrefix(ciphertext, []byte("test:")) {
		return nil, job.ErrInvalidCommandPayload
	}
	return append([]byte(nil), ciphertext[len("test:"):]...), nil
}

type recordingCommandSecretResolver struct {
	value      []byte
	references []string
}

func (resolver *recordingCommandSecretResolver) Resolve(_ context.Context, reference string) ([]byte, error) {
	resolver.references = append(resolver.references, reference)
	return append([]byte(nil), resolver.value...), nil
}

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingListener() *blockingListener { return &blockingListener{closed: make(chan struct{})} }
func (listener *blockingListener) Accept() (net.Conn, error) {
	<-listener.closed
	return nil, net.ErrClosed
}
func (listener *blockingListener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}
func (*blockingListener) Addr() net.Addr { return testAddress("test") }
func (listener *blockingListener) isClosed() bool {
	select {
	case <-listener.closed:
		return true
	default:
		return false
	}
}

type testAddress string

func (address testAddress) Network() string { return "tcp" }
func (address testAddress) String() string  { return string(address) }
