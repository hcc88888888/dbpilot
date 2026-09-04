package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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
	"dbpilot.local/platform/internal/metrictemplate"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"dbpilot.local/platform/internal/plugincatalog"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestProductionMySQLMetricTemplateDialectRejectsUnsafeStatements(t *testing.T) {
	validator := mysqlMetricTemplateDialect{}
	definition := metrictemplate.TemplateDefinition{DatabaseFamily: "mysql", Variants: []string{"mysql"}, Name: "acceptance", QueryKind: metrictemplate.QuerySQL, ReadOnlyStatement: "SELECT 1 AS value", CollectionIntervalSeconds: 10, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, ValueMappings: []metrictemplate.ValueMapping{{SourceColumn: "value", MetricName: "mysql.acceptance.value", MetricType: metrictemplate.MetricGauge, Unit: "1"}}, CardinalityLimit: 10}
	validated, err := validator.ValidateReadOnly(context.Background(), definition)
	require.NoError(t, err)
	require.Empty(t, validated.ReadOnlyStatement)
	for _, statement := range []string{"DELETE FROM mysql.user", "SELECT 1; SELECT 2", "SELECT SLEEP(1)"} {
		unsafe := definition
		unsafe.ReadOnlyStatement = statement
		_, err := validator.ValidateReadOnly(context.Background(), unsafe)
		require.Error(t, err, statement)
	}
}

func TestLivePluginArtifactAuthorizerAcceptsCanonicalCatalogArtifactProvenance(t *testing.T) {
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	digest := strings.Repeat("a", 64)
	manifest := strings.Repeat("b", 64)
	assignment := pluginassignment.Assignment{
		ID: "assignment-1", Scope: scope, HostID: "host-1", AgentID: "agent-1", PluginID: "mysql", DatabaseFamily: "mysql",
		DesiredVersionID: "plugin-version-1", DesiredVersion: "1.0.0", ArtifactID: "plugin-package-1", ArtifactSHA256: digest, ManifestDigest: manifest,
		DesiredState: pluginassignment.DesiredRunning, ConfigurationRevision: 1, OperationRevision: 1, RolloutPercentage: 100,
		InstanceIDs: []string{"dbi-1"}, TemplateRevisionIDs: []string{}, ReconcileState: pluginassignment.ReconcilePending, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	version := plugincatalog.PluginVersion{
		ID: assignment.DesiredVersionID, Scope: scope, PluginID: assignment.PluginID, Version: assignment.DesiredVersion, Status: plugincatalog.StatusAvailable,
		ArtifactID: assignment.ArtifactID, PackageSHA256: digest, ManifestDigest: manifest, PublisherID: "publisher-1", SigningKeyID: "key-1",
		ProtocolVersion: "v1", MinimumAgentProtocolVersion: "v1", MaximumAgentProtocolVersion: "v1", SupportedVariants: []string{"mysql"},
		DatabaseVersionRange: ">=8 <9", Capabilities: []string{"metrics.collect"}, MetricTemplateSchemaVersion: 1,
		Platforms: []plugincatalog.Platform{{OperatingSystem: "linux", Architecture: "amd64", SHA256: digest, SizeBytes: 1}}, Revision: 1, CreatedAt: now,
	}
	stored := artifact.Artifact{
		ID: assignment.ArtifactID, Scope: scope, Kind: "plugin-package", ContentType: "application/gzip", SizeBytes: 1,
		Checksum: "sha256:" + digest, SourceResource: artifact.ResourceReference{ResourceType: "plugin_catalog_operation", ResourceID: "plugin-operation-" + strings.Repeat("c", 32)},
		CreatedAt: now, StorageReference: "sha256/" + digest + ".blob",
	}
	authorizer := livePluginArtifactAuthorizer{
		AgentScopes: fixedEnrolledAgentScopes{scopes: map[string]platformscope.Scope{"agent-1": scope}},
		Assignments: staticPluginArtifactAssignmentReader{value: assignment}, Versions: staticPluginArtifactVersionReader{value: version},
		Artifacts: staticPluginArtifactMetadataReader{value: stored}, ExecutionFences: alwaysActivePluginArtifactFence{}, Now: func() time.Time { return now },
	}

	grant, err := authorizer.AuthorizePluginArtifact(context.Background(), assignment.AgentID, assignment.ID, assignment.ArtifactID, assignment.OperationRevision)

	require.NoError(t, err)
	require.Equal(t, stored, grant.Artifact)
}

type staticPluginArtifactAssignmentReader struct{ value pluginassignment.Assignment }

func (reader staticPluginArtifactAssignmentReader) Get(context.Context, platformscope.Scope, string) (pluginassignment.Assignment, error) {
	return reader.value, nil
}

type staticPluginArtifactVersionReader struct{ value plugincatalog.PluginVersion }

func (reader staticPluginArtifactVersionReader) ListVersions(context.Context, platformscope.Scope, plugincatalog.VersionFilter) (plugincatalog.VersionPage, error) {
	return plugincatalog.VersionPage{Items: []plugincatalog.PluginVersion{reader.value}}, nil
}

type staticPluginArtifactMetadataReader struct{ value artifact.Artifact }

func (reader staticPluginArtifactMetadataReader) Get(context.Context, platformscope.Scope, string) (artifact.Artifact, error) {
	return reader.value, nil
}

type alwaysActivePluginArtifactFence struct{}

func (alwaysActivePluginArtifactFence) ExecutionLeaseActive(string, string, time.Time) bool {
	return true
}

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

func TestGenerationZeroImportWindowIsExplicitAndPreflightValidated(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "controlplane.yaml.example"))
	require.NoError(t, err)
	configured := strings.Replace(string(contents), "  observation_delivery_timeout: 5s", `  observation_delivery_timeout: 5s
  generation_zero_import:
    enabled: true
    targets:
      spiffe-agent-id:
        tenant_id: tenant-1
        project_id: project-1
        host_id: host-legacy-1`, 1)
	path := filepath.Join(t.TempDir(), "controlplane.yaml")
	require.NoError(t, os.WriteFile(path, []byte(configured), 0o600))

	config, err := loadConfig(path)
	require.NoError(t, err)
	require.NoError(t, validateConfig(config))
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
	config.Artifact.PluginLeaseOrigin = "https://control.example"
	require.ErrorContains(t, validateConfig(config), "publisher")

	config.PluginPublishers = []PluginPublisherSettings{{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: base64.StdEncoding.EncodeToString(public)}}
	config.Artifact.PluginLeaseOrigin = ""
	require.ErrorContains(t, validateConfig(config), "plugin_lease_origin")
	config.Artifact.PluginLeaseOrigin = "https://control.example"
	require.NoError(t, validateConfig(config))
	config.Artifact.StorageRoot = ""
	require.ErrorContains(t, validateConfig(config), "storage_root")

	disabled := validServerConfig()
	disabled.PluginCatalog.Enabled = false
	require.NoError(t, validateConfig(disabled))
}

func TestCheckConfigCatchesLegacyCatalogOriginBeforeServerStartup(t *testing.T) {
	public := ed25519.PublicKey(bytes.Repeat([]byte{0x42}, ed25519.PublicKeySize))
	config := validServerConfig()
	config.PluginCatalog.Enabled = true
	config.Artifact.StorageRoot = t.TempDir()
	config.Artifact.PluginLeaseOrigin = ""
	config.Command = CommandSettings{SigningPrivateKeyRef: "env://DBPILOT_COMMAND_SIGNING_PRIVATE_KEY", ExecutionTokenKeyRef: "env://DBPILOT_COMMAND_EXECUTION_TOKEN_KEY"}
	config.Identity = IdentitySettings{Mode: "oidc", Issuer: "https://issuer.example", Audience: "dbpilot"}
	config.PluginPublishers = []PluginPublisherSettings{{PublisherID: "publisher-1", KeyID: "key-1", PublicKey: base64.StdEncoding.EncodeToString(public)}}
	path := filepath.Join(t.TempDir(), "controlplane.yaml")
	write := func() {
		body, err := yaml.Marshal(config)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, body, 0o600))
	}
	write()
	var stdout, stderr bytes.Buffer
	require.Equal(t, 2, run([]string{"--config", path, "--check-config"}, &stdout, &stderr))
	require.Contains(t, stderr.String(), "plugin_lease_origin")
	require.Empty(t, stdout.String())

	config.Artifact.PluginLeaseOrigin = "https://control.example"
	write()
	stdout.Reset()
	stderr.Reset()
	require.Equal(t, 0, run([]string{"--config", path, "--check-config"}, &stdout, &stderr))
	require.Equal(t, "configuration valid\n", stdout.String())
	require.Empty(t, stderr.String())
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
	config.Artifact.PluginLeaseOrigin = "https://control.example"
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
	require.True(t, server.commandLifecycle.HasTargetAuthorizer(), "default plugin commands must retain the resolved database-backed target authorizer through dispatch")
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
	require.False(t, server.ready.Load())
}

func TestRunGenerationZeroImportPreflightOccursAfterMigrationsBeforeListeners(t *testing.T) {
	config := validServerConfig()
	migrations, listens := 0, 0
	config.Ping = func(context.Context) error { return nil }
	config.Migrate = func(context.Context) error { migrations++; return nil }
	config.Listen = func(string, string) (net.Listener, error) { listens++; return newBlockingListener(), nil }
	server, err := NewServer(config)
	require.NoError(t, err)
	server.importPreflight = func(context.Context) error { return errors.New("legacy host mismatch") }

	err = server.Run(context.Background())

	require.EqualError(t, err, "generation-zero credential import preflight failed")
	require.Equal(t, 1, migrations)
	require.Zero(t, listens)
}

func TestGenerationZeroImportConfigRejectsDormantOrUnscopedWindows(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"dormant targets": func(config *Config) {
			config.Enrollment.GenerationZeroImport.Targets = map[string]GenerationZeroImportTargetSettings{"agent-a": {TenantID: "tenant-a", ProjectID: "project-a", HostID: "host-a"}}
		},
		"empty enabled window": func(config *Config) {
			config.Enrollment.GenerationZeroImport.Enabled = true
		},
		"scope mismatch": func(config *Config) {
			config.Enrollment.GenerationZeroImport = GenerationZeroImportSettings{Enabled: true, Targets: map[string]GenerationZeroImportTargetSettings{"agent-a": {TenantID: "tenant-other", ProjectID: "project-a", HostID: "host-a"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			config := validServerConfig()
			mutate(&config)
			require.ErrorContains(t, validateConfig(config), "generation-zero")
		})
	}
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

func TestEnrollmentAndAgentControlTLSPerformRealDistinctHandshakes(t *testing.T) {
	now := time.Now().UTC()
	serverCA, serverCAKey, serverPool := testTLSAuthority(t, "server-ca", now)
	serverCertificate := testTLSServerCertificate(t, serverCA, serverCAKey, now)
	agentCA, agentCAKey, agentPool := testTLSAuthority(t, "agent-ca", now)
	agentCertificate := testTLSClientCertificate(t, agentCA, agentCAKey, "agent-1", now)
	otherCA, otherCAKey, _ := testTLSAuthority(t, "other-ca", now)
	wrongCertificate := testTLSClientCertificate(t, otherCA, otherCAKey, "agent-1", now)
	config := validServerConfig()
	config.Enrollment = EnrollmentSettings{Listener: ListenerConfig{Address: "127.0.0.1:10443"}}
	config.EnrollmentServerTLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12}
	config.GRPCServerTLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, ClientCAs: agentPool, MinVersion: tls.VersionTLS12}
	config.EnrollmentService = &enrollment.ApplicationService{}
	server, err := NewServer(config)
	require.NoError(t, err)

	require.NoError(t, performTLSHandshake(server.enrollmentTLS, &tls.Config{RootCAs: serverPool, ServerName: "localhost", MinVersion: tls.VersionTLS12}))
	require.Error(t, performTLSHandshake(server.grpcTLS, &tls.Config{RootCAs: serverPool, ServerName: "localhost", MinVersion: tls.VersionTLS12}), "AgentControl must reject a client without mTLS")
	require.Error(t, performTLSHandshake(server.grpcTLS, &tls.Config{RootCAs: serverPool, ServerName: "localhost", Certificates: []tls.Certificate{wrongCertificate}, MinVersion: tls.VersionTLS12}))
	require.NoError(t, performTLSHandshake(server.grpcTLS, &tls.Config{RootCAs: serverPool, ServerName: "localhost", Certificates: []tls.Certificate{agentCertificate}, MinVersion: tls.VersionTLS12}))
}

func TestNewServerRejectsEnrollmentCAOutsideAgentControlTrust(t *testing.T) {
	now := time.Now().UTC()
	agentCA, agentCAKey, agentRoots := testTLSAuthority(t, "agent-ca", now)
	_, _, wrongRoots := testTLSAuthority(t, "wrong-agent-ca", now)
	directory := t.TempDir()
	caPath := filepath.Join(directory, "agent-ca.pem")
	keyPath := filepath.Join(directory, "agent-ca-key.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: agentCA.Raw}), 0o600))
	keyDER, err := x509.MarshalPKCS8PrivateKey(agentCAKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600))
	config := validServerConfig()
	config.Enrollment = EnrollmentSettings{
		Listener: ListenerConfig{Address: "127.0.0.1:10443"}, AgentCA: TLSMaterial{CertFile: caPath, KeyFile: keyPath}, CertificateLifetime: time.Hour,
	}
	config.EnrollmentServerTLS = &tls.Config{MinVersion: tls.VersionTLS12}
	config.GRPCServerTLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientCAs: wrongRoots}

	server, err := NewServer(config)
	require.Nil(t, server)
	require.ErrorContains(t, err, "not trusted by AgentControl")

	config.GRPCServerTLS.ClientCAs = agentRoots
	server, err = NewServer(config)
	require.NoError(t, err)
	server.closeResources()
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

func TestNewServerFailsClosedWhenCredentialLeasingEnabledWithoutProvider(t *testing.T) {
	config := validServerConfig()
	config.CredentialLeases.Enabled = true
	config.CredentialLeaseProvider = nil
	server, err := NewServer(config)
	require.Error(t, err)
	require.Nil(t, server)
	require.Contains(t, err.Error(), "credential lease provider")
}

func TestCredentialLeaseProviderForConfigUsesOnlyExplicitEnvironmentBindings(t *testing.T) {
	t.Setenv("DBPILOT_DB_ONE", "operator-runtime-secret")
	config := Config{CredentialLeases: CredentialLeaseSettings{Enabled: true, Environment: map[string]CredentialLeaseEnvironmentBinding{"secret://database/one": {Username: "monitor", Variable: "DBPILOT_DB_ONE", Revision: 4}}}}
	provider, err := credentialLeaseProviderForConfig(config)
	require.NoError(t, err)
	credential, err := provider.Resolve(context.Background(), "secret://database/one")
	require.NoError(t, err)
	require.Equal(t, []byte("operator-runtime-secret"), credential.SecretBytes)
	credential.Release()
	_, err = provider.Resolve(context.Background(), "secret://database/other")
	require.Error(t, err)

	missing := config
	missing.CredentialLeases.Environment["secret://database/one"] = CredentialLeaseEnvironmentBinding{Username: "monitor", Variable: "DBPILOT_MISSING", Revision: 4}
	_, err = credentialLeaseProviderForConfig(missing)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "operator-runtime-secret")
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

func testTLSAuthority(t *testing.T, commonName string, now time.Time) (*x509.Certificate, ed25519.PrivateKey, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(encoded)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return certificate, privateKey, pool
}

func testTLSServerCertificate(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, now time.Time) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{encoded}, PrivateKey: privateKey}
}

func testTLSClientCertificate(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, agentID string, now time.Time) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	identity, err := url.Parse("spiffe://dbpilot.local/agent/" + agentID)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano() + 2), URIs: []*url.URL{identity}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{encoded}, PrivateKey: privateKey}
}

func performTLSHandshake(serverConfig, clientConfig *tls.Config) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		serverResult <- tls.Server(connection, serverConfig.Clone()).Handshake()
	}()
	client, clientErr := tls.Dial("tcp", listener.Addr().String(), clientConfig.Clone())
	if client != nil {
		_ = client.Close()
	}
	serverErr := <-serverResult
	return errors.Join(clientErr, serverErr)
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
