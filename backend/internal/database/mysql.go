package database

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const mysqlDriverName = "mysql"

// SQLOpener keeps a database driver behind the runtime-owned adapter boundary.
// Production wiring can delegate to sql.Open, while tests can supply a local
// database/sql implementation without network access.
type SQLOpener interface {
	Open(context.Context, string, string) (*sql.DB, error)
}

// TLSOpeningSQLOpener opens a database after securely applying an ephemeral
// TLS configuration. Implementations must not persist or log the supplied
// certificate material.
type TLSOpeningSQLOpener interface {
	SQLOpener
	OpenWithTLS(context.Context, string, string, *tls.Config) (*sql.DB, error)
}

// SecretResolver resolves runtime-only secret references. Returned values are
// never copied to policy structures, logs, or adapter errors.
type SecretResolver interface {
	ResolveSecret(context.Context, string) ([]byte, error)
}

// StaticSecretResolver is a runtime configuration boundary suitable for
// injected secret stores in a process. It copies values before returning them.
type StaticSecretResolver map[string][]byte

func (resolver StaticSecretResolver) ResolveSecret(ctx context.Context, reference string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, found := resolver[reference]
	if !found {
		return nil, errors.New("secret not found")
	}
	return append([]byte(nil), value...), nil
}

// EnvironmentSecretResolver resolves secret://provider/name as
// DBPILOT_SECRET_PROVIDER_NAME. It is the default runtime resolver; callers
// can inject a dedicated secret manager with the WithRuntime constructors.
type EnvironmentSecretResolver struct{}

func (EnvironmentSecretResolver) ResolveSecret(ctx context.Context, reference string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parsed, err := url.Parse(reference)
	if err != nil || parsed.Scheme != "secret" || parsed.Host == "" || parsed.Path == "" {
		return nil, errors.New("secret not found")
	}
	name := strings.ToUpper(parsed.Host + "_" + strings.TrimPrefix(parsed.Path, "/"))
	name = strings.Map(func(character rune) rune {
		if (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') {
			return character
		}
		return '_'
	}, name)
	value, found := os.LookupEnv("DBPILOT_SECRET_" + name)
	if !found {
		return nil, errors.New("secret not found")
	}
	return []byte(value), nil
}

// SQLDriverOpener is the concrete database/sql opener for runtime wiring.
// The selected driver must be registered by the program. It intentionally
// declines TLS because driver-specific TLS registration must be explicit.
type SQLDriverOpener struct{}

func (SQLDriverOpener) Open(ctx context.Context, driverName, dataSourceName string) (*sql.DB, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return sql.Open(driverName, dataSourceName)
}

// SQLOpenerFunc adapts an Open function to SQLOpener.
type SQLOpenerFunc func(context.Context, string, string) (*sql.DB, error)

func (function SQLOpenerFunc) Open(ctx context.Context, driverName, dataSourceName string) (*sql.DB, error) {
	return function(ctx, driverName, dataSourceName)
}

type sqlProtocolFactory struct {
	protocol     EngineFamily
	opener       SQLOpener
	catalog      TemplateCatalog
	resolver     SecretResolver
	capabilities CapabilityMatrix
}

// NewMySQLFactory creates adapters for explicitly selected MySQL-protocol
// families. It never derives a protocol or driver from user-controlled input.
func NewMySQLFactory(opener SQLOpener, catalog TemplateCatalog) Factory {
	return NewMySQLFactoryWithRuntime(opener, catalog, EnvironmentSecretResolver{})
}

// NewMySQLFactoryWithRuntime creates a MySQL-protocol factory with the
// runtime-only resolver needed to consume credential and TLS secret refs.
func NewMySQLFactoryWithRuntime(opener SQLOpener, catalog TemplateCatalog, resolver SecretResolver) Factory {
	return &sqlProtocolFactory{
		protocol: mysqlDriverName,
		opener:   opener,
		catalog:  catalog,
		resolver: resolver,
		capabilities: CapabilityMatrix{
			ReadOnlySQL: true,
			Metrics:     true,
		},
	}
}

func (factory *sqlProtocolFactory) Capabilities() CapabilityMatrix {
	return cloneCapabilities(factory.capabilities)
}

func (factory *sqlProtocolFactory) Open(ctx context.Context, config InstanceConfig) (Adapter, error) {
	if ctx == nil {
		return nil, errors.New("database open context is required")
	}
	if err := validateInstanceConfig(config); err != nil {
		return nil, err
	}
	if isNilInterface(factory.opener) {
		return nil, errors.New("database SQL opener is required")
	}
	if isNilInterface(factory.catalog) {
		return nil, errors.New("database metric template catalog is required")
	}
	if isNilInterface(factory.resolver) {
		return nil, errors.New("database runtime secret resolver is required")
	}
	if !factory.accepts(config.Family) {
		return nil, fmt.Errorf("database family %q does not use %s protocol", config.Family, factory.protocol)
	}

	openContext, cancel := context.WithTimeout(ctx, config.ConnectTimeout)
	defer cancel()
	password, tlsConfig, err := resolveRuntimeConnection(openContext, config, factory.resolver)
	if err != nil {
		return nil, err
	}
	dsn, err := factory.dsn(config, password)
	if err != nil {
		return nil, err
	}
	database, err := factory.openDatabase(openContext, dsn, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("open %s database", factory.protocol)
	}
	if database == nil {
		return nil, fmt.Errorf("open %s database: opener returned nil database", factory.protocol)
	}
	adapter := &sqlAdapter{
		family:         config.Family,
		capabilities:   cloneCapabilities(factory.capabilities),
		database:       database,
		catalog:        factory.catalog,
		connectTimeout: config.ConnectTimeout,
		queryTimeout:   config.QueryTimeout,
	}
	if err := adapter.Ping(ctx); err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("connect %s database", factory.protocol)
	}
	return adapter, nil
}

func (factory *sqlProtocolFactory) openDatabase(ctx context.Context, dsn string, tlsConfig *tls.Config) (*sql.DB, error) {
	if tlsConfig == nil {
		return factory.opener.Open(ctx, string(factory.protocol), dsn)
	}
	tlsOpener, ok := factory.opener.(TLSOpeningSQLOpener)
	if !ok {
		return nil, errors.New("database SQL opener cannot apply TLS settings")
	}
	return tlsOpener.OpenWithTLS(ctx, string(factory.protocol), dsn, tlsConfig)
}

func (factory *sqlProtocolFactory) accepts(family EngineFamily) bool {
	if factory.protocol == mysqlDriverName {
		switch family {
		case MySQLFamily, MariaDBFamily, TiDBFamily, OceanBaseFamily:
			return true
		default:
			return false
		}
	}
	return family == PostgresFamily || family == OpenGaussFamily
}

func (factory *sqlProtocolFactory) dsn(config InstanceConfig, password []byte) (string, error) {
	if factory.protocol == mysqlDriverName {
		return mysqlDSN(config, password)
	}
	return postgresDSN(config, password)
}

func mysqlDSN(config InstanceConfig, password []byte) (string, error) {
	address, err := url.Parse(config.Address)
	if err != nil {
		return "", fmt.Errorf("parse MySQL address: %w", err)
	}
	if address.Host == "" {
		return "", errors.New("MySQL address host is required")
	}
	parameters := url.Values{
		"timeout":      []string{config.ConnectTimeout.String()},
		"readTimeout":  []string{config.QueryTimeout.String()},
		"writeTimeout": []string{config.QueryTimeout.String()},
	}
	if config.TLS.Enabled {
		parameters.Set("tls", "custom")
	}
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?%s", config.User, url.QueryEscape(string(password)), address.Host, url.PathEscape(config.Database), parameters.Encode()), nil
}

func resolveRuntimeConnection(ctx context.Context, config InstanceConfig, resolver SecretResolver) ([]byte, *tls.Config, error) {
	resolverContext, cancel := context.WithTimeout(ctx, config.ConnectTimeout)
	defer cancel()
	password, err := resolveRuntimeSecret(resolverContext, resolver, config.SecretRef, "credential")
	if err != nil {
		return nil, nil, err
	}
	if !config.TLS.Enabled {
		if config.TLS.ServerName != "" || config.TLS.CASecretRef != "" || config.TLS.CertificateSecretRef != "" || config.TLS.KeySecretRef != "" {
			return nil, nil, errors.New("database TLS settings require TLS to be enabled")
		}
		return password, nil, nil
	}

	address, err := url.Parse(config.Address)
	if err != nil || address.Hostname() == "" {
		return nil, nil, errors.New("database TLS address is invalid")
	}
	serverName := config.TLS.ServerName
	if serverName == "" {
		serverName = address.Hostname()
	}
	configTLS := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if config.TLS.CASecretRef != "" {
		certificateAuthority, err := resolveRuntimeSecret(resolverContext, resolver, config.TLS.CASecretRef, "CA")
		if err != nil {
			return nil, nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(certificateAuthority) {
			return nil, nil, errors.New("database TLS CA certificate is invalid")
		}
		configTLS.RootCAs = pool
	}
	if config.TLS.CertificateSecretRef != "" {
		certificatePEM, err := resolveRuntimeSecret(resolverContext, resolver, config.TLS.CertificateSecretRef, "client certificate")
		if err != nil {
			return nil, nil, err
		}
		keyPEM, err := resolveRuntimeSecret(resolverContext, resolver, config.TLS.KeySecretRef, "client key")
		if err != nil {
			return nil, nil, err
		}
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return nil, nil, errors.New("database TLS client certificate is invalid")
		}
		configTLS.Certificates = []tls.Certificate{certificate}
	}
	return password, configTLS, nil
}

func resolveRuntimeSecret(ctx context.Context, resolver SecretResolver, reference, kind string) ([]byte, error) {
	value, err := resolver.ResolveSecret(ctx, reference)
	if err != nil || len(value) == 0 {
		return nil, fmt.Errorf("resolve database %s secret", kind)
	}
	return value, nil
}

type sqlAdapter struct {
	family         EngineFamily
	capabilities   CapabilityMatrix
	database       *sql.DB
	catalog        TemplateCatalog
	connectTimeout time.Duration
	queryTimeout   time.Duration

	closeOnce sync.Once
	closeDone chan struct{}
	closeErr  error
}

func (adapter *sqlAdapter) Family() EngineFamily { return adapter.family }

func (adapter *sqlAdapter) Capabilities() CapabilityMatrix {
	return cloneCapabilities(adapter.capabilities)
}

func (adapter *sqlAdapter) Ping(ctx context.Context) error {
	if ctx == nil {
		return errors.New("database ping context is required")
	}
	pingContext, cancel := context.WithTimeout(ctx, adapter.connectTimeout)
	defer cancel()
	if err := adapter.database.PingContext(pingContext); err != nil {
		return errors.New("database ping failed")
	}
	return nil
}

func (adapter *sqlAdapter) QueryMetric(ctx context.Context, metricID string, arguments map[string]any) ([]MetricRow, error) {
	if ctx == nil {
		return nil, errors.New("database query context is required")
	}
	queryContext, cancel := context.WithTimeout(ctx, adapter.queryTimeout)
	defer cancel()
	return ExecuteReadOnly(queryContext, sqlQueryer{database: adapter.database}, adapter.family, adapter.catalog, metricID, arguments, 0)
}

func (adapter *sqlAdapter) Close() error {
	adapter.closeOnce.Do(func() {
		adapter.closeDone = make(chan struct{})
		go func() {
			adapter.closeErr = adapter.database.Close()
			close(adapter.closeDone)
		}()
	})

	timer := time.NewTimer(adapter.connectTimeout)
	defer timer.Stop()
	select {
	case <-adapter.closeDone:
		if adapter.closeErr != nil {
			return errors.New("close database adapter")
		}
		return nil
	case <-timer.C:
		return fmt.Errorf("close database adapter: %w", context.DeadlineExceeded)
	}
}

type sqlQueryer struct{ database *sql.DB }

func (queryer sqlQueryer) QueryContext(ctx context.Context, statement string, arguments ...any) (Rows, error) {
	rows, err := queryer.database.QueryContext(ctx, statement, arguments...)
	if err != nil {
		return nil, errors.New("database metric query failed")
	}
	return rows, nil
}

func postgresDSN(config InstanceConfig, password []byte) (string, error) {
	address, err := url.Parse(config.Address)
	if err != nil {
		return "", fmt.Errorf("parse PostgreSQL address: %w", err)
	}
	if address.Host == "" {
		return "", errors.New("PostgreSQL address host is required")
	}
	parameters := url.Values{
		"connect_timeout":   []string{strconvDurationSeconds(config.ConnectTimeout)},
		"statement_timeout": []string{fmt.Sprintf("%d", config.QueryTimeout.Milliseconds())},
		"sslmode":           []string{"disable"},
	}
	if config.TLS.Enabled {
		parameters.Set("sslmode", "verify-full")
	}
	return (&url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(config.User, string(password)),
		Host:     address.Host,
		Path:     "/" + strings.TrimPrefix(config.Database, "/"),
		RawQuery: parameters.Encode(),
	}).String(), nil
}

func strconvDurationSeconds(duration time.Duration) string {
	seconds := duration / time.Second
	if duration%time.Second != 0 {
		seconds++
	}
	return fmt.Sprintf("%d", seconds)
}
