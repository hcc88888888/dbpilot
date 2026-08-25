package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

const mysqlDriverName = "mysql"

// SQLOpener keeps a database driver behind the runtime-owned adapter boundary.
// Production wiring can delegate to sql.Open, while tests can supply a local
// database/sql implementation without network access.
type SQLOpener interface {
	Open(driverName, dataSourceName string) (*sql.DB, error)
}

// SQLOpenerFunc adapts an Open function to SQLOpener.
type SQLOpenerFunc func(driverName, dataSourceName string) (*sql.DB, error)

func (function SQLOpenerFunc) Open(driverName, dataSourceName string) (*sql.DB, error) {
	return function(driverName, dataSourceName)
}

type sqlProtocolFactory struct {
	protocol     EngineFamily
	opener       SQLOpener
	catalog      TemplateCatalog
	capabilities CapabilityMatrix
}

// NewMySQLFactory creates adapters for explicitly selected MySQL-protocol
// families. It never derives a protocol or driver from user-controlled input.
func NewMySQLFactory(opener SQLOpener, catalog TemplateCatalog) Factory {
	return &sqlProtocolFactory{
		protocol: mysqlDriverName,
		opener:   opener,
		catalog:  catalog,
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
	if !factory.accepts(config.Family) {
		return nil, fmt.Errorf("database family %q does not use %s protocol", config.Family, factory.protocol)
	}

	dsn, err := factory.dsn(config)
	if err != nil {
		return nil, err
	}
	database, err := factory.opener.Open(string(factory.protocol), dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", factory.protocol, err)
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
		return nil, fmt.Errorf("connect %s database: %w", factory.protocol, err)
	}
	return adapter, nil
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

func (factory *sqlProtocolFactory) dsn(config InstanceConfig) (string, error) {
	if factory.protocol == mysqlDriverName {
		return mysqlDSN(config)
	}
	return postgresDSN(config)
}

func mysqlDSN(config InstanceConfig) (string, error) {
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
		parameters.Set("tls", "true")
	}
	return fmt.Sprintf("%s@tcp(%s)/%s?%s", config.User, address.Host, url.PathEscape(config.Database), parameters.Encode()), nil
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
	return adapter.database.PingContext(pingContext)
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
		return adapter.closeErr
	case <-timer.C:
		return fmt.Errorf("close database adapter: %w", context.DeadlineExceeded)
	}
}

type sqlQueryer struct{ database *sql.DB }

func (queryer sqlQueryer) QueryContext(ctx context.Context, statement string, arguments ...any) (Rows, error) {
	return queryer.database.QueryContext(ctx, statement, arguments...)
}

func postgresDSN(config InstanceConfig) (string, error) {
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
		User:     url.User(config.User),
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
