package database

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// damengDriverName is the fixed name used by the vendor-supplied DM Go
// database/sql driver. Runtime wiring owns importing and registering that
// driver, keeping its licensing and platform requirements out of the core.
const damengDriverName = "dm"

var damengSchemaPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_$#]{0,127}$`)

var damengMetricTemplates = []MetricTemplate{
	{ID: "dameng.sessions", Statement: `SELECT COUNT(*) AS "sessions" FROM "V$SESSIONS"`, MaxRows: 1, ValueColumns: []string{"sessions"}},
	{ID: "dameng.locks", Statement: `SELECT COUNT(*) AS "locks" FROM "V$LOCK"`, MaxRows: 1, ValueColumns: []string{"locks"}},
	{ID: "dameng.transactions", Statement: `SELECT COUNT(*) AS "transactions" FROM "V$TRX"`, MaxRows: 1, ValueColumns: []string{"transactions"}},
	{ID: "dameng.storage", Statement: `SELECT COALESCE(SUM(TOTAL_SIZE), 0) AS "storage_pages" FROM "V$TABLESPACE"`, MaxRows: 1, ValueColumns: []string{"storage_pages"}},
	{ID: "dameng.slow_sql", Statement: `SELECT COUNT(*) AS "slow_sql" FROM "V$LONG_EXEC_SQLS"`, MaxRows: 1, ValueColumns: []string{"slow_sql"}},
}

// DamengMetricTemplates returns copies of the fixed, runtime-owned DM metric
// templates. Policy can select an ID but cannot provide a statement.
func DamengMetricTemplates() []MetricTemplate {
	templates := make([]MetricTemplate, len(damengMetricTemplates))
	for index, template := range damengMetricTemplates {
		templates[index] = template
		templates[index].ValueColumns = append([]string(nil), template.ValueColumns...)
	}
	return templates
}

func damengMetricIDs() []string {
	templates := DamengMetricTemplates()
	ids := make([]string, len(templates))
	for index, template := range templates {
		ids[index] = template.ID
	}
	return ids
}

// NewDamengFactory creates a DM adapter factory with the default runtime
// secret resolver. The caller supplies the driver opener, so the proprietary
// driver is not linked into the core binary by default.
func NewDamengFactory(opener SQLOpener, catalog TemplateCatalog) Factory {
	return NewDamengFactoryWithRuntime(opener, catalog, EnvironmentSecretResolver{})
}

// NewDamengFactoryWithRuntime creates a DM adapter factory using injected
// runtime secret resolution and the explicit driver opener boundary.
func NewDamengFactoryWithRuntime(opener SQLOpener, catalog TemplateCatalog, resolver SecretResolver) Factory {
	return &damengFactory{
		opener:   opener,
		catalog:  catalog,
		resolver: resolver,
		capabilities: CapabilityMatrix{
			ReadOnlySQL: true,
			Metrics:     true,
			MetricIDs:   damengMetricIDs(),
		},
	}
}

// RegisterDamengFactory registers the fixed Dameng family with the default
// environment-backed runtime secret resolver.
func RegisterDamengFactory(registry Registry, opener SQLOpener, catalog TemplateCatalog) error {
	return RegisterDamengFactoryWithRuntime(registry, opener, catalog, EnvironmentSecretResolver{})
}

// RegisterDamengFactoryWithRuntime registers the DM adapter with explicit
// runtime secret resolution for composition roots that own secret stores.
func RegisterDamengFactoryWithRuntime(registry Registry, opener SQLOpener, catalog TemplateCatalog, resolver SecretResolver) error {
	if isNilInterface(registry) {
		return errors.New("database registry is required")
	}
	return registry.Register(DamengFamily, NewDamengFactoryWithRuntime(opener, catalog, resolver))
}

type damengFactory struct {
	opener       SQLOpener
	catalog      TemplateCatalog
	resolver     SecretResolver
	capabilities CapabilityMatrix
}

func (factory *damengFactory) Capabilities() CapabilityMatrix {
	return cloneCapabilities(factory.capabilities)
}

func (factory *damengFactory) Open(ctx context.Context, config InstanceConfig) (Adapter, error) {
	if ctx == nil {
		return nil, errors.New("database open context is required")
	}
	if err := validateInstanceConfig(config); err != nil {
		return nil, err
	}
	if config.Family != DamengFamily {
		return nil, fmt.Errorf("database family %q does not use Dameng protocol", config.Family)
	}
	if isNilInterface(factory.opener) {
		return nil, errors.New("database Dameng opener is required")
	}
	if isNilInterface(factory.catalog) {
		return nil, errors.New("database metric template catalog is required")
	}
	if isNilInterface(factory.resolver) {
		return nil, errors.New("database runtime secret resolver is required")
	}

	openContext, cancel := context.WithTimeout(ctx, config.ConnectTimeout)
	defer cancel()
	password, tlsConfig, err := resolveRuntimeConnection(openContext, config, factory.resolver)
	if err != nil {
		return nil, err
	}
	dsn, err := damengDSN(config, password)
	if err != nil {
		return nil, err
	}
	database, err := factory.openDatabase(openContext, dsn, tlsConfig)
	if err != nil {
		return nil, errors.New("open Dameng database")
	}
	if database == nil {
		return nil, errors.New("open Dameng database: opener returned nil database")
	}
	adapter := &sqlAdapter{
		family:         DamengFamily,
		capabilities:   cloneCapabilities(factory.capabilities),
		database:       database,
		catalog:        damengTemplateCatalog{fallback: factory.catalog},
		connectTimeout: config.ConnectTimeout,
		queryTimeout:   config.QueryTimeout,
	}
	if err := adapter.Ping(ctx); err != nil {
		_ = adapter.Close()
		return nil, errors.New("connect Dameng database")
	}
	return adapter, nil
}

func (factory *damengFactory) openDatabase(ctx context.Context, dsn string, config *tls.Config) (*sql.DB, error) {
	if config == nil {
		return factory.opener.Open(ctx, damengDriverName, dsn)
	}
	opener, ok := factory.opener.(TLSOpeningSQLOpener)
	if !ok {
		return nil, errors.New("database Dameng opener cannot apply TLS settings")
	}
	return opener.OpenWithTLS(ctx, damengDriverName, dsn, config)
}

func damengDSN(config InstanceConfig, password []byte) (string, error) {
	address, err := url.Parse(config.Address)
	if err != nil || address.Scheme != damengDriverName || address.Host == "" || (address.Path != "" && address.Path != "/") {
		return "", errors.New("Dameng address must use dm://host:port")
	}
	if !damengSchemaPattern.MatchString(config.Database) {
		return "", errors.New("Dameng schema is invalid")
	}
	parameters := url.Values{
		"connectTimeout": []string{strconvDurationMilliseconds(config.ConnectTimeout)},
		"logLevel":       []string{"off"},
		"schema":         []string{config.Database},
		"socketTimeout":  []string{strconvDurationSeconds(config.QueryTimeout)},
	}
	return fmt.Sprintf("dm://%s:%s@%s?%s", url.PathEscape(config.User), url.PathEscape(string(password)), address.Host, parameters.Encode()), nil
}

func strconvDurationMilliseconds(duration time.Duration) string {
	milliseconds := duration / time.Millisecond
	if duration%time.Millisecond != 0 {
		milliseconds++
	}
	return fmt.Sprintf("%d", milliseconds)
}

type damengTemplateCatalog struct{ fallback TemplateCatalog }

func (catalog damengTemplateCatalog) Lookup(family EngineFamily, id string) (MetricTemplate, bool) {
	if family == DamengFamily {
		for _, template := range DamengMetricTemplates() {
			if template.ID == id {
				return template, true
			}
		}
	}
	return catalog.fallback.Lookup(family, id)
}
