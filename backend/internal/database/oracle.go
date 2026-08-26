package database

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// oracleDriverName is deliberately fixed to go-ora's pure-Go database/sql
// driver name. Runtime wiring must provide an opener for this driver; the core
// binary does not import the driver.
const oracleDriverName = "oracle"

var oracleTargetPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_$#.-]{0,127}$`)

var oracleMetricTemplates = []MetricTemplate{
	{ID: "oracle.sessions", Statement: "SELECT COUNT(*) AS sessions FROM v$session", MaxRows: 1, ValueColumns: []string{"sessions"}},
	{ID: "oracle.transactions", Statement: "SELECT COUNT(*) AS transactions FROM v$transaction", MaxRows: 1, ValueColumns: []string{"transactions"}},
	{ID: "oracle.locks", Statement: "SELECT COUNT(*) AS locks FROM gv$session WHERE blocking_session IS NOT NULL", MaxRows: 1, ValueColumns: []string{"locks"}},
	{ID: "oracle.tablespace", Statement: "SELECT ROUND(SUM(bytes) / 1048576) AS tablespace_mb FROM dba_data_files", MaxRows: 1, ValueColumns: []string{"tablespace_mb"}},
	{ID: "oracle.slow_sql", Statement: "SELECT COUNT(*) AS slow_sql FROM v$sql WHERE elapsed_time >= 1000000", MaxRows: 1, ValueColumns: []string{"slow_sql"}},
}

// OracleMetricTemplates returns copies of the fixed, runtime-owned Oracle
// metric templates. Policy may select an ID but never supply SQL text.
func OracleMetricTemplates() []MetricTemplate {
	templates := make([]MetricTemplate, len(oracleMetricTemplates))
	for index, template := range oracleMetricTemplates {
		templates[index] = template
		templates[index].ValueColumns = append([]string(nil), template.ValueColumns...)
	}
	return templates
}

func oracleMetricIDs() []string {
	templates := OracleMetricTemplates()
	ids := make([]string, len(templates))
	for index, template := range templates {
		ids[index] = template.ID
	}
	return ids
}

// NewOracleFactory creates an Oracle adapter factory with the default runtime
// secret resolver. The caller supplies the driver opener so no Oracle driver is
// linked into the core binary by default.
func NewOracleFactory(opener SQLOpener, catalog TemplateCatalog) Factory {
	return NewOracleFactoryWithRuntime(opener, catalog, EnvironmentSecretResolver{})
}

// NewOracleFactoryWithRuntime creates an Oracle adapter factory using an
// injected runtime secret resolver and opener boundary.
func NewOracleFactoryWithRuntime(opener SQLOpener, catalog TemplateCatalog, resolver SecretResolver) Factory {
	return &oracleFactory{
		opener:   opener,
		catalog:  catalog,
		resolver: resolver,
		capabilities: CapabilityMatrix{
			ReadOnlySQL: true,
			Metrics:     true,
			MetricIDs:   oracleMetricIDs(),
		},
	}
}

// RegisterOracleFactory registers the fixed Oracle family with the supplied
// registry. It never selects a driver or a family from instance input.
func RegisterOracleFactory(registry Registry, opener SQLOpener, catalog TemplateCatalog) error {
	return RegisterOracleFactoryWithRuntime(registry, opener, catalog, EnvironmentSecretResolver{})
}

// RegisterOracleFactoryWithRuntime registers Oracle with explicit runtime
// secret resolution. It is useful to composition roots that own secret stores.
func RegisterOracleFactoryWithRuntime(registry Registry, opener SQLOpener, catalog TemplateCatalog, resolver SecretResolver) error {
	if isNilInterface(registry) {
		return errors.New("database registry is required")
	}
	return registry.Register(OracleFamily, NewOracleFactoryWithRuntime(opener, catalog, resolver))
}

type oracleFactory struct {
	opener       SQLOpener
	catalog      TemplateCatalog
	resolver     SecretResolver
	capabilities CapabilityMatrix
}

func (factory *oracleFactory) Capabilities() CapabilityMatrix {
	return cloneCapabilities(factory.capabilities)
}

func (factory *oracleFactory) Open(ctx context.Context, config InstanceConfig) (Adapter, error) {
	if ctx == nil {
		return nil, errors.New("database open context is required")
	}
	if err := validateInstanceConfig(config); err != nil {
		return nil, err
	}
	if config.Family != OracleFamily {
		return nil, fmt.Errorf("database family %q does not use Oracle protocol", config.Family)
	}
	if isNilInterface(factory.opener) {
		return nil, errors.New("database Oracle opener is required")
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
	dsn, err := oracleDSN(config, password)
	if err != nil {
		return nil, err
	}
	database, err := factory.openDatabase(openContext, dsn, tlsConfig)
	if err != nil {
		return nil, errors.New("open Oracle database")
	}
	if database == nil {
		return nil, errors.New("open Oracle database: opener returned nil database")
	}
	adapter := &sqlAdapter{
		family:         OracleFamily,
		capabilities:   cloneCapabilities(factory.capabilities),
		database:       database,
		catalog:        oracleTemplateCatalog{fallback: factory.catalog},
		connectTimeout: config.ConnectTimeout,
		queryTimeout:   config.QueryTimeout,
	}
	if err := adapter.Ping(ctx); err != nil {
		_ = adapter.Close()
		return nil, errors.New("connect Oracle database")
	}
	return adapter, nil
}

func (factory *oracleFactory) openDatabase(ctx context.Context, dsn string, config *tls.Config) (*sql.DB, error) {
	if config == nil {
		return factory.opener.Open(ctx, oracleDriverName, dsn)
	}
	opener, ok := factory.opener.(TLSOpeningSQLOpener)
	if !ok {
		return nil, errors.New("database Oracle opener cannot apply TLS settings")
	}
	return opener.OpenWithTLS(ctx, oracleDriverName, dsn, config)
}

func oracleDSN(config InstanceConfig, password []byte) (string, error) {
	address, err := url.Parse(config.Address)
	if err != nil || address.Scheme != "oracle" || address.Host == "" || (address.Path != "" && address.Path != "/") {
		return "", errors.New("Oracle address must use oracle://host:port")
	}
	targetKind, target, err := oracleTarget(config.Database)
	if err != nil {
		return "", err
	}
	parameters := url.Values{
		"CONNECTION TIMEOUT": []string{strconvDurationSeconds(config.ConnectTimeout)},
		"TIMEOUT":            []string{strconvDurationSeconds(config.QueryTimeout)},
	}
	if config.TLS.Enabled {
		// go-ora uses URL options to select TCPS. The TLS-capable opener receives
		// the ephemeral tls.Config separately, so certificate material never
		// enters this data source name.
		parameters.Set("SSL", "TRUE")
		parameters.Set("SSL VERIFY", "TRUE")
	}
	path := target
	if targetKind == "sid" {
		path = ""
		parameters.Set("SID", target)
	}
	return fmt.Sprintf("oracle://%s:%s@%s/%s?%s", url.PathEscape(config.User), url.PathEscape(string(password)), address.Host, url.PathEscape(path), parameters.Encode()), nil
}

func oracleTarget(database string) (string, string, error) {
	targetKind := "service"
	target := database
	if kind, value, found := strings.Cut(database, ":"); found {
		switch kind {
		case "service", "sid":
			targetKind, target = kind, value
		default:
			return "", "", errors.New("Oracle database target must use service: or sid:")
		}
	}
	if !oracleTargetPattern.MatchString(target) {
		return "", "", errors.New("Oracle service name or SID is invalid")
	}
	return targetKind, target, nil
}

type oracleTemplateCatalog struct{ fallback TemplateCatalog }

func (catalog oracleTemplateCatalog) Lookup(family EngineFamily, id string) (MetricTemplate, bool) {
	if family == OracleFamily {
		for _, template := range OracleMetricTemplates() {
			if template.ID == id {
				return template, true
			}
		}
	}
	return catalog.fallback.Lookup(family, id)
}
