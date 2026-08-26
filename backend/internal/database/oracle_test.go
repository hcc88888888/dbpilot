package database

import (
	"context"
	"database/sql/driver"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRegisterOracleFamilyExposesIndependentBuiltInCapabilities(t *testing.T) {
	registry := NewRegistry()
	if err := RegisterOracleFactoryWithRuntime(registry, &fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}, adapterTestResolver()); err != nil {
		t.Fatalf("RegisterOracleFactoryWithRuntime() error = %v", err)
	}

	capabilities, found := registry.Capabilities(OracleFamily)
	if !found {
		t.Fatal("Capabilities(OracleFamily) found = false, want registered Oracle family")
	}
	wantMetricIDs := []string{"oracle.sessions", "oracle.transactions", "oracle.locks", "oracle.tablespace", "oracle.slow_sql"}
	if !capabilities.ReadOnlySQL || !capabilities.Metrics || capabilities.Explain || capabilities.Transactions || !slices.Equal(capabilities.MetricIDs, wantMetricIDs) {
		t.Fatalf("Capabilities(OracleFamily) = %#v, want read-only Oracle metric capabilities %#v", capabilities, wantMetricIDs)
	}
	capabilities.MetricIDs[0] = "mutated"
	again, _ := registry.Capabilities(OracleFamily)
	if !slices.Equal(again.MetricIDs, wantMetricIDs) {
		t.Fatalf("capability mutation leaked into registry: %#v", again.MetricIDs)
	}
}

func TestOracleFactoryBuildsFixedDriverDSNFromServiceName(t *testing.T) {
	state := &sqlDriverState{}
	opener := &fakeSQLOpener{db: newTestSQLDB(t, state)}
	config := adapterTestConfig(OracleFamily)
	config.Address = "oracle://db.example.test:1521"
	config.Database = "service:finance_pdb"
	config.TLS = TLSConfig{Enabled: true, ServerName: "db.internal.test"}

	adapter, err := oracleFactoryForTest(opener, staticCatalog{}).Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	if got, want := opener.driverName, oracleDriverName; got != want {
		t.Fatalf("driver name = %q, want fixed %q", got, want)
	}
	if got, want := opener.dsn, "oracle://readonly:runtime-password@db.example.test:1521/finance_pdb?CONNECTION+TIMEOUT=5&SSL=TRUE&SSL+VERIFY=TRUE&TIMEOUT=15"; got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}
	if opener.tlsConfig == nil || opener.tlsConfig.ServerName != "db.internal.test" {
		t.Fatalf("TLS config = %#v, want runtime TLS propagation", opener.tlsConfig)
	}
}

func TestOracleFactoryBuildsSIDOnlyFromValidatedDatabaseField(t *testing.T) {
	state := &sqlDriverState{}
	opener := &fakeSQLOpener{db: newTestSQLDB(t, state)}
	config := adapterTestConfig(OracleFamily)
	config.Address = "oracle://db.example.test:1521"
	config.Database = "sid:ORCL"

	adapter, err := oracleFactoryForTest(opener, staticCatalog{}).Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	if got, want := opener.dsn, "oracle://readonly:runtime-password@db.example.test:1521/?CONNECTION+TIMEOUT=5&SID=ORCL&TIMEOUT=15"; got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}

	config.Database = "sid:bad/value"
	if _, err := oracleFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Open(context.Background(), config); err == nil {
		t.Fatal("Open() error = nil, want invalid SID rejected before opening")
	}
	config.Database = "app"
	config.Address = "oracle://db.example.test:1521/untrusted-service"
	if _, err := oracleFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Open(context.Background(), config); err == nil {
		t.Fatal("Open() error = nil, want address path rejected as an Oracle service name")
	}
}

func TestOracleFactoryResolvesRuntimeSecretsAndTLSWithoutLeakingReferences(t *testing.T) {
	caPEM, certificatePEM, keyPEM := testTLSMaterial(t)
	resolver := &fakeSecretResolver{secrets: map[string][]byte{
		"secret://runtime/db-primary":  []byte("password with spaces"),
		"secret://runtime/database-ca": caPEM,
		"secret://runtime/client-cert": certificatePEM,
		"secret://runtime/client-key":  keyPEM,
	}}
	opener := &fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}
	config := adapterTestConfig(OracleFamily)
	config.Address = "oracle://db.example.test:1521"
	config.TLS = TLSConfig{
		Enabled:              true,
		ServerName:           "db.internal.test",
		CASecretRef:          "secret://runtime/database-ca",
		CertificateSecretRef: "secret://runtime/client-cert",
		KeySecretRef:         "secret://runtime/client-key",
	}

	adapter, err := NewOracleFactoryWithRuntime(opener, staticCatalog{}, resolver).Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	if got, want := resolver.references, []string{"secret://runtime/db-primary", "secret://runtime/database-ca", "secret://runtime/client-cert", "secret://runtime/client-key"}; !slices.Equal(got, want) {
		t.Fatalf("resolved references = %q, want %q", got, want)
	}
	if !strings.Contains(opener.dsn, "password%20with%20spaces") {
		t.Fatalf("DSN does not contain the resolved password: %q", opener.dsn)
	}
	for _, secret := range []string{config.SecretRef, config.TLS.CASecretRef, config.TLS.CertificateSecretRef, config.TLS.KeySecretRef} {
		if strings.Contains(opener.dsn, secret) {
			t.Fatalf("DSN leaked secret reference %q: %q", secret, opener.dsn)
		}
	}
	if opener.tlsConfig == nil || opener.tlsConfig.RootCAs == nil || len(opener.tlsConfig.Certificates) != 1 {
		t.Fatalf("TLS config = %#v, want CA and client certificate", opener.tlsConfig)
	}
}

func TestOracleFactoryRejectsUnsupportedTLSAndSanitizesDriverErrors(t *testing.T) {
	config := adapterTestConfig(OracleFamily)
	config.Address = "oracle://db.example.test:1521"
	config.TLS = TLSConfig{Enabled: true, ServerName: "db.internal.test"}
	resolver := StaticSecretResolver{config.SecretRef: []byte("never-return-this-password")}
	opener := basicSQLOpener{delegate: &fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}}

	if _, err := NewOracleFactoryWithRuntime(opener, staticCatalog{}, resolver).Open(context.Background(), config); err == nil {
		t.Fatal("Open() error = nil, want unsupported TLS opener rejected")
	}

	config.TLS = TLSConfig{}
	_, err := NewOracleFactoryWithRuntime(failingSQLOpener{err: errors.New("oracle driver rejected password never-return-this-password")}, staticCatalog{}, resolver).Open(context.Background(), config)
	if err == nil {
		t.Fatal("Open() error = nil, want driver failure")
	}
	if strings.Contains(err.Error(), "never-return-this-password") || strings.Contains(strings.ToLower(err.Error()), "driver") {
		t.Fatalf("Open() leaked driver details: %v", err)
	}
}

func TestOracleFactoryBoundsOpenPingQueryAndClose(t *testing.T) {
	config := adapterTestConfig(OracleFamily)
	config.Address = "oracle://db.example.test:1521"
	config.ConnectTimeout = 20 * time.Millisecond
	blocking := &blockingSQLOpener{}
	if _, err := NewOracleFactoryWithRuntime(blocking, staticCatalog{}, StaticSecretResolver{config.SecretRef: []byte("runtime-password")}).Open(context.Background(), config); err == nil {
		t.Fatal("Open() error = nil, want bounded opener timeout")
	}
	if !blocking.contextCancelled {
		t.Fatal("oracle opener context was not cancelled at connect timeout")
	}

	template := OracleMetricTemplates()[0]
	state := &sqlDriverState{columns: append([]string(nil), template.ValueColumns...), rows: [][]driver.Value{{int64(4)}}}
	adapter, err := oracleFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), func() InstanceConfig {
		value := adapterTestConfig(OracleFamily)
		value.Address = "oracle://db.example.test:1521"
		return value
	}())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	deadline := time.Now().Add(100 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := adapter.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	if state.pingDeadline.After(deadline.Add(10 * time.Millisecond)) {
		t.Fatalf("ping deadline = %v, exceeds caller deadline %v", state.pingDeadline, deadline)
	}
	if _, err := adapter.QueryMetric(ctx, template.ID, nil); err != nil {
		t.Fatalf("QueryMetric() error = %v", err)
	}
	if state.queryDeadline.After(deadline.Add(10 * time.Millisecond)) {
		t.Fatalf("query deadline = %v, exceeds caller deadline %v", state.queryDeadline, deadline)
	}
	if _, err := adapter.QueryMetric(ctx, "SELECT password FROM users", nil); err == nil {
		t.Fatal("QueryMetric() error = nil, want arbitrary policy SQL rejected as a metric ID")
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestOracleMetricTemplatesAreRegisteredReadOnlyAndBounded(t *testing.T) {
	templates := OracleMetricTemplates()
	wantIDs := []string{"oracle.sessions", "oracle.transactions", "oracle.locks", "oracle.tablespace", "oracle.slow_sql"}
	gotIDs := make([]string, 0, len(templates))
	for _, template := range templates {
		gotIDs = append(gotIDs, template.ID)
		if err := validateTemplate(template, template.ID); err != nil {
			t.Fatalf("template %q is not a bounded read-only metric: %v", template.ID, err)
		}
	}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("OracleMetricTemplates IDs = %q, want %q", gotIDs, wantIDs)
	}
	templates[0].ValueColumns[0] = "mutated"
	if got := OracleMetricTemplates()[0].ValueColumns[0]; got == "mutated" {
		t.Fatal("OracleMetricTemplates returned shared template state")
	}
}

func oracleFactoryForTest(opener SQLOpener, catalog TemplateCatalog) Factory {
	return NewOracleFactoryWithRuntime(opener, catalog, adapterTestResolver())
}
