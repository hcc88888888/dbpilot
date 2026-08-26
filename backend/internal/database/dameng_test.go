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

func TestRegisterDamengFamilyExposesIndependentBuiltInCapabilities(t *testing.T) {
	registry := NewRegistry()
	if err := RegisterDamengFactoryWithRuntime(registry, &fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}, adapterTestResolver()); err != nil {
		t.Fatalf("RegisterDamengFactoryWithRuntime() error = %v", err)
	}

	capabilities, found := registry.Capabilities(DamengFamily)
	if !found {
		t.Fatal("Capabilities(DamengFamily) found = false, want registered Dameng family")
	}
	wantMetricIDs := []string{"dameng.sessions", "dameng.locks", "dameng.transactions", "dameng.storage", "dameng.slow_sql"}
	if !capabilities.ReadOnlySQL || !capabilities.Metrics || capabilities.Explain || capabilities.Transactions || !slices.Equal(capabilities.MetricIDs, wantMetricIDs) {
		t.Fatalf("Capabilities(DamengFamily) = %#v, want read-only Dameng metric capabilities %#v", capabilities, wantMetricIDs)
	}
	capabilities.MetricIDs[0] = "mutated"
	again, _ := registry.Capabilities(DamengFamily)
	if !slices.Equal(again.MetricIDs, wantMetricIDs) {
		t.Fatalf("capability mutation leaked into registry: %#v", again.MetricIDs)
	}
}

func TestDamengFactoryBuildsFixedDriverDSNFromValidatedSchema(t *testing.T) {
	state := &sqlDriverState{}
	opener := &fakeSQLOpener{db: newTestSQLDB(t, state)}
	config := adapterTestConfig(DamengFamily)
	config.Address = "dm://db.example.test:5236"
	config.Database = "APP_DATA"

	adapter, err := damengFactoryForTest(opener, staticCatalog{}).Open(context.Background(), config)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer adapter.Close()

	if got, want := opener.driverName, damengDriverName; got != want {
		t.Fatalf("driver name = %q, want fixed %q", got, want)
	}
	if got, want := opener.dsn, "dm://readonly:runtime-password@db.example.test:5236?connectTimeout=5000&logLevel=off&schema=APP_DATA&socketTimeout=15"; got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}

	config.Database = "app/schema"
	if _, err := damengFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Open(context.Background(), config); err == nil {
		t.Fatal("Open() error = nil, want invalid schema rejected before opening")
	}
	config.Database = "app"
	config.Address = "dm://db.example.test:5236/untrusted-schema"
	if _, err := damengFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}, staticCatalog{}).Open(context.Background(), config); err == nil {
		t.Fatal("Open() error = nil, want address path rejected as a Dameng schema")
	}
}

func TestDamengFactoryResolvesRuntimeSecretsAndTLSWithoutLeakingReferences(t *testing.T) {
	caPEM, certificatePEM, keyPEM := testTLSMaterial(t)
	resolver := &fakeSecretResolver{secrets: map[string][]byte{
		"secret://runtime/db-primary":  []byte("password with spaces"),
		"secret://runtime/database-ca": caPEM,
		"secret://runtime/client-cert": certificatePEM,
		"secret://runtime/client-key":  keyPEM,
	}}
	opener := &fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}
	config := adapterTestConfig(DamengFamily)
	config.Address = "dm://db.example.test:5236"
	config.TLS = TLSConfig{
		Enabled:              true,
		ServerName:           "db.internal.test",
		CASecretRef:          "secret://runtime/database-ca",
		CertificateSecretRef: "secret://runtime/client-cert",
		KeySecretRef:         "secret://runtime/client-key",
	}

	adapter, err := NewDamengFactoryWithRuntime(opener, staticCatalog{}, resolver).Open(context.Background(), config)
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
	if opener.tlsConfig == nil || opener.tlsConfig.ServerName != "db.internal.test" || opener.tlsConfig.RootCAs == nil || len(opener.tlsConfig.Certificates) != 1 {
		t.Fatalf("TLS config = %#v, want server name, CA, and client certificate", opener.tlsConfig)
	}
	if strings.Contains(opener.dsn, "sslCertPath") || strings.Contains(opener.dsn, "sslKeyPath") {
		t.Fatalf("DSN leaked TLS file-system settings: %q", opener.dsn)
	}
}

func TestDamengFactoryRejectsUnsupportedTLSAndSanitizesDriverErrors(t *testing.T) {
	config := adapterTestConfig(DamengFamily)
	config.Address = "dm://db.example.test:5236"
	config.TLS = TLSConfig{Enabled: true, ServerName: "db.internal.test"}
	resolver := StaticSecretResolver{config.SecretRef: []byte("never-return-this-password")}
	opener := basicSQLOpener{delegate: &fakeSQLOpener{db: newTestSQLDB(t, &sqlDriverState{})}}

	if _, err := NewDamengFactoryWithRuntime(opener, staticCatalog{}, resolver).Open(context.Background(), config); err == nil {
		t.Fatal("Open() error = nil, want unsupported TLS opener rejected")
	}

	config.TLS = TLSConfig{}
	_, err := NewDamengFactoryWithRuntime(failingSQLOpener{err: errors.New("Dameng driver rejected password never-return-this-password")}, staticCatalog{}, resolver).Open(context.Background(), config)
	if err == nil {
		t.Fatal("Open() error = nil, want driver failure")
	}
	if strings.Contains(err.Error(), "never-return-this-password") || strings.Contains(strings.ToLower(err.Error()), "driver") {
		t.Fatalf("Open() leaked driver details: %v", err)
	}
}

func TestDamengFactoryBoundsOpenPingQueryAndClose(t *testing.T) {
	config := adapterTestConfig(DamengFamily)
	config.Address = "dm://db.example.test:5236"
	config.ConnectTimeout = 20 * time.Millisecond
	blocking := &blockingSQLOpener{}
	if _, err := NewDamengFactoryWithRuntime(blocking, staticCatalog{}, StaticSecretResolver{config.SecretRef: []byte("runtime-password")}).Open(context.Background(), config); err == nil {
		t.Fatal("Open() error = nil, want bounded opener timeout")
	}
	if !blocking.contextCancelled {
		t.Fatal("Dameng opener context was not cancelled at connect timeout")
	}

	template := DamengMetricTemplates()[0]
	state := &sqlDriverState{columns: append([]string(nil), template.ValueColumns...), rows: [][]driver.Value{{int64(4)}}}
	adapter, err := damengFactoryForTest(&fakeSQLOpener{db: newTestSQLDB(t, state)}, staticCatalog{}).Open(context.Background(), func() InstanceConfig {
		value := adapterTestConfig(DamengFamily)
		value.Address = "dm://db.example.test:5236"
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
	if _, err := adapter.QueryMetric(ctx, "DELETE FROM V$LOCK", nil); err == nil {
		t.Fatal("QueryMetric() error = nil, want policy mutation rejected as a metric ID")
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestDamengMetricTemplatesAreRegisteredReadOnlyAndBounded(t *testing.T) {
	templates := DamengMetricTemplates()
	wantIDs := []string{"dameng.sessions", "dameng.locks", "dameng.transactions", "dameng.storage", "dameng.slow_sql"}
	gotIDs := make([]string, 0, len(templates))
	for _, template := range templates {
		gotIDs = append(gotIDs, template.ID)
		if err := validateTemplate(template, template.ID); err != nil {
			t.Fatalf("template %q is not a bounded read-only metric: %v", template.ID, err)
		}
	}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("DamengMetricTemplates IDs = %q, want %q", gotIDs, wantIDs)
	}
	templates[0].ValueColumns[0] = "mutated"
	if got := DamengMetricTemplates()[0].ValueColumns[0]; got == "mutated" {
		t.Fatal("DamengMetricTemplates returned shared template state")
	}
}

func damengFactoryForTest(opener SQLOpener, catalog TemplateCatalog) Factory {
	return NewDamengFactoryWithRuntime(opener, catalog, adapterTestResolver())
}
