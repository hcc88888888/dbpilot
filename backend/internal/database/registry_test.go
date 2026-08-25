package database

import (
	"context"
	"testing"
	"time"
)

func TestRegistryRejectsDuplicateFamily(t *testing.T) {
	registry := NewRegistry()
	factory := &fakeFactory{capabilities: CapabilityMatrix{Metrics: true}}

	if err := registry.Register(MySQLFamily, factory); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if err := registry.Register(MySQLFamily, factory); err == nil {
		t.Fatal("Register() error = nil, want duplicate-family rejection")
	}
}

func TestRegistryOpenRejectsUnsupportedFamily(t *testing.T) {
	registry := NewRegistry()

	if _, err := registry.Open(context.Background(), validInstanceConfig()); err == nil {
		t.Fatal("Open() error = nil, want unsupported-family rejection")
	}
}

func TestRegistryOpenRejectsInvalidInstanceConfig(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(MySQLFamily, &fakeFactory{}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*InstanceConfig)
	}{
		{
			name: "missing instance ID",
			mutate: func(config *InstanceConfig) {
				config.ID = ""
			},
		},
		{
			name: "missing secret reference",
			mutate: func(config *InstanceConfig) {
				config.SecretRef = ""
			},
		},
		{
			name: "malformed secret reference",
			mutate: func(config *InstanceConfig) {
				config.SecretRef = "production-password"
			},
		},
		{
			name: "address is not an absolute URL",
			mutate: func(config *InstanceConfig) {
				config.Address = "db.example.test:3306"
			},
		},
		{
			name: "address has no port",
			mutate: func(config *InstanceConfig) {
				config.Address = "mysql://db.example.test"
			},
		},
		{
			name: "zero connect timeout",
			mutate: func(config *InstanceConfig) {
				config.ConnectTimeout = 0
			},
		},
		{
			name: "query timeout exceeds bound",
			mutate: func(config *InstanceConfig) {
				config.QueryTimeout = 61 * time.Second
			},
		},
		{
			name: "TLS CA is not a secret reference",
			mutate: func(config *InstanceConfig) {
				config.TLS.CASecretRef = "ca.pem"
			},
		},
		{
			name: "TLS certificate is not a secret reference",
			mutate: func(config *InstanceConfig) {
				config.TLS.CertificateSecretRef = "-----BEGIN CERTIFICATE-----"
			},
		},
		{
			name: "TLS key is not a secret reference",
			mutate: func(config *InstanceConfig) {
				config.TLS.KeySecretRef = "-----BEGIN PRIVATE KEY-----"
			},
		},
		{
			name: "TLS certificate has no key",
			mutate: func(config *InstanceConfig) {
				config.TLS.CertificateSecretRef = "secret://runtime/client-cert"
			},
		},
		{
			name: "TLS key has no certificate",
			mutate: func(config *InstanceConfig) {
				config.TLS.KeySecretRef = "secret://runtime/client-key"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validInstanceConfig()
			test.mutate(&config)

			if _, err := registry.Open(context.Background(), config); err == nil {
				t.Fatal("Open() error = nil, want invalid-config rejection")
			}
		})
	}
}

func TestRegistryOpenAcceptsPairedTLSSecretReferences(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(MySQLFamily, &fakeFactory{}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	config := validInstanceConfig()
	config.TLS = TLSConfig{
		CASecretRef:          "secret://runtime/ca",
		CertificateSecretRef: "secret://runtime/client-cert",
		KeySecretRef:         "secret://runtime/client-key",
	}

	if _, err := registry.Open(context.Background(), config); err != nil {
		t.Fatalf("Open() error = %v, want paired TLS secret references accepted", err)
	}
}

func TestRegistryOpenRejectsNonCanonicalSecretReferences(t *testing.T) {
	registry := NewRegistry()
	if err := registry.Register(MySQLFamily, &fakeFactory{}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*InstanceConfig)
	}{
		{
			name: "credential reference has no provider",
			mutate: func(config *InstanceConfig) {
				config.SecretRef = "secret:///db-primary"
			},
		},
		{
			name: "credential reference has no name",
			mutate: func(config *InstanceConfig) {
				config.SecretRef = "secret://runtime/"
			},
		},
		{
			name: "credential reference has no path",
			mutate: func(config *InstanceConfig) {
				config.SecretRef = "secret://runtime"
			},
		},
		{
			name: "credential reference has extra path segments",
			mutate: func(config *InstanceConfig) {
				config.SecretRef = "secret://runtime/db-primary/secondary"
			},
		},
		{
			name: "credential reference has a query",
			mutate: func(config *InstanceConfig) {
				config.SecretRef = "secret://runtime/db-primary?version=1"
			},
		},
		{
			name: "credential reference has a fragment",
			mutate: func(config *InstanceConfig) {
				config.SecretRef = "secret://runtime/db-primary#current"
			},
		},
		{
			name: "credential reference has credentials",
			mutate: func(config *InstanceConfig) {
				config.SecretRef = "secret://user@runtime/db-primary"
			},
		},
		{
			name: "TLS CA reference has no name",
			mutate: func(config *InstanceConfig) {
				config.TLS.CASecretRef = "secret://runtime/"
			},
		},
		{
			name: "TLS certificate reference has extra path segments",
			mutate: func(config *InstanceConfig) {
				config.TLS.CertificateSecretRef = "secret://runtime/client/cert"
				config.TLS.KeySecretRef = "secret://runtime/client-key"
			},
		},
		{
			name: "TLS key reference has extra path segments",
			mutate: func(config *InstanceConfig) {
				config.TLS.CertificateSecretRef = "secret://runtime/client-cert"
				config.TLS.KeySecretRef = "secret://runtime/client/key"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validInstanceConfig()
			test.mutate(&config)

			if _, err := registry.Open(context.Background(), config); err == nil {
				t.Fatal("Open() error = nil, want malformed secret reference rejection")
			}
		})
	}
}

func TestRegistryRejectsTypedNilFactory(t *testing.T) {
	registry := NewRegistry()
	var factory nilFactoryFunc

	if err := registry.Register(MySQLFamily, factory); err == nil {
		t.Fatal("Register() error = nil, want typed-nil factory rejection")
	}
}

func TestRegistryOpenRejectsTypedNilAdapter(t *testing.T) {
	registry := NewRegistry()
	var adapter nilAdapterFunc
	if err := registry.Register(MySQLFamily, &fakeFactory{adapter: adapter}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if _, err := registry.Open(context.Background(), validInstanceConfig()); err == nil {
		t.Fatal("Open() error = nil, want typed-nil adapter rejection")
	}
}

func TestCapabilityCopiesAreImmutable(t *testing.T) {
	registry := NewRegistry()
	factory := &fakeFactory{capabilities: CapabilityMatrix{
		ReadOnlySQL: true,
		Metrics:     true,
		MetricIDs:   []string{"db.connections"},
	}}
	if err := registry.Register(MySQLFamily, factory); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	factory.capabilities.MetricIDs[0] = "mutated-after-registration"
	capabilities, ok := registry.Capabilities(MySQLFamily)
	if !ok {
		t.Fatal("Capabilities() found = false, want true")
	}
	if got, want := capabilities.MetricIDs[0], "db.connections"; got != want {
		t.Fatalf("registered MetricIDs[0] = %q, want %q", got, want)
	}

	capabilities.MetricIDs[0] = "mutated-by-caller"
	capabilities, ok = registry.Capabilities(MySQLFamily)
	if !ok {
		t.Fatal("Capabilities() found = false, want true")
	}
	if got, want := capabilities.MetricIDs[0], "db.connections"; got != want {
		t.Fatalf("returned MetricIDs[0] = %q, want defensive copy %q", got, want)
	}
}

func TestRegistryOpenReturnsAdapterForCallerToClose(t *testing.T) {
	adapter := &fakeAdapter{}
	factory := &fakeFactory{adapter: adapter}
	registry := NewRegistry()
	if err := registry.Register(MySQLFamily, factory); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	opened, err := registry.Open(context.Background(), validInstanceConfig())
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if opened != adapter {
		t.Fatal("Open() returned a different adapter than the factory created")
	}
	if factory.opened.ID != "db-primary" {
		t.Fatalf("factory received instance ID %q, want db-primary", factory.opened.ID)
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got, want := adapter.closeCalls, 1; got != want {
		t.Fatalf("Close() calls = %d, want %d", got, want)
	}
}

func validInstanceConfig() InstanceConfig {
	return InstanceConfig{
		ID:             "db-primary",
		Family:         MySQLFamily,
		Address:        "mysql://db.example.test:3306",
		Database:       "app",
		User:           "readonly",
		SecretRef:      "secret://runtime/db-primary",
		ConnectTimeout: 5 * time.Second,
		QueryTimeout:   15 * time.Second,
	}
}

type fakeFactory struct {
	adapter      Adapter
	capabilities CapabilityMatrix
	opened       InstanceConfig
}

func (f *fakeFactory) Capabilities() CapabilityMatrix { return f.capabilities }

func (f *fakeFactory) Open(_ context.Context, config InstanceConfig) (Adapter, error) {
	f.opened = config
	if f.adapter == nil {
		f.adapter = &fakeAdapter{}
	}
	return f.adapter, nil
}

type fakeAdapter struct {
	closeCalls int
}

func (*fakeAdapter) Family() EngineFamily { return MySQLFamily }

func (*fakeAdapter) Capabilities() CapabilityMatrix { return CapabilityMatrix{} }

func (*fakeAdapter) Ping(context.Context) error { return nil }

func (*fakeAdapter) QueryMetric(context.Context, string, map[string]any) ([]MetricRow, error) {
	return nil, nil
}

func (f *fakeAdapter) Close() error {
	f.closeCalls++
	return nil
}

type nilFactoryFunc func()

func (nilFactoryFunc) Capabilities() CapabilityMatrix { return CapabilityMatrix{} }

func (nilFactoryFunc) Open(context.Context, InstanceConfig) (Adapter, error) {
	return &fakeAdapter{}, nil
}

type nilAdapterFunc func()

func (nilAdapterFunc) Family() EngineFamily { return MySQLFamily }

func (nilAdapterFunc) Capabilities() CapabilityMatrix { return CapabilityMatrix{} }

func (nilAdapterFunc) Ping(context.Context) error { return nil }

func (nilAdapterFunc) QueryMetric(context.Context, string, map[string]any) ([]MetricRow, error) {
	return nil, nil
}

func (nilAdapterFunc) Close() error { return nil }
