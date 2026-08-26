package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/require"
)

func TestExampleConfigurationStrictlyDecodes(t *testing.T) {
	config, err := loadConfig(filepath.Join("..", "..", "config", "controlplane.yaml.example"))
	require.NoError(t, err)
	require.Equal(t, 15*time.Second, config.EvaluationEvery)
	require.Equal(t, time.Minute, config.RetryEvery)
	require.Contains(t, config.Agents, "spiffe-agent-id")
}

func TestPostgresDeduplicatorFailsClosedWhenSharedStateIsUnavailable(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { mock.ExpectClose(); require.NoError(t, database.Close()) })
	mock.ExpectQuery("SELECT accepted").WithArgs("agent-1", "batch-1").WillReturnError(errors.New("database unavailable"))

	ack, found := (postgresBatchDeduplicator{database: database}).Lookup("agent-1", "batch-1")
	require.True(t, found)
	require.False(t, ack.Accepted)
	require.True(t, ack.Retryable)
	require.Equal(t, "DEDUP_UNAVAILABLE", ack.ErrorCode)
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

func validServerConfig() Config {
	return Config{
		DatabaseURL:      "postgres://dbpilot:password@localhost/dbpilot?sslmode=require",
		WebhookAllowlist: []string{"hooks.example.com"},
		HTTP:             ListenerConfig{Address: "127.0.0.1:8443", TLS: TLSMaterial{CertFile: "unused", KeyFile: "unused"}},
		GRPC:             ListenerConfig{Address: "127.0.0.1:9443", TLS: TLSMaterial{CertFile: "unused", KeyFile: "unused", ClientCAFile: "unused"}},
		HTTPServerTLS:    &tls.Config{MinVersion: tls.VersionTLS12},
		GRPCServerTLS:    &tls.Config{MinVersion: tls.VersionTLS12},
	}
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
