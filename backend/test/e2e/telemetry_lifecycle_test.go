package e2e_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	telemetryv1 "dbpilot.local/platform/gen/telemetry/v1"
	"dbpilot.local/platform/internal/exporter"
	"dbpilot.local/platform/internal/ingest"
	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"dbpilot.local/platform/internal/telemetry"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestTelemetryLifecycleRetainsFailedBatchesAcrossRestartAndDeliversViaMTLS(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, os.RemoveAll("dbpilot-spool")) })
	directory := t.TempDir()
	logPath := filepath.Join(directory, "application.log")
	require.NoError(t, os.WriteFile(logPath, []byte("runtime collection "+time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600))

	store, err := spool.Open(filepath.Join(directory, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 512})
	require.NoError(t, err)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	envelope, err := policy.Sign(private, policy.Policy{AgentID: "agent-a", Version: 1, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Sources: []policy.Source{{ID: "file-log", Kind: policy.SourceFileLog, Path: logPath, Interval: 5 * time.Second, Params: map[string]string{"start_at": "beginning"}}}, Limits: policy.Limits{MaxSpoolBytes: 1 << 20, MaxBatchBytes: 1 << 16, MaxEventsPerSec: 100}})
	require.NoError(t, err)
	signedPolicy, err := policy.Verify(public, envelope, time.Now())
	require.NoError(t, err)
	engine := telemetry.NewEngine(telemetry.NewEmbeddedBuilder(store))
	result, err := engine.Apply(context.Background(), signedPolicy)
	require.NoError(t, err)
	require.Equal(t, telemetry.ApplyActive, result.State)
	require.Eventually(t, func() bool { return len(pending(t, store, spool.Log)) == 1 }, 5*time.Second, 20*time.Millisecond)

	failed := exporter.NewClient(unavailableIngest{}, store, "agent-a")
	failedCtx, cancelFailed := context.WithTimeout(context.Background(), 5*time.Millisecond)
	err = failed.SendPending(failedCtx)
	cancelFailed()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, engine.Stop(context.Background()))
	require.NoError(t, store.Close())

	store, err = spool.Open(filepath.Join(directory, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 512})
	require.NoError(t, err)
	defer store.Close()
	client, service, closeGateway := startMTLSGateway(t)
	defer closeGateway()
	require.NoError(t, exporter.NewClient(client, store, "agent-a").SendPending(context.Background()))
	require.Empty(t, pending(t, store, spool.Log))
	received := service.ReceivedBatches()
	require.Len(t, received, 1)
	for _, batch := range received {
		require.Equal(t, "agent-a", batch.AgentID)
		require.Equal(t, "file-log", batch.SourceID)
	}
	assertClosedPolicySurface(t)
}

func pending(t *testing.T, store *spool.Store, class spool.DataClass) []spool.Batch {
	t.Helper()
	value, err := store.Pending(context.Background(), class, 10)
	require.NoError(t, err)
	return value
}

func assertClosedPolicySurface(t *testing.T) {
	t.Helper()
	for _, forbidden := range []string{"Command", "Executable", "Shell", "RawYAML", "VectorConfig", "OTelConfig"} {
		_, exists := reflect.TypeOf(policy.Source{}).FieldByName(forbidden)
		require.False(t, exists, "policy source must not expose %s", forbidden)
	}
}

type unavailableIngest struct{}

func (unavailableIngest) PushLogBatch(context.Context, *telemetryv1.LogBatch, ...grpc.CallOption) (*telemetryv1.BatchAck, error) {
	return nil, status.Error(codes.Unavailable, "temporary outage")
}
func (unavailableIngest) PushMetricBatch(context.Context, *telemetryv1.MetricBatch, ...grpc.CallOption) (*telemetryv1.BatchAck, error) {
	return nil, status.Error(codes.Unavailable, "temporary outage")
}
func (unavailableIngest) ReportPolicyStatus(context.Context, *telemetryv1.PolicyStatus, ...grpc.CallOption) (*telemetryv1.PolicyStatusAck, error) {
	return nil, errors.New("not implemented")
}

func startMTLSGateway(t *testing.T) (telemetryv1.TelemetryIngestClient, *ingest.Service, func()) {
	t.Helper()
	serverTLS, clientTLS := certificatePair(t)
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	service := ingest.NewService(ingest.AllowAnyVerifiedAgent{}, ingest.NewMemoryDeduplicator())
	telemetryv1.RegisterTelemetryIngestServer(server, service)
	go func() { _ = server.Serve(listener) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	connection, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)), grpc.WithBlock())
	cancel()
	require.NoError(t, err)
	return telemetryv1.NewTelemetryIngestClient(connection), service, func() { _ = connection.Close(); server.Stop(); _ = listener.Close() }
}

func certificatePair(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().Add(-time.Minute)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DBPilot Test CA"}, NotBefore: now, NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	require.NoError(t, err)
	caCertificate, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	server := signedCertificate(t, 2, "gateway", []string{"gateway"}, nil, caCertificate, caPrivate)
	client := signedCertificate(t, 3, "agent-a", nil, []string{"spiffe://dbpilot/agent/agent-a"}, caCertificate, caPrivate)
	pool := x509.NewCertPool()
	pool.AddCert(caCertificate)
	return &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}, &tls.Config{Certificates: []tls.Certificate{client}, RootCAs: pool, ServerName: "gateway", MinVersion: tls.VersionTLS12}
}

func signedCertificate(t *testing.T, serial int64, commonName string, dnsNames, uriStrings []string, ca *x509.Certificate, caKey ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: commonName}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: dnsNames, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	for _, raw := range uriStrings {
		uri, err := url.Parse(raw)
		require.NoError(t, err)
		template.URIs = append(template.URIs, uri)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
	require.NoError(t, err)
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	require.NoError(t, err)
	return certificate
}
