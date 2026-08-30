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
	"sync"
	"testing"
	"time"

	telemetryv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent"
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
	directory := workingTreeTempDir(t)
	logPath := filepath.Join(directory, "application.log")
	require.NoError(t, os.WriteFile(logPath, []byte("runtime collection "+time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o600))

	store, err := spool.Open(filepath.Join(directory, "spool"), spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 512})
	require.NoError(t, err)
	firstStore := store
	t.Cleanup(func() { require.NoError(t, firstStore.Close()) })
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	envelope, err := policy.Sign(private, policy.Policy{AgentID: "agent-a", Version: 1, IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Sources: []policy.Source{{ID: "file-log", Kind: policy.SourceFileLog, Path: logPath, Interval: 5 * time.Second, Params: map[string]string{"start_at": "beginning"}}}, Limits: policy.Limits{MaxSpoolBytes: 1 << 20, MaxBatchBytes: 1 << 16, MaxEventsPerSec: 100}})
	require.NoError(t, err)
	verifier := agent.Verifier{PublicKey: public, Environment: policy.ValidationEnvironment{AllowedRoots: []string{directory}, ResolvePath: filepath.EvalSymlinks}}
	_, err = verifier.Verify(context.Background(), envelope)
	require.NoError(t, err, "test policy must be valid before starting the runtime")
	runCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reporter := newRecordingHealthReporter()
	appender := newNotifyingSpoolAppender(store)
	runtime := agent.NewRuntime(agent.Dependencies{
		AgentID: "agent-a", PolicySource: staticPolicySource{envelope: envelope},
		PolicyVerifier: verifier,
		Engine:         telemetry.NewEngine(telemetry.NewEmbeddedBuilder(appender)), Store: store,
		Exporter: exporter.NewClient(unavailableIngest{}, store, "agent-a"), HealthReporter: reporter,
		PollInterval: time.Hour, ExportInterval: time.Hour, ShutdownTimeout: 100 * time.Millisecond, OperationTimeout: 20 * time.Millisecond,
	})
	runDone := make(chan error, 1)
	runtimeExited := make(chan struct{})
	go func() {
		defer close(runtimeExited)
		runDone <- runtime.Run(runCtx)
	}()
	t.Cleanup(func() {
		cancel()
		<-runtimeExited
	})
	waitForRuntimeSignal(t, reporter.active, runDone, "active policy")
	waitForRuntimeSignal(t, appender.appended, runDone, "spooled log batch")
	require.Len(t, pending(t, store, spool.Log), 1)
	cancel()
	require.NoError(t, <-runDone)

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

func workingTreeTempDir(t *testing.T) string {
	t.Helper()
	workingDirectory, err := os.Getwd()
	require.NoError(t, err)
	directory, err := os.MkdirTemp(workingDirectory, ".telemetry-lifecycle-*")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(directory)) })
	return directory
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

type staticPolicySource struct{ envelope policy.SignatureEnvelope }

func (s staticPolicySource) Fetch(ctx context.Context) (policy.SignatureEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return policy.SignatureEnvelope{}, err
	}
	return s.envelope, nil
}

type recordingHealthReporter struct {
	once   sync.Once
	active chan struct{}
}

func newRecordingHealthReporter() *recordingHealthReporter {
	return &recordingHealthReporter{active: make(chan struct{})}
}

func (r *recordingHealthReporter) Report(_ context.Context, status agent.PolicyStatus) error {
	if status.State == string(telemetry.ApplyActive) {
		r.once.Do(func() { close(r.active) })
	}
	return nil
}

type notifyingSpoolAppender struct {
	store    *spool.Store
	once     sync.Once
	appended chan struct{}
}

func newNotifyingSpoolAppender(store *spool.Store) *notifyingSpoolAppender {
	return &notifyingSpoolAppender{store: store, appended: make(chan struct{})}
}

func (a *notifyingSpoolAppender) Append(ctx context.Context, class spool.DataClass, batch spool.Batch) error {
	if err := a.store.Append(ctx, class, batch); err != nil {
		return err
	}
	a.once.Do(func() { close(a.appended) })
	return nil
}

func waitForRuntimeSignal(t *testing.T, signal <-chan struct{}, runDone <-chan error, description string) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-signal:
	case err := <-runDone:
		require.NoError(t, err, "runtime exited before %s", description)
		require.FailNow(t, "runtime exited before "+description)
	case <-timer.C:
		require.FailNow(t, "timed out waiting for "+description)
	}
}

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
	client := signedCertificate(t, 3, "agent-a", nil, []string{"spiffe://dbpilot.local/agent/agent-a"}, caCertificate, caPrivate)
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
