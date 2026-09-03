package agentcontrol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPluginArtifactLeaseIssuerAuthorizesExactAssignmentVersionAndIsNonceIdempotent(t *testing.T) {
	fixture := newLeaseIssuerFixture(t)
	request := &agentv1.PluginArtifactLeaseRequest{RequestNonce: bytes.Repeat([]byte{1}, 32), AssignmentId: "assignment-1", ArtifactId: "artifact-1", OperationRevision: 7}
	first, err := fixture.issuer.Issue(context.Background(), "agent-1", request)
	require.NoError(t, err)
	second, err := fixture.issuer.Issue(context.Background(), "agent-1", request)
	require.NoError(t, err)
	require.Equal(t, first, second)
	require.Equal(t, "https://dbpilot.internal/api/v1/agent/plugin-artifacts/"+first.GetLeaseId(), first.GetDownloadUrl())
	require.NotEmpty(t, first.GetRequestHeaders()["X-DBPilot-Artifact-Lease"])

	conflict := proto.Clone(request).(*agentv1.PluginArtifactLeaseRequest)
	conflict.ArtifactId = "artifact-other"
	_, err = fixture.issuer.Issue(context.Background(), "agent-1", conflict)
	require.ErrorIs(t, err, ErrPluginArtifactLeaseRejected)
}

func TestPluginArtifactLeaseIssuerRejectsCrossAgentStaleOperationAndRevokedVersion(t *testing.T) {
	fixture := newLeaseIssuerFixture(t)
	request := &agentv1.PluginArtifactLeaseRequest{RequestNonce: bytes.Repeat([]byte{2}, 32), AssignmentId: "assignment-1", ArtifactId: "artifact-1", OperationRevision: 7}
	for _, name := range []string{"cross agent", "stale operation", "revoked version", "artifact digest"} {
		t.Run(name, func(t *testing.T) {
			copyFixture := fixture.clone(t)
			copyFixture.authorizer.reject = true
			_, err := copyFixture.issuer.Issue(context.Background(), "agent-1", request)
			require.ErrorIs(t, err, ErrPluginArtifactLeaseRejected)
		})
	}
}

func TestPluginArtifactLeaseHTTPHandlerBindsTLSAgentAndRevalidatesOperation(t *testing.T) {
	fixture := newLeaseIssuerFixture(t)
	request := &agentv1.PluginArtifactLeaseRequest{RequestNonce: bytes.Repeat([]byte{3}, 32), AssignmentId: "assignment-1", ArtifactId: "artifact-1", OperationRevision: 7}
	lease, err := fixture.issuer.Issue(context.Background(), "agent-1", request)
	require.NoError(t, err)
	handler, err := NewPluginArtifactLeaseHTTPHandler(fixture.issuer, fixture.blobs)
	require.NoError(t, err)

	httpRequest := httptest.NewRequest(http.MethodGet, lease.GetDownloadUrl(), nil)
	httpRequest.SetPathValue("leaseID", lease.GetLeaseId())
	httpRequest.Header.Set("X-DBPilot-Artifact-Lease", lease.GetRequestHeaders()["X-DBPilot-Artifact-Lease"])
	httpRequest.TLS = verifiedAgentTLSState(t, "agent-1")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httpRequest)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, fixture.body, recorder.Body.Bytes())
	require.Empty(t, recorder.Header().Get("Location"))

	fixture.authorizer.operationRevision++
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httpRequest)
	require.Equal(t, http.StatusForbidden, recorder.Code)

	crossAgent := httptest.NewRequest(http.MethodGet, lease.GetDownloadUrl(), nil)
	crossAgent.SetPathValue("leaseID", lease.GetLeaseId())
	crossAgent.Header = httpRequest.Header.Clone()
	crossAgent.TLS = verifiedAgentTLSState(t, "agent-other")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, crossAgent)
	require.Equal(t, http.StatusForbidden, recorder.Code)
}

func TestPluginArtifactLeaseHTTPHandlerRejectsRevokedLeafBeforeOpeningArtifact(t *testing.T) {
	fixture := newLeaseIssuerFixture(t)
	lease, err := fixture.issuer.Issue(context.Background(), "agent-1", &agentv1.PluginArtifactLeaseRequest{RequestNonce: bytes.Repeat([]byte{8}, 32), AssignmentId: "assignment-1", ArtifactId: "artifact-1", OperationRevision: 7})
	require.NoError(t, err)
	credentials := &recordingAgentCredentialAuthorizer{err: errors.New("old generation")}
	handler, err := NewPluginArtifactLeaseHTTPHandler(fixture.issuer, fixture.blobs, credentials)
	require.NoError(t, err)
	request := httptest.NewRequest(http.MethodGet, lease.GetDownloadUrl(), nil)
	request.SetPathValue("leaseID", lease.GetLeaseId())
	request.Header.Set(pluginArtifactLeaseHeader, lease.GetRequestHeaders()[pluginArtifactLeaseHeader])
	request.TLS = verifiedAgentTLSState(t, "agent-1")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.Equal(t, "agent-1", credentials.agentID)
}

func TestAgentControlRoutesLeaseRequestThroughAuthenticatedSession(t *testing.T) {
	registry := NewRegistry(4)
	require.NoError(t, registry.register("agent-1", []string{"plugin.reconcile.v1", "plugin_reconcile.instance_descriptors.v1"}, nil, func() {}))
	issuer := &recordingLeaseIssuer{response: &agentv1.PluginArtifactLeaseResponse{RequestNonce: bytes.Repeat([]byte{4}, 32), LeaseId: "lease-1"}}
	server := NewServer(registry, NoopObserver{}, WithPluginArtifactLeaseIssuer(issuer))
	request := &agentv1.PluginArtifactLeaseRequest{RequestNonce: bytes.Repeat([]byte{4}, 32), AssignmentId: "assignment-1", ArtifactId: "artifact-1", OperationRevision: 7}
	require.NoError(t, server.handleAgentMessage(context.Background(), "agent-1", &agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginArtifactLeaseRequest{PluginArtifactLeaseRequest: request}}))
	require.Equal(t, "agent-1", issuer.agentID)
	session, ok := registry.liveSession("agent-1")
	require.True(t, ok)
	select {
	case message := <-session.send:
		require.Equal(t, "lease-1", message.GetPluginArtifactLeaseResponse().GetLeaseId())
	case <-time.After(time.Second):
		t.Fatal("lease response was not routed to authenticated session")
	}
}

func TestPluginArtifactLeaseExecutionFenceExistsOnlyAfterLiveCommandStart(t *testing.T) {
	now := time.Now().UTC()
	registry := NewRegistry(4)
	registry.now = func() time.Time { return now }
	require.NoError(t, registry.register("agent-1", []string{"plugin.reconcile.v1", "plugin_reconcile.instance_descriptors.v1"}, nil, func() {}))
	require.False(t, registry.ExecutionLeaseActive("agent-1", "command-1", now))
	start := &agentv1.CommandStart{CommandId: "command-1", ExecutionToken: bytes.Repeat([]byte{8}, 32), LeaseRevision: 1, LeaseSeconds: 60, StartDeadline: timestamppb.New(now.Add(time.Minute))}
	require.NoError(t, registry.Start(context.Background(), "agent-1", start))
	require.True(t, registry.ExecutionLeaseActive("agent-1", "command-1", now))
	require.False(t, registry.ExecutionLeaseActive("agent-1", "command-1", now.Add(61*time.Second)))
}

func TestPluginArtifactLeaseRealMTLSServerServesOnlyBoundAgent(t *testing.T) {
	fixture := newLeaseIssuerFixture(t)
	lease, err := fixture.issuer.Issue(context.Background(), "agent-1", &agentv1.PluginArtifactLeaseRequest{RequestNonce: bytes.Repeat([]byte{5}, 32), AssignmentId: "assignment-1", ArtifactId: "artifact-1", OperationRevision: 7})
	require.NoError(t, err)
	handler, err := NewPluginArtifactLeaseHTTPHandler(fixture.issuer, fixture.blobs)
	require.NoError(t, err)
	ca, caKey, roots := testPluginLeaseCA(t)
	serverCertificate := testPluginLeaseCertificate(t, ca, caKey, "server", "", false)
	oldAgentCertificate := testPluginLeaseCertificate(t, ca, caKey, "agent-1-old", "agent-1", true)
	agentCertificate := testPluginLeaseCertificate(t, ca, caKey, "agent-1-current", "agent-1", true)
	leaf, err := x509.ParseCertificate(agentCertificate.Certificate[0])
	require.NoError(t, err)
	credentialAuthorizer := exactLeafAuthorizer{fingerprint: sha256.Sum256(leaf.Raw), serial: leaf.SerialNumber.Text(16)}
	handler, err = NewPluginArtifactLeaseHTTPHandler(fixture.issuer, fixture.blobs, credentialAuthorizer)
	require.NoError(t, err)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	oldClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{oldAgentCertificate}, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	request, err := http.NewRequest(http.MethodGet, server.URL+pluginArtifactPathPrefix+lease.GetLeaseId(), nil)
	require.NoError(t, err)
	request.Header.Set(pluginArtifactLeaseHeader, lease.GetRequestHeaders()[pluginArtifactLeaseHeader])
	oldResponse, err := oldClient.Do(request.Clone(context.Background()))
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, oldResponse.StatusCode)
	require.NoError(t, oldResponse.Body.Close())

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{agentCertificate}, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	response, err := client.Do(request)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusOK, response.StatusCode)
	require.Equal(t, fixture.body, body)

	noCertificate := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	_, err = noCertificate.Do(request.Clone(context.Background()))
	require.Error(t, err)
}

type exactLeafAuthorizer struct {
	fingerprint [sha256.Size]byte
	serial      string
}

func (authorizer exactLeafAuthorizer) AuthorizeAgentCredential(_ context.Context, _ string, fingerprint [sha256.Size]byte, serial string) error {
	if fingerprint != authorizer.fingerprint || serial != authorizer.serial {
		return errors.New("credential is not current")
	}
	return nil
}

type leaseIssuerFixture struct {
	issuer     *PluginArtifactLeaseIssuer
	scope      platformscope.Scope
	artifact   artifact.Artifact
	body       []byte
	blobs      leaseFixtureBlobStore
	authorizer *leaseFixtureAuthorizer
}

func newLeaseIssuerFixture(t *testing.T) *leaseIssuerFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	scope := platformscope.Scope{TenantID: "tenant-1", ProjectID: "project-1"}
	body := []byte("immutable signed plugin package")
	digest := sha256.Sum256(body)
	artifactValue := artifact.Artifact{ID: "artifact-1", Scope: scope, Kind: "plugin-package", ContentType: "application/gzip", SizeBytes: int64(len(body)), Checksum: "sha256:" + hex.EncodeToString(digest[:]), SourceResource: artifact.ResourceReference{ResourceType: "plugin_catalog_operation", ResourceID: "plugin-operation-" + strings.Repeat("a", 32)}, CreatedAt: now, StorageReference: "sha256/blob"}
	authorizer := &leaseFixtureAuthorizer{agentID: "agent-1", assignmentID: "assignment-1", artifactID: "artifact-1", operationRevision: 7, artifact: artifactValue}
	fixture := &leaseIssuerFixture{scope: scope, artifact: artifactValue, body: body, authorizer: authorizer}
	fixture.blobs = leaseFixtureBlobStore{body: body}
	issuer, err := NewPluginArtifactLeaseIssuer(PluginArtifactLeaseIssuerConfig{Origin: "https://dbpilot.internal", HMACKey: bytes.Repeat([]byte{9}, 32), TTL: time.Minute, MaximumLeases: 32, Authorizer: authorizer, Now: func() time.Time { return now }})
	require.NoError(t, err)
	fixture.issuer = issuer
	return fixture
}

func (fixture *leaseIssuerFixture) clone(t *testing.T) *leaseIssuerFixture {
	t.Helper()
	copyFixture := *fixture
	authorizerCopy := *fixture.authorizer
	copyFixture.authorizer = &authorizerCopy
	issuer, err := NewPluginArtifactLeaseIssuer(PluginArtifactLeaseIssuerConfig{Origin: "https://dbpilot.internal", HMACKey: bytes.Repeat([]byte{9}, 32), TTL: time.Minute, MaximumLeases: 32, Authorizer: &authorizerCopy, Now: fixture.issuer.now})
	require.NoError(t, err)
	copyFixture.issuer = issuer
	return &copyFixture
}

type leaseFixtureAuthorizer struct {
	agentID           string
	assignmentID      string
	artifactID        string
	operationRevision uint64
	artifact          artifact.Artifact
	reject            bool
}

func (authorizer *leaseFixtureAuthorizer) AuthorizePluginArtifact(_ context.Context, agentID, assignmentID, artifactID string, operationRevision uint64) (PluginArtifactGrant, error) {
	if authorizer.reject || agentID != authorizer.agentID || assignmentID != authorizer.assignmentID || artifactID != authorizer.artifactID || operationRevision != authorizer.operationRevision {
		return PluginArtifactGrant{}, ErrPluginArtifactLeaseRejected
	}
	return PluginArtifactGrant{AgentID: agentID, AssignmentID: assignmentID, ArtifactID: artifactID, OperationRevision: operationRevision, Artifact: authorizer.artifact}, nil
}

type leaseFixtureBlobStore struct{ body []byte }

func (store leaseFixtureBlobStore) Open(context.Context, artifact.Artifact) (artifact.ReadSeekCloser, error) {
	return &memoryReadSeekCloser{Reader: bytes.NewReader(store.body)}, nil
}

type memoryReadSeekCloser struct{ *bytes.Reader }

func (*memoryReadSeekCloser) Close() error { return nil }

func verifiedAgentTLSState(t *testing.T, agentID string) *tls.ConnectionState {
	t.Helper()
	identity, err := url.Parse("spiffe://dbpilot.local/agent/" + agentID)
	require.NoError(t, err)
	certificate := &x509.Certificate{Raw: []byte("plugin-artifact-test-leaf-" + agentID), SerialNumber: big.NewInt(7), URIs: []*url.URL{identity}}
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}
}

func testPluginLeaseCA(t *testing.T) (*x509.Certificate, ed25519.PrivateKey, *x509.CertPool) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DBPilot test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(encoded)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return certificate, privateKey, roots
}

func testPluginLeaseCertificate(t *testing.T, ca *x509.Certificate, caKey ed25519.PrivateKey, commonName, agentID string, client bool) tls.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: commonName}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if client {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		identity, parseErr := url.Parse("spiffe://dbpilot.local/agent/" + agentID)
		require.NoError(t, parseErr)
		template.URIs = []*url.URL{identity}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, ca, publicKey, caKey)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{encoded, ca.Raw}, PrivateKey: privateKey}
}

func stringsOfByte(value byte, count int) string { return string(bytes.Repeat([]byte{value}, count)) }

type recordingLeaseIssuer struct {
	agentID  string
	response *agentv1.PluginArtifactLeaseResponse
	err      error
}

func (issuer *recordingLeaseIssuer) Issue(_ context.Context, agentID string, _ *agentv1.PluginArtifactLeaseRequest) (*agentv1.PluginArtifactLeaseResponse, error) {
	issuer.agentID = agentID
	return issuer.response, issuer.err
}

var _ io.Reader = (*memoryReadSeekCloser)(nil)
