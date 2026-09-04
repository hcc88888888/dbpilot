package agentcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/platformdb"
	"dbpilot.local/platform/internal/platformscope"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAgentCredentialPostgresMTLSReplacementRaceAndArtifactAdmission(t *testing.T) {
	if os.Getenv("DBPILOT_ENROLLMENT_POSTGRES_INTEGRATION") != "1" {
		t.Skip("set DBPILOT_ENROLLMENT_POSTGRES_INTEGRATION=1 to run")
	}
	dsn := os.Getenv("DBPILOT_ENROLLMENT_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("DBPILOT_ENROLLMENT_POSTGRES_DSN is required")
	}
	database, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, database.Close()) })
	ctx := context.Background()
	require.NoError(t, database.PingContext(ctx))
	require.NoError(t, platformdb.RunMigrations(ctx, database))
	require.NoError(t, hostinventory.RunMigrations(ctx, database))
	require.NoError(t, enrollment.RunMigrations(ctx, database))

	suffix := fmt.Sprintf("credential-race-%d", time.Now().UnixNano())
	scope := platformscope.Scope{TenantID: "tenant-" + suffix, ProjectID: "project-" + suffix}
	hostID, agentID := "host-"+suffix, "agent-"+suffix
	t.Cleanup(func() {
		_, _ = database.ExecContext(context.Background(), "DELETE FROM audit_events WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_issuances WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM host_observations WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM managed_hosts WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
		_, _ = database.ExecContext(context.Background(), "DELETE FROM agent_enrollment_tokens WHERE tenant_id=$1 AND project_id=$2", scope.TenantID, scope.ProjectID)
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	observation := hostinventory.Observation{
		HostID: hostID, AgentID: agentID, Revision: 1, AgentVersion: "integration", Hostname: "credential-race.example",
		OS: "linux", Architecture: "amd64", LogicalCPUCount: 2, MemoryCapacityBytes: 1 << 30,
		NetworkAddresses: []string{"127.0.0.1"}, Capabilities: []string{"collect_now"}, ObservedAt: now,
	}
	_, err = hostinventory.NewPostgresRepository(database).RecordEnrollment(ctx, scope, hostinventory.Enrollment{
		HostID: hostID, AgentID: agentID, DisplayName: "Credential race host", Labels: map[string]string{}, Revision: 1, EnrolledAt: now,
	}, observation, now)
	require.NoError(t, err)

	ca, caKey, roots := testPluginLeaseCA(t)
	serverCertificate := testPluginLeaseCertificate(t, ca, caKey, "server", "", false)
	oldCertificate := testPluginLeaseCertificate(t, ca, caKey, "old-"+suffix, agentID, true)
	currentCertificate := testPluginLeaseCertificate(t, ca, caKey, "current-"+suffix, agentID, true)
	oldLeaf := parsedTLSLeaf(t, oldCertificate)
	currentLeaf := parsedTLSLeaf(t, currentCertificate)
	activateCredential := func(generation uint64, leaf *x509.Certificate) {
		fingerprint := sha256.Sum256(leaf.Raw)
		result, updateErr := database.ExecContext(ctx, `UPDATE managed_hosts SET credential_generation=$1,active_certificate_fingerprint=$2,active_certificate_serial=$3,credential_revoked_at=NULL,version=version+1,updated_at=$4 WHERE tenant_id=$5 AND project_id=$6 AND host_id=$7 AND status<>'decommissioned'`, generation, fingerprint[:], leaf.SerialNumber.Text(16), now, scope.TenantID, scope.ProjectID, hostID)
		require.NoError(t, updateErr)
		rows, rowsErr := result.RowsAffected()
		require.NoError(t, rowsErr)
		require.Equal(t, int64(1), rows)
	}
	activateCredential(1, oldLeaf)

	repository := enrollment.NewPostgresRepository(database)
	barrier := &postgresCredentialBarrier{delegate: repository, called: make(chan struct{}, 8)}
	registry := NewRegistry(4)
	server := NewServer(registry, NoopObserver{}, WithAgentCredentialAuthorizer(barrier))
	oldStream := newTestConnectStream(tlsContextForLeaf(t, oldCertificate))
	connectResult := make(chan error, 1)
	go func() { connectResult <- server.Connect(oldStream) }()
	barrier.wait(t)
	activateCredential(2, currentLeaf)
	oldStream.push(helloMessage(agentID, ProtocolVersion, "collect_now"))
	oldStream.closeReceive()
	require.Equal(t, codes.Unauthenticated, status.Code(<-connectResult), "replacement in the pre-Hello window must reject the stale leaf")
	_, admitted := registry.Session(agentID)
	require.False(t, admitted)

	fixture := newLeaseIssuerFixture(t)
	fixture.authorizer.agentID = agentID
	lease, err := fixture.issuer.Issue(ctx, agentID, pluginArtifactLeaseRequest())
	require.NoError(t, err)
	handler, err := NewPluginArtifactLeaseHTTPHandler(fixture.issuer, fixture.blobs, repository)
	require.NoError(t, err)
	httpServer := httptest.NewUnstartedServer(handler)
	httpServer.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	httpServer.StartTLS()
	t.Cleanup(httpServer.Close)
	request, err := http.NewRequest(http.MethodGet, httpServer.URL+pluginArtifactPathPrefix+lease.GetLeaseId(), nil)
	require.NoError(t, err)
	request.Header.Set(pluginArtifactLeaseHeader, lease.GetRequestHeaders()[pluginArtifactLeaseHeader])
	require.Equal(t, http.StatusForbidden, artifactStatus(t, roots, oldCertificate, request), "replaced leaf must not download artifacts")
	require.Equal(t, http.StatusOK, artifactStatus(t, roots, currentCertificate, request), "current exact leaf may download artifacts")

	currentStream := newTestConnectStream(tlsContextForLeaf(t, currentCertificate), helloMessage(agentID, ProtocolVersion, "collect_now"))
	currentStream.closeReceive()
	require.NoError(t, server.Connect(currentStream))

	result, err := database.ExecContext(ctx, `UPDATE managed_hosts SET status='decommissioned',credential_generation=credential_generation+1,active_certificate_fingerprint=''::bytea,active_certificate_serial='',credential_revoked_at=$1,version=version+1,updated_at=$1 WHERE tenant_id=$2 AND project_id=$3 AND host_id=$4`, now.Add(time.Second), scope.TenantID, scope.ProjectID, hostID)
	require.NoError(t, err)
	rows, err := result.RowsAffected()
	require.NoError(t, err)
	require.Equal(t, int64(1), rows)
	require.Equal(t, http.StatusForbidden, artifactStatus(t, roots, currentCertificate, request), "decommissioned leaf must not download artifacts")
	decommissionedStream := newTestConnectStream(tlsContextForLeaf(t, currentCertificate), helloMessage(agentID, ProtocolVersion, "collect_now"))
	require.Equal(t, codes.Unauthenticated, status.Code(server.Connect(decommissionedStream)))
}

func parsedTLSLeaf(t *testing.T, certificate tls.Certificate) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	require.NoError(t, err)
	return leaf
}

func pluginArtifactLeaseRequest() *agentv1.PluginArtifactLeaseRequest {
	return &agentv1.PluginArtifactLeaseRequest{RequestNonce: make([]byte, sha256.Size), AssignmentId: "assignment-1", ArtifactId: "artifact-1", OperationRevision: 7}
}

func artifactStatus(t *testing.T, roots *x509.CertPool, certificate tls.Certificate, request *http.Request) int {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{certificate}, ServerName: "localhost", MinVersion: tls.VersionTLS12}}}
	response, err := client.Do(request.Clone(context.Background()))
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	return response.StatusCode
}

type postgresCredentialBarrier struct {
	delegate AgentCredentialAuthorizer
	called   chan struct{}
}

func (barrier *postgresCredentialBarrier) AuthorizeAgentCredential(ctx context.Context, agentID string, fingerprint [sha256.Size]byte, serial string) error {
	err := barrier.delegate.AuthorizeAgentCredential(ctx, agentID, fingerprint, serial)
	barrier.called <- struct{}{}
	return err
}

func (barrier *postgresCredentialBarrier) wait(t *testing.T) {
	t.Helper()
	select {
	case <-barrier.called:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for PostgreSQL credential authorization")
	}
}
