package agentcontrol

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestConnectRejectsCredentialThatIsNotTheCurrentPersistedLeaf(t *testing.T) {
	authorizer := &recordingAgentCredentialAuthorizer{err: errors.New("credential revoked")}
	server := NewServer(NewRegistry(1), NoopObserver{}, WithAgentCredentialAuthorizer(authorizer))
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))

	err := server.Connect(stream)

	require.Equal(t, codes.Unauthenticated, status.Code(err))
	require.Equal(t, "agent-a", authorizer.agentID)
	require.NotEqual(t, [sha256.Size]byte{}, authorizer.fingerprint)
	require.NotEmpty(t, authorizer.serial)
}

func TestRegistryTerminateCancelsLiveSessionAndDropsQueuedCommands(t *testing.T) {
	registry := NewRegistry(2)
	cancelled := make(chan struct{}, 1)
	require.NoError(t, registry.register("agent-a", []string{"collect_now"}, nil, func() { cancelled <- struct{}{} }))
	current, ok := registry.liveSession("agent-a")
	require.True(t, ok)
	now := time.Now().UTC()
	registry.now = func() time.Time { return now }
	envelope := &agentv1.CommandEnvelope{CommandId: "command-a", AgentId: "agent-a", ExpiresAt: timestamppb.New(now.Add(time.Minute)), Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"health"}}}}
	require.NoError(t, registry.Dispatch(context.Background(), "agent-a", envelope))
	require.Len(t, current.send, 1)

	require.True(t, registry.Terminate("agent-a"))
	require.Empty(t, current.send)
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("session cancellation was not delivered")
	}
	_, ok = registry.Session("agent-a")
	require.False(t, ok)
	require.False(t, registry.Terminate("agent-a"), "termination is idempotent")
}

func TestRegistryTerminatesOnlySupersededCredentialAndPreservesNewCertificateRace(t *testing.T) {
	registry := NewRegistry(1)
	oldFingerprint := sha256.Sum256([]byte("old-leaf"))
	newFingerprint := sha256.Sum256([]byte("new-leaf"))
	cancelled := make(chan struct{}, 1)
	require.NoError(t, registry.registerCredential("agent-a", []string{"collect_now"}, nil, oldFingerprint, "01", func() { cancelled <- struct{}{} }))

	require.False(t, registry.TerminateSuperseded("agent-a", oldFingerprint), "the committed active leaf must never terminate its own session")
	_, ok := registry.Session("agent-a")
	require.True(t, ok)
	require.True(t, registry.TerminateSuperseded("agent-a", newFingerprint), "the prior leaf must be cancelled after replacement commits")
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("superseded session cancellation was not delivered")
	}
}

func TestAgentControlOldLeafReconnectFailsAfterReplacementAndCurrentLeafFailsAfterDecommission(t *testing.T) {
	ca, caKey, _ := testPluginLeaseCA(t)
	oldCertificate := testPluginLeaseCertificate(t, ca, caKey, "agent-old", "agent-a", true)
	currentCertificate := testPluginLeaseCertificate(t, ca, caKey, "agent-current", "agent-a", true)
	currentLeaf, err := x509.ParseCertificate(currentCertificate.Certificate[0])
	require.NoError(t, err)
	authorizer := &mutableCredentialAuthorizer{fingerprint: sha256.Sum256(currentLeaf.Raw), serial: currentLeaf.SerialNumber.Text(16)}
	server := NewServer(NewRegistry(1), NoopObserver{}, WithAgentCredentialAuthorizer(authorizer))

	old := newTestConnectStream(tlsContextForLeaf(t, oldCertificate), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	require.Equal(t, codes.Unauthenticated, status.Code(server.Connect(old)))
	current := newTestConnectStream(tlsContextForLeaf(t, currentCertificate), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	current.closeReceive()
	require.NoError(t, server.Connect(current))

	authorizer.revoked = true
	decommissioned := newTestConnectStream(tlsContextForLeaf(t, currentCertificate), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	require.Equal(t, codes.Unauthenticated, status.Code(server.Connect(decommissioned)))
}

type mutableCredentialAuthorizer struct {
	fingerprint [sha256.Size]byte
	serial      string
	revoked     bool
}

func (authorizer *mutableCredentialAuthorizer) AuthorizeAgentCredential(_ context.Context, _ string, fingerprint [sha256.Size]byte, serial string) error {
	if authorizer.revoked || fingerprint != authorizer.fingerprint || serial != authorizer.serial {
		return errors.New("credential inactive")
	}
	return nil
}

func tlsContextForLeaf(t *testing.T, certificate tls.Certificate) context.Context {
	t.Helper()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	require.NoError(t, err)
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
	return peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
}

type recordingAgentCredentialAuthorizer struct {
	agentID     string
	fingerprint [sha256.Size]byte
	serial      string
	err         error
}

func (authorizer *recordingAgentCredentialAuthorizer) AuthorizeAgentCredential(_ context.Context, agentID string, fingerprint [sha256.Size]byte, serial string) error {
	authorizer.agentID, authorizer.fingerprint, authorizer.serial = agentID, fingerprint, serial
	return authorizer.err
}
