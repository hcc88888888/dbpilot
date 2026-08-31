package agentcontrol

import (
	"bytes"
	"context"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/credentiallease"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCredentialLeaseRequestUsesAuthenticatedLiveSessionAndNeverCommandPersistence(t *testing.T) {
	issuer := &recordingCredentialLeaseIssuer{}
	registry := NewRegistry(8)
	server := NewServer(registry, NoopObserver{}, WithCredentialLeaseIssuer(issuer))
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "plugin.reconcile.v1", "plugin_reconcile.instance_descriptors.v1", "credential_lease.v1"))
	done := make(chan error, 1)
	go func() { done <- server.Connect(stream) }()
	require.NotNil(t, stream.nextSent(t).GetHelloAck())
	require.Eventually(t, func() bool { _, ok := registry.Session("agent-a"); return ok }, time.Second, time.Millisecond)
	nonce := bytes.Repeat([]byte{0x44}, 32)
	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CredentialLeaseRequest{CredentialLeaseRequest: &agentv1.CredentialLeaseRequest{RequestNonce: nonce, InstanceId: "instance-1", AssignmentId: "assignment-1", ConfigurationRevision: 5}}})
	require.Equal(t, "lease-1", stream.nextSent(t).GetCredentialLeaseResponse().GetLeaseId())
	require.Equal(t, "agent-a", issuer.agent.AgentID)
	require.NotEmpty(t, issuer.agent.SessionID)
	stream.closeReceive()
	require.NoError(t, <-done)
}

type recordingCredentialLeaseIssuer struct {
	agent credentiallease.AuthenticatedAgent
}

func (issuer *recordingCredentialLeaseIssuer) Issue(_ context.Context, agent credentiallease.AuthenticatedAgent, request *agentv1.CredentialLeaseRequest) (*agentv1.CredentialLeaseResponse, error) {
	issuer.agent = agent
	return &agentv1.CredentialLeaseResponse{RequestNonce: append([]byte(nil), request.GetRequestNonce()...), LeaseId: "lease-1", InstanceId: request.GetInstanceId(), AssignmentId: request.GetAssignmentId(), CredentialRevision: 9, ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)), Credential: &agentv1.CredentialMaterial{Username: "monitor", SecretBytes: []byte("fixture-password")}}, nil
}
