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

func TestMetricTemplateLeaseRequestUsesAuthenticatedLiveSession(t *testing.T) {
	issuer := &recordingMetricTemplateLeaseIssuer{}
	registry := NewRegistry(8)
	server := NewServer(registry, NoopObserver{}, WithMetricTemplateLeaseIssuer(issuer))
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "metric_template_lease.v1"))
	done := make(chan error, 1)
	go func() { done <- server.Connect(stream) }()
	require.NotNil(t, stream.nextSent(t).GetHelloAck())
	require.Eventually(t, func() bool { _, ok := registry.Session("agent-a"); return ok }, time.Second, time.Millisecond)
	nonce := bytes.Repeat([]byte{0x45}, 32)
	digest := bytes.Repeat([]byte{0x46}, 32)
	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_MetricTemplateLeaseRequest{MetricTemplateLeaseRequest: &agentv1.MetricTemplateLeaseRequest{RequestNonce: nonce, CommandId: "command-a", AssignmentId: "assignment-a", InstanceId: "instance-a", ConfigurationRevision: 5, OperationRevision: 7, TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: digest}}})
	response := stream.nextSent(t).GetMetricTemplateLeaseResponse()
	require.Equal(t, "lease-a", response.GetLeaseId())
	require.Equal(t, []byte("SELECT value FROM metrics"), response.GetDefinition().GetReadOnlyStatement())
	require.Equal(t, "agent-a", issuer.agent.AgentID)
	require.NotEmpty(t, issuer.agent.SessionID)
	stream.closeReceive()
	require.NoError(t, <-done)
}

func TestRegistryUnregisterZerosQueuedMetricTemplateQuery(t *testing.T) {
	registry := NewRegistry(4)
	require.NoError(t, registry.register("agent-a", nil, nil, func() {}))
	session, ok := registry.liveSession("agent-a")
	require.True(t, ok)
	query := []byte("SELECT queued_secret")
	require.NoError(t, registry.enqueue("agent-a", &agentv1.ServerMessage{Message: &agentv1.ServerMessage_MetricTemplateLeaseResponse{MetricTemplateLeaseResponse: &agentv1.MetricTemplateLeaseResponse{Definition: &agentv1.MetricTemplateDefinition{ReadOnlyStatement: query}}}}))
	registry.unregister("agent-a", session)
	require.Equal(t, make([]byte, len(query)), query)
}

func TestMetricTemplateLeaseResponseExpiryCannotExceedValidFor(t *testing.T) {
	now := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	request := &agentv1.MetricTemplateLeaseRequest{RequestNonce: bytes.Repeat([]byte{1}, 32), CommandId: "command-a", AssignmentId: "assignment-a", InstanceId: "instance-a", ConfigurationRevision: 5, OperationRevision: 7, TemplateId: "template-a", RevisionId: "revision-a", QueryDigest: bytes.Repeat([]byte{2}, 32)}
	response := &agentv1.MetricTemplateLeaseResponse{RequestNonce: append([]byte(nil), request.GetRequestNonce()...), LeaseId: "lease-a", CommandId: request.GetCommandId(), AssignmentId: request.GetAssignmentId(), InstanceId: request.GetInstanceId(), ConfigurationRevision: request.GetConfigurationRevision(), OperationRevision: request.GetOperationRevision(), TemplateId: request.GetTemplateId(), RevisionId: request.GetRevisionId(), QueryDigest: append([]byte(nil), request.GetQueryDigest()...), ExpiresAt: timestamppb.New(now.Add(time.Hour)), ValidForSeconds: 30, Definition: &agentv1.MetricTemplateDefinition{Revision: 1, QueryKind: "sql", ReadOnlyStatement: []byte("SELECT 1"), CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 1, CardinalityLimit: 1, ValueMappings: []*agentv1.MetricTemplateValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}}}
	require.False(t, validMetricTemplateLeaseResponse(response, request, now))
	response.ExpiresAt = timestamppb.New(now.Add(31 * time.Second))
	require.True(t, validMetricTemplateLeaseResponse(response, request, now))
}

type recordingMetricTemplateLeaseIssuer struct {
	agent credentiallease.AuthenticatedAgent
}

func (issuer *recordingMetricTemplateLeaseIssuer) Issue(_ context.Context, agent credentiallease.AuthenticatedAgent, request *agentv1.MetricTemplateLeaseRequest) (*agentv1.MetricTemplateLeaseResponse, error) {
	issuer.agent = agent
	return &agentv1.MetricTemplateLeaseResponse{RequestNonce: append([]byte(nil), request.GetRequestNonce()...), LeaseId: "lease-a", CommandId: request.GetCommandId(), AssignmentId: request.GetAssignmentId(), InstanceId: request.GetInstanceId(), ConfigurationRevision: request.GetConfigurationRevision(), OperationRevision: request.GetOperationRevision(), TemplateId: request.GetTemplateId(), RevisionId: request.GetRevisionId(), QueryDigest: append([]byte(nil), request.GetQueryDigest()...), ExpiresAt: timestamppb.New(time.Now().Add(30 * time.Second)), ValidForSeconds: 30, Definition: &agentv1.MetricTemplateDefinition{Revision: 1, QueryKind: "sql", ReadOnlyStatement: []byte("SELECT value FROM metrics"), CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, CardinalityLimit: 10, ValueMappings: []*agentv1.MetricTemplateValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}}}, nil
}
