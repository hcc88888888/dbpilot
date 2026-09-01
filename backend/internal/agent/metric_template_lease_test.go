package agent

import (
	"bytes"
	"context"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/metrictemplatelease"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestControlClientMetricTemplateLeaseClampsExpiryAndPreservesTemplateID(t *testing.T) {
	now := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	client := newTransportTestClient(t, (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open)
	client.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	require.Eventually(t, func() bool {
		for _, message := range stream.sentMessages() {
			if message.GetHeartbeat() != nil {
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	digest := bytes.Repeat([]byte{0x51}, 32)
	result := make(chan struct {
		material metrictemplatelease.Material
		err      error
	}, 1)
	go func() {
		material, err := client.LeaseMetricTemplate(ctx, metrictemplatelease.Request{CommandID: "command-a", AssignmentID: "assignment-a", InstanceID: "instance-a", ConfigurationRevision: 5, OperationRevision: 7, TemplateID: "template-a", RevisionID: "revision-a", QueryDigest: digest})
		result <- struct {
			material metrictemplatelease.Material
			err      error
		}{material, err}
	}()
	var request *agentv1.MetricTemplateLeaseRequest
	require.Eventually(t, func() bool {
		for _, message := range stream.sentMessages() {
			if candidate := message.GetMetricTemplateLeaseRequest(); candidate != nil {
				request = candidate
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	query := []byte("SELECT value FROM metrics")
	response := &agentv1.MetricTemplateLeaseResponse{RequestNonce: request.GetRequestNonce(), LeaseId: "lease-a", CommandId: request.GetCommandId(), AssignmentId: request.GetAssignmentId(), InstanceId: request.GetInstanceId(), ConfigurationRevision: request.GetConfigurationRevision(), OperationRevision: request.GetOperationRevision(), TemplateId: request.GetTemplateId(), RevisionId: request.GetRevisionId(), QueryDigest: request.GetQueryDigest(), ExpiresAt: timestamppb.New(now.Add(time.Hour)), ValidForSeconds: 30, Definition: &agentv1.MetricTemplateDefinition{Revision: 3, QueryKind: "sql", ReadOnlyStatement: append([]byte(nil), query...), CollectionIntervalSeconds: 60, TimeoutSeconds: 5, MaxRows: 1, MaxColumns: 2, CardinalityLimit: 10, ValueMappings: []*agentv1.MetricTemplateValueMapping{{SourceColumn: "value", MetricName: "mysql.custom.value", MetricType: "gauge", Unit: "1"}}}}
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_MetricTemplateLeaseResponse{MetricTemplateLeaseResponse: response}}
	lease := <-result
	require.NoError(t, lease.err)
	require.Equal(t, "template-a", lease.material.TemplateID)
	require.Equal(t, "revision-a", lease.material.RevisionID)
	require.Equal(t, now.Add(30*time.Second), lease.material.ExpiresAt)
	require.Equal(t, query, []byte("SELECT value FROM metrics"), "fixture copy is independent of cleared wire bytes")
	require.Empty(t, response.GetDefinition().GetReadOnlyStatement(), "wire query is cleared after delivery")
	cancel()
	require.NoError(t, <-done)
}
