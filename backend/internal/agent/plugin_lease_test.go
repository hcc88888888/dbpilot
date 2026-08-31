package agent

import (
	"context"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"dbpilot.local/platform/internal/agent/pluginsupervisor"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestControlClientCorrelatesEphemeralPluginArtifactLeaseOnLiveStream(t *testing.T) {
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	client := newTransportTestClient(t, (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open)
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

	result := make(chan struct {
		lease pluginsupervisor.ArtifactLease
		err   error
	}, 1)
	go func() {
		lease, err := client.LeasePluginArtifact(ctx, pluginsupervisor.ArtifactLeaseRequest{AssignmentID: "assignment-1", ArtifactID: "artifact-1", OperationRevision: 9})
		result <- struct {
			lease pluginsupervisor.ArtifactLease
			err   error
		}{lease: lease, err: err}
	}()

	var request *agentv1.PluginArtifactLeaseRequest
	require.Eventually(t, func() bool {
		for _, message := range stream.sentMessages() {
			if candidate := message.GetPluginArtifactLeaseRequest(); candidate != nil {
				request = candidate
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	require.Len(t, request.GetRequestNonce(), 32)
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_PluginArtifactLeaseResponse{PluginArtifactLeaseResponse: &agentv1.PluginArtifactLeaseResponse{RequestNonce: request.GetRequestNonce(), LeaseId: "lease-1", AssignmentId: "assignment-1", ArtifactId: "artifact-1", OperationRevision: 9, ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)), DownloadUrl: "https://dbpilot.internal/api/v1/agent/plugin-artifacts/lease-1", RequestHeaders: map[string]string{"X-DBPilot-Artifact-Lease": "opaque-value"}}}}

	leaseResult := <-result
	require.NoError(t, leaseResult.err)
	require.Equal(t, "lease-1", leaseResult.lease.LeaseID)
	require.Equal(t, "opaque-value", leaseResult.lease.RequestHeaders["X-DBPilot-Artifact-Lease"])
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientRejectsMismatchedLeaseAndIgnoresLateUnknownResponse(t *testing.T) {
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	client := newTransportTestClient(t, (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	requestContext, requestCancel := context.WithTimeout(ctx, time.Second)
	defer requestCancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.LeasePluginArtifact(requestContext, pluginsupervisor.ArtifactLeaseRequest{AssignmentID: "assignment-1", ArtifactID: "artifact-1", OperationRevision: 9})
		result <- err
	}()
	var request *agentv1.PluginArtifactLeaseRequest
	require.Eventually(t, func() bool {
		for _, message := range stream.sentMessages() {
			if candidate := message.GetPluginArtifactLeaseRequest(); candidate != nil {
				request = candidate
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_PluginArtifactLeaseResponse{PluginArtifactLeaseResponse: &agentv1.PluginArtifactLeaseResponse{RequestNonce: request.GetRequestNonce(), LeaseId: "lease-secret-must-not-appear", AssignmentId: "assignment-other", ArtifactId: "artifact-1", OperationRevision: 9, ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)), DownloadUrl: "https://dbpilot.internal/artifact"}}}
	err := <-result
	require.ErrorIs(t, err, pluginsupervisor.ErrArtifactLease)
	require.NotContains(t, err.Error(), "lease-secret")

	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_PluginArtifactLeaseResponse{PluginArtifactLeaseResponse: &agentv1.PluginArtifactLeaseResponse{RequestNonce: make([]byte, 32), LeaseId: "late-lease"}}}
	time.Sleep(20 * time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

func TestControlClientEmitsBoundedPluginObservationWithHeartbeat(t *testing.T) {
	stream := newFakeControlStream()
	stream.receive <- helloAckMessage()
	client := newTransportTestClient(t, (&sequenceStreamOpener{streams: []ControlStream{stream}}).Open)
	client.pluginObservations = staticPluginObservationProvider{report: &agentv1.PluginObservation{HostId: "host-1", AgentId: "agent-a", ObservationRevision: 3, ObservedAt: timestamppb.Now(), Assignments: []*agentv1.PluginAssignmentObservation{}}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	require.Eventually(t, func() bool {
		for _, message := range stream.sentMessages() {
			if report := message.GetPluginObservation(); report != nil {
				return report.GetObservationRevision() == 3 && report.GetHostId() == "host-1"
			}
		}
		return false
	}, time.Second, time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

type staticPluginObservationProvider struct{ report *agentv1.PluginObservation }

func (provider staticPluginObservationProvider) Observation() *agentv1.PluginObservation {
	return provider.report
}
