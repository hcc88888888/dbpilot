package agentcontrol

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAgentControlRoutesAuthenticatedPluginObservation(t *testing.T) {
	observer := &recordingPluginObserver{}
	server := NewServer(NewRegistry(4), NoopObserver{}, WithPluginObserver(observer))
	report := &agentv1.PluginObservation{AgentId: "agent-a", HostId: "host-a", ObservationRevision: 1}
	err := server.handleAgentMessage(context.Background(), "agent-a", &agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginObservation{PluginObservation: report}})
	require.NoError(t, err)
	require.Same(t, report, observer.report)

	report.AgentId = "agent-b"
	err = server.handleAgentMessage(context.Background(), "agent-a", &agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginObservation{PluginObservation: report}})
	require.Error(t, err)
}

func TestAgentControlPluginObservationDeliveryErrorsDoNotTerminateMessageHandling(t *testing.T) {
	for _, submitErr := range []error{ErrPluginObservationCapacity, ErrPluginObservationClosed, errors.New("persistence unavailable")} {
		t.Run(submitErr.Error(), func(t *testing.T) {
			observer := &recordingObserver{}
			server := NewServer(NewRegistry(4), observer, WithPluginObserver(errorPluginObserver{err: submitErr}))
			report := &agentv1.PluginObservation{AgentId: "agent-a", HostId: "host-a", ObservationRevision: 1}

			require.NoError(t, server.handleAgentMessage(context.Background(), "agent-a", &agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginObservation{PluginObservation: report}}))
			require.NoError(t, server.handleAgentMessage(context.Background(), "agent-a", &agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: "agent-a"}}}))
			require.NoError(t, server.handleAgentMessage(context.Background(), "agent-a", &agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandAcknowledgement{CommandAcknowledgement: &agentv1.CommandAcknowledgement{CommandId: "command-a"}}}))
			require.Equal(t, [3]int{1, 0, 0}, observer.counts())
		})
	}
}

func TestAgentControlRejectsInvalidPluginObservationWithoutMislabelingPersistence(t *testing.T) {
	server := NewServer(NewRegistry(4), NoopObserver{}, WithPluginObserver(errorPluginObserver{err: ErrPluginObservationInvalid}))
	report := &agentv1.PluginObservation{AgentId: "agent-a", HostId: "host-a", ObservationRevision: 1}

	err := server.handleAgentMessage(context.Background(), "agent-a", &agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginObservation{PluginObservation: report}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestConnectKeepsHeartbeatAndCommandHealthyWhilePluginObservationLaneRecovers(t *testing.T) {
	sink := &controlledPluginSink{release: make(chan struct{}), delivered: make(chan string, 4)}
	dispatcher, err := NewPluginObservationDispatcher(sink, PluginObservationDispatcherConfig{MaximumPendingAgents: 2, DeliveryTimeout: 20 * time.Millisecond, RetryBackoff: time.Millisecond})
	require.NoError(t, err)
	defer dispatcher.Close()
	registry := NewRegistry(2)
	observer := &pluginStreamObserver{heartbeat: make(chan struct{}, 1)}
	server := NewServer(registry, observer, WithPluginObserver(dispatcher))
	stream := newTestConnectStream(tlsPeerContext(t, true, "spiffe://dbpilot.local/agent/agent-a"), helloMessage("agent-a", ProtocolVersion, "collect_now"))
	done := make(chan error, 1)
	go func() { done <- server.Connect(stream) }()
	_ = stream.nextSent(t)

	stream.push(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginObservation{PluginObservation: pluginReport("agent-a", 1)}})
	require.Equal(t, "agent-a:1", <-sink.delivered)
	time.Sleep(40 * time.Millisecond)
	stream.push(
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginObservation{PluginObservation: pluginReport("agent-a", 2)}},
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_PluginObservation{PluginObservation: pluginReport("agent-a", 3)}},
		&agentv1.AgentMessage{Message: &agentv1.AgentMessage_Heartbeat{Heartbeat: &agentv1.Heartbeat{AgentId: "agent-a"}}},
	)
	select {
	case <-observer.heartbeat:
	case <-time.After(time.Second):
		t.Fatal("heartbeat handling stopped behind the quarantined plugin observation lane")
	}
	require.NoError(t, registry.Dispatch(context.Background(), "agent-a", collectNowEnvelope("command-a", "agent-a", time.Now().Add(time.Minute))))
	require.Equal(t, "command-a", stream.nextSent(t).GetCommand().GetCommandId())

	close(sink.release)
	require.Equal(t, "agent-a:3", <-sink.delivered)
	stream.closeReceive()
	require.NoError(t, <-done)
}

type recordingPluginObserver struct{ report *agentv1.PluginObservation }

func (observer *recordingPluginObserver) SubmitPlugin(_ string, report *agentv1.PluginObservation) error {
	observer.report = report
	return nil
}

type errorPluginObserver struct{ err error }

func (observer errorPluginObserver) SubmitPlugin(string, *agentv1.PluginObservation) error {
	return observer.err
}

type pluginStreamObserver struct {
	NoopObserver
	heartbeat chan struct{}
}

func (observer *pluginStreamObserver) Heartbeat(context.Context, string, *agentv1.Heartbeat) {
	observer.heartbeat <- struct{}{}
}
