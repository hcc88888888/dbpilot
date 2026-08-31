package agentcontrol

import (
	"context"
	"testing"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
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

type recordingPluginObserver struct{ report *agentv1.PluginObservation }

func (observer *recordingPluginObserver) SubmitPlugin(_ string, report *agentv1.PluginObservation) error {
	observer.report = report
	return nil
}
