package agentcontrol

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPluginObservationDispatcherCoalescesHotAgentAndDoesNotStarveColdAgent(t *testing.T) {
	sink := &controlledPluginSink{release: make(chan struct{}), delivered: make(chan string, 8)}
	dispatcher, err := NewPluginObservationDispatcher(sink, PluginObservationDispatcherConfig{MaximumPendingAgents: 4, DeliveryTimeout: time.Second, RetryBackoff: time.Millisecond})
	require.NoError(t, err)
	defer dispatcher.Close()
	require.NoError(t, dispatcher.SubmitPlugin("agent-hot", pluginReport("agent-hot", 1)))
	require.Equal(t, "agent-hot:1", <-sink.delivered)
	require.NoError(t, dispatcher.SubmitPlugin("agent-hot", pluginReport("agent-hot", 2)))
	require.NoError(t, dispatcher.SubmitPlugin("agent-hot", pluginReport("agent-hot", 3)))
	require.NoError(t, dispatcher.SubmitPlugin("agent-cold", pluginReport("agent-cold", 1)))
	require.Equal(t, "agent-cold:1", <-sink.delivered, "cold Agent gets its own fair in-flight lane")
	close(sink.release)
	require.Eventually(t, func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return sink.persisted["agent-hot"] == 3 && sink.persisted["agent-cold"] == 1
	}, time.Second, 10*time.Millisecond)
}

func TestPluginObservationDispatcherQuarantinesContextIgnoringSinkAndCloseIsBounded(t *testing.T) {
	sink := &controlledPluginSink{never: true, delivered: make(chan string, 2)}
	dispatcher, err := NewPluginObservationDispatcher(sink, PluginObservationDispatcherConfig{MaximumPendingAgents: 2, DeliveryTimeout: 20 * time.Millisecond, RetryBackoff: time.Millisecond})
	require.NoError(t, err)
	require.NoError(t, dispatcher.SubmitPlugin("agent-stuck", pluginReport("agent-stuck", 1)))
	require.Equal(t, "agent-stuck:1", <-sink.delivered)
	time.Sleep(40 * time.Millisecond)
	started := time.Now()
	dispatcher.Close()
	require.Less(t, time.Since(started), 50*time.Millisecond)
	require.ErrorIs(t, dispatcher.SubmitPlugin("agent-after-close", pluginReport("agent-after-close", 1)), ErrPluginObservationClosed)
}

type controlledPluginSink struct {
	mu        sync.Mutex
	release   chan struct{}
	delivered chan string
	persisted map[string]uint64
	never     bool
}

func (sink *controlledPluginSink) RecordPluginObservation(_ context.Context, agentID string, report *agentv1.PluginObservation) error {
	sink.delivered <- agentID + ":" + fmt.Sprint(report.GetObservationRevision())
	if sink.never {
		select {}
	}
	if sink.release != nil {
		<-sink.release
	}
	sink.mu.Lock()
	if sink.persisted == nil {
		sink.persisted = map[string]uint64{}
	}
	sink.persisted[agentID] = report.GetObservationRevision()
	sink.mu.Unlock()
	return nil
}
func pluginReport(agent string, revision uint64) *agentv1.PluginObservation {
	return &agentv1.PluginObservation{HostId: "host-" + agent, AgentId: agent, ObservationRevision: revision, ObservedAt: timestamppb.New(time.Now().UTC()), Assignments: []*agentv1.PluginAssignmentObservation{}}
}
