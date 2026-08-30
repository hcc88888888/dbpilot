package agentcontrol

import (
	"context"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDiscoveryDispatcherDoesNotBlockControlStreamAndCoalescesPendingRevision(t *testing.T) {
	sink := &blockingDiscoverySink{entered: make(chan uint64, 3), release: make(chan struct{}, 3)}
	dispatcher, err := NewDiscoveryDispatcher(sink, DiscoveryDispatcherConfig{MaximumPendingAgents: 2, DeliveryTimeout: time.Second, RetryBackoff: time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(dispatcher.Close)
	require.NoError(t, dispatcher.SubmitDiscovery("agent-1", validDiscoveryReportFixture(1)))
	require.Equal(t, uint64(1), <-sink.entered)
	require.NoError(t, dispatcher.SubmitDiscovery("agent-1", validDiscoveryReportFixture(2)))
	require.NoError(t, dispatcher.SubmitDiscovery("agent-1", validDiscoveryReportFixture(3)))
	sink.release <- struct{}{}
	require.Equal(t, uint64(3), <-sink.entered)
	sink.release <- struct{}{}
}

func TestDiscoveryDispatcherRejectsIdentityMismatchBeforePersistence(t *testing.T) {
	sink := &blockingDiscoverySink{entered: make(chan uint64, 1), release: make(chan struct{}, 1)}
	dispatcher, err := NewDiscoveryDispatcher(sink, DiscoveryDispatcherConfig{})
	require.NoError(t, err)
	t.Cleanup(dispatcher.Close)
	report := validDiscoveryReportFixture(1)
	report.AgentId = "agent-2"
	require.ErrorIs(t, dispatcher.SubmitDiscovery("agent-1", report), ErrDiscoveryObservationInvalid)
}

type blockingDiscoverySink struct {
	entered chan uint64
	release chan struct{}
}

func (sink *blockingDiscoverySink) RecordDiscoveryReport(ctx context.Context, _ string, report *agentv1.DiscoveryReport) error {
	sink.entered <- report.GetObservationRevision()
	select {
	case <-sink.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func validDiscoveryReportFixture(revision uint64) *agentv1.DiscoveryReport {
	now := timestamppb.New(time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC))
	return &agentv1.DiscoveryReport{HostId: "host-1", AgentId: "agent-1", ObservationRevision: revision, RuleRevision: 4, ObservedAt: now, Candidates: []*agentv1.DiscoveryCandidateObservation{{ObservationId: "obs-1", Source: agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE, DatabaseFamily: "mysql", DatabaseVariant: "mysql", Fingerprint: make([]byte, 32), ObservedAt: now}}}
}
