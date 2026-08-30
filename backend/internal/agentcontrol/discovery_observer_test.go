package agentcontrol

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	discoverydomain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDiscoveryDispatcherDoesNotBlockControlStreamAndCoalescesPendingRevision(t *testing.T) {
	sink := &blockingDiscoverySink{entered: make(chan uint64, 3), release: make(chan struct{}, 3)}
	dispatcher, err := NewDiscoveryDispatcher(sink, DiscoveryDispatcherConfig{MaximumPendingAgents: 2, DeliveryTimeout: time.Second, RetryBackoff: time.Millisecond, Acknowledge: func(string, *agentv1.DiscoveryReportAcknowledgement) error { return nil }})
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
	dispatcher, err := NewDiscoveryDispatcher(sink, DiscoveryDispatcherConfig{Acknowledge: func(string, *agentv1.DiscoveryReportAcknowledgement) error { return nil }})
	require.NoError(t, err)
	t.Cleanup(dispatcher.Close)
	report := validDiscoveryReportFixture(1)
	report.AgentId = "agent-2"
	require.ErrorIs(t, dispatcher.SubmitDiscovery("agent-1", report), ErrDiscoveryObservationInvalid)
}

func TestDiscoveryDispatcherQuarantinesNeverReturningAgentWithoutBlockingPeerOrClose(t *testing.T) {
	sink := selectiveDiscoverySink{blocked: make(chan struct{})}
	t.Cleanup(func() { close(sink.blocked) })
	acknowledged := make(chan string, 2)
	dispatcher, err := NewDiscoveryDispatcher(sink, DiscoveryDispatcherConfig{MaximumPendingAgents: 2, DeliveryTimeout: 10 * time.Millisecond, RetryBackoff: time.Millisecond, Acknowledge: func(agent string, _ *agentv1.DiscoveryReportAcknowledgement) error { acknowledged <- agent; return nil }})
	require.NoError(t, err)
	blocked := validDiscoveryReportFixture(1)
	blocked.AgentId = "agent-a"
	blocked.HostId = "host-a"
	fast := validDiscoveryReportFixture(1)
	fast.AgentId = "agent-b"
	fast.HostId = "host-b"
	require.NoError(t, dispatcher.SubmitDiscovery("agent-a", blocked))
	require.NoError(t, dispatcher.SubmitDiscovery("agent-b", fast))
	select {
	case agent := <-acknowledged:
		require.Equal(t, "agent-b", agent)
	case <-time.After(time.Second):
		t.Fatal("cold Agent was blocked by non-cooperative peer")
	}
	started := time.Now()
	dispatcher.Close()
	require.Less(t, time.Since(started), 100*time.Millisecond)
}

func TestDiscoveryDispatcherSendsTerminalAckForUncommittedStaleReport(t *testing.T) {
	acknowledged := make(chan *agentv1.DiscoveryReportAcknowledgement, 1)
	dispatcher, err := NewDiscoveryDispatcher(errorDiscoverySink{err: discoverydomain.ErrConflict}, DiscoveryDispatcherConfig{Acknowledge: func(_ string, ack *agentv1.DiscoveryReportAcknowledgement) error { acknowledged <- ack; return nil }})
	require.NoError(t, err)
	defer dispatcher.Close()
	require.NoError(t, dispatcher.SubmitDiscovery("agent-1", validDiscoveryReportFixture(1)))
	select {
	case ack := <-acknowledged:
		require.False(t, ack.GetPersisted())
		require.False(t, ack.GetRetryable())
		require.Equal(t, "REPORT_REJECTED", ack.GetReasonCode())
	case <-time.After(time.Second):
		t.Fatal("terminal acknowledgement was not emitted")
	}
}

func TestDiscoveryDispatcherAcceptsLegacyNativeShapeWithoutAgingDocker(t *testing.T) {
	persisted := make(chan *agentv1.DiscoveryReport, 1)
	acknowledged := make(chan *agentv1.DiscoveryReportAcknowledgement, 1)
	dispatcher, err := NewDiscoveryDispatcher(capturingDiscoverySink{reports: persisted}, DiscoveryDispatcherConfig{SourceResultsSupported: func(string) bool { return false }, Acknowledge: func(_ string, ack *agentv1.DiscoveryReportAcknowledgement) error { acknowledged <- ack; return nil }})
	require.NoError(t, err)
	defer dispatcher.Close()
	legacy := validDiscoveryReportFixture(1)
	legacy.SourceResults = nil
	legacy.Candidates = nil
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(legacy)
	require.NoError(t, err)
	require.NoError(t, dispatcher.SubmitDiscovery("agent-1", legacy))
	stored := <-persisted
	require.Len(t, stored.GetSourceResults(), 2)
	require.Equal(t, agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_COMPLETED, stored.GetSourceResults()[0].GetStatus())
	require.Equal(t, agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_NOT_REQUESTED, stored.GetSourceResults()[1].GetStatus())
	ack := <-acknowledged
	expectedDigest := sha256.Sum256(wire)
	require.Equal(t, expectedDigest[:], ack.GetReportDigest(), "legacy ACK digest must cover the original old wire shape")
}

func TestDiscoveryDispatcherRequiresNegotiatedSourceResultsAndRejectsLegacyDockerCandidates(t *testing.T) {
	dispatcher, err := NewDiscoveryDispatcher(capturingDiscoverySink{reports: make(chan *agentv1.DiscoveryReport, 1)}, DiscoveryDispatcherConfig{Acknowledge: func(string, *agentv1.DiscoveryReportAcknowledgement) error { return nil }})
	require.NoError(t, err)
	defer dispatcher.Close()
	missing := validDiscoveryReportFixture(1)
	missing.SourceResults = nil
	require.ErrorIs(t, dispatcher.SubmitDiscovery("agent-1", missing), ErrDiscoveryObservationInvalid)
	legacyDispatcher, err := NewDiscoveryDispatcher(capturingDiscoverySink{reports: make(chan *agentv1.DiscoveryReport, 1)}, DiscoveryDispatcherConfig{SourceResultsSupported: func(string) bool { return false }, Acknowledge: func(string, *agentv1.DiscoveryReportAcknowledgement) error { return nil }})
	require.NoError(t, err)
	defer legacyDispatcher.Close()
	missing.Candidates[0].Source = agentv1.DiscoverySource_DISCOVERY_SOURCE_DOCKER
	require.ErrorIs(t, legacyDispatcher.SubmitDiscovery("agent-1", missing), ErrDiscoveryObservationInvalid)
}

type blockingDiscoverySink struct {
	entered chan uint64
	release chan struct{}
}

type selectiveDiscoverySink struct{ blocked chan struct{} }

func (sink selectiveDiscoverySink) RecordDiscoveryReport(_ context.Context, agent string, _ *agentv1.DiscoveryReport) error {
	if agent == "agent-a" {
		<-sink.blocked
	}
	return nil
}

type errorDiscoverySink struct{ err error }

type capturingDiscoverySink struct{ reports chan *agentv1.DiscoveryReport }

func (sink capturingDiscoverySink) RecordDiscoveryReport(_ context.Context, _ string, report *agentv1.DiscoveryReport) error {
	sink.reports <- proto.Clone(report).(*agentv1.DiscoveryReport)
	return nil
}

func (sink errorDiscoverySink) RecordDiscoveryReport(context.Context, string, *agentv1.DiscoveryReport) error {
	return sink.err
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
	return &agentv1.DiscoveryReport{HostId: "host-1", AgentId: "agent-1", ObservationRevision: revision, RuleRevision: 4, ObservedAt: now, RuleSetDigest: make([]byte, 32), DisappearanceGraceSeconds: 60, RuleIssuedAt: now, RuleExpiresAt: timestamppb.New(now.AsTime().Add(time.Hour)), RuleAttestationSignature: make([]byte, 64), RuleAttestationVersion: 1, RuleAttestationAlgorithm: "ed25519-sha256", RuleAttestationKeyId: "test", SourceResults: []*agentv1.DiscoverySourceResult{{Source: agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE, Status: agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_COMPLETED, Reason: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_HEALTHY, ObservedAt: now}, {Source: agentv1.DiscoverySource_DISCOVERY_SOURCE_DOCKER, Status: agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_NOT_CONFIGURED, Reason: agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_NOT_CONFIGURED, ObservedAt: now}}, Candidates: []*agentv1.DiscoveryCandidateObservation{{ObservationId: "obs-1", Source: agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE, DatabaseFamily: "mysql", DatabaseVariant: "mysql", Fingerprint: make([]byte, 32), ObservedAt: now}}}
}
