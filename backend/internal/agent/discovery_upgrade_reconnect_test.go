package agent

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	agentdiscovery "dbpilot.local/platform/internal/agent/discovery"
	domain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestOldPendingOnNewServerReconnectsOnceAndResumesNewShape(t *testing.T) {
	firstStream, secondStream := newFakeControlStream(), newFakeControlStream()
	opener := &sequenceStreamOpener{streams: []ControlStream{firstStream, secondStream}}
	client := newTransportTestClient(t, opener.Open)

	now := time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC)
	store, err := agentdiscovery.NewFileReportStore(filepath.Join(t.TempDir(), "pending.pb"))
	require.NoError(t, err)
	pending := legacyPendingReport(now)
	require.NoError(t, store.Save(context.Background(), pending))
	rules, attestation := upgradeTestRules(t, now)
	native := &upgradeDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	docker := &upgradeDetector{candidate: domain.CandidateObservation{ObservationID: "docker-1", Source: domain.SourceDocker, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:49161", ContainerIdentity: "orders-db", ContainerImage: "mysql:8.4", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceContainerImage, Value: "mysql:8.4"}}}}
	revisions := &upgradeRevisionStore{revision: 7}
	coordinator, err := agentdiscovery.NewCoordinator(agentdiscovery.CoordinatorConfig{HostID: "host-1", AgentID: "agent-a", Detector: native, DockerDetector: docker, RuleSet: rules, Attestation: attestation, RevisionStore: revisions, ReportStore: store, RetryBackoff: time.Millisecond, Now: func() time.Time { return now }, Compatibility: func() agentdiscovery.CompatibilityState {
		return agentdiscovery.CompatibilityState(client.DiscoveryCompatibility())
	}, SourceResultsSupported: client.DiscoverySourceResultsSupported, SourceResultsPeerSupported: client.DiscoverySourceResultsPeerSupported, RequestSourceResultsReconnect: client.RequestDiscoverySourceResultsReconnect, Reporter: client.ReportDiscovery})
	require.NoError(t, err)
	require.NoError(t, client.executors.Register(CommandKindCollectNow, coordinatorCapabilityExecutor{coordinator: coordinator}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	firstHello := waitForAgentMessage(t, firstStream, func(message *agentv1.AgentMessage) bool { return message.GetHello() != nil }).GetHello()
	require.Contains(t, firstHello.GetCapabilities(), "discovery_source_results_pending_legacy_v1")
	require.NotContains(t, firstHello.GetCapabilities(), CapabilityDiscoverySourceResultsV1)
	firstStream.receive <- sourceResultsHelloAck()
	waitForAgentMessage(t, firstStream, func(message *agentv1.AgentMessage) bool { return message.GetHeartbeat() != nil })

	firstScan := make(chan error, 1)
	go func() { firstScan <- coordinator.Scan(context.Background(), agentdiscovery.ScanPeriodic) }()
	legacyWire := waitForAgentMessage(t, firstStream, func(message *agentv1.AgentMessage) bool { return message.GetDiscoveryReport() != nil }).GetDiscoveryReport()
	require.Empty(t, legacyWire.GetSourceResults())
	require.Equal(t, pending.GetObservationRevision(), legacyWire.GetObservationRevision())
	acknowledgeDiscovery(t, firstStream, legacyWire)
	require.NoError(t, <-firstScan)

	secondHello := waitForAgentMessage(t, secondStream, func(message *agentv1.AgentMessage) bool { return message.GetHello() != nil }).GetHello()
	require.Contains(t, secondHello.GetCapabilities(), CapabilityDiscoverySourceResultsV1)
	require.NotContains(t, secondHello.GetCapabilities(), "discovery_source_results_pending_legacy_v1")
	secondStream.receive <- sourceResultsHelloAck()
	waitForAgentMessage(t, secondStream, func(message *agentv1.AgentMessage) bool { return message.GetHeartbeat() != nil })
	require.Eventually(t, client.DiscoverySourceResultsSupported, time.Second, time.Millisecond)
	require.NoError(t, client.sendAgentMessage(&agentv1.AgentMessage{Message: &agentv1.AgentMessage_CommandProgress{CommandProgress: &agentv1.CommandProgress{CommandId: "unrelated-healthy"}}}))
	waitForAgentMessage(t, secondStream, func(message *agentv1.AgentMessage) bool { return message.GetCommandProgress() != nil })

	secondScan := make(chan error, 1)
	go func() { secondScan <- coordinator.Scan(context.Background(), agentdiscovery.ScanPeriodic) }()
	newWire := waitForAgentMessage(t, secondStream, func(message *agentv1.AgentMessage) bool { return message.GetDiscoveryReport() != nil }).GetDiscoveryReport()
	require.Len(t, newWire.GetSourceResults(), 2)
	require.Len(t, newWire.GetCandidates(), 2)
	require.Equal(t, uint64(8), newWire.GetObservationRevision())
	acknowledgeDiscovery(t, secondStream, newWire)
	require.NoError(t, <-secondScan)

	time.Sleep(30 * time.Millisecond)
	opener.mu.Lock()
	require.Equal(t, 2, opener.index, "protocol upgrade must create exactly two sessions")
	opener.mu.Unlock()
	cleared, err := store.Load(context.Background())
	require.NoError(t, err)
	require.Nil(t, cleared)
	cancel()
	require.NoError(t, <-done)
}

func TestGracefulProtocolReconnectFailureUsesNormalBackoff(t *testing.T) {
	first, third := newFakeControlStream(), newFakeControlStream()
	opener := &failingUpgradeOpener{first: first, third: third}
	client := newTransportTestClient(t, opener.Open)
	client.reconnectBackoff = 40 * time.Millisecond
	capability := &mutableUpgradeCapability{}
	require.NoError(t, client.executors.Register(CommandKindCollectNow, capability))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	waitForAgentMessage(t, first, func(message *agentv1.AgentMessage) bool { return message.GetHello() != nil })
	first.receive <- sourceResultsHelloAck()
	waitForAgentMessage(t, first, func(message *agentv1.AgentMessage) bool { return message.GetHeartbeat() != nil })
	require.True(t, client.RequestDiscoverySourceResultsReconnect())
	require.False(t, client.RequestDiscoverySourceResultsReconnect())
	capability.setUpgraded()
	thirdHello := waitForAgentMessage(t, third, func(message *agentv1.AgentMessage) bool { return message.GetHello() != nil }).GetHello()
	require.Contains(t, thirdHello.GetCapabilities(), CapabilityDiscoverySourceResultsV1)
	opener.mu.Lock()
	require.GreaterOrEqual(t, opener.thirdOpened.Sub(opener.failedAt), 35*time.Millisecond)
	require.Equal(t, 3, opener.calls)
	opener.mu.Unlock()
	third.receive <- sourceResultsHelloAck()
	waitForAgentMessage(t, third, func(message *agentv1.AgentMessage) bool { return message.GetHeartbeat() != nil })
	time.Sleep(30 * time.Millisecond)
	opener.mu.Lock()
	require.Equal(t, 3, opener.calls, "successful upgraded Hello must not reconnect again")
	opener.mu.Unlock()
	cancel()
	require.NoError(t, <-done)
}

type coordinatorCapabilityExecutor struct{ coordinator *agentdiscovery.Coordinator }

func (executor coordinatorCapabilityExecutor) Execute(context.Context, *agentv1.CommandEnvelope, ProgressReporter) (*agentv1.CommandResult, error) {
	return nil, errors.New("not executed")
}
func (executor coordinatorCapabilityExecutor) AdditionalCapabilities() []string {
	return executor.coordinator.AdditionalCapabilities()
}

type upgradeDetector struct{ candidate domain.CandidateObservation }

func (detector *upgradeDetector) Discover(context.Context, []domain.Rule) ([]domain.CandidateObservation, error) {
	return []domain.CandidateObservation{detector.candidate}, nil
}

type upgradeRevisionStore struct {
	mu       sync.Mutex
	revision uint64
}

func (store *upgradeRevisionStore) Next(context.Context) (uint64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.revision++
	return store.revision, nil
}

func legacyPendingReport(now time.Time) *agentv1.DiscoveryReport {
	timestamp := timestamppb.New(now)
	return &agentv1.DiscoveryReport{HostId: "host-1", AgentId: "agent-a", ObservationRevision: 7, RuleRevision: 4, ObservedAt: timestamp, RuleSetDigest: make([]byte, 32), DisappearanceGraceSeconds: 60, RuleIssuedAt: timestamp, RuleExpiresAt: timestamppb.New(now.Add(time.Hour)), RuleAttestationSignature: make([]byte, 64), RuleAttestationVersion: 1, RuleAttestationAlgorithm: "ed25519-sha256", RuleAttestationKeyId: "test"}
}

func upgradeTestRules(t *testing.T, now time.Time) (domain.RuleSet, domain.RuleAttestation) {
	t.Helper()
	rules := domain.RuleSet{Revision: 4, ScanInterval: time.Minute, DisappearanceGrace: time.Minute, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Rules: []domain.Rule{{ID: "mysql", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", ProcessNames: []string{"mysqld"}, DefaultPorts: []uint16{3306}}}}
	digest, err := domain.CanonicalRuleSetDigest(rules)
	require.NoError(t, err)
	return rules, domain.RuleAttestation{Version: domain.RuleAttestationVersion, Algorithm: domain.RuleAttestationAlgorithm, KeyID: "test", Revision: rules.Revision, Digest: digest, IssuedAt: rules.IssuedAt, ExpiresAt: rules.ExpiresAt, DisappearanceGrace: rules.DisappearanceGrace, Signature: make([]byte, 64)}
}

func sourceResultsHelloAck() *agentv1.ServerMessage {
	return &agentv1.ServerMessage{Message: &agentv1.ServerMessage_HelloAck{HelloAck: &agentv1.HelloAck{ProtocolVersion: ControlProtocolVersion, Capabilities: []string{CapabilityDiscoveryReportACKV1, CapabilityDiscoveryPolicyAttestationV1, CapabilityDiscoverySourceResultsV1}}}}
}

func waitForAgentMessage(t *testing.T, stream *fakeControlStream, predicate func(*agentv1.AgentMessage) bool) *agentv1.AgentMessage {
	t.Helper()
	var found *agentv1.AgentMessage
	require.Eventually(t, func() bool {
		for _, message := range stream.sentMessages() {
			if predicate(message) {
				found = message
				return true
			}
		}
		return false
	}, time.Second, time.Millisecond)
	return proto.Clone(found).(*agentv1.AgentMessage)
}

func acknowledgeDiscovery(t *testing.T, stream *fakeControlStream, report *agentv1.DiscoveryReport) {
	t.Helper()
	digest, err := agentdiscovery.ReportDigest(report)
	require.NoError(t, err)
	stream.receive <- &agentv1.ServerMessage{Message: &agentv1.ServerMessage_DiscoveryReportAcknowledgement{DiscoveryReportAcknowledgement: &agentv1.DiscoveryReportAcknowledgement{HostId: report.GetHostId(), AgentId: report.GetAgentId(), ObservationRevision: report.GetObservationRevision(), ReportDigest: digest[:], Persisted: true}}}
}

type mutableUpgradeCapability struct {
	mu       sync.Mutex
	upgraded bool
}

func (capability *mutableUpgradeCapability) Execute(context.Context, *agentv1.CommandEnvelope, ProgressReporter) (*agentv1.CommandResult, error) {
	return nil, errors.New("not executed")
}
func (capability *mutableUpgradeCapability) AdditionalCapabilities() []string {
	capability.mu.Lock()
	defer capability.mu.Unlock()
	if capability.upgraded {
		return []string{CapabilityDiscoverySourceResultsV1}
	}
	return []string{CapabilityDiscoverySourceResultsPendingLegacyV1, "native_discovery_v1"}
}
func (capability *mutableUpgradeCapability) setUpgraded() {
	capability.mu.Lock()
	capability.upgraded = true
	capability.mu.Unlock()
}

type failingUpgradeOpener struct {
	mu                    sync.Mutex
	calls                 int
	first, third          *fakeControlStream
	failedAt, thirdOpened time.Time
}

func (opener *failingUpgradeOpener) Open(ctx context.Context) (ControlStream, error) {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	opener.calls++
	switch opener.calls {
	case 1:
		opener.first.setContext(ctx)
		return opener.first, nil
	case 2:
		opener.failedAt = time.Now()
		return nil, errors.New("transient reconnect failure")
	case 3:
		opener.thirdOpened = time.Now()
		opener.third.setContext(ctx)
		return opener.third, nil
	default:
		return nil, errors.New("unexpected reconnect")
	}
}
