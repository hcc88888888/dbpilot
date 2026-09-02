package discovery

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	domain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDockerDetectorMatchesSignedImageAndOwnershipLabels(t *testing.T) {
	client := &fakeDockerRPCClient{snapshot: &discoveryv1.DockerSnapshotResponse{ObservedAt: timestamppb.New(time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)), Containers: []*discoveryv1.DockerContainerObservation{{
		ContainerId: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Name: "mysql-a", Image: "mysql:8.4", Status: discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING,
		Labels: map[string]string{"dbpilot.discovery.family": "mysql", "dbpilot.run": "run-01"}, Ports: []*discoveryv1.DockerPortMapping{{HostAddress: "127.0.0.1", HostPort: 49161, ContainerPort: 3306, Protocol: "tcp"}},
	}}}}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: client, RuleRevision: 7, AllowedLabelKeys: []string{"dbpilot.discovery.family", "dbpilot.run"}})
	require.NoError(t, err)
	rules := []domain.Rule{{ID: "mysql-docker", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", DockerImagePatterns: []string{`^mysql:8\.4$`}, DockerLabelSelectors: []string{"dbpilot.discovery.family=mysql", "dbpilot.run=run-01"}, DefaultPorts: []uint16{3306}}}

	candidates, err := detector.Discover(context.Background(), rules)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, domain.SourceDocker, candidates[0].Source)
	require.Equal(t, "127.0.0.1:49161", candidates[0].NormalizedEndpoint)
	require.Equal(t, "mysql", candidates[0].DatabaseFamily)
	require.Equal(t, uint64(7), client.request.RuleRevision)
	require.ElementsMatch(t, []string{"dbpilot.discovery.family", "dbpilot.run"}, client.request.AllowedLabelKeys)
}

func TestDockerDetectorDiscoversInternalOnlyMySQLOnSignedAllowlistedNetwork(t *testing.T) {
	client := &fakeDockerRPCClient{snapshot: &discoveryv1.DockerSnapshotResponse{Containers: []*discoveryv1.DockerContainerObservation{{
		ContainerId: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Name: "mysql-a", Image: "mysql:8.4", Status: discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING,
		Labels: map[string]string{"dbpilot.discovery.family": "mysql"}, InternalEndpoints: []*discoveryv1.DockerInternalEndpoint{{NetworkName: "dbpilot_acceptance", Address: "172.30.0.10", Port: 3306, Protocol: "tcp"}},
	}}}}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: client, RuleRevision: 7, AllowedLabelKeys: []string{"dbpilot.discovery.family"}, AllowedNetworkNames: []string{"dbpilot_acceptance"}})
	require.NoError(t, err)
	rules := []domain.Rule{{ID: "mysql-docker", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", DockerImagePatterns: []string{`^mysql:8\.4$`}, DockerLabelSelectors: []string{"dbpilot.discovery.family=mysql"}, DockerNetworkNames: []string{"dbpilot_acceptance"}, DefaultPorts: []uint16{3306}}}

	candidates, err := detector.Discover(context.Background(), rules)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, "172.30.0.10:3306", candidates[0].NormalizedEndpoint)
	require.Empty(t, client.snapshot.GetContainers()[0].GetPorts(), "internal-only fixture has no host publication")
	require.Equal(t, []string{"dbpilot_acceptance"}, client.request.GetAllowedNetworkNames())
}

func TestDockerDetectorRejectsInternalEndpointOutsideSignedNetworkRule(t *testing.T) {
	base := &discoveryv1.DockerContainerObservation{
		ContainerId: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Name: "mysql-a", Image: "mysql:8.4", Status: discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING,
		Labels: map[string]string{"dbpilot.discovery.family": "mysql"}, InternalEndpoints: []*discoveryv1.DockerInternalEndpoint{{NetworkName: "other_network", Address: "172.31.0.10", Port: 3306, Protocol: "tcp"}},
	}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: &fakeDockerRPCClient{snapshot: &discoveryv1.DockerSnapshotResponse{Containers: []*discoveryv1.DockerContainerObservation{base}}}, RuleRevision: 7, AllowedLabelKeys: []string{"dbpilot.discovery.family"}, AllowedNetworkNames: []string{"dbpilot_acceptance"}})
	require.NoError(t, err)
	rules := []domain.Rule{{ID: "mysql-docker", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", DockerImagePatterns: []string{`^mysql:8\.4$`}, DockerLabelSelectors: []string{"dbpilot.discovery.family=mysql"}, DockerNetworkNames: []string{"dbpilot_acceptance"}, DefaultPorts: []uint16{3306}}}
	_, err = detector.Discover(context.Background(), rules)
	require.Error(t, err)
}

func TestDockerDetectorSignedNetworkDoesNotFallBackToPublishedPort(t *testing.T) {
	client := &fakeDockerRPCClient{snapshot: &discoveryv1.DockerSnapshotResponse{Containers: []*discoveryv1.DockerContainerObservation{{
		ContainerId: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Name: "mysql-a", Image: "mysql:8.4", Status: discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING,
		Labels: map[string]string{"dbpilot.discovery.family": "mysql"}, Ports: []*discoveryv1.DockerPortMapping{{HostAddress: "127.0.0.1", HostPort: 49161, ContainerPort: 3306, Protocol: "tcp"}},
	}}}}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: client, RuleRevision: 7, AllowedLabelKeys: []string{"dbpilot.discovery.family"}, AllowedNetworkNames: []string{"dbpilot_acceptance"}})
	require.NoError(t, err)
	rules := []domain.Rule{{ID: "mysql-docker", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", DockerImagePatterns: []string{`^mysql:8\.4$`}, DockerLabelSelectors: []string{"dbpilot.discovery.family=mysql"}, DockerNetworkNames: []string{"dbpilot_acceptance"}, DefaultPorts: []uint16{3306}}}

	candidates, err := detector.Discover(context.Background(), rules)
	require.NoError(t, err)
	require.Empty(t, candidates, "a signed internal-network rule must never fall back to a published host port")
}

func TestAgentRejectsUnsafeDockerInternalAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0", "::", "127.0.0.1", "::1", "169.254.10.20", "fe80::1", "224.0.0.1", "ff02::1"} {
		t.Run(address, func(t *testing.T) {
			container := &discoveryv1.DockerContainerObservation{
				ContainerId: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Name: "mysql-a", Image: "mysql:8.4", Status: discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING,
				InternalEndpoints: []*discoveryv1.DockerInternalEndpoint{{NetworkName: "dbpilot_acceptance", Address: address, Port: 3306, Protocol: "tcp"}},
			}
			require.Error(t, validateDockerObservation(container, nil, []string{"dbpilot_acceptance"}))
		})
	}
}

func TestDockerDetectorUsesStableIdentityLabelAndKeepsContainerIDAsEvidence(t *testing.T) {
	const ephemeralID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	client := &fakeDockerRPCClient{snapshot: &discoveryv1.DockerSnapshotResponse{Containers: []*discoveryv1.DockerContainerObservation{{ContainerId: ephemeralID, Name: "generated-name", Image: "mysql:8.4", Status: discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING, Labels: map[string]string{"dbpilot.discovery.family": "mysql", "dbpilot.instance_id": "orders-db"}, Ports: []*discoveryv1.DockerPortMapping{{HostAddress: "127.0.0.1", HostPort: 49161, ContainerPort: 3306, Protocol: "tcp"}}}}}}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: client, RuleRevision: 7, AllowedLabelKeys: []string{"dbpilot.discovery.family", "dbpilot.instance_id"}})
	require.NoError(t, err)
	rules := []domain.Rule{{ID: "mysql-docker", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", DockerImagePatterns: []string{`^mysql:8\.4$`}, DockerLabelSelectors: []string{"dbpilot.discovery.family=mysql"}, DockerIdentityLabel: "dbpilot.instance_id", DefaultPorts: []uint16{3306}}}
	candidates, err := detector.Discover(context.Background(), rules)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	require.Equal(t, "orders-db", candidates[0].ContainerIdentity)
	require.Contains(t, candidates[0].Evidence, domain.Evidence{Kind: domain.EvidenceContainerID, Value: ephemeralID})
}

func TestDockerRecreateWithNewContainerIDKeepsStableFingerprint(t *testing.T) {
	firstID := "1111111111111111111111111111111111111111111111111111111111111111"
	secondID := "2222222222222222222222222222222222222222222222222222222222222222"
	client := &fakeDockerRPCClient{}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: client, RuleRevision: 7, AllowedLabelKeys: []string{"dbpilot.discovery.family", "dbpilot.instance_id"}})
	require.NoError(t, err)
	rules := []domain.Rule{{ID: "mysql-docker", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", DockerImagePatterns: []string{`^mysql:8\.4$`}, DockerLabelSelectors: []string{"dbpilot.discovery.family=mysql"}, DockerIdentityLabel: "dbpilot.instance_id", DefaultPorts: []uint16{3306}}}
	fixture := func(id string, hostPort uint32) *discoveryv1.DockerSnapshotResponse {
		return &discoveryv1.DockerSnapshotResponse{Containers: []*discoveryv1.DockerContainerObservation{{ContainerId: id, Name: "generated", Image: "mysql:8.4", Status: discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING, Labels: map[string]string{"dbpilot.discovery.family": "mysql", "dbpilot.instance_id": "orders-db"}, Ports: []*discoveryv1.DockerPortMapping{{HostAddress: "127.0.0.1", HostPort: hostPort, ContainerPort: 3306, Protocol: "tcp"}}}}}
	}
	client.snapshot = fixture(firstID, 49161)
	first, err := detector.Discover(context.Background(), rules)
	require.NoError(t, err)
	require.Len(t, first, 1)
	client.snapshot = fixture(secondID, 59272)
	second, err := detector.Discover(context.Background(), rules)
	require.NoError(t, err)
	require.Len(t, second, 1)
	firstFingerprint, err := domain.Fingerprint("host-1", first[0])
	require.NoError(t, err)
	secondFingerprint, err := domain.Fingerprint("host-1", second[0])
	require.NoError(t, err)
	require.Equal(t, firstFingerprint, secondFingerprint)
	require.NotEqual(t, first[0].Evidence, second[0].Evidence, "ephemeral ID remains observation evidence")
}

func TestDockerDetectorRejectsMismatchedOwnershipLabelAndUntrustedHelperData(t *testing.T) {
	client := &fakeDockerRPCClient{snapshot: &discoveryv1.DockerSnapshotResponse{Containers: []*discoveryv1.DockerContainerObservation{{ContainerId: "short", Image: "mysql:8.4", Labels: map[string]string{"dbpilot.discovery.family": "mysql"}, CommandSummary: "--password=raw", Ports: []*discoveryv1.DockerPortMapping{{HostAddress: "127.0.0.1", HostPort: 49161, ContainerPort: 3306, Protocol: "tcp"}}}}}}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: client, RuleRevision: 7, AllowedLabelKeys: []string{"dbpilot.discovery.family"}})
	require.NoError(t, err)
	rules := []domain.Rule{{ID: "mysql-docker", Version: 1, DatabaseFamily: "mysql", DatabaseVariant: "mysql", DockerImagePatterns: []string{`^mysql:8\.4$`}, DockerLabelSelectors: []string{"dbpilot.discovery.family=mysql"}, DefaultPorts: []uint16{3306}}}
	_, err = detector.Discover(context.Background(), rules)
	require.Error(t, err)
}

func TestDockerDetectorAcceptsCredentialSummaryOnlyAfterHelperRedaction(t *testing.T) {
	container := &discoveryv1.DockerContainerObservation{ContainerId: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Name: "mysql-a", Image: "mysql:8.4", Status: discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING, Labels: map[string]string{"dbpilot.discovery.family": "mysql"}, CommandSummary: "mysqld --password=[REDACTED]", Ports: []*discoveryv1.DockerPortMapping{{HostAddress: "127.0.0.1", HostPort: 49161, ContainerPort: 3306, Protocol: "tcp"}}}
	require.NoError(t, validateDockerObservation(container, []string{"dbpilot.discovery.family"}))
	container.CommandSummary = "mysqld --password=raw-secret"
	require.Error(t, validateDockerObservation(container, []string{"dbpilot.discovery.family"}))
}

func TestAgentIndependentlyRejectsUnredactedDockerCredentialForms(t *testing.T) {
	base := &discoveryv1.DockerContainerObservation{ContainerId: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Name: "mysql-a", Image: "mysql:8.4", Status: discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING, Labels: map[string]string{"dbpilot.discovery.family": "mysql"}, Ports: []*discoveryv1.DockerPortMapping{{HostAddress: "127.0.0.1", HostPort: 49161, ContainerPort: 3306, Protocol: "tcp"}}}
	unsafe := []string{"mysql -p raw", "app --dsn=alice:secret@tcp(db)/app", "app alice:secret@tcp(db:3306)/app", "app scott/secret@db:1521/service", "app user=alice password=secret host=db", "app --endpoint=mysql://alice:secret@db/app?token=raw", "app -H Authorization:raw"}
	for _, summary := range unsafe {
		clone := proto.Clone(base).(*discoveryv1.DockerContainerObservation)
		clone.CommandSummary = summary
		require.Error(t, validateDockerObservation(clone, []string{"dbpilot.discovery.family"}), summary)
	}
	for _, summary := range []string{"mysql -p [REDACTED]", "app --dsn=[REDACTED]", "app --endpoint=mysql://%5BREDACTED%5D@db/app?token=%5BREDACTED%5D"} {
		clone := proto.Clone(base).(*discoveryv1.DockerContainerObservation)
		clone.CommandSummary = summary
		require.NoError(t, validateDockerObservation(clone, []string{"dbpilot.discovery.family"}), summary)
	}
}

func TestCoordinatorKeepsNativeDiscoveryWhenDockerHelperUnavailable(t *testing.T) {
	native := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	docker := errorDetector{err: ErrDockerDiscoveryUnavailable}
	rules, attestation := testRules(t)
	reports := make(chan *agentv1.DiscoveryReport, 1)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: native, DockerDetector: docker, RuleSet: rules, Attestation: attestation, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }, Reporter: func(_ context.Context, report *agentv1.DiscoveryReport) error {
		reports <- report
		return nil
	}})
	require.NoError(t, err)
	require.NoError(t, coordinator.Scan(context.Background(), ScanEnrollment))
	report := <-reports
	require.Len(t, report.GetCandidates(), 1)
	require.Equal(t, agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_COMPLETED, report.GetSourceResults()[0].GetStatus())
	require.Equal(t, agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_UNAVAILABLE, report.GetSourceResults()[1].GetStatus())
	require.Equal(t, agentv1.DiscoverySourceReason_DISCOVERY_SOURCE_REASON_HELPER_UNAVAILABLE, report.GetSourceResults()[1].GetReason())
	require.NotContains(t, coordinator.AdditionalCapabilities(), "docker_discovery_unavailable")
	require.Contains(t, coordinator.AdditionalCapabilities(), "docker_discovery_configured")
}

func TestDockerLiveSourceStatusRecoversWithoutControlSessionReconnect(t *testing.T) {
	native := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	docker := &recoveringDetector{err: ErrDockerDiscoveryUnavailable}
	rules, attestation := testRules(t)
	reports := make(chan *agentv1.DiscoveryReport, 2)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: native, DockerDetector: docker, RuleSet: rules, Attestation: attestation, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }, Reporter: func(_ context.Context, report *agentv1.DiscoveryReport) error { reports <- report; return nil }})
	require.NoError(t, err)
	require.NoError(t, coordinator.Scan(context.Background(), ScanPeriodic))
	require.Equal(t, agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_UNAVAILABLE, (<-reports).GetSourceResults()[1].GetStatus())
	docker.err = nil
	require.NoError(t, coordinator.Scan(context.Background(), ScanPeriodic))
	require.Equal(t, agentv1.DiscoverySourceResultStatus_DISCOVERY_SOURCE_RESULT_STATUS_COMPLETED, (<-reports).GetSourceResults()[1].GetStatus())
}

func TestDockerOnlyCommandFailsHonestlyWhenHelperUnavailable(t *testing.T) {
	native := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	rules, attestation := testRules(t)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: native, DockerDetector: errorDetector{err: ErrDockerDiscoveryUnavailable}, RuleSet: rules, Attestation: attestation, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }, Reporter: func(context.Context, *agentv1.DiscoveryReport) error { return nil }})
	require.NoError(t, err)
	_, err = coordinator.Execute(context.Background(), &agentv1.CommandEnvelope{CommandId: "docker-only", Command: &agentv1.CommandEnvelope_DiscoverDatabases{DiscoverDatabases: &agentv1.DiscoverDatabases{HostId: "host-1", RuleRevision: 4, IncludeDocker: true}}}, nil)
	require.ErrorIs(t, err, ErrDockerDiscoveryUnavailable)
	require.Zero(t, native.calls)
}

func TestOldServerNegotiationKeepsNativeOldShapeAndDisablesDocker(t *testing.T) {
	native := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	docker := &recoveringDetector{}
	rules, attestation := testRules(t)
	reports := make(chan *agentv1.DiscoveryReport, 1)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: native, DockerDetector: docker, RuleSet: rules, Attestation: attestation, SourceResultsSupported: func() bool { return false }, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }, Reporter: func(_ context.Context, report *agentv1.DiscoveryReport) error { reports <- report; return nil }})
	require.NoError(t, err)
	require.NoError(t, coordinator.Scan(context.Background(), ScanPeriodic))
	report := <-reports
	require.Empty(t, report.GetSourceResults())
	require.Len(t, report.GetCandidates(), 1)
	require.Equal(t, agentv1.DiscoverySource_DISCOVERY_SOURCE_NATIVE, report.GetCandidates()[0].GetSource())
	require.Equal(t, 0, docker.calls)
	require.Contains(t, coordinator.AdditionalCapabilities(), "discovery_source_results_v1")
	_, err = coordinator.Execute(context.Background(), &agentv1.CommandEnvelope{CommandId: "docker-only", Command: &agentv1.CommandEnvelope_DiscoverDatabases{DiscoverDatabases: &agentv1.DiscoverDatabases{HostId: "host-1", RuleRevision: 4, IncludeDocker: true}}}, nil)
	require.ErrorIs(t, err, ErrDockerDiscoveryUnavailable)
}

func TestDockerWatchEveryReadyReconnectTriggersFullReconciliationWithoutEvent(t *testing.T) {
	client := &reconnectingDockerRPCClient{}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: client, RuleRevision: 7, ReconnectBackoff: 10 * time.Millisecond})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	notifications := make(chan struct{}, 4)
	go detector.Watch(ctx, func() error { notifications <- struct{}{}; return nil })
	select {
	case <-notifications:
	case <-time.After(time.Second):
		t.Fatal("initial ready stream did not trigger reconciliation")
	}
	select {
	case <-notifications:
	case <-time.After(time.Second):
		t.Fatal("reconnected ready stream did not trigger reconciliation")
	}
	cancel()
	require.Eventually(t, func() bool { return client.calls.Load() >= 2 }, time.Second, time.Millisecond)
}

func TestCoordinatorCoalescesHighChurnIntoOneInFlightAndOneFinalScan(t *testing.T) {
	native := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	ackStarted := make(chan struct{})
	ackRelease := make(chan struct{})
	docker := newChurnDetector(ackStarted)
	rules, attestation := testRules(t)
	reports := make(chan uint64, 4)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: native, DockerDetector: docker, RuleSet: rules, Attestation: attestation, RetryBackoff: time.Millisecond, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }, Reporter: func(_ context.Context, report *agentv1.DiscoveryReport) error {
		if report.GetObservationRevision() == 2 {
			close(ackStarted)
			<-ackRelease
		}
		reports <- report.GetObservationRevision()
		return nil
	}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- coordinator.Run(ctx) }()
	require.Equal(t, uint64(1), <-reports)
	select {
	case <-docker.burstDone:
	case <-time.After(time.Second):
		t.Fatal("churn burst was not consumed promptly while a scan was in flight")
	}
	close(ackRelease)
	require.Equal(t, uint64(2), <-reports)
	require.Equal(t, uint64(3), <-reports)
	cancel()
	require.NoError(t, <-done)
	require.Equal(t, 3, docker.callCount())
	require.Equal(t, 1, docker.maximumConcurrent())
}

type errorDetector struct{ err error }

func (detector errorDetector) Discover(context.Context, []domain.Rule) ([]domain.CandidateObservation, error) {
	return nil, detector.err
}

type recoveringDetector struct {
	err   error
	calls int
}

func (detector *recoveringDetector) Discover(context.Context, []domain.Rule) ([]domain.CandidateObservation, error) {
	detector.calls++
	return nil, detector.err
}

type fakeDockerRPCClient struct {
	snapshot *discoveryv1.DockerSnapshotResponse
	err      error
	request  *discoveryv1.DockerSnapshotRequest
}

func (client *fakeDockerRPCClient) Snapshot(_ context.Context, request *discoveryv1.DockerSnapshotRequest, _ ...grpc.CallOption) (*discoveryv1.DockerSnapshotResponse, error) {
	client.request = request
	return client.snapshot, client.err
}
func (client *fakeDockerRPCClient) Watch(context.Context, *discoveryv1.DockerWatchRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[discoveryv1.DockerEvent], error) {
	return nil, errors.New("unused")
}

type reconnectingDockerRPCClient struct{ calls atomic.Int32 }

func (*reconnectingDockerRPCClient) Snapshot(context.Context, *discoveryv1.DockerSnapshotRequest, ...grpc.CallOption) (*discoveryv1.DockerSnapshotResponse, error) {
	return nil, errors.New("unused")
}
func (client *reconnectingDockerRPCClient) Watch(context.Context, *discoveryv1.DockerWatchRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[discoveryv1.DockerEvent], error) {
	client.calls.Add(1)
	return readyEOFStream{}, nil
}

type readyEOFStream struct{}

func (readyEOFStream) Recv() (*discoveryv1.DockerEvent, error) { return nil, io.EOF }
func (readyEOFStream) Header() (metadata.MD, error) {
	return metadata.Pairs("dbpilot-docker-watch-ready", "1"), nil
}
func (readyEOFStream) Trailer() metadata.MD     { return nil }
func (readyEOFStream) CloseSend() error         { return nil }
func (readyEOFStream) Context() context.Context { return context.Background() }
func (readyEOFStream) SendMsg(any) error        { return nil }
func (readyEOFStream) RecvMsg(any) error        { return io.EOF }

type churnDetector struct {
	mu         sync.Mutex
	calls      int
	active     int
	maximum    int
	ackStarted <-chan struct{}
	burstDone  chan struct{}
}

func newChurnDetector(ackStarted <-chan struct{}) *churnDetector {
	return &churnDetector{ackStarted: ackStarted, burstDone: make(chan struct{})}
}

func (detector *churnDetector) Discover(ctx context.Context, _ []domain.Rule) ([]domain.CandidateObservation, error) {
	detector.mu.Lock()
	detector.calls++
	detector.active++
	if detector.active > detector.maximum {
		detector.maximum = detector.active
	}
	detector.mu.Unlock()
	defer func() { detector.mu.Lock(); detector.active--; detector.mu.Unlock() }()
	return nil, nil
}

func (detector *churnDetector) Watch(ctx context.Context, trigger func() error) {
	_ = trigger()
	select {
	case <-detector.ackStarted:
	case <-ctx.Done():
		return
	}
	for index := 0; index < 1000; index++ {
		_ = trigger()
	}
	close(detector.burstDone)
	<-ctx.Done()
}

func (detector *churnDetector) callCount() int {
	detector.mu.Lock()
	defer detector.mu.Unlock()
	return detector.calls
}
func (detector *churnDetector) maximumConcurrent() int {
	detector.mu.Lock()
	defer detector.mu.Unlock()
	return detector.maximum
}
