package discovery

import (
	"context"
	"errors"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	domain "dbpilot.local/platform/internal/discovery"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
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

func TestCoordinatorKeepsNativeDiscoveryWhenDockerHelperUnavailable(t *testing.T) {
	native := &recordingDetector{candidate: domain.CandidateObservation{ObservationID: "native-1", Source: domain.SourceNative, DatabaseFamily: "mysql", DatabaseVariant: "mysql", NormalizedEndpoint: "127.0.0.1:3306", ProcessIdentity: "mysqld", Confidence: .9, Evidence: []domain.Evidence{{Kind: domain.EvidenceProcessName, Value: "mysqld"}}}}
	docker := errorDetector{err: ErrDockerDiscoveryUnavailable}
	rules, attestation := testRules(t)
	reports := make(chan int, 1)
	coordinator, err := NewCoordinator(CoordinatorConfig{HostID: "host-1", AgentID: "agent-1", Detector: native, DockerDetector: docker, RuleSet: rules, Attestation: attestation, Now: func() time.Time { return time.Date(2026, 8, 30, 8, 0, 0, 0, time.UTC) }, Reporter: func(_ context.Context, report *agentv1.DiscoveryReport) error {
		reports <- len(report.GetCandidates())
		return nil
	}})
	require.NoError(t, err)
	require.NoError(t, coordinator.Scan(context.Background(), ScanEnrollment))
	require.Equal(t, 1, <-reports)
	require.Contains(t, coordinator.AdditionalCapabilities(), "docker_discovery_unavailable")
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

type errorDetector struct{ err error }

func (detector errorDetector) Discover(context.Context, []domain.Rule) ([]domain.CandidateObservation, error) {
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
