package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"

	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	domain "dbpilot.local/platform/internal/discovery"
	dockerhelper "dbpilot.local/platform/internal/dockerdiscovery"
	"google.golang.org/grpc"
)

var (
	ErrDockerDiscoveryUnavailable = errors.New("docker_discovery_unavailable")
	dockerContainerIDPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	dockerSecretPattern           = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|credential|authorization)(=|:)`)
)

type DockerDetectorConfig struct {
	Client           discoveryv1.DockerDiscoveryClient
	RuleRevision     uint64
	AllowedLabelKeys []string
	ReconnectBackoff time.Duration
}

type DockerDetector struct {
	client    discoveryv1.DockerDiscoveryClient
	revision  uint64
	allowed   []string
	reconnect time.Duration
}

func NewDockerDetector(config DockerDetectorConfig) (*DockerDetector, error) {
	if config.Client == nil || config.RuleRevision == 0 || len(config.AllowedLabelKeys) > 32 {
		return nil, domain.ErrInvalid
	}
	seen := make(map[string]struct{}, len(config.AllowedLabelKeys))
	for _, key := range config.AllowedLabelKeys {
		if key == "" || len(key) > 128 || strings.ContainsAny(key, "\x00\r\n/\\:@") {
			return nil, domain.ErrInvalid
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, domain.ErrInvalid
		}
		seen[key] = struct{}{}
	}
	if config.ReconnectBackoff == 0 {
		config.ReconnectBackoff = time.Second
	}
	if config.ReconnectBackoff < 10*time.Millisecond || config.ReconnectBackoff > time.Minute {
		return nil, domain.ErrInvalid
	}
	allowed := append([]string(nil), config.AllowedLabelKeys...)
	sort.Strings(allowed)
	return &DockerDetector{client: config.Client, revision: config.RuleRevision, allowed: allowed, reconnect: config.ReconnectBackoff}, nil
}

func NewDockerDetectorAt(ctx context.Context, socketPath string, ruleRevision uint64, allowedLabelKeys []string) (*DockerDetector, *grpc.ClientConn, error) {
	connection, err := dockerhelper.Dial(ctx, socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrDockerDiscoveryUnavailable, err)
	}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: discoveryv1.NewDockerDiscoveryClient(connection), RuleRevision: ruleRevision, AllowedLabelKeys: allowedLabelKeys})
	if err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	return detector, connection, nil
}

func (detector *DockerDetector) Discover(ctx context.Context, rules []domain.Rule) ([]domain.CandidateObservation, error) {
	response, err := detector.client.Snapshot(ctx, &discoveryv1.DockerSnapshotRequest{RuleRevision: detector.revision, AllowedLabelKeys: append([]string(nil), detector.allowed...)}, grpc.MaxCallRecvMsgSize(4<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: helper snapshot", ErrDockerDiscoveryUnavailable)
	}
	if response.GetErrorCode() != "" {
		return nil, fmt.Errorf("%w: helper reported error", ErrDockerDiscoveryUnavailable)
	}
	if len(response.GetContainers()) > 1024 {
		return nil, domain.ErrInvalid
	}
	result := make([]domain.CandidateObservation, 0)
	for _, container := range response.GetContainers() {
		if err := validateDockerObservation(container, detector.allowed); err != nil {
			return nil, err
		}
		if container.GetStatus() != discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING {
			continue
		}
		for _, rule := range rules {
			if len(rule.DockerImagePatterns) == 0 || !matchesDockerRule(container, rule) {
				continue
			}
			for _, port := range container.GetPorts() {
				if port.GetProtocol() != "tcp" || !containsPort(rule.DefaultPorts, uint16(port.GetContainerPort())) {
					continue
				}
				endpoint := net.JoinHostPort(port.GetHostAddress(), fmt.Sprintf("%d", port.GetHostPort()))
				observation := domain.CandidateObservation{ObservationID: "docker-" + container.GetContainerId()[:16], Source: domain.SourceDocker, DatabaseFamily: rule.DatabaseFamily, DatabaseVariant: rule.DatabaseVariant, NormalizedEndpoint: endpoint, ContainerIdentity: container.GetContainerId(), ContainerImage: container.GetImage(), Confidence: .95, Evidence: []domain.Evidence{{Kind: domain.EvidenceContainerImage, Value: container.GetImage()}, {Kind: domain.EvidenceContainerPort, Value: fmt.Sprintf("%d/tcp", port.GetContainerPort())}}}
				for _, selector := range rule.DockerLabelSelectors {
					key, _, _ := strings.Cut(selector, "=")
					observation.Evidence = append(observation.Evidence, domain.Evidence{Kind: domain.EvidenceContainerLabel, Value: key})
				}
				result = append(result, observation)
				break
			}
		}
	}
	return result, nil
}

func (detector *DockerDetector) Watch(ctx context.Context, notify func()) {
	for ctx.Err() == nil {
		stream, err := detector.client.Watch(ctx, &discoveryv1.DockerWatchRequest{RuleRevision: detector.revision, AllowedLabelKeys: append([]string(nil), detector.allowed...)}, grpc.MaxCallRecvMsgSize(4<<20))
		if err == nil {
			for {
				_, receiveErr := stream.Recv()
				if receiveErr != nil {
					if receiveErr == io.EOF {
						break
					}
					err = receiveErr
					break
				}
				if notify != nil {
					notify()
				}
			}
		}
		timer := time.NewTimer(detector.reconnect)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return
		}
	}
}

func validateDockerObservation(container *discoveryv1.DockerContainerObservation, allowed []string) error {
	if container == nil || !dockerContainerIDPattern.MatchString(container.GetContainerId()) || container.GetName() == "" || len(container.GetName()) > 256 || container.GetImage() == "" || len(container.GetImage()) > 512 || len(container.GetPorts()) > 256 || len(container.GetLabels()) > len(allowed) || len(container.GetCommandSummary()) > 512 || dockerhelper.RedactCommand(strings.Fields(container.GetCommandSummary())) != container.GetCommandSummary() || strings.ContainsAny(container.GetName()+container.GetImage()+container.GetCommandSummary()+container.GetCgroup(), "\x00\r\n") {
		return domain.ErrInvalid
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key, value := range container.GetLabels() {
		if _, ok := allowedSet[key]; !ok || len(value) > 256 || dockerSecretPattern.MatchString(key+"="+value) && value != "[REDACTED]" {
			return domain.ErrInvalid
		}
	}
	for _, port := range container.GetPorts() {
		if port.GetHostPort() == 0 || port.GetHostPort() > 65535 || port.GetContainerPort() == 0 || port.GetContainerPort() > 65535 || net.ParseIP(port.GetHostAddress()) == nil || (port.GetProtocol() != "tcp" && port.GetProtocol() != "udp") {
			return domain.ErrInvalid
		}
	}
	return nil
}

func matchesDockerRule(container *discoveryv1.DockerContainerObservation, rule domain.Rule) bool {
	imageMatch := false
	for _, pattern := range rule.DockerImagePatterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		if compiled.MatchString(container.GetImage()) {
			imageMatch = true
			break
		}
	}
	if !imageMatch {
		return false
	}
	for _, selector := range rule.DockerLabelSelectors {
		key, value, ok := strings.Cut(selector, "=")
		if !ok || container.GetLabels()[key] != value {
			return false
		}
	}
	return true
}

func containsPort(values []uint16, target uint16) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func DockerAllowedLabelKeys(rules []domain.Rule) []string {
	seen := map[string]struct{}{}
	for _, rule := range rules {
		for _, selector := range rule.DockerLabelSelectors {
			key, _, ok := strings.Cut(selector, "=")
			if ok {
				seen[key] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for key := range seen {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
