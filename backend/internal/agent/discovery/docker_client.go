package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	discoveryv1 "dbpilot.local/platform/gen/discovery/v1"
	domain "dbpilot.local/platform/internal/discovery"
	dockerhelper "dbpilot.local/platform/internal/dockerdiscovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrDockerDiscoveryUnavailable      = errors.New("docker_discovery_unavailable")
	ErrDockerDiscoveryPermissionDenied = errors.New("docker_discovery_permission_denied")
	dockerContainerIDPattern           = regexp.MustCompile(`^[a-f0-9]{64}$`)
	dockerNetworkNamePattern           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	dockerSecretPattern                = regexp.MustCompile(`(?i)(password|passwd|pwd|token|secret|credential|authorization)(=|:)`)
	dockerDSNPattern                   = regexp.MustCompile(`[^\s:]+:[^\s@]+@(?:tcp\(|[^\s]+)`)
	dockerOracleDSNPattern             = regexp.MustCompile(`(?i)^[^/:@\s]+/[^@\s]+@[a-z0-9_.-]+(?::[0-9]+)?(?:/[a-z0-9_.-]+)?$`)
)

const dockerSnapshotTimeout = 8 * time.Second

type DockerDetectorConfig struct {
	Client              discoveryv1.DockerDiscoveryClient
	RuleRevision        uint64
	AllowedLabelKeys    []string
	AllowedNetworkNames []string
	ReconnectBackoff    time.Duration
}

type DockerDetector struct {
	client    discoveryv1.DockerDiscoveryClient
	revision  uint64
	allowed   []string
	networks  []string
	reconnect time.Duration
}

func NewDockerDetector(config DockerDetectorConfig) (*DockerDetector, error) {
	if config.Client == nil || config.RuleRevision == 0 || len(config.AllowedLabelKeys) > 32 || len(config.AllowedNetworkNames) > 32 {
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
	seenNetworks := make(map[string]struct{}, len(config.AllowedNetworkNames))
	for _, name := range config.AllowedNetworkNames {
		if !dockerNetworkNamePattern.MatchString(name) {
			return nil, domain.ErrInvalid
		}
		if _, duplicate := seenNetworks[name]; duplicate {
			return nil, domain.ErrInvalid
		}
		seenNetworks[name] = struct{}{}
	}
	if config.ReconnectBackoff == 0 {
		config.ReconnectBackoff = time.Second
	}
	if config.ReconnectBackoff < 10*time.Millisecond || config.ReconnectBackoff > time.Minute {
		return nil, domain.ErrInvalid
	}
	allowed := append([]string(nil), config.AllowedLabelKeys...)
	sort.Strings(allowed)
	networks := append([]string(nil), config.AllowedNetworkNames...)
	sort.Strings(networks)
	return &DockerDetector{client: config.Client, revision: config.RuleRevision, allowed: allowed, networks: networks, reconnect: config.ReconnectBackoff}, nil
}

func NewDockerDetectorAt(ctx context.Context, socketPath string, ruleRevision uint64, allowedLabelKeys []string, networkAllowlists ...[]string) (*DockerDetector, *grpc.ClientConn, error) {
	if len(networkAllowlists) > 1 {
		return nil, nil, domain.ErrInvalid
	}
	var allowedNetworkNames []string
	if len(networkAllowlists) == 1 {
		allowedNetworkNames = networkAllowlists[0]
	}
	connection, err := dockerhelper.Dial(ctx, socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrDockerDiscoveryUnavailable, err)
	}
	detector, err := NewDockerDetector(DockerDetectorConfig{Client: discoveryv1.NewDockerDiscoveryClient(connection), RuleRevision: ruleRevision, AllowedLabelKeys: allowedLabelKeys, AllowedNetworkNames: allowedNetworkNames})
	if err != nil {
		_ = connection.Close()
		return nil, nil, err
	}
	return detector, connection, nil
}

func (detector *DockerDetector) Discover(ctx context.Context, rules []domain.Rule) ([]domain.CandidateObservation, error) {
	snapshotContext, cancel := context.WithTimeout(ctx, dockerSnapshotTimeout)
	defer cancel()
	response, err := detector.client.Snapshot(snapshotContext, &discoveryv1.DockerSnapshotRequest{RuleRevision: detector.revision, AllowedLabelKeys: append([]string(nil), detector.allowed...), AllowedNetworkNames: append([]string(nil), detector.networks...)}, grpc.MaxCallRecvMsgSize(4<<20))
	if err != nil {
		if status.Code(err) == codes.PermissionDenied {
			return nil, ErrDockerDiscoveryPermissionDenied
		}
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
		if err := validateDockerObservation(container, detector.allowed, detector.networks); err != nil {
			return nil, err
		}
		if container.GetStatus() != discoveryv1.DockerContainerStatus_DOCKER_CONTAINER_STATUS_RUNNING {
			continue
		}
		for _, rule := range rules {
			if len(rule.DockerImagePatterns) == 0 || !matchesDockerRule(container, rule) {
				continue
			}
			endpoint, endpointPort, found := dockerEndpoint(container, rule)
			if found {
				stableIdentity, identityErr := stableDockerIdentity(container, rule)
				if identityErr != nil {
					return nil, identityErr
				}
				observation := domain.CandidateObservation{ObservationID: "docker-" + container.GetContainerId()[:16], Source: domain.SourceDocker, DatabaseFamily: rule.DatabaseFamily, DatabaseVariant: rule.DatabaseVariant, NormalizedEndpoint: endpoint, ContainerIdentity: stableIdentity, ContainerImage: container.GetImage(), Confidence: .95, Evidence: []domain.Evidence{{Kind: domain.EvidenceContainerImage, Value: container.GetImage()}, {Kind: domain.EvidenceContainerPort, Value: fmt.Sprintf("%d/tcp", endpointPort)}, {Kind: domain.EvidenceContainerID, Value: container.GetContainerId()}}}
				for _, selector := range rule.DockerLabelSelectors {
					key, _, _ := strings.Cut(selector, "=")
					observation.Evidence = append(observation.Evidence, domain.Evidence{Kind: domain.EvidenceContainerLabel, Value: key})
				}
				result = append(result, observation)
			}
		}
	}
	return result, nil
}

func dockerEndpoint(container *discoveryv1.DockerContainerObservation, rule domain.Rule) (string, uint32, bool) {
	allowedNetworks := make(map[string]struct{}, len(rule.DockerNetworkNames))
	for _, name := range rule.DockerNetworkNames {
		allowedNetworks[name] = struct{}{}
	}
	for _, endpoint := range container.GetInternalEndpoints() {
		if _, allowed := allowedNetworks[endpoint.GetNetworkName()]; !allowed || endpoint.GetProtocol() != "tcp" || !containsPort(rule.DefaultPorts, uint16(endpoint.GetPort())) {
			continue
		}
		return net.JoinHostPort(endpoint.GetAddress(), fmt.Sprintf("%d", endpoint.GetPort())), endpoint.GetPort(), true
	}
	for _, port := range container.GetPorts() {
		if port.GetProtocol() != "tcp" || !containsPort(rule.DefaultPorts, uint16(port.GetContainerPort())) {
			continue
		}
		return net.JoinHostPort(port.GetHostAddress(), fmt.Sprintf("%d", port.GetHostPort())), port.GetContainerPort(), true
	}
	return "", 0, false
}

func stableDockerIdentity(container *discoveryv1.DockerContainerObservation, rule domain.Rule) (string, error) {
	value := ""
	if rule.DockerIdentityLabel != "" {
		value = container.GetLabels()[rule.DockerIdentityLabel]
	}
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(container.GetName()))
	}
	if value == "" || len(value) > 128 || !controlIdentifier.MatchString(value) {
		return "", domain.ErrInvalid
	}
	return value, nil
}

func (detector *DockerDetector) Watch(ctx context.Context, reconcile func() error) {
	for ctx.Err() == nil {
		stream, err := detector.client.Watch(ctx, &discoveryv1.DockerWatchRequest{RuleRevision: detector.revision, AllowedLabelKeys: append([]string(nil), detector.allowed...), AllowedNetworkNames: append([]string(nil), detector.networks...)}, grpc.MaxCallRecvMsgSize(4<<20))
		if err == nil {
			if _, headerErr := stream.Header(); headerErr != nil {
				err = headerErr
			} else if reconcile != nil {
				err = reconcile()
			}
			for {
				if err != nil {
					break
				}
				_, receiveErr := stream.Recv()
				if receiveErr != nil {
					if receiveErr == io.EOF {
						break
					}
					err = receiveErr
					break
				}
				if reconcile != nil {
					if reconcileErr := reconcile(); reconcileErr != nil {
						err = reconcileErr
						break
					}
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

func validateDockerObservation(container *discoveryv1.DockerContainerObservation, allowed []string, networkAllowlists ...[]string) error {
	if len(networkAllowlists) > 1 {
		return domain.ErrInvalid
	}
	if container == nil || !dockerContainerIDPattern.MatchString(container.GetContainerId()) || container.GetName() == "" || len(container.GetName()) > 256 || container.GetImage() == "" || len(container.GetImage()) > 512 || len(container.GetPorts()) > 256 || len(container.GetInternalEndpoints()) > 256 || len(container.GetLabels()) > len(allowed) || len(container.GetCommandSummary()) > 512 || !validRedactedCommandSummary(container.GetCommandSummary()) || strings.ContainsAny(container.GetName()+container.GetImage()+container.GetCommandSummary()+container.GetCgroup(), "\x00\r\n") {
		return domain.ErrInvalid
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key, value := range container.GetLabels() {
		if _, ok := allowedSet[key]; !ok || len(value) > 256 || !validRedactedExternalValue(value) || dockerSecretPattern.MatchString(key+"="+value) && value != "[REDACTED]" {
			return domain.ErrInvalid
		}
	}
	for _, port := range container.GetPorts() {
		if port.GetHostPort() == 0 || port.GetHostPort() > 65535 || port.GetContainerPort() == 0 || port.GetContainerPort() > 65535 || net.ParseIP(port.GetHostAddress()) == nil || (port.GetProtocol() != "tcp" && port.GetProtocol() != "udp") {
			return domain.ErrInvalid
		}
	}
	var configuredNetworks []string
	if len(networkAllowlists) == 1 {
		configuredNetworks = networkAllowlists[0]
	}
	allowedNetworks := make(map[string]struct{}, len(configuredNetworks))
	for _, name := range configuredNetworks {
		allowedNetworks[name] = struct{}{}
	}
	for _, endpoint := range container.GetInternalEndpoints() {
		if endpoint.GetPort() == 0 || endpoint.GetPort() > 65535 || net.ParseIP(endpoint.GetAddress()) == nil || !dockerNetworkNamePattern.MatchString(endpoint.GetNetworkName()) || endpoint.GetProtocol() != "tcp" && endpoint.GetProtocol() != "udp" {
			return domain.ErrInvalid
		}
		if _, ok := allowedNetworks[endpoint.GetNetworkName()]; !ok {
			return domain.ErrInvalid
		}
	}
	return nil
}

func validRedactedCommandSummary(summary string) bool {
	if !utf8.ValidString(summary) || strings.TrimSpace(summary) != summary || strings.ContainsAny(summary, "\x00\r\n") {
		return false
	}
	tokens := strings.Fields(summary)
	pending := false
	for _, token := range tokens {
		if pending {
			if token != "[REDACTED]" {
				return false
			}
			pending = false
			continue
		}
		lower := strings.ToLower(token)
		if token == "-H" || agentSensitiveFlag(lower) {
			pending = true
			continue
		}
		key, value, equal := strings.Cut(token, "=")
		if equal && agentCredentialAssignmentKey(strings.ToLower(strings.TrimLeft(key, "-"))) {
			if value != "[REDACTED]" {
				return false
			}
			continue
		}
		if equal && (key == "-H" || agentSensitiveFlag(strings.ToLower(key))) {
			if value != "[REDACTED]" {
				return false
			}
			continue
		}
		if strings.HasPrefix(token, "-p") && len(token) > 2 {
			if token != "-p[REDACTED]" {
				return false
			}
			continue
		}
		if strings.HasPrefix(token, "-H") && len(token) > 2 {
			if token != "-H[REDACTED]" {
				return false
			}
			continue
		}
		if equal {
			if !validRedactedExternalValue(value) {
				return false
			}
		} else if !validRedactedExternalValue(token) {
			return false
		}
	}
	return !pending
}

func agentSensitiveFlag(value string) bool {
	switch value {
	case "-p", "--password", "--passwd", "--pwd", "--token", "--secret", "--credential", "--authorization", "--header", "--database-url", "--database_url", "--dsn", "--uri", "--url", "--connection", "--connection-string", "--connection_string":
		return true
	default:
		return false
	}
}

func agentCredentialAssignmentKey(value string) bool {
	switch value {
	case "user", "username", "password", "passwd", "pwd", "token", "secret", "credential", "authorization", "api-key", "api_key":
		return true
	default:
		return false
	}
}

func validRedactedExternalValue(value string) bool {
	if !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	if !strings.Contains(value, "://") {
		if dockerDSNPattern.MatchString(value) || dockerOracleDSNPattern.MatchString(value) {
			return false
		}
		return !dockerSecretPattern.MatchString(value) || value == "[REDACTED]"
	}
	parsed, err := url.Parse(strings.ReplaceAll(value, "[REDACTED]", "REDACTED"))
	if err != nil || parsed.Scheme == "" {
		return false
	}
	if parsed.User != nil {
		if !redactionMarker(parsed.User.Username()) {
			return false
		}
		if _, hasPassword := parsed.User.Password(); hasPassword {
			return false
		}
	}
	query := parsed.Query()
	for key, values := range query {
		if !dockerSecretPattern.MatchString(key + "=") {
			continue
		}
		for _, item := range values {
			if !redactionMarker(item) {
				return false
			}
		}
	}
	return true
}

func redactionMarker(value string) bool { return value == "REDACTED" || value == "[REDACTED]" }

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
		if rule.DockerIdentityLabel != "" {
			seen[rule.DockerIdentityLabel] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for key := range seen {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func DockerAllowedNetworkNames(rules []domain.Rule) []string {
	seen := map[string]struct{}{}
	for _, rule := range rules {
		for _, name := range rule.DockerNetworkNames {
			seen[name] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
