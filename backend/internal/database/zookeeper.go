package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	zooKeeperRoleLeader        = "leader"
	zooKeeperRoleFollower      = "follower"
	zooKeeperCompatibilityPath = "/commands/monitor"
)

type ZooKeeperEndpointFailure struct{ Endpoint Endpoint }
type ZooKeeperEndpointErrors struct{ Failures []ZooKeeperEndpointFailure }

func (errors *ZooKeeperEndpointErrors) Error() string {
	if len(errors.Failures) == 1 {
		return fmt.Sprintf("ZooKeeper collection failed for %s endpoint", errors.Failures[0].Endpoint.Role)
	}
	return fmt.Sprintf("ZooKeeper collection failed for %d endpoints", len(errors.Failures))
}

type ZooKeeperParseIssues struct{ Issues []ParseIssue }

func (issues *ZooKeeperParseIssues) Error() string {
	return fmt.Sprintf("ZooKeeper collection skipped %d malformed or unavailable metrics", len(issues.Issues))
}

type zooKeeperAdapter struct {
	definition   ComponentDefinition
	client       JMXClient
	capabilities CapabilityMatrix
}

type zooKeeperMonitorFetcher interface {
	FetchZooKeeperMonitor(context.Context, Endpoint) (map[string]JSONValue, error)
}

func NewZooKeeperAdapter(definition ComponentDefinition, client JMXClient) (ComponentAdapter, error) {
	if err := validateComponentDefinition(definition); err != nil {
		return nil, err
	}
	if definition.Kind != ZooKeeperComponent {
		return nil, fmt.Errorf("component %q is not a ZooKeeper component", definition.ID)
	}
	if isNilInterface(client) {
		return nil, errors.New("ZooKeeper JMX client is required")
	}
	for _, endpoint := range definition.Endpoints {
		if _, err := normalizedZooKeeperRole(endpoint.Role); err != nil {
			return nil, err
		}
	}
	definition.Endpoints = append([]Endpoint(nil), definition.Endpoints...)
	return &zooKeeperAdapter{definition: definition, client: client, capabilities: CapabilityMatrix{Metrics: true, MetricIDs: ZooKeeperMetricIDs()}}, nil
}

func NewZooKeeperAdapterWithRuntime(definition ComponentDefinition, resolver SecretResolver) (ComponentAdapter, error) {
	if isNilInterface(resolver) {
		return nil, errors.New("ZooKeeper runtime secret resolver is required")
	}
	config := JMXClientConfig{SecretRef: definition.SecretRef}
	if definition.TLSRef != "" {
		config.TLS = TLSConfig{Enabled: true, CASecretRef: definition.TLSRef}
	}
	return NewZooKeeperAdapter(definition, NewJMXClient(resolver, config))
}
func RegisterZooKeeperAdapter(registry ComponentRegistry, definition ComponentDefinition, client JMXClient) error {
	if isNilInterface(registry) {
		return errors.New("component registry is required")
	}
	adapter, err := NewZooKeeperAdapter(definition, client)
	if err != nil {
		return err
	}
	return registry.Register(definition, adapter)
}
func RegisterZooKeeperAdapterWithRuntime(registry ComponentRegistry, definition ComponentDefinition, resolver SecretResolver) error {
	if isNilInterface(registry) {
		return errors.New("component registry is required")
	}
	adapter, err := NewZooKeeperAdapterWithRuntime(definition, resolver)
	if err != nil {
		return err
	}
	return registry.Register(definition, adapter)
}
func ZooKeeperMetricIDs() []string                 { return metricIDs(zooKeeperBeanAllowlist()) }
func (*zooKeeperAdapter) Component() ComponentKind { return ZooKeeperComponent }
func (adapter *zooKeeperAdapter) Capabilities() CapabilityMatrix {
	return cloneCapabilities(adapter.capabilities)
}
func (adapter *zooKeeperAdapter) Ping(ctx context.Context) error {
	_, err := adapter.Collect(ctx, MetricRequest{})
	return err
}
func (*zooKeeperAdapter) Close() error { return nil }

func (adapter *zooKeeperAdapter) Collect(ctx context.Context, request MetricRequest) ([]MetricSample, error) {
	if ctx == nil {
		return nil, errors.New("ZooKeeper collect context is required")
	}
	requested, err := validateComponentMetricRequest(request, ZooKeeperMetricIDs(), "ZooKeeper")
	if err != nil {
		return nil, err
	}
	samples := make([]MetricSample, 0)
	failures := make([]ZooKeeperEndpointFailure, 0)
	issues := make([]ParseIssue, 0)
	for _, endpoint := range adapter.definition.Endpoints {
		role, roleErr := normalizedZooKeeperRole(endpoint.Role)
		if roleErr != nil {
			return samples, roleErr
		}
		if endpointPath(endpoint.URL) == zooKeeperCompatibilityPath {
			monitor, ok := adapter.client.(zooKeeperMonitorFetcher)
			if !ok {
				failures = append(failures, ZooKeeperEndpointFailure{Endpoint: Endpoint{Role: role}})
				continue
			}
			values, fetchErr := monitor.FetchZooKeeperMonitor(ctx, endpoint)
			if fetchErr != nil {
				failures = append(failures, ZooKeeperEndpointFailure{Endpoint: Endpoint{Role: role}})
				continue
			}
			endpointSamples, endpointIssues, normalizeErr := NormalizeJMXBeans([]JMXBean{{Name: "dbpilot:zookeeper=monitor", Attributes: values}}, zooKeeperMonitorAllowlist(), JMXMetricLabels{Cluster: adapter.definition.ID, Component: string(ZooKeeperComponent), Role: role, Host: componentEndpointHost(endpoint.URL), Instance: adapter.definition.ID})
			if normalizeErr != nil {
				return samples, errors.New("normalize ZooKeeper monitor metrics")
			}
			issues = append(issues, endpointIssues...)
			for _, sample := range endpointSamples {
				if len(requested) == 0 || requested[sample.MetricName] {
					samples = append(samples, sample)
				}
			}
			continue
		}
		beans, fetchErr := adapter.client.Fetch(ctx, endpoint, zooKeeperBeanAllowlist())
		if fetchErr != nil {
			failures = append(failures, ZooKeeperEndpointFailure{Endpoint: Endpoint{Role: role}})
			continue
		}
		endpointSamples, endpointIssues, normalizeErr := NormalizeJMXBeans(beans, zooKeeperBeanAllowlist(), JMXMetricLabels{Cluster: adapter.definition.ID, Component: string(ZooKeeperComponent), Role: role, Host: componentEndpointHost(endpoint.URL), Instance: adapter.definition.ID})
		if normalizeErr != nil {
			return samples, errors.New("normalize ZooKeeper JMX metrics")
		}
		issues = append(issues, endpointIssues...)
		for _, sample := range endpointSamples {
			if len(requested) == 0 || requested[sample.MetricName] {
				samples = append(samples, sample)
			}
		}
	}
	statuses := make([]error, 0, 2)
	if len(failures) != 0 {
		statuses = append(statuses, &ZooKeeperEndpointErrors{Failures: failures})
	}
	if len(issues) != 0 {
		statuses = append(statuses, &ZooKeeperParseIssues{Issues: issues})
	}
	if len(statuses) != 0 {
		return samples, errors.Join(statuses...)
	}
	return samples, nil
}

func normalizedZooKeeperRole(role string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case zooKeeperRoleLeader:
		return zooKeeperRoleLeader, nil
	case zooKeeperRoleFollower:
		return zooKeeperRoleFollower, nil
	default:
		return "", errors.New("ZooKeeper endpoint role must be leader or follower")
	}
}
func endpointPath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Path
}
func zooKeeperBeanAllowlist() BeanAllowlist {
	return BeanAllowlist{
		"org.apache.ZooKeeperService:name0=ReplicatedServer_*": zooKeeperMetricProperties(),
	}
}
func zooKeeperMetricProperties() BeanProperties {
	return BeanProperties{"AvgRequestLatency": {MetricName: "zookeeper.request.latency", Unit: "ms"}, "OutstandingRequests": {MetricName: "zookeeper.outstanding_requests", Unit: "count"}, "PacketsReceived": {MetricName: "zookeeper.requests.received", Unit: "count"}, "PacketsSent": {MetricName: "zookeeper.requests.sent", Unit: "count"}, "NumAliveConnections": {MetricName: "zookeeper.sessions", Unit: "count"}, "QuorumSize": {MetricName: "zookeeper.quorum.members", Unit: "count"}, "ZnodeCount": {MetricName: "zookeeper.znodes", Unit: "count"}, "WatchCount": {MetricName: "zookeeper.watches", Unit: "count"}, "TxnLogElapsedSyncTime": {MetricName: "zookeeper.transaction_log.sync_time", Unit: "ms"}, "SnapshotTime": {MetricName: "zookeeper.snapshot.time", Unit: "ms"}}
}

func zooKeeperMonitorAllowlist() BeanAllowlist {
	return BeanAllowlist{"dbpilot:zookeeper=monitor": {"zk_avg_latency": {MetricName: "zookeeper.request.latency", Unit: "ms"}, "zk_num_alive_connections": {MetricName: "zookeeper.sessions", Unit: "count"}, "zk_outstanding_requests": {MetricName: "zookeeper.outstanding_requests", Unit: "count"}, "zk_packets_received": {MetricName: "zookeeper.requests.received", Unit: "count"}, "zk_packets_sent": {MetricName: "zookeeper.requests.sent", Unit: "count"}, "zk_znode_count": {MetricName: "zookeeper.znodes", Unit: "count"}, "zk_watch_count": {MetricName: "zookeeper.watches", Unit: "count"}}}
}

func parseZooKeeperMonitor(body []byte) (map[string]JSONValue, error) {
	values := make(map[string]JSONValue)
	if json.Unmarshal(body, &values) == nil {
		return values, nil
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.HasPrefix(fields[0], "zk_") {
			encoded, _ := json.Marshal(fields[1])
			values[fields[0]] = encoded
		}
	}
	if len(values) == 0 {
		return nil, errors.New("decode ZooKeeper monitor response")
	}
	return values, nil
}
