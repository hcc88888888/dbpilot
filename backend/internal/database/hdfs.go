package database

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const (
	hdfsRoleNameNode = "namenode"
	hdfsRoleDataNode = "datanode"
)

// HDFSEndpointFailure identifies an unavailable endpoint without exposing its address or runtime credentials.
type HDFSEndpointFailure struct{ Endpoint Endpoint }
type HDFSEndpointErrors struct{ Failures []HDFSEndpointFailure }

func (errors *HDFSEndpointErrors) Error() string {
	if len(errors.Failures) == 1 {
		return fmt.Sprintf("HDFS JMX collection failed for %s endpoint", errors.Failures[0].Endpoint.Role)
	}
	return fmt.Sprintf("HDFS JMX collection failed for %d endpoints", len(errors.Failures))
}

// HDFSParseIssues records optional or malformed fixed JMX metrics.
type HDFSParseIssues struct{ Issues []ParseIssue }

func (issues *HDFSParseIssues) Error() string {
	return fmt.Sprintf("HDFS JMX collection skipped %d malformed or unavailable metrics", len(issues.Issues))
}

type hdfsAdapter struct {
	definition   ComponentDefinition
	client       JMXClient
	capabilities CapabilityMatrix
}

func NewHDFSAdapter(definition ComponentDefinition, client JMXClient) (ComponentAdapter, error) {
	if err := validateComponentDefinition(definition); err != nil {
		return nil, err
	}
	if definition.Kind != HDFSComponent {
		return nil, fmt.Errorf("component %q is not an HDFS component", definition.ID)
	}
	if isNilInterface(client) {
		return nil, errors.New("HDFS JMX client is required")
	}
	for _, endpoint := range definition.Endpoints {
		if _, err := normalizedHDFSRole(endpoint.Role); err != nil {
			return nil, err
		}
	}
	definition.Endpoints = append([]Endpoint(nil), definition.Endpoints...)
	return &hdfsAdapter{definition: definition, client: client, capabilities: CapabilityMatrix{Metrics: true, MetricIDs: HDFSMetricIDs()}}, nil
}

func NewHDFSAdapterWithRuntime(definition ComponentDefinition, resolver SecretResolver) (ComponentAdapter, error) {
	if isNilInterface(resolver) {
		return nil, errors.New("HDFS runtime secret resolver is required")
	}
	config := JMXClientConfig{SecretRef: definition.SecretRef}
	if definition.TLSRef != "" {
		config.TLS = TLSConfig{Enabled: true, CASecretRef: definition.TLSRef}
	}
	return NewHDFSAdapter(definition, NewJMXClient(resolver, config))
}
func RegisterHDFSAdapter(registry ComponentRegistry, definition ComponentDefinition, client JMXClient) error {
	if isNilInterface(registry) {
		return errors.New("component registry is required")
	}
	adapter, err := NewHDFSAdapter(definition, client)
	if err != nil {
		return err
	}
	return registry.Register(definition, adapter)
}
func RegisterHDFSAdapterWithRuntime(registry ComponentRegistry, definition ComponentDefinition, resolver SecretResolver) error {
	if isNilInterface(registry) {
		return errors.New("component registry is required")
	}
	adapter, err := NewHDFSAdapterWithRuntime(definition, resolver)
	if err != nil {
		return err
	}
	return registry.Register(definition, adapter)
}
func HDFSMetricIDs() []string                 { return metricIDs(hdfsAllBeanAllowlist()) }
func (*hdfsAdapter) Component() ComponentKind { return HDFSComponent }
func (adapter *hdfsAdapter) Capabilities() CapabilityMatrix {
	return cloneCapabilities(adapter.capabilities)
}
func (adapter *hdfsAdapter) Ping(ctx context.Context) error {
	_, err := adapter.Collect(ctx, MetricRequest{})
	return err
}
func (*hdfsAdapter) Close() error { return nil }

func (adapter *hdfsAdapter) Collect(ctx context.Context, request MetricRequest) ([]MetricSample, error) {
	if ctx == nil {
		return nil, errors.New("HDFS collect context is required")
	}
	requested, err := validateComponentMetricRequest(request, HDFSMetricIDs(), "HDFS")
	if err != nil {
		return nil, err
	}
	samples := make([]MetricSample, 0)
	failures := make([]HDFSEndpointFailure, 0)
	issues := make([]ParseIssue, 0)
	for _, endpoint := range adapter.definition.Endpoints {
		role, roleErr := normalizedHDFSRole(endpoint.Role)
		if roleErr != nil {
			return samples, roleErr
		}
		allowlist := hdfsBeanAllowlist(role)
		beans, fetchErr := adapter.client.Fetch(ctx, endpoint, allowlist)
		if fetchErr != nil {
			failures = append(failures, HDFSEndpointFailure{Endpoint: Endpoint{Role: role}})
			continue
		}
		endpointSamples, endpointIssues, normalizeErr := NormalizeJMXBeans(beans, allowlist, JMXMetricLabels{Cluster: adapter.definition.ID, Component: string(HDFSComponent), Role: role, Host: componentEndpointHost(endpoint.URL), Instance: adapter.definition.ID})
		if normalizeErr != nil {
			return samples, errors.New("normalize HDFS JMX metrics")
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
		statuses = append(statuses, &HDFSEndpointErrors{Failures: failures})
	}
	if len(issues) != 0 {
		statuses = append(statuses, &HDFSParseIssues{Issues: issues})
	}
	if len(statuses) != 0 {
		return samples, errors.Join(statuses...)
	}
	return samples, nil
}

func normalizedHDFSRole(role string) (string, error) {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(role), "-", "")) {
	case hdfsRoleNameNode, "name_node":
		return hdfsRoleNameNode, nil
	case hdfsRoleDataNode, "data_node":
		return hdfsRoleDataNode, nil
	default:
		return "", errors.New("HDFS endpoint role must be namenode or datanode")
	}
}
func hdfsBeanAllowlist(role string) BeanAllowlist {
	all := hdfsAllBeanAllowlist()
	allowed := make(BeanAllowlist)
	for bean, properties := range all {
		if (role == hdfsRoleNameNode && strings.Contains(bean, "service=NameNode")) || (role == hdfsRoleDataNode && strings.Contains(bean, "service=DataNode")) {
			allowed[bean] = properties
		}
	}
	return allowed
}
func hdfsAllBeanAllowlist() BeanAllowlist {
	return BeanAllowlist{
		"Hadoop:service=NameNode,name=FSNamesystem":           {"CapacityTotal": {MetricName: "hdfs.namenode.capacity_total", Unit: "bytes"}, "CapacityUsed": {MetricName: "hdfs.namenode.capacity_used", Unit: "bytes"}, "CapacityRemaining": {MetricName: "hdfs.namenode.capacity_remaining", Unit: "bytes"}, "FilesTotal": {MetricName: "hdfs.namenode.files", Unit: "count"}, "BlocksTotal": {MetricName: "hdfs.namenode.blocks", Unit: "count"}, "UnderReplicatedBlocks": {MetricName: "hdfs.namenode.under_replicated_blocks", Unit: "count"}, "MissingBlocks": {MetricName: "hdfs.namenode.missing_blocks", Unit: "count"}, "CorruptFiles": {MetricName: "hdfs.namenode.corrupt_files", Unit: "count"}},
		"Hadoop:service=NameNode,name=RpcActivityForPort8020": {"RpcQueueTimeAvgTime": {MetricName: "hdfs.namenode.rpc.queue_latency", Unit: "ms"}, "RpcProcessingTimeAvgTime": {MetricName: "hdfs.namenode.rpc.processing_latency", Unit: "ms"}, "NumOpenConnections": {MetricName: "hdfs.namenode.rpc.open_connections", Unit: "count"}},
		"Hadoop:service=DataNode,name=FSDatasetState":         {"Capacity": {MetricName: "hdfs.datanode.capacity", Unit: "bytes"}, "DfsUsed": {MetricName: "hdfs.datanode.used", Unit: "bytes"}, "Remaining": {MetricName: "hdfs.datanode.remaining", Unit: "bytes"}, "NumFailedVolumes": {MetricName: "hdfs.datanode.failed_volumes", Unit: "count"}, "NumBlocks": {MetricName: "hdfs.datanode.blocks", Unit: "count"}},
		"Hadoop:service=DataNode,name=DataNodeInfo":           {"xceiverCount": {MetricName: "hdfs.datanode.xceiver_count", Unit: "count"}},
		"Hadoop:service=DataNode,name=DataNodeActivity-*":     {"BytesRead": {MetricName: "hdfs.datanode.io.bytes_read", Unit: "bytes"}, "BytesWritten": {MetricName: "hdfs.datanode.io.bytes_written", Unit: "bytes"}},
	}
}
func metricIDs(allowlist BeanAllowlist) []string {
	set := make(map[string]struct{})
	for _, properties := range allowlist {
		for _, definition := range properties {
			set[definition.MetricName] = struct{}{}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
func validateComponentMetricRequest(request MetricRequest, ids []string, component string) (map[string]bool, error) {
	allowed := make(map[string]bool, len(ids))
	for _, id := range ids {
		allowed[id] = true
	}
	requested := make(map[string]bool, len(request.MetricIDs))
	for _, id := range request.MetricIDs {
		if !allowed[id] {
			return nil, fmt.Errorf("unsupported %s metric %q", component, id)
		}
		requested[id] = true
	}
	return requested, nil
}
func componentEndpointHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
