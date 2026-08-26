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
	hbaseRoleMaster       = "master"
	hbaseRoleRegionServer = "regionserver"
)

// HBaseEndpointFailure identifies a failed endpoint without putting its URL
// or runtime credentials in a returned error string.
type HBaseEndpointFailure struct {
	Endpoint Endpoint
}

// HBaseEndpointErrors preserves partial collection: samples from healthy
// endpoints are returned while callers can still surface unavailable roles.
type HBaseEndpointErrors struct {
	Failures []HBaseEndpointFailure
}

func (errors *HBaseEndpointErrors) Error() string {
	if len(errors.Failures) == 1 {
		return fmt.Sprintf("HBase JMX collection failed for %s endpoint", errors.Failures[0].Endpoint.Role)
	}
	return fmt.Sprintf("HBase JMX collection failed for %d endpoints", len(errors.Failures))
}

type hbaseAdapter struct {
	definition   ComponentDefinition
	client       JMXClient
	capabilities CapabilityMatrix
}

// NewHBaseAdapter creates a read-only HBase component adapter. Bean and
// property selection are fixed in this package; callers can only select the
// published metric IDs.
func NewHBaseAdapter(definition ComponentDefinition, client JMXClient) (ComponentAdapter, error) {
	if err := validateComponentDefinition(definition); err != nil {
		return nil, err
	}
	if definition.Kind != HBaseComponent {
		return nil, fmt.Errorf("component %q is not an HBase component", definition.ID)
	}
	if isNilInterface(client) {
		return nil, errors.New("HBase JMX client is required")
	}
	for _, endpoint := range definition.Endpoints {
		if _, err := normalizedHBaseRole(endpoint.Role); err != nil {
			return nil, err
		}
	}
	return &hbaseAdapter{
		definition: definition,
		client:     client,
		capabilities: CapabilityMatrix{
			Metrics:   true,
			MetricIDs: HBaseMetricIDs(),
		},
	}, nil
}

// NewHBaseAdapterWithRuntime creates the shared JMX client from runtime-only
// secret references. TLSRef is treated as the trusted CA bundle reference.
func NewHBaseAdapterWithRuntime(definition ComponentDefinition, resolver SecretResolver) (ComponentAdapter, error) {
	if isNilInterface(resolver) {
		return nil, errors.New("HBase runtime secret resolver is required")
	}
	config := JMXClientConfig{SecretRef: definition.SecretRef}
	if definition.TLSRef != "" {
		config.TLS = TLSConfig{Enabled: true, CASecretRef: definition.TLSRef}
	}
	return NewHBaseAdapter(definition, NewJMXClient(resolver, config))
}

// RegisterHBaseAdapter constructs and registers the fixed HBase adapter.
func RegisterHBaseAdapter(registry ComponentRegistry, definition ComponentDefinition, client JMXClient) error {
	if isNilInterface(registry) {
		return errors.New("component registry is required")
	}
	adapter, err := NewHBaseAdapter(definition, client)
	if err != nil {
		return err
	}
	return registry.Register(definition, adapter)
}

// RegisterHBaseAdapterWithRuntime registers HBase with credentials and TLS
// material resolved on each JMX request.
func RegisterHBaseAdapterWithRuntime(registry ComponentRegistry, definition ComponentDefinition, resolver SecretResolver) error {
	if isNilInterface(registry) {
		return errors.New("component registry is required")
	}
	adapter, err := NewHBaseAdapterWithRuntime(definition, resolver)
	if err != nil {
		return err
	}
	return registry.Register(definition, adapter)
}

// HBaseMetricIDs returns copies of the fixed, supported HBase metric IDs.
func HBaseMetricIDs() []string {
	set := make(map[string]struct{})
	for _, properties := range hbaseAllBeanAllowlist() {
		for _, metric := range properties {
			set[metric.MetricName] = struct{}{}
		}
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (adapter *hbaseAdapter) Component() ComponentKind { return HBaseComponent }

func (adapter *hbaseAdapter) Capabilities() CapabilityMatrix {
	return cloneCapabilities(adapter.capabilities)
}

func (adapter *hbaseAdapter) Ping(ctx context.Context) error {
	_, err := adapter.Collect(ctx, MetricRequest{})
	return err
}

func (adapter *hbaseAdapter) Collect(ctx context.Context, request MetricRequest) ([]MetricSample, error) {
	if ctx == nil {
		return nil, errors.New("HBase collect context is required")
	}
	requested, err := validateHBaseMetricRequest(request)
	if err != nil {
		return nil, err
	}
	samples := make([]MetricSample, 0)
	failures := make([]HBaseEndpointFailure, 0)
	for _, endpoint := range adapter.definition.Endpoints {
		role, _ := normalizedHBaseRole(endpoint.Role)
		beans, fetchErr := adapter.client.Fetch(ctx, endpoint, hbaseBeanAllowlist(role))
		if fetchErr != nil {
			failures = append(failures, HBaseEndpointFailure{Endpoint: Endpoint{Role: role}})
			continue
		}
		host := hbaseEndpointHost(endpoint.URL)
		endpointSamples, _, normalizeErr := NormalizeJMXBeans(beans, hbaseBeanAllowlist(role), JMXMetricLabels{
			Cluster:   adapter.definition.ID,
			Component: string(HBaseComponent),
			Role:      role,
			Host:      host,
			Instance:  adapter.definition.ID,
		})
		if normalizeErr != nil {
			return samples, errors.New("normalize HBase JMX metrics")
		}
		for _, sample := range endpointSamples {
			if len(requested) == 0 || requested[sample.MetricName] {
				samples = append(samples, sample)
			}
		}
	}
	if len(failures) != 0 {
		return samples, &HBaseEndpointErrors{Failures: failures}
	}
	return samples, nil
}

func (*hbaseAdapter) Close() error { return nil }

func normalizedHBaseRole(role string) (string, error) {
	switch strings.ToLower(strings.ReplaceAll(strings.TrimSpace(role), "-", "")) {
	case hbaseRoleMaster:
		return hbaseRoleMaster, nil
	case hbaseRoleRegionServer, "region_server":
		return hbaseRoleRegionServer, nil
	default:
		return "", errors.New("HBase endpoint role must be master or regionserver")
	}
}

func validateHBaseMetricRequest(request MetricRequest) (map[string]bool, error) {
	allowed := make(map[string]bool, len(HBaseMetricIDs()))
	for _, id := range HBaseMetricIDs() {
		allowed[id] = true
	}
	requested := make(map[string]bool, len(request.MetricIDs))
	for _, id := range request.MetricIDs {
		if !allowed[id] {
			return nil, fmt.Errorf("unsupported HBase metric %q", id)
		}
		requested[id] = true
	}
	return requested, nil
}

func hbaseEndpointHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func hbaseBeanAllowlist(role string) BeanAllowlist {
	all := hbaseAllBeanAllowlist()
	allowed := map[string]struct{}{
		"Hadoop:service=HBase,name=JvmMetrics": {},
	}
	if role == hbaseRoleMaster {
		allowed["Hadoop:service=HBase,name=Master,sub=Server"] = struct{}{}
		allowed["Hadoop:service=HBase,name=Master"] = struct{}{}
	} else {
		for bean := range all {
			if strings.Contains(bean, "name=RegionServer") {
				allowed[bean] = struct{}{}
			}
		}
	}
	result := make(BeanAllowlist, len(allowed))
	for bean := range allowed {
		result[bean] = all[bean]
	}
	return result
}

func hbaseAllBeanAllowlist() BeanAllowlist {
	return BeanAllowlist{
		"Hadoop:service=HBase,name=JvmMetrics": {
			"MemHeapUsedM": {MetricName: "hbase.jvm.heap_used", Unit: "MiB"},
			"MemHeapMaxM":  {MetricName: "hbase.jvm.heap_max", Unit: "MiB"},
			"GcCount":      {MetricName: "hbase.jvm.gc_count", Unit: "count"},
			"GcTimeMillis": {MetricName: "hbase.jvm.gc_time", Unit: "ms"},
		},
		"Hadoop:service=HBase,name=Master,sub=Server": {
			"numRegionServers":     {MetricName: "hbase.master.live_region_servers", Unit: "count"},
			"numLiveRegionServers": {MetricName: "hbase.master.live_region_servers", Unit: "count"},
			"numDeadRegionServers": {MetricName: "hbase.master.dead_region_servers", Unit: "count"},
			"averageLoad":          {MetricName: "hbase.master.average_load", Unit: "count"},
		},
		"Hadoop:service=HBase,name=Master": {
			"numRegionServers":     {MetricName: "hbase.master.live_region_servers", Unit: "count"},
			"numLiveRegionServers": {MetricName: "hbase.master.live_region_servers", Unit: "count"},
			"numDeadRegionServers": {MetricName: "hbase.master.dead_region_servers", Unit: "count"},
			"averageLoad":          {MetricName: "hbase.master.average_load", Unit: "count"},
		},
		"Hadoop:service=HBase,name=RegionServer,sub=Server": {
			"regionCount":             {MetricName: "hbase.regionserver.regions", Unit: "count"},
			"storeCount":              {MetricName: "hbase.regionserver.stores", Unit: "count"},
			"storeFileCount":          {MetricName: "hbase.regionserver.store_files", Unit: "count"},
			"blockCacheCount":         {MetricName: "hbase.block_cache.blocks", Unit: "count"},
			"blockCacheSize":          {MetricName: "hbase.block_cache.size", Unit: "bytes"},
			"blockCacheFreeSize":      {MetricName: "hbase.block_cache.free_size", Unit: "bytes"},
			"blockCacheHitCount":      {MetricName: "hbase.block_cache.hits", Unit: "count"},
			"blockCacheMissCount":     {MetricName: "hbase.block_cache.misses", Unit: "count"},
			"blockCacheEvictionCount": {MetricName: "hbase.block_cache.evictions", Unit: "count"},
			"flushQueueLength":        {MetricName: "hbase.flush.queue_length", Unit: "count"},
			"compactionQueueLength":   {MetricName: "hbase.compaction.queue_length", Unit: "count"},
		},
		"Hadoop:service=HBase,name=RegionServer,sub=Regions": {
			"numRegions":     {MetricName: "hbase.regionserver.regions", Unit: "count"},
			"numStores":      {MetricName: "hbase.regionserver.stores", Unit: "count"},
			"numStoreFiles":  {MetricName: "hbase.regionserver.store_files", Unit: "count"},
			"memstoreSize":   {MetricName: "hbase.memstore.size", Unit: "bytes"},
			"storeFileSize":  {MetricName: "hbase.store.file_size", Unit: "bytes"},
			"storeFileCount": {MetricName: "hbase.regionserver.store_files", Unit: "count"},
		},
		"Hadoop:service=HBase,name=RegionServer,sub=WAL": {
			"appendCount":     {MetricName: "hbase.wal.appends", Unit: "count"},
			"appendTime":      {MetricName: "hbase.wal.append_time", Unit: "ms"},
			"syncTime":        {MetricName: "hbase.wal.sync_time", Unit: "ms"},
			"slowAppendCount": {MetricName: "hbase.wal.slow_appends", Unit: "count"},
		},
		"Hadoop:service=HBase,name=RegionServer,sub=Flush": {
			"flushTime":  {MetricName: "hbase.flush.time", Unit: "ms"},
			"flushCount": {MetricName: "hbase.flush.count", Unit: "count"},
		},
		"Hadoop:service=HBase,name=RegionServer,sub=Compactions": {
			"compactionTime":  {MetricName: "hbase.compaction.time", Unit: "ms"},
			"compactionCount": {MetricName: "hbase.compaction.count", Unit: "count"},
		},
		"Hadoop:service=HBase,name=RegionServer,sub=Split": {
			"splitTime":  {MetricName: "hbase.split.time", Unit: "ms"},
			"splitCount": {MetricName: "hbase.split.count", Unit: "count"},
		},
		"Hadoop:service=HBase,name=RegionServer,sub=IPC": {
			"queueCallTime":      {MetricName: "hbase.request.queue_time", Unit: "ms"},
			"processingCallTime": {MetricName: "hbase.request.processing_time", Unit: "ms"},
			"totalCallTime":      {MetricName: "hbase.request.total_time", Unit: "ms"},
			"numOpenConnections": {MetricName: "hbase.request.open_connections", Unit: "count"},
		},
	}
}

var _ ComponentAdapter = (*hbaseAdapter)(nil)
