package database

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestRegisterHBaseAdapterCollectsMasterAndRegionServerFixtures(t *testing.T) {
	registry := NewComponentRegistry()
	definition := hbaseTestDefinition()
	client := &fixtureJMXClient{fixtures: map[string][]JMXBean{
		definition.Endpoints[0].URL: decodeHBaseFixture(t, `{"beans":[{"name":"Hadoop:service=HBase,name=Master,sub=Server","numRegionServers":3,"numDeadRegionServers":1,"averageLoad":2.5},{"name":"Hadoop:service=HBase,name=JvmMetrics","MemHeapUsedM":128}]}`),
		definition.Endpoints[1].URL: decodeHBaseFixture(t, `{"beans":[{"name":"Hadoop:service=HBase,name=RegionServer,sub=Server","regionCount":12,"blockCacheHitCount":42,"blockCacheMissCount":2,"flushQueueLength":4,"compactionQueueLength":5},{"name":"Hadoop:service=HBase,name=RegionServer,sub=WAL","appendCount":9,"syncTime":7}]}`),
	}}
	if err := RegisterHBaseAdapter(registry, definition, client); err != nil {
		t.Fatalf("RegisterHBaseAdapter() error = %v", err)
	}
	adapter, found := registry.Adapter(definition.ID)
	if !found {
		t.Fatal("registered HBase adapter was not found")
	}
	samples, err := adapter.Collect(context.Background(), MetricRequest{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	assertHBaseSample(t, samples, "hbase.master.live_region_servers", "master", 3)
	assertHBaseSample(t, samples, "hbase.regionserver.regions", "regionserver", 12)
	assertHBaseSample(t, samples, "hbase.block_cache.hits", "regionserver", 42)
	assertHBaseSample(t, samples, "hbase.wal.appends", "regionserver", 9)
	if !slices.Contains(client.allowlistedProperties(), "numRegionServers") || slices.Contains(client.allowlistedProperties(), "unsafe") {
		t.Fatalf("JMX allowlist properties = %v, want fixed HBase properties only", client.allowlistedProperties())
	}
}

func TestHBaseAdapterSupportsVersionAliasesAndMissingOptionalBeans(t *testing.T) {
	definition := hbaseTestDefinition()
	client := &fixtureJMXClient{fixtures: map[string][]JMXBean{
		definition.Endpoints[0].URL: decodeHBaseFixture(t, `{"beans":[{"name":"Hadoop:service=HBase,name=Master","numLiveRegionServers":4}]}`),
		definition.Endpoints[1].URL: decodeHBaseFixture(t, `{"beans":[{"name":"Hadoop:service=HBase,name=RegionServer,sub=Regions","numRegions":15,"memstoreSize":11,"storeFileSize":22}]}`),
	}}
	adapter, err := NewHBaseAdapter(definition, client)
	if err != nil {
		t.Fatalf("NewHBaseAdapter() error = %v", err)
	}
	samples, err := adapter.Collect(context.Background(), MetricRequest{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	assertHBaseSample(t, samples, "hbase.master.live_region_servers", "master", 4)
	assertHBaseSample(t, samples, "hbase.regionserver.regions", "regionserver", 15)
	assertHBaseSample(t, samples, "hbase.memstore.size", "regionserver", 11)
	assertHBaseSample(t, samples, "hbase.store.file_size", "regionserver", 22)
}

func TestHBaseAdapterReturnsEndpointFailuresWithoutDiscardingHealthySamples(t *testing.T) {
	definition := hbaseTestDefinition()
	client := &fixtureJMXClient{
		fixtures: map[string][]JMXBean{definition.Endpoints[0].URL: decodeHBaseFixture(t, `{"beans":[{"name":"Hadoop:service=HBase,name=Master,sub=Server","numRegionServers":3}]}`)},
		errors:   map[string]error{definition.Endpoints[1].URL: errors.New("unreachable")},
	}
	adapter, err := NewHBaseAdapter(definition, client)
	if err != nil {
		t.Fatalf("NewHBaseAdapter() error = %v", err)
	}
	samples, err := adapter.Collect(context.Background(), MetricRequest{})
	assertHBaseSample(t, samples, "hbase.master.live_region_servers", "master", 3)
	var endpointErrors *HBaseEndpointErrors
	if !errors.As(err, &endpointErrors) || len(endpointErrors.Failures) != 1 || endpointErrors.Failures[0].Endpoint.Role != "regionserver" {
		t.Fatalf("Collect() error = %v, want independent RegionServer endpoint failure", err)
	}
}

func TestHBaseAdapterRejectsUnknownMetricIDs(t *testing.T) {
	definition := hbaseTestDefinition()
	adapter, err := NewHBaseAdapter(definition, &fixtureJMXClient{})
	if err != nil {
		t.Fatalf("NewHBaseAdapter() error = %v", err)
	}
	if _, err := adapter.Collect(context.Background(), MetricRequest{MetricIDs: []string{"unsafe.bean.property"}}); err == nil {
		t.Fatal("Collect() error = nil, want arbitrary metric request rejected")
	}
}

func TestNewHBaseAdapterWithRuntimeResolvesCredentialAndTLSReferences(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got, want := request.Header.Get("Authorization"), "Bearer runtime-token"; got != want {
			t.Fatalf("Authorization = %q, want %q", got, want)
		}
		_, _ = writer.Write([]byte(`{"beans":[{"name":"Hadoop:service=HBase,name=Master,sub=Server","numRegionServers":2}]}`))
	}))
	defer server.Close()
	certificate := server.Certificate()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if _, err := x509.ParseCertificate(certificate.Raw); err != nil {
		t.Fatalf("server certificate: %v", err)
	}
	definition := hbaseTestDefinition()
	definition.Endpoints = []Endpoint{{URL: server.URL + "/jmx", Role: "master"}}
	definition.TLSRef = "secret://runtime/hbase-ca"
	adapter, err := NewHBaseAdapterWithRuntime(definition, StaticSecretResolver{
		definition.SecretRef: []byte("runtime-token"),
		definition.TLSRef:    caPEM,
	})
	if err != nil {
		t.Fatalf("NewHBaseAdapterWithRuntime() error = %v", err)
	}
	samples, err := adapter.Collect(context.Background(), MetricRequest{})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	assertHBaseSample(t, samples, "hbase.master.live_region_servers", "master", 2)
}

func hbaseTestDefinition() ComponentDefinition {
	return ComponentDefinition{
		ID:        "hbase-prod",
		Kind:      HBaseComponent,
		SecretRef: "secret://runtime/hbase",
		Endpoints: []Endpoint{
			{URL: "https://master.example.test:16010/jmx", Role: "master"},
			{URL: "https://rs-1.example.test:16030/jmx", Role: "regionserver"},
		},
	}
}

func decodeHBaseFixture(t *testing.T, fixture string) []JMXBean {
	t.Helper()
	var payload struct {
		Beans []map[string]JSONValue `json:"beans"`
	}
	if err := json.Unmarshal([]byte(fixture), &payload); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	beans := make([]JMXBean, 0, len(payload.Beans))
	for _, raw := range payload.Beans {
		name := stringJSONValue(raw["name"])
		delete(raw, "name")
		beans = append(beans, JMXBean{Name: name, Attributes: raw})
	}
	return beans
}

func assertHBaseSample(t *testing.T, samples []MetricSample, name, role string, value float64) {
	t.Helper()
	for _, sample := range samples {
		if sample.MetricName == name && sample.Role == role && sample.Value == value {
			if sample.Component != "hbase" || sample.Cluster != "hbase-prod" || sample.Instance != "hbase-prod" {
				t.Fatalf("sample labels = %#v, want HBase component and instance labels", sample)
			}
			return
		}
	}
	t.Fatalf("samples = %#v, want %s/%s=%v", samples, name, role, value)
}

type fixtureJMXClient struct {
	fixtures map[string][]JMXBean
	errors   map[string]error
	requests []BeanAllowlist
}

func (client *fixtureJMXClient) Fetch(_ context.Context, endpoint Endpoint, allowlist BeanAllowlist) ([]JMXBean, error) {
	client.requests = append(client.requests, allowlist)
	if err := client.errors[endpoint.URL]; err != nil {
		return nil, err
	}
	return client.fixtures[endpoint.URL], nil
}

func (client *fixtureJMXClient) allowlistedProperties() []string {
	properties := make([]string, 0)
	for _, allowlist := range client.requests {
		for _, bean := range allowlist {
			for property := range bean {
				properties = append(properties, property)
			}
		}
	}
	return properties
}
