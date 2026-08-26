package database

import (
	"context"
	"errors"
	"testing"
)

func TestHDFSAdapterCollectsNameNodeAndDataNodeFixtures(t *testing.T) {
	definition := hdfsTestDefinition()
	client := &fixtureJMXClient{fixtures: map[string][]JMXBean{
		definition.Endpoints[0].URL: decodeHBaseFixture(t, `{"beans":[{"name":"Hadoop:service=NameNode,name=FSNamesystem","CapacityTotal":1000,"CapacityUsed":400,"UnderReplicatedBlocks":3,"MissingBlocks":1},{"name":"Hadoop:service=NameNode,name=RpcActivityForPort8020","RpcQueueTimeAvgTime":4}]}`),
		definition.Endpoints[1].URL: decodeHBaseFixture(t, `{"beans":[{"name":"Hadoop:service=DataNode,name=FSDatasetState","Capacity":500,"DfsUsed":200,"Remaining":300,"NumFailedVolumes":2},{"name":"Hadoop:service=DataNode,name=DataNodeInfo","xceiverCount":7},{"name":"Hadoop:service=DataNode,name=DataNodeActivity-9866","BytesRead":12,"BytesWritten":13}]}`),
	}}
	adapter, err := NewHDFSAdapter(definition, client)
	if err != nil {
		t.Fatalf("NewHDFSAdapter() error = %v", err)
	}

	samples, err := adapter.Collect(context.Background(), MetricRequest{})
	allowHDFSParseIssues(t, err)
	assertComponentSample(t, samples, "hdfs.namenode.capacity_total", "hdfs", "namenode", 1000)
	assertComponentSample(t, samples, "hdfs.namenode.under_replicated_blocks", "hdfs", "namenode", 3)
	assertComponentSample(t, samples, "hdfs.datanode.capacity", "hdfs", "datanode", 500)
	assertComponentSample(t, samples, "hdfs.datanode.failed_volumes", "hdfs", "datanode", 2)
	assertComponentSample(t, samples, "hdfs.datanode.io.bytes_read", "hdfs", "datanode", 12)
	if !containsString(client.allowlistedProperties(), "CapacityTotal") || containsString(client.allowlistedProperties(), "unsafe") {
		t.Fatalf("JMX allowlist properties = %v, want fixed HDFS properties only", client.allowlistedProperties())
	}
}

func TestHDFSAdapterReportsOptionalFieldsWithoutDiscardingSamples(t *testing.T) {
	definition := hdfsTestDefinition()
	client := &fixtureJMXClient{fixtures: map[string][]JMXBean{
		definition.Endpoints[0].URL: decodeHBaseFixture(t, `{"beans":[{"name":"Hadoop:service=NameNode,name=FSNamesystem","CapacityTotal":1000}]}`),
	}}
	adapter, err := NewHDFSAdapter(definition, client)
	if err != nil {
		t.Fatalf("NewHDFSAdapter() error = %v", err)
	}

	samples, err := adapter.Collect(context.Background(), MetricRequest{})
	assertComponentSample(t, samples, "hdfs.namenode.capacity_total", "hdfs", "namenode", 1000)
	var issues *HDFSParseIssues
	if !errors.As(err, &issues) || !hasParseIssue(issues.Issues, "Hadoop:service=NameNode,name=FSNamesystem", "CapacityUsed", JMXParseMissingAttribute) {
		t.Fatalf("Collect() error = %v, want missing optional field status", err)
	}
}

func TestHDFSAdapterRejectsUnknownMetricAndRole(t *testing.T) {
	definition := hdfsTestDefinition()
	if _, err := NewHDFSAdapter(ComponentDefinition{ID: definition.ID, Kind: HDFSComponent, SecretRef: definition.SecretRef, Endpoints: []Endpoint{{URL: definition.Endpoints[0].URL, Role: "worker"}}}, &fixtureJMXClient{}); err == nil {
		t.Fatal("NewHDFSAdapter() error = nil, want invalid role rejected")
	}
	adapter, err := NewHDFSAdapter(definition, &fixtureJMXClient{})
	if err != nil {
		t.Fatalf("NewHDFSAdapter() error = %v", err)
	}
	if _, err := adapter.Collect(context.Background(), MetricRequest{MetricIDs: []string{"unsafe.bean.property"}}); err == nil {
		t.Fatal("Collect() error = nil, want arbitrary metric request rejected")
	}
}

func hdfsTestDefinition() ComponentDefinition {
	return ComponentDefinition{ID: "hdfs-prod", Kind: HDFSComponent, SecretRef: "secret://runtime/hdfs", Endpoints: []Endpoint{
		{URL: "https://namenode.example.test:9870/jmx", Role: "namenode"},
		{URL: "https://datanode-1.example.test:9864/jmx", Role: "datanode"},
	}}
}

func allowHDFSParseIssues(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	var issues *HDFSParseIssues
	if !errors.As(err, &issues) {
		t.Fatalf("Collect() error = %v, want only HDFS parse issue status", err)
	}
}
