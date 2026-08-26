package database

import (
	"context"
	"errors"
)

// ComponentKind identifies a non-SQL observability component.
type ComponentKind string

const (
	HBaseComponent     ComponentKind = "hbase"
	HDFSComponent      ComponentKind = "hdfs"
	ZooKeeperComponent ComponentKind = "zookeeper"
	ComponentHBase                   = HBaseComponent
	ComponentHDFS                    = HDFSComponent
	ComponentZooKeeper               = ZooKeeperComponent
)

// Endpoint is a read-only component collection endpoint.
type Endpoint struct {
	URL  string `yaml:"url" json:"url"`
	Role string `yaml:"role" json:"role"`
}

// DependencyRef links an HBase component to authorized dependency clusters.
type DependencyRef struct {
	HDFSClusterID      string `yaml:"hdfs_cluster_id" json:"hdfs_cluster_id"`
	ZooKeeperClusterID string `yaml:"zookeeper_cluster_id" json:"zookeeper_cluster_id"`
}

// ComponentDefinition describes a component without embedding credentials.
type ComponentDefinition struct {
	ID           string        `yaml:"id" json:"id"`
	Kind         ComponentKind `yaml:"kind" json:"kind"`
	Endpoints    []Endpoint    `yaml:"endpoints" json:"endpoints"`
	SecretRef    string        `yaml:"secret_ref" json:"secret_ref"`
	TLSRef       string        `yaml:"tls_ref,omitempty" json:"tls_ref,omitempty"`
	Dependencies DependencyRef `yaml:"dependencies,omitempty" json:"dependencies,omitempty"`
}

// ComponentEndpointStatus identifies an endpoint collection scope without
// retaining or exposing its URL.
type ComponentEndpointStatus struct {
	Role string `json:"role"`
	Host string `json:"host"`
}

// ComponentCollectionStatus is the collection completeness input shared by
// the Agent envelope and dependency health aggregation.
type ComponentCollectionStatus struct {
	Cluster             string                    `json:"cluster"`
	Component           ComponentKind             `json:"component"`
	State               string                    `json:"state"`
	ErrorCode           string                    `json:"error_code,omitempty"`
	Attempts            int                       `json:"attempts"`
	SampleCount         int                       `json:"sample_count"`
	IncompleteEndpoints []ComponentEndpointStatus `json:"incomplete_endpoints,omitempty"`
}

type componentEndpointFailureReporter interface {
	FailedEndpoints() []ComponentEndpointStatus
}

// FailedComponentEndpoints extracts sanitized endpoint dimensions from a
// possibly joined adapter status.
func FailedComponentEndpoints(err error) []ComponentEndpointStatus {
	var reporter componentEndpointFailureReporter
	if !errors.As(err, &reporter) {
		return nil
	}
	return reporter.FailedEndpoints()
}

// ComponentAdapter is the deliberately narrow boundary for non-SQL adapters.
type ComponentAdapter interface {
	Component() ComponentKind
	Capabilities() CapabilityMatrix
	Ping(context.Context) error
	Collect(context.Context, MetricRequest) ([]MetricSample, error)
	Close() error
}

// ComponentRegistry stores authorized component definitions and their adapters.
type ComponentRegistry interface {
	Register(ComponentDefinition, ComponentAdapter) error
	Definition(string) (ComponentDefinition, bool)
	Adapter(string) (ComponentAdapter, bool)
}
