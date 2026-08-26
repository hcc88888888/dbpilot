package database

import "context"

// ComponentKind identifies a non-SQL observability component.
type ComponentKind string

const (
	HBaseComponent      ComponentKind = "hbase"
	HDFSComponent       ComponentKind = "hdfs"
	ZooKeeperComponent  ComponentKind = "zookeeper"
	ComponentHBase      = HBaseComponent
	ComponentHDFS       = HDFSComponent
	ComponentZooKeeper  = ZooKeeperComponent
)

// Endpoint is a read-only component collection endpoint.
type Endpoint struct {
	URL  string
	Role string
}

// DependencyRef links an HBase component to authorized dependency clusters.
type DependencyRef struct {
	HDFSClusterID      string
	ZooKeeperClusterID string
}

// ComponentDefinition describes a component without embedding credentials.
type ComponentDefinition struct {
	ID           string
	Kind         ComponentKind
	Endpoints    []Endpoint
	SecretRef    string
	TLSRef       string
	Dependencies DependencyRef
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
