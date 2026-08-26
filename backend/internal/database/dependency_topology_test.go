package database

import (
	"errors"
	"reflect"
	"testing"
)

func TestResolveTopologyUsesOnlyAuthorizedHBaseDependencyReferences(t *testing.T) {
	definitions := []ComponentDefinition{
		componentDefinition("hdfs-prod", HDFSComponent, "namenode"),
		componentDefinition("zk-prod", ZooKeeperComponent, "leader"),
		{
			ID:        "hbase-prod",
			Kind:      HBaseComponent,
			SecretRef: "secret://runtime/hbase-prod",
			Endpoints: []Endpoint{{URL: "https://hbase.example.test/jmx", Role: "master"}},
			Dependencies: DependencyRef{
				HDFSClusterID:      "hdfs-prod",
				ZooKeeperClusterID: "zk-prod",
			},
		},
	}

	topology, err := ResolveTopology(definitions)
	if err != nil {
		t.Fatalf("ResolveTopology() error = %v", err)
	}
	if len(topology.Relations) != 2 {
		t.Fatalf("relations = %#v, want two authorized dependencies", topology.Relations)
	}
	if !topology.HasRelation("hbase-prod", "hdfs-prod", HDFSComponent) || !topology.HasRelation("hbase-prod", "zk-prod", ZooKeeperComponent) {
		t.Fatalf("relations = %#v, want HBase-to-HDFS and HBase-to-ZooKeeper", topology.Relations)
	}
	if _, containsSecret := reflect.TypeOf(TopologyNode{}).FieldByName("SecretRef"); containsSecret {
		t.Fatal("TopologyNode must not expose inherited credential references")
	}
}

func TestResolveTopologyRejectsUnauthorizedDependencyReference(t *testing.T) {
	definitions := []ComponentDefinition{
		componentDefinition("hdfs-prod", HDFSComponent, "namenode"),
		{
			ID:           "hbase-prod",
			Kind:         HBaseComponent,
			SecretRef:    "secret://runtime/hbase-prod",
			Endpoints:    []Endpoint{{URL: "https://hbase.example.test/jmx", Role: "master"}},
			Dependencies: DependencyRef{ZooKeeperClusterID: "unapproved-zk"},
		},
	}

	_, err := ResolveTopology(definitions)
	if !errors.Is(err, ErrUnauthorizedDependency) {
		t.Fatalf("ResolveTopology() error = %v, want ErrUnauthorizedDependency", err)
	}
}

func componentDefinition(id string, kind ComponentKind, role string) ComponentDefinition {
	return ComponentDefinition{
		ID:        id,
		Kind:      kind,
		SecretRef: "secret://runtime/" + id,
		Endpoints: []Endpoint{{URL: "https://" + id + ".example.test/jmx", Role: role}},
	}
}
