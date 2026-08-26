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
	if len(topology.Relations()) != 2 {
		t.Fatalf("relations = %#v, want two authorized dependencies", topology.Relations())
	}
	if !topology.HasRelation("hbase-prod", "hdfs-prod", HDFSComponent) || !topology.HasRelation("hbase-prod", "zk-prod", ZooKeeperComponent) {
		t.Fatalf("relations = %#v, want HBase-to-HDFS and HBase-to-ZooKeeper", topology.Relations())
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

func TestResolveTopologyCanonicalizesRoleAliasesAndReturnsDefensiveCopies(t *testing.T) {
	topology, err := ResolveTopology([]ComponentDefinition{
		{ID: "hdfs-prod", Kind: HDFSComponent, SecretRef: "secret://runtime/hdfs", Endpoints: []Endpoint{{URL: "https://hdfs.example.test/jmx", Role: "Data-Node"}}},
		{ID: "zk-prod", Kind: ZooKeeperComponent, SecretRef: "secret://runtime/zk", Endpoints: []Endpoint{{URL: "https://zk.example.test/jmx", Role: "LEADER"}}},
		{ID: "hbase-prod", Kind: HBaseComponent, SecretRef: "secret://runtime/hbase", Endpoints: []Endpoint{{URL: "https://hbase.example.test/jmx", Role: "Region-Server"}}, Dependencies: DependencyRef{HDFSClusterID: "hdfs-prod", ZooKeeperClusterID: "zk-prod"}},
	})
	if err != nil {
		t.Fatalf("ResolveTopology() error = %v", err)
	}
	nodes := topology.Nodes()
	if !hasTopologyRole(nodes, "hbase-prod", "regionserver") || !hasTopologyRole(nodes, "hdfs-prod", "datanode") || !hasTopologyRole(nodes, "zk-prod", "leader") {
		t.Fatalf("Nodes() = %#v, want canonical role aliases", nodes)
	}
	nodes[0].ID = "mutated"
	nodes[0].Roles[0] = "mutated"
	relations := topology.Relations()
	relations[0].ComponentID = "mutated"
	if topology.HasRelation("mutated", "hdfs-prod", HDFSComponent) || hasTopologyRole(topology.Nodes(), "mutated", "mutated") || !topology.HasRelation("hbase-prod", "hdfs-prod", HDFSComponent) || !hasTopologyRole(topology.Nodes(), "hbase-prod", "regionserver") {
		t.Fatal("Topology accessor leaked mutable state")
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

func hasTopologyRole(nodes []TopologyNode, id, role string) bool {
	for _, node := range nodes {
		if node.ID != id {
			continue
		}
		for _, candidate := range node.Roles {
			if candidate == role {
				return true
			}
		}
	}
	return false
}
