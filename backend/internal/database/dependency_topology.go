package database

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrUnauthorizedDependency means a dependency ID did not resolve to a
// definition of the required kind. It is intentionally returned before any
// metric collection, so references cannot become an access-control bypass.
var ErrUnauthorizedDependency = errors.New("unauthorized component dependency")

// TopologyNode is the credential-free part of a component definition needed
// by dependency health. Secret and TLS references, endpoints, and adapters
// are deliberately not copied into topology output.
type TopologyNode struct {
	ID    string
	Kind  ComponentKind
	Roles []string
}

// DependencyRelation is one authorized, directed HBase dependency edge.
type DependencyRelation struct {
	ComponentID    string
	DependencyID   string
	DependencyKind ComponentKind
}

// Topology contains a stable snapshot of the definitions needed to correlate
// HBase health with its explicitly authorized HDFS and ZooKeeper dependencies.
type Topology struct {
	Nodes     []TopologyNode
	Relations []DependencyRelation
}

// ResolveTopology resolves only HBase dependency IDs to definitions supplied
// by the trusted component registry/configuration layer. The returned value is
// metadata-only and never grants or copies dependency credentials.
func ResolveTopology(definitions []ComponentDefinition) (Topology, error) {
	nodes := make(map[string]TopologyNode, len(definitions))
	dependencies := make(map[string]DependencyRef, len(definitions))

	for _, definition := range definitions {
		if strings.TrimSpace(definition.ID) == "" {
			return Topology{}, errors.New("component ID is required")
		}
		if !validComponentKind(definition.Kind) {
			return Topology{}, fmt.Errorf("component %q has unsupported kind %q", definition.ID, definition.Kind)
		}
		if _, exists := nodes[definition.ID]; exists {
			return Topology{}, fmt.Errorf("component %q is declared more than once", definition.ID)
		}
		if definition.Kind != HBaseComponent && (definition.Dependencies.HDFSClusterID != "" || definition.Dependencies.ZooKeeperClusterID != "") {
			return Topology{}, fmt.Errorf("%w: only HBase may declare dependencies", ErrUnauthorizedDependency)
		}
		nodes[definition.ID] = TopologyNode{ID: definition.ID, Kind: definition.Kind, Roles: topologyRoles(definition.Endpoints)}
		dependencies[definition.ID] = definition.Dependencies
	}

	topology := Topology{Nodes: make([]TopologyNode, 0, len(nodes))}
	for _, node := range nodes {
		topology.Nodes = append(topology.Nodes, node)
	}
	sort.Slice(topology.Nodes, func(i, j int) bool { return topology.Nodes[i].ID < topology.Nodes[j].ID })

	for _, node := range topology.Nodes {
		if node.Kind != HBaseComponent {
			continue
		}
		dependency := dependencies[node.ID]
		for _, reference := range []struct {
			id   string
			kind ComponentKind
		}{
			{id: dependency.HDFSClusterID, kind: HDFSComponent},
			{id: dependency.ZooKeeperClusterID, kind: ZooKeeperComponent},
		} {
			if reference.id == "" {
				continue
			}
			resolved, exists := nodes[reference.id]
			if !exists || resolved.Kind != reference.kind {
				return Topology{}, fmt.Errorf("%w: HBase component %q references %s %q", ErrUnauthorizedDependency, node.ID, reference.kind, reference.id)
			}
			topology.Relations = append(topology.Relations, DependencyRelation{ComponentID: node.ID, DependencyID: reference.id, DependencyKind: reference.kind})
		}
	}
	sort.Slice(topology.Relations, func(i, j int) bool {
		left, right := topology.Relations[i], topology.Relations[j]
		if left.ComponentID != right.ComponentID {
			return left.ComponentID < right.ComponentID
		}
		return left.DependencyKind < right.DependencyKind
	})
	return topology, nil
}

// HasRelation reports whether a particular typed dependency edge is present.
func (topology Topology) HasRelation(componentID, dependencyID string, kind ComponentKind) bool {
	for _, relation := range topology.Relations {
		if relation.ComponentID == componentID && relation.DependencyID == dependencyID && relation.DependencyKind == kind {
			return true
		}
	}
	return false
}

func (topology Topology) node(id string) (TopologyNode, bool) {
	for _, node := range topology.Nodes {
		if node.ID == id {
			node.Roles = append([]string(nil), node.Roles...)
			return node, true
		}
	}
	return TopologyNode{}, false
}

func (topology Topology) dependencyID(componentID string, kind ComponentKind) (string, bool) {
	for _, relation := range topology.Relations {
		if relation.ComponentID == componentID && relation.DependencyKind == kind {
			return relation.DependencyID, true
		}
	}
	return "", false
}

func topologyRoles(endpoints []Endpoint) []string {
	roles := make(map[string]struct{}, len(endpoints))
	for _, endpoint := range endpoints {
		role := strings.ToLower(strings.TrimSpace(endpoint.Role))
		if role != "" {
			roles[role] = struct{}{}
		}
	}
	result := make([]string, 0, len(roles))
	for role := range roles {
		result = append(result, role)
	}
	sort.Strings(result)
	return result
}
