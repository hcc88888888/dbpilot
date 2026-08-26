package database

import (
	"fmt"
	"net/url"
	"strings"
	"sync"
)

type componentRegistry struct {
	mu         sync.RWMutex
	definitions map[string]ComponentDefinition
	adapters    map[string]ComponentAdapter
}

// NewComponentRegistry returns an empty registry of non-SQL components.
func NewComponentRegistry() ComponentRegistry {
	return &componentRegistry{definitions: make(map[string]ComponentDefinition), adapters: make(map[string]ComponentAdapter)}
}

func (r *componentRegistry) Register(definition ComponentDefinition, adapter ComponentAdapter) error {
	if err := validateComponentDefinition(definition); err != nil { return err }
	if isNilInterface(adapter) { return fmt.Errorf("component adapter for %q is required", definition.ID) }
	if adapter.Component() != definition.Kind { return fmt.Errorf("component adapter for %q has kind %q, want %q", definition.ID, adapter.Component(), definition.Kind) }
	r.mu.Lock(); defer r.mu.Unlock()
	if _, exists := r.definitions[definition.ID]; exists { return fmt.Errorf("component %q is already registered", definition.ID) }
	for dependencyID, expected := range map[string]ComponentKind{"HDFS": HDFSComponent, "ZooKeeper": ZooKeeperComponent} {
		id := definition.Dependencies.HDFSClusterID
		if dependencyID == "ZooKeeper" { id = definition.Dependencies.ZooKeeperClusterID }
		if id == "" { continue }
		dep, exists := r.definitions[id]
		if !exists || dep.Kind != expected { return fmt.Errorf("component %q references unauthorized %s dependency %q", definition.ID, dependencyID, id) }
	}
	definition.Endpoints = append([]Endpoint(nil), definition.Endpoints...)
	r.definitions[definition.ID], r.adapters[definition.ID] = definition, adapter
	return nil
}

func (r *componentRegistry) Definition(id string) (ComponentDefinition, bool) {
	r.mu.RLock(); definition, ok := r.definitions[id]; r.mu.RUnlock()
	if ok { definition.Endpoints = append([]Endpoint(nil), definition.Endpoints...) }
	return definition, ok
}

func (r *componentRegistry) Adapter(id string) (ComponentAdapter, bool) {
	r.mu.RLock(); adapter, ok := r.adapters[id]; r.mu.RUnlock(); return adapter, ok
}

func validateComponentDefinition(def ComponentDefinition) error {
	if err := validateInstanceID(def.ID); err != nil { return fmt.Errorf("component ID: %w", err) }
	if !validComponentKind(def.Kind) { return fmt.Errorf("unsupported component kind %q", def.Kind) }
	if len(def.Endpoints) == 0 { return fmt.Errorf("component %q requires at least one endpoint", def.ID) }
	for _, endpoint := range def.Endpoints {
		if strings.TrimSpace(endpoint.URL) != endpoint.URL || endpoint.URL == "" { return fmt.Errorf("component %q endpoint is required", def.ID) }
		parsed, err := url.ParseRequestURI(endpoint.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" { return fmt.Errorf("component %q endpoint must be an absolute URL without credentials, query, or fragment", def.ID) }
	}
	if err := validateSecretRef(def.SecretRef); err != nil { return err }
	if def.TLSRef != "" { if err := validateSecretRef(def.TLSRef); err != nil { return fmt.Errorf("component TLS secret reference: %w", err) } }
	if def.Kind != HBaseComponent && (def.Dependencies.HDFSClusterID != "" || def.Dependencies.ZooKeeperClusterID != "") { return fmt.Errorf("only hbase components may declare dependencies") }
	return nil
}

func validComponentKind(kind ComponentKind) bool { return kind == HBaseComponent || kind == HDFSComponent || kind == ZooKeeperComponent }
