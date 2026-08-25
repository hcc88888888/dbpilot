package database

import (
	"context"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maximumOperationTimeout = time.Minute

type registry struct {
	mu           sync.RWMutex
	factories    map[EngineFamily]Factory
	capabilities map[EngineFamily]CapabilityMatrix
}

// NewRegistry returns an empty registry for explicitly registered adapter
// families.
func NewRegistry() Registry {
	return &registry{
		factories:    make(map[EngineFamily]Factory),
		capabilities: make(map[EngineFamily]CapabilityMatrix),
	}
}

func (r *registry) Register(family EngineFamily, factory Factory) error {
	if strings.TrimSpace(string(family)) == "" {
		return fmt.Errorf("database family is required")
	}
	if factoryIsNil(factory) {
		return fmt.Errorf("database factory for %q is required", family)
	}

	capabilities := cloneCapabilities(factory.Capabilities())

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[family]; exists {
		return fmt.Errorf("database family %q is already registered", family)
	}
	r.factories[family] = factory
	r.capabilities[family] = capabilities
	return nil
}

func (r *registry) Open(ctx context.Context, config InstanceConfig) (Adapter, error) {
	if err := validateInstanceConfig(config); err != nil {
		return nil, err
	}

	r.mu.RLock()
	factory, exists := r.factories[config.Family]
	r.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("unsupported database family %q", config.Family)
	}

	adapter, err := factory.Open(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open %q database adapter: %w", config.Family, err)
	}
	if adapter == nil {
		return nil, fmt.Errorf("open %q database adapter: factory returned nil adapter", config.Family)
	}
	return adapter, nil
}

func (r *registry) Capabilities(family EngineFamily) (CapabilityMatrix, bool) {
	r.mu.RLock()
	capabilities, exists := r.capabilities[family]
	r.mu.RUnlock()
	if !exists {
		return CapabilityMatrix{}, false
	}
	return cloneCapabilities(capabilities), true
}

func validateInstanceConfig(config InstanceConfig) error {
	if err := validateInstanceID(config.ID); err != nil {
		return err
	}
	if strings.TrimSpace(string(config.Family)) == "" {
		return fmt.Errorf("database family is required")
	}
	if err := validateAddress(config.Address); err != nil {
		return err
	}
	if err := validateSecretRef(config.SecretRef); err != nil {
		return err
	}
	if err := validateTimeout("connect", config.ConnectTimeout); err != nil {
		return err
	}
	if err := validateTimeout("query", config.QueryTimeout); err != nil {
		return err
	}
	return nil
}

func validateInstanceID(id string) error {
	if id == "" || strings.TrimSpace(id) != id {
		return fmt.Errorf("database instance ID is required")
	}
	if len(id) > 128 {
		return fmt.Errorf("database instance ID exceeds 128 bytes")
	}
	for index, character := range id {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return fmt.Errorf("database instance ID contains invalid character at position %d", index)
	}
	return nil
}

func validateAddress(address string) error {
	if strings.TrimSpace(address) != address || address == "" {
		return fmt.Errorf("database address is required")
	}
	parsed, err := url.ParseRequestURI(address)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("database address must be an absolute URL with host and port")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("database address must not contain credentials, query, or fragment")
	}
	port := parsed.Port()
	if port == "" {
		return fmt.Errorf("database address must include a port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("database address port must be between 1 and 65535")
	}
	return nil
}

func validateSecretRef(secretRef string) error {
	if strings.TrimSpace(secretRef) != secretRef || secretRef == "" {
		return fmt.Errorf("database secret reference is required")
	}
	parsed, err := url.ParseRequestURI(secretRef)
	if err != nil || parsed.Scheme != "secret" || parsed.Host == "" || parsed.Path == "" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("database secret reference must use secret://provider/name format")
	}
	return nil
}

func validateTimeout(operation string, timeout time.Duration) error {
	if timeout <= 0 || timeout > maximumOperationTimeout {
		return fmt.Errorf("database %s timeout must be greater than zero and at most %s", operation, maximumOperationTimeout)
	}
	return nil
}

func cloneCapabilities(capabilities CapabilityMatrix) CapabilityMatrix {
	copy := capabilities
	copy.MetricIDs = append([]string(nil), capabilities.MetricIDs...)
	return copy
}

func factoryIsNil(factory Factory) bool {
	if factory == nil {
		return true
	}
	value := reflect.ValueOf(factory)
	return value.Kind() == reflect.Ptr && value.IsNil()
}
