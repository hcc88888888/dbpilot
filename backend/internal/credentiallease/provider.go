package credentiallease

import (
	"context"
	"regexp"
)

type MemoryProvider struct{ values map[string]Credential }

func NewMemoryProvider(values map[string]Credential) (*MemoryProvider, error) {
	provider := &MemoryProvider{values: make(map[string]Credential, len(values))}
	for reference, credential := range values {
		if !strictSecretReference(reference) || !validCredential(credential) {
			return nil, ErrLeaseRejected
		}
		provider.values[reference] = credential.Clone()
	}
	return provider, nil
}

func (provider *MemoryProvider) Resolve(ctx context.Context, reference string) (Credential, error) {
	if provider == nil || ctx == nil || ctx.Err() != nil || !strictSecretReference(reference) {
		return Credential{}, ErrLeaseRejected
	}
	credential, ok := provider.values[reference]
	if !ok {
		return Credential{}, ErrLeaseRejected
	}
	return credential.Clone(), nil
}

type EnvironmentBinding struct {
	Username string
	Variable string
	Revision uint64
}

type EnvironmentProvider struct {
	bindings map[string]EnvironmentBinding
	lookup   func(string) (string, bool)
}

var environmentVariable = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)

func NewEnvironmentProvider(bindings map[string]EnvironmentBinding, lookup func(string) (string, bool)) (*EnvironmentProvider, error) {
	if lookup == nil || len(bindings) == 0 {
		return nil, ErrLeaseRejected
	}
	cloned := make(map[string]EnvironmentBinding, len(bindings))
	for reference, binding := range bindings {
		if !strictSecretReference(reference) || !environmentVariable.MatchString(binding.Variable) || binding.Revision == 0 || len(binding.Username) > MaximumUsernameBytes {
			return nil, ErrLeaseRejected
		}
		cloned[reference] = binding
	}
	return &EnvironmentProvider{bindings: cloned, lookup: lookup}, nil
}

func (provider *EnvironmentProvider) Resolve(ctx context.Context, reference string) (Credential, error) {
	if provider == nil || ctx == nil || ctx.Err() != nil {
		return Credential{}, ErrLeaseRejected
	}
	binding, ok := provider.bindings[reference]
	if !ok {
		return Credential{}, ErrLeaseRejected
	}
	value, ok := provider.lookup(binding.Variable)
	if !ok || value == "" || len(value) > MaximumSecretBytes {
		return Credential{}, ErrLeaseRejected
	}
	credential := Credential{Username: binding.Username, SecretBytes: []byte(value), Revision: binding.Revision}
	if !validCredential(credential) {
		credential.Release()
		return Credential{}, ErrLeaseRejected
	}
	return credential, nil
}

var _ SecretProvider = (*MemoryProvider)(nil)
var _ SecretProvider = (*EnvironmentProvider)(nil)
