package inspection

import (
	"context"
	"errors"
	"sort"
	"strings"

	"dbpilot.local/platform/internal/platformscope"
)

var (
	ErrUnknownTarget = errors.New("inspection target is not configured in scope")
	ErrNoTargets     = errors.New("inspection target selection is empty")
)

type HostTarget struct {
	Scope                   platformscope.Scope `json:"scope"`
	AgentID                 string              `json:"agent_id"`
	DisplayName             string              `json:"display_name"`
	Host                    string              `json:"host"`
	Labels                  map[string]string   `json:"labels"`
	Connectivity            string              `json:"connectivity"`
	Capabilities            []string            `json:"capabilities"`
	AdvertisedSources       []SourceType        `json:"advertised_sources,omitempty"`
	TrustedProcessAllowlist bool                `json:"trusted_process_allowlist"`
}

type TargetResolver interface {
	Resolve(context.Context, platformscope.Scope, TargetSelector) ([]HostTarget, error)
	List(context.Context, platformscope.Scope) ([]HostTarget, error)
}

type ConfiguredTargetResolver struct {
	targets []HostTarget
}

func NewConfiguredTargetResolver(targets []HostTarget) (*ConfiguredTargetResolver, error) {
	cloned := cloneHostTargets(targets)
	seen := make(map[string]struct{}, len(cloned))
	for _, target := range cloned {
		if validateHostTarget(target) != nil {
			return nil, ErrInvalid
		}
		key := target.Scope.Key() + "\x00" + target.AgentID
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrInvalid
		}
		seen[key] = struct{}{}
	}
	sortHostTargets(cloned)
	return &ConfiguredTargetResolver{targets: cloned}, nil
}

func (resolver *ConfiguredTargetResolver) Resolve(ctx context.Context, scope platformscope.Scope, selector TargetSelector) ([]HostTarget, error) {
	if ctx == nil || resolver == nil || scope.Validate() != nil || (len(selector.AgentIDs) == 0 && len(selector.Labels) == 0) || !validSelectorLabels(selector.Labels) {
		return nil, ErrInvalid
	}
	available := make(map[string]HostTarget)
	for _, target := range resolver.targets {
		if target.Scope == scope {
			available[target.AgentID] = target
		}
	}
	selected := make(map[string]HostTarget)
	for _, agentID := range selector.AgentIDs {
		if !validID(agentID) {
			return nil, ErrUnknownTarget
		}
		target, exists := available[agentID]
		if !exists {
			return nil, ErrUnknownTarget
		}
		selected[agentID] = target
	}
	if len(selector.Labels) > 0 {
		for agentID, target := range available {
			if targetLabelsMatch(target.Labels, selector.Labels) {
				selected[agentID] = target
			}
		}
	}
	if len(selected) == 0 {
		return nil, ErrNoTargets
	}
	result := make([]HostTarget, 0, len(selected))
	for _, target := range selected {
		result = append(result, target)
	}
	sortHostTargets(result)
	return cloneHostTargets(result), nil
}

func (resolver *ConfiguredTargetResolver) List(ctx context.Context, scope platformscope.Scope) ([]HostTarget, error) {
	if ctx == nil || resolver == nil || scope.Validate() != nil {
		return nil, ErrInvalid
	}
	result := make([]HostTarget, 0)
	for _, target := range resolver.targets {
		if target.Scope == scope {
			result = append(result, target)
		}
	}
	return cloneHostTargets(result), nil
}

func validateHostTarget(target HostTarget) error {
	if target.Scope.Validate() != nil || !validID(target.AgentID) || strings.TrimSpace(target.DisplayName) == "" || len(target.DisplayName) > 120 || strings.TrimSpace(target.Host) == "" || len(target.Host) > 255 || !validSelectorLabels(target.Labels) || len(target.Capabilities) > 128 {
		return ErrInvalid
	}
	for _, capability := range target.Capabilities {
		if !validID(capability) {
			return ErrInvalid
		}
	}
	for _, source := range target.AdvertisedSources {
		if !validSource(source) {
			return ErrInvalid
		}
	}
	return nil
}

func validSelectorLabels(labels map[string]string) bool {
	if len(labels) > 32 {
		return false
	}
	for key, value := range labels {
		if !validID(key) || strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) || len(value) > 128 {
			return false
		}
	}
	return true
}

func targetLabelsMatch(actual, selected map[string]string) bool {
	for key, value := range selected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func cloneHostTargets(targets []HostTarget) []HostTarget {
	result := make([]HostTarget, len(targets))
	for index, target := range targets {
		result[index] = target
		result[index].Labels = make(map[string]string, len(target.Labels))
		for key, value := range target.Labels {
			result[index].Labels[key] = value
		}
		result[index].Capabilities = append([]string(nil), target.Capabilities...)
		result[index].AdvertisedSources = append([]SourceType(nil), target.AdvertisedSources...)
	}
	return result
}

func sortHostTargets(targets []HostTarget) {
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Scope.Key() != targets[j].Scope.Key() {
			return targets[i].Scope.Key() < targets[j].Scope.Key()
		}
		return targets[i].AgentID < targets[j].AgentID
	})
}
