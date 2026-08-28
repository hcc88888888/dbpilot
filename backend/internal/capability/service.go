package capability

import "sort"

type ReasonCode string

const (
	DeploymentDisabled  ReasonCode = "deployment_disabled"
	DatabaseUnsupported ReasonCode = "database_unsupported"
	AgentUnsupported    ReasonCode = "agent_unsupported"
	PermissionDenied    ReasonCode = "permission_denied"
)

type Definition struct {
	Name                         string
	DeploymentFlags              []string
	DatabaseTypes                []string
	RequiredDatabaseCapabilities []string
	AgentCapabilities            []string
	RequiredPermission           string
}

type Input struct {
	DeploymentFlags      map[string]bool
	DatabaseType         string
	DatabaseCapabilities map[string]bool
	AgentCapabilities    map[string]bool
	Permissions          map[string]bool
}

type Capability struct {
	Name               string     `json:"name"`
	Enabled            bool       `json:"enabled"`
	ReasonCode         ReasonCode `json:"reason_code,omitempty"`
	DatabaseTypes      []string   `json:"database_types"`
	AgentCapabilities  []string   `json:"agent_capabilities"`
	RequiredPermission string     `json:"required_permission"`
}

type Service struct{ catalog []Definition }

func FoundationCatalog() []Definition {
	return []Definition{
		{Name: "platform.jobs", DeploymentFlags: []string{"jobs"}, RequiredPermission: "platform.jobs.read"},
		{Name: "platform.audit", DeploymentFlags: []string{"audit"}, RequiredPermission: "platform.audit.read"},
		{Name: "platform.artifacts", DeploymentFlags: []string{"artifacts"}, RequiredPermission: "platform.artifacts.read"},
		{Name: "agent.control", DeploymentFlags: []string{"agent_control"}, AgentCapabilities: []string{"collect_now"}, RequiredPermission: "platform.jobs.cancel"},
	}
}

func FoundationDeploymentFlags() map[string]bool {
	return map[string]bool{"jobs": true, "audit": true, "artifacts": true, "agent_control": true}
}

func NewService(catalog []Definition) Service {
	return Service{catalog: cloneCatalog(catalog)}
}

func (service Service) Resolve(input Input) []Capability {
	return Resolve(service.catalog, input)
}

func Resolve(catalog []Definition, input Input) []Capability {
	result := make([]Capability, 0, len(catalog))
	for _, definition := range catalog {
		value := Capability{
			Name:               definition.Name,
			DatabaseTypes:      sortedUnique(definition.DatabaseTypes),
			AgentCapabilities:  sortedUnique(definition.AgentCapabilities),
			RequiredPermission: definition.RequiredPermission,
		}
		switch {
		case !allEnabled(definition.DeploymentFlags, input.DeploymentFlags):
			value.ReasonCode = DeploymentDisabled
		case !databaseSupported(definition, input):
			value.ReasonCode = DatabaseUnsupported
		case !allEnabled(definition.AgentCapabilities, input.AgentCapabilities):
			value.ReasonCode = AgentUnsupported
		case definition.RequiredPermission != "" && !input.Permissions[definition.RequiredPermission]:
			value.ReasonCode = PermissionDenied
		default:
			value.Enabled = true
		}
		result = append(result, value)
	}
	sort.SliceStable(result, func(left, right int) bool { return result[left].Name < result[right].Name })
	return result
}

func databaseSupported(definition Definition, input Input) bool {
	if len(definition.DatabaseTypes) > 0 && !contains(definition.DatabaseTypes, input.DatabaseType) {
		return false
	}
	return allEnabled(definition.RequiredDatabaseCapabilities, input.DatabaseCapabilities)
}

func allEnabled(required []string, available map[string]bool) bool {
	for _, name := range required {
		if name != "" && !available[name] {
			return false
		}
	}
	return true
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func cloneCatalog(catalog []Definition) []Definition {
	result := make([]Definition, len(catalog))
	for index, definition := range catalog {
		result[index] = definition
		result[index].DeploymentFlags = append([]string(nil), definition.DeploymentFlags...)
		result[index].DatabaseTypes = append([]string(nil), definition.DatabaseTypes...)
		result[index].RequiredDatabaseCapabilities = append([]string(nil), definition.RequiredDatabaseCapabilities...)
		result[index].AgentCapabilities = append([]string(nil), definition.AgentCapabilities...)
	}
	return result
}
