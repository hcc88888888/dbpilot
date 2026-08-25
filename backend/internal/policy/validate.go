package policy

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const minimumCollectionInterval = 5 * time.Second

var metricTemplateIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

func Validate(p Policy, env ValidationEnvironment) error {
	return validate(p, env, true)
}

// ValidateStructural validates fields that are self-contained in a signed
// policy. Runtime validation must additionally use Validate with an agent
// environment for filesystem, plugin-registry, and version checks.
func ValidateStructural(p Policy) error {
	return validate(p, ValidationEnvironment{}, false)
}

func validate(p Policy, env ValidationEnvironment, runtime bool) error {
	if strings.TrimSpace(p.AgentID) == "" {
		return ErrInvalidAgentID
	}
	if p.Version == 0 || (env.PreviousVersion != 0 && p.Version <= env.PreviousVersion) {
		return ErrPolicyVersionRollback
	}
	if p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.IssuedAt) {
		return ErrExpiredPolicy
	}
	if len(p.Sources) == 0 {
		return ErrNoSources
	}
	if p.Limits.MaxSpoolBytes <= 0 || p.Limits.MaxBatchBytes <= 0 || p.Limits.MaxEventsPerSec <= 0 {
		return ErrInvalidLimits
	}

	ids := make(map[string]struct{}, len(p.Sources))
	for _, source := range p.Sources {
		if strings.TrimSpace(source.ID) == "" {
			return ErrDuplicateSourceID
		}
		if _, exists := ids[source.ID]; exists {
			return ErrDuplicateSourceID
		}
		ids[source.ID] = struct{}{}
		if !allowedSourceKind(source.Kind) {
			return ErrSourceKindNotAllowed
		}
		if source.Interval < minimumCollectionInterval {
			return ErrIntervalTooShort
		}
		if len(source.Labels) > 32 {
			return ErrTooManyLabels
		}

		switch source.Kind {
		case SourceFileLog:
			if err := validatePathSyntax(source.Path); err != nil {
				return err
			}
			if runtime {
				if err := validatePath(source.Path, env); err != nil {
					return err
				}
			}
		case SourcePrometheus, SourceHTTPJSONMetrics:
			if err := validateEndpoint(source.Endpoint); err != nil {
				return err
			}
		case SourcePluginMetrics:
			if strings.TrimSpace(source.PluginID) == "" || !validPluginParameters(source.Params) {
				return ErrUnsafePluginParameter
			}
			if runtime {
				if err := validatePluginSource(source, env); err != nil {
					return err
				}
			}
		case SourceSQLMetrics:
			if !metricTemplateIDPattern.MatchString(source.MetricID) {
				return ErrInvalidMetricTemplateID
			}
		}
	}
	return nil
}

// ValidateSQLMetricSpec ensures policy can select only a well-formed template
// name. Runtime secret references and statements are intentionally ignored:
// neither has a JSON representation in signed policy.
func ValidateSQLMetricSpec(spec SQLMetricSpec) error {
	if !metricTemplateIDPattern.MatchString(spec.MetricID) {
		return ErrInvalidMetricTemplateID
	}
	return nil
}

func allowedSourceKind(kind SourceKind) bool {
	switch kind {
	case SourceFileLog, SourceJournald, SourceHostMetrics, SourcePrometheus, SourceHTTPJSONMetrics, SourceSQLMetrics, SourcePluginMetrics:
		return true
	default:
		return false
	}
}

func validatePath(raw string, env ValidationEnvironment) error {
	if err := validatePathSyntax(raw); err != nil {
		return err
	}
	if env.ResolvePath == nil {
		return ErrPathResolution
	}
	resolved, err := env.ResolvePath(raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrPathResolution, err)
	}
	if strings.HasPrefix(resolved, "/") {
		resolved = path.Clean(resolved)
	} else {
		resolved = filepath.Clean(resolved)
	}
	for _, root := range env.ForbiddenRoots {
		if isWithinFilesystem(resolved, root) {
			return ErrForbiddenPath
		}
	}
	if len(env.AllowedRoots) == 0 {
		return ErrPathOutsideAllowRoots
	}
	for _, root := range env.AllowedRoots {
		if isWithinFilesystem(resolved, root) {
			return nil
		}
	}
	return ErrPathOutsideAllowRoots
}

func validatePathSyntax(raw string) error {
	if raw == "" || (!filepath.IsAbs(raw) && !path.IsAbs(raw)) {
		return ErrPathTraversal
	}
	for _, part := range strings.Split(filepath.ToSlash(raw), "/") {
		if part == ".." {
			return ErrPathTraversal
		}
	}
	return nil
}

func isWithinFilesystem(candidate, root string) bool {
	if root == "" {
		return false
	}
	// Policies can be prepared off-host, so retain POSIX-root semantics for
	// existing signed policies while using native volume-aware logic for native
	// Agent paths such as C:\\dbpilot\\logs.
	if strings.HasPrefix(candidate, "/") || strings.HasPrefix(root, "/") {
		candidate, root = path.Clean(candidate), path.Clean(root)
		return root == "/" || candidate == root || strings.HasPrefix(candidate, root+"/")
	}
	candidate, root = filepath.Clean(candidate), filepath.Clean(root)
	if !filepath.IsAbs(candidate) || !filepath.IsAbs(root) {
		return false
	}
	if !strings.EqualFold(filepath.VolumeName(candidate), filepath.VolumeName(root)) {
		return false
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validPluginParameters(params map[string]string) bool {
	for key, value := range params {
		if !validParameterKey(key) || containsShellSyntax(value) {
			return false
		}
	}
	return true
}

func validParameterKey(key string) bool {
	if key == "" || len(key) > 64 {
		return false
	}
	switch strings.ToLower(key) {
	case "command", "command_line", "executable", "exec", "shell", "script", "args":
		return false
	}
	for index, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '-' || r == '.' || (index > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func containsShellSyntax(value string) bool {
	return strings.ContainsAny(value, "\x00\r\n;|&$`<>") || strings.Contains(strings.ToLower(value), "curl ") || strings.Contains(strings.ToLower(value), "wget ") || strings.Contains(strings.ToLower(value), "http://") || strings.Contains(strings.ToLower(value), "https://")
}

func validatePluginSource(source Source, env ValidationEnvironment) error {
	definition, ok := env.PluginDefinitions[source.PluginID]
	if !ok {
		return ErrPluginNotRegistered
	}
	for key, value := range source.Params {
		schema, ok := definition.Parameters[key]
		if !ok || schema.MaxLength <= 0 || len(value) > schema.MaxLength || containsShellSyntax(value) {
			return ErrUnsafePluginParameter
		}
		pattern, err := regexp.Compile(schema.ValuePattern)
		if err != nil || !pattern.MatchString(value) {
			return ErrUnsafePluginParameter
		}
	}
	return nil
}

func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ErrInvalidEndpoint
	}
	return nil
}
