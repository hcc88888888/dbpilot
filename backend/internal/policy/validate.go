package policy

import (
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
)

const minimumCollectionInterval = 5 * time.Second

func Validate(p Policy, env ValidationEnvironment) error {
	if strings.TrimSpace(p.AgentID) == "" {
		return ErrInvalidAgentID
	}
	if p.Version == 0 {
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
			if err := validatePath(source.Path, env); err != nil {
				return err
			}
		case SourcePrometheus, SourceHTTPJSONMetrics:
			if err := validateEndpoint(source.Endpoint); err != nil {
				return err
			}
		case SourcePluginMetrics:
			if _, ok := env.PluginIDs[source.PluginID]; !ok || strings.TrimSpace(source.PluginID) == "" {
				return ErrPluginNotRegistered
			}
		}
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
	if raw == "" || !path.IsAbs(raw) {
		return ErrPathTraversal
	}
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			return ErrPathTraversal
		}
	}
	resolved := path.Clean(raw)
	if env.ResolvePath != nil {
		var err error
		resolved, err = env.ResolvePath(raw)
		if err != nil {
			return fmt.Errorf("resolve telemetry path: %w", err)
		}
		resolved = path.Clean(resolved)
	}
	for _, root := range env.ForbiddenRoots {
		if isWithin(resolved, root) {
			return ErrForbiddenPath
		}
	}
	if len(env.AllowedRoots) == 0 {
		return ErrPathOutsideAllowRoots
	}
	for _, root := range env.AllowedRoots {
		if isWithin(resolved, root) {
			return nil
		}
	}
	return ErrPathOutsideAllowRoots
}

func isWithin(candidate, root string) bool {
	root = path.Clean(root)
	return candidate == root || strings.HasPrefix(candidate, root+"/")
}

func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ErrInvalidEndpoint
	}
	return nil
}
