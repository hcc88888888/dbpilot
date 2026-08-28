package agent

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	CollectionKindDependencies = "dependencies"
	CollectionKindHost         = "host"
)

type CollectionRequest struct {
	Kinds       []string
	InstanceIDs []string
}

type Collector interface {
	Collect(context.Context, CollectionRequest) error
}

type CollectionCoordinator struct {
	Host         Collector
	Dependencies Collector
}

func (c *CollectionCoordinator) Collect(ctx context.Context, request CollectionRequest) error {
	if c == nil || ctx == nil {
		return errors.New("collection coordinator context is required")
	}
	normalized, err := normalizeCollectionRequest(request)
	if err != nil {
		return err
	}
	for _, kind := range normalized.Kinds {
		if err := ctx.Err(); err != nil {
			return err
		}
		collector := c.collector(kind)
		if isNilDependencyBoundary(collector) {
			return fmt.Errorf("collection kind %q is unavailable", kind)
		}
		if err := collector.Collect(ctx, normalized); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("collect %s: %w", kind, err)
		}
	}
	return nil
}

func (c *CollectionCoordinator) collector(kind string) Collector {
	switch kind {
	case CollectionKindDependencies:
		return c.Dependencies
	case CollectionKindHost:
		return c.Host
	default:
		return nil
	}
}

func (c *CollectionCoordinator) Available() bool {
	return c != nil && (!isNilDependencyBoundary(c.Host) || !isNilDependencyBoundary(c.Dependencies))
}

func normalizeCollectionRequest(request CollectionRequest) (CollectionRequest, error) {
	kinds := make(map[string]struct{}, len(request.Kinds))
	for _, raw := range request.Kinds {
		kind := strings.ToLower(strings.TrimSpace(raw))
		switch kind {
		case CollectionKindDependencies, CollectionKindHost:
			kinds[kind] = struct{}{}
		default:
			return CollectionRequest{}, fmt.Errorf("unsupported collection kind %q", raw)
		}
	}
	if len(kinds) == 0 {
		return CollectionRequest{}, errors.New("at least one collection kind is required")
	}
	normalized := CollectionRequest{Kinds: make([]string, 0, len(kinds)), InstanceIDs: append([]string(nil), request.InstanceIDs...)}
	for kind := range kinds {
		normalized.Kinds = append(normalized.Kinds, kind)
	}
	sort.Strings(normalized.Kinds)
	return normalized, nil
}

type dependencyCollectionAdapter struct{ collector *DependencyCollector }

func NewDependencyCollectionAdapter(collector *DependencyCollector) Collector {
	if collector == nil {
		return nil
	}
	return dependencyCollectionAdapter{collector: collector}
}

func (adapter dependencyCollectionAdapter) Collect(ctx context.Context, request CollectionRequest) error {
	if adapter.collector == nil || len(request.Kinds) == 0 {
		return errors.New("dependency collector is unavailable")
	}
	if !containsCollectionKind(request.Kinds, CollectionKindDependencies) {
		return errors.New("collection request does not include dependencies")
	}
	return adapter.collector.CollectOnce(ctx)
}
