package artifact

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

type Store interface {
	Get(context.Context, platformscope.Scope, string) (Artifact, error)
}

type DownloadSigner interface {
	Sign(context.Context, Artifact, time.Duration) (string, error)
}

type Service struct {
	store  Store
	signer DownloadSigner
	now    func() time.Time
}

func NewService(store Store, signer DownloadSigner) *Service {
	return &Service{store: store, signer: signer, now: time.Now}
}

func (service *Service) Get(ctx context.Context, scope platformscope.Scope, id string) (Artifact, error) {
	if service == nil || service.store == nil || ctx == nil || scope.Validate() != nil || strings.TrimSpace(id) == "" || id != strings.TrimSpace(id) {
		return Artifact{}, ErrInvalid
	}
	value, err := service.store.Get(ctx, scope, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Artifact{}, ErrNotFound
		}
		return Artifact{}, err
	}
	if value.ID != id || value.Scope != scope {
		return Artifact{}, ErrNotFound
	}
	normalizeArtifactTimes(&value)
	return value, nil
}

func (service *Service) CreateDownload(ctx context.Context, scope platformscope.Scope, id string, ttl time.Duration) (Download, error) {
	if service == nil || service.signer == nil || ttl <= 0 {
		return Download{}, beforeDownloadSideEffect(ErrInvalid)
	}
	value, err := service.Get(ctx, scope, id)
	if err != nil {
		return Download{}, beforeDownloadSideEffect(err)
	}
	now := service.currentTime()
	if value.ExpiresAt != nil && !value.ExpiresAt.After(now) {
		return Download{}, beforeDownloadSideEffect(ErrExpired)
	}
	if ttl > MaximumDownloadTTL {
		ttl = MaximumDownloadTTL
	}
	if value.ExpiresAt != nil && now.Add(ttl).After(*value.ExpiresAt) {
		ttl = value.ExpiresAt.Sub(now)
	}
	if ttl <= 0 {
		return Download{}, beforeDownloadSideEffect(ErrExpired)
	}
	signed, err := service.signer.Sign(ctx, value, ttl)
	if err != nil {
		return Download{}, err
	}
	return Download{URL: signed, ExpiresAt: now.Add(ttl).UTC()}, nil
}

func beforeDownloadSideEffect(err error) error {
	return fmt.Errorf("%w: %w", ErrBeforeDownloadSideEffect, err)
}

func (service *Service) currentTime() time.Time {
	if service.now == nil {
		return time.Now().UTC()
	}
	return service.now().UTC()
}

func normalizeArtifactTimes(value *Artifact) {
	value.CreatedAt = value.CreatedAt.UTC()
	if value.ExpiresAt != nil {
		expires := value.ExpiresAt.UTC()
		value.ExpiresAt = &expires
	}
}
