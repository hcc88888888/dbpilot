package artifact

import (
	"context"
	"errors"
	"fmt"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

type Store interface {
	Get(context.Context, platformscope.Scope, string) (Artifact, error)
}

type DownloadSigner interface {
	Sign(context.Context, Artifact, time.Time) (string, error)
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
	if service == nil || service.store == nil || ctx == nil || scope.Validate() != nil || !validArtifactID(id) {
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
	return service.CreateDownloadAt(ctx, scope, id, service.currentTime(), ttl)
}

// CreateDownloadAt makes descriptor creation deterministic for an idempotency
// claim. A retry may use an already-expired issuedAt and still reconstruct the
// exact original descriptor; Verify remains responsible for current expiry.
func (service *Service) CreateDownloadAt(ctx context.Context, scope platformscope.Scope, id string, issuedAt time.Time, ttl time.Duration) (Download, error) {
	if service == nil || service.signer == nil || issuedAt.IsZero() || ttl <= 0 {
		return Download{}, beforeDownloadSideEffect(ErrInvalid)
	}
	value, err := service.Get(ctx, scope, id)
	if err != nil {
		return Download{}, beforeDownloadSideEffect(err)
	}
	issuedAt = issuedAt.UTC()
	if value.ExpiresAt != nil && !value.ExpiresAt.After(issuedAt) {
		return Download{}, beforeDownloadSideEffect(ErrExpired)
	}
	if ttl > MaximumDownloadTTL {
		ttl = MaximumDownloadTTL
	}
	expiresAt := issuedAt.Add(ttl)
	if value.ExpiresAt != nil && expiresAt.After(*value.ExpiresAt) {
		expiresAt = value.ExpiresAt.UTC()
	}
	expiresAt = expiresAt.Truncate(time.Second)
	if !expiresAt.After(issuedAt) {
		return Download{}, beforeDownloadSideEffect(ErrExpired)
	}
	signed, err := service.signer.Sign(ctx, value, expiresAt)
	if err != nil {
		return Download{}, err
	}
	return Download{URL: signed, ExpiresAt: expiresAt}, nil
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
