// Package credentialcache holds short-lived database credentials in Agent
// memory only. It has no serialization or filesystem API by design.
package credentialcache

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
)

const maximumSecretBytes = 64 << 10

var (
	ErrUnavailable = errors.New("credential lease unavailable")
	resourceID     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

type Key struct {
	AssignmentID          string
	InstanceID            string
	CredentialRevision    uint64
	ConfigurationRevision uint64
	OperationRevision     uint64
}

type Lease struct {
	ID          string
	Key         Key
	ExpiresAt   time.Time
	Username    string
	SecretBytes []byte
}

func (value Lease) clone() Lease {
	value.SecretBytes = append([]byte(nil), value.SecretBytes...)
	return value
}

func (value *Lease) zero() {
	if value == nil {
		return
	}
	zero(value.SecretBytes)
	value.SecretBytes = nil
	value.Username = ""
}

type Handle struct {
	ID          string
	Key         Key
	ExpiresAt   time.Time
	Username    string
	SecretBytes []byte
}

func (value *Handle) Release() {
	if value == nil {
		return
	}
	zero(value.SecretBytes)
	value.SecretBytes = nil
	value.Username = ""
}

type Loader func(context.Context) (Lease, error)

type entry struct {
	ready chan struct{}
	lease Lease
	err   error
}

type Cache struct {
	now     func() time.Time
	mu      sync.Mutex
	entries map[Key]*entry
	closed  bool
}

func New(now func() time.Time) *Cache {
	if now == nil {
		now = time.Now
	}
	return &Cache{now: now, entries: make(map[Key]*entry)}
}

func (cache *Cache) Get(ctx context.Context, key Key, loader Loader) (*Handle, error) {
	if cache == nil || ctx == nil || ctx.Err() != nil || !key.valid() || loader == nil {
		return nil, ErrUnavailable
	}
	now := cache.now().UTC()
	cache.mu.Lock()
	if cache.closed {
		cache.mu.Unlock()
		return nil, ErrUnavailable
	}
	cache.pruneLocked(now)
	cache.invalidateSupersededLocked(key)
	if current := cache.entries[key]; current != nil {
		ready := current.ready
		cache.mu.Unlock()
		select {
		case <-ready:
			cache.mu.Lock()
			defer cache.mu.Unlock()
			if current.err != nil || !current.lease.ExpiresAt.After(cache.now().UTC()) || cache.entries[key] != current {
				return nil, ErrUnavailable
			}
			return handle(current.lease), nil
		case <-ctx.Done():
			return nil, ErrUnavailable
		}
	}
	current := &entry{ready: make(chan struct{})}
	cache.entries[key] = current
	cache.mu.Unlock()

	loaded, err := loader(ctx)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if err != nil || !loaded.valid(now) || loaded.Key != key || cache.closed || cache.entries[key] != current {
		loaded.zero()
		current.err = ErrUnavailable
		if cache.entries[key] == current {
			delete(cache.entries, key)
		}
		close(current.ready)
		return nil, ErrUnavailable
	}
	current.lease = loaded.clone()
	loaded.zero()
	close(current.ready)
	return handle(current.lease), nil
}

func (cache *Cache) Prune() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	cache.pruneLocked(cache.now().UTC())
	cache.mu.Unlock()
}

func (cache *Cache) InvalidateAssignment(assignmentID string) {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	for key, current := range cache.entries {
		if key.AssignmentID == assignmentID {
			select {
			case <-current.ready:
				current.lease.zero()
			default:
				current.err = ErrUnavailable
			}
			delete(cache.entries, key)
		}
	}
	cache.mu.Unlock()
}

func (cache *Cache) Close() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	cache.closed = true
	for key, current := range cache.entries {
		select {
		case <-current.ready:
			current.lease.zero()
		default:
			current.err = ErrUnavailable
		}
		delete(cache.entries, key)
	}
	cache.mu.Unlock()
}

func (cache *Cache) invalidateSupersededLocked(want Key) {
	for key, current := range cache.entries {
		if key.AssignmentID != want.AssignmentID || key.InstanceID != want.InstanceID || key == want {
			continue
		}
		select {
		case <-current.ready:
			current.lease.zero()
		default:
			current.err = ErrUnavailable
		}
		delete(cache.entries, key)
	}
}

func (cache *Cache) pruneLocked(now time.Time) {
	for key, current := range cache.entries {
		select {
		case <-current.ready:
			if current.err != nil || !current.lease.ExpiresAt.After(now) {
				current.lease.zero()
				delete(cache.entries, key)
			}
		default:
		}
	}
}

func (value Key) valid() bool {
	return resourceID.MatchString(value.AssignmentID) && resourceID.MatchString(value.InstanceID) && value.CredentialRevision > 0 && value.ConfigurationRevision > 0 && value.OperationRevision > 0
}

func (value Lease) valid(now time.Time) bool {
	return resourceID.MatchString(value.ID) && value.Key.valid() && value.ExpiresAt.Location() == time.UTC && value.ExpiresAt.After(now) && len(value.Username) <= 256 && strings.TrimSpace(value.Username) == value.Username && !strings.ContainsAny(value.Username, "\x00\r\n") && len(value.SecretBytes) > 0 && len(value.SecretBytes) <= maximumSecretBytes
}

func handle(value Lease) *Handle {
	return &Handle{ID: value.ID, Key: value.Key, ExpiresAt: value.ExpiresAt, Username: value.Username, SecretBytes: append([]byte(nil), value.SecretBytes...)}
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
