package credentialcache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCacheSingleflightsAndReturnsReleasableCopies(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	cache := New(func() time.Time { return now })
	key := validKey()
	var calls atomic.Int32
	loader := func(context.Context) (Lease, error) {
		calls.Add(1)
		return Lease{ID: "lease-1", Key: key, ExpiresAt: now.Add(time.Minute), Username: "monitor", SecretBytes: []byte("fixture-password")}, nil
	}

	const callers = 8
	handles := make(chan *Handle, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			handle, err := cache.Get(context.Background(), key, loader)
			require.NoError(t, err)
			handles <- handle
		}()
	}
	wait.Wait()
	close(handles)
	require.Equal(t, int32(1), calls.Load())
	for handle := range handles {
		require.Equal(t, []byte("fixture-password"), handle.SecretBytes)
		retained := handle.SecretBytes
		handle.Release()
		require.Equal(t, make([]byte, len(retained)), retained)
	}
}

func TestCacheExpiryAndRotationZeroizeStoredBuffers(t *testing.T) {
	now := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	cache := New(func() time.Time { return now })
	firstKey := validKey()
	first, err := cache.Get(context.Background(), firstKey, func(context.Context) (Lease, error) {
		return Lease{ID: "lease-1", Key: firstKey, ExpiresAt: now.Add(time.Minute), Username: "monitor", SecretBytes: []byte("old-password")}, nil
	})
	require.NoError(t, err)
	first.Release()
	oldBuffer := cache.entries[firstKey].lease.SecretBytes

	rotatedKey := firstKey
	rotatedKey.CredentialRevision++
	rotated, err := cache.Get(context.Background(), rotatedKey, func(context.Context) (Lease, error) {
		return Lease{ID: "lease-2", Key: rotatedKey, ExpiresAt: now.Add(time.Minute), Username: "monitor", SecretBytes: []byte("new-password")}, nil
	})
	require.NoError(t, err)
	rotated.Release()
	require.NotContains(t, cache.entries, firstKey)
	require.Equal(t, make([]byte, len(oldBuffer)), oldBuffer)

	newBuffer := cache.entries[rotatedKey].lease.SecretBytes
	now = now.Add(2 * time.Minute)
	cache.Prune()
	require.Empty(t, cache.entries)
	require.Equal(t, make([]byte, len(newBuffer)), newBuffer)
}

func TestNewCacheIsEmptyAndNeverRestoresAPreviousLease(t *testing.T) {
	cache := New(time.Now)
	require.Empty(t, cache.entries)
	cache.Close()
	require.Empty(t, New(time.Now).entries)
}

func TestCacheTimerZerosAndRemovesWithoutAnotherGet(t *testing.T) {
	cache := New(time.Now)
	key := validKey()
	handle, err := cache.Get(context.Background(), key, func(context.Context) (Lease, error) {
		return Lease{ID: "lease-timer", Key: key, ExpiresAt: time.Now().UTC().Add(50 * time.Millisecond), Username: "monitor", SecretBytes: []byte("timer-secret")}, nil
	})
	require.NoError(t, err)
	handle.Release()
	stored := cache.entries[key].lease.SecretBytes
	require.Eventually(t, func() bool { cache.mu.Lock(); defer cache.mu.Unlock(); return cache.entries[key] == nil }, time.Second, 10*time.Millisecond)
	require.Equal(t, make([]byte, len(stored)), stored)
}

func validKey() Key {
	return Key{AssignmentID: "assignment-1", InstanceID: "instance-1", CredentialRevision: 9, ConfigurationRevision: 5, OperationRevision: 7}
}
