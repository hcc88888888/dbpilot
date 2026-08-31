package pluginstate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFileStorePersistsNewestValidatedFamilyStateWithoutSecrets(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileStore(root)
	require.NoError(t, err)

	state := validFamilyState()
	state.ProcessID = 4242
	state.ProcessStartTicks = 77
	state.Failures = []time.Time{time.Unix(100, 0).UTC()}
	saved, err := store.Put(context.Background(), state)
	require.NoError(t, err)
	require.Equal(t, uint64(1), saved.StateRevision)

	reopened, err := NewFileStore(root)
	require.NoError(t, err)
	got, ok := reopened.Get("mysql")
	require.True(t, ok)
	require.Equal(t, saved, got)

	for _, suffix := range []string{".a", ".b"} {
		body, readErr := os.ReadFile(filepath.Join(root, stateFileName+suffix))
		if readErr == nil {
			require.NotContains(t, strings.ToLower(string(body)), "secret")
			require.NotContains(t, strings.ToLower(string(body)), "token")
			require.NotContains(t, strings.ToLower(string(body)), "download_url")
		}
	}
}

func TestFileStoreRejectsStaleOperationAndRecoversFromOneTornSlot(t *testing.T) {
	root := t.TempDir()
	store, err := NewFileStore(root)
	require.NoError(t, err)

	first := validFamilyState()
	first.ObservedOperationRevision = 4
	_, err = store.Put(context.Background(), first)
	require.NoError(t, err)

	newer := first
	newer.ObservedOperationRevision = 5
	newer.InstalledVersion = "1.1.0"
	saved, err := store.Put(context.Background(), newer)
	require.NoError(t, err)
	require.Equal(t, uint64(2), saved.StateRevision)

	stale := newer
	stale.ObservedOperationRevision = 4
	_, err = store.Put(context.Background(), stale)
	require.ErrorIs(t, err, ErrStaleOperation)

	// Revision two is stored in slot B; a torn older slot must not hide it.
	require.NoError(t, os.WriteFile(filepath.Join(root, stateFileName+".a"), []byte("{"), 0o600))
	reopened, err := NewFileStore(root)
	require.NoError(t, err)
	got, ok := reopened.Get("mysql")
	require.True(t, ok)
	require.Equal(t, "1.1.0", got.InstalledVersion)
	require.Equal(t, uint64(5), got.ObservedOperationRevision)
}

func TestFileStoreRejectsUnsafeRootAndInvalidState(t *testing.T) {
	_, err := NewFileStore("relative")
	require.Error(t, err)

	root := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err == nil {
		_, err = NewFileStore(link)
		require.Error(t, err)
	}

	store, err := NewFileStore(root)
	require.NoError(t, err)
	invalid := validFamilyState()
	invalid.DatabaseFamily = "../mysql"
	_, err = store.Put(context.Background(), invalid)
	require.ErrorIs(t, err, ErrInvalidState)
}

func validFamilyState() FamilyState {
	return FamilyState{
		AssignmentID:                "assignment-1",
		PluginID:                    "mysql",
		DatabaseFamily:              "mysql",
		InstalledVersion:            "1.0.0",
		ActiveSlot:                  SlotA,
		DesiredState:                DesiredRunning,
		ProcessState:                ProcessRunning,
		HealthState:                 HealthHealthy,
		CircuitState:                CircuitClosed,
		ActiveConfigurationRevision: 1,
		ObservedOperationRevision:   1,
		BoundInstanceCount:          2,
		StartedAt:                   time.Unix(200, 0).UTC(),
	}
}
