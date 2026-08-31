package spool

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCursorRecoveryAfterSegmentFsyncBeforeBboltVisibilityCommit(t *testing.T) {
	root := filepath.Join(t.TempDir(), "spool")
	store, err := Open(root, Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	require.NoError(t, store.Close())
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	payload := []byte("durable-before-index")
	digest := sha256.Sum256(payload)
	receipt := &persistedCursorReceipt{Key: "assignment-1\x004\x00template-1\x00instance-1", Sequence: 7, Digest: digest[:], CollectedAt: now}
	record, err := encodeRecord(recordHeader{ID: "batch-7", SourceID: "plugin-runtime:assignment-1:instance-1", CreatedAt: now, Class: Metric, Sequence: 1, Cursor: receipt}, payload)
	require.NoError(t, err)
	activePath := filepath.Join(root, "segments", "active.open")
	file, err := os.OpenFile(activePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	require.NoError(t, err)
	_, err = file.Write(record)
	require.NoError(t, err)
	require.NoError(t, file.Sync())
	require.NoError(t, file.Close())

	reopened, err := Open(root, Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	pending, err := reopened.Pending(context.Background(), Metric, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	persisted, found, err := reopened.Cursor(context.Background(), receipt.Key)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, uint64(7), persisted.Sequence)
	require.Equal(t, digest[:], persisted.Digest)
}
