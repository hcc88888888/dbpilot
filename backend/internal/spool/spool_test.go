package spool_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
	"github.com/stretchr/testify/require"
)

func openStore(t *testing.T, limits spool.Limits) *spool.Store {
	t.Helper()
	store, err := spool.Open(secureSpoolRoot(t), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func secureSpoolRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "spool")
	require.NoError(t, os.Mkdir(root, 0o700))
	require.NoError(t, os.Chmod(root, 0o700))
	return root
}

func batch(id string, size int, priority int) spool.Batch {
	return spool.Batch{ID: id, SourceID: "source", CreatedAt: time.Unix(1, 0).Add(time.Duration(len(id)) * time.Second), Priority: priority, Payload: bytes.Repeat([]byte("x"), size)}
}

func TestPolicyAndCheckpointPersistAcrossReopen(t *testing.T) {
	root := secureSpoolRoot(t)
	limits := spool.Limits{MaxBytes: 8192, SegmentBytes: 1024}
	store, err := spool.Open(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	envelope := policy.SignatureEnvelope{Policy: policy.Policy{AgentID: "agent", Version: 7}, Signature: []byte("signature")}
	if err := store.PutPolicy(envelope); err != nil {
		t.Fatal(err)
	}
	if err := store.PutCheckpoint("file", []byte("42")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = spool.Open(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	gotPolicy, err := store.ActivePolicy()
	if err != nil || gotPolicy.Policy.Version != 7 {
		t.Fatalf("ActivePolicy() = %#v, %v", gotPolicy, err)
	}
	gotCheckpoint, err := store.Checkpoint("file")
	if err != nil || string(gotCheckpoint) != "42" {
		t.Fatalf("Checkpoint() = %q, %v", gotCheckpoint, err)
	}
}

func TestAppendPendingOrderDuplicateAndAck(t *testing.T) {
	ctx := context.Background()
	store := openStore(t, spool.Limits{MaxBytes: 8192, SegmentBytes: 1024})
	for _, item := range []spool.Batch{batch("first", 20, 1), batch("second", 20, 1)} {
		if err := store.Append(ctx, spool.Log, item); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Append(ctx, spool.Log, batch("first", 200, 1)); err != nil {
		t.Fatal(err)
	}
	pending, err := store.Pending(ctx, spool.Log, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending[0].ID != "first" || pending[1].ID != "second" {
		t.Fatalf("pending = %#v", pending)
	}
	if err := store.Ack(ctx, spool.Log, "first"); err != nil {
		t.Fatal(err)
	}
	if err := store.Ack(ctx, spool.Log, "first"); err != nil {
		t.Fatal(err)
	}
	pending, err = store.Pending(ctx, spool.Log, 10)
	if err != nil || len(pending) != 1 || pending[0].ID != "second" {
		t.Fatalf("after ack = %#v, %v", pending, err)
	}
}

func TestAppendWithCursorRetainsExactReceiptAfterAckAndReopen(t *testing.T) {
	ctx := context.Background()
	root := secureSpoolRoot(t)
	limits := spool.Limits{MaxBytes: 8192, SegmentBytes: 1024}
	store, err := spool.Open(root, limits)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("first"))
	receipt := spool.CursorReceipt{Key: "assignment-1\x004\x00template-1\x00instance-1", Sequence: 7, Digest: digest[:], CollectedAt: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)}
	original := spool.Batch{ID: "plugin-batch-7", SourceID: "plugin-runtime:assignment-1:instance-1", CreatedAt: receipt.CollectedAt, Payload: []byte("first")}

	result, err := store.AppendWithCursor(ctx, spool.Metric, original, receipt)
	require.NoError(t, err)
	require.Equal(t, spool.CursorAppendStored, result)
	require.NoError(t, store.Ack(ctx, spool.Metric, original.ID))
	require.NoError(t, store.Close())

	store, err = spool.Open(root, limits)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	persisted, found, err := store.Cursor(ctx, receipt.Key)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, receipt.Sequence, persisted.Sequence)
	require.Equal(t, receipt.Digest, persisted.Digest)
	result, err = store.AppendWithCursor(ctx, spool.Metric, original, receipt)
	require.NoError(t, err)
	require.Equal(t, spool.CursorAppendDuplicate, result)
	pending, err := store.Pending(ctx, spool.Metric, 10)
	require.NoError(t, err)
	require.Empty(t, pending, "an ACKed exact retry must not re-enter delivery")

	conflict := receipt
	conflictDigest := sha256.Sum256([]byte("different"))
	conflict.Digest = conflictDigest[:]
	_, err = store.AppendWithCursor(ctx, spool.Metric, spool.Batch{ID: original.ID, SourceID: original.SourceID, CreatedAt: original.CreatedAt, Payload: []byte("different")}, conflict)
	require.ErrorIs(t, err, spool.ErrCursorConflict)
}

func TestAppendWithCursorSerializesConcurrentSameSequence(t *testing.T) {
	ctx := context.Background()
	store := openStore(t, spool.Limits{MaxBytes: 8192, SegmentBytes: 1024})
	digest := sha256.Sum256([]byte("first"))
	receipt := spool.CursorReceipt{Key: "assignment-1\x004\x00template-1\x00instance-1", Sequence: 7, Digest: digest[:], CollectedAt: time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)}
	batch := spool.Batch{ID: "plugin-batch-7", SourceID: "plugin-runtime:assignment-1:instance-1", CreatedAt: receipt.CollectedAt, Payload: []byte("first")}
	results := make(chan spool.CursorAppendResult, 2)
	errors := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			ready.Done()
			<-start
			result, err := store.AppendWithCursor(ctx, spool.Metric, batch, receipt)
			results <- result
			errors <- err
		}()
	}
	ready.Wait()
	close(start)
	first, second := <-results, <-results
	require.NoError(t, <-errors)
	require.NoError(t, <-errors)
	require.ElementsMatch(t, []spool.CursorAppendResult{spool.CursorAppendStored, spool.CursorAppendDuplicate}, []spool.CursorAppendResult{first, second})
}

func TestSegmentRotationAndRecoveryTruncatesIncompleteFinalRecord(t *testing.T) {
	ctx := context.Background()
	root := secureSpoolRoot(t)
	limits := spool.Limits{MaxBytes: 8192, SegmentBytes: 100}
	store, err := spool.Open(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Metric, batch("one", 80, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Metric, batch("two", 80, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	segments, err := filepath.Glob(filepath.Join(root, "segments", "*.seg"))
	if err != nil || len(segments) < 2 {
		t.Fatalf("segments = %v, %v", segments, err)
	}
	file, err := os.OpenFile(segments[len(segments)-1], os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0x44, 0x42, 0x50}); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = spool.Open(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pending, err := store.Pending(ctx, spool.Metric, 10)
	if err != nil || len(pending) != 2 {
		t.Fatalf("recovered = %#v, %v", pending, err)
	}
}

func TestCorruptSegmentIsQuarantined(t *testing.T) {
	ctx := context.Background()
	root := secureSpoolRoot(t)
	limits := spool.Limits{MaxBytes: 8192, SegmentBytes: 100}
	store, err := spool.Open(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Log, batch("one", 80, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Log, batch("two", 80, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	segments, err := filepath.Glob(filepath.Join(root, "segments", "*.seg"))
	if err != nil || len(segments) == 0 {
		t.Fatal("expected a sealed segment")
	}
	contents, err := os.ReadFile(segments[0])
	if err != nil {
		t.Fatal(err)
	}
	contents[len(contents)-1] ^= 0xff
	if err := os.WriteFile(segments[0], contents, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err = spool.Open(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if !contains(store.HealthFindings(), spool.FindingCorruptSegment) {
		t.Fatalf("findings = %v", store.HealthFindings())
	}
	quarantine, _ := filepath.Glob(filepath.Join(root, "quarantine", "*.seg"))
	if len(quarantine) == 0 {
		t.Fatal("corrupt segment was not quarantined")
	}
}

func TestCapacityEvictsMetricsThenNonAuditLogsButRejectsAudit(t *testing.T) {
	ctx := context.Background()
	store := openStore(t, spool.Limits{MaxBytes: 1200, SegmentBytes: 200})
	if err := store.Append(ctx, spool.Metric, batch("metric", 500, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Log, batch("low", 500, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Log, batch("high", 500, 9)); err != nil {
		t.Fatal(err)
	}
	metrics, err := store.Pending(ctx, spool.Metric, 10)
	if err != nil || len(metrics) != 0 {
		t.Fatalf("metrics = %#v, %v", metrics, err)
	}
	logs, err := store.Pending(ctx, spool.Log, 10)
	if err != nil || len(logs) != 1 || logs[0].ID != "high" {
		t.Fatalf("logs = %#v, %v", logs, err)
	}
	if err := store.Append(ctx, spool.AuditLog, batch("audit-one", 500, 1)); err != nil {
		t.Fatal(err)
	}
	err = store.Append(ctx, spool.AuditLog, batch("audit-two", 700, 1))
	if !errors.Is(err, spool.ErrAuditCapacity) {
		t.Fatalf("Append(audit) error = %v", err)
	}
	if !contains(store.HealthFindings(), spool.FindingAuditSpoolFull) {
		t.Fatalf("findings = %v", store.HealthFindings())
	}
}

func TestOpenRejectsInvalidRoots(t *testing.T) {
	for _, root := range []string{"", ".", string(filepath.Separator)} {
		if _, err := spool.Open(root, spool.Limits{MaxBytes: 1024, SegmentBytes: 512}); !errors.Is(err, spool.ErrInvalidRoot) {
			t.Errorf("Open(%q) error = %v", root, err)
		}
	}
}

func TestOpenRejectsLinuxSymlinkAndInsecureRoots(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux root ownership and mode checks")
	}
	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Open(link, spool.Limits{MaxBytes: 1024, SegmentBytes: 512}); !errors.Is(err, spool.ErrInvalidRoot) {
		t.Fatalf("Open(symlink root) error = %v", err)
	}
	insecureRoot := filepath.Join(parent, "insecure")
	if err := os.Mkdir(insecureRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.Open(insecureRoot, spool.Limits{MaxBytes: 1024, SegmentBytes: 512}); !errors.Is(err, spool.ErrInvalidRoot) {
		t.Fatalf("Open(insecure root) error = %v", err)
	}
}

func TestAuditIOFailureRaisesHealthFinding(t *testing.T) {
	ctx := context.Background()
	root := secureSpoolRoot(t)
	store, err := spool.Open(root, spool.Limits{MaxBytes: 4096, SegmentBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	segments := filepath.Join(root, "segments")
	if err := os.RemoveAll(segments); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(segments, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.AuditLog, batch("audit-io", 10, 1)); err == nil {
		t.Fatal("Append(audit) error = nil")
	}
	if !contains(store.HealthFindings(), spool.FindingAuditSpoolIOFailure) {
		t.Fatalf("findings = %v", store.HealthFindings())
	}
}

func TestMetricEvictionUsesPriorityThenAge(t *testing.T) {
	ctx := context.Background()
	store := openStore(t, spool.Limits{MaxBytes: 800, SegmentBytes: 1024})
	if err := store.Append(ctx, spool.Metric, batch("old-high", 200, 9)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Metric, batch("new-low", 200, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Metric, batch("incoming", 200, 5)); err != nil {
		t.Fatal(err)
	}
	pending, err := store.Pending(ctx, spool.Metric, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 || pending[0].ID != "old-high" || pending[1].ID != "incoming" {
		t.Fatalf("pending after metric eviction = %#v", pending)
	}
}

func TestSegmentBytesKeepsActiveSegmentUntilRotation(t *testing.T) {
	ctx := context.Background()
	root := secureSpoolRoot(t)
	store, err := spool.Open(root, spool.Limits{MaxBytes: 8192, SegmentBytes: 600})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Append(ctx, spool.Log, batch("one", 20, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Log, batch("two", 20, 1)); err != nil {
		t.Fatal(err)
	}
	sealed, _ := filepath.Glob(filepath.Join(root, "segments", "*.seg"))
	if len(sealed) != 0 {
		t.Fatalf("sealed segments before rotation = %v", sealed)
	}
	if err := store.Append(ctx, spool.Log, batch("three", 300, 1)); err != nil {
		t.Fatal(err)
	}
	sealed, _ = filepath.Glob(filepath.Join(root, "segments", "*.seg"))
	if len(sealed) != 1 {
		t.Fatalf("sealed segments after rotation = %v", sealed)
	}
}

func TestPendingRejectsClosedStore(t *testing.T) {
	store := openStore(t, spool.Limits{MaxBytes: 1024, SegmentBytes: 512})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pending(context.Background(), spool.Log, 1); !errors.Is(err, spool.ErrClosed) {
		t.Fatalf("Pending after Close error = %v", err)
	}
}

func TestCloseAuditSealFailureRaisesHealthFinding(t *testing.T) {
	ctx := context.Background()
	root := secureSpoolRoot(t)
	store, err := spool.Open(root, spool.Limits{MaxBytes: 4096, SegmentBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.AuditLog, batch("audit-close", 20, 1)); err != nil {
		t.Fatal(err)
	}
	active := filepath.Join(root, "segments", "active.open")
	if err := os.Rename(active, filepath.Join(root, "moved-active")); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err == nil {
		t.Fatal("Close() error = nil")
	}
	if !contains(store.HealthFindings(), spool.FindingAuditSpoolIOFailure) {
		t.Fatalf("findings = %v", store.HealthFindings())
	}
}

func TestSealMakesActiveBatchesAvailableWithoutClosingState(t *testing.T) {
	store := openStore(t, spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	require.NoError(t, store.Append(context.Background(), spool.Log, spool.Batch{ID: "seal-1", SourceID: "source", CreatedAt: time.Now(), Payload: []byte("payload")}))
	require.NoError(t, store.Seal())
	batches, err := store.Pending(context.Background(), spool.Log, 1)
	require.NoError(t, err)
	require.Len(t, batches, 1)
}

func TestRecordHealthFindingExposesExporterFailure(t *testing.T) {
	store := openStore(t, spool.Limits{MaxBytes: 1 << 20, SegmentBytes: 1 << 20})
	store.RecordHealthFinding("TELEMETRY_PERMANENT_REJECTION", "gateway rejected batch")
	if !contains(store.HealthFindings(), "TELEMETRY_PERMANENT_REJECTION") {
		t.Fatalf("findings = %v", store.HealthFindings())
	}
}

func TestOpenRestoresReplacementBackupAfterInterruptedCompaction(t *testing.T) {
	ctx := context.Background()
	root := secureSpoolRoot(t)
	limits := spool.Limits{MaxBytes: 4096, SegmentBytes: 100}
	store, err := spool.Open(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, spool.Log, batch("persist", 20, 1)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	segments, err := filepath.Glob(filepath.Join(root, "segments", "*.seg"))
	if err != nil || len(segments) != 1 {
		t.Fatalf("sealed segments = %v, %v", segments, err)
	}
	if err := os.Rename(segments[0], segments[0]+".previous"); err != nil {
		t.Fatal(err)
	}
	store, err = spool.Open(root, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pending, err := store.Pending(ctx, spool.Log, 10)
	if err != nil || len(pending) != 1 || pending[0].ID != "persist" {
		t.Fatalf("recovered pending = %#v, %v", pending, err)
	}
}

func TestStatsReportsActualDurableUsageAndCapacity(t *testing.T) {
	store := openStore(t, spool.Limits{MaxBytes: 4096, SegmentBytes: 4096})
	require.NoError(t, store.Append(context.Background(), spool.Log, batch("stats", 128, 1)))

	stats, err := store.Stats()

	require.NoError(t, err)
	require.Equal(t, int64(4096), stats.MaxBytes)
	require.Greater(t, stats.UsedBytes, int64(128), "durable usage includes the bounded record envelope")
	require.Equal(t, 1, stats.PendingBatches)
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
