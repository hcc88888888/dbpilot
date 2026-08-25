package spool_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dbpilot.local/platform/internal/policy"
	"dbpilot.local/platform/internal/spool"
)

func openStore(t *testing.T, limits spool.Limits) *spool.Store {
	t.Helper()
	store, err := spool.Open(t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func batch(id string, size int, priority int) spool.Batch {
	return spool.Batch{ID: id, SourceID: "source", CreatedAt: time.Unix(1, 0).Add(time.Duration(len(id)) * time.Second), Priority: priority, Payload: bytes.Repeat([]byte("x"), size)}
}

func TestPolicyAndCheckpointPersistAcrossReopen(t *testing.T) {
	root := t.TempDir()
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

func TestSegmentRotationAndRecoveryTruncatesIncompleteFinalRecord(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
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
	root := t.TempDir()
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

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
