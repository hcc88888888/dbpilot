package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	domain "dbpilot.local/platform/internal/discovery"
	"google.golang.org/protobuf/proto"
)

const maximumPendingReportBytes = domain.MaximumDiscoveryReportBytes
const maximumLegacyPendingReportBytes = 4 << 20

type ReportStore interface {
	Load(context.Context) (*agentv1.DiscoveryReport, error)
	Save(context.Context, *agentv1.DiscoveryReport) error
	Clear(context.Context, *agentv1.DiscoveryReport) error
}

type memoryReportStore struct{ report *agentv1.DiscoveryReport }

func (store *memoryReportStore) Load(context.Context) (*agentv1.DiscoveryReport, error) {
	if store.report == nil {
		return nil, nil
	}
	return proto.Clone(store.report).(*agentv1.DiscoveryReport), nil
}
func (store *memoryReportStore) Save(_ context.Context, report *agentv1.DiscoveryReport) error {
	if store.report != nil {
		left, _ := ReportDigest(store.report)
		right, _ := ReportDigest(report)
		if left != right {
			return errors.New("pending discovery report conflict")
		}
		return nil
	}
	store.report = proto.Clone(report).(*agentv1.DiscoveryReport)
	return nil
}
func (store *memoryReportStore) Clear(_ context.Context, report *agentv1.DiscoveryReport) error {
	if store.report == nil {
		return nil
	}
	left, _ := ReportDigest(store.report)
	right, _ := ReportDigest(report)
	if left != right {
		return errors.New("pending discovery report conflict")
	}
	store.report = nil
	return nil
}

type FileReportStore struct {
	mu              sync.Mutex
	path            string
	retiredRevision uint64
	unavailable     bool
}
type reportRetirement struct {
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
	Reason   string `json:"reason"`
}

func NewFileReportStore(path string) (*FileReportStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("report state path must be absolute and clean")
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		return nil, errors.New("report state parent is unavailable")
	}
	store := &FileReportStore{path: path}
	if marker, exists, err := readReportRetirement(path + ".retired"); err != nil {
		return nil, err
	} else if exists {
		store.retiredRevision = marker.Revision
		store.unavailable = true
	}
	if err := store.recover(); err != nil {
		return nil, err
	}
	return store, nil
}
func (store *FileReportStore) RetiredRevision() uint64 { return store.retiredRevision }
func (store *FileReportStore) Unavailable() bool       { return store.unavailable }
func (store *FileReportStore) ConsumeRetirement(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	marker, exists, err := readReportRetirement(store.path + ".retired")
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if marker.Revision != store.retiredRevision {
		return errors.New("report retirement marker revision changed")
	}
	legacy, legacyErr := loadReportAtLimit(store.path, maximumLegacyPendingReportBytes)
	if legacyErr == nil && legacy != nil {
		digest, _ := ReportDigest(legacy)
		if legacy.GetObservationRevision() != marker.Revision || hex.EncodeToString(digest[:]) != marker.Digest {
			return errors.New("legacy pending report changed before retirement")
		}
		if err = os.Remove(store.path); err != nil {
			return err
		}
		_ = os.Remove(store.path + ".tmp")
		if err = syncParentDirectory(store.path); err != nil {
			return err
		}
	} else if legacyErr != nil && !errors.Is(legacyErr, os.ErrNotExist) {
		return legacyErr
	}
	if err = os.Remove(store.path + ".retired"); err != nil {
		return err
	}
	if err = syncParentDirectory(store.path); err != nil {
		return err
	}
	store.retiredRevision = 0
	store.unavailable = false
	return nil
}
func (store *FileReportStore) Load(ctx context.Context) (*agentv1.DiscoveryReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.load()
}
func (store *FileReportStore) Save(ctx context.Context, report *agentv1.DiscoveryReport) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumPendingReportBytes {
		return errors.New("pending discovery report is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, err := store.load()
	if err != nil {
		return err
	}
	if current != nil {
		left, _ := ReportDigest(current)
		right, _ := ReportDigest(report)
		if left != right {
			return errors.New("pending discovery report conflict")
		}
		return nil
	}
	temporary, err := os.OpenFile(store.path+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() { _ = temporary.Close(); _ = os.Remove(store.path + ".tmp") }
	if _, err = temporary.Write(encoded); err != nil {
		cleanup()
		return err
	}
	if err = temporary.Sync(); err != nil {
		cleanup()
		return err
	}
	if err = temporary.Close(); err != nil {
		_ = os.Remove(store.path + ".tmp")
		return err
	}
	if err = os.Rename(store.path+".tmp", store.path); err != nil {
		_ = os.Remove(store.path + ".tmp")
		return err
	}
	return syncParentDirectory(store.path)
}
func (store *FileReportStore) Clear(ctx context.Context, report *agentv1.DiscoveryReport) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, err := store.load()
	if err != nil {
		return err
	}
	if current == nil {
		return nil
	}
	left, _ := ReportDigest(current)
	right, _ := ReportDigest(report)
	if left != right {
		return errors.New("pending discovery report conflict")
	}
	if err := os.Remove(store.path); err != nil {
		return err
	}
	return syncParentDirectory(store.path)
}
func (store *FileReportStore) load() (*agentv1.DiscoveryReport, error) {
	return loadReportAt(store.path)
}
func loadReportAt(path string) (*agentv1.DiscoveryReport, error) {
	return loadReportAtLimit(path, maximumPendingReportBytes)
}
func loadReportAtLimit(path string, limit int64) (*agentv1.DiscoveryReport, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("pending discovery report is invalid")
	}
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	body, err := io.ReadAll(io.LimitReader(handle, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, errors.New("pending discovery report is invalid")
	}
	var report agentv1.DiscoveryReport
	if proto.Unmarshal(body, &report) != nil {
		return nil, errors.New("pending discovery report is invalid")
	}
	return &report, nil
}
func (store *FileReportStore) recover() error {
	if store.retiredRevision != 0 {
		legacy, legacyErr := loadReportAtLimit(store.path, maximumLegacyPendingReportBytes)
		if errors.Is(legacyErr, os.ErrNotExist) || legacy == nil {
			return nil
		}
		if legacyErr != nil {
			return legacyErr
		}
		digest, _ := ReportDigest(legacy)
		marker, _, markerErr := readReportRetirement(store.path + ".retired")
		if markerErr != nil || legacy.GetObservationRevision() != marker.Revision || hex.EncodeToString(digest[:]) != marker.Digest {
			return errors.New("legacy pending report retirement identity mismatch")
		}
		return nil
	}
	final, finalErr := loadReportAt(store.path)
	temporary, tempErr := loadReportAt(store.path + ".tmp")
	if finalErr != nil {
		legacy, legacyErr := loadReportAtLimit(store.path, maximumLegacyPendingReportBytes)
		if legacyErr == nil && legacy != nil {
			return store.retireLegacy(legacy)
		}
		if info, statErr := os.Lstat(store.path); statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Size() <= maximumLegacyPendingReportBytes {
			store.unavailable = true
			_ = os.Remove(store.path)
			_ = os.Remove(store.path + ".tmp")
			return syncParentDirectory(store.path)
		}
		return finalErr
	}
	if final != nil {
		if temporary != nil || tempErr != nil {
			_ = os.Remove(store.path + ".tmp")
			return syncParentDirectory(store.path)
		}
		return nil
	}
	if temporary != nil && tempErr == nil {
		if err := os.Rename(store.path+".tmp", store.path); err != nil {
			return err
		}
		return syncParentDirectory(store.path)
	}
	if tempErr != nil {
		if err := os.Remove(store.path + ".tmp"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncParentDirectory(store.path)
	}
	return nil
}
func (store *FileReportStore) retireLegacy(report *agentv1.DiscoveryReport) error {
	digest, err := ReportDigest(report)
	if err != nil {
		return err
	}
	marker := reportRetirement{Revision: report.GetObservationRevision(), Digest: hex.EncodeToString(digest[:]), Reason: "legacy_report_exceeds_current_protocol"}
	encoded, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	temporary := store.path + ".retired.tmp"
	_ = os.Remove(temporary)
	handle, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = handle.Write(encoded); err != nil {
		_ = handle.Close()
		return err
	}
	if err = handle.Sync(); err != nil {
		_ = handle.Close()
		return err
	}
	if err = handle.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(store.path + ".retired")
	}
	if err = os.Rename(temporary, store.path+".retired"); err != nil {
		return err
	}
	if err = syncParentDirectory(store.path); err != nil {
		return err
	}
	store.retiredRevision = marker.Revision
	store.unavailable = true
	return nil
}
func readReportRetirement(path string) (reportRetirement, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return reportRetirement{}, false, nil
	}
	if err != nil {
		return reportRetirement{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 512 {
		return reportRetirement{}, false, errors.New("report retirement marker invalid")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return reportRetirement{}, false, err
	}
	var marker reportRetirement
	if json.Unmarshal(body, &marker) != nil || marker.Revision == 0 || len(marker.Digest) != 64 || marker.Reason == "" {
		return reportRetirement{}, false, errors.New("report retirement marker invalid")
	}
	return marker, true, nil
}
func syncParentDirectory(path string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func ReportDigest(report *agentv1.DiscoveryReport) ([sha256.Size]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
