// Package spool persists DBPilot telemetry batches locally until the ingest
// gateway acknowledges them. Payload bytes are kept in segment files; bbolt
// contains only small state and indexes.
package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"dbpilot.local/platform/internal/policy"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrInvalidRoot    = errors.New("invalid spool root")
	ErrAuditCapacity  = errors.New("audit spool capacity exhausted")
	ErrNoActivePolicy = errors.New("no active policy")
	ErrNoCheckpoint   = errors.New("no checkpoint")
	ErrClosed         = errors.New("spool closed")
)

const (
	FindingAuditSpoolFull      = "AUDIT_SPOOL_FULL"
	FindingAuditSpoolIOFailure = "AUDIT_SPOOL_IO_FAILURE"
	FindingCorruptSegment      = "CORRUPT_SEGMENT"
)

var (
	bucketAgentState   = []byte("agent_state")
	bucketPolicyState  = []byte("policy_state")
	bucketCheckpoints  = []byte("checkpoints")
	bucketSegmentIndex = []byte("segment_index")
	bucketDedup        = []byte("dedup")
)

// Limits bounds the total on-disk payload and the preferred segment size.
type Limits struct {
	MaxBytes     int64
	SegmentBytes int64
}

// DataClass determines delivery and eviction behavior.
type DataClass string

const (
	Log       DataClass = "LOG"
	AuditLog  DataClass = "AUDIT_LOG"
	Metric    DataClass = "METRIC"
	JobResult DataClass = "JOB_RESULT"
)

// Batch is the DBPilot-owned durable delivery unit.
type Batch struct {
	ID        string
	SourceID  string
	CreatedAt time.Time
	Priority  int
	Payload   []byte
	Checksum  uint32
}

// Store owns a single process's bbolt metadata database and segment files.
type Store struct {
	mu         sync.Mutex
	root       string
	segments   string
	quarantine string
	limits     Limits
	db         *bolt.DB
	nextSeq    uint64
	entries    map[DataClass][]entry
	findings   map[string]struct{}
	activeFile string
	activeSize int64
}

// Close flushes bbolt state. It is safe to call more than once.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	hadAuditActive := s.activeContainsAudit()
	sealErr := s.sealActive()
	if sealErr != nil && hadAuditActive {
		s.findings[FindingAuditSpoolIOFailure] = struct{}{}
	}
	err := s.db.Close()
	s.db = nil
	if err != nil && hadAuditActive {
		s.findings[FindingAuditSpoolIOFailure] = struct{}{}
	}
	if sealErr != nil {
		return sealErr
	}
	if err != nil {
		return err
	}
	return nil
}

// Open validates and creates a private root, opens bbolt metadata, and scans
// the spool files to recover durable batches.
func Open(root string, limits Limits) (*Store, error) {
	if err := validRoot(root); err != nil {
		return nil, err
	}
	if limits.MaxBytes <= 0 || limits.SegmentBytes <= 0 {
		return nil, fmt.Errorf("%w: non-positive limits", ErrInvalidRoot)
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return nil, err
	}
	segments := filepath.Join(root, "segments")
	quarantine := filepath.Join(root, "quarantine")
	for _, directory := range []string{segments, quarantine} {
		if err := ensurePrivateDirectory(directory); err != nil {
			return nil, err
		}
	}
	if err := restoreReplacementBackups(segments); err != nil {
		return nil, fmt.Errorf("recover spool replacement: %w", err)
	}
	statePath := filepath.Join(root, "state.db")
	if info, err := os.Lstat(statePath); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidRoot
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	db, err := bolt.Open(statePath, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("open spool state: %w", err)
	}
	s := &Store{root: root, segments: segments, quarantine: quarantine, limits: limits, db: db, entries: make(map[DataClass][]entry), findings: make(map[string]struct{})}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{bucketAgentState, bucketPolicyState, bucketCheckpoints, bucketSegmentIndex, bucketDedup} {
			if _, err := tx.CreateBucketIfNotExists(bucket); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := s.recover(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func validRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) {
		return ErrInvalidRoot
	}
	clean := filepath.Clean(root)
	volume := filepath.VolumeName(clean)
	if clean == string(filepath.Separator) || (volume != "" && clean == volume+string(filepath.Separator)) {
		return ErrInvalidRoot
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return ErrInvalidRoot
		}
		if err := validatePrivateDirectory(info); err != nil {
			return err
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect spool root: %w", err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create spool root: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("restrict spool root: %w", err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return err
	}
	return validatePrivateDirectory(info)
}

// PutPolicy atomically replaces the persisted signed policy envelope.
func (s *Store) PutPolicy(envelope policy.SignatureEnvelope) error {
	value, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bucketPolicyState).Put([]byte("active"), value) })
}

// ActivePolicy returns the currently persisted signed policy envelope.
func (s *Store) ActivePolicy() (policy.SignatureEnvelope, error) {
	var out policy.SignatureEnvelope
	err := s.view(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketPolicyState).Get([]byte("active"))
		if value == nil {
			return ErrNoActivePolicy
		}
		return json.Unmarshal(value, &out)
	})
	return out, err
}

// PutCheckpoint records an opaque, bounded receiver checkpoint.
func (s *Store) PutCheckpoint(sourceID string, value []byte) error {
	if sourceID == "" || len(value) > 1<<20 {
		return fmt.Errorf("invalid checkpoint")
	}
	copyValue := append([]byte(nil), value...)
	return s.update(func(tx *bolt.Tx) error { return tx.Bucket(bucketCheckpoints).Put([]byte(sourceID), copyValue) })
}

// Checkpoint returns a copy of a receiver checkpoint.
func (s *Store) Checkpoint(sourceID string) ([]byte, error) {
	var out []byte
	err := s.view(func(tx *bolt.Tx) error {
		value := tx.Bucket(bucketCheckpoints).Get([]byte(sourceID))
		if value == nil {
			return ErrNoCheckpoint
		}
		out = append([]byte(nil), value...)
		return nil
	})
	return out, err
}

// HealthFindings returns stable health finding codes accumulated by recovery
// and capacity enforcement.
func (s *Store) HealthFindings() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	values := make([]string, 0, len(s.findings))
	for value := range s.findings {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func (s *Store) update(fn func(*bolt.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	return s.db.Update(fn)
}
func (s *Store) view(fn func(*bolt.Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	return s.db.View(fn)
}
