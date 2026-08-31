package spool

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	recordVersion  byte = 1
	maxHeaderBytes      = 1 << 20
)

var (
	recordMagic = [4]byte{'D', 'B', 'P', 'S'}
	crcTable    = crc32.MakeTable(crc32.Castagnoli)
)

type recordHeader struct {
	ID        string                  `json:"id"`
	SourceID  string                  `json:"source_id"`
	CreatedAt time.Time               `json:"created_at"`
	Priority  int                     `json:"priority"`
	Checksum  uint32                  `json:"checksum"`
	Class     DataClass               `json:"class"`
	Sequence  uint64                  `json:"sequence"`
	Cursor    *persistedCursorReceipt `json:"cursor,omitempty"`
}

type persistedCursorReceipt struct {
	Version               uint8     `json:"version"`
	Key                   string    `json:"key"`
	AssignmentID          string    `json:"assignment_id"`
	ConfigurationRevision uint64    `json:"configuration_revision"`
	TemplateID            string    `json:"template_id"`
	InstanceID            string    `json:"instance_id"`
	Sequence              uint64    `json:"sequence"`
	Digest                []byte    `json:"digest"`
	CollectedAt           time.Time `json:"collected_at"`
	ACKPending            bool      `json:"ack_pending"`
}

type entry struct {
	batch    Batch
	class    DataClass
	sequence uint64
	file     string
	bytes    int64
	cursor   *persistedCursorReceipt
}

// Append durably adds a batch. A repeated (class, ID) is a no-op so retries
// cannot duplicate telemetry.
func (s *Store) Append(ctx context.Context, class DataClass, batch Batch) error {
	_, err := s.append(ctx, class, batch, nil)
	return err
}

// AppendWithCursor makes a plugin batch visible and advances its durable
// logical cursor in the same bbolt transaction. The segment record also
// carries the receipt so recovery of a crash after segment fsync but before
// the bbolt commit cannot expose payload bytes without their conflict fence.
func (s *Store) AppendWithCursor(ctx context.Context, class DataClass, batch Batch, receipt CursorReceipt) (CursorAppendResult, error) {
	payloadDigest := sha256.Sum256(batch.Payload)
	if !validCursorReceipt(receipt) || !bytes.Equal(payloadDigest[:], receipt.Digest) {
		return 0, fmt.Errorf("invalid spool cursor receipt")
	}
	value := &persistedCursorReceipt{Version: 1, Key: receipt.Key, AssignmentID: receipt.AssignmentID, ConfigurationRevision: receipt.ConfigurationRevision, TemplateID: receipt.TemplateID, InstanceID: receipt.InstanceID, Sequence: receipt.Sequence, Digest: append([]byte(nil), receipt.Digest...), CollectedAt: receipt.CollectedAt.UTC(), ACKPending: true}
	return s.append(ctx, class, batch, value)
}

// Cursor returns the retained producer receipt, including after the payload
// has been acknowledged and removed from the pending delivery set.
func (s *Store) Cursor(ctx context.Context, key string) (CursorReceipt, bool, error) {
	if err := ctx.Err(); err != nil {
		return CursorReceipt{}, false, err
	}
	if key == "" || len(key) > 1024 {
		return CursorReceipt{}, false, fmt.Errorf("invalid spool cursor key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return CursorReceipt{}, false, ErrClosed
	}
	value, err := loadCursorReceipt(s.db, key)
	if err != nil || value == nil {
		return CursorReceipt{}, false, err
	}
	return publicCursorReceipt(value), true, nil
}

func (s *Store) MarkCursorAcknowledged(ctx context.Context, key string, sequence uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if key == "" || sequence == 0 {
		return ErrCursorConflict
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	current, err := loadCursorReceipt(s.db, key)
	if err != nil || current == nil || current.Sequence != sequence {
		return ErrCursorConflict
	}
	if !current.ACKPending {
		return nil
	}
	current.ACKPending = false
	encoded, err := json.Marshal(current)
	if err != nil {
		return err
	}
	if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketCursorReceipt).Put([]byte(key), encoded) }); err != nil {
		return err
	}
	for class := range s.entries {
		for index := range s.entries[class] {
			cursor := s.entries[class][index].cursor
			if cursor != nil && cursor.Key == key && cursor.Sequence == sequence {
				cursor.ACKPending = false
			}
		}
	}
	return nil
}

func (s *Store) append(ctx context.Context, class DataClass, batch Batch, receipt *persistedCursorReceipt) (CursorAppendResult, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if !validClass(class) || batch.ID == "" || batch.SourceID == "" {
		return 0, fmt.Errorf("invalid spool batch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, ErrClosed
	}
	if receipt != nil {
		current, err := loadCursorReceipt(s.db, receipt.Key)
		if err != nil {
			return 0, err
		}
		if current != nil {
			if current.ACKPending && receipt.Sequence > current.Sequence {
				return 0, ErrCursorACKPending
			}
			if receipt.Sequence < current.Sequence || receipt.Sequence == current.Sequence && (!bytes.Equal(receipt.Digest, current.Digest) || !receipt.CollectedAt.Equal(current.CollectedAt)) || receipt.Sequence > current.Sequence && receipt.CollectedAt.Before(current.CollectedAt) {
				return 0, ErrCursorConflict
			}
			if receipt.Sequence == current.Sequence {
				return CursorAppendDuplicate, nil
			}
		}
	}
	if s.find(class, batch.ID) != nil {
		if receipt != nil {
			return 0, ErrCursorConflict
		}
		return CursorAppendDuplicate, nil
	}
	sequence := s.nextSeq + 1
	encoded, err := encodeRecord(recordHeader{ID: batch.ID, SourceID: batch.SourceID, CreatedAt: batch.CreatedAt.UTC(), Priority: batch.Priority, Checksum: batch.Checksum, Class: class, Sequence: sequence}, batch.Payload)
	if receipt != nil {
		encoded, err = encodeRecord(recordHeader{ID: batch.ID, SourceID: batch.SourceID, CreatedAt: batch.CreatedAt.UTC(), Priority: batch.Priority, Checksum: batch.Checksum, Class: class, Sequence: sequence, Cursor: receipt}, batch.Payload)
	}
	if err != nil {
		return 0, err
	}
	if s.activeFile != "" && s.activeSize > 0 && s.activeSize+int64(len(encoded)) > s.limits.SegmentBytes {
		if err := s.sealActive(); err != nil {
			return 0, s.auditIOFailure(class, err)
		}
	}
	if err := s.makeCapacity(class, int64(len(encoded))); err != nil {
		return 0, s.auditIOFailure(class, err)
	}
	if s.activeFile == "" {
		s.activeFile = "active.open"
		s.activeSize = 0
	}
	path := filepath.Join(s.segments, s.activeFile)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, s.auditIOFailure(class, err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		return 0, s.auditIOFailure(class, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return 0, s.auditIOFailure(class, err)
	}
	if err := file.Close(); err != nil {
		return 0, s.auditIOFailure(class, err)
	}
	stored := batch
	stored.Payload = append([]byte(nil), batch.Payload...)
	stored.CreatedAt = stored.CreatedAt.UTC()
	item := entry{batch: stored, class: class, sequence: sequence, file: s.activeFile, bytes: int64(len(encoded)), cursor: clonePersistedCursor(receipt)}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketSegmentIndex).Put(sequenceKey(sequence), []byte(s.activeFile)); err != nil {
			return err
		}
		if err := tx.Bucket(bucketDedup).Put(dedupKey(class, batch.ID), sequenceKey(sequence)); err != nil {
			return err
		}
		if receipt != nil {
			encodedReceipt, err := json.Marshal(receipt)
			if err != nil {
				return err
			}
			return tx.Bucket(bucketCursorReceipt).Put([]byte(receipt.Key), encodedReceipt)
		}
		return nil
	}); err != nil {
		_ = os.Truncate(path, s.activeSize)
		return 0, s.auditIOFailure(class, err)
	}
	s.entries[class] = append(s.entries[class], item)
	s.nextSeq = sequence
	s.activeSize += int64(len(encoded))
	if s.activeSize >= s.limits.SegmentBytes {
		if err := s.sealActive(); err != nil {
			return 0, s.auditIOFailure(class, err)
		}
	}
	return CursorAppendStored, nil
}

// Lookup returns whether a pending batch has the supplied logical identity
// and whether its durable payload exactly matches. Gateway cursor recovery
// uses this after a crash between Append and its own cursor fsync.
func (s *Store) Lookup(ctx context.Context, class DataClass, id string, payload []byte) (bool, bool, error) {
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	if !validClass(class) || id == "" {
		return false, false, fmt.Errorf("invalid spool lookup")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return false, false, ErrClosed
	}
	item := s.find(class, id)
	if item == nil {
		return false, false, nil
	}
	return true, bytes.Equal(item.batch.Payload, payload), nil
}

// Pending returns the oldest unacknowledged batches of a data class.
func (s *Store) Pending(ctx context.Context, class DataClass, limit int) ([]Batch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validClass(class) || limit < 0 {
		return nil, fmt.Errorf("invalid pending request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	items := s.entries[class]
	if limit == 0 || limit > len(items) {
		limit = len(items)
	}
	result := make([]Batch, 0, limit)
	for _, item := range items[:limit] {
		copyBatch := item.batch
		copyBatch.Payload = append([]byte(nil), item.batch.Payload...)
		result = append(result, copyBatch)
	}
	return result, nil
}

// Ack is idempotent. A sealed segment is removed only after all of its
// records have been acknowledged; otherwise it is compacted durably.
func (s *Store) Ack(ctx context.Context, class DataClass, batchID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validClass(class) || batchID == "" {
		return fmt.Errorf("invalid acknowledgement")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}
	item := s.find(class, batchID)
	if item == nil {
		return nil
	}
	size, err := s.rewriteWithout(*item)
	if err != nil {
		return s.auditIOFailure(class, err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketSegmentIndex).Delete(sequenceKey(item.sequence)); err != nil {
			return err
		}
		return tx.Bucket(bucketDedup).Delete(dedupKey(class, batchID))
	}); err != nil {
		return s.auditIOFailure(class, err)
	}
	s.remove(class, batchID)
	if item.file == s.activeFile {
		s.activeSize = size
		if size == 0 {
			s.activeFile = ""
		}
	}
	return nil
}

func (s *Store) recover() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	paths, err := filepath.Glob(filepath.Join(s.segments, "*.seg"))
	if err != nil {
		return err
	}
	sort.Strings(paths)
	activePath := filepath.Join(s.segments, "active.open")
	if _, err := os.Lstat(activePath); err == nil {
		paths = append(paths, activePath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	loaded := make(map[DataClass][]entry)
	var maxSeq uint64
	for _, path := range paths {
		items, err := recoverFile(path)
		if err != nil {
			if errors.Is(err, errCorruptRecord) {
				if quarantineErr := s.quarantineFile(path); quarantineErr != nil {
					return quarantineErr
				}
				s.findings[FindingCorruptSegment] = struct{}{}
				continue
			}
			return fmt.Errorf("recover %s: %w", path, err)
		}
		for _, item := range items {
			item.file = filepath.Base(path)
			loaded[item.class] = append(loaded[item.class], item)
			if item.sequence > maxSeq {
				maxSeq = item.sequence
			}
		}
	}
	for class := range loaded {
		sort.Slice(loaded[class], func(i, j int) bool { return loaded[class][i].sequence < loaded[class][j].sequence })
	}
	s.entries, s.nextSeq = loaded, maxSeq
	if info, err := os.Stat(activePath); err == nil {
		s.activeFile, s.activeSize = filepath.Base(activePath), info.Size()
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range [][]byte{bucketSegmentIndex, bucketDedup} {
			b := tx.Bucket(bucket)
			if err := b.ForEach(func(key, _ []byte) error { return b.Delete(key) }); err != nil {
				return err
			}
		}
		for class, entries := range s.entries {
			for _, item := range entries {
				if err := tx.Bucket(bucketSegmentIndex).Put(sequenceKey(item.sequence), []byte(item.file)); err != nil {
					return err
				}
				if err := tx.Bucket(bucketDedup).Put(dedupKey(class, item.batch.ID), sequenceKey(item.sequence)); err != nil {
					return err
				}
				if item.cursor != nil {
					current, err := loadCursorReceiptTx(tx, item.cursor.Key)
					if err != nil {
						return err
					}
					if current != nil && (item.cursor.Sequence < current.Sequence || item.cursor.Sequence == current.Sequence && (!bytes.Equal(item.cursor.Digest, current.Digest) || !item.cursor.CollectedAt.Equal(current.CollectedAt))) {
						return ErrCursorConflict
					}
					if current == nil || item.cursor.Sequence > current.Sequence {
						encoded, err := json.Marshal(item.cursor)
						if err != nil {
							return err
						}
						if err := tx.Bucket(bucketCursorReceipt).Put([]byte(item.cursor.Key), encoded); err != nil {
							return err
						}
					}
				}
			}
		}
		return nil
	})
}

func (s *Store) makeCapacity(newClass DataClass, needed int64) error {
	for s.usedBytes()+needed > s.limits.MaxBytes {
		candidate := s.evictionCandidate()
		if candidate == nil {
			if newClass == AuditLog {
				s.findings[FindingAuditSpoolFull] = struct{}{}
				return ErrAuditCapacity
			}
			return fmt.Errorf("spool capacity exhausted")
		}
		if err := s.delete(candidate.class, candidate.batch.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) evictionCandidate() *entry {
	var choices []*entry
	for _, class := range []DataClass{Metric, Log, JobResult} {
		for index := range s.entries[class] {
			choices = append(choices, &s.entries[class][index])
		}
		if len(choices) > 0 {
			sort.Slice(choices, func(i, j int) bool {
				if choices[i].batch.Priority != choices[j].batch.Priority {
					return choices[i].batch.Priority < choices[j].batch.Priority
				}
				return choices[i].sequence < choices[j].sequence
			})
			return choices[0]
		}
	}
	return nil
}

func (s *Store) delete(class DataClass, id string) error {
	item := s.find(class, id)
	if item == nil {
		return nil
	}
	size, err := s.rewriteWithout(*item)
	if err != nil {
		return err
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketSegmentIndex).Delete(sequenceKey(item.sequence)); err != nil {
			return err
		}
		return tx.Bucket(bucketDedup).Delete(dedupKey(class, id))
	}); err != nil {
		return err
	}
	s.remove(class, id)
	if item.file == s.activeFile {
		s.activeSize = size
		if size == 0 {
			s.activeFile = ""
		}
	}
	return nil
}

func (s *Store) auditIOFailure(class DataClass, err error) error {
	if class == AuditLog && err != nil && !errors.Is(err, ErrAuditCapacity) {
		s.findings[FindingAuditSpoolIOFailure] = struct{}{}
	}
	return err
}

func (s *Store) activeContainsAudit() bool {
	for _, item := range s.entries[AuditLog] {
		if item.file == s.activeFile {
			return true
		}
	}
	return false
}

// sealActive promotes the fsynced active segment only when it contains
// records. The metadata is updated after the rename; recovery can rebuild it
// if the process stops between those operations.
func (s *Store) sealActive() error {
	if s.activeFile == "" {
		return nil
	}
	var first uint64
	for _, values := range s.entries {
		for _, item := range values {
			if item.file == s.activeFile && (first == 0 || item.sequence < first) {
				first = item.sequence
			}
		}
	}
	if first == 0 {
		if err := os.Remove(filepath.Join(s.segments, s.activeFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		s.activeFile, s.activeSize = "", 0
		return nil
	}
	sealed := fmt.Sprintf("%020d.seg", first)
	if err := os.Rename(filepath.Join(s.segments, s.activeFile), filepath.Join(s.segments, sealed)); err != nil {
		return err
	}
	if err := syncDirectory(s.segments); err != nil {
		return err
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		for _, values := range s.entries {
			for _, item := range values {
				if item.file == s.activeFile {
					if err := tx.Bucket(bucketSegmentIndex).Put(sequenceKey(item.sequence), []byte(sealed)); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for class, values := range s.entries {
		for index := range values {
			if s.entries[class][index].file == s.activeFile {
				s.entries[class][index].file = sealed
			}
		}
	}
	s.activeFile, s.activeSize = "", 0
	return nil
}

// rewriteWithout removes one delivered or evicted record while preserving
// every other record in the same segment. It returns the new physical size.
func (s *Store) rewriteWithout(exclude entry) (int64, error) {
	var remaining []entry
	for _, values := range s.entries {
		for _, item := range values {
			if item.file == exclude.file && item.sequence != exclude.sequence {
				remaining = append(remaining, item)
			}
		}
	}
	sort.Slice(remaining, func(i, j int) bool { return remaining[i].sequence < remaining[j].sequence })
	path := filepath.Join(s.segments, exclude.file)
	if len(remaining) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		return 0, nil
	}
	var contents []byte
	for _, item := range remaining {
		record, err := encodeRecord(recordHeader{ID: item.batch.ID, SourceID: item.batch.SourceID, CreatedAt: item.batch.CreatedAt.UTC(), Priority: item.batch.Priority, Checksum: item.batch.Checksum, Class: item.class, Sequence: item.sequence, Cursor: clonePersistedCursor(item.cursor)}, item.batch.Payload)
		if err != nil {
			return 0, err
		}
		contents = append(contents, record...)
	}
	if err := atomicReplace(path, contents); err != nil {
		return 0, err
	}
	return int64(len(contents)), nil
}

func atomicReplace(path string, contents []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rewrite-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// Rename cannot replace an existing file on Windows. Keep the old,
		// fsynced segment as a recovery backup until the new file is in place.
		// Open restores a lone backup after an interrupted replacement.
		backup := path + ".previous"
		if _, err := os.Lstat(backup); err == nil {
			return fmt.Errorf("stale segment replacement backup: %s", backup)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(path, backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(tmpPath, path); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
		if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDirectory(filepath.Dir(path))
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

// restoreReplacementBackups completes or rolls back an interrupted Windows
// replacement before the normal segment scanner sees any data. A backup is
// removed only if the replacement destination exists; otherwise it is the
// last durable copy and is restored.
func restoreReplacementBackups(directory string) error {
	backups, err := filepath.Glob(filepath.Join(directory, "*.previous"))
	if err != nil {
		return err
	}
	for _, backup := range backups {
		target := strings.TrimSuffix(backup, ".previous")
		if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(backup, target); err != nil {
				return err
			}
			continue
		} else if err != nil {
			return err
		}
		if err := os.Remove(backup); err != nil {
			return err
		}
	}
	return syncDirectory(directory)
}

func (s *Store) usedBytes() int64 {
	var total int64
	for _, values := range s.entries {
		for _, item := range values {
			total += item.bytes
		}
	}
	return total
}
func (s *Store) find(class DataClass, id string) *entry {
	for index := range s.entries[class] {
		if s.entries[class][index].batch.ID == id {
			return &s.entries[class][index]
		}
	}
	return nil
}
func (s *Store) remove(class DataClass, id string) {
	values := s.entries[class]
	for index := range values {
		if values[index].batch.ID == id {
			s.entries[class] = append(values[:index], values[index+1:]...)
			return
		}
	}
}
func validClass(class DataClass) bool {
	return class == Log || class == AuditLog || class == Metric || class == JobResult
}

func encodeRecord(header recordHeader, payload []byte) ([]byte, error) {
	if len(payload) > int(^uint32(0)) {
		return nil, fmt.Errorf("payload too large")
	}
	headerBytes, err := json.Marshal(header)
	if err != nil || len(headerBytes) > maxHeaderBytes {
		return nil, fmt.Errorf("invalid segment header: %w", err)
	}
	const prefix = 4 + 1 + 4 + 8
	result := make([]byte, prefix+len(headerBytes)+len(payload)+4)
	copy(result[:4], recordMagic[:])
	result[4] = recordVersion
	binary.BigEndian.PutUint32(result[5:9], uint32(len(headerBytes)))
	binary.BigEndian.PutUint64(result[9:17], uint64(len(payload)))
	copy(result[17:], headerBytes)
	copy(result[17+len(headerBytes):], payload)
	binary.BigEndian.PutUint32(result[len(result)-4:], crc32.Checksum(result[:len(result)-4], crcTable))
	return result, nil
}

var errCorruptRecord = errors.New("corrupt segment record")

func recoverFile(path string) ([]entry, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	var items []entry
	for offset := 0; offset < len(contents); {
		start := offset
		if len(contents)-offset < 17 {
			return items, file.Truncate(int64(start))
		}
		if string(contents[offset:offset+4]) != string(recordMagic[:]) || contents[offset+4] != recordVersion {
			return nil, errCorruptRecord
		}
		headerLength := int(binary.BigEndian.Uint32(contents[offset+5 : offset+9]))
		payloadLength := binary.BigEndian.Uint64(contents[offset+9 : offset+17])
		if headerLength < 0 || headerLength > maxHeaderBytes || payloadLength > uint64(len(contents)) {
			return nil, errCorruptRecord
		}
		total := 17 + headerLength + int(payloadLength) + 4
		if total < 0 || len(contents)-offset < total {
			return items, file.Truncate(int64(start))
		}
		bodyEnd := offset + total - 4
		if crc32.Checksum(contents[offset:bodyEnd], crcTable) != binary.BigEndian.Uint32(contents[bodyEnd:offset+total]) {
			return nil, errCorruptRecord
		}
		var header recordHeader
		if err := json.Unmarshal(contents[offset+17:offset+17+headerLength], &header); err != nil || !validClass(header.Class) || header.ID == "" || header.SourceID == "" || header.Sequence == 0 || header.Cursor != nil && !validPersistedCursorReceipt(header.Cursor) {
			return nil, errCorruptRecord
		}
		payload := append([]byte(nil), contents[offset+17+headerLength:bodyEnd]...)
		items = append(items, entry{batch: Batch{ID: header.ID, SourceID: header.SourceID, CreatedAt: header.CreatedAt, Priority: header.Priority, Payload: payload, Checksum: header.Checksum}, class: header.Class, sequence: header.Sequence, bytes: int64(total), cursor: clonePersistedCursor(header.Cursor)})
		offset += total
	}
	return items, nil
}

func (s *Store) quarantineFile(path string) error {
	name := filepath.Base(path)
	target := filepath.Join(s.quarantine, name)
	if _, err := os.Stat(target); err == nil {
		target = filepath.Join(s.quarantine, strings.TrimSuffix(name, ".seg")+"-"+strconv.FormatInt(time.Now().UnixNano(), 10)+".seg")
	}
	return os.Rename(path, target)
}

func dedupKey(class DataClass, id string) []byte { return []byte(string(class) + "\x00" + id) }
func sequenceKey(sequence uint64) []byte         { return []byte(fmt.Sprintf("%020d", sequence)) }

func validCursorReceipt(value CursorReceipt) bool {
	wantKey := value.AssignmentID + "\x00" + strconv.FormatUint(value.ConfigurationRevision, 10) + "\x00" + value.TemplateID + "\x00" + value.InstanceID
	return value.Key == wantKey && len(value.Key) <= 1024 && !strings.ContainsAny(value.Key, "\r\n") && value.AssignmentID != "" && value.ConfigurationRevision > 0 && value.TemplateID != "" && value.InstanceID != "" && value.Sequence > 0 && len(value.Digest) == sha256.Size && !value.CollectedAt.IsZero()
}

func validPersistedCursorReceipt(value *persistedCursorReceipt) bool {
	if value == nil {
		return false
	}
	if value.Version == 0 {
		parts := strings.Split(value.Key, "\x00")
		if len(parts) != 4 {
			return false
		}
		revision, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil || revision == 0 {
			return false
		}
		value.Version, value.AssignmentID, value.ConfigurationRevision, value.TemplateID, value.InstanceID, value.ACKPending = 1, parts[0], revision, parts[2], parts[3], true
	}
	return value.Version == 1 && validCursorReceipt(publicCursorReceipt(value))
}

func clonePersistedCursor(value *persistedCursorReceipt) *persistedCursorReceipt {
	if value == nil {
		return nil
	}
	return &persistedCursorReceipt{Version: value.Version, Key: value.Key, AssignmentID: value.AssignmentID, ConfigurationRevision: value.ConfigurationRevision, TemplateID: value.TemplateID, InstanceID: value.InstanceID, Sequence: value.Sequence, Digest: append([]byte(nil), value.Digest...), CollectedAt: value.CollectedAt.UTC(), ACKPending: value.ACKPending}
}

func publicCursorReceipt(value *persistedCursorReceipt) CursorReceipt {
	if value == nil {
		return CursorReceipt{}
	}
	return CursorReceipt{Key: value.Key, AssignmentID: value.AssignmentID, ConfigurationRevision: value.ConfigurationRevision, TemplateID: value.TemplateID, InstanceID: value.InstanceID, Sequence: value.Sequence, Digest: append([]byte(nil), value.Digest...), CollectedAt: value.CollectedAt.UTC(), ACKPending: value.ACKPending}
}

func loadCursorReceipt(db *bolt.DB, key string) (*persistedCursorReceipt, error) {
	var result *persistedCursorReceipt
	err := db.View(func(tx *bolt.Tx) error {
		var err error
		result, err = loadCursorReceiptTx(tx, key)
		return err
	})
	return result, err
}

func loadCursorReceiptTx(tx *bolt.Tx, key string) (*persistedCursorReceipt, error) {
	encoded := tx.Bucket(bucketCursorReceipt).Get([]byte(key))
	if encoded == nil {
		return nil, nil
	}
	var result persistedCursorReceipt
	if json.Unmarshal(encoded, &result) != nil || !validPersistedCursorReceipt(&result) {
		return nil, ErrCursorConflict
	}
	return clonePersistedCursor(&result), nil
}
func syncDirectory(path string) error {
	// Windows does not allow Sync on directory handles. Rename itself is the
	// atomic durability boundary there; Linux gets the directory fsync needed
	// to persist the rename across a crash.
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
