package spool

import (
	"context"
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
	ID        string    `json:"id"`
	SourceID  string    `json:"source_id"`
	CreatedAt time.Time `json:"created_at"`
	Priority  int       `json:"priority"`
	Checksum  uint32    `json:"checksum"`
	Class     DataClass `json:"class"`
	Sequence  uint64    `json:"sequence"`
}

type entry struct {
	batch    Batch
	class    DataClass
	sequence uint64
	file     string
	bytes    int64
}

// Append durably adds a batch. A repeated (class, ID) is a no-op so retries
// cannot duplicate telemetry.
func (s *Store) Append(ctx context.Context, class DataClass, batch Batch) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validClass(class) || batch.ID == "" || batch.SourceID == "" {
		return fmt.Errorf("invalid spool batch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return errors.New("spool closed")
	}
	if s.find(class, batch.ID) != nil {
		return nil
	}
	sequence := s.nextSeq + 1
	encoded, err := encodeRecord(recordHeader{ID: batch.ID, SourceID: batch.SourceID, CreatedAt: batch.CreatedAt.UTC(), Priority: batch.Priority, Checksum: batch.Checksum, Class: class, Sequence: sequence}, batch.Payload)
	if err != nil {
		return err
	}
	if err := s.makeCapacity(class, int64(len(encoded))); err != nil {
		return err
	}
	fileName := fmt.Sprintf("%020d.seg", sequence)
	path := filepath.Join(s.segments, fileName)
	tmp, err := os.CreateTemp(s.segments, ".active-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(encoded); err != nil {
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
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if err := syncDirectory(s.segments); err != nil {
		return err
	}
	stored := batch
	stored.Payload = append([]byte(nil), batch.Payload...)
	stored.CreatedAt = stored.CreatedAt.UTC()
	item := entry{batch: stored, class: class, sequence: sequence, file: fileName, bytes: int64(len(encoded))}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketSegmentIndex).Put(sequenceKey(sequence), []byte(fileName)); err != nil {
			return err
		}
		return tx.Bucket(bucketDedup).Put(dedupKey(class, batch.ID), sequenceKey(sequence))
	}); err != nil {
		_ = os.Remove(path)
		return err
	}
	s.entries[class] = append(s.entries[class], item)
	s.nextSeq = sequence
	return nil
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

// Ack is idempotent. Since segments are single-batch sealed files, a
// successful acknowledgement removes the complete segment atomically.
func (s *Store) Ack(ctx context.Context, class DataClass, batchID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validClass(class) || batchID == "" {
		return fmt.Errorf("invalid acknowledgement")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.find(class, batchID)
	if item == nil {
		return nil
	}
	if err := os.Remove(filepath.Join(s.segments, item.file)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketSegmentIndex).Delete(sequenceKey(item.sequence)); err != nil {
			return err
		}
		return tx.Bucket(bucketDedup).Delete(dedupKey(class, batchID))
	}); err != nil {
		return err
	}
	s.remove(class, batchID)
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
				if class == Metric {
					return choices[i].sequence < choices[j].sequence
				}
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
	if err := os.Remove(filepath.Join(s.segments, item.file)); err != nil && !errors.Is(err, os.ErrNotExist) {
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
	return nil
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
		if err := json.Unmarshal(contents[offset+17:offset+17+headerLength], &header); err != nil || !validClass(header.Class) || header.ID == "" || header.SourceID == "" || header.Sequence == 0 {
			return nil, errCorruptRecord
		}
		payload := append([]byte(nil), contents[offset+17+headerLength:bodyEnd]...)
		items = append(items, entry{batch: Batch{ID: header.ID, SourceID: header.SourceID, CreatedAt: header.CreatedAt, Priority: header.Priority, Payload: payload, Checksum: header.Checksum}, class: header.Class, sequence: header.Sequence, bytes: int64(total)})
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
