package plugingateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var errCursor = errors.New("PLUGIN_CURSOR_REJECTED")

// cursorKey intentionally excludes payload data. A plugin sequence is scoped
// to the exact assignment configuration, template and database instance.
type cursorKey struct {
	AssignmentID          string
	ConfigurationRevision uint64
	TemplateID            string
	InstanceID            string
}

func (key cursorKey) valid() bool {
	return identifier(key.AssignmentID) && key.ConfigurationRevision > 0 && identifier(key.TemplateID) && identifier(key.InstanceID)
}

func (key cursorKey) fileName() string {
	value := sha256.Sum256([]byte(key.AssignmentID + "\x00" + stringRevision(key.ConfigurationRevision) + "\x00" + key.TemplateID + "\x00" + key.InstanceID))
	return hex.EncodeToString(value[:]) + ".json"
}

func stringRevision(value uint64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	result := make([]byte, 0, 20)
	for value > 0 {
		result = append(result, digits[value%10])
		value /= 10
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return string(result)
}

type cursorState struct {
	Sequence    uint64
	Digest      []byte
	CollectedAt time.Time
}

type persistedCursor struct {
	Sequence    uint64 `json:"sequence"`
	Digest      string `json:"digest"`
	CollectedAt string `json:"collected_at"`
}

// CursorStore keeps cursors below the Agent-owned state root. Its locks are
// keyed by the same logical batch identity and are held across validation,
// spool append and cursor fsync by Session.appendBatch.
type CursorStore struct {
	root  string
	mu    sync.Mutex
	locks map[cursorKey]*sync.Mutex
}

func NewCursorStore(root string) (*CursorStore, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errCursor
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, errCursor
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, errCursor
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errCursor
	}
	if err := restoreCursorBackups(root); err != nil {
		return nil, errCursor
	}
	return &CursorStore{root: root, locks: make(map[cursorKey]*sync.Mutex)}, nil
}

func (store *CursorStore) Lock(key cursorKey) func() {
	store.mu.Lock()
	lock := store.locks[key]
	if lock == nil {
		lock = &sync.Mutex{}
		store.locks[key] = lock
	}
	store.mu.Unlock()
	lock.Lock()
	return lock.Unlock
}

func (store *CursorStore) Load(key cursorKey) (cursorState, error) {
	if store == nil || !key.valid() {
		return cursorState{}, errCursor
	}
	path := filepath.Join(store.root, key.fileName())
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cursorState{}, nil
	}
	if err != nil {
		return cursorState{}, errCursor
	}
	var persisted persistedCursor
	if json.Unmarshal(contents, &persisted) != nil || persisted.Sequence == 0 {
		return cursorState{}, errCursor
	}
	digest, err := hex.DecodeString(persisted.Digest)
	if err != nil || len(digest) != sha256.Size {
		return cursorState{}, errCursor
	}
	collectedAt, err := time.Parse(time.RFC3339Nano, persisted.CollectedAt)
	if err != nil || collectedAt.IsZero() {
		return cursorState{}, errCursor
	}
	return cursorState{Sequence: persisted.Sequence, Digest: digest, CollectedAt: collectedAt.UTC()}, nil
}

func (store *CursorStore) Commit(key cursorKey, sequence uint64, digest []byte, collectedAt time.Time) error {
	if store == nil || !key.valid() || sequence == 0 || len(digest) != sha256.Size || collectedAt.IsZero() {
		return errCursor
	}
	current, err := store.Load(key)
	if err != nil {
		return err
	}
	if sequence < current.Sequence || (sequence == current.Sequence && !equalBytes(digest, current.Digest)) {
		return errCursor
	}
	if sequence == current.Sequence {
		return nil
	}
	contents, err := json.Marshal(persistedCursor{Sequence: sequence, Digest: hex.EncodeToString(digest), CollectedAt: collectedAt.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return errCursor
	}
	temporary, err := os.CreateTemp(store.root, ".cursor-*")
	if err != nil {
		return errCursor
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if temporary.Chmod(0o600) != nil || writeAndSync(temporary, contents) != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return errCursor
	}
	path := filepath.Join(store.root, key.fileName())
	if runtime.GOOS == "windows" {
		backup := path + ".previous"
		if _, err := os.Lstat(backup); err == nil {
			return errCursor
		} else if !errors.Is(err, os.ErrNotExist) {
			return errCursor
		}
		if err := os.Rename(path, backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errCursor
		}
		if err := os.Rename(temporaryPath, path); err != nil {
			return errCursor
		}
		if err := syncCursorDirectory(store.root); err != nil {
			return errCursor
		}
		if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errCursor
		}
		return syncCursorDirectory(store.root)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errCursor
	}
	return syncCursorDirectory(store.root)
}

func writeAndSync(file *os.File, contents []byte) error {
	if _, err := file.Write(contents); err != nil {
		return err
	}
	return file.Sync()
}

func syncCursorDirectory(path string) error {
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

func restoreCursorBackups(root string) error {
	backups, err := filepath.Glob(filepath.Join(root, "*.json.previous"))
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
	return syncCursorDirectory(root)
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var value byte
	for index := range left {
		value |= left[index] ^ right[index]
	}
	return value == 0
}
