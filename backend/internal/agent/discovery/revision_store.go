package discovery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type RevisionStore interface {
	Next(context.Context) (uint64, error)
}

type memoryRevisionStore struct{ revision uint64 }

func (store *memoryRevisionStore) Next(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store.revision++
	if store.revision == 0 {
		return 0, errors.New("discovery revision exhausted")
	}
	return store.revision, nil
}

// FileRevisionStore uses two durable slots so a torn write leaves the previous
// monotonic revision available after restart.
type FileRevisionStore struct {
	mu       sync.Mutex
	path     string
	revision uint64
}

func NewFileRevisionStore(path string) (*FileRevisionStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("discovery revision path must be absolute and clean")
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() {
		return nil, errors.New("discovery revision parent is unavailable")
	}
	store := &FileRevisionStore{path: path}
	validSlots := 0
	var invalidSlot error
	for _, suffix := range []string{".a", ".b"} {
		value, exists, err := readRevision(path + suffix)
		if err != nil {
			invalidSlot = err
			continue
		}
		if exists {
			validSlots++
			if value > store.revision {
				store.revision = value
			}
		}
	}
	if validSlots == 0 && invalidSlot != nil {
		return nil, invalidSlot
	}
	return store, nil
}

func (store *FileRevisionStore) Next(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	next := store.revision + 1
	if next == 0 {
		return 0, errors.New("discovery revision exhausted")
	}
	suffix := ".a"
	if next%2 == 0 {
		suffix = ".b"
	}
	handle, err := os.OpenFile(store.path+suffix, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, err
	}
	_, writeErr := fmt.Fprintf(handle, "%d\n", next)
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if writeErr != nil {
		return 0, writeErr
	}
	if syncErr != nil {
		return 0, syncErr
	}
	if closeErr != nil {
		return 0, closeErr
	}
	store.revision = next
	return next, nil
}

func readRevision(path string) (uint64, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 32 {
		return 0, false, errors.New("discovery revision state is invalid")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return 0, false, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil || value == 0 {
		return 0, false, errors.New("discovery revision state is invalid")
	}
	return value, true, nil
}
