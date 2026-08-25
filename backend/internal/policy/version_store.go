package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// VersionStore records the latest applied version for each agent. The
// interface permits a future durable backend (for example bbolt) to replace
// the JSON implementation without changing policy verification.
type VersionStore interface {
	CheckAndRecord(agentID string, version uint64) error
	Close() error
}

type jsonVersionStore struct {
	mu       sync.Mutex
	path     string
	versions map[string]uint64
}

func OpenVersionStore(filename string) (VersionStore, error) {
	store := &jsonVersionStore{path: filename, versions: make(map[string]uint64)}
	bytes, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: read: %v", ErrVersionStore, err)
	}
	if err := json.Unmarshal(bytes, &store.versions); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrVersionStore, err)
	}
	return store, nil
}

func (s *jsonVersionStore) CheckAndRecord(agentID string, version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, existed := s.versions[agentID]
	if existed && version <= previous {
		return ErrPolicyVersionRollback
	}
	s.versions[agentID] = version
	if err := s.persist(); err != nil {
		if existed {
			s.versions[agentID] = previous
		} else {
			delete(s.versions, agentID)
		}
		return err
	}
	return nil
}

func (s *jsonVersionStore) Close() error { return nil }

func (s *jsonVersionStore) persist() error {
	bytes, err := json.Marshal(s.versions)
	if err != nil {
		return fmt.Errorf("%w: encode: %v", ErrVersionStore, err)
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("%w: create directory: %v", ErrVersionStore, err)
	}
	temporary, err := os.CreateTemp(directory, ".policy-versions-*")
	if err != nil {
		return fmt.Errorf("%w: create temporary file: %v", ErrVersionStore, err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err := temporary.Write(bytes); err != nil {
		temporary.Close()
		return fmt.Errorf("%w: write: %v", ErrVersionStore, err)
	}
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("%w: chmod: %v", ErrVersionStore, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: close: %v", ErrVersionStore, err)
	}
	if err := os.Rename(temporaryName, s.path); err != nil {
		return fmt.Errorf("%w: replace: %v", ErrVersionStore, err)
	}
	return nil
}
