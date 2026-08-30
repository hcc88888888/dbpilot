package discovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type AcceptedRuleState struct {
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}

type RuleStateStore struct {
	mu    sync.Mutex
	path  string
	state AcceptedRuleState
}

func NewRuleStateStore(path string) (*RuleStateStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("rule state path must be absolute and clean")
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		return nil, errors.New("rule state parent is unavailable")
	}
	store := &RuleStateStore{path: path}
	valid := 0
	var invalid error
	for _, suffix := range []string{".a", ".b"} {
		state, exists, err := readRuleState(path + suffix)
		if err != nil {
			invalid = err
			continue
		}
		if exists {
			valid++
			if state.Revision > store.state.Revision {
				store.state = state
			}
		}
	}
	if valid == 0 && invalid != nil {
		return nil, invalid
	}
	return store, nil
}

func (store *RuleStateStore) Accept(ctx context.Context, revision uint64, digest [sha256.Size]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if revision == 0 {
		return errors.New("rule revision is required")
	}
	encodedDigest := hex.EncodeToString(digest[:])
	store.mu.Lock()
	defer store.mu.Unlock()
	if revision < store.state.Revision {
		return errors.New("discovery rule revision rollback")
	}
	if revision == store.state.Revision {
		if store.state.Digest != encodedDigest {
			return errors.New("discovery rule digest conflict")
		}
		return nil
	}
	state := AcceptedRuleState{Revision: revision, Digest: encodedDigest}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	suffix := ".a"
	if revision%2 == 0 {
		suffix = ".b"
	}
	handle, err := os.OpenFile(store.path+suffix, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := handle.Write(encoded)
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	store.state = state
	return nil
}

func readRuleState(path string) (AcceptedRuleState, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return AcceptedRuleState{}, false, nil
	}
	if err != nil {
		return AcceptedRuleState{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 256 {
		return AcceptedRuleState{}, false, errors.New("rule state is invalid")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return AcceptedRuleState{}, false, err
	}
	var state AcceptedRuleState
	if json.Unmarshal(body, &state) != nil || state.Revision == 0 || len(state.Digest) != sha256.Size*2 {
		return AcceptedRuleState{}, false, errors.New("rule state is invalid")
	}
	if _, err := hex.DecodeString(state.Digest); err != nil {
		return AcceptedRuleState{}, false, errors.New("rule state is invalid")
	}
	return state, true, nil
}
