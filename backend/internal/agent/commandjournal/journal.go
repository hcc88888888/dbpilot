package commandjournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

var (
	commandsBucket = []byte("commands")
	metaBucket     = []byte("meta")

	ErrInvalidEnvelope   = errors.New("command envelope is invalid")
	ErrCommandNotFound   = errors.New("command journal entry was not found")
	ErrCommandExpired    = errors.New("command has expired")
	ErrInvalidTransition = errors.New("invalid command journal state transition")
)

type State string

const (
	StateAccepted  State = "accepted"
	StateRunning   State = "running"
	StateCompleted State = "completed"
)

// Entry is the recovery-safe view of one journaled command.
type Entry struct {
	CommandID      string
	State          State
	EnvelopeDigest [sha256.Size]byte
	ExpiresAt      time.Time
	AcceptedAt     time.Time
	StartedAt      time.Time
	CompletedAt    time.Time
	Result         *agentv1.CommandResult
}

// Journal is the persistence boundary consumed by the Agent control client.
type Journal interface {
	Accept(context.Context, *agentv1.CommandEnvelope) (bool, error)
	Start(context.Context, string, time.Time) error
	Complete(context.Context, string, *agentv1.CommandResult, time.Time) error
	Active(context.Context) ([]Entry, error)
}

type storedEntry struct {
	CommandID           string `json:"command_id"`
	State               State  `json:"state"`
	EnvelopeDigestHex   string `json:"envelope_digest"`
	ExpiresAtUnixNano   int64  `json:"expires_at_unix_nano"`
	AcceptedAtUnixNano  int64  `json:"accepted_at_unix_nano"`
	StartedAtUnixNano   int64  `json:"started_at_unix_nano,omitempty"`
	CompletedAtUnixNano int64  `json:"completed_at_unix_nano,omitempty"`
	Result              []byte `json:"result,omitempty"`
}

type BoltJournal struct {
	database  *bbolt.DB
	now       func() time.Time
	closeOnce sync.Once
	closeErr  error
}

func Open(path string) (*BoltJournal, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("command journal path is required")
	}
	database, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open command journal: %w", err)
	}
	journal := &BoltJournal{database: database, now: time.Now}
	if err := database.Update(func(transaction *bbolt.Tx) error {
		if _, err := transaction.CreateBucketIfNotExists(commandsBucket); err != nil {
			return err
		}
		_, err := transaction.CreateBucketIfNotExists(metaBucket)
		return err
	}); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("initialize command journal: %w", err)
	}
	if err := database.Sync(); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("sync command journal buckets: %w", err)
	}
	return journal, nil
}

func (j *BoltJournal) Accept(ctx context.Context, envelope *agentv1.CommandEnvelope) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if envelope == nil || strings.TrimSpace(envelope.GetCommandId()) == "" || envelope.GetCommand() == nil || envelope.GetExpiresAt() == nil || !envelope.GetExpiresAt().IsValid() {
		return false, ErrInvalidEnvelope
	}
	encodedEnvelope, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return false, fmt.Errorf("marshal command envelope: %w", err)
	}
	digest := sha256.Sum256(encodedEnvelope)
	entry := storedEntry{
		CommandID: envelope.GetCommandId(), State: StateAccepted, EnvelopeDigestHex: hex.EncodeToString(digest[:]),
		ExpiresAtUnixNano: envelope.GetExpiresAt().AsTime().UTC().UnixNano(), AcceptedAtUnixNano: j.now().UTC().UnixNano(),
	}
	encodedEntry, err := json.Marshal(entry)
	if err != nil {
		return false, fmt.Errorf("marshal command journal entry: %w", err)
	}
	inserted := false
	err = j.database.Update(func(transaction *bbolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket := transaction.Bucket(commandsBucket)
		key := []byte(envelope.GetCommandId())
		if bucket.Get(key) != nil {
			return nil
		}
		if err := bucket.Put(key, encodedEntry); err != nil {
			return err
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("accept command: %w", err)
	}
	if !inserted {
		return false, nil
	}
	if err := j.database.Sync(); err != nil {
		return false, fmt.Errorf("sync accepted command: %w", err)
	}
	return true, nil
}

func (j *BoltJournal) Start(ctx context.Context, commandID string, at time.Time) error {
	return j.transition(ctx, commandID, func(entry *storedEntry) error {
		if entry.State != StateAccepted {
			return fmt.Errorf("%w: %s to running", ErrInvalidTransition, entry.State)
		}
		if !at.Before(time.Unix(0, entry.ExpiresAtUnixNano)) {
			return ErrCommandExpired
		}
		entry.State = StateRunning
		entry.StartedAtUnixNano = at.UTC().UnixNano()
		return nil
	})
}

func (j *BoltJournal) Complete(ctx context.Context, commandID string, result *agentv1.CommandResult, at time.Time) error {
	if result == nil || result.GetCommandId() != commandID {
		return errors.New("command result must match the journal command ID")
	}
	encodedResult, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal command result: %w", err)
	}
	return j.transition(ctx, commandID, func(entry *storedEntry) error {
		if entry.State != StateRunning && entry.State != StateAccepted {
			return fmt.Errorf("%w: %s to completed", ErrInvalidTransition, entry.State)
		}
		entry.State = StateCompleted
		entry.CompletedAtUnixNano = at.UTC().UnixNano()
		entry.Result = encodedResult
		return nil
	})
}

func (j *BoltJournal) transition(ctx context.Context, commandID string, update func(*storedEntry) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(commandID) == "" {
		return ErrCommandNotFound
	}
	err := j.database.Update(func(transaction *bbolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket := transaction.Bucket(commandsBucket)
		encoded := bucket.Get([]byte(commandID))
		if encoded == nil {
			return ErrCommandNotFound
		}
		entry, err := decodeStoredEntry(encoded)
		if err != nil {
			return err
		}
		if err := update(&entry); err != nil {
			return err
		}
		updated, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(commandID), updated)
	})
	if err != nil {
		return err
	}
	if err := j.database.Sync(); err != nil {
		return fmt.Errorf("sync command journal transition: %w", err)
	}
	return nil
}

func (j *BoltJournal) Active(ctx context.Context) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries := make([]Entry, 0)
	err := j.database.View(func(transaction *bbolt.Tx) error {
		return transaction.Bucket(commandsBucket).ForEach(func(_, encoded []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			stored, err := decodeStoredEntry(encoded)
			if err != nil {
				return err
			}
			if stored.State != StateAccepted && stored.State != StateRunning {
				return nil
			}
			entry, err := publicEntry(stored)
			if err != nil {
				return err
			}
			entries = append(entries, entry)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("list active commands: %w", err)
	}
	return entries, nil
}

func (j *BoltJournal) Get(ctx context.Context, commandID string) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	var result Entry
	err := j.database.View(func(transaction *bbolt.Tx) error {
		encoded := transaction.Bucket(commandsBucket).Get([]byte(commandID))
		if encoded == nil {
			return ErrCommandNotFound
		}
		stored, err := decodeStoredEntry(encoded)
		if err != nil {
			return err
		}
		result, err = publicEntry(stored)
		return err
	})
	return result, err
}

func (j *BoltJournal) Close() error {
	j.closeOnce.Do(func() { j.closeErr = j.database.Close() })
	return j.closeErr
}

func decodeStoredEntry(encoded []byte) (storedEntry, error) {
	var entry storedEntry
	if err := json.Unmarshal(encoded, &entry); err != nil {
		return storedEntry{}, fmt.Errorf("decode command journal entry: %w", err)
	}
	return entry, nil
}

func publicEntry(stored storedEntry) (Entry, error) {
	digestBytes, err := hex.DecodeString(stored.EnvelopeDigestHex)
	if err != nil || len(digestBytes) != sha256.Size {
		return Entry{}, errors.New("command journal envelope digest is invalid")
	}
	entry := Entry{
		CommandID: stored.CommandID, State: stored.State, ExpiresAt: time.Unix(0, stored.ExpiresAtUnixNano).UTC(),
		AcceptedAt: time.Unix(0, stored.AcceptedAtUnixNano).UTC(), StartedAt: unixNanoTime(stored.StartedAtUnixNano), CompletedAt: unixNanoTime(stored.CompletedAtUnixNano),
	}
	copy(entry.EnvelopeDigest[:], digestBytes)
	if len(stored.Result) > 0 {
		entry.Result = &agentv1.CommandResult{}
		if err := proto.Unmarshal(stored.Result, entry.Result); err != nil {
			return Entry{}, fmt.Errorf("decode command journal result: %w", err)
		}
	}
	return entry, nil
}

func unixNanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

var _ Journal = (*BoltJournal)(nil)
