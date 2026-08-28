package commandjournal

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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

	ErrInvalidEnvelope       = errors.New("command envelope is invalid")
	ErrCommandNotFound       = errors.New("command journal entry was not found")
	ErrCommandExpired        = errors.New("command has expired")
	ErrInvalidTransition     = errors.New("invalid command journal state transition")
	ErrCommandIDConflict     = errors.New("command ID is already bound to a different envelope")
	ErrNonceReplay           = errors.New("command nonce is already reserved by a different envelope")
	ErrStartMismatch         = errors.New("command start fence does not match the journal entry")
	ErrAlreadyRunning        = errors.New("command is already running with this execution fence")
	ErrStartConflict         = errors.New("command is running with a different execution fence")
	ErrStartDeadlineExceeded = errors.New("command start deadline has expired")
	ErrResultDigestMismatch  = errors.New("command result acknowledgement digest does not match")
)

type State string

const (
	StatePrepared        State = "prepared"
	StateStartAuthorized State = "start_authorized"
	StateRunning         State = "running"
	StateInterrupted     State = "interrupted"
	StateCompleted       State = "completed"
	StateCancelled       State = "cancelled"
)

// Entry is the recovery-safe view of one journaled command.
type Entry struct {
	CommandID          string
	State              State
	Envelope           *agentv1.CommandEnvelope
	EnvelopeDigest     [sha256.Size]byte
	ExpiresAt          time.Time
	PreparedAt         time.Time
	StartedAt          time.Time
	InterruptedAt      time.Time
	CompletedAt        time.Time
	ReportedAt         time.Time
	ExecutionToken     []byte
	ExecutionTokenHash [sha256.Size]byte
	LeaseRevision      uint64
	Result             *agentv1.CommandResult
	ResultDigest       [sha256.Size]byte
}

// Journal is the persistence boundary consumed by the Agent control client.
type Journal interface {
	Prepare(context.Context, *agentv1.CommandEnvelope, time.Time) (bool, error)
	AuthorizeStart(context.Context, string, []byte, uint64, time.Time) error
	CancelPrepared(context.Context, string, time.Time) error
	MarkInterrupted(context.Context, string, time.Time) error
	Complete(context.Context, string, *agentv1.CommandResult, time.Time) error
	Active(context.Context) ([]Entry, error)
	PendingResults(context.Context) ([]Entry, error)
	MarkReported(context.Context, string, [sha256.Size]byte, time.Time) error
	Get(context.Context, string) (Entry, error)
}

type storedEntry struct {
	CommandID                   string `json:"command_id"`
	State                       State  `json:"state"`
	Envelope                    []byte `json:"envelope"`
	EnvelopeDigestHex           string `json:"envelope_digest"`
	ExpiresAtUnixNano           int64  `json:"expires_at_unix_nano"`
	PreparedAtUnixNano          int64  `json:"prepared_at_unix_nano"`
	StartedAtUnixNano           int64  `json:"started_at_unix_nano,omitempty"`
	InterruptedAtUnixNano       int64  `json:"interrupted_at_unix_nano,omitempty"`
	CompletedAtUnixNano         int64  `json:"completed_at_unix_nano,omitempty"`
	ReportedAtUnixNano          int64  `json:"reported_at_unix_nano,omitempty"`
	ExecutionToken              []byte `json:"execution_token,omitempty"`
	ExecutionTokenHashHex       string `json:"execution_token_hash,omitempty"`
	LeaseRevision               uint64 `json:"lease_revision,omitempty"`
	Result                      []byte `json:"result,omitempty"`
	ResultDigestHex             string `json:"result_digest,omitempty"`
	AcknowledgedResultDigestHex string `json:"acknowledged_result_digest,omitempty"`
}

type nonceReservation struct {
	CommandID         string `json:"command_id"`
	EnvelopeDigestHex string `json:"envelope_digest"`
	ExpiresAtUnixNano int64  `json:"expires_at_unix_nano"`
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
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("harden existing command journal permissions: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect command journal: %w", err)
	}
	database, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open command journal: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("harden command journal permissions: %w", err)
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
	if err := journal.recoverRunning(time.Now().UTC()); err != nil {
		_ = database.Close()
		return nil, err
	}
	if err := database.Sync(); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("sync command journal buckets: %w", err)
	}
	return journal, nil
}

func (j *BoltJournal) Prepare(ctx context.Context, envelope *agentv1.CommandEnvelope, at time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if envelope == nil || strings.TrimSpace(envelope.GetCommandId()) == "" || envelope.GetCommand() == nil || len(envelope.GetNonce()) == 0 || envelope.GetExpiresAt() == nil || !envelope.GetExpiresAt().IsValid() || at.IsZero() {
		return false, ErrInvalidEnvelope
	}
	encodedEnvelope, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	if err != nil {
		return false, fmt.Errorf("marshal command envelope: %w", err)
	}
	digest := sha256.Sum256(encodedEnvelope)
	entry := storedEntry{
		CommandID: envelope.GetCommandId(), State: StatePrepared, Envelope: encodedEnvelope,
		EnvelopeDigestHex: hex.EncodeToString(digest[:]), ExpiresAtUnixNano: envelope.GetExpiresAt().AsTime().UTC().UnixNano(),
		PreparedAtUnixNano: at.UTC().UnixNano(),
	}
	encodedEntry, err := json.Marshal(entry)
	if err != nil {
		return false, fmt.Errorf("marshal command journal entry: %w", err)
	}
	reservation := nonceReservation{CommandID: entry.CommandID, EnvelopeDigestHex: entry.EnvelopeDigestHex, ExpiresAtUnixNano: entry.ExpiresAtUnixNano}
	encodedReservation, err := json.Marshal(reservation)
	if err != nil {
		return false, fmt.Errorf("marshal command nonce reservation: %w", err)
	}
	nonceDigest := sha256.Sum256(envelope.GetNonce())
	nonceKey := append([]byte("nonce:"), []byte(hex.EncodeToString(nonceDigest[:]))...)
	inserted := false
	err = j.database.Update(func(transaction *bbolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		bucket := transaction.Bucket(commandsBucket)
		key := []byte(envelope.GetCommandId())
		if existing := bucket.Get(key); existing != nil {
			stored, err := decodeStoredEntry(existing)
			if err != nil {
				return err
			}
			if stored.EnvelopeDigestHex == entry.EnvelopeDigestHex {
				return nil
			}
			return ErrCommandIDConflict
		}
		meta := transaction.Bucket(metaBucket)
		if encoded := meta.Get(nonceKey); encoded != nil {
			var existing nonceReservation
			if err := json.Unmarshal(encoded, &existing); err != nil {
				return fmt.Errorf("decode command nonce reservation: %w", err)
			}
			if time.Unix(0, existing.ExpiresAtUnixNano).After(at.UTC()) && (existing.CommandID != reservation.CommandID || existing.EnvelopeDigestHex != reservation.EnvelopeDigestHex) {
				return ErrNonceReplay
			}
		}
		if err := bucket.Put(key, encodedEntry); err != nil {
			return err
		}
		if err := meta.Put(nonceKey, encodedReservation); err != nil {
			return err
		}
		inserted = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("prepare command: %w", err)
	}
	if !inserted {
		return false, nil
	}
	if err := j.database.Sync(); err != nil {
		return false, fmt.Errorf("sync prepared command: %w", err)
	}
	return true, nil
}

func (j *BoltJournal) AuthorizeStart(ctx context.Context, commandID string, executionToken []byte, leaseRevision uint64, startDeadline time.Time) error {
	if len(executionToken) != sha256.Size || leaseRevision == 0 || startDeadline.IsZero() {
		return ErrStartMismatch
	}
	if err := j.transition(ctx, commandID, func(entry *storedEntry) error {
		now := j.now().UTC()
		switch entry.State {
		case StateRunning:
			if matchesFence(entry, executionToken, leaseRevision) {
				return ErrAlreadyRunning
			}
			return ErrStartConflict
		case StatePrepared:
			if !now.Before(startDeadline.UTC()) {
				return ErrStartDeadlineExceeded
			}
			if !now.Before(time.Unix(0, entry.ExpiresAtUnixNano)) {
				return ErrCommandExpired
			}
			tokenHash := sha256.Sum256(executionToken)
			entry.State = StateStartAuthorized
			entry.ExecutionToken = append([]byte(nil), executionToken...)
			entry.ExecutionTokenHashHex = hex.EncodeToString(tokenHash[:])
			entry.LeaseRevision = leaseRevision
			return nil
		case StateStartAuthorized:
			if !matchesFence(entry, executionToken, leaseRevision) {
				return ErrStartConflict
			}
			if !now.Before(startDeadline.UTC()) {
				return ErrStartDeadlineExceeded
			}
			if !now.Before(time.Unix(0, entry.ExpiresAtUnixNano)) {
				return ErrCommandExpired
			}
			return nil
		default:
			if !matchesFence(entry, executionToken, leaseRevision) {
				return ErrStartMismatch
			}
			return fmt.Errorf("%w: %s to running", ErrInvalidTransition, entry.State)
		}
	}); err != nil {
		return err
	}
	return j.transition(ctx, commandID, func(entry *storedEntry) error {
		now := j.now().UTC()
		switch entry.State {
		case StateRunning:
			if matchesFence(entry, executionToken, leaseRevision) {
				return ErrAlreadyRunning
			}
			return ErrStartConflict
		case StateStartAuthorized:
			if !matchesFence(entry, executionToken, leaseRevision) {
				return ErrStartConflict
			}
			if !now.Before(startDeadline.UTC()) {
				return ErrStartDeadlineExceeded
			}
		default:
			if !matchesFence(entry, executionToken, leaseRevision) {
				return ErrStartMismatch
			}
			return fmt.Errorf("%w: %s to running", ErrInvalidTransition, entry.State)
		}
		entry.State = StateRunning
		entry.StartedAtUnixNano = now.UnixNano()
		return nil
	})
}

func (j *BoltJournal) CancelPrepared(ctx context.Context, commandID string, at time.Time) error {
	return j.transition(ctx, commandID, func(entry *storedEntry) error {
		if entry.State == StateCancelled {
			return nil
		}
		if entry.State != StatePrepared {
			return fmt.Errorf("%w: %s to cancelled", ErrInvalidTransition, entry.State)
		}
		entry.State = StateCancelled
		entry.CompletedAtUnixNano = at.UTC().UnixNano()
		entry.Envelope = nil
		return nil
	})
}

func (j *BoltJournal) MarkInterrupted(ctx context.Context, commandID string, at time.Time) error {
	return j.transition(ctx, commandID, func(entry *storedEntry) error {
		if entry.State == StateInterrupted {
			return nil
		}
		if (entry.State != StateRunning && entry.State != StateStartAuthorized) || !validStoredFence(entry) {
			return fmt.Errorf("%w: %s to interrupted", ErrInvalidTransition, entry.State)
		}
		return setInterrupted(entry, at)
	})
}

func (j *BoltJournal) Complete(ctx context.Context, commandID string, result *agentv1.CommandResult, at time.Time) error {
	if result == nil || result.GetCommandId() != commandID || len(result.GetExecutionToken()) != sha256.Size || result.GetLeaseRevision() == 0 {
		return errors.New("command result must match the journal command and execution fence")
	}
	encodedResult, resultDigest, err := encodeResult(result)
	if err != nil {
		return err
	}
	return j.transition(ctx, commandID, func(entry *storedEntry) error {
		if entry.State != StateRunning {
			return fmt.Errorf("%w: %s to completed", ErrInvalidTransition, entry.State)
		}
		if !matchesFence(entry, result.GetExecutionToken(), result.GetLeaseRevision()) {
			return ErrStartMismatch
		}
		entry.State = StateCompleted
		entry.CompletedAtUnixNano = at.UTC().UnixNano()
		entry.Result = encodedResult
		entry.ResultDigestHex = hex.EncodeToString(resultDigest[:])
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

func (j *BoltJournal) recoverRunning(at time.Time) error {
	changed := false
	err := j.database.Update(func(transaction *bbolt.Tx) error {
		bucket := transaction.Bucket(commandsBucket)
		return bucket.ForEach(func(key, encoded []byte) error {
			entry, err := decodeStoredEntry(encoded)
			if err != nil {
				return err
			}
			if entry.State != StateRunning && entry.State != StateStartAuthorized {
				return nil
			}
			if !validStoredFence(&entry) {
				return errors.New("running command journal entry has an invalid execution fence")
			}
			if err := setInterrupted(&entry, at); err != nil {
				return err
			}
			updated, err := json.Marshal(entry)
			if err != nil {
				return err
			}
			changed = true
			return bucket.Put(key, updated)
		})
	})
	if err != nil {
		return fmt.Errorf("recover interrupted commands: %w", err)
	}
	if changed {
		if err := j.database.Sync(); err != nil {
			return fmt.Errorf("sync interrupted command recovery: %w", err)
		}
	}
	return nil
}

func (j *BoltJournal) Active(ctx context.Context) ([]Entry, error) {
	return j.list(ctx, "list active commands", func(entry storedEntry) bool {
		return entry.State == StatePrepared || entry.State == StateStartAuthorized || entry.State == StateRunning
	})
}

func (j *BoltJournal) PendingResults(ctx context.Context) ([]Entry, error) {
	return j.list(ctx, "list pending command results", func(entry storedEntry) bool {
		return (entry.State == StateCompleted || entry.State == StateInterrupted) && entry.ReportedAtUnixNano == 0 && len(entry.Result) > 0
	})
}

func (j *BoltJournal) list(ctx context.Context, operation string, include func(storedEntry) bool) ([]Entry, error) {
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
			if !include(stored) {
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
		return nil, fmt.Errorf("%s: %w", operation, err)
	}
	return entries, nil
}

func (j *BoltJournal) MarkReported(ctx context.Context, commandID string, resultDigest [sha256.Size]byte, at time.Time) error {
	return j.transition(ctx, commandID, func(entry *storedEntry) error {
		if (entry.State != StateCompleted && entry.State != StateInterrupted) || len(entry.Result) == 0 {
			return fmt.Errorf("%w: %s to reported", ErrInvalidTransition, entry.State)
		}
		storedDigest, err := decodeDigest(entry.ResultDigestHex, "result")
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(storedDigest[:], resultDigest[:]) != 1 {
			return ErrResultDigestMismatch
		}
		if entry.ReportedAtUnixNano == 0 {
			entry.ReportedAtUnixNano = at.UTC().UnixNano()
			entry.AcknowledgedResultDigestHex = hex.EncodeToString(resultDigest[:])
		}
		return nil
	})
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
	envelopeDigest, err := decodeDigest(stored.EnvelopeDigestHex, "envelope")
	if err != nil {
		return Entry{}, err
	}
	entry := Entry{
		CommandID: stored.CommandID, State: stored.State, EnvelopeDigest: envelopeDigest,
		ExpiresAt: time.Unix(0, stored.ExpiresAtUnixNano).UTC(), PreparedAt: unixNanoTime(stored.PreparedAtUnixNano),
		StartedAt: unixNanoTime(stored.StartedAtUnixNano), InterruptedAt: unixNanoTime(stored.InterruptedAtUnixNano),
		CompletedAt: unixNanoTime(stored.CompletedAtUnixNano), ReportedAt: unixNanoTime(stored.ReportedAtUnixNano),
		ExecutionToken: append([]byte(nil), stored.ExecutionToken...), LeaseRevision: stored.LeaseRevision,
	}
	if len(stored.Envelope) > 0 {
		entry.Envelope = &agentv1.CommandEnvelope{}
		if err := proto.Unmarshal(stored.Envelope, entry.Envelope); err != nil {
			return Entry{}, fmt.Errorf("decode command journal envelope: %w", err)
		}
	}
	if stored.ExecutionTokenHashHex != "" {
		entry.ExecutionTokenHash, err = decodeDigest(stored.ExecutionTokenHashHex, "execution token")
		if err != nil {
			return Entry{}, err
		}
	}
	if len(stored.Result) > 0 {
		entry.Result = &agentv1.CommandResult{}
		if err := proto.Unmarshal(stored.Result, entry.Result); err != nil {
			return Entry{}, fmt.Errorf("decode command journal result: %w", err)
		}
		entry.ResultDigest, err = decodeDigest(stored.ResultDigestHex, "result")
		if err != nil {
			return Entry{}, err
		}
	}
	return entry, nil
}

func encodeResult(result *agentv1.CommandResult) ([]byte, [sha256.Size]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(result)
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("marshal command result: %w", err)
	}
	return encoded, sha256.Sum256(encoded), nil
}

func setInterrupted(entry *storedEntry, at time.Time) error {
	result := &agentv1.CommandResult{
		CommandId: entry.CommandID, State: agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED,
		Summary: "command execution was interrupted before a terminal result", ErrorCode: "EXECUTION_INTERRUPTED",
		ExecutionToken: append([]byte(nil), entry.ExecutionToken...), LeaseRevision: entry.LeaseRevision,
	}
	encodedResult, resultDigest, err := encodeResult(result)
	if err != nil {
		return err
	}
	entry.State = StateInterrupted
	entry.InterruptedAtUnixNano = at.UTC().UnixNano()
	entry.CompletedAtUnixNano = at.UTC().UnixNano()
	entry.Result = encodedResult
	entry.ResultDigestHex = hex.EncodeToString(resultDigest[:])
	return nil
}

func matchesFence(entry *storedEntry, executionToken []byte, leaseRevision uint64) bool {
	return len(entry.ExecutionToken) == sha256.Size && len(executionToken) == sha256.Size && subtle.ConstantTimeCompare(entry.ExecutionToken, executionToken) == 1 && entry.LeaseRevision == leaseRevision
}

func validStoredFence(entry *storedEntry) bool {
	if len(entry.ExecutionToken) != sha256.Size || entry.LeaseRevision == 0 {
		return false
	}
	tokenHash := sha256.Sum256(entry.ExecutionToken)
	return entry.ExecutionTokenHashHex == hex.EncodeToString(tokenHash[:])
}

func decodeDigest(encoded, kind string) ([sha256.Size]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size {
		return [sha256.Size]byte{}, fmt.Errorf("command journal %s digest is invalid", kind)
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return digest, nil
}

func unixNanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

var _ Journal = (*BoltJournal)(nil)
