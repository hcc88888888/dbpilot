package commandjournal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	agentv1 "dbpilot.local/platform/gen/agent/v1"
	"github.com/stretchr/testify/require"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestOpenRehardensExistingJournalPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX read permission bits")
	}
	path := filepath.Join(t.TempDir(), "commands.db")
	require.NoError(t, os.WriteFile(path, nil, 0o666))
	require.NoError(t, os.Chmod(path, 0o666))
	journal, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, journal.Close())
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestPreparePersistsEnvelopeWithoutAuthorizingExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 0).UTC()
	envelope := journalEnvelope("command-prepare", now.Add(time.Hour))
	journal, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })

	prepared, err := journal.Prepare(context.Background(), envelope, now)
	require.NoError(t, err)
	require.True(t, prepared)
	entry, err := journal.Get(context.Background(), envelope.GetCommandId())
	require.NoError(t, err)
	require.Equal(t, StatePrepared, entry.State)
	require.True(t, proto.Equal(envelope, entry.Envelope))
	require.Empty(t, entry.ExecutionToken)
	require.Zero(t, entry.LeaseRevision)
}

func TestStartAuthorizesMatchingTokenAndRevisionOnce(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	journal, err := Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	prepared, err := journal.Prepare(context.Background(), journalEnvelope("command-start", now.Add(time.Hour)), now)
	require.NoError(t, err)
	require.True(t, prepared)
	token := bytes.Repeat([]byte{0x2a}, sha256.Size)
	journal.now = func() time.Time { return now.Add(time.Minute) }

	require.NoError(t, journal.AuthorizeStart(context.Background(), "command-start", token, 9, now.Add(30*time.Minute)))
	entry, err := journal.Get(context.Background(), "command-start")
	require.NoError(t, err)
	require.Equal(t, StateRunning, entry.State)
	require.Equal(t, token, entry.ExecutionToken)
	require.Equal(t, uint64(9), entry.LeaseRevision)
	require.ErrorIs(t, journal.AuthorizeStart(context.Background(), "command-start", token, 9, now.Add(30*time.Minute)), ErrInvalidTransition)
	require.ErrorIs(t, journal.AuthorizeStart(context.Background(), "command-start", bytes.Repeat([]byte{0x3b}, sha256.Size), 9, now.Add(30*time.Minute)), ErrStartMismatch)
}

func TestStartAuthorizedReopenBecomesInterruptedAndRejectsLaterStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 0).UTC()
	token := bytes.Repeat([]byte{0x3c}, sha256.Size)
	tokenHash := sha256.Sum256(token)
	journal, err := Open(path)
	require.NoError(t, err)
	prepared, err := journal.Prepare(context.Background(), journalEnvelope("command-start-authorized", now.Add(time.Hour)), now)
	require.NoError(t, err)
	require.True(t, prepared)
	require.NoError(t, journal.transition(context.Background(), "command-start-authorized", func(entry *storedEntry) error {
		entry.State = StateStartAuthorized
		entry.ExecutionToken = append([]byte(nil), token...)
		entry.ExecutionTokenHashHex = hex.EncodeToString(tokenHash[:])
		entry.LeaseRevision = 10
		return nil
	}))
	require.NoError(t, journal.Close())

	reopened, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	reopened.now = func() time.Time { return now }
	entry, err := reopened.Get(context.Background(), "command-start-authorized")
	require.NoError(t, err)
	require.Equal(t, StateInterrupted, entry.State)
	pending, err := reopened.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED, pending[0].Result.GetState())
	require.ErrorIs(t, reopened.AuthorizeStart(context.Background(), "command-start-authorized", bytes.Repeat([]byte{0x3d}, sha256.Size), 10, now.Add(time.Minute)), ErrStartMismatch)
	require.ErrorIs(t, reopened.AuthorizeStart(context.Background(), "command-start-authorized", token, 10, now.Add(time.Minute)), ErrInvalidTransition)
	pending, err = reopened.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1, "later Start must not create another interrupted result")
}

func TestStartDeadlineIsCheckedAtJournalTransactionTime(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	deadline := now.Add(time.Minute)
	journal, err := Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	journal.now = func() time.Time { return deadline }
	prepared, err := journal.Prepare(context.Background(), journalEnvelope("command-deadline", now.Add(time.Hour)), now)
	require.NoError(t, err)
	require.True(t, prepared)

	err = journal.AuthorizeStart(context.Background(), "command-deadline", bytes.Repeat([]byte{0x4d}, sha256.Size), 12, deadline)

	require.ErrorIs(t, err, ErrStartDeadlineExceeded)
	entry, getErr := journal.Get(context.Background(), "command-deadline")
	require.NoError(t, getErr)
	require.Equal(t, StatePrepared, entry.State)
}

func TestInterruptedRunningReopenProducesOnePendingResultWithoutReexecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 0).UTC()
	token := bytes.Repeat([]byte{0x4c}, sha256.Size)
	journal, err := Open(path)
	require.NoError(t, err)
	prepared, err := journal.Prepare(context.Background(), journalEnvelope("command-interrupted", now.Add(time.Hour)), now)
	require.NoError(t, err)
	require.True(t, prepared)
	journal.now = func() time.Time { return now.Add(time.Minute) }
	require.NoError(t, journal.AuthorizeStart(context.Background(), "command-interrupted", token, 11, now.Add(30*time.Minute)))
	require.NoError(t, journal.Close())

	reopened, err := Open(path)
	require.NoError(t, err)
	entry, err := reopened.Get(context.Background(), "command-interrupted")
	require.NoError(t, err)
	require.Equal(t, StateInterrupted, entry.State)
	pending, err := reopened.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, agentv1.CommandResultState_COMMAND_RESULT_STATE_INTERRUPTED, pending[0].Result.GetState())
	require.Equal(t, token, pending[0].Result.GetExecutionToken())
	require.Equal(t, uint64(11), pending[0].Result.GetLeaseRevision())
	require.NoError(t, reopened.Close())

	reopenedAgain, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopenedAgain.Close() })
	pending, err = reopenedAgain.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1, "restart recovery must not create duplicate interrupted results")
}

func TestResultAckRequiresMatchingPersistedResultDigest(t *testing.T) {
	now := time.Unix(1_725_000_000, 0).UTC()
	token := bytes.Repeat([]byte{0x5d}, sha256.Size)
	journal, err := Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	prepared, err := journal.Prepare(context.Background(), journalEnvelope("command-result-ack", now.Add(time.Hour)), now)
	require.NoError(t, err)
	require.True(t, prepared)
	journal.now = func() time.Time { return now.Add(time.Minute) }
	require.NoError(t, journal.AuthorizeStart(context.Background(), "command-result-ack", token, 13, now.Add(30*time.Minute)))
	result := &agentv1.CommandResult{
		CommandId: "command-result-ack", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED,
		ExecutionToken: token, LeaseRevision: 13,
	}
	require.NoError(t, journal.Complete(context.Background(), "command-result-ack", result, now.Add(2*time.Minute)))
	entry, err := journal.Get(context.Background(), "command-result-ack")
	require.NoError(t, err)
	wrong := sha256.Sum256([]byte("different result"))
	require.ErrorIs(t, journal.MarkReported(context.Background(), "command-result-ack", wrong, now.Add(3*time.Minute)), ErrResultDigestMismatch)
	pending, err := journal.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.NoError(t, journal.MarkReported(context.Background(), "command-result-ack", entry.ResultDigest, now.Add(4*time.Minute)))
	pending, err = journal.PendingResults(context.Background())
	require.NoError(t, err)
	require.Empty(t, pending)
}

func TestJournalAcceptDeduplicatesCommandIDDurably(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 123).UTC()
	envelope := journalEnvelope("command-a", now.Add(time.Hour))
	journal, err := Open(path)
	require.NoError(t, err)

	accepted, err := journal.Prepare(context.Background(), envelope, now)
	require.NoError(t, err)
	require.True(t, accepted)
	accepted, err = journal.Prepare(context.Background(), envelope, now)
	require.NoError(t, err)
	require.False(t, accepted)
	require.NoError(t, journal.Close())

	reopened, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	accepted, err = reopened.Prepare(context.Background(), envelope, now)
	require.NoError(t, err)
	require.False(t, accepted)
	entry, err := reopened.Get(context.Background(), "command-a")
	require.NoError(t, err)
	require.Equal(t, StatePrepared, entry.State)
	deterministic, err := proto.MarshalOptions{Deterministic: true}.Marshal(envelope)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(deterministic), entry.EnvelopeDigest)
}

func TestJournalRejectsCommandIDCollisionWithDifferentEnvelopeDigest(t *testing.T) {
	journal, err := Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	expiresAt := time.Now().Add(time.Hour)
	original := journalEnvelope("command-a", expiresAt)
	accepted, err := journal.Prepare(context.Background(), original, expiresAt.Add(-time.Hour))
	require.NoError(t, err)
	require.True(t, accepted)

	collision := proto.Clone(original).(*agentv1.CommandEnvelope)
	collision.JobId = "different-job"
	accepted, err = journal.Prepare(context.Background(), collision, expiresAt.Add(-time.Hour))
	require.False(t, accepted)
	require.ErrorIs(t, err, ErrCommandIDConflict)
	accepted, err = journal.Prepare(context.Background(), original, expiresAt.Add(-time.Hour))
	require.NoError(t, err)
	require.False(t, accepted, "exact envelope replay remains a duplicate")
}

func TestJournalPersistsNonceReservationAcrossRestartAndReclaimsExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 0).UTC()
	journal, err := Open(path)
	require.NoError(t, err)
	first := journalEnvelope("command-a", now.Add(time.Hour))
	first.Nonce = []byte("shared-nonce")
	accepted, err := journal.Prepare(context.Background(), first, now)
	require.NoError(t, err)
	require.True(t, accepted)
	require.NoError(t, journal.Close())

	reopened, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	exactReplay := proto.Clone(first).(*agentv1.CommandEnvelope)
	accepted, err = reopened.Prepare(context.Background(), exactReplay, now)
	require.NoError(t, err)
	require.False(t, accepted)
	reusedNonce := journalEnvelope("command-b", now.Add(time.Hour))
	reusedNonce.Nonce = []byte("shared-nonce")
	accepted, err = reopened.Prepare(context.Background(), reusedNonce, now)
	require.False(t, accepted)
	require.ErrorIs(t, err, ErrNonceReplay)

	afterExpiry := journalEnvelope("command-c", now.Add(3*time.Hour))
	afterExpiry.Nonce = []byte("shared-nonce")
	accepted, err = reopened.Prepare(context.Background(), afterExpiry, now.Add(2*time.Hour))
	require.NoError(t, err)
	require.True(t, accepted, "expired nonce reservation may be reclaimed")
}

func TestJournalActiveReturnsOnlyAcceptedAndRunningCommands(t *testing.T) {
	journal, err := Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	now := time.Unix(1_725_000_000, 0).UTC()
	for _, id := range []string{"accepted", "running", "completed"} {
		accepted, acceptErr := journal.Prepare(context.Background(), journalEnvelope(id, now.Add(time.Hour)), now)
		require.NoError(t, acceptErr)
		require.True(t, accepted)
	}
	runningToken := bytes.Repeat([]byte{0x31}, sha256.Size)
	completedToken := bytes.Repeat([]byte{0x32}, sha256.Size)
	journal.now = func() time.Time { return now.Add(time.Minute) }
	require.NoError(t, journal.AuthorizeStart(context.Background(), "running", runningToken, 1, now.Add(30*time.Minute)))
	require.NoError(t, journal.AuthorizeStart(context.Background(), "completed", completedToken, 2, now.Add(30*time.Minute)))
	require.NoError(t, journal.Complete(context.Background(), "completed", &agentv1.CommandResult{CommandId: "completed", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "done", ExecutionToken: completedToken, LeaseRevision: 2}, now.Add(2*time.Minute)))

	active, err := journal.Active(context.Background())
	require.NoError(t, err)
	require.Len(t, active, 2)
	require.Equal(t, "accepted", active[0].CommandID)
	require.Equal(t, StatePrepared, active[0].State)
	require.Equal(t, "running", active[1].CommandID)
	require.Equal(t, StateRunning, active[1].State)
}

func TestJournalCompletedResultSurvivesCloseAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 0).UTC()
	journal, err := Open(path)
	require.NoError(t, err)
	accepted, err := journal.Prepare(context.Background(), journalEnvelope("command-a", now.Add(time.Hour)), now)
	require.NoError(t, err)
	require.True(t, accepted)
	token := bytes.Repeat([]byte{0x33}, sha256.Size)
	journal.now = func() time.Time { return now.Add(time.Minute) }
	require.NoError(t, journal.AuthorizeStart(context.Background(), "command-a", token, 3, now.Add(30*time.Minute)))
	wantResult := &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "collected", ExecutionToken: token, LeaseRevision: 3}
	require.NoError(t, journal.Complete(context.Background(), "command-a", wantResult, now.Add(2*time.Minute)))
	require.NoError(t, journal.Close())

	reopened, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	entry, err := reopened.Get(context.Background(), "command-a")
	require.NoError(t, err)
	require.Equal(t, StateCompleted, entry.State)
	require.Equal(t, now.Add(time.Minute), entry.StartedAt)
	require.Equal(t, now.Add(2*time.Minute), entry.CompletedAt)
	require.True(t, proto.Equal(wantResult, entry.Result))
}

func TestJournalCompletedResultRemainsPendingUntilDurablyMarkedReported(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 0).UTC()
	journal, err := Open(path)
	require.NoError(t, err)
	accepted, err := journal.Prepare(context.Background(), journalEnvelope("command-a", now.Add(time.Hour)), now)
	require.NoError(t, err)
	require.True(t, accepted)
	token := bytes.Repeat([]byte{0x34}, sha256.Size)
	journal.now = func() time.Time { return now.Add(time.Minute) }
	require.NoError(t, journal.AuthorizeStart(context.Background(), "command-a", token, 4, now.Add(30*time.Minute)))
	result := &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "done", ExecutionToken: token, LeaseRevision: 4}
	require.NoError(t, journal.Complete(context.Background(), "command-a", result, now.Add(2*time.Minute)))
	pending, err := journal.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, proto.Equal(result, pending[0].Result))
	require.True(t, pending[0].ReportedAt.IsZero())
	require.NoError(t, journal.Close())

	reopened, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	pending, err = reopened.PendingResults(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 1, "completed but unreported result must survive restart")
	reportedAt := now.Add(3 * time.Minute)
	require.NoError(t, reopened.MarkReported(context.Background(), "command-a", pending[0].ResultDigest, reportedAt))
	pending, err = reopened.PendingResults(context.Background())
	require.NoError(t, err)
	require.Empty(t, pending)
	entry, err := reopened.Get(context.Background(), "command-a")
	require.NoError(t, err)
	require.Equal(t, reportedAt, entry.ReportedAt)
}

func TestJournalRejectsStartingExpiredCommand(t *testing.T) {
	journal, err := Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	expiresAt := time.Unix(1_725_000_000, 0).UTC()
	accepted, err := journal.Prepare(context.Background(), journalEnvelope("command-a", expiresAt), expiresAt.Add(-time.Hour))
	require.NoError(t, err)
	require.True(t, accepted)

	journal.now = func() time.Time { return expiresAt }
	err = journal.AuthorizeStart(context.Background(), "command-a", bytes.Repeat([]byte{0x35}, sha256.Size), 5, expiresAt.Add(time.Minute))

	require.ErrorIs(t, err, ErrCommandExpired)
	entry, getErr := journal.Get(context.Background(), "command-a")
	require.NoError(t, getErr)
	require.Equal(t, StatePrepared, entry.State)
}

func TestJournalCreatesExplicitCommandsAndMetaBuckets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	journal, err := Open(path)
	require.NoError(t, err)
	require.NoError(t, journal.Close())

	database, err := bbolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	require.NoError(t, database.View(func(transaction *bbolt.Tx) error {
		require.NotNil(t, transaction.Bucket([]byte("commands")))
		require.NotNil(t, transaction.Bucket([]byte("meta")))
		return nil
	}))
}

func journalEnvelope(commandID string, expiresAt time.Time) *agentv1.CommandEnvelope {
	return &agentv1.CommandEnvelope{
		CommandId: commandID, JobId: "job-" + commandID, AgentId: "agent-a", Nonce: []byte("nonce-" + commandID),
		IssuedAt: timestamppb.New(expiresAt.Add(-time.Hour)), ExpiresAt: timestamppb.New(expiresAt),
		Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{CollectionKinds: []string{"host"}}},
	}
}
