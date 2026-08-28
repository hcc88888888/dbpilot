package commandjournal

import (
	"context"
	"crypto/sha256"
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

func TestJournalAcceptDeduplicatesCommandIDDurably(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 123).UTC()
	envelope := journalEnvelope("command-a", now.Add(time.Hour))
	journal, err := Open(path)
	require.NoError(t, err)

	accepted, err := journal.Accept(context.Background(), envelope)
	require.NoError(t, err)
	require.True(t, accepted)
	accepted, err = journal.Accept(context.Background(), envelope)
	require.NoError(t, err)
	require.False(t, accepted)
	require.NoError(t, journal.Close())

	reopened, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	accepted, err = reopened.Accept(context.Background(), envelope)
	require.NoError(t, err)
	require.False(t, accepted)
	entry, err := reopened.Get(context.Background(), "command-a")
	require.NoError(t, err)
	require.Equal(t, StateAccepted, entry.State)
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
	accepted, err := journal.Accept(context.Background(), original)
	require.NoError(t, err)
	require.True(t, accepted)

	collision := proto.Clone(original).(*agentv1.CommandEnvelope)
	collision.JobId = "different-job"
	accepted, err = journal.Accept(context.Background(), collision)
	require.False(t, accepted)
	require.ErrorIs(t, err, ErrCommandIDConflict)
	accepted, err = journal.Accept(context.Background(), original)
	require.NoError(t, err)
	require.False(t, accepted, "exact envelope replay remains a duplicate")
}

func TestJournalPersistsNonceReservationAcrossRestartAndReclaimsExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 0).UTC()
	journal, err := Open(path)
	require.NoError(t, err)
	journal.now = func() time.Time { return now }
	first := journalEnvelope("command-a", now.Add(time.Hour))
	first.Nonce = []byte("shared-nonce")
	accepted, err := journal.Accept(context.Background(), first)
	require.NoError(t, err)
	require.True(t, accepted)
	require.NoError(t, journal.Close())

	reopened, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	reopened.now = func() time.Time { return now }
	exactReplay := proto.Clone(first).(*agentv1.CommandEnvelope)
	accepted, err = reopened.Accept(context.Background(), exactReplay)
	require.NoError(t, err)
	require.False(t, accepted)
	reusedNonce := journalEnvelope("command-b", now.Add(time.Hour))
	reusedNonce.Nonce = []byte("shared-nonce")
	accepted, err = reopened.Accept(context.Background(), reusedNonce)
	require.False(t, accepted)
	require.ErrorIs(t, err, ErrNonceReplay)

	reopened.now = func() time.Time { return now.Add(2 * time.Hour) }
	afterExpiry := journalEnvelope("command-c", now.Add(3*time.Hour))
	afterExpiry.Nonce = []byte("shared-nonce")
	accepted, err = reopened.Accept(context.Background(), afterExpiry)
	require.NoError(t, err)
	require.True(t, accepted, "expired nonce reservation may be reclaimed")
}

func TestJournalActiveReturnsOnlyAcceptedAndRunningCommands(t *testing.T) {
	journal, err := Open(filepath.Join(t.TempDir(), "commands.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	now := time.Unix(1_725_000_000, 0).UTC()
	for _, id := range []string{"accepted", "running", "completed"} {
		accepted, acceptErr := journal.Accept(context.Background(), journalEnvelope(id, now.Add(time.Hour)))
		require.NoError(t, acceptErr)
		require.True(t, accepted)
	}
	require.NoError(t, journal.Start(context.Background(), "running", now.Add(time.Minute)))
	require.NoError(t, journal.Start(context.Background(), "completed", now.Add(time.Minute)))
	require.NoError(t, journal.Complete(context.Background(), "completed", &agentv1.CommandResult{CommandId: "completed", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "done"}, now.Add(2*time.Minute)))

	active, err := journal.Active(context.Background())
	require.NoError(t, err)
	require.Len(t, active, 2)
	require.Equal(t, "accepted", active[0].CommandID)
	require.Equal(t, StateAccepted, active[0].State)
	require.Equal(t, "running", active[1].CommandID)
	require.Equal(t, StateRunning, active[1].State)
}

func TestJournalCompletedResultSurvivesCloseAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.db")
	now := time.Unix(1_725_000_000, 0).UTC()
	journal, err := Open(path)
	require.NoError(t, err)
	accepted, err := journal.Accept(context.Background(), journalEnvelope("command-a", now.Add(time.Hour)))
	require.NoError(t, err)
	require.True(t, accepted)
	require.NoError(t, journal.Start(context.Background(), "command-a", now.Add(time.Minute)))
	wantResult := &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "collected"}
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
	accepted, err := journal.Accept(context.Background(), journalEnvelope("command-a", now.Add(time.Hour)))
	require.NoError(t, err)
	require.True(t, accepted)
	require.NoError(t, journal.Start(context.Background(), "command-a", now.Add(time.Minute)))
	result := &agentv1.CommandResult{CommandId: "command-a", State: agentv1.CommandResultState_COMMAND_RESULT_STATE_SUCCEEDED, Summary: "done"}
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
	require.NoError(t, reopened.MarkReported(context.Background(), "command-a", reportedAt))
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
	accepted, err := journal.Accept(context.Background(), journalEnvelope("command-a", expiresAt))
	require.NoError(t, err)
	require.True(t, accepted)

	err = journal.Start(context.Background(), "command-a", expiresAt)

	require.ErrorIs(t, err, ErrCommandExpired)
	entry, getErr := journal.Get(context.Background(), "command-a")
	require.NoError(t, getErr)
	require.Equal(t, StateAccepted, entry.State)
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
