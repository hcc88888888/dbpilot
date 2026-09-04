package job

import (
	"context"
	"database/sql"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

type Repository interface {
	CreateWithOutbox(context.Context, Job, []OutboxMessage) error
	CreateInTx(context.Context, *sql.Tx, Job, []OutboxMessage) error
	Get(context.Context, platformscope.Scope, string) (Job, error)
	Transition(context.Context, Transition) (Job, error)
	RequestCancel(context.Context, platformscope.Scope, string, string, int64, time.Time) (Job, error)
}

// CancellationSnapshotRepository is the HTTP-specific transactional boundary
// used to repair a cancellation whose idempotency row was left processing.
type CancellationSnapshotRepository interface {
	RequestCancelWithSnapshot(context.Context, platformscope.Scope, string, string, int64, time.Time, CancellationSnapshotInput) (Job, error)
	GetCancellationSnapshot(context.Context, platformscope.Scope, string, CancellationSnapshotKey) (CancellationSnapshot, error)
	FindCancellationSnapshot(context.Context, platformscope.Scope, string, CancellationSnapshotCorrelation) (CancellationSnapshot, error)
}

// DispatchRepository is the explicitly privileged, cross-scope persistence
// boundary used only by the internal command dispatcher. ClaimOutbox may claim
// work globally, but every returned message carries its immutable Scope and all
// subsequent mutations must present that exact scope.
type DispatchRepository interface {
	ClaimOutbox(context.Context, int, time.Time) ([]OutboxMessage, error)
	ReservePrepareSlot(context.Context, platformscope.Scope, string, time.Time) (bool, error)
	LookupCommand(context.Context, string) (OutboxMessage, error)
	PrepareCommandEnvelope(context.Context, platformscope.Scope, string, []byte) ([]byte, error)
	ClaimPreparedCommands(context.Context, int, time.Time) ([]OutboxMessage, error)
	PreparedCommandsForAgent(context.Context, string, int) ([]OutboxMessage, error)
	MarkPrepared(context.Context, platformscope.Scope, string, [32]byte, time.Time) error
	AuthorizeStart(context.Context, platformscope.Scope, string, [32]byte, [32]byte, []byte, time.Time, time.Time) (StartGrant, error)
	MarkStartEnqueued(context.Context, platformscope.Scope, string, uint64, time.Time) error
	RenewExecutionLease(context.Context, platformscope.Scope, string, [32]byte, uint64, time.Time, time.Time) (uint64, error)
	ClaimExpiredExecution(context.Context, int, time.Time) ([]RecoveryClaim, error)
	FinalizeExpiredExecution(context.Context, RecoveryClaim, time.Time) error
	FinalizeExpiredPrepared(context.Context, platformscope.Scope, string, [32]byte, time.Time, time.Time) error
	ClaimPendingTerminalAudits(context.Context, int, time.Time) ([]OutboxMessage, error)
	PendingTerminalAuditsForAgent(context.Context, string, int) ([]OutboxMessage, error)
	MarkTerminalAuditRecorded(context.Context, platformscope.Scope, string, string, time.Time) error
	PersistTerminalResult(context.Context, TerminalResultCAS) (TerminalResultOutcome, error)
	CorrectValidationTerminalStatus(context.Context, platformscope.Scope, string, [32]byte, CommandStatus, CommandStatus, time.Time) error
	ClaimPendingCancellations(context.Context, int, time.Time) ([]OutboxMessage, error)
	DeferCancellation(context.Context, platformscope.Scope, string, time.Time) error
	AcknowledgeCommand(context.Context, platformscope.Scope, string, CommandStatus, time.Time, *time.Time) error
	RenewCommandLease(context.Context, platformscope.Scope, string, time.Time, time.Time) error
	ClaimExpiredCommands(context.Context, int, time.Time) ([]OutboxMessage, error)
	MarkCommandTerminal(context.Context, platformscope.Scope, string, CommandStatus, time.Time) error
	PendingCancellationsForAgent(context.Context, string, int) ([]OutboxMessage, error)
}
