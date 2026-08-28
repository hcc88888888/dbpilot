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

// DispatchRepository is the explicitly privileged, cross-scope persistence
// boundary used only by the internal command dispatcher. ClaimOutbox may claim
// work globally, but every returned message carries its immutable Scope and all
// subsequent mutations must present that exact scope.
type DispatchRepository interface {
	ClaimOutbox(context.Context, int, time.Time) ([]OutboxMessage, error)
	LookupCommand(context.Context, string) (OutboxMessage, error)
	PrepareCommandEnvelope(context.Context, platformscope.Scope, string, []byte) ([]byte, error)
	ClaimPendingCancellations(context.Context, int, time.Time) ([]OutboxMessage, error)
	DeferCancellation(context.Context, platformscope.Scope, string, time.Time) error
	AcknowledgeCommand(context.Context, platformscope.Scope, string, CommandStatus, time.Time, *time.Time) error
	RenewCommandLease(context.Context, platformscope.Scope, string, time.Time, time.Time) error
	ClaimExpiredCommands(context.Context, int, time.Time) ([]OutboxMessage, error)
	MarkCommandTerminal(context.Context, platformscope.Scope, string, CommandStatus, time.Time) error
	PendingCancellationsForAgent(context.Context, string, int) ([]OutboxMessage, error)
}
