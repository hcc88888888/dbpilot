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
	RequestCancel(context.Context, platformscope.Scope, string, string, time.Time) (Job, error)
	ClaimOutbox(context.Context, int, time.Time) ([]OutboxMessage, error)
	MarkOutboxPublished(context.Context, string, time.Time) error
}
