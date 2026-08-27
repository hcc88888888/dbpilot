package audit

import (
	"errors"
	"time"

	"dbpilot.local/platform/internal/platformscope"
)

var (
	ErrInvalidEvent    = errors.New("invalid audit event")
	ErrSensitiveDetail = errors.New("audit detail contains sensitive material")
	ErrImmutableID     = errors.New("audit event ID is service assigned and immutable")
	ErrInvalidCursor   = errors.New("audit cursor does not belong to scope")
)

type Actor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type Resource struct {
	Type string `json:"resource_type"`
	ID   string `json:"resource_id"`
}

type Event struct {
	ID         string              `json:"id"`
	Scope      platformscope.Scope `json:"scope"`
	OccurredAt time.Time           `json:"occurred_at"`
	Action     string              `json:"action"`
	Actor      Actor               `json:"actor"`
	Resource   Resource            `json:"source_resource"`
	Result     string              `json:"result"`
	RequestID  string              `json:"request_id"`
	TraceID    string              `json:"trace_id,omitempty"`
	JobID      string              `json:"job_id,omitempty"`
	CommandID  string              `json:"command_id,omitempty"`
	Detail     map[string]any      `json:"detail,omitempty"`
	CreatedAt  time.Time           `json:"-"`
}

type ListQuery struct {
	Cursor string
	Limit  int
}

type StoreListQuery struct {
	After   time.Time
	AfterID string
	Limit   int
}

type Page struct {
	Items      []Event `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
}
