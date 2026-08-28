package inspection

import (
	"context"
	"errors"
	"time"

	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/platformscope"
)

var (
	ErrInvalid   = errors.New("invalid inspection value")
	ErrNotFound  = errors.New("inspection value not found")
	ErrConflict  = errors.New("inspection version conflict")
	ErrDuplicate = errors.New("inspection request already exists")
)

type Schedule struct {
	Cron     string `json:"cron"`
	Timezone string `json:"timezone"`
}

type PolicyItem struct {
	ItemID  string `json:"item_id"`
	Version int    `json:"version"`
}

type TargetSelector struct {
	AgentIDs []string          `json:"agent_ids,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type PolicyClaim struct {
	Token          string
	Occurrence     time.Time
	LeaseExpiresAt time.Time
}

type Policy struct {
	Scope          platformscope.Scope `json:"scope"`
	ID             string              `json:"id"`
	Name           string              `json:"name"`
	Enabled        bool                `json:"enabled"`
	Version        int64               `json:"version"`
	Schedule       *Schedule           `json:"schedule,omitempty"`
	NextRunAt      *time.Time          `json:"next_run_at,omitempty"`
	Items          []PolicyItem        `json:"item_versions"`
	Selector       TargetSelector      `json:"selector"`
	TargetTimeout  time.Duration       `json:"target_timeout"`
	MaxConcurrency int                 `json:"max_concurrency"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
	Claim          *PolicyClaim        `json:"-"`
}

type RunTrigger string

const (
	RunTriggerManual    RunTrigger = "manual"
	RunTriggerScheduled RunTrigger = "scheduled"
	RunTriggerRetry     RunTrigger = "retry"
)

type Run struct {
	Scope                platformscope.Scope `json:"scope"`
	ID                   string              `json:"id"`
	PolicyID             string              `json:"policy_id,omitempty"`
	PolicyVersion        int64               `json:"policy_version,omitempty"`
	RetryOfRunID         string              `json:"retry_of_run_id,omitempty"`
	JobID                string              `json:"job_id"`
	Status               RunStatus           `json:"status"`
	Trigger              RunTrigger          `json:"trigger"`
	OccurrenceKey        string              `json:"occurrence_key,omitempty"`
	ScheduledFor         *time.Time          `json:"scheduled_for,omitempty"`
	PolicySnapshot       *Policy             `json:"policy_snapshot,omitempty"`
	ItemSnapshot         []Item              `json:"item_snapshot"`
	TargetCount          int                 `json:"target_count"`
	CompletedTargetCount int                 `json:"completed_target_count"`
	FailedTargetCount    int                 `json:"failed_target_count"`
	ReportID             string              `json:"report_id,omitempty"`
	AuditCorrelation     string              `json:"audit_correlation"`
	IdempotencyKey       string              `json:"-"`
	InitiatedBy          string              `json:"initiated_by"`
	RequestID            string              `json:"request_id"`
	TraceID              string              `json:"trace_id,omitempty"`
	StartedAt            *time.Time          `json:"started_at,omitempty"`
	FinishedAt           *time.Time          `json:"finished_at,omitempty"`
	CreatedAt            time.Time           `json:"created_at"`
}

type ReportStatus string

const (
	ReportGenerating ReportStatus = "generating"
	ReportCompleted  ReportStatus = "completed"
	ReportFailed     ReportStatus = "failed"
)

type ReportSnapshot struct {
	Scope       platformscope.Scope     `json:"scope"`
	ID          string                  `json:"id"`
	RunID       string                  `json:"run_id"`
	PolicyID    string                  `json:"policy_id,omitempty"`
	Status      ReportStatus            `json:"status"`
	Summary     string                  `json:"summary"`
	Snapshot    []byte                  `json:"snapshot"`
	Artifacts   []job.ArtifactReference `json:"artifacts"`
	GeneratedAt time.Time               `json:"generated_at"`
}

type CursorFilter struct {
	Before   time.Time
	BeforeID string
	Limit    int
}

type ItemFilter struct {
	CursorFilter
	Versions []PolicyItem
}
type PolicyFilter struct{ CursorFilter }
type RunFilter struct{ CursorFilter }
type ReportFilter struct{ CursorFilter }

type ItemPage struct {
	Items []Item
	More  bool
}

type PolicyPage struct {
	Items []Policy
	More  bool
}

type RunPage struct {
	Items []Run
	More  bool
}

type ReportPage struct {
	Items []ReportSnapshot
	More  bool
}

type RunDetail struct {
	Run      Run
	Targets  []TargetRun
	Findings []Finding
}

type Repository interface {
	CreateItem(context.Context, Item) error
	ListItems(context.Context, platformscope.Scope, ItemFilter) (ItemPage, error)
	CreatePolicy(context.Context, Policy) error
	ListPolicies(context.Context, platformscope.Scope, PolicyFilter) (PolicyPage, error)
	GetPolicy(context.Context, platformscope.Scope, string) (Policy, error)
	UpdatePolicy(context.Context, Policy, int64) (Policy, error)
	ClaimDuePolicies(context.Context, time.Time, int, time.Duration) ([]Policy, error)
	CreateRunWithJob(context.Context, Run, []TargetRun, job.Job, []job.OutboxMessage) error
	CreateClaimedRunWithJob(context.Context, Policy, Run, []TargetRun, job.Job, []job.OutboxMessage) (Run, error)
	GetRun(context.Context, platformscope.Scope, string) (RunDetail, error)
	GetRunByIdempotencyKey(context.Context, platformscope.Scope, string) (Run, error)
	ListRuns(context.Context, platformscope.Scope, RunFilter) (RunPage, error)
	GetReport(context.Context, platformscope.Scope, string) (ReportSnapshot, error)
	ListReports(context.Context, platformscope.Scope, ReportFilter) (ReportPage, error)
}
