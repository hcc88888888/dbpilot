package controlplane

import (
	"context"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/capability"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/monitoring"
	"dbpilot.local/platform/internal/platformscope"
)

type JobService interface {
	Get(context.Context, platformscope.Scope, string) (job.Job, error)
	Transition(context.Context, job.Transition) (job.Job, error)
}

type ArtifactService interface {
	Get(context.Context, platformscope.Scope, string) (artifact.Artifact, error)
	CreateDownload(context.Context, platformscope.Scope, string, time.Duration) (artifact.Download, error)
}

type AuditService interface {
	List(context.Context, platformscope.Scope, audit.ListQuery) (audit.Page, error)
}

type CapabilityService interface {
	Resolve(capability.Input) []capability.Capability
}

type IdempotencyService interface {
	Begin(context.Context, idempotency.Key, string) (idempotency.Claim, error)
	Complete(context.Context, idempotency.Key, string, idempotency.Response) (idempotency.Response, error)
	Abort(context.Context, idempotency.Key, string) error
}

// Services contains the dependencies made available to HTTP handlers.
// Monitoring deliberately uses its storage-neutral QueryStore boundary.
type Services struct {
	Repository   alert.ControlPlaneRepository
	Evaluator    EvaluatorHealthReader
	Monitoring   monitoring.QueryStore
	Jobs         JobService
	Artifacts    ArtifactService
	Audit        AuditService
	Capabilities CapabilityService
	Idempotency  IdempotencyService
	// CapabilityInput supplies deployment/database/Agent facts. The handler
	// always derives the permission intersection from the authenticated
	// principal and never trusts this callback for user authorization.
	CapabilityInput func(context.Context, platformscope.Scope) capability.Input
	// MonitoringResponseBytes caps complete monitoring HTTP envelopes for every
	// QueryStore implementation. Zero uses monitoring's conservative default.
	MonitoringResponseBytes int
	Now                     func() time.Time
	Ready                   func(context.Context) error
}
