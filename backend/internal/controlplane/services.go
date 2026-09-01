package controlplane

import (
	"context"
	"net/http"
	"time"

	"dbpilot.local/platform/internal/alert"
	"dbpilot.local/platform/internal/artifact"
	"dbpilot.local/platform/internal/audit"
	"dbpilot.local/platform/internal/capability"
	"dbpilot.local/platform/internal/databaseinstance"
	"dbpilot.local/platform/internal/discovery"
	"dbpilot.local/platform/internal/enrollment"
	"dbpilot.local/platform/internal/hostinventory"
	"dbpilot.local/platform/internal/idempotency"
	"dbpilot.local/platform/internal/inspection"
	"dbpilot.local/platform/internal/job"
	"dbpilot.local/platform/internal/metrictemplate"
	"dbpilot.local/platform/internal/monitoring"
	"dbpilot.local/platform/internal/platformscope"
	"dbpilot.local/platform/internal/pluginassignment"
	"dbpilot.local/platform/internal/plugincatalog"
)

type JobService interface {
	Get(context.Context, platformscope.Scope, string) (job.Job, error)
	RequestCancelWithSnapshot(context.Context, platformscope.Scope, string, string, int64, time.Time, job.CancellationSnapshotInput) (job.Job, error)
	GetCancellationSnapshot(context.Context, platformscope.Scope, string, job.CancellationSnapshotKey) (job.CancellationSnapshot, error)
	FindCancellationSnapshot(context.Context, platformscope.Scope, string, job.CancellationSnapshotCorrelation) (job.CancellationSnapshot, error)
}

type ArtifactService interface {
	Get(context.Context, platformscope.Scope, string) (artifact.Artifact, error)
	CreateDownloadAt(context.Context, platformscope.Scope, string, time.Time, time.Duration) (artifact.Download, error)
}

type AuditService interface {
	List(context.Context, platformscope.Scope, audit.ListQuery) (audit.Page, error)
	RecordOnce(context.Context, audit.Event) (audit.Event, error)
}

type CapabilityService interface {
	Resolve(capability.Input) []capability.Capability
}

type IdempotencyService interface {
	Begin(context.Context, idempotency.Key, string, idempotency.ReconcileFunc) (idempotency.Claim, error)
	BeginRecoverable(context.Context, idempotency.Key, string, []byte, idempotency.ReconcileFunc, idempotency.RecoverProcessingFunc) (idempotency.Claim, error)
	BeginUnreturnedRecoverable(context.Context, idempotency.Key, string, []byte, idempotency.ReconcileFunc, idempotency.RecoverProcessingFunc) (idempotency.Claim, error)
	Complete(context.Context, idempotency.Key, string, string, idempotency.Response, []byte, idempotency.ReconcileFunc) (idempotency.Response, error)
	Abort(context.Context, idempotency.Key, string, string) error
}

type EnrollmentService interface {
	Create(context.Context, platformscope.Scope, enrollment.CreateRequest) (enrollment.CreatedEnrollment, error)
	Replace(context.Context, platformscope.Scope, enrollment.CreateRequest, uint64) (enrollment.CreatedEnrollment, error)
	ResolveReplacement(context.Context, platformscope.Scope, enrollment.ReplacementLookup) (enrollment.ReplacementState, error)
}

type PluginAssignmentReconciler interface {
	ReconcileAssignment(context.Context, pluginassignment.Assignment, time.Time) (job.Job, error)
	FindScheduledJob(context.Context, pluginassignment.Assignment) (job.Job, bool, error)
}

// InspectionOverview is the storage-neutral aggregate returned by the host
// inspection application boundary.
type InspectionOverview struct {
	TargetCount        int
	OnlineTargetCount  int
	RunStatusCounts    map[inspection.RunStatus]int
	FindingLevelCounts map[inspection.FindingLevel]int
}

type InspectionTargetPage struct {
	Items      []inspection.HostTarget
	More       bool
	NextCursor string
}

// InspectionService owns inspection orchestration and durable write
// semantics. The HTTP layer only supplies authenticated scope and actor data,
// validates transport preconditions, and maps the domain values to OpenAPI.
type InspectionService interface {
	ListItems(context.Context, platformscope.Scope, inspection.ItemFilter) (inspection.ItemPage, error)
	CreateItem(context.Context, platformscope.Scope, string, string, inspection.Item) (inspection.Item, error)
	GetOverview(context.Context, platformscope.Scope) (InspectionOverview, error)
	ListPolicies(context.Context, platformscope.Scope, inspection.PolicyFilter) (inspection.PolicyPage, error)
	CreatePolicy(context.Context, platformscope.Scope, string, string, inspection.Policy) (inspection.Policy, error)
	GetPolicy(context.Context, platformscope.Scope, string) (inspection.Policy, error)
	UpdatePolicy(context.Context, platformscope.Scope, string, string, string, int64, inspection.Policy) (inspection.Policy, error)
	RunPolicy(context.Context, platformscope.Scope, string, string, string) (inspection.Run, error)
	ListReports(context.Context, platformscope.Scope, inspection.ReportFilter) (inspection.ReportPage, error)
	GetReport(context.Context, platformscope.Scope, string) (inspection.ReportSnapshot, error)
	CreateReportDownload(context.Context, platformscope.Scope, string, string, string, string) (artifact.Download, error)
	ListRuns(context.Context, platformscope.Scope, inspection.RunFilter) (inspection.RunPage, error)
	CreateRun(context.Context, inspection.CreateRunRequest) (inspection.Run, error)
	GetRun(context.Context, platformscope.Scope, string) (inspection.RunDetail, error)
	CancelRun(context.Context, platformscope.Scope, string, string, string) (inspection.Run, error)
	RetryRun(context.Context, platformscope.Scope, string, string, string) (inspection.Run, error)
	ListTargets(context.Context, platformscope.Scope, inspection.CursorFilter) (InspectionTargetPage, error)
}

// Services contains the dependencies made available to HTTP handlers.
// Monitoring deliberately uses its storage-neutral QueryStore boundary.
type Services struct {
	Repository                 alert.ControlPlaneRepository
	Evaluator                  EvaluatorHealthReader
	Monitoring                 monitoring.QueryStore
	Jobs                       JobService
	Artifacts                  ArtifactService
	Audit                      AuditService
	Capabilities               CapabilityService
	Idempotency                IdempotencyService
	Inspection                 InspectionService
	Hosts                      hostinventory.Service
	Enrollment                 EnrollmentService
	Discovery                  discovery.Service
	DatabaseInstances          databaseinstance.Service
	PluginCatalog              plugincatalog.CatalogService
	PluginAssignments          pluginassignment.Service
	MetricTemplates            metrictemplate.Service
	PluginReconciler           PluginAssignmentReconciler
	PluginUploadRemove         func(string) error
	PluginUploadCleanupFailure func(error)
	ArtifactContent            http.Handler
	AgentPluginArtifactContent http.Handler
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
