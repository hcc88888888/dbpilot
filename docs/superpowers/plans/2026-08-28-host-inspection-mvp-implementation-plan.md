# DBPilot Host Inspection MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a real host-level inspection loop with immediate and scheduled runs, deterministic findings, immutable HTML/JSON reports, and a self-developed frontend backed by the control plane.

**Architecture:** The control plane owns versioned inspection items, policies, schedules, runs, findings, and report snapshots. It creates existing Job/Command outbox work that sends signed two-phase `CollectNow{collection_kinds:["host"]}` commands; the Agent appends a fresh bounded host snapshot to the existing metric spool, and the control plane evaluates only samples at or after the run freshness fence. Reports are immutable inspection snapshots written through Artifact and exposed through the generated `/api/v1` client.

**Tech Stack:** Go 1.27, PostgreSQL 16, Protobuf/gRPC, OpenAPI 3.1, oapi-codegen, OpenAPI Generator, OpenTelemetry pdata, gopsutil v4, native ES modules, Node `node:test`, Docker Desktop, Kylin V10 SP1.

**Spec:** `docs/superpowers/specs/2026-08-28-instance-inspection-design.md`

## Global Constraints

- Work only in the isolated `codex/contract-foundation` worktree; do not modify the dirty `main` checkout.
- Functional correctness is the priority. Fix wrong findings, wrong data, failed core workflows, and incorrect command execution immediately; ledger non-blocking hardening and cleanup for later.
- Host inspection covers every configured Agent target. SQL/database probes are outside this plan.
- This MVP ships exactly the 13 version-one items listed in Task 2. Read-only/growth filesystem checks, network connectivity/error checks, critical-port checks, and Agent policy-state checks are queued for the next host-function phase and are not completion claims for this plan.
- No arbitrary Shell, raw SQL, or user-provided executable expression may reach the Agent.
- `healthy`, `warning`, `critical`, `unsupported`, and `missing_data` remain distinct; unknown or stale data is never healthy.
- Immediate and scheduled execution use the same persisted Run/Target/Job path.
- A failed target does not cancel sibling targets; a mixed batch completes with `partial` outcome.
- Every write is tenant/project scoped. HTTP writes use Idempotency-Key; policy updates use ETag/If-Match.
- Historical policy/item snapshots, findings, and reports are immutable.
- Agent execution continues to use Prepare/Start, execution token/revision fencing, cancellation, retained Result, and ResultAck.
- Generated Go and TypeScript files are never hand-edited; modify canonical OpenAPI/Protobuf inputs and run the pinned generators.
- Linux release boundaries remain CentOS 7+ and Kylin V10+; Kylin V10 SP1 amd64 smoke is required.
- First-stage report formats are HTML and JSON. PDF/Word and email are outside this plan.

## File Structure

### Contract

- Modify `contracts/openapi/dbpilot-api.yaml` — expose inspection schemas.
- Modify `contracts/openapi/modules/platform.yaml` — add inspection routes and permission metadata.
- Create `contracts/openapi/common/inspection.yaml` — canonical inspection DTOs, enums, requests, and pages.
- Create `contracts/examples/inspection/` — deterministic API examples used by lint and Prism.
- Regenerate `backend/gen/openapi/` and `frontend/generated/api/`.

### Control plane domain

- Create `backend/internal/inspection/model.go` — domain values and state validation.
- Create `backend/internal/inspection/catalog.go` — built-in host item catalog.
- Create `backend/internal/inspection/evaluator.go` — deterministic evidence evaluation.
- Create `backend/internal/inspection/service.go` — policy/run application service.
- Create `backend/internal/inspection/repository.go` — narrow persistence interfaces.
- Create `backend/internal/inspection/postgres.go` — scoped PostgreSQL persistence and scheduler claims.
- Create `backend/internal/inspection/report.go` — immutable report DTO and HTML/JSON renderers.
- Create `backend/internal/inspection/migrate.go` and `backend/internal/inspection/migrations/0001_host_inspection.sql`.
- Add focused tests beside every file and PostgreSQL integration tests in `backend/internal/inspection/postgres_integration_test.go`.

### Agent host snapshot

- Create `backend/internal/agent/collection_coordinator.go` — route trusted collection kinds.
- Create `backend/internal/agent/host_snapshot_collector.go` — bounded gopsutil host snapshot to OTLP metric spool.
- Create `backend/internal/agent/host_reader_linux.go` and `host_reader_other.go` — platform-specific host and time-sync reads.
- Create `backend/internal/telemetry/log_summary.go` — bounded in-memory severity/source summaries populated by the existing log pipeline.
- Modify `backend/internal/telemetry/engine.go` — observe sanitized log metadata before spool append.
- Modify `backend/internal/agent/collectnow_executor.go` — pass normalized command selection to the coordinator.
- Modify `backend/cmd/agent/main.go` — register host collection even without HBase dependency components.
- Modify `backend/packaging/config/agent.yaml.example` — trusted database process-name allowlist.
- Modify `backend/go.mod` and `backend/go.sum` — promote the already-transitive gopsutil v4 module to a direct dependency.

### Runtime and UI

- Create `backend/internal/controlplane/inspection_api.go` and tests — strict generated handler methods.
- Modify `backend/internal/controlplane/services.go`, `platform_api.go`, `platform_http.go`, `problem.go` — service wiring and stable errors.
- Modify `backend/cmd/controlplane/main.go` and its tests — migrations, scheduler/evaluator workers, readiness, and shutdown.
- Create `frontend/modules/inspection/inspection-api.js`, `inspection.js`, and `inspection.css`.
- Create `frontend/tests/inspection.test.js`.
- Modify `frontend/app.js`, `index.html`, `frontend/modules/reports/reports-api.js`, `reports.js`, and their tests.
- Create `backend/test/e2e/inspection_lifecycle_test.go`.
- Create `backend/scripts/verify-host-inspection.ps1` and update documentation.

---

### Task 1: Add the Host Inspection REST Contract

**Files:**
- Create: `contracts/openapi/common/inspection.yaml`
- Create: `contracts/examples/inspection/items.json`
- Create: `contracts/examples/inspection/policy.json`
- Create: `contracts/examples/inspection/run.json`
- Create: `contracts/examples/inspection/report.json`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Modify: `contracts/openapi/modules/platform.yaml`
- Regenerate: `backend/gen/openapi/`
- Regenerate: `frontend/generated/api/`
- Test: `tests/contracts/openapi.test.mjs`
- Test: `frontend/tests/control-plane-client.test.js`

**Interfaces:**
- Consumes: existing identifiers, pagination, Job, ArtifactReference, Problem Details, bearer security, Idempotency-Key, and ETag conventions.
- Produces: generated operation methods `GetInspectionOverview`, `ListInspectionTargets`, `ListInspectionItems`, `CreateInspectionItem`, `ListInspectionPolicies`, `CreateInspectionPolicy`, `GetInspectionPolicy`, `UpdateInspectionPolicy`, `RunInspectionPolicy`, `ListInspectionRuns`, `CreateInspectionRun`, `GetInspectionRun`, `CancelInspectionRun`, `RetryInspectionRun`, `ListInspectionReports`, `GetInspectionReport`, and `CreateInspectionReportDownload`.

- [ ] **Step 1: Write failing contract tests**

Add assertions that every inspection write declares the exact permission and required headers:

```javascript
const expected = new Map([
  ['createInspectionItem', 'inspection:manage'],
  ['createInspectionPolicy', 'inspection:manage'],
  ['updateInspectionPolicy', 'inspection:manage'],
  ['runInspectionPolicy', 'inspection:execute'],
  ['createInspectionRun', 'inspection:execute'],
  ['cancelInspectionRun', 'inspection:execute'],
  ['retryInspectionRun', 'inspection:execute'],
  ['createInspectionReportDownload', 'inspection:view'],
]);
for (const [operationId, permission] of expected) {
  const operation = operations.get(operationId);
  assert.equal(operation['x-dbpilot-permission'], permission);
  assert.ok(operation.parameters.some((item) => item.name === 'Idempotency-Key'));
}
```

Assert `InspectionFinding.level` is exactly `healthy|warning|critical|unsupported|missing_data`, run status is exactly `queued|collecting|evaluating|generating_report|completed|partial|failed|cancelled`, and all examples validate.

Assert overview, targets, items, policies, runs and reports read operations all declare `inspection:view`. `InspectionTarget` exposes Agent ID, display name, host, labels, connectivity and capabilities but no endpoint, credential or local filesystem data.

- [ ] **Step 2: Run the contract tests and verify failure**

Run: `node --test tests/contracts/openapi.test.mjs`

Expected: FAIL because inspection schemas and operations do not exist.

- [ ] **Step 3: Add canonical schemas and paths**

Define bounded request models. The custom metric rule shape is data, not code:

```yaml
InspectionMetricRule:
  type: object
  additionalProperties: false
  required: [metric_name, window, aggregation, operator, warning_threshold, critical_threshold]
  properties:
    metric_name: { type: string, pattern: '^[a-z][a-z0-9_.]{1,127}$' }
    labels: { type: object, maxProperties: 16, additionalProperties: { type: string, maxLength: 128 } }
    window: { type: string, enum: [5m, 15m, 1h] }
    aggregation: { type: string, enum: [latest, avg, max, min] }
    operator: { type: string, enum: [gt, gte, lt, lte] }
    warning_threshold: { type: number }
    critical_threshold: { type: number }
```

Limit run targets to 10,000, policy items to 200, item evidence to 64 KiB, page size to 100, and policy names to 120 characters. Scheduled policies accept a five-field cron expression plus an IANA timezone; no seconds field is accepted.

- [ ] **Step 4: Expose component schemas and generate clients/server**

Add every public inspection schema to `dbpilot-api.yaml#/components/schemas`, then run:

```powershell
npm run contracts:lint
npm run contracts:generate
npm run contracts:verify
```

Expected: lint and generation drift checks PASS; generated Go and TypeScript contain all operation methods.

- [ ] **Step 5: Add generated-client boundary assertions**

Assert the scoped client propagates Bearer, `X-Request-ID`, Idempotency-Key, If-Match, and AbortSignal for an inspection write, and maps 401/403 without demo fallback.

- [ ] **Step 6: Run focused contract/frontend tests**

Run: `node --test tests/contracts/openapi.test.mjs frontend/tests/control-plane-client.test.js`

Expected: PASS.

- [ ] **Step 7: Commit the contract**

```powershell
git add -- contracts backend/gen/openapi frontend/generated/api tests/contracts frontend/tests/control-plane-client.test.js
git commit -m "feat: define host inspection contract"
```

### Task 2: Implement Versioned Items and Deterministic Host Evaluation

**Files:**
- Create: `backend/internal/inspection/model.go`
- Create: `backend/internal/inspection/model_test.go`
- Create: `backend/internal/inspection/catalog.go`
- Create: `backend/internal/inspection/catalog_test.go`
- Create: `backend/internal/inspection/evaluator.go`
- Create: `backend/internal/inspection/evaluator_test.go`

**Interfaces:**
- Consumes: `platformscope.Scope`, UTC timestamps, metric samples and normalized host evidence.
- Produces:

```go
type EvidenceStore interface {
    Samples(context.Context, platformscope.Scope, string, []string, time.Time, time.Time, int) ([]Observation, error)
}

type Evaluator struct { Evidence EvidenceStore; Now func() time.Time }
func (e *Evaluator) EvaluateTarget(context.Context, RunSnapshot, TargetRun) ([]Finding, error)
func BuiltinHostItems() []Item
```

- [ ] **Step 1: Write failing model/state tests**

Table-test valid and invalid transitions, including:

```go
require.NoError(t, ValidateRunTransition(RunQueued, RunCollecting))
require.NoError(t, ValidateRunTransition(RunGeneratingReport, RunPartial))
require.Error(t, ValidateRunTransition(RunCompleted, RunEvaluating))
require.Equal(t, RunPartial, AggregateRunStatus([]TargetStatus{TargetSucceeded, TargetFailed}))
require.Equal(t, RunFailed, AggregateRunStatus([]TargetStatus{TargetFailed, TargetUnsupported}))
```

Assert immutable snapshots reject duplicate item versions, duplicate targets, empty scope, more than 200 items, more than 10,000 targets, non-UTC timestamps, and evidence larger than 64 KiB.

- [ ] **Step 2: Run model tests and verify failure**

Run: `Push-Location backend; go test ./internal/inspection -run 'Test(Model|Transition|Aggregate)' -count=1 -v; Pop-Location`

Expected: FAIL because the package does not exist.

- [ ] **Step 3: Implement domain values and built-in catalog**

Define closed string types:

```go
type FindingLevel string
const (
    LevelHealthy FindingLevel = "healthy"
    LevelWarning FindingLevel = "warning"
    LevelCritical FindingLevel = "critical"
    LevelUnsupported FindingLevel = "unsupported"
    LevelMissingData FindingLevel = "missing_data"
)

type MetricRule struct {
    MetricName string
    Labels map[string]string
    Window time.Duration
    Aggregation Aggregation
    Operator Operator
    WarningThreshold float64
    CriticalThreshold float64
}
```

Ship version `1` items for CPU utilization, load per CPU, memory utilization, Swap utilization, filesystem utilization, inode utilization, Agent heartbeat freshness, metric freshness, spool utilization, OOM evidence, time synchronization, database process presence, and error-log summary. Items without evidence return `missing_data`; a source not advertised by the Agent returns `unsupported`.

- [ ] **Step 4: Write failing evaluator tests**

Cover threshold equality, latest/avg/max/min, stale samples, NaN/Inf rejection, label mismatch, duplicated samples, missing series, unsupported source, and deterministic finding order. Use exact boundary assertions such as `warning >= 80`, `critical >= 90` for filesystem utilization.

- [ ] **Step 5: Implement the evaluator**

Normalize UTC, sort observations by timestamp and stable identity, cap the input read before allocation, and evaluate the immutable item version. Evidence contains only selected metric/value/time/threshold fields and never raw logs or labels matching secret markers.

- [ ] **Step 6: Run inspection domain tests**

Run: `Push-Location backend; go test ./internal/inspection -count=1 -v; Pop-Location`

Expected: PASS.

- [ ] **Step 7: Commit the domain**

```powershell
git add -- backend/internal/inspection/model.go backend/internal/inspection/model_test.go backend/internal/inspection/catalog.go backend/internal/inspection/catalog_test.go backend/internal/inspection/evaluator.go backend/internal/inspection/evaluator_test.go
git commit -m "feat: add deterministic host inspection rules"
```

### Task 3: Add PostgreSQL Policies, Runs, Scheduling, and Job Creation

**Files:**
- Create: `backend/internal/inspection/repository.go`
- Create: `backend/internal/inspection/postgres.go`
- Create: `backend/internal/inspection/postgres_test.go`
- Create: `backend/internal/inspection/postgres_integration_test.go`
- Create: `backend/internal/inspection/service.go`
- Create: `backend/internal/inspection/service_test.go`
- Create: `backend/internal/inspection/targets.go`
- Create: `backend/internal/inspection/targets_test.go`
- Create: `backend/internal/inspection/migrate.go`
- Create: `backend/internal/inspection/migrate_test.go`
- Create: `backend/internal/inspection/migrations/0001_host_inspection.sql`
- Create: `backend/scripts/verify-inspection-postgres.ps1`
- Modify: `backend/internal/platformdb/postgres_integration_test.go`
- Modify: `backend/go.mod`
- Modify: `backend/go.sum`

**Interfaces:**
- Consumes: Task 2 models, `job.Repository.CreateInTx`, protobuf `CollectNow`, configured host target inventory, stable ID/clock factories.
- Produces:

```go
type Repository interface {
    CreateItem(context.Context, Item) error
    ListItems(context.Context, platformscope.Scope, ItemFilter) (ItemPage, error)
    CreatePolicy(context.Context, Policy) error
    ListPolicies(context.Context, platformscope.Scope, PolicyFilter) (PolicyPage, error)
    GetPolicy(context.Context, platformscope.Scope, string) (Policy, error)
    UpdatePolicy(context.Context, Policy, int64) (Policy, error)
    ClaimDuePolicies(context.Context, time.Time, int, time.Duration) ([]Policy, error)
    CreateRunWithJob(context.Context, Run, []TargetRun, job.Job, []job.OutboxMessage) error
    GetRun(context.Context, platformscope.Scope, string) (RunDetail, error)
    ListRuns(context.Context, platformscope.Scope, RunFilter) (RunPage, error)
    GetReport(context.Context, platformscope.Scope, string) (ReportSnapshot, error)
    ListReports(context.Context, platformscope.Scope, ReportFilter) (ReportPage, error)
}

type TargetResolver interface {
    Resolve(context.Context, platformscope.Scope, TargetSelector) ([]HostTarget, error)
    List(context.Context, platformscope.Scope) ([]HostTarget, error)
}

func (s *Service) CreateRun(context.Context, CreateRunRequest) (Run, error)
func (s *Service) RetryRun(context.Context, platformscope.Scope, string, string, string) (Run, error)
func (s *Service) ScheduleDue(context.Context, time.Time) (int, error)
```

- [ ] **Step 1: Write failing migration and repository tests**

Assert all seven inspection tables exist, scope columns participate in foreign/unique keys, occurrence key is unique per scope, snapshots are JSONB with size checks, report rows are immutable, and scheduler indexes cover `(enabled, next_run_at, lease_expires_at)`.

Assert every query includes tenant/project, cursor order is `(created_at DESC, id DESC)`, and policy compare-and-swap rejects a stale version.

- [ ] **Step 2: Run repository tests and verify failure**

Run: `Push-Location backend; go test ./internal/inspection -run 'Test(Migration|Postgres|PolicyCAS|SchedulerClaim)' -count=1 -v; Pop-Location`

Expected: FAIL because persistence is absent.

- [ ] **Step 3: Implement schema and repository**

Use `inspection_items`, `inspection_policies`, `inspection_policy_items`, `inspection_runs`, `inspection_target_runs`, `inspection_findings`, and `inspection_reports`. Store explicit UTC timestamps, immutable item/policy snapshots, occurrence key, Job ID, Agent/Command IDs, target status, report Artifact IDs, and stable Audit correlation.

`ClaimDuePolicies` uses `FOR UPDATE SKIP LOCKED`, writes a bounded lease, and advances `next_run_at` only when the occurrence is durably created. A unique occurrence collision is an idempotent duplicate, not a second run.

- [ ] **Step 4: Write failing run creation tests**

Assert explicit Agent IDs and label selectors resolve to a sorted, unique target set; unknown targets fail validation; an empty result fails; and one transaction inserts Run, TargetRuns, Job, Job targets, and unsigned `CollectNow{collection_kinds:["host"]}` outbox rows.

Use this exact unsigned payload shape:

```go
&agentv1.CommandEnvelope{
    AgentId: target.AgentID,
    LeaseSeconds: 60,
    Command: &agentv1.CommandEnvelope_CollectNow{CollectNow: &agentv1.CollectNow{
        CollectionKinds: []string{"host"},
    }},
}
```

- [ ] **Step 5: Implement service and target resolution**

Implement `ConfiguredTargetResolver` from an injected immutable `[]HostTarget`; it matches explicit Agent IDs and exact string labels only inside the authenticated scope. Snapshot targets and item versions before opening the transaction. Generate one Job target and one command per Agent ID; use run ID as Job source resource and the persisted occurrence key for scheduled idempotency.

An internal delivery/evaluation/report retry keeps the same Run/Target/Command IDs. A user `RetryRun` request accepts only a terminal failed or partial Run and creates a new Run/Job/Command set with `retry_of_run_id`; the HTTP Idempotency-Key prevents duplicate retry runs.

Add `github.com/robfig/cron/v3 v3.0.1` and parse schedules with exactly `cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow`; descriptors, seconds fields and local-machine timezone defaults are rejected. Resolve the policy's explicit IANA timezone with `time.LoadLocation`.

- [ ] **Step 6: Add live PostgreSQL atomicity and concurrency tests**

Under `DBPILOT_CONTRACT_E2E=1`, prove a forced outbox insert error rolls back Run/Targets/Job, two scheduler claimers receive disjoint policies, restart reclaims an expired lease, and duplicate occurrence creation returns the existing run. `verify-inspection-postgres.ps1` starts a uniquely named PostgreSQL 16 container on an ephemeral loopback port, exports the DSN only to the test process, and removes the container and anonymous volume in `finally`.

- [ ] **Step 7: Run focused and integration tests**

Run:

```powershell
Push-Location backend
go test ./internal/inspection -count=1 -v
Pop-Location
powershell -NoProfile -File backend/scripts/verify-inspection-postgres.ps1
```

Expected: PASS with the verifier-managed PostgreSQL fixture.

- [ ] **Step 8: Commit persistence and scheduling**

```powershell
git add -- backend/internal/inspection backend/internal/platformdb/postgres_integration_test.go backend/scripts/verify-inspection-postgres.ps1 backend/go.mod backend/go.sum
git commit -m "feat: persist and schedule host inspections"
```

### Task 4: Make Agent CollectNow Produce a Fresh Host Snapshot

**Files:**
- Create: `backend/internal/agent/collection_coordinator.go`
- Create: `backend/internal/agent/collection_coordinator_test.go`
- Create: `backend/internal/agent/host_snapshot_collector.go`
- Create: `backend/internal/agent/host_snapshot_collector_test.go`
- Create: `backend/internal/agent/host_reader_linux.go`
- Create: `backend/internal/agent/host_reader_other.go`
- Create: `backend/internal/telemetry/log_summary.go`
- Create: `backend/internal/telemetry/log_summary_test.go`
- Modify: `backend/internal/telemetry/engine.go`
- Modify: `backend/internal/telemetry/engine_test.go`
- Modify: `backend/internal/agent/collectnow_executor.go`
- Modify: `backend/internal/agent/collectnow_executor_test.go`
- Modify: `backend/cmd/agent/main.go`
- Modify: `backend/cmd/agent/main_test.go`
- Modify: `backend/packaging/config/agent.yaml.example`
- Modify: `backend/go.mod`
- Modify: `backend/go.sum`

**Interfaces:**
- Consumes: validated `CollectNow.collection_kinds`, current Agent ID, existing spool Store, gopsutil host readers, optional `DependencyCollector`.
- Produces:

```go
type CollectionRequest struct { Kinds []string; InstanceIDs []string }
type Collector interface { Collect(context.Context, CollectionRequest) error }
type CollectionCoordinator struct { Host Collector; Dependencies Collector }
func (c *CollectionCoordinator) Collect(context.Context, CollectionRequest) error

type LogSummaryProvider interface { Snapshot(time.Time, time.Duration) []LogSummary }
type HostSnapshotCollector struct { AgentID string; Store spool.Store; Reader HostReader; Logs LogSummaryProvider; ProcessNames []string; Now func() time.Time }
func (c *HostSnapshotCollector) Collect(context.Context, CollectionRequest) error
```

- [ ] **Step 1: Write failing coordinator tests**

Assert `host` invokes only the host collector, `dependencies` invokes only the dependency adapter, `host+dependencies` invokes both once in sorted order, unknown kinds fail before collection, duplicate kinds are deduplicated, and cancellation stops remaining work.

- [ ] **Step 2: Run the coordinator tests and verify failure**

Run: `Push-Location backend; go test ./internal/agent -run 'Test(CollectionCoordinator|CollectNow)' -count=1 -v; Pop-Location`

Expected: FAIL because selection-aware collection is absent.

- [ ] **Step 3: Implement selection-aware CollectNow**

Change `CollectNowExecutor` to pass a normalized `CollectionRequest` to the coordinator. Preserve fixed public summaries and stable error code `COLLECT_NOW_FAILED`; collector internals never enter CommandResult.

Adapt `DependencyCollector` through a wrapper that accepts only `dependencies`. Do not advertise `collect_now` unless at least one collector is configured.

- [ ] **Step 4: Write failing host snapshot tests**

Inject a fake `HostReader` and `LogSummaryProvider`; assert one `host` request appends one OTLP metric batch containing bounded canonical metrics for CPU, load, memory, Swap, filesystem, inode, network, process count, configured database-process presence, boot time, time-sync availability, and warning/error log counts. Assert all samples have `agent.id`, `host.name`, `os.type`, and `inspection.snapshot_at`; filesystem/device/interface/process/source cardinality is capped and sorted.

Assert append failure returns an error, cancelled context performs no append, NaN/Inf values are rejected, and a second same-clock collection has a distinct durable batch ID.

- [ ] **Step 5: Implement the host snapshot collector**

Promote `github.com/shirou/gopsutil/v4 v4.26.7` to a direct module. Wrap CPU, load, memory, disk, filesystem, network, host, and process readers behind `HostReader`. On Linux, read time synchronization with `unix.Adjtimex`; on unsupported local test platforms return an explicit unavailable observation. Convert values to `pmetric.Metrics`, marshal with `pmetric.ProtoMarshaler`, enforce the existing exporter batch limit, and append as `spool.Metric` with source ID `inspection-host-snapshot`.

`telemetry.LogSummaryIndex` keeps only bounded counters by sanitized source ID and normalized severity for the most recent hour. The existing log consumer observes metadata before spool append; it never retains raw bodies. The host snapshot emits those counts as metrics. An empty post-start window produces `missing_data`, not a zero-error healthy result.

Extend `telemetry.EmbeddedBuilder` with an optional `LogObserver` constructor argument and pass the same `LogSummaryIndex` instance from `cmd/agent/main.go` to both the embedded telemetry pipeline and `HostSnapshotCollector`. Observer failure cannot discard the original log batch; invalid metadata is ignored and counted in a fixed internal health metric.

Use existing metric names emitted by the configured hostmetrics receiver where available; inspection-only availability fields use the `dbpilot.inspection.host.*` prefix.

- [ ] **Step 6: Wire the production Agent**

Construct `HostSnapshotCollector` from the existing spool, Agent identity, log summary index, and an Agent-configured allowlist of at most 64 normalized database process names. Register `CollectNowExecutor` with a coordinator containing the host collector and the optional dependency collector. Update the no-components production test to require `collect_now` because host collection is always available after spool readiness.

- [ ] **Step 7: Run Agent and telemetry tests**

Run: `Push-Location backend; go test ./internal/agent ./internal/telemetry ./cmd/agent -count=1 -v; Pop-Location`

Expected: PASS.

- [ ] **Step 8: Commit Agent host collection**

```powershell
git add -- backend/internal/agent backend/cmd/agent backend/go.mod backend/go.sum
git commit -m "feat: collect host snapshots on inspection demand"
```

### Task 5: Evaluate Completed Targets and Generate Immutable Reports

**Files:**
- Create: `backend/internal/inspection/report.go`
- Create: `backend/internal/inspection/report_test.go`
- Create: `backend/internal/inspection/worker.go`
- Create: `backend/internal/inspection/worker_test.go`
- Modify: `backend/internal/inspection/postgres.go`
- Modify: `backend/internal/inspection/postgres_test.go`
- Modify: `backend/internal/artifact/model.go`
- Modify: `backend/internal/artifact/postgres.go`
- Modify: `backend/internal/artifact/postgres_test.go`
- Modify: `backend/internal/artifact/download_handler.go`
- Modify: `backend/internal/artifact/download_handler_test.go`

**Interfaces:**
- Consumes: Task 2 evaluator, Task 3 run repository, terminal Job/target results, fresh metric samples, Artifact storage, Audit service.
- Produces:

```go
type ArtifactWriter interface {
    Put(context.Context, artifact.Artifact, []byte) (artifact.Artifact, error)
}
type Worker struct { Runs RunWorkerRepository; Jobs JobReader; Evaluator *Evaluator; Artifacts ArtifactWriter; Audit AuditRecorder }
func (w *Worker) Process(context.Context, time.Time, int) (int, error)
func RenderJSON(ReportSnapshot) ([]byte, error)
func RenderHTML(ReportSnapshot) ([]byte, error)
```

- [ ] **Step 1: Write failing worker state tests**

Assert a successful command is not evaluated until at least one required sample has `sampled_at >= run.freshness_fence`; stale-only data produces `missing_data`; a failed command produces a failed target without evaluating fabricated health; sibling targets continue; and mixed targets aggregate to `partial`.

- [ ] **Step 2: Run worker tests and verify failure**

Run: `Push-Location backend; go test ./internal/inspection -run 'Test(Worker|Freshness|Partial)' -count=1 -v; Pop-Location`

Expected: FAIL because the worker is absent.

- [ ] **Step 3: Implement bounded evaluation claims**

Add repository claims for collecting/evaluating/reporting runs using `FOR UPDATE SKIP LOCKED` and leases. Persist Findings with `(tenant_id, project_id, run_id, target_id, item_id, item_version)` uniqueness. A retry reads existing Findings and never duplicates them.

Map unsupported capability to `unsupported`, stale or absent required evidence to `missing_data`, executor failure to target failure, and valid evaluated evidence to healthy/warning/critical.

- [ ] **Step 4: Write failing report and Artifact writer tests**

Assert JSON keys and ordering are deterministic; HTML escapes every external string; report content excludes scope internals, credentials, connection strings and raw logs; both formats include policy/item versions and Job/Command/Audit references.

Assert `ArtifactWriter.Put` writes a temporary file inside the retained `os.Root`, fsyncs, atomically renames, inserts metadata, and treats an existing identical checksum as success. A conflicting checksum for the same Artifact ID fails.

- [ ] **Step 5: Implement report rendering and Artifact output**

Reserve stable IDs `inspection-report-<run-id>`, `inspection-report-<run-id>.json`, and `inspection-report-<run-id>.html`. Render from the persisted snapshot only. Finalize report snapshot, two Artifact references, Run terminal state, and stable Audit correlation in an idempotent sequence; Artifact generation failure leaves `generating_report` claimable without collecting again.

- [ ] **Step 6: Run report/worker/artifact tests**

Run: `Push-Location backend; go test ./internal/inspection ./internal/artifact -count=1 -v; Pop-Location`

Expected: PASS.

- [ ] **Step 7: Commit evaluation and reports**

```powershell
git add -- backend/internal/inspection backend/internal/artifact
git commit -m "feat: evaluate inspections and generate reports"
```

### Task 6: Expose Strict HTTP APIs and Build the Inspection UI

**Files:**
- Create: `backend/internal/controlplane/inspection_api.go`
- Create: `backend/internal/controlplane/inspection_api_test.go`
- Modify: `backend/internal/controlplane/services.go`
- Modify: `backend/internal/controlplane/platform_api.go`
- Modify: `backend/internal/controlplane/platform_http.go`
- Modify: `backend/internal/controlplane/problem.go`
- Modify: `backend/cmd/controlplane/main.go`
- Modify: `backend/cmd/controlplane/main_test.go`
- Create: `frontend/modules/inspection/inspection-api.js`
- Create: `frontend/modules/inspection/inspection.js`
- Create: `frontend/modules/inspection/inspection.css`
- Create: `frontend/tests/inspection.test.js`
- Modify: `frontend/app.js`
- Modify: `index.html`
- Modify: `frontend/modules/reports/reports-api.js`
- Modify: `frontend/modules/reports/reports.js`
- Modify: `frontend/tests/reports.test.js`

**Interfaces:**
- Consumes: generated Task 1 operations, Task 3 service, Task 5 report metadata, existing OIDC/RBAC, generated-client boundary and enterprise styles.
- Produces: working inspection overview/policy/run/report views and inspection entries in Report Center.

- [ ] **Step 1: Write failing strict-handler tests**

Cover every generated method. Assert URL scope wins over body fields, permission mapping is exact, Idempotency-Key is required for run/cancel/retry, stale If-Match returns 412, list cursors remain scoped, ETag reflects policy version, and internal errors use stable Problem codes without raw details.

- [ ] **Step 2: Run HTTP tests and verify failure**

Run: `Push-Location backend; go test ./internal/controlplane -run TestInspection -count=1 -v; Pop-Location`

Expected: FAIL because strict inspection handlers are absent.

- [ ] **Step 3: Implement HTTP and server wiring**

Extend `PlatformServices` with a typed `InspectionService`. Implement generated handlers by delegating to it; keep orchestration out of HTTP files. Map invalid item/policy/run, not found, conflict, precondition, unavailable evidence and query limits to fixed Problem codes.

Extend `cmd/controlplane.AgentAssignment` with immutable display name, host and string labels, then build `ConfiguredTargetResolver` from those validated assignments. Run inspection migrations before readiness. Add two bounded periodic loops: one claims scheduled policies, one processes collecting/evaluating/reporting runs. Both stop on server context cancellation and join the existing worker wait group.

- [ ] **Step 4: Write failing frontend API and view tests**

Assert the API uses the generated scoped client, passes Idempotency-Key/If-Match/AbortSignal, and never falls back after 401/403/5xx. Test overview cards, policy form, target/item selection, run progress, partial result, `unsupported`, `missing_data`, report detail, cancel/retry permissions, XSS escaping, scope changes and abort handling.

- [ ] **Step 5: Run frontend tests and verify failure**

Run: `node --test frontend/tests/inspection.test.js frontend/tests/reports.test.js`

Expected: FAIL because the inspection module is absent and Report Center is not connected.

- [ ] **Step 6: Implement the self-developed inspection module**

Follow the existing module factory pattern with four views: overview, policies, runs, and report detail. Use one store per mounted scope, one AbortController per load, delegated event handlers, escaped output, accessible labels, explicit loading/empty/error states, and the existing enterprise visual tokens.

In control-plane mode render only server responses. Demo mode remains explicitly labeled and is selected only when no control-plane URL is configured.

- [ ] **Step 7: Connect Report Center**

Map inspection report rows to the existing report list/detail DTO, make download call `CreateInspectionReportDownload`, and remove PDF/Word/email actions for HTML/JSON inspection reports. Existing demo reports remain unchanged when no control plane is configured.

- [ ] **Step 8: Run HTTP and frontend regression tests**

Run:

```powershell
Push-Location backend
go test ./internal/controlplane ./cmd/controlplane -count=1 -v
Pop-Location
node --test frontend/tests/*.test.js
```

Expected: PASS.

- [ ] **Step 9: Commit HTTP and UI**

```powershell
git add -- backend/internal/controlplane backend/cmd/controlplane frontend index.html
git commit -m "feat: expose host inspection workflow"
```

### Task 7: Add End-to-End, Kylin, and Operational Verification

**Files:**
- Create: `backend/test/e2e/inspection_lifecycle_test.go`
- Create: `backend/scripts/verify-host-inspection.ps1`
- Modify: `backend/scripts/verify-contract-foundation.ps1`
- Modify: `backend/scripts/verify-kylin-docker.ps1`
- Modify: `.github/workflows/contracts.yml`
- Create: `docs/host-inspection-operations.md`
- Modify: `README.md`
- Modify: `backend/README.md`

**Interfaces:**
- Consumes: all Tasks 1–6.
- Produces: one local verifier that proves the host inspection lifecycle and one Kylin smoke path using the production Agent.

- [ ] **Step 1: Write a failing PostgreSQL lifecycle E2E test**

With the existing PostgreSQL fixture and in-memory Agent stream, create a two-target immediate run. Return one successful fresh host snapshot and one failed command. Assert Run `partial`, immutable Findings, HTML/JSON Artifact metadata, Job/Command/Audit traceability, idempotent exact retry, and no duplicate Finding/report rows.

- [ ] **Step 2: Run the E2E test and verify failure**

Run: `Push-Location backend; $env:DBPILOT_CONTRACT_E2E='1'; go test ./test/e2e -run TestHostInspectionLifecycle -count=1 -v; Remove-Item Env:DBPILOT_CONTRACT_E2E; Pop-Location`

Expected: FAIL until the full lifecycle is wired.

- [ ] **Step 3: Add the self-cleaning verifier**

`verify-host-inspection.ps1` starts a uniquely named PostgreSQL 16 container with an anonymous volume, waits for readiness, runs inspection migrations and the E2E test, and removes the container plus volume in `finally`. It records and validates only the exact resource IDs it created.

- [ ] **Step 4: Extend Kylin production-Agent smoke**

Start the real Agent in `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1`, send signed Prepare/Start for `CollectNow{collection_kinds:["host"]}`, require a persisted Result/ResultAck, and decode the metric spool to prove canonical CPU, memory, filesystem, load and snapshot timestamp metrics exist. Fail on an early clean Agent exit or empty host snapshot.

- [ ] **Step 5: Run all fresh verification**

Run:

```powershell
npm run contracts:lint
npm run contracts:breaking
npm run contracts:verify
node --test
Push-Location backend
go test ./... -count=1
go vet ./...
Pop-Location
powershell -NoProfile -File backend/scripts/verify-host-inspection.ps1
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1
powershell -NoProfile -File backend/scripts/verify-kylin-docker.ps1 -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' -Architecture amd64
```

Expected: zero contract drift, zero Node/Go failures, host inspection lifecycle PASS, foundation PASS, and Kylin reports a non-empty production host snapshot.

- [ ] **Step 6: Document operations and deferred work**

Document policy scheduling, target labels, freshness semantics, partial success, report repair, retention, readiness, metrics, troubleshooting, Windows verification and Kylin evidence. Record SQL database probes, HBase/MongoDB/Neo4j depth, PDF/Word, email and non-blocking hardening as later work with affected module, trigger, impact, severity and recommended stage.

- [ ] **Step 7: Commit verification and documentation**

```powershell
git add -- backend/test/e2e/inspection_lifecycle_test.go backend/scripts .github/workflows/contracts.yml docs/host-inspection-operations.md README.md backend/README.md
git commit -m "test: verify host inspection lifecycle"
```

## Parallel and Dependency Boundaries

- Task 1 and Task 2 may execute in parallel because they touch contract files and the new Go domain package respectively.
- Task 3 starts after Task 2 fixes public domain types; it may proceed while Task 1 generation finishes if it does not import generated OpenAPI types.
- Task 4 starts after Task 3 because both promote direct Go dependencies in `backend/go.mod`; its production code is otherwise independent of inspection persistence.
- Task 5 requires Tasks 2–4.
- Task 6 requires Tasks 1, 3, and 5.
- Task 7 requires all earlier tasks.

Do not run two implementation agents concurrently when they share generated files, `backend/cmd/controlplane/main.go`, `frontend/app.js`, `index.html`, migration numbering, or verification scripts.

## Completion Gate

Completion requires:

- All seven tasks have task-scoped spec and quality approval.
- Final whole-branch review has no unadjudicated Critical or Important finding.
- Fresh contract, Node, Go, PostgreSQL, foundation, and Kylin commands from Task 7 all pass.
- `git diff --check` is clean.
- The feature worktree has no unexpected tracked or untracked implementation files.
- The dirty `main` checkout remains unchanged.
