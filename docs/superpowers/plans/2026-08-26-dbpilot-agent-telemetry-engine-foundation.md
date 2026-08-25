# DBPilot Agent Telemetry Engine Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-process, single-binary DBPilot Agent that applies signed DBPilot telemetry policies, collects Linux host metrics, journald and custom file logs, collects Prometheus/HTTP/SQL custom metrics, buffers telemetry durably, and sends acknowledged batches to a test DBPilot Ingest Gateway.

**Architecture:** The Go Agent embeds selected OpenTelemetry Collector component factories behind DBPilot-owned policy and engine interfaces; neither Vector nor a standalone Collector process is installed. DBPilot policy is validated and compiled into an in-memory receiver/processor/exporter pipeline, while a DBPilot segment spool provides bounded durable delivery and a custom gRPC exporter enforces mTLS identity. Typed command execution and production database adapters remain separate follow-up plans.

**Tech Stack:** Go 1.25 language floor built with Go 1.27.0, gRPC, Protobuf, buf, OpenTelemetry Collector/Contrib v0.158.0 Go components, bbolt for small state, length-prefixed CRC-protected segment files for payloads, testify, Linux systemd packaging.

**Spec:** `docs/superpowers/specs/2026-08-25-dbpilot-agent-platform-design.md` and `docs/superpowers/specs/2026-08-25-dbpilot-platform-integration-design.md`

## Global Constraints

- `dbpilot-agent` is one process and one deployable binary; it must not install, start, expose, or require Vector or a standalone OpenTelemetry Collector.
- Go modules declare `go 1.25`; Go 1.27.0 is the pinned build toolchain.
- Server and Agent support Linux amd64 on CentOS 7+ and Kylin V10+; Agent also supports Linux arm64 for Kylin ARM environments.
- Linux release builds use `CGO_ENABLED=0`; amd64 builds use `GOAMD64=v1`.
- Agent accepts only signed, versioned DBPilot policy. It never accepts raw Vector, OTel Collector, executable, or shell configuration from Server.
- Custom file sources are confined to configured allow roots after symlink resolution and reject `/proc`, `/sys`, credential directories, and path traversal.
- SQL metrics are one read-only statement with enforced timeout, interval, and row limits. Plugin metrics use a preinstalled signed registry; policy cannot choose an executable.
- Telemetry leaves Agent only through DBPilot-owned gRPC contracts with mTLS. Agent never receives ClickHouse, VictoriaMetrics, or S3 credentials.
- bbolt stores policy state, checkpoints, segment indexes, and deduplication metadata only. Log and metric payloads live in bounded spool segment files.
- Audit-class logs must never be silently discarded. Capacity or permission failures produce an Agent health finding.
- Every task follows red-green-refactor TDD, runs focused tests before the full suite, and ends in a focused commit.

---

## Planned File Structure

```text
backend/
├── go.mod                              # Module and pinned dependency versions
├── buf.yaml                            # Protobuf lint configuration
├── buf.gen.yaml                        # Go/gRPC generation configuration
├── api/telemetry/v1/telemetry.proto    # Policy ACK, log/metric batch and ingest RPCs
├── gen/telemetry/v1/                   # Generated protobuf code
├── cmd/agent/main.go                   # Linux Agent entry point and signal handling
├── cmd/telemetry-test-gateway/main.go  # Local-only contract test gateway
├── internal/policy/model.go            # DBPilot telemetry policy types
├── internal/policy/validate.go         # Security and resource validation
├── internal/policy/signature.go        # Canonical Ed25519 policy signing
├── internal/telemetry/catalog.go       # Allowed embedded component catalog
├── internal/telemetry/compiler.go      # Policy-to-runtime compilation
├── internal/telemetry/engine.go        # Atomic pipeline lifecycle
├── internal/telemetry/custommetrics.go # HTTP/SQL/registered-plugin metric collectors
├── internal/spool/state.go             # bbolt metadata and checkpoints
├── internal/spool/segments.go          # CRC segment append/read/ack/recovery
├── internal/exporter/client.go         # mTLS gRPC acknowledged exporter
├── internal/agent/runtime.go            # Policy, engine, spool and exporter supervision
├── internal/ingest/service.go           # Test gateway validation and ACK behavior
├── packaging/systemd/dbpilot-agent.service
├── packaging/config/agent.yaml.example
├── scripts/build-linux.ps1
└── test/e2e/telemetry_lifecycle_test.go
```

Generated files under `backend/gen` are reproducible build output, are committed in Task 1, and are regenerated in CI to detect drift.

---

### Task 1: Module, Telemetry Contract, and Linux-Buildable Binaries

**Files:**
- Create: `backend/go.mod`
- Create: `backend/buf.yaml`
- Create: `backend/buf.gen.yaml`
- Create: `backend/api/telemetry/v1/telemetry.proto`
- Create: `backend/api/telemetry/v1/contract_test.go`
- Create: `backend/cmd/agent/main.go`
- Create: `backend/cmd/telemetry-test-gateway/main.go`

**Interfaces:**
- Produces protobuf service `TelemetryIngest` with unary RPCs `PushLogBatch`, `PushMetricBatch`, and `ReportPolicyStatus`.
- Produces `LogBatch`, `MetricBatch`, `BatchAck`, and `PolicyStatus` messages.
- `LogBatch` fields: `batch_id`, `agent_id`, `source_id`, `category`, `first_offset`, `last_offset`, `payload`, `checksum`, `created_at_unix`.
- `MetricBatch` fields: `batch_id`, `agent_id`, `source_id`, `payload`, `checksum`, `created_at_unix`.
- `BatchAck` fields: `batch_id`, `accepted`, `retryable`, `error_code`.
- `PolicyStatus` fields: `agent_id`, `version`, `state`, `error_code`, `reported_at_unix`.

- [ ] **Step 1: Write the contract test before the proto exists**

```go
func TestTelemetryContractContainsRequiredOperations(t *testing.T) {
    body, err := os.ReadFile("telemetry.proto")
    require.NoError(t, err)
    text := string(body)
    for _, required := range []string{
        "rpc PushLogBatch", "rpc PushMetricBatch", "rpc ReportPolicyStatus",
        "batch_id", "agent_id", "source_id", "checksum", "retryable",
    } {
        assert.Contains(t, text, required)
    }
}
```

- [ ] **Step 2: Run the contract test and verify the missing-file failure**

Run: `go test ./api/telemetry/v1 -run TestTelemetryContractContainsRequiredOperations -v`

Expected: FAIL because `telemetry.proto` does not exist.

- [ ] **Step 3: Define the proto and generation configuration**

Use `proto3`, package `dbpilot.telemetry.v1`, and Go package `dbpilot.local/platform/gen/telemetry/v1;telemetryv1`. Keep tenant/project fields out of client-authoritative messages: the gateway derives them from the authenticated Agent identity.

```proto
service TelemetryIngest {
  rpc PushLogBatch(LogBatch) returns (BatchAck);
  rpc PushMetricBatch(MetricBatch) returns (BatchAck);
  rpc ReportPolicyStatus(PolicyStatus) returns (PolicyStatusAck);
}
```

- [ ] **Step 4: Generate code and make the contract test pass**

Run:

```powershell
buf lint
buf generate
go mod tidy
go test ./api/telemetry/v1 -v
```

Expected: all commands PASS.

- [ ] **Step 5: Add minimal flag-parsing binaries and verify Linux static builds**

Both binaries expose `--version`; the Agent also requires `--config`. Missing required flags return a non-zero exit code without starting listeners.

Run:

```powershell
$env:CGO_ENABLED='0'
$env:GOOS='linux'
$env:GOARCH='amd64'
$env:GOAMD64='v1'
go build ./cmd/agent ./cmd/telemetry-test-gateway
$env:GOARCH='arm64'
Remove-Item Env:GOAMD64 -ErrorAction SilentlyContinue
go build ./cmd/agent ./cmd/telemetry-test-gateway
```

Expected: both amd64 and arm64 builds PASS.

- [ ] **Step 6: Commit the contract slice**

```powershell
git add backend
git commit -m "feat: define DBPilot telemetry ingest contract"
```

---

### Task 2: Signed DBPilot Telemetry Policy and Security Validation

**Files:**
- Create: `backend/internal/policy/model.go`
- Create: `backend/internal/policy/validate.go`
- Create: `backend/internal/policy/signature.go`
- Create: `backend/internal/policy/policy_test.go`

**Interfaces:**
- Produces `policy.Policy`, `policy.Source`, `policy.Limits`, `policy.SignatureEnvelope`.
- Produces `policy.Validate(p Policy, env ValidationEnvironment) error`.
- Produces `policy.Sign(private ed25519.PrivateKey, p Policy) (SignatureEnvelope, error)`.
- Produces `policy.Verify(public ed25519.PublicKey, envelope SignatureEnvelope, now time.Time) (Policy, error)`.
- `ValidationEnvironment` contains `AllowedRoots []string`, `ForbiddenRoots []string`, `PluginIDs map[string]struct{}`, and `ResolvePath func(string) (string, error)`.

- [ ] **Step 1: Write failing validation and signature tests**

Cover a valid file source, path traversal, resolved symlink escape, `/proc` rejection, raw `otel`/`vector` source type rejection, duplicate source IDs, zero/negative limits, payload mutation, expiry, and policy version rollback.

```go
func TestValidateRejectsResolvedPathOutsideAllowRoot(t *testing.T) {
    p := validPolicy(fileSource("/var/log/app/current.log"))
    env := testEnvironment(func(string) (string, error) {
        return "/etc/shadow", nil
    })
    require.ErrorIs(t, policy.Validate(p, env), policy.ErrPathOutsideAllowRoots)
}

func TestVerifyRejectsPolicyMutation(t *testing.T) {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    require.NoError(t, err)
    envelope, err := policy.Sign(priv, validPolicy(fileSource("/var/log/app/app.log")))
    require.NoError(t, err)
    envelope.Policy.Limits.MaxSpoolBytes++
    _, err = policy.Verify(pub, envelope, time.Now())
    require.ErrorIs(t, err, policy.ErrInvalidSignature)
}
```

- [ ] **Step 2: Run the tests and verify missing-type failures**

Run: `go test ./internal/policy -v`

Expected: FAIL because the policy package does not exist.

- [ ] **Step 3: Implement closed policy source kinds**

Define only these initial kinds:

```go
const (
    SourceFileLog         SourceKind = "FILE_LOG"
    SourceJournald        SourceKind = "JOURNALD"
    SourceHostMetrics     SourceKind = "HOST_METRICS"
    SourcePrometheus      SourceKind = "PROMETHEUS"
    SourceHTTPJSONMetrics SourceKind = "HTTP_JSON_METRICS"
    SourceSQLMetrics      SourceKind = "SQL_METRICS"
    SourcePluginMetrics   SourceKind = "PLUGIN_METRICS"
)
```

`SourcePluginMetrics` contains `PluginID` and named parameter values, never an executable or shell string. `Policy` includes `AgentID`, monotonically increasing `Version`, `IssuedAt`, `ExpiresAt`, `Sources`, and `Limits`.

- [ ] **Step 4: Implement deterministic signing and full validation**

Canonical signing bytes are deterministic JSON over an alias type with source slices sorted by `ID`; reject duplicate IDs before sorting. Verification checks signature, Agent ID, expiry, non-empty sources, limits, allowed source kinds, path confinement, endpoint scheme, collection interval floor of 5 seconds, maximum label count of 32, and plugin registry membership.

- [ ] **Step 5: Run focused and race tests**

Run:

```powershell
go test ./internal/policy -v
go test -race ./internal/policy
```

Expected: both PASS.

- [ ] **Step 6: Commit policy security**

```powershell
git add backend/internal/policy
git commit -m "feat: validate signed telemetry policies"
```

---

### Task 3: Embedded Component Catalog and Policy Compiler

**Files:**
- Create: `backend/internal/telemetry/catalog.go`
- Create: `backend/internal/telemetry/compiler.go`
- Create: `backend/internal/telemetry/compiler_test.go`
- Modify: `backend/go.mod`

**Interfaces:**
- Consumes `policy.Policy` and validated `policy.Source` values.
- Produces `telemetry.NewCatalog() Catalog` containing only approved factories.
- Produces `telemetry.Compile(p policy.Policy, catalog Catalog) (RuntimeConfig, error)`.
- `RuntimeConfig` contains typed receiver, processor, exporter, extension, and pipeline configurations; it does not expose raw YAML.

- [ ] **Step 1: Pin OpenTelemetry v0.158.0 consistently**

Add core and contrib modules at `v0.158.0`. Include only the packages required for `filelog`, `journald`, `hostmetrics`, `prometheus`, `batch`, `memory_limiter`, `filter`, `transform`, and file storage. Mixed Collector release tags fail dependency review.

- [ ] **Step 2: Write failing compiler tests**

```go
func TestCompileBuildsOnlyApprovedComponents(t *testing.T) {
    cfg, err := telemetry.Compile(policyWithFileHostAndPrometheus(), telemetry.NewCatalog())
    require.NoError(t, err)
    assert.ElementsMatch(t,
        []string{"file_log/app", "host_metrics/base", "prometheus/custom"},
        cfg.ReceiverIDs(),
    )
    assert.ElementsMatch(t, []string{"memory_limiter", "batch"}, cfg.ProcessorIDs())
    assert.Equal(t, []string{"dbpilot"}, cfg.ExporterIDs())
}

func TestCatalogDoesNotExposeExecReceiver(t *testing.T) {
    _, ok := telemetry.NewCatalog().ReceiverFactory("exec")
    assert.False(t, ok)
}
```

Also test multiline mapping, journald unit filters, Prometheus TLS/auth mapping, resource labels, memory/spool limits, unknown source rejection, and deterministic component IDs.

- [ ] **Step 3: Run the compiler tests and verify failure**

Run: `go test ./internal/telemetry -run 'TestCompile|TestCatalog' -v`

Expected: FAIL because catalog/compiler types are missing.

- [ ] **Step 4: Implement the closed component catalog**

The catalog constructor registers factory constructors in code. It contains no generic plugin loading, dynamic Go modules, `exec` receiver, scripting receiver, or raw configuration provider.

```go
type Catalog interface {
    ReceiverFactory(name string) (receiver.Factory, bool)
    ProcessorFactory(name string) (processor.Factory, bool)
}
```

- [ ] **Step 5: Implement deterministic policy compilation**

Sort sources by ID, create one receiver instance per source, prepend `memory_limiter`, append `batch`, add DBPilot resource attributes, and bind all log pipelines to `dbpilot/logs` and metric pipelines to `dbpilot/metrics`. Reject a policy that produces zero pipelines.

- [ ] **Step 6: Run tests, dependency consistency, and static import checks**

Run:

```powershell
go test ./internal/telemetry -run 'TestCompile|TestCatalog' -v
go mod tidy
go list -m all
rg 'execreceiver|os/exec|vector.yaml|otel.yaml' internal/telemetry
```

Expected: tests PASS; module list contains one aligned Collector release family; `rg` returns no matches.

- [ ] **Step 7: Commit the compiler slice**

```powershell
git add backend/go.mod backend/go.sum backend/internal/telemetry
git commit -m "feat: compile policies into embedded telemetry pipelines"
```

---

### Task 4: Atomic Telemetry Engine Lifecycle

**Files:**
- Create: `backend/internal/telemetry/engine.go`
- Create: `backend/internal/telemetry/engine_test.go`

**Interfaces:**
- Produces `telemetry.Builder` with `Build(ctx context.Context, cfg RuntimeConfig) (Candidate, error)`.
- Produces `telemetry.Candidate` with `Start`, `Healthy`, `Stop`, and `Version`.
- Produces `telemetry.Engine.Apply(ctx context.Context, p policy.Policy) (ApplyResult, error)`.
- `ApplyResult` contains `Version`, `State` (`ACTIVE`, `REJECTED`, `ROLLED_BACK`), and `ErrorCode`.

- [ ] **Step 1: Write failing lifecycle tests using fake candidates**

Cover first activation, candidate build failure, health-check failure, successful atomic replacement, old pipeline stop only after new health, same-version idempotency, lower-version rejection, and concurrent apply serialization.

```go
func TestApplyKeepsOldPipelineWhenCandidateUnhealthy(t *testing.T) {
    builder := newFakeBuilder(healthyCandidate(1), unhealthyCandidate(2))
    engine := telemetry.NewEngine(builder)
    requireApplyActive(t, engine, policyVersion(1))

    result, err := engine.Apply(context.Background(), policyVersion(2))
    require.Error(t, err)
    assert.Equal(t, telemetry.ApplyRolledBack, result.State)
    assert.Equal(t, int64(1), engine.ActiveVersion())
    assert.False(t, builder.Candidate(1).Stopped())
    assert.True(t, builder.Candidate(2).Stopped())
}
```

- [ ] **Step 2: Run lifecycle tests and verify failure**

Run: `go test ./internal/telemetry -run 'TestApply|TestEngine' -v`

Expected: FAIL because `Engine` is missing.

- [ ] **Step 3: Implement serialized two-phase activation**

`Apply` validates/compiles before taking the short swap lock, starts the candidate, waits for its bounded health check, atomically swaps the active pointer, then stops the old pipeline. On any pre-swap failure, stop the candidate and leave the old pipeline unchanged.

- [ ] **Step 4: Run focused and race tests**

Run:

```powershell
go test ./internal/telemetry -run 'TestApply|TestEngine' -v
go test -race ./internal/telemetry
```

Expected: all PASS.

- [ ] **Step 5: Commit engine lifecycle**

```powershell
git add backend/internal/telemetry
git commit -m "feat: atomically apply telemetry pipelines"
```

---

### Task 5: Safe Custom Metrics Collectors

**Files:**
- Create: `backend/internal/telemetry/custommetrics.go`
- Create: `backend/internal/telemetry/custommetrics_test.go`

**Interfaces:**
- Produces `MetricPoint{Name string, Type MetricType, Value float64, Timestamp time.Time, Labels map[string]string}`.
- Produces `HTTPCollector.Collect(ctx context.Context, spec policy.HTTPJSONMetricSpec) ([]MetricPoint, error)`.
- Produces `SQLCollector.Collect(ctx context.Context, queryer ReadOnlyQueryer, spec policy.SQLMetricSpec) ([]MetricPoint, error)`.
- Produces `PluginCollector.Collect(ctx context.Context, registry PluginRegistry, spec policy.PluginMetricSpec) ([]MetricPoint, error)`.
- `ReadOnlyQueryer.Query(ctx context.Context, statement string, maxRows int) ([]map[string]any, error)`.
- `PluginRegistry.Resolve(pluginID string) (RegisteredPlugin, error)`; `RegisteredPlugin` owns the fixed executable, signature digest, allowed parameter names, timeout, and output decoder.

- [ ] **Step 1: Write failing safety tests**

Test HTTPS-only HTTP endpoints by default, response-size limit, invalid numeric mapping, SQL comment/multi-statement/write keyword rejection, timeout propagation, row limit, unknown plugin, extra plugin parameter, plugin digest mismatch, output limit, label-count limit, and metric-name validation.

```go
func TestSQLCollectorRejectsMultipleStatements(t *testing.T) {
    spec := policy.SQLMetricSpec{Statement: "SELECT 1; DROP TABLE users"}
    _, err := telemetry.NewSQLCollector().Collect(context.Background(), fakeQueryer{}, spec)
    require.ErrorIs(t, err, telemetry.ErrUnsafeSQLMetric)
}

func TestPluginPolicyCannotSelectExecutable(t *testing.T) {
    registry := fakeRegistryWith("disk-check", "/usr/libexec/dbpilot/disk-check")
    spec := policy.PluginMetricSpec{PluginID: "../../bin/sh"}
    _, err := telemetry.NewPluginCollector().Collect(context.Background(), registry, spec)
    require.ErrorIs(t, err, telemetry.ErrUnknownPlugin)
}
```

- [ ] **Step 2: Run custom metric tests and verify failure**

Run: `go test ./internal/telemetry -run 'HTTPCollector|SQLCollector|Plugin' -v`

Expected: FAIL because collectors are missing.

- [ ] **Step 3: Implement HTTP and SQL collectors with hard limits**

HTTP uses an injected `http.Client`, rejects redirects outside the approved host, limits the response body, and maps only configured numeric JSON paths. SQL strips comments for analysis, accepts exactly one statement beginning with `SELECT` or `WITH`, rejects known write/DDL/control keywords, and still relies on a read-only database account and database timeout as defense in depth.

- [ ] **Step 4: Implement the registered plugin collector**

Only the local registry supplies the executable. Construct `exec.CommandContext` with a fixed executable and individually encoded allowed arguments; never invoke a shell. Clear the environment, add only registry-approved variables, verify the executable SHA-256 before every launch, limit stdout/stderr, and decode Prometheus text or strict JSON according to the registry entry.

- [ ] **Step 5: Run tests and verify there is no shell invocation**

Run:

```powershell
go test ./internal/telemetry -run 'HTTPCollector|SQLCollector|Plugin' -v
rg 'sh -c|bash -c|cmd /c|powershell' internal/telemetry
```

Expected: tests PASS and `rg` returns no matches.

- [ ] **Step 6: Commit custom metrics**

```powershell
git add backend/internal/telemetry backend/internal/policy
git commit -m "feat: collect bounded custom metrics safely"
```

---

### Task 6: Durable State and Bounded Segment Spool

**Files:**
- Create: `backend/internal/spool/state.go`
- Create: `backend/internal/spool/segments.go`
- Create: `backend/internal/spool/spool_test.go`

**Interfaces:**
- Produces `spool.Open(root string, limits Limits) (*Store, error)`.
- Produces `Store.PutPolicy(envelope policy.SignatureEnvelope) error`, `Store.ActivePolicy() (policy.SignatureEnvelope, error)`, `Store.PutCheckpoint(sourceID string, value []byte) error`, and `Store.Checkpoint(sourceID string) ([]byte, error)`.
- Produces `Store.Append(ctx context.Context, class DataClass, batch Batch) error`.
- Produces `Store.Pending(ctx context.Context, class DataClass, limit int) ([]Batch, error)`.
- Produces `Store.Ack(ctx context.Context, class DataClass, batchID string) error`.
- `Batch` contains `ID string`, `SourceID string`, `CreatedAt time.Time`, `Priority int`, `Payload []byte`, and `Checksum uint32`.
- Data classes are `LOG`, `AUDIT_LOG`, `METRIC`, and `JOB_RESULT`; only `AUDIT_LOG` is non-droppable.

- [ ] **Step 1: Write failing state and recovery tests**

Cover policy/checkpoint persistence, reopen recovery, append order, CRC corruption quarantine, ACK deletion, duplicate batch idempotency, segment rotation, metric eviction at capacity, non-audit log eviction according to priority, audit capacity rejection with health finding, and invalid root path rejection.

```go
func TestAuditBatchIsNeverSilentlyEvicted(t *testing.T) {
    store := openTestStore(t, spool.Limits{MaxBytes: 1024, SegmentBytes: 512})
    require.NoError(t, store.Append(ctx, spool.AuditLog, batchOfSize("a1", 700)))
    err := store.Append(ctx, spool.AuditLog, batchOfSize("a2", 700))
    require.ErrorIs(t, err, spool.ErrAuditCapacity)
    assert.Contains(t, store.HealthFindings(), spool.FindingAuditSpoolFull)
}
```

- [ ] **Step 2: Run spool tests and verify failure**

Run: `go test ./internal/spool -v`

Expected: FAIL because the spool package does not exist.

- [ ] **Step 3: Implement bbolt state with narrow buckets**

Create buckets `agent_state`, `policy_state`, `checkpoints`, `segment_index`, and `dedup`. Store only metadata and bounded values. Validate that `root` is non-empty, absolute, not a filesystem root, and owned/created with restrictive permissions on Linux.

- [ ] **Step 4: Implement the segment record format and recovery**

Each record is `[magic][version][header length][payload length][header JSON][payload][CRC32C]`. Write to a temporary active segment, `fsync`, then atomically rename sealed segments. On open, scan records, truncate only an incomplete final record, quarantine checksum-corrupt sealed segments, rebuild missing indexes, and emit a health finding.

- [ ] **Step 5: Implement capacity policy and ACK cleanup**

Evict delivered segments first, then oldest low-priority metrics, then oldest non-audit logs. Never evict an unacknowledged audit batch. `Ack` is idempotent and removes a sealed segment only after every record in it is acknowledged.

- [ ] **Step 6: Run focused, race, and filesystem tests**

Run:

```powershell
go test ./internal/spool -v
go test -race ./internal/spool
```

Expected: all PASS.

- [ ] **Step 7: Commit durable spool**

```powershell
git add backend/internal/spool backend/go.mod backend/go.sum
git commit -m "feat: persist bounded agent telemetry spool"
```

---

### Task 7: Acknowledged mTLS Exporter and Test Ingest Service

**Files:**
- Create: `backend/internal/exporter/client.go`
- Create: `backend/internal/exporter/client_test.go`
- Create: `backend/internal/ingest/service.go`
- Create: `backend/internal/ingest/service_test.go`
- Modify: `backend/cmd/telemetry-test-gateway/main.go`

**Interfaces:**
- Produces `exporter.Client.SendPending(ctx context.Context) error`.
- Produces `exporter.NewClient(api telemetryv1.TelemetryIngestClient, store PendingStore, agentID string) *Client`.
- `PendingStore` provides `Pending(ctx context.Context, class spool.DataClass, limit int) ([]spool.Batch, error)`, `Ack(ctx context.Context, class spool.DataClass, batchID string) error`, and `RecordHealthFinding(code string, detail string)`.
- Produces `ingest.NewService(identities AgentIdentityResolver, dedup BatchDeduplicator) *Service` implementing `TelemetryIngestServer`.
- Authenticated Agent identity comes from the verified client certificate URI `spiffe://dbpilot/agent/{agentID}`.

- [ ] **Step 1: Write failing exporter/service tests**

Cover certificate Agent mismatch, unknown Agent, checksum mismatch, duplicate batch idempotency, accepted ACK causing local ACK, retryable rejection retaining the batch, permanent rejection retaining/quarantining with health finding, upload oldest-first, cancellation, and bounded exponential backoff.

```go
func TestIngestRejectsClaimedAgentMismatch(t *testing.T) {
    ctx := contextWithSPIFFEAgent("agent-a")
    _, err := service.PushLogBatch(ctx, &telemetryv1.LogBatch{
        BatchId: "b1", AgentId: "agent-b", Payload: []byte("x"),
    })
    require.Error(t, err)
    assert.Equal(t, codes.PermissionDenied, status.Code(err))
}
```

- [ ] **Step 2: Run tests and verify failure**

Run: `go test ./internal/exporter ./internal/ingest -v`

Expected: FAIL because implementations are missing.

- [ ] **Step 3: Implement gateway identity and batch validation**

Extract the SPIFFE URI only from gRPC peer TLS state, ignore forwarded identity headers, compare it with the message Agent ID, verify checksum and size, and return the same accepted ACK for a duplicate batch ID belonging to the same Agent.

- [ ] **Step 4: Implement ordered acknowledged export**

Read pending batches oldest-first, send one bounded batch at a time, ACK local state only when `accepted=true`, back off retryable transport/service errors up to 30 seconds, and surface permanent rejection as a health finding without a tight retry loop.

- [ ] **Step 5: Wire a test-only mTLS gateway binary**

The gateway requires explicit CA, server certificate, server key, and listen flags. It binds loopback by default, verifies client certificates, and stores received batch metadata in memory only. It must refuse plaintext mode.

- [ ] **Step 6: Run tests and Linux builds**

Run:

```powershell
go test ./internal/exporter ./internal/ingest -v
go test -race ./internal/exporter ./internal/ingest
$env:CGO_ENABLED='0'; $env:GOOS='linux'; $env:GOARCH='amd64'; $env:GOAMD64='v1'
go build ./cmd/telemetry-test-gateway
```

Expected: all PASS.

- [ ] **Step 7: Commit exporter and ingest service**

```powershell
git add backend/internal/exporter backend/internal/ingest backend/cmd/telemetry-test-gateway
git commit -m "feat: export acknowledged telemetry over mTLS"
```

---

### Task 8: Agent Runtime, Packaging, and End-to-End Linux Verification

**Files:**
- Create: `backend/internal/agent/runtime.go`
- Create: `backend/internal/agent/runtime_test.go`
- Modify: `backend/cmd/agent/main.go`
- Create: `backend/packaging/systemd/dbpilot-agent.service`
- Create: `backend/packaging/config/agent.yaml.example`
- Create: `backend/scripts/build-linux.ps1`
- Create: `backend/test/e2e/telemetry_lifecycle_test.go`
- Create: `backend/README.md`

**Interfaces:**
- Produces `agent.Runtime.Run(ctx context.Context) error`.
- Runtime consumes `PolicySource`, `PolicyVerifier`, `telemetry.Engine`, `spool.Store`, `exporter.Client`, and `HealthReporter` interfaces.
- Produces signed release artifacts `dbpilot-agent-linux-amd64` and `dbpilot-agent-linux-arm64` plus SHA-256 checksum files.

- [ ] **Step 1: Write failing runtime tests**

Cover startup from last valid policy, remote newer policy activation, invalid policy rejection/status report, failed candidate rollback/status report, exporter retry without stopping collectors, SIGTERM cancellation, and shutdown order: stop receivers, seal spool, attempt bounded flush, close state.

```go
func TestRuntimeStartsFromLastValidPolicyWhileServerUnavailable(t *testing.T) {
    deps := runtimeDepsWithStoredPolicy(policyVersion(7))
    deps.PolicySource.Err = status.Error(codes.Unavailable, "offline")
    runtime := agent.NewRuntime(deps)
    cancelAfterEngineStarts(runtime)
    require.NoError(t, runtime.Run(context.Background()))
    assert.Equal(t, int64(7), deps.Engine.ActiveVersion())
}
```

- [ ] **Step 2: Run runtime tests and verify failure**

Run: `go test ./internal/agent -v`

Expected: FAIL because `Runtime` is missing.

- [ ] **Step 3: Implement cancellation-safe runtime supervision**

Load and verify stored policy, start the engine, run policy polling, health reporting, and spool exporting in separate bounded loops under one cancellation context, and return a typed startup error when no valid stored or remote policy exists. Runtime must not expose a public local administration listener.

- [ ] **Step 4: Wire the Agent binary and restrictive example configuration**

Required configuration fields are Agent ID, Server address, CA/cert/key paths, policy public key path, data directory, and allowed log roots. Reject relative secret/data paths, missing TLS material, world-writable data directories on Linux, and an empty allowed-root list when file collection is enabled.

- [ ] **Step 5: Add systemd unit and deterministic cross-build script**

The service runs as `dbpilot`, uses `NoNewPrivileges=true`, `PrivateTmp=true`, `ProtectSystem=strict`, writable path `/var/lib/dbpilot-agent`, configuration `/etc/dbpilot/agent.yaml`, restart-on-failure, and an explicit file descriptor limit. Journald access is granted by group/ACL outside the process; do not run as root.

`build-linux.ps1` sets `CGO_ENABLED=0`, builds amd64 with `GOAMD64=v1`, builds arm64, injects version/commit through linker flags, emits SHA-256 files, and fails if the output directory is empty, relative, or a filesystem root.

- [ ] **Step 6: Write the end-to-end telemetry lifecycle test**

The test creates a temporary CA and Agent certificate, starts an mTLS ingest service on a random loopback port, signs a policy containing a temporary file source and host metrics source, starts one runtime, appends and rotates the log file, simulates one failed upload, restores the gateway, and asserts:

- policy status becomes `ACTIVE`;
- log and metric batches contain the authenticated Agent ID;
- rotated file content is delivered once;
- the failed batch survives runtime restart;
- accepted batches are removed from the spool;
- no raw Vector/OTel configuration or arbitrary executable appears in the policy surface.

- [ ] **Step 7: Run full verification**

Run:

```powershell
buf lint
buf generate
go test ./...
go test -race ./internal/...
go vet ./...
rg 'vector|otelcol' packaging cmd/agent
powershell -File scripts/build-linux.ps1 -OutputDirectory .\bin -Version 0.1.0-test
```

Expected: lint, generation, tests, race tests, vet, and both Linux builds PASS; `rg` finds no runtime dependency or service entry for Vector/standalone Collector. Run the Linux-only journald integration test on dedicated CentOS 7, Kylin V10 x86_64, and Kylin V10 arm64 VM runners so systemd and journal permissions are real.

- [ ] **Step 8: Document operator behavior and compatibility evidence**

`backend/README.md` documents installation, directories, permissions, journald group/ACL, signed policy flow, supported source kinds, spool capacity behavior, health findings, mTLS setup, upgrade/rollback, and the exact CentOS 7/Kylin V10 amd64/arm64 smoke-test commands and recorded results.

- [ ] **Step 9: Commit the verified Agent foundation**

```powershell
git add backend/internal/agent backend/cmd/agent backend/packaging backend/scripts backend/test backend/README.md
git commit -m "feat: complete embedded agent telemetry foundation"
```

---

## Follow-Up Implementation Plans

Write these as separate plans after this foundation passes review:

1. **Secure Agent Control Plane:** enrollment, certificate rotation, heartbeat, typed jobs, approvals, audit trail, PostgreSQL Outbox, cancellation and result reporting.
2. **Database Adapter Foundation:** capability matrix plus MySQL, PostgreSQL and Oracle connection, metadata, metrics, log templates and read-only SQL metrics.
3. **Central Telemetry Storage:** production Log/Metrics Ingest Gateway, ClickHouse schema, VictoriaMetrics write path, S3 archive, retention and tenant isolation.
4. **Remaining Database Adapters:** MariaDB, Dameng, OceanBase, HBase, Neo4j, MongoDB, TiDB and openGauss in capability-based waves.
5. **Unified Web Management:** Agent inventory, policy editor, validation preview, rollout status, health findings and collection diagnostics.
