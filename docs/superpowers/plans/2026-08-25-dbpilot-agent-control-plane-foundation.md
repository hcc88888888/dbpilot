# DBPilot Agent Control Plane Foundation Implementation Plan

> **Superseded on 2026-08-26:** Agent architecture was revised to a single-process, single-binary design with an embedded OpenTelemetry-based telemetry engine, operating-system and custom log collection, custom metrics, segment spool storage, and CentOS 7 / Kylin V10 compatibility requirements. Do not execute this plan further. A replacement plan will be written after the revised specifications are approved.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a testable vertical slice in which a DBPilot Agent registers, sends heartbeats and capabilities, receives a signed structured job, executes it through a safe handler, and reports an auditable result.

**Architecture:** A single Go module contains separate `control-plane` and `agent` binaries plus focused internal packages. The first slice uses gRPC with development TLS, PostgreSQL-compatible repository interfaces backed by an in-memory implementation for tests, and a typed command registry that cannot execute arbitrary shell strings.

**Tech Stack:** Go 1.24+, gRPC, Protobuf, buf, standard `crypto/tls` and `crypto/ed25519`, `testify`, SQLite only in the Agent spool task.

**Spec:** `docs/superpowers/specs/2026-08-25-dbpilot-agent-platform-design.md` and `docs/superpowers/specs/2026-08-25-dbpilot-platform-integration-design.md`

## Global Constraints

- DBPilot remains the sole source of truth for Agent identity, instance capability, jobs, approvals and audit events.
- Agent communication uses gRPC with mutual TLS; development certificates are generated only for local tests.
- Agent accepts typed commands only and never executes an arbitrary shell string.
- Every job carries a unique ID, target, expiry, signature, requester and optional approval reference.
- High-risk operations cannot execute without a valid approval reference.
- Internal packages expose DBPilot-owned contracts and do not leak third-party product schemas.
- Current workspace has no Go toolchain and is not a Git repository; execution begins by installing Go 1.24+ and initializing Git.

---

## Planned File Structure

```text
backend/
├── go.mod
├── buf.yaml
├── buf.gen.yaml
├── api/agent/v1/agent.proto
├── gen/agent/v1/agent.pb.go
├── gen/agent/v1/agent_grpc.pb.go
├── cmd/control-plane/main.go
├── cmd/agent/main.go
├── internal/agent/client.go
├── internal/agent/executor.go
├── internal/agent/handlers.go
├── internal/agent/spool.go
├── internal/controlplane/server.go
├── internal/controlplane/service.go
├── internal/domain/agent.go
├── internal/domain/job.go
├── internal/domain/audit.go
├── internal/repository/interfaces.go
├── internal/repository/memory.go
├── internal/security/certificates.go
└── internal/security/signatures.go
```

`domain` owns stable business types; `repository` owns persistence ports; `controlplane` owns registration and dispatch; `agent` owns local execution and buffering; `security` owns certificate and signature primitives.

---

### Task 1: Go Module, Protobuf Contract, and Health Binaries

**Files:**
- Create: `backend/go.mod`
- Create: `backend/buf.yaml`
- Create: `backend/buf.gen.yaml`
- Create: `backend/api/agent/v1/agent.proto`
- Create: `backend/cmd/control-plane/main.go`
- Create: `backend/cmd/agent/main.go`
- Test: `backend/api/agent/v1/contract_test.go`

**Interfaces:**
- Produces: protobuf service `AgentControl` with `Register`, `Heartbeat`, `PollJob`, and `ReportJobResult` RPCs.
- Produces: messages `RegisterRequest`, `RegisterResponse`, `HeartbeatRequest`, `HeartbeatResponse`, `JobEnvelope`, and `JobResult`.

- [ ] **Step 1: Initialize version control and the Go module**

Run:

```powershell
git init
New-Item -ItemType Directory -Force backend
Set-Location backend
go mod init dbpilot.local/platform
```

Expected: `backend/go.mod` declares `module dbpilot.local/platform`.

- [ ] **Step 2: Write the protobuf contract test**

Create `backend/api/agent/v1/contract_test.go` that reads `agent.proto` and asserts the contract contains all four RPC names plus the `expires_at_unix`, `signature`, `approval_ref`, and `capabilities` fields.

```go
func TestAgentContractContainsRequiredOperations(t *testing.T) {
    body, err := os.ReadFile("agent.proto")
    require.NoError(t, err)
    text := string(body)
    for _, required := range []string{"rpc Register", "rpc Heartbeat", "rpc PollJob", "rpc ReportJobResult", "expires_at_unix", "signature", "approval_ref", "capabilities"} {
        assert.Contains(t, text, required)
    }
}
```

- [ ] **Step 3: Run the contract test and verify failure**

Run: `go test ./api/agent/v1 -v`

Expected: FAIL because `agent.proto` does not exist.

- [ ] **Step 4: Define `AgentControl` and messages**

Define `agent.proto` using `proto3`, package `dbpilot.agent.v1`, and Go package `dbpilot.local/platform/gen/agent/v1;agentv1`. `JobEnvelope` must include string fields `job_id`, `type`, `target_id`, `payload_json`, `requested_by`, `approval_ref`, bytes `signature`, and int64 `expires_at_unix`. `HeartbeatRequest` must include `agent_id`, `version`, repeated string `capabilities`, and int64 `sent_at_unix`.

- [ ] **Step 5: Generate and compile protobuf code**

Run:

```powershell
buf lint
buf generate
go mod tidy
go test ./api/agent/v1 -v
go build ./cmd/control-plane ./cmd/agent
```

Expected: lint, test and both builds PASS.

- [ ] **Step 6: Commit the contract slice**

```powershell
git add backend
git commit -m "feat: define DBPilot agent control contract"
```

---

### Task 2: Domain Models and Job State Machine

**Files:**
- Create: `backend/internal/domain/agent.go`
- Create: `backend/internal/domain/job.go`
- Create: `backend/internal/domain/audit.go`
- Test: `backend/internal/domain/job_test.go`

**Interfaces:**
- Produces: `domain.Agent`, `domain.Job`, `domain.JobStatus`, `domain.RiskLevel`, and `domain.AuditEvent`.
- Produces: `func (j *Job) Transition(to JobStatus, at time.Time) error`.
- Produces statuses: `PENDING`, `APPROVING`, `DISPATCHED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELED`, `EXPIRED`.

- [ ] **Step 1: Write failing state transition tests**

Test valid `PENDING → DISPATCHED → RUNNING → SUCCEEDED`, invalid `PENDING → SUCCEEDED`, and expiration from a non-terminal state.

```go
func TestJobRejectsSkippedTransition(t *testing.T) {
    job := domain.Job{ID: "job-1", Status: domain.JobPending}
    err := job.Transition(domain.JobSucceeded, time.Now())
    require.ErrorIs(t, err, domain.ErrInvalidTransition)
}
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `go test ./internal/domain -v`

Expected: FAIL because the domain package does not exist.

- [ ] **Step 3: Implement focused domain files**

Implement the explicit transition map in `job.go`. Define `RiskRead`, `RiskWrite`, and `RiskCritical`; jobs with `RiskWrite` or `RiskCritical` require a non-empty `ApprovalRef` before dispatch. Keep JSON and transport concerns out of domain types.

- [ ] **Step 4: Run the domain tests**

Run: `go test ./internal/domain -v`

Expected: PASS.

- [ ] **Step 5: Commit the domain slice**

```powershell
git add backend/internal/domain
git commit -m "feat: add agent and job domain models"
```

---

### Task 3: Repository Ports and Deterministic Memory Repository

**Files:**
- Create: `backend/internal/repository/interfaces.go`
- Create: `backend/internal/repository/memory.go`
- Test: `backend/internal/repository/memory_test.go`

**Interfaces:**
- Consumes: `domain.Agent`, `domain.Job`, `domain.AuditEvent`.
- Produces: `AgentRepository`, `JobRepository`, and `AuditRepository` interfaces.
- Produces: `NewMemoryStore() *MemoryStore` implementing all three interfaces.

- [ ] **Step 1: Write failing repository tests**

Cover agent upsert, heartbeat update, atomic next-job claim, duplicate job rejection, and immutable audit append.

```go
func TestClaimNextJobIsAtomic(t *testing.T) {
    store := repository.NewMemoryStore()
    require.NoError(t, store.CreateJob(ctx, domain.Job{ID: "job-1", TargetAgentID: "agent-1", Status: domain.JobPending}))
    first, err := store.ClaimNextJob(ctx, "agent-1", now)
    require.NoError(t, err)
    assert.Equal(t, domain.JobDispatched, first.Status)
    _, err = store.ClaimNextJob(ctx, "agent-1", now)
    require.ErrorIs(t, err, repository.ErrNotFound)
}
```

- [ ] **Step 2: Run repository tests to verify failure**

Run: `go test ./internal/repository -v`

Expected: FAIL because repository types do not exist.

- [ ] **Step 3: Implement ports and the mutex-protected store**

Return copies of stored values so callers cannot mutate repository state. Sort pending jobs by `CreatedAt` and then `ID` to make claims deterministic. Reject duplicate IDs with `ErrConflict`.

- [ ] **Step 4: Run repository and race tests**

Run:

```powershell
go test ./internal/repository -v
go test -race ./internal/repository
```

Expected: both PASS.

- [ ] **Step 5: Commit the repository slice**

```powershell
git add backend/internal/repository
git commit -m "feat: add control plane repository ports"
```

---

### Task 4: Enrollment, Certificates, and Job Signatures

**Files:**
- Create: `backend/internal/security/certificates.go`
- Create: `backend/internal/security/signatures.go`
- Test: `backend/internal/security/certificates_test.go`
- Test: `backend/internal/security/signatures_test.go`

**Interfaces:**
- Produces: `IssueAgentCertificate(ca *x509.Certificate, caKey crypto.Signer, agentID string, ttl time.Duration) (certPEM, keyPEM []byte, err error)`.
- Produces: `SignJob(private ed25519.PrivateKey, job domain.Job) ([]byte, error)`.
- Produces: `VerifyJob(public ed25519.PublicKey, job domain.Job, signature []byte, now time.Time) error`.

- [ ] **Step 1: Write failing certificate and signature tests**

Test certificate subject and expiry, valid signature, changed payload rejection, expired job rejection, and missing approval rejection for write risk.

```go
func TestVerifyJobRejectsPayloadMutation(t *testing.T) {
    pub, priv, err := ed25519.GenerateKey(rand.Reader)
    require.NoError(t, err)
    job := validReadJob()
    sig, err := security.SignJob(priv, job)
    require.NoError(t, err)
    job.PayloadJSON = `{"sql":"DROP TABLE orders"}`
    require.ErrorIs(t, security.VerifyJob(pub, job, sig, time.Now()), security.ErrInvalidSignature)
}
```

- [ ] **Step 2: Run security tests to verify failure**

Run: `go test ./internal/security -v`

Expected: FAIL because implementations do not exist.

- [ ] **Step 3: Implement canonical signing and certificate issuance**

Canonical signing bytes must concatenate length-prefixed `ID`, `Type`, `TargetAgentID`, `PayloadJSON`, `RequestedBy`, `ApprovalRef`, risk level and Unix expiry. Certificate SAN must contain the Agent ID as a URI `spiffe://dbpilot/agent/{agentID}`.

- [ ] **Step 4: Run security tests**

Run: `go test ./internal/security -v`

Expected: PASS.

- [ ] **Step 5: Commit the security slice**

```powershell
git add backend/internal/security
git commit -m "feat: secure agent enrollment and signed jobs"
```

---

### Task 5: Control Plane Registration, Heartbeat, and Dispatch Service

**Files:**
- Create: `backend/internal/controlplane/service.go`
- Create: `backend/internal/controlplane/server.go`
- Modify: `backend/cmd/control-plane/main.go`
- Test: `backend/internal/controlplane/service_test.go`

**Interfaces:**
- Consumes: repository ports and security functions.
- Produces: `NewService(deps Dependencies) *Service`.
- Produces: gRPC `Register`, `Heartbeat`, `PollJob`, and `ReportJobResult` implementations.

- [ ] **Step 1: Write failing service tests**

Cover invalid enrollment token, successful registration, unknown Agent heartbeat, capability replacement, signed dispatch, result transition and audit creation.

```go
func TestHeartbeatReplacesCapabilities(t *testing.T) {
    svc, store := newTestService(t)
    registerAgent(t, svc, "agent-1")
    _, err := svc.Heartbeat(ctx, &agentv1.HeartbeatRequest{AgentId: "agent-1", Version: "0.1.0", Capabilities: []string{"host.metrics", "mysql.explain"}})
    require.NoError(t, err)
    saved, err := store.GetAgent(ctx, "agent-1")
    require.NoError(t, err)
    assert.ElementsMatch(t, []string{"host.metrics", "mysql.explain"}, saved.Capabilities)
}
```

- [ ] **Step 2: Run control-plane tests to verify failure**

Run: `go test ./internal/controlplane -v`

Expected: FAIL because the service is missing.

- [ ] **Step 3: Implement the service and transport mapping**

Registration consumes a one-time token from an in-memory token store and returns Agent ID plus certificate material. Heartbeat updates `LastSeenAt`, version and capabilities. Polling claims one job, signs it and writes a `job.dispatched` audit event. Result reporting verifies the Agent identity matches the job target before applying the terminal state.

- [ ] **Step 4: Add a TLS gRPC server entry point**

`cmd/control-plane/main.go` must load CA, server certificate, signing key and listen address from flags. It must require and verify Agent client certificates for all RPCs except initial registration, which is exposed on a separate enrollment listener.

- [ ] **Step 5: Run tests and builds**

Run:

```powershell
go test ./internal/controlplane -v
go test ./...
go build ./cmd/control-plane
```

Expected: all PASS.

- [ ] **Step 6: Commit the control-plane slice**

```powershell
git add backend/internal/controlplane backend/cmd/control-plane
git commit -m "feat: register agents and dispatch signed jobs"
```

---

### Task 6: Typed Agent Executor

**Files:**
- Create: `backend/internal/agent/executor.go`
- Create: `backend/internal/agent/handlers.go`
- Test: `backend/internal/agent/executor_test.go`

**Interfaces:**
- Consumes: verified `domain.Job`.
- Produces: `type Handler func(context.Context, json.RawMessage) (json.RawMessage, error)`.
- Produces: `NewExecutor(verifier JobVerifier, handlers map[string]Handler) *Executor`.
- Produces: built-in handlers `TEST_CONNECTION` and `COLLECT_HOST_INFO` using injected interfaces rather than shell commands.

- [ ] **Step 1: Write failing executor tests**

Cover unknown command rejection, invalid signature rejection, expired job rejection, context timeout, output-size limit and successful typed handler execution.

```go
func TestExecutorNeverFallsBackToShell(t *testing.T) {
    exec := agent.NewExecutor(acceptingVerifier{}, map[string]agent.Handler{})
    _, err := exec.Execute(ctx, domain.Job{ID: "job-1", Type: "sh -c whoami"})
    require.ErrorIs(t, err, agent.ErrUnsupportedCommand)
}
```

- [ ] **Step 2: Run Agent tests to verify failure**

Run: `go test ./internal/agent -run Executor -v`

Expected: FAIL because the executor does not exist.

- [ ] **Step 3: Implement the command registry and limits**

Executor must verify before handler lookup, derive a timeout context from the job, limit the serialized result to 1 MiB, and return stable error codes `INVALID_SIGNATURE`, `EXPIRED`, `UNSUPPORTED_COMMAND`, `TIMEOUT`, `OUTPUT_LIMIT`, and `HANDLER_FAILED`.

- [ ] **Step 4: Implement two safe handlers**

`TEST_CONNECTION` calls an injected `ConnectionTester.Test(ctx, instanceID)` interface. `COLLECT_HOST_INFO` calls an injected `HostInfoCollector.Collect(ctx)` interface. Neither handler may import `os/exec`.

- [ ] **Step 5: Run tests and static import check**

Run:

```powershell
go test ./internal/agent -v
rg 'os/exec' internal/agent
```

Expected: tests PASS and `rg` returns no matches.

- [ ] **Step 6: Commit the executor slice**

```powershell
git add backend/internal/agent
git commit -m "feat: execute signed typed agent commands"
```

---

### Task 7: Agent Client, Heartbeat Loop, and Result Reporting

**Files:**
- Create: `backend/internal/agent/client.go`
- Modify: `backend/cmd/agent/main.go`
- Test: `backend/internal/agent/client_test.go`

**Interfaces:**
- Consumes: generated `AgentControlClient` and `Executor`.
- Produces: `Client.Run(ctx context.Context) error`.
- Produces configuration fields `AgentID`, `Version`, `HeartbeatInterval`, `PollInterval`, `Capabilities`, and TLS certificate paths.

- [ ] **Step 1: Write failing client loop tests with a fake clock**

Verify immediate heartbeat, periodic heartbeat, polling, execution, result report, server-unavailable backoff, and graceful cancellation.

```go
func TestClientReportsExecutorResult(t *testing.T) {
    api := newFakeAgentControl(jobEnvelope("job-1", "COLLECT_HOST_INFO"))
    client := newTestClient(api, successfulExecutor())
    cancelAfterOneJob(client)
    require.NoError(t, client.Run(ctx))
    require.Len(t, api.results, 1)
    assert.Equal(t, "job-1", api.results[0].JobId)
}
```

- [ ] **Step 2: Run client tests to verify failure**

Run: `go test ./internal/agent -run Client -v`

Expected: FAIL because `Client` does not exist.

- [ ] **Step 3: Implement the cancellation-safe loop**

Use separate tickers for heartbeat and polling, exponential backoff capped at 30 seconds for transport failures, and no retry for rejected jobs. Stop tickers and return `nil` on context cancellation.

- [ ] **Step 4: Wire the Agent binary**

`cmd/agent/main.go` loads Agent ID, certificates, server address and intervals from flags, constructs the gRPC client and executor, handles `SIGINT`/`SIGTERM`, and exits non-zero on startup configuration errors.

- [ ] **Step 5: Run tests and race detector**

Run:

```powershell
go test ./internal/agent -v
go test -race ./internal/agent
go build ./cmd/agent
```

Expected: all PASS.

- [ ] **Step 6: Commit the Agent client slice**

```powershell
git add backend/internal/agent backend/cmd/agent
git commit -m "feat: add agent heartbeat and job loop"
```

---

### Task 8: Durable Agent Spool and Offline Safety

**Files:**
- Create: `backend/internal/agent/spool.go`
- Test: `backend/internal/agent/spool_test.go`
- Modify: `backend/internal/agent/client.go`

**Interfaces:**
- Produces: `OpenSpool(path string, maxBytes int64) (*Spool, error)`.
- Produces: `AppendResult`, `PendingResults`, `MarkDelivered`, and `Close`.
- Consumes: `JobResult` reports from Task 7.

- [ ] **Step 1: Write failing durability tests**

Test reopen persistence, ordered delivery, delivery acknowledgement, capacity rejection and that pending jobs are never stored for offline execution.

```go
func TestSpoolPersistsResultsAcrossRestart(t *testing.T) {
    path := filepath.Join(t.TempDir(), "agent-spool.db")
    spool, err := agent.OpenSpool(path, 8<<20)
    require.NoError(t, err)
    require.NoError(t, spool.AppendResult(ctx, result("job-1")))
    require.NoError(t, spool.Close())
    reopened, err := agent.OpenSpool(path, 8<<20)
    require.NoError(t, err)
    pending, err := reopened.PendingResults(ctx, 10)
    require.NoError(t, err)
    assert.Equal(t, "job-1", pending[0].JobID)
}
```

- [ ] **Step 2: Run spool tests to verify failure**

Run: `go test ./internal/agent -run Spool -v`

Expected: FAIL because `Spool` is missing.

- [ ] **Step 3: Implement SQLite result spool**

Use a single `results` table keyed by job ID with created time, serialized payload and delivered flag. Enforce the configured file-size limit before append. Do not define any table for pending executable jobs.

- [ ] **Step 4: Integrate result retry**

Persist the result before network reporting; on successful report mark it delivered. At Agent startup, send stored results oldest-first before polling for new jobs.

- [ ] **Step 5: Run Agent tests**

Run: `go test ./internal/agent -v`

Expected: PASS.

- [ ] **Step 6: Commit the spool slice**

```powershell
git add backend/internal/agent
git commit -m "feat: persist agent results during outages"
```

---

### Task 9: End-to-End Secure Job Test and Operator Documentation

**Files:**
- Create: `backend/test/e2e/agent_job_test.go`
- Create: `backend/README.md`
- Create: `backend/scripts/dev-certs.ps1`

**Interfaces:**
- Consumes: both binaries and all contracts from Tasks 1–8.
- Produces: reproducible local command sequence and an end-to-end test proving registration through audited result.

- [ ] **Step 1: Write the failing end-to-end test**

The test must create a temporary CA, start enrollment and mTLS gRPC servers on random loopback ports, register an Agent, create a signed `COLLECT_HOST_INFO` job, run one Agent cycle, and assert `SUCCEEDED` plus audit events `agent.registered`, `job.dispatched`, and `job.completed` sharing the same trace ID.

- [ ] **Step 2: Run the end-to-end test to verify failure**

Run: `go test ./test/e2e -run TestAgentJobLifecycle -v`

Expected: FAIL until test harness wiring is complete.

- [ ] **Step 3: Complete the local harness and certificate script**

`dev-certs.ps1` generates a local CA, server certificate and signing keys under an explicitly supplied output directory. It must refuse an empty path or filesystem root and must never overwrite an existing private key without `-Force`.

- [ ] **Step 4: Document setup and safety boundaries**

`backend/README.md` must include Go/buf prerequisites, generation commands, test commands, local startup commands, RPC overview, supported typed commands and an explicit statement that arbitrary shell execution is unsupported.

- [ ] **Step 5: Run the full verification suite**

Run:

```powershell
buf lint
buf breaking --against '.git#branch=main'
go test ./...
go test -race ./internal/...
go vet ./...
go build ./cmd/...
```

Expected: every command PASS. If the repository has no `main` branch baseline yet, run `buf breaking` after the first contract commit establishes one.

- [ ] **Step 6: Commit the verified vertical slice**

```powershell
git add backend
git commit -m "test: verify secure agent job lifecycle"
```

---

## Follow-Up Plans

Create separate plans after this foundation passes:

1. MySQL, PostgreSQL and Oracle Adapter capability plan.
2. Metrics pipeline with OTLP/Remote Write and VictoriaMetrics.
3. Unified IAM, Policy Service and approval workflow persistence.
4. SQL Review Service using SQLFluff and SQLGlot.
5. React application shell and module-specific frontends.

Each follow-up consumes the stable contracts produced here and must remain independently testable.
