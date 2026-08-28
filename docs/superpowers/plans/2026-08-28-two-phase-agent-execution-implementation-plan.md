# DBPilot Two-Phase Agent Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 用 `CommandPrepare → CommandStart`、持久化 fencing token 和 ResultAck 消除 DBPilot 命令取消、续租、超时和结果确认竞态，并关闭最终复审剩余的 HTTP Audit、Artifact 和未知枚举正确性问题。

**Architecture:** Agent 收到签名 envelope 后只写入 journal 并返回 Prepared；控制面通过 PostgreSQL CAS 确认未取消并生成 execution token 后才发送 Start。Heartbeat、timeout claim、Cancel 和 Result 都携带 token/revision，Result 只有在 Job/Command/Audit 持久化后才收到成功 Ack；HTTP 幂等记录使用可修复阶段补齐 Audit。

**Tech Stack:** Go 1.25+、PostgreSQL 16、Protobuf/gRPC、bbolt、OpenAPI 3.1、oapi-codegen、OpenAPI Generator、Node `node:test`、Docker Desktop、Kylin V10 SP1。

**Spec:** `docs/superpowers/specs/2026-08-28-two-phase-agent-execution-design.md`

## Global Constraints

- Agent 不提供任意 Shell；所有操作继续使用 Protobuf `oneof` 类型化命令。
- Start 前取消保证 executor 未被调用；Start 后状态以 Agent 的真实 Result 为准。
- 所有 command 状态变更使用 command ID、execution token hash、lease revision 和 claim token CAS。
- running 状态在 Agent 重启后不得自动重新执行数据库副作用。
- ResultAck 只确认已经持久化且与已存 terminal digest 一致的结果。
- 新数据库变更使用 `backend/internal/job/migrations/0005_two_phase_execution.sql` 和 `backend/internal/platformdb/migrations/0005_http_idempotency_reconciliation.sql`；不得重写既有 migration。
- 生成代码必须提交，REST/Protobuf drift 必须为零。
- 标准测试不得依赖外部服务；PostgreSQL、Prism 和 Kylin 测试显式启用并自动清理。
- CentOS 7+、Kylin V10+ 支持边界不变；Kylin V10 SP1 amd64 需要重新 smoke。

---

## Task 1: Add CommandPrepare/CommandStart and Agent Recovery Semantics

**Files:**
- Modify: `contracts/protobuf/dbpilot/agent/v1/command.proto`
- Modify: `backend/gen/agent/v1/command.pb.go`
- Modify: `backend/internal/commandvalidation/validation.go`
- Modify: `backend/internal/commandvalidation/validation_test.go`
- Modify: `backend/internal/agent/commandjournal/journal.go`
- Modify: `backend/internal/agent/commandjournal/journal_test.go`
- Modify: `backend/internal/agent/controlclient.go`
- Modify: `backend/internal/agent/controlclient_test.go`
- Modify: `backend/internal/agentcontrol/registry.go`
- Modify: `backend/internal/agentcontrol/server.go`
- Modify: `backend/internal/agentcontrol/server_test.go`
- Modify: `tests/contracts/agent-proto.test.mjs`

**Interfaces:**
- Produces Protobuf messages `CommandPrepared`, `CommandStart`, token/revision fields on Heartbeat/Progress/Result/Cancellation, and digest-bound `CommandResultAcknowledgement`.
- Produces journal methods:

```go
Prepare(context.Context, *agentv1.CommandEnvelope, time.Time) (bool, error)
AuthorizeStart(context.Context, string, []byte, uint64, time.Time) error
MarkInterrupted(context.Context, string, time.Time) error
MarkReported(context.Context, string, [32]byte, time.Time) error
```

- [ ] **Step 1: Write failing protocol and journal tests**

Add structural assertions that ServerMessage contains `command_start`, Agent messages contain `command_prepared`, and Result/Progress carry token/revision. Add journal tests proving Prepare does not execute, matching Start moves prepared→running once, mismatched token/revision fails, running reopen becomes interrupted, and completed result remains pending until digest-matching ResultAck.

- [ ] **Step 2: Verify RED**

Run:

```powershell
node --test tests/contracts/agent-proto.test.mjs
Push-Location backend
go test ./internal/agent/commandjournal ./internal/agent ./internal/agentcontrol -run 'Test(Prepare|Start|Interrupted|ResultAck)' -count=1 -v
Pop-Location
```

Expected: FAIL because prepare/start messages and journal transitions do not exist.

- [ ] **Step 3: Define the pre-stable Agent v1 messages**

Use new oneof field numbers without reusing existing numbers. `CommandStart` includes `command_id`, 32-byte execution token, positive `lease_revision`, positive `lease_seconds`, and UTC start deadline. `CommandPrepared` includes command ID and SHA-256 envelope digest. ResultAck includes command ID, result digest, persisted flag, retryable flag, and stable reason code.

- [ ] **Step 4: Implement journal state and restart behavior**

Persist full deterministic envelope bytes, state `prepared/start_authorized/running/interrupted/completed`, token hash/encrypted token metadata, revision, result bytes/digest and Ack state. On reopen, prepared remains prepared; running becomes interrupted and emits one pending interrupted Result instead of executing again.

- [ ] **Step 5: Implement Agent and server flows**

Agent behavior:

```text
Envelope → validate → journal.Prepare+Sync → CommandPrepared
CommandStart(token,revision) → journal.AuthorizeStart+Sync → executor once
Result → journal.Complete+Sync → resend until matching ResultAck
```

Server calls Observer.Prepared before sending Start. Server calls Observer.Result and emits success ResultAck only when returned outcome is persisted and digest-matched. Registry snapshot copies all mutable maps under lock.

- [ ] **Step 6: Run focused and repeated tests**

```powershell
Push-Location backend
go test ./internal/commandvalidation ./internal/agent/commandjournal ./internal/agent ./internal/agentcontrol -count=1
go test ./internal/agent/commandjournal ./internal/agent ./internal/agentcontrol -count=20
Pop-Location
```

Expected: PASS with no goroutine leaks or duplicate executor calls.

- [ ] **Step 7: Regenerate and commit**

```powershell
npm run contracts:generate
git add -- contracts/protobuf backend/gen/agent backend/internal/commandvalidation backend/internal/agent backend/internal/agentcontrol tests/contracts/agent-proto.test.mjs
git commit -m "feat: add two-phase Agent execution protocol"
```

## Task 2: Implement PostgreSQL Start, Cancel, Lease and Result Fencing

**Files:**
- Create: `backend/internal/job/migrations/0005_two_phase_execution.sql`
- Modify: `backend/internal/job/model.go`
- Modify: `backend/internal/job/repository.go`
- Modify: `backend/internal/job/postgres.go`
- Modify: `backend/internal/job/postgres_test.go`
- Modify: `backend/internal/job/postgres_integration_test.go`
- Modify: `backend/internal/job/dispatcher.go`
- Modify: `backend/internal/job/dispatcher_test.go`
- Modify: `backend/test/e2e/job_command_lifecycle_test.go`

**Interfaces:**
- Consumes Task 1 messages and journal semantics.
- Produces:

```go
MarkPrepared(ctx context.Context, scope platformscope.Scope, commandID string, digest [32]byte, at time.Time) error
AuthorizeStart(ctx context.Context, scope platformscope.Scope, commandID string, expectedDigest [32]byte, tokenHash [32]byte, tokenCiphertext []byte, at, deadline time.Time) (StartGrant, error)
RenewExecutionLease(ctx context.Context, scope platformscope.Scope, commandID string, tokenHash [32]byte, expectedRevision uint64, at, deadline time.Time) (uint64, error)
ClaimExpiredExecution(ctx context.Context, limit int, at time.Time) ([]RecoveryClaim, error)
FinalizeExpiredExecution(ctx context.Context, claim RecoveryClaim, at time.Time) error
PersistTerminalResult(ctx context.Context, input TerminalResultCAS) (TerminalResultOutcome, error)
```

- [ ] **Step 1: Write failing CAS race tests**

Create unit and PostgreSQL integration tests for:

- cancel commits before Start → AuthorizeStart fails and executor never runs;
- Start commits before cancel → FIFO command/start/cancel and true late Result determines status;
- heartbeat increments revision after timeout claim → stale timeout finalize updates zero rows;
- result terminalizes after timeout claim → stale timeout fails;
- contradictory late Result returns conflict and does not update Job or command row;
- identical late Result returns persisted idempotent outcome.

- [ ] **Step 2: Verify RED**

```powershell
Push-Location backend
go test ./internal/job -run 'Test(TwoPhase|StartCancelRace|LeaseFence|ResultFence)' -count=1 -v
Pop-Location
```

Expected: FAIL because existing methods do not accept claim token/deadline/revision CAS.

- [ ] **Step 3: Add migration 0005**

Add command phase, prepare digest, encrypted execution token, token hash, lease revision, start deadline, recovery claim token/deadline/revision, terminal result digest and terminal timestamp. Add check constraints for valid phase/required-field combinations and indexes for prepared commands, pending cancellations and expired execution leases.

- [ ] **Step 4: Implement atomic Start and cancellation transactions**

`AuthorizeStart` locks command+Job and succeeds only when command is prepared, target nonterminal, and Job not cancelling/terminal. `RequestCancel` atomically persists Job and command intent. Prepared commands are terminalized cancelled without Start; start-authorized/running commands remain cancelling and are sent token-bound Cancel.

- [ ] **Step 5: Implement fenced lease/result transitions**

Every heartbeat renewal compares token hash and expected revision, increments revision, and clears only its matching recovery claim. Timeout finalization compares claim token, claimed deadline and claimed revision. Result CAS compares token/revision and persists terminal digest before Job/Audit mapping.

- [ ] **Step 6: Implement lifecycle ordering**

Lifecycle sequence:

```text
Prepare ACK persisted → Start CAS committed → CommandStart
Heartbeat → revision CAS
Result → terminal CAS → Job target/aggregate → Audit.RecordOnce → ResultAck
```

Contradictory terminal result returns non-retryable ResultAck conflict; it never overwrites existing state.

- [ ] **Step 7: Run live PostgreSQL race suite**

Use a disposable `postgres:16-alpine` container and run:

```powershell
$env:DBPILOT_JOB_POSTGRES_INTEGRATION='1'
$env:DBPILOT_JOB_POSTGRES_DSN='postgres://dbpilot:dbpilot@127.0.0.1:55432/dbpilot_job?sslmode=disable'
Push-Location backend
go test ./internal/job ./test/e2e -run 'Test(TwoPhase|StartCancelRace|LeaseFence|JobCommandLifecycle)' -count=1 -v
Pop-Location
```

The verifier script owns container creation/cleanup and substitutes its unique port/DSN. Expected: PASS; no remaining container.

- [ ] **Step 8: Commit**

```powershell
git add -- backend/internal/job backend/test/e2e/job_command_lifecycle_test.go
git commit -m "fix: fence command start leases and results"
```

## Task 3: Repair HTTP Audit and Artifact/Enum Compatibility

**Files:**
- Create: `backend/internal/platformdb/migrations/0005_http_idempotency_reconciliation.sql`
- Modify: `backend/internal/idempotency/service.go`
- Modify: `backend/internal/idempotency/postgres.go`
- Modify: `backend/internal/idempotency/*_test.go`
- Modify: `backend/internal/controlplane/platform_api.go`
- Modify: `backend/internal/controlplane/platform_api_test.go`
- Modify: `backend/internal/artifact/signer.go`
- Modify: `backend/internal/artifact/download_handler.go`
- Modify: `backend/internal/artifact/*_test.go`
- Modify: `backend/internal/audit/service.go`
- Modify: `backend/internal/audit/service_test.go`
- Modify: `frontend/generated/api/openapi-generator-config.json`
- Modify: `scripts/contracts/generate-rest.ps1`
- Modify: `tests/contracts/generated-rest.test.mjs`

**Interfaces:**
- Adds idempotency phases `processing`, `side_effect_committed`, `audited`, `completed` and a reconciliation callback for exact fingerprint retries.
- Artifact signed path stores base64url ID and local reads use `os.Root`.

- [ ] **Step 1: Write failing reconciliation/security tests**

Cover cancel committed + Audit failure + retry repair, Artifact descriptor saved + Audit failure + retry, special-character Artifact IDs, symlink-swap attempt, missing root/signing key readiness, DSA/EC/OpenSSH PEM, Oracle Easy Connect and MongoDB credential strings, and unknown enum deserialization.

- [ ] **Step 2: Verify RED**

```powershell
Push-Location backend
go test ./internal/idempotency ./internal/controlplane ./internal/artifact ./internal/audit -run 'Test(Reconcile|SpecialArtifactID|SymlinkSwap|Readiness|Credential)' -count=1 -v
Pop-Location
node --test tests/contracts/generated-rest.test.mjs frontend/tests/control-plane-client.test.js
```

Expected: FAIL on processing reconciliation, ID compatibility, TOCTOU and unknown enum.

- [ ] **Step 3: Implement idempotency reconciliation phases**

Persist side-effect response before Audit. Exact processing retry loads the saved Job/descriptor response, calls Audit.RecordOnce, advances audited→completed, and returns the original status/body/headers without re-executing the side effect.

- [ ] **Step 4: Implement safe Artifact paths/readiness**

Encode arbitrary nonblank Artifact IDs as base64url path segments. Use `os.OpenRoot`/`os.Root.Open` for relative StorageReference access, reject absolute paths and invalid metadata, and verify root plus signing key during control-plane construction before enabling Artifact capability.

- [ ] **Step 5: Harden Audit and enum conversion**

Use generic private-key PEM matching and credential parsers for URI/Oracle forms. Update REST generator post-processing so every generated enum `FromJSONTyped` returns `UnknownDefaultOpenApi` for values not in the enum.

- [ ] **Step 6: Run focused/full tests and regenerate**

```powershell
npm run contracts:generate
node --test
Push-Location backend
go test ./... -count=1
go vet ./...
Pop-Location
npm run contracts:verify
```

Expected: all pass; no generated drift.

- [ ] **Step 7: Commit**

```powershell
git add -- backend/internal/idempotency backend/internal/platformdb backend/internal/controlplane backend/internal/artifact backend/internal/audit frontend/generated frontend/generated/api/openapi-generator-config.json scripts/contracts/generate-rest.ps1 tests/contracts/generated-rest.test.mjs
git commit -m "fix: reconcile HTTP audit and artifact compatibility"
```

## Task 4: End-to-End Concurrency and Platform Verification

**Files:**
- Modify: `backend/test/e2e/job_command_lifecycle_test.go`
- Modify: `backend/scripts/verify-contract-foundation.ps1`
- Modify: `backend/scripts/verify-kylin-docker.ps1`
- Modify: `.github/workflows/contracts.yml`
- Modify: `README.md`
- Modify: `backend/README.md`

**Interfaces:**
- Consumes Tasks 1–3.
- Produces the final verification gate for two-phase cancellation, recovery, ResultAck, HTTP reconciliation and Artifact readiness.

- [ ] **Step 1: Extend E2E scenarios**

Add real PostgreSQL + in-memory gRPC scenarios:

- Prepare then cancel before Start: executor calls = 0.
- Start/cancel race: deterministic transaction winner and honest result.
- Heartbeat after timeout claim: stale worker cannot update.
- Control-plane crash before ResultAck: Agent reconnect resends and receives Ack after persistence.
- Agent crash while running: no automatic re-execution; durable timed-out/failed evidence.
- HTTP cancel Audit reconciliation after injected Audit failure.

- [ ] **Step 2: Run E2E RED before final wiring**

```powershell
Push-Location backend
go test ./test/e2e -run TestTwoPhaseCommandLifecycle -count=1 -v
Pop-Location
```

Expected: FAIL until all integration wiring and migrations are active.

- [ ] **Step 3: Wire control-plane loops and Agent startup**

Register Prepare/Start/Cancel/ResultAck handlers, execution-timeout worker and reconnect recovery. Ensure shutdown joins workers and no Result is marked reported before Ack.

- [ ] **Step 4: Run complete foundation verifier**

```powershell
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1
```

Expected: PASS for lint, breaking, drift, Node, Prism, Go, PostgreSQL E2E and four Linux builds; all containers cleaned.

- [ ] **Step 5: Run Kylin V10 SP1 smoke**

```powershell
powershell -NoProfile -File backend/scripts/verify-kylin-docker.ps1 -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' -Architecture amd64
```

Expected: PASS with ID `kylin`, VERSION_ID `V10`, both binaries/config/journal/protocol smoke, and no remaining container/temp directory.

- [ ] **Step 6: Update operational documentation**

Document prepare/start phases, cancellation timing, execution fencing, ResultAck retry, interrupted execution manual review, HTTP idempotency reconciliation and Artifact readiness requirements.

- [ ] **Step 7: Commit**

```powershell
git add -- backend/test/e2e backend/scripts .github/workflows/contracts.yml README.md backend/README.md
git commit -m "test: verify two-phase Agent execution"
```

## Completion Gate

Run fresh:

```powershell
npm run contracts:lint
npm run contracts:breaking
npm run contracts:verify
node --test
Push-Location backend
go test ./... -count=1
go vet ./...
Pop-Location
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1
git status --short
```

Completion requires zero failures, zero generated drift, a clean worktree, no verifier containers/temp files, and an independent whole-branch review with no Critical or Important concurrency findings.
