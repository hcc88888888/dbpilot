# DBPilot Contract Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 DBPilot 的 OpenAPI 3.1 REST、Protobuf/gRPC Agent 控制协议、生成代码、Mock、Job/Command 运行骨架与公共平台服务，使前端、后端和首批业务模块可以依赖稳定契约并行开发。

**Architecture:** 根目录 `contracts/` 是唯一契约源；浏览器通过生成的 ES Module 客户端访问控制面，控制面实现 oapi-codegen 的 strict `net/http` 接口。远程操作统一进入 PostgreSQL Job + transactional outbox，再通过 Agent 主动建立的 gRPC 双向流派发类型化 Command；Agent 使用 bbolt 保证命令去重和断线恢复。

**Tech Stack:** OpenAPI 3.1、Redocly CLI、Prism、OpenAPI Generator `typescript-fetch`、TypeScript、Go 1.25、oapi-codegen v2.8.0、kin-openapi、Protobuf、Buf、gRPC、PostgreSQL、bbolt、Node.js `node:test`、PowerShell、Docker Desktop。

**Spec:** `docs/superpowers/specs/2026-08-28-api-contract-parallel-development-design.md`

## Global Constraints

- REST 基础路径固定为 `/api/v1/tenants/{tenant_id}/projects/{project_id}`，路径 kebab-case，JSON snake_case。
- OpenAPI 3.1 与 Protobuf 是唯一事实来源；生成的 Go、TypeScript、JavaScript 和声明文件必须提交。
- 前端生产代码继续使用浏览器原生 ES Module；TypeScript 只用于生成流水线。
- 长耗时、批量和远程副作用操作返回 `202 Accepted` 与 Job；写请求支持 `Idempotency-Key`，配置更新支持 `ETag`/`If-Match`。
- Agent 只能执行 Protobuf `oneof` 定义的类型化命令，不提供任意 Shell 字符串执行。
- Command 交付语义固定为 at-least-once，Agent 按 `command_id` 持久化去重。
- 浏览器身份使用 OIDC 短期 Bearer Token；Agent 与控制面使用 mTLS/SPIFFE。
- 全链路传播 W3C `traceparent`；客户端必须容忍未知响应字段和 unknown enum 降级值。
- Redis 慢查询、敏感数据扫描和敏感数据脱敏不属于产品范围。
- Server 与 Agent 发布物支持 CentOS 7 及以上、Kylin V10 及以上；本地 Windows 使用 Docker Desktop 验证 Linux 兼容性。
- 功能正确性问题、越权、命令注入、数据破坏和错误执行必须立即修复；不影响功能的加固项记录后统一处理。
- 执行时保留当前工作区中与本计划无关的未跟踪文件和本地改动，不得批量暂存或清理。

---

## File Structure

```text
contracts/
  openapi/
    dbpilot-api.yaml                 # REST 根文档，只组合公共组件和模块路径
    common/*.yaml                    # 标识、分页、Problem、Job、Artifact、权限、审计
    modules/platform.yaml            # Job、Artifact、Audit、Capability 公共端点
  protobuf/dbpilot/agent/v1/*.proto  # Agent 遥测、策略、命令、资产和控制流
  examples/platform/*.json           # Prism 与契约测试共用样例
backend/
  api/openapi/oapi-codegen.yaml      # Go strict std-http 生成配置
  gen/openapi/dbpilot.gen.go         # 生成的 REST 类型和接口
  gen/agent/v1/*.pb.go               # 生成的 Agent gRPC 类型
  internal/job/*                     # Job、outbox 与 PostgreSQL 持久化
  internal/agentcontrol/*            # Agent 会话注册和 Command 派发
  internal/agent/commandjournal/*    # Agent 本地 bbolt 命令日志
  internal/artifact/*                # Artifact 元数据及受控访问
  internal/audit/*                   # 公共审计事件
  internal/capability/*              # 部署、适配器、数据库和权限能力求交集
  internal/controlplane/platform_api.go
  internal/controlplane/problem.go
frontend/
  generated/api/src/*                # OpenAPI Generator TypeScript 输出
  generated/api/dist/*               # tsc 产出的浏览器 ES Module 与 .d.ts
  shared/control-plane-client.js      # Token、scope、request-id 和幂等适配
scripts/contracts/*.ps1              # lint、bundle、generate、drift、mock 命令
tests/contracts/*.test.mjs           # Node 契约和生成物测试
deploy/contracts/prism.compose.yaml  # 本地 REST Mock
.github/workflows/contracts.yml       # 契约 CI 门禁
```

## Task 1: Pin the Contract Toolchain and Verification Entry Points

**Files:**
- Create: `package.json`
- Create: `package-lock.json`
- Create: `redocly.yaml`
- Create: `scripts/contracts/lint.ps1`
- Create: `scripts/contracts/generate.ps1`
- Create: `scripts/contracts/verify-drift.ps1`
- Create: `scripts/contracts/breaking.ps1`
- Create: `tests/contracts/toolchain.test.mjs`
- Modify: `backend/go.mod`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: existing Go module `dbpilot.local/platform` and Node `node:test` workflow.
- Produces: `npm run contracts:lint`, `npm run contracts:generate`, `npm run contracts:verify`; Go tool `oapi-codegen` pinned at v2.8.0.

- [ ] **Step 1: Write the failing toolchain contract test**

```javascript
// tests/contracts/toolchain.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('contract toolchain is pinned and generated output is tracked', async () => {
  const pkg = JSON.parse(await readFile('package.json', 'utf8'));
  assert.equal(pkg.scripts['contracts:lint'], 'powershell -NoProfile -File scripts/contracts/lint.ps1');
  assert.equal(pkg.scripts['contracts:generate'], 'powershell -NoProfile -File scripts/contracts/generate.ps1');
  assert.equal(pkg.scripts['contracts:breaking'], 'powershell -NoProfile -File scripts/contracts/breaking.ps1');
  assert.equal(pkg.devDependencies['@redocly/cli'], '2.2.0');
  assert.equal(pkg.devDependencies['@stoplight/prism-cli'], '5.14.2');
  assert.equal(pkg.devDependencies.typescript, '5.9.2');
  const ignore = await readFile('.gitignore', 'utf8');
  assert.doesNotMatch(ignore, /^backend\/gen\/$/m);
});
```

- [ ] **Step 2: Run the test and verify the missing toolchain fails**

Run: `node --test tests/contracts/toolchain.test.mjs`

Expected: FAIL because root `package.json` does not exist.

- [ ] **Step 3: Add pinned Node and Go tools**

Create `package.json` with `type: module`, the three scripts above, `contracts:verify` pointing to `scripts/contracts/verify-drift.ps1`, and exact dev dependencies. Run:

```powershell
npm install --save-dev --save-exact @redocly/cli@2.2.0 @stoplight/prism-cli@5.14.2 typescript@5.9.2
Push-Location backend
go get -tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0
Pop-Location
```

Remove only the `backend/gen/` rule from `.gitignore`; retain certificate, database and worktree exclusions.

- [ ] **Step 4: Add deterministic PowerShell entry points**

`lint.ps1` runs Redocly when the root OpenAPI document exists and runs Buf when root `buf.yaml` exists. `generate.ps1` stops on error and invokes the existing component scripts in this exact order: `generate-rest.ps1`, then `generate-agent.ps1`; Task 4 changes missing components from optional to an error. `breaking.ps1` compares Agent Protobuf with `origin/main` once that branch contains the canonical contract; absence is accepted only for the one-time canonical migration. `verify-drift.ps1` runs generation followed by:

```powershell
$changed = git status --short -- contracts backend/gen frontend/generated
if ($changed) {
  $changed | Write-Error
  exit 1
}
```

Each script starts with `$ErrorActionPreference = 'Stop'` and resolves the repository root from `$PSScriptRoot` instead of depending on the caller's current directory.

- [ ] **Step 5: Run the test and baseline Go tests**

Run:

```powershell
node --test tests/contracts/toolchain.test.mjs
Push-Location backend
go test ./...
Pop-Location
```

Expected: toolchain test PASS and all existing Go tests PASS.

- [ ] **Step 6: Commit the toolchain**

```powershell
git add -- package.json package-lock.json redocly.yaml scripts/contracts tests/contracts/toolchain.test.mjs backend/go.mod backend/go.sum .gitignore
git commit -m "build: add contract generation toolchain"
```

## Task 2: Define the Common OpenAPI 3.1 Contract

**Files:**
- Create: `contracts/openapi/dbpilot-api.yaml`
- Create: `contracts/openapi/common/identifiers.yaml`
- Create: `contracts/openapi/common/pagination.yaml`
- Create: `contracts/openapi/common/errors.yaml`
- Create: `contracts/openapi/common/jobs.yaml`
- Create: `contracts/openapi/common/artifacts.yaml`
- Create: `contracts/openapi/common/permissions.yaml`
- Create: `contracts/openapi/common/audit.yaml`
- Create: `contracts/openapi/modules/platform.yaml`
- Create: `contracts/examples/platform/job-running.json`
- Create: `contracts/examples/platform/problem-validation.json`
- Create: `contracts/examples/platform/capabilities.json`
- Create: `tests/contracts/openapi-common.test.mjs`

**Interfaces:**
- Consumes: Task 1 Redocly lint command.
- Produces: operation IDs `getJob`, `cancelJob`, `getArtifact`, `createArtifactDownload`, `listAuditEvents`, `getCapabilities`; schemas `Job`, `Problem`, `Page`, `Artifact`, `AuditEvent`, `CapabilitySet`.

- [ ] **Step 1: Write the failing OpenAPI invariant test**

```javascript
// tests/contracts/openapi-common.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('root contract exposes common platform operations and permission metadata', async () => {
  const source = (await Promise.all([
    readFile('contracts/openapi/dbpilot-api.yaml', 'utf8'),
    readFile('contracts/openapi/modules/platform.yaml', 'utf8'),
  ])).join('\n');
  for (const value of ['openapi: 3.1.0', 'operationId: getJob', 'operationId: cancelJob',
    'operationId: getCapabilities', 'application/problem+json', 'x-dbpilot-permission']) {
    assert.match(source, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});
```

- [ ] **Step 2: Run the invariant test and confirm it fails**

Run: `node --test tests/contracts/openapi-common.test.mjs`

Expected: FAIL because `contracts/openapi/dbpilot-api.yaml` is absent.

- [ ] **Step 3: Define identifiers, pagination and Problem Details**

Use opaque string IDs with `minLength: 1`, RFC 3339 `date-time`, and cursor page:

```yaml
Page:
  type: object
  required: [limit, has_more]
  properties:
    limit: { type: integer, minimum: 1, maximum: 500 }
    next_cursor: { type: [string, 'null'] }
    has_more: { type: boolean }
```

`Problem` requires `type`, `title`, `status`, `code`, `request_id`; field errors contain `field`, `code`, `message`. Every error response uses `application/problem+json`.

- [ ] **Step 4: Define Job, Artifact, Audit and Capability schemas**

`JobStatus` contains exactly `queued`, `dispatched`, `running`, `succeeded`, `failed`, `cancelling`, `cancelled`, `timed_out`. `JobOutcome` contains `complete`, `partial`, `none`. Job includes counts, progress, source resource, timestamps, trace fields and Artifact references. Capability entries include `name`, `enabled`, `reason_code`, `database_types`, `agent_capabilities` and required permission.

- [ ] **Step 5: Define common platform paths**

Add the following paths under the scoped base path and mark each operation with one permission:

```text
GET  /jobs/{job_id}                         platform.jobs.read
POST /jobs/{job_id}/actions/cancel          platform.jobs.cancel
GET  /artifacts/{artifact_id}                platform.artifacts.read
POST /artifacts/{artifact_id}/actions/download platform.artifacts.download
GET  /audit-events                          platform.audit.read
GET  /capabilities                          platform.capabilities.read
```

The cancel and download actions require `Idempotency-Key`. Cancel accepts `If-Match` against the Job version and returns `412` on a stale version; its success response is `202` with Job. Artifact download returns a short-lived download descriptor, never file bytes.

- [ ] **Step 6: Add examples and lint the contract**

Run:

```powershell
node --test tests/contracts/openapi-common.test.mjs
npm run contracts:lint
```

Expected: invariant test PASS; Redocly reports zero errors.

- [ ] **Step 7: Commit the common REST contract**

```powershell
git add -- contracts/openapi contracts/examples/platform tests/contracts/openapi-common.test.mjs
git commit -m "feat: define common platform REST contract"
```

## Task 3: Generate Go Strict Server and Browser ES Module Clients

**Files:**
- Create: `backend/api/openapi/oapi-codegen.yaml`
- Create: `backend/gen/openapi/dbpilot.gen.go`
- Create: `backend/gen/openapi/permissions.gen.go`
- Create: `backend/gen/openapi/permissions_test.go`
- Create: `scripts/contracts/generate-rest.ps1`
- Create: `scripts/contracts/generate-permissions.mjs`
- Create: `frontend/generated/api/openapi-generator-config.json`
- Create: `frontend/generated/api/tsconfig.json`
- Create: `frontend/generated/api/src/`
- Create: `frontend/generated/api/dist/`
- Create: `tests/contracts/generated-rest.test.mjs`
- Modify: `scripts/contracts/generate.ps1`

**Interfaces:**
- Consumes: `contracts/openapi/dbpilot-api.yaml` from Task 2.
- Produces: Go package `dbpilot.local/platform/gen/openapi` with `StrictServerInterface` and generated permission constants; browser exports `PlatformApi`, `Configuration`, and generated models from `frontend/generated/api/dist/index.js`.

- [ ] **Step 1: Write a failing generated-client smoke test**

```javascript
// tests/contracts/generated-rest.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../../frontend/generated/api/dist/index.js';

test('generated browser client exposes the platform API', () => {
  assert.equal(typeof api.PlatformApi, 'function');
  assert.equal(typeof api.Configuration, 'function');
});
```

Add a Go test in `backend/gen/openapi/permissions_test.go` that asserts `OperationPermissions["getJob"] == "platform.jobs.read"` and every operation in the bundled document has exactly one generated permission.

- [ ] **Step 2: Run the smoke test and verify it fails**

Run: `node --test tests/contracts/generated-rest.test.mjs`

Expected: FAIL with module-not-found for generated output.

- [ ] **Step 3: Configure Go generation**

Create `oapi-codegen.yaml`:

```yaml
package: openapi
generate:
  models: true
  std-http-server: true
  strict-server: true
  embedded-spec: true
output: gen/openapi/dbpilot.gen.go
output-options:
  skip-prune: false
```

Invoke from `backend` with `go tool oapi-codegen -config api/openapi/oapi-codegen.yaml ../contracts/openapi/dbpilot-api.yaml`.

`generate-permissions.mjs` reads the Redocly JSON bundle, rejects operations with zero or multiple `x-dbpilot-permission` values, and writes deterministic Go constants plus `OperationPermissions map[string]string` to `backend/gen/openapi/permissions.gen.go`.

- [ ] **Step 4: Configure frontend generation and compilation**

Use Docker image `openapitools/openapi-generator-cli:v7.15.0` with generator `typescript-fetch`, `supportsES6=true`, `typescriptThreePlus=true`, and `useSingleRequestParameter=true`. Generate into `frontend/generated/api/src`; run TypeScript with:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "bundler",
    "declaration": true,
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*.ts"]
}
```

`generate-rest.ps1` removes only the known generated `src` and `dist` directories after resolving and verifying they remain under `frontend/generated/api`, then regenerates them. The root `generate.ps1` invokes existing component scripts in the fixed order `generate-rest.ps1`, `generate-agent.ps1`; before Task 4, the absent Agent component is skipped explicitly.

- [ ] **Step 5: Generate and compile all REST artifacts**

Run:

```powershell
npm run contracts:generate
node --test tests/contracts/generated-rest.test.mjs
Push-Location backend
go test ./gen/openapi
Pop-Location
```

Expected: generated-client smoke test PASS and generated Go package compiles.

- [ ] **Step 6: Commit generated REST artifacts**

```powershell
git add -- backend/api/openapi backend/gen/openapi frontend/generated/api scripts/contracts/generate.ps1 scripts/contracts/generate-rest.ps1 tests/contracts/generated-rest.test.mjs
git commit -m "build: generate REST clients and strict server"
```

## Task 4: Migrate and Expand the Agent Protobuf Contract

**Files:**
- Create: `buf.yaml`
- Create: `buf.gen.yaml`
- Create: `contracts/protobuf/dbpilot/agent/v1/telemetry.proto`
- Create: `contracts/protobuf/dbpilot/agent/v1/policy.proto`
- Create: `contracts/protobuf/dbpilot/agent/v1/command.proto`
- Create: `contracts/protobuf/dbpilot/agent/v1/inventory.proto`
- Create: `tests/contracts/agent-proto.test.mjs`
- Create: `scripts/contracts/generate-agent.ps1`
- Create: `backend/gen/agent/v1/*.pb.go`
- Modify: imports in `backend/internal/ingest/service.go`
- Modify: imports in `backend/internal/exporter/client.go`
- Modify: imports in `backend/cmd/controlplane/main.go`
- Modify: imports in `backend/cmd/telemetry-test-gateway/main.go`
- Delete: `backend/api/telemetry/v1/telemetry.proto`
- Delete: `backend/api/telemetry/v1/contract_test.go`
- Delete: `backend/gen/telemetry/v1/telemetry.pb.go`
- Delete: `backend/gen/telemetry/v1/telemetry_grpc.pb.go`
- Delete: `backend/buf.yaml`
- Delete: `backend/buf.gen.yaml`

**Interfaces:**
- Consumes: existing `TelemetryIngest` RPC and message field numbers unchanged during migration.
- Produces: package `dbpilot.agent.v1`, Go import `dbpilot.local/platform/gen/agent/v1`, services `TelemetryIngest` and `AgentControl`.

- [ ] **Step 1: Write the failing canonical contract test**

```javascript
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('Agent v1 exposes typed commands and forbids arbitrary shell', async () => {
  const names = ['telemetry.proto', 'policy.proto', 'command.proto', 'inventory.proto'];
  const files = (await Promise.all(names.map((name) =>
    readFile(`contracts/protobuf/dbpilot/agent/v1/${name}`, 'utf8')))).join('\n');
  for (const required of ['service AgentControl',
    'rpc Connect(stream AgentMessage) returns (stream ServerMessage)',
    'oneof command', 'CollectNow', 'InspectInstance', 'ExecuteSQL',
    'ExecuteRegisteredProcess', 'CollectDiagnostic', 'service TelemetryIngest']) {
    assert.match(files, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.doesNotMatch(files, /shell_command/);
});
```

- [ ] **Step 2: Run the canonical test and confirm it fails**

Run: `node --test tests/contracts/agent-proto.test.mjs`

Expected: FAIL because the canonical proto files are absent.

- [ ] **Step 3: Move TelemetryIngest without changing wire numbers**

Copy the current messages and RPCs into `telemetry.proto`, change only package and `go_package`, and retain every existing field number. Configure root Buf module path as `contracts/protobuf/dbpilot`, so source path `agent/v1` generates to `backend/gen/agent/v1`. Configure remote plugins `buf.build/protocolbuffers/go:v1.36.11` and `buf.build/grpc/go:v1.6.1` with `paths=source_relative`.

- [ ] **Step 4: Define Hello, policy, inventory and typed commands**

The command envelope contains `command_id`, `job_id`, `issued_at`, `expires_at`, `nonce`, `signature`, `lease_seconds`, and:

```protobuf
oneof command {
  CollectNow collect_now = 20;
  InspectInstance inspect_instance = 21;
  ExecuteSQL execute_sql = 22;
  ExecuteRegisteredProcess execute_registered_process = 23;
  CollectDiagnostic collect_diagnostic = 24;
}
```

`ExecuteSQL` requires `instance_id`, `workorder_id`, `review_revision`, `sql_digest`, `transaction_policy`, `timeout_seconds`. `ExecuteRegisteredProcess` contains `process_id` and a map of structured parameters, not a command line.

- [ ] **Step 5: Define AgentControl message envelopes**

`AgentMessage.oneof` includes hello, heartbeat, inventory, command acknowledgement, progress and result. `ServerMessage.oneof` includes hello acknowledgement, policy update, command, command cancellation and flow-control instruction. Reserve removed field numbers and include protocol version plus repeated capabilities in Hello.

- [ ] **Step 6: Generate, migrate imports and run regression tests**

Add `generate-agent.ps1` using pinned image `bufbuild/buf:1.57.2` with the repository mounted at `/workspace`, then update the root lint and generator scripts to require both component scripts.

Run:

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace bufbuild/buf:1.57.2 lint
docker run --rm -v "${PWD}:/workspace" -w /workspace bufbuild/buf:1.57.2 generate
Push-Location backend
go test ./internal/ingest ./internal/exporter ./cmd/controlplane ./cmd/telemetry-test-gateway
Pop-Location
```

Expected: Buf PASS; all migrated telemetry tests PASS without wire-field changes.

- [ ] **Step 7: Commit the canonical Agent contract**

```powershell
git add -- buf.yaml buf.gen.yaml contracts/protobuf tests/contracts/agent-proto.test.mjs scripts/contracts backend/gen/agent backend/internal/ingest backend/internal/exporter backend/cmd/controlplane backend/cmd/telemetry-test-gateway backend/api/telemetry backend/gen/telemetry backend/buf.yaml backend/buf.gen.yaml
git commit -m "feat: establish Agent v1 control contract"
```

## Task 5: Implement Job State and Transactional Outbox Persistence

**Files:**
- Create: `backend/internal/job/model.go`
- Create: `backend/internal/job/repository.go`
- Create: `backend/internal/job/postgres.go`
- Create: `backend/internal/job/postgres_test.go`
- Create: `backend/internal/job/migrate.go`
- Create: `backend/internal/job/migrations/0001_jobs_outbox.sql`
- Create: `backend/internal/job/migrations_test.go`
- Create: `backend/internal/platformscope/scope.go`
- Create: `backend/internal/platformscope/scope_test.go`

**Interfaces:**
- Consumes: scoped opaque IDs and Job states from the OpenAPI contract.
- Produces:

```go
type Repository interface {
    CreateWithOutbox(context.Context, Job, []OutboxMessage) error
    CreateInTx(context.Context, *sql.Tx, Job, []OutboxMessage) error
    Get(context.Context, platformscope.Scope, string) (Job, error)
    Transition(context.Context, Transition) (Job, error)
    RequestCancel(context.Context, platformscope.Scope, string, string, time.Time) (Job, error)
    ClaimOutbox(context.Context, int, time.Time) ([]OutboxMessage, error)
    MarkOutboxPublished(context.Context, string, time.Time) error
}
```

- [ ] **Step 1: Write failing state-machine tests**

Test allowed transitions `queued→dispatched→running→succeeded`, cancellation, failure and timeout. Explicitly reject `succeeded→running`, terminal cancellation and progress regression. Test multi-target aggregation returns `OutcomePartial` when at least one target succeeds and one fails.

- [ ] **Step 2: Run the state tests and verify they fail**

Run: `Push-Location backend; go test ./internal/job -run 'TestTransition|TestAggregate' -v; Pop-Location`

Expected: FAIL because the job package is absent.

- [ ] **Step 3: Implement the minimal domain model**

Define shared `platformscope.Scope{TenantID, ProjectID string}` with `Validate` and `Key`, then define `Status`, `Outcome`, `Job`, `TargetResult`, `Transition`, `OutboxMessage`, stable sentinel errors (`ErrNotFound`, `ErrConflict`, `ErrInvalidTransition`) and a pure `ApplyTransition(Job, Transition) (Job, error)` function. Store all timestamps as UTC.

- [ ] **Step 4: Run state tests until green**

Run: `Push-Location backend; go test ./internal/job -run 'TestTransition|TestAggregate' -v; Pop-Location`

Expected: PASS.

- [ ] **Step 5: Write failing transaction and claim tests**

Using `go-sqlmock`, assert `CreateWithOutbox` starts one transaction, calls `CreateInTx`, inserts the Job and every outbox row, then commits; any outbox failure rolls back. Assert a module-owned transaction can insert its business resource and call `CreateInTx` before the same commit. Assert `ClaimOutbox` uses `FOR UPDATE SKIP LOCKED`, sets a lease, and returns rows ordered by creation time.

- [ ] **Step 6: Add schema and PostgreSQL repository**

The migration creates `jobs`, `job_targets`, and `command_outbox`, tenant/project composite indexes, unique `(tenant_id, project_id, idempotency_key, job_type)`, and outbox lease indexes. SQL updates include the current version in the predicate so competing transitions return `ErrConflict`. `job.RunMigrations(context.Context, *sql.DB) error` embeds and applies this package's migrations through `dbpilot_schema_migrations`.

- [ ] **Step 7: Run package and migration tests**

Run: `Push-Location backend; go test ./internal/job -v; Pop-Location`

Expected: all Job tests PASS.

- [ ] **Step 8: Commit Job and outbox persistence**

```powershell
git add -- backend/internal/job backend/internal/platformscope
git commit -m "feat: add durable job and command outbox"
```

## Task 6: Implement Agent Sessions and the Durable Command Journal

**Files:**
- Create: `backend/internal/agentcontrol/identity.go`
- Create: `backend/internal/agentcontrol/registry.go`
- Create: `backend/internal/agentcontrol/server.go`
- Create: `backend/internal/agentcontrol/server_test.go`
- Create: `backend/internal/agent/commandjournal/journal.go`
- Create: `backend/internal/agent/commandjournal/journal_test.go`
- Create: `backend/internal/agent/controlclient.go`
- Create: `backend/internal/agent/controlclient_test.go`
- Create: `backend/internal/agent/commandverify.go`
- Create: `backend/internal/agent/commandverify_test.go`
- Modify: `backend/cmd/controlplane/main.go`
- Modify: `backend/cmd/agent/main.go`
- Modify: `backend/packaging/config/agent.yaml.example`

**Interfaces:**
- Consumes: generated `agentv1.AgentControlServer`, Job outbox messages and gRPC peer TLS context.
- Produces:

```go
type Dispatcher interface {
    Dispatch(context.Context, string, *agentv1.CommandEnvelope) error
    Cancel(context.Context, string, string) error
}
type Journal interface {
    Accept(context.Context, *agentv1.CommandEnvelope) (bool, error)
    Start(context.Context, string, time.Time) error
    Complete(context.Context, string, *agentv1.CommandResult, time.Time) error
    Active(context.Context) ([]Entry, error)
}
type CommandExecutor interface {
    Execute(context.Context, *agentv1.CommandEnvelope, ProgressReporter) (*agentv1.CommandResult, error)
}
```

- [ ] **Step 1: Write failing SPIFFE identity and handshake tests**

Create an in-memory gRPC stream. Assert Connect rejects missing peer certificate, non-SPIFFE URI, Hello without agent ID, duplicate active agent ID and unsupported protocol version. Assert a valid `spiffe://dbpilot.local/agent/{agent_id}` identity receives HelloAck and registers capabilities.

- [ ] **Step 2: Run the AgentControl tests and verify failure**

Run: `Push-Location backend; go test ./internal/agentcontrol -v; Pop-Location`

Expected: FAIL because AgentControl server is absent.

- [ ] **Step 3: Implement identity extraction and session registry**

Extract exactly one SPIFFE URI SAN from `credentials.TLSInfo`, verify the trust domain and match the path agent ID to Hello. Registry keeps one cancellable live session per agent and exposes a bounded send queue; full queues return a retryable dispatch error instead of blocking the gRPC receive loop.

- [ ] **Step 4: Implement Connect receive/send loops**

Require Hello as the first message, send HelloAck, report the registered session, route acknowledgements/progress/results to an observer, renew leases on heartbeat, and unregister on EOF. Validate command expiry and advertised capability before enqueueing.

- [ ] **Step 5: Run AgentControl tests until green**

Run: `Push-Location backend; go test ./internal/agentcontrol -v; Pop-Location`

Expected: PASS.

- [ ] **Step 6: Write failing bbolt journal tests**

Open a temporary bbolt file. Assert first `Accept` returns true, duplicate `command_id` returns false, completed commands survive close/reopen, `Active` returns accepted/running commands only, and expired commands cannot start.

- [ ] **Step 7: Implement the journal with explicit buckets**

Use buckets `commands` and `meta`; encode journal entries as deterministic JSON containing state, envelope digest, accepted/start/completed timestamps and protobuf-encoded result bytes. Each state transition runs in one bbolt update transaction and calls `Sync` before acknowledging command acceptance.

- [ ] **Step 8: Write failing Agent client verification and reconnect tests**

Assert the Agent rejects invalid Ed25519 signatures, expired envelopes, repeated nonce, unadvertised capability and mismatched Agent ID before journaling. With a fake stream and executor, assert it reports active commands after reconnect, acknowledges a new command only after durable `Accept`, emits progress/result, and deduplicates a replayed `command_id`.

- [ ] **Step 9: Implement the Agent control client and verifier**

`ControlClient.Run` opens the bidirectional stream, sends Hello plus journal recovery state, heartbeats with a bounded interval, validates incoming envelopes, and dispatches only to a registered `CommandExecutor` for the concrete `oneof` command. Cancellation calls the command context cancel function. `cmd/agent/main.go` supplies the configured control-plane public key, journal path and capability-derived executor registry; command kinds without an executor are not advertised. The example Agent YAML documents `control.public_key_file`, `control.journal_path`, heartbeat interval and reconnect backoff.

- [ ] **Step 10: Register AgentControl and run focused tests**

Register the new service beside `TelemetryIngest` in `cmd/controlplane/main.go`, then run:

```powershell
Push-Location backend
go test ./internal/agentcontrol ./internal/agent/commandjournal ./internal/agent ./cmd/agent ./cmd/controlplane -v
Pop-Location
```

Expected: all focused tests PASS.

- [ ] **Step 11: Commit Agent command reliability**

```powershell
git add -- backend/internal/agentcontrol backend/internal/agent/commandjournal backend/internal/agent/controlclient.go backend/internal/agent/controlclient_test.go backend/internal/agent/commandverify.go backend/internal/agent/commandverify_test.go backend/cmd/agent/main.go backend/cmd/controlplane/main.go backend/packaging/config/agent.yaml.example
git commit -m "feat: add reliable Agent command control stream"
```

## Task 7: Implement Artifact, Audit and Capability Services

**Files:**
- Create: `backend/internal/artifact/model.go`
- Create: `backend/internal/artifact/service.go`
- Create: `backend/internal/artifact/service_test.go`
- Create: `backend/internal/artifact/postgres.go`
- Create: `backend/internal/artifact/postgres_test.go`
- Create: `backend/internal/artifact/signer.go`
- Create: `backend/internal/artifact/signer_test.go`
- Create: `backend/internal/audit/model.go`
- Create: `backend/internal/audit/service.go`
- Create: `backend/internal/audit/service_test.go`
- Create: `backend/internal/audit/postgres.go`
- Create: `backend/internal/audit/postgres_test.go`
- Create: `backend/internal/capability/service.go`
- Create: `backend/internal/capability/service_test.go`
- Create: `backend/internal/platformdb/migrations/0001_platform_services.sql`
- Create: `backend/internal/platformdb/migrate.go`
- Create: `backend/internal/platformdb/migrate_test.go`

**Interfaces:**
- Consumes: `platformscope.Scope`, Agent capability sets and Credential Reference policy.
- Produces: `artifact.Service.Get/CreateDownload`, `audit.Service.Record/List`, `capability.Service.Resolve`.

- [ ] **Step 1: Write failing Artifact authorization tests**

Assert metadata access requires an exact tenant/project match, expired artifacts cannot produce downloads, checksums and sizes are returned, and `CreateDownload` returns a descriptor valid for no more than five minutes without exposing a storage credential.

- [ ] **Step 2: Implement Artifact metadata and signer boundaries**

Use:

```go
type Store interface { Get(context.Context, platformscope.Scope, string) (Artifact, error) }
type DownloadSigner interface { Sign(context.Context, Artifact, time.Duration) (string, error) }
func (s Service) CreateDownload(ctx context.Context, scope platformscope.Scope, id string, ttl time.Duration) (Download, error)
```

Clamp TTL to five minutes and return stable not-found/expired errors. Implement `HMACDownloadSigner` that signs artifact ID, scope and expiry into a control-plane download URL using key bytes obtained through the existing secret resolver; its tests reject tampered IDs, scope and expiry.

- [ ] **Step 3: Write failing Audit redaction and immutability tests**

Assert `Record` rejects missing actor/action/resource/result, replaces SQL text with digest/summary, rejects password/token/credential keys, always uses UTC, and returns an immutable event ID. Assert cursor list filtering is tenant/project scoped.

- [ ] **Step 4: Implement Audit service and PostgreSQL schema**

Create append-only `audit_events` with no update/delete repository methods. Store request ID, trace ID, job ID, command ID and actor/action/resource/result fields. Redact recursively before persistence. Implement PostgreSQL stores for Artifact metadata and Audit events; use cursor predicates over `(created_at, id)` and enforce tenant/project in every query.

- [ ] **Step 5: Write failing capability intersection tests**

Given deployment flags, database adapter capabilities, Agent capabilities and user permissions, assert a capability is enabled only when all required inputs are true. Include explicit reasons `deployment_disabled`, `database_unsupported`, `agent_unsupported`, `permission_denied`.

- [ ] **Step 6: Implement the pure capability resolver**

```go
func Resolve(catalog []Definition, input Input) []Capability
```

Sort output by capability name for deterministic responses and include supported database types without front-end database-name branching.

- [ ] **Step 7: Run all three service test suites**

Run: `Push-Location backend; go test ./internal/artifact ./internal/audit ./internal/capability ./internal/platformdb -v; Pop-Location`

Expected: all tests PASS.

- [ ] **Step 8: Commit common platform services**

```powershell
git add -- backend/internal/artifact backend/internal/audit backend/internal/capability backend/internal/platformdb
git commit -m "feat: add artifact audit and capability services"
```

## Task 8: Add OIDC/RBAC and Implement the Generated Platform HTTP API

**Files:**
- Create: `backend/internal/controlplane/oidc.go`
- Create: `backend/internal/controlplane/oidc_test.go`
- Create: `backend/internal/controlplane/authorization.go`
- Create: `backend/internal/controlplane/authorization_test.go`
- Create: `backend/internal/controlplane/platform_api.go`
- Create: `backend/internal/controlplane/platform_api_test.go`
- Create: `backend/internal/controlplane/problem.go`
- Modify: `backend/internal/controlplane/services.go`
- Modify: `backend/internal/controlplane/http.go`
- Modify: `backend/cmd/controlplane/main.go`
- Modify: `backend/config/controlplane.yaml.example`
- Modify: `backend/go.mod`
- Modify: `backend/go.sum`

**Interfaces:**
- Consumes: generated `openapi.StrictServerInterface`, Job, Artifact, Audit and Capability services.
- Produces: OIDC `BearerPrincipalResolver`, `Authorizer.Require(principal, platformscope.Scope, permission)`, generated platform routes and RFC 9457 responses.

- [ ] **Step 1: Write failing Bearer identity tests**

Assert missing/multiple/invalid Authorization headers return unauthenticated, expired or wrong issuer/audience claims fail, and valid claims map subject plus tenant/project/action grants. Use an injected verifier so unit tests perform no network calls.

- [ ] **Step 2: Implement OIDC resolver boundary**

```go
type TokenVerifier interface { Verify(context.Context, string) (OIDCClaims, error) }
type BearerPrincipalResolver struct { Verifier TokenVerifier }
func (r BearerPrincipalResolver) ResolvePrincipal(*http.Request) (Principal, error)
```

Production configuration contains issuer and audience. Add `github.com/coreos/go-oidc/v3/oidc@v3.16.0` and construct its provider/verifier once during control-plane startup so discovery keys are cached by the library; local-header mode remains loopback-only for development tests.

- [ ] **Step 3: Write failing RBAC tests**

Table-test platform admin, exact project grant, wrong tenant, wrong project and missing action. Assert list requests are scope-filtered and no handler trusts actor or project values from the JSON body.

- [ ] **Step 4: Implement permission checks and operation mapping**

Map each generated operation ID to the exact `x-dbpilot-permission` value from Task 2. Authorization happens after authentication and scope parsing but before strict handler execution.

- [ ] **Step 5: Write failing generated-handler tests**

Test `GET /jobs/{id}`, cancel with and without `Idempotency-Key`, capability response, Artifact download, Audit cursor list, `ETag`, `If-Match`, request ID propagation, and all common Problem Details mappings. Validate returned bodies against the embedded OpenAPI schema with kin-openapi.

- [ ] **Step 6: Implement strict platform handler and Problem mapping**

`platformAPI` implements every generated method and delegates only to typed services. `problem.go` maps validation, not-found, conflict, precondition, forbidden, timeout and internal errors to stable codes; internal details never enter `title` or `detail`.

- [ ] **Step 7: Mount generated routes without disturbing existing routes**

Create the generated strict handler with stdlib `http.ServeMux`, mount it within the existing authenticated scoped middleware, retain `/healthz`, `/readyz`, alert and monitoring routes, and run `job.RunMigrations` plus `platformdb.RunMigrations` during startup before readiness becomes true.

- [ ] **Step 8: Run focused HTTP and server tests**

Run:

```powershell
Push-Location backend
go test ./internal/controlplane ./cmd/controlplane -v
Pop-Location
```

Expected: existing alert/monitoring tests and new platform tests all PASS.

- [ ] **Step 9: Commit identity and platform HTTP endpoints**

```powershell
git add -- backend/internal/controlplane backend/cmd/controlplane backend/config/controlplane.yaml.example
git commit -m "feat: expose authorized platform contract endpoints"
```

## Task 9: Add the Frontend Control-Plane Boundary and Prism Mock

**Files:**
- Create: `frontend/shared/control-plane-client.js`
- Create: `frontend/tests/control-plane-client.test.js`
- Create: `deploy/contracts/prism.compose.yaml`
- Create: `scripts/contracts/start-mock.ps1`
- Create: `tests/contracts/prism.test.mjs`
- Modify: `package.json`
- Modify: `package-lock.json`

**Interfaces:**
- Consumes: generated `Configuration` and `PlatformApi` from Task 3.
- Produces:

```javascript
createControlPlaneClient({ baseUrl, getAccessToken, fetchImpl, requestIdFactory })
client.forScope({ tenantId, projectId })
scoped.platform
scoped.requestOptions({ idempotencyKey, etag, signal })
```

- [ ] **Step 1: Write failing client-boundary tests**

Assert scope values are URL encoded, Bearer token is read per request, `X-Request-ID` is present, write calls propagate `Idempotency-Key`, conditional updates propagate `If-Match`, Problem JSON becomes a stable `ControlPlaneError`, AbortError is preserved, and 401/403 never fall back to demo data.

- [ ] **Step 2: Run the frontend boundary test and verify failure**

Run: `node --test frontend/tests/control-plane-client.test.js`

Expected: FAIL because the shared boundary module is absent.

- [ ] **Step 3: Implement the generated-client wrapper**

Use generated middleware to add authorization and trace headers. Expose scope-bound API instances and a fixed error mapping based on `problem.code`; never display raw server `detail` for internal failures.

- [ ] **Step 4: Run frontend tests**

Run: `node --test frontend/tests/control-plane-client.test.js frontend/tests/*.test.js`

Expected: new and existing frontend tests PASS.

- [ ] **Step 5: Add Prism Docker Compose and readiness test**

Compose mounts `contracts/openapi` read-only and starts Prism with dynamic responses disabled. `start-mock.ps1` validates Docker Desktop, starts the named compose project, waits for `/api/v1/tenants/demo/projects/demo/capabilities`, and prints the base URL. The Node test calls capabilities and asserts the example response schema.

- [ ] **Step 6: Run Prism integration test**

Run:

```powershell
powershell -NoProfile -File scripts/contracts/start-mock.ps1
node --test tests/contracts/prism.test.mjs
docker compose -p dbpilot-contracts -f deploy/contracts/prism.compose.yaml down
```

Expected: Prism readiness and example test PASS; compose resources are removed.

- [ ] **Step 7: Commit the frontend boundary and mock**

```powershell
git add -- frontend/shared/control-plane-client.js frontend/tests/control-plane-client.test.js deploy/contracts scripts/contracts/start-mock.ps1 tests/contracts/prism.test.mjs package.json package-lock.json
git commit -m "feat: add generated frontend API boundary and mock"
```

## Task 10: Add Contract CI, End-to-End Traceability and Linux Verification

**Files:**
- Create: `.github/workflows/contracts.yml`
- Create: `backend/test/e2e/job_command_lifecycle_test.go`
- Create: `backend/internal/job/dispatcher.go`
- Create: `backend/internal/job/dispatcher_test.go`
- Create: `backend/scripts/verify-contract-foundation.ps1`
- Modify: `backend/scripts/build-linux.ps1`
- Modify: `backend/scripts/verify-kylin-docker.ps1`
- Modify: `README.md`
- Modify: `backend/README.md`

**Interfaces:**
- Consumes: all outputs from Tasks 1–9.
- Produces: one CI gate and one local verification command covering contract lint, generation drift, frontend, Go, Job→Command traceability, Linux builds and Kylin container smoke checks.

- [ ] **Step 1: Write a failing Job-to-Command lifecycle E2E test**

Use a PostgreSQL 16 Alpine container named `dbpilot-contract-postgres` and an in-memory Agent stream. Gate the test with `DBPILOT_CONTRACT_E2E=1` and read its DSN from `DBPILOT_CONTRACT_POSTGRES_DSN`. `verify-contract-foundation.ps1` starts the container on loopback port 55432 with database/user/password `dbpilot_contract`, waits for `pg_isready`, and always removes it in `finally`. Create a Job with two command targets, claim and dispatch outbox rows, send progress and one success/one failure result, then assert:

```text
Job.status   = succeeded
Job.outcome  = partial
completed    = 1
failed       = 1
request_id, trace_id, job_id and command_id are present in Audit events
large result is represented by artifact_id, not inline bytes
```

- [ ] **Step 2: Run the E2E test and verify it fails**

Run: `Push-Location backend; go test ./test/e2e -run TestJobCommandLifecycle -v; Pop-Location`

Expected: FAIL until the outbox dispatcher and result observer are wired end to end.

- [ ] **Step 3: Wire outbox dispatch and Agent result observation**

Add the minimal control-plane worker that claims outbox rows, builds signed Command envelopes, dispatches through `agentcontrol.Dispatcher`, marks delivery, and maps acknowledgements/progress/results back to Job transitions, Artifact references and Audit events. Reuse existing periodic worker lifecycle and bounded shutdown pattern in `cmd/controlplane/main.go`.

- [ ] **Step 4: Run the lifecycle and complete regression suites**

Run:

```powershell
npm run contracts:lint
npm run contracts:breaking
npm run contracts:verify
node --test
Push-Location backend
go test ./...
Pop-Location
```

Expected: contract lint/drift PASS, all frontend tests PASS, all Go tests PASS.

- [ ] **Step 5: Add GitHub Actions contract gate**

The workflow installs Node from the committed lockfile and Go from `backend/go.mod`, then uses the pinned OpenAPI Generator and Buf Docker images from the scripts. It runs the exact commands from Step 4 plus `verify-contract-foundation.ps1`, and triggers on changes to `contracts/**`, generated directories, generator scripts, frontend modules, backend Go code or workflow files.

- [ ] **Step 6: Extend Linux and Kylin verification**

Build both `dbpilot-controlplane` and `dbpilot-agent` for linux/amd64 and linux/arm64 with `CGO_ENABLED=0`. Extend the Kylin verifier to execute `--version`, open and close an Agent journal, parse a sample policy and start each binary far enough to validate configuration before expected connection failure.

- [ ] **Step 7: Run the local foundation verifier**

Run:

```powershell
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1
powershell -NoProfile -File backend/scripts/verify-kylin-docker.ps1 -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' -Architecture amd64
```

Expected: foundation verifier PASS. Kylin verifier reports PASS for binary execution and journal/policy smoke checks against the locally installed Kylin V10 SP1 image.

- [ ] **Step 8: Document developer workflow and stability boundary**

Document contract editing, generation, Prism startup, test commands, generated-file policy, breaking-change checks, Agent capability negotiation and the one-time pre-stable `/api/v1` migration. State that v1 becomes additive-only after the first eight modules adopt generated clients and strict handlers.

- [ ] **Step 9: Commit CI and verification**

```powershell
git add -- .github/workflows/contracts.yml backend/test/e2e/job_command_lifecycle_test.go backend/scripts README.md backend/README.md
git commit -m "ci: verify DBPilot contract foundation"
```

## Completion Gate

Before marking this plan complete, run fresh verification and record the output:

```powershell
npm run contracts:lint
npm run contracts:breaking
npm run contracts:verify
node --test
Push-Location backend
go test ./...
Pop-Location
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1
git status --short
```

Completion requires zero lint errors, zero generation drift, zero frontend/Go test failures, and no unexpected tracked changes. Existing unrelated local state must remain unchanged. After this gate, create eight independent module implementation plans for workorder, SQL window, SQL review, slow SQL, audit log, locks, schema diff and reports; each module plan consumes the generated clients, strict server interfaces and common Job/Command services delivered here.
