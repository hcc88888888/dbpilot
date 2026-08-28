# SQL Window Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Provide scoped SQL sessions, reviewed query execution, plans, history, and cancellation through the common contract.

**Architecture:** REST resources live in `contracts/openapi/modules/sql-window.yaml`; execution creates a Job and typed `ExecuteSQL`, while bounded history stays synchronous. Result sets beyond the inline limit become Artifacts.

**Tech Stack:** OpenAPI 3.1, generated browser client, Go/PostgreSQL, Job/outbox, Agent v1 `ExecuteSQL`, Node `node:test`.

**Spec:** `docs/superpowers/specs/2026-08-28-api-contract-parallel-development-design.md`

## Global Constraints

- No browser-to-Agent or arbitrary shell path; execution requires target ownership, review revision, digest, transaction policy, and timeout.
- SQL text is never written to Audit; only digest/summary is retained.
- Production frontend uses `frontend/shared/control-plane-client.js` and generated models.

---

### Task 1: Session/query contract

**Files:**
- Create: `contracts/openapi/modules/sql-window.yaml`, `contracts/examples/sql-window/query-running.json`, `tests/contracts/sql-window.test.mjs`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Regenerate: `backend/gen/openapi/dbpilot.gen.go`, `frontend/generated/api/src/`, `frontend/generated/api/dist/`

**Interfaces:**
- Produces: `createSQLSession`, `submitSQLQuery`, `getSQLQuery`, `cancelSQLQuery`, `listQueryHistory`, `getQueryPlan`.
- `submitSQLQuery` and cancellation return Job; history uses cursor pagination capped at 100.

- [ ] **Step 1: Write the failing structural contract test for operations, permissions, bounded SQL input, idempotency, Job and Artifact schemas.**
- [ ] **Step 2: Run `node --test tests/contracts/sql-window.test.mjs`; expect failure.**
- [ ] **Step 3: Add/bundle/generate the contract and run `npm run contracts:lint && npm run contracts:generate`.**
- [ ] **Step 4: Re-run the structural and generated-client tests; expect pass.**

### Task 2: Query service and command mapping

**Files:**
- Create: `backend/internal/sqlwindow/model.go`, `service.go`, `postgres.go`, `handler.go`
- Test: `backend/internal/sqlwindow/service_test.go`, `postgres_test.go`, `handler_test.go`
- Create: `backend/internal/platformdb/migrations/0006_sql_window.sql`

**Interfaces:**
- Produces: `Service.Submit(ctx, scope, actor, SubmitInput) (job.Job, error)` and `Service.Cancel(...)`.
- Uses: `job.CreateInTx`, `ExecuteSQL`, Artifact metadata, Audit `RecordOnce`; Executor/Instance Registry gates target and process authority.

- [ ] **Step 1: Write failing tests for cross-scope sessions, unsafe timeout/policy, review/digest mismatch, duplicate key, result truncation, and cancellation recovery.**
- [ ] **Step 2: Run `go test ./internal/sqlwindow -count=1`; expect failure.**
- [ ] **Step 3: Implement transactionally and map Agent terminal results without optimistic success.**
- [ ] **Step 4: Run `go test ./internal/sqlwindow ./internal/job ./internal/agent -count=1`; expect pass.**

### Task 3: Frontend adoption and Definition of Done

**Files:**
- Modify: `frontend/modules/sql-window/sql-window-api.js`, `sql-window.js`, `sql-window.css`
- Test: `frontend/tests/sql-window.test.js`

- [ ] **Step 1: Add failing tests for generated requests, trace/idempotency headers, Job polling, safe result rendering, and auth failure behavior.**
- [ ] **Step 2: Replace production demo DTOs/calls and render Artifact downloads for large results.**
- [ ] **Step 3: Run `node --test frontend/tests/sql-window.test.js`.**
- [ ] **Step 4: Definition of Done: lint/drift clean; strict handler and Agent lifecycle tests pass; query history is scoped; cancellation/timeout are durable; no credentials, raw server detail, or unbounded result body is exposed.**
