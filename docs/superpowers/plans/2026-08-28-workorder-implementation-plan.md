# Workorder Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the workorder demo adapter with an authorized, review-pinned approval and Agent execution workflow.

**Architecture:** `contracts/openapi/modules/workorders.yaml` defines tickets and actions; strict handlers persist approvals and create a Job plus unsigned `ExecuteSQL` outbox command in one transaction. Agent results drive Job/workorder state and large logs are Artifact references.

**Tech Stack:** OpenAPI 3.1, generated `typescript-fetch`, Go strict handlers, PostgreSQL, Job/outbox, Agent v1 `ExecuteSQL`, Node `node:test`.

**Spec:** `docs/superpowers/specs/2026-08-28-api-contract-parallel-development-design.md`

## Global Constraints

- SQL execution requires immutable `review_revision`, SHA-256 `sql_digest`, approval, scope permission, and an authorized instance target.
- Browser code uses `frontend/shared/control-plane-client.js`; no private DTO or arbitrary shell path is allowed.
- Every write is idempotent and audited; remote work returns `202` with a Job.

---

### Task 1: Contract and generated boundary

**Files:**
- Create: `contracts/openapi/modules/workorders.yaml`
- Create: `contracts/examples/workorders/workorder-approved.json`
- Create: `tests/contracts/workorders.test.mjs`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Regenerate: `backend/gen/openapi/dbpilot.gen.go`, `frontend/generated/api/src/`, `frontend/generated/api/dist/`

**Interfaces:**
- Produces: `listWorkorders`, `createWorkorder`, `approveWorkorder`, `rejectWorkorder`, `executeWorkorder`, `cancelWorkorder`, `rollbackWorkorder`.
- `executeWorkorder` returns Job and requires `workorders.execute`.

- [ ] **Step 1: Write a structural test asserting the seven operations, permissions, idempotency headers, immutable review fields, and Job response.**
- [ ] **Step 2: Run `node --test tests/contracts/workorders.test.mjs`; expect failure because the module contract is absent.**
- [ ] **Step 3: Add the contract/example, compose the root document, then run `npm run contracts:lint && npm run contracts:generate`.**
- [ ] **Step 4: Run `node --test tests/contracts/workorders.test.mjs tests/contracts/generated-rest.test.mjs`; expect pass.**

### Task 2: Transactional service and Agent lifecycle

**Files:**
- Create: `backend/internal/workorder/model.go`, `service.go`, `postgres.go`, `handler.go`
- Test: `backend/internal/workorder/service_test.go`, `postgres_test.go`, `handler_test.go`
- Create: `backend/internal/platformdb/migrations/0005_workorders.sql`

**Interfaces:**
- Produces: `Service.Execute(ctx, scope, actor, workorderID, idempotencyKey) (job.Job, error)`.
- Uses: `job.Repository.CreateInTx` and an unsigned `agentv1.ExecuteSQL`; execution is rejected unless approval, revision, digest, and instance ownership match.

- [ ] **Step 1: Write failing tests for stale review revision, digest substitution, missing approval, duplicate execution, cross-scope access, and Job/outbox atomicity.**
- [ ] **Step 2: Run `go test ./internal/workorder -count=1`; expect those policy tests to fail.**
- [ ] **Step 3: Implement the repository/service/strict handler and Audit `RecordOnce` events.**
- [ ] **Step 4: Run `go test ./internal/workorder ./internal/job -count=1`; expect pass.**

### Task 3: Frontend adoption and module Definition of Done

**Files:**
- Modify: `frontend/modules/workorder/workorder-api.js`, `workorder.js`, `workorder.css`
- Test: `frontend/tests/workorder.test.js`

- [ ] **Step 1: Add failing tests proving production uses the generated scoped API, renders Job progress, and never falls back after 401/403.**
- [ ] **Step 2: Replace production demo calls while retaining an explicitly selected demo adapter only.**
- [ ] **Step 3: Run `node --test frontend/tests/workorder.test.js` and `go test ./internal/workorder -count=1`.**
- [ ] **Step 4: Definition of Done: contract/drift clean; strict auth/scope/idempotency/audit tests pass; approval-pinned ExecuteSQL E2E reaches Artifact/Job terminal evidence; no duplicate DTO or raw SQL audit body remains.**
