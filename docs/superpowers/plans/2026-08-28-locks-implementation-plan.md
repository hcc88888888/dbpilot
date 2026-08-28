# Locks Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose scoped lock snapshots, events, deadlock evidence, and safe refresh/replay analysis.

**Architecture:** Lock reads use normalized telemetry; refresh uses Job plus typed `CollectNow` for authorized instances. Transaction replay is analysis-only in this module; no terminate-session or arbitrary process command is introduced.

**Tech Stack:** OpenAPI 3.1, generated browser client, Go/PostgreSQL, telemetry, Job/Artifact/Audit, Agent v1 `CollectNow`.

**Spec:** `docs/superpowers/specs/2026-08-28-api-contract-parallel-development-design.md`

## Global Constraints

- Instance ownership and `locks.read`/`locks.refresh` permissions are enforced server-side.
- Raw credentials and unbounded SQL are never returned; replay evidence is an Artifact when large.
- Unsupported Agent/database capabilities produce explicit disabled reasons.

---

### Task 1: Lock contract

**Files:**
- Create: `contracts/openapi/modules/locks.yaml`, `contracts/examples/locks/deadlock.json`, `tests/contracts/locks.test.mjs`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Regenerate: `backend/gen/openapi/dbpilot.gen.go`, `frontend/generated/api/src/`, `frontend/generated/api/dist/`

**Interfaces:**
- Produces: `listLockEvents`, `getLockEvent`, `getLockSnapshot`, `refreshLockSnapshot`, `createTransactionReplay`.
- Refresh returns Job; replay returns bounded analysis or Job+Artifact.

- [ ] **Step 1: Write a failing structural test for operations, filters, permissions, idempotency and Job/Artifact responses.**
- [ ] **Step 2: Run `node --test tests/contracts/locks.test.mjs`; expect failure.**
- [ ] **Step 3: Add/bundle/generate and lint.**
- [ ] **Step 4: Re-run structural/generated tests; expect pass.**

### Task 2: Lock query and refresh service

**Files:**
- Create: `backend/internal/locks/model.go`, `service.go`, `postgres.go`, `handler.go`
- Test: `backend/internal/locks/service_test.go`, `postgres_test.go`, `handler_test.go`
- Create: `backend/internal/platformdb/migrations/0010_locks.sql`

**Interfaces:**
- Produces: `Service.Refresh(ctx, scope, actor, instanceID, idempotencyKey) (job.Job, error)`.
- Uses: `CollectNow{collection_kinds:["locks"], instance_ids:[instanceID]}`, target authorizer, Job/outbox, Artifact and Audit.

- [ ] **Step 1: Write failing tests for scope/target authority, snapshot ordering, capability denial, duplicate refresh, timeout and redacted replay evidence.**
- [ ] **Step 2: Run `go test ./internal/locks -count=1`; expect failure.**
- [ ] **Step 3: Implement the repository/service/strict handler and command mapping.**
- [ ] **Step 4: Run `go test ./internal/locks ./internal/job -count=1`; expect pass.**

### Task 3: Frontend adoption and Definition of Done

**Files:**
- Modify: `frontend/modules/locks/locks-api.js`, `locks.js`, `locks.css`
- Test: `frontend/tests/locks.test.js`

- [ ] **Step 1: Add failing tests for generated list/detail/refresh/replay calls, Job progress, safe graph/timeline rendering and permission errors.**
- [ ] **Step 2: Replace production demo transport and duplicate DTOs.**
- [ ] **Step 3: Run `node --test frontend/tests/locks.test.js`.**
- [ ] **Step 4: Definition of Done: lint/drift and strict tests pass; refresh is durable/authorized; replay is non-mutating; capability reasons are accurate; no raw secret or production demo fallback remains.**
