# Schema Diff Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement authorized schema comparison Jobs, object-level differences, DDL Artifacts, and workorder-only application handoff.

**Architecture:** A schema diff creates one Job spanning source and target instances and uses typed `InspectInstance` commands. This module never applies DDL directly; selected changes become a workorder reference.

**Tech Stack:** OpenAPI 3.1, generated browser client, Go/PostgreSQL, Job/outbox, Agent v1 `InspectInstance`, Artifact/Audit.

**Spec:** `docs/superpowers/specs/2026-08-28-api-contract-parallel-development-design.md`

## Global Constraints

- Source and target instance ownership is required; identical instances and unsupported database combinations are rejected.
- Generated DDL is content, never a shell command, and is downloaded through Artifact authorization.
- Applying a diff creates/links a workorder; schema-diff handlers do not execute changes.

---

### Task 1: Schema-diff contract

**Files:**
- Create: `contracts/openapi/modules/schema-diff.yaml`, `contracts/examples/schema-diff/diff-complete.json`, `tests/contracts/schema-diff.test.mjs`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Regenerate: `backend/gen/openapi/dbpilot.gen.go`, `frontend/generated/api/src/`, `frontend/generated/api/dist/`

**Interfaces:**
- Produces: `createSchemaDiff`, `getSchemaDiff`, `listSchemaDiffs`, `listSchemaDiffItems`, `createSchemaDiffWorkorder`.
- Create returns Job; workorder handoff returns a resource reference and requires idempotency.

- [ ] **Step 1: Write a failing structural test for operations, dual targets, object filters, permissions, Job/Artifact and workorder-only apply semantics.**
- [ ] **Step 2: Run `node --test tests/contracts/schema-diff.test.mjs`; expect failure.**
- [ ] **Step 3: Add/bundle/generate and lint.**
- [ ] **Step 4: Re-run structural/generated tests; expect pass.**

### Task 2: Comparison orchestration

**Files:**
- Create: `backend/internal/schemadiff/model.go`, `service.go`, `postgres.go`, `handler.go`, `compare.go`
- Test: `backend/internal/schemadiff/service_test.go`, `postgres_test.go`, `handler_test.go`, `compare_test.go`
- Create: `backend/internal/platformdb/migrations/0011_schema_diff.sql`

**Interfaces:**
- Produces: `Service.Create(ctx, scope, actor, CreateInput) (job.Job, error)` and `Service.CreateWorkorder(...)`.
- Uses: two `InspectInstance` commands, target authorizer, Job partial outcome, Artifact DDL and Audit `RecordOnce`.

- [ ] **Step 1: Write failing tests for dual-target authority, deterministic comparison, partial Agent result, timeout/cancel, duplicate creation and no direct DDL execution.**
- [ ] **Step 2: Run `go test ./internal/schemadiff -count=1`; expect failure.**
- [ ] **Step 3: Implement orchestration/comparison/repository/strict handler.**
- [ ] **Step 4: Run `go test ./internal/schemadiff ./internal/job -count=1`; expect pass.**

### Task 3: Frontend adoption and Definition of Done

**Files:**
- Modify: `frontend/modules/schema-diff/schema-diff-api.js`, `schema-diff.js`, `schema-diff.css`
- Test: `frontend/tests/schema-diff.test.js`

- [ ] **Step 1: Add failing tests for generated create/list/detail/workorder calls, Job polling, safe DDL rendering/download and permission errors.**
- [ ] **Step 2: Replace production demo transport/DTOs.**
- [ ] **Step 3: Run `node --test frontend/tests/schema-diff.test.js`.**
- [ ] **Step 4: Definition of Done: contract/drift, backend and two-Agent E2E tests pass; partial/timeout states are honest; DDL is Artifact-backed; implementation occurs only through workorders; production has no demo fallback.**
