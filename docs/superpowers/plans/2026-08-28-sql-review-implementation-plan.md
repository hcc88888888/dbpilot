# SQL Review Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move SQL review submissions, immutable revisions, findings, rules, and approvals onto generated contracts and strict handlers.

**Architecture:** SQL review is analysis-only: it produces immutable `review_revision` plus `sql_digest` and never executes SQL. Large/batch analysis may use Job and Artifact, but no Agent command is issued by this module.

**Tech Stack:** OpenAPI 3.1, generated browser client, Go/PostgreSQL, Job/Artifact/Audit, Node `node:test`.

**Spec:** `docs/superpowers/specs/2026-08-28-api-contract-parallel-development-design.md`

## Global Constraints

- Review output cannot execute SQL; workorders consume immutable revision/digest pairs.
- Rule mutations require ETag/If-Match and Idempotency-Key; Audit stores digest/summary only.
- Existing frontend files remain the UI entry points.

---

### Task 1: Review/rule contract

**Files:**
- Create: `contracts/openapi/modules/sql-review.yaml`, `contracts/examples/sql-review/review-approved.json`, `tests/contracts/sql-review.test.mjs`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Regenerate: `backend/gen/openapi/dbpilot.gen.go`, `frontend/generated/api/src/`, `frontend/generated/api/dist/`

**Interfaces:**
- Produces: `submitSQLReview`, `getSQLReview`, `listSQLReviews`, `approveSQLReview`, `rejectSQLReview`, `listSQLReviewRules`, `updateSQLReviewRule`.
- Review response requires `review_revision`, SHA-256 digest, findings, risk and status.

- [ ] **Step 1: Write a failing structural test for operations, permissions, immutable revision/digest, ETags, idempotency, and no execute action.**
- [ ] **Step 2: Run `node --test tests/contracts/sql-review.test.mjs`; expect failure.**
- [ ] **Step 3: Define/bundle/generate and run `npm run contracts:lint && npm run contracts:generate`.**
- [ ] **Step 4: Re-run contract/generated tests; expect pass.**

### Task 2: Review engine boundary

**Files:**
- Create: `backend/internal/sqlreview/model.go`, `service.go`, `postgres.go`, `handler.go`, `engine.go`
- Test: `backend/internal/sqlreview/service_test.go`, `postgres_test.go`, `handler_test.go`, `engine_test.go`
- Create: `backend/internal/platformdb/migrations/0007_sql_review.sql`

**Interfaces:**
- Produces: `Service.Submit(ctx, scope, actor, SQL) (Review, *job.Job, error)` and immutable `ReviewReference{ID, Revision, Digest}`.
- Uses: Job only for batch/long analysis, Artifact for large findings, Audit `RecordOnce`; Agent usage is explicitly none.

- [ ] **Step 1: Write failing tests for deterministic digest, immutable revisions, rule-version pinning, scope/RBAC, ETag conflict, and absence of execution side effects.**
- [ ] **Step 2: Run `go test ./internal/sqlreview -count=1`; expect failure.**
- [ ] **Step 3: Implement the engine/service/repository/strict handler.**
- [ ] **Step 4: Run `go test ./internal/sqlreview ./internal/job -count=1`; expect pass.**

### Task 3: Frontend adoption and Definition of Done

**Files:**
- Modify: `frontend/modules/sql-review/sql-review-api.js`, `sql-review.js`, `sql-review.css`
- Test: `frontend/tests/sql-review.test.js`

- [ ] **Step 1: Add failing tests for generated submission/list/rule calls, immutable revision display, safe findings, and 401/403 behavior.**
- [ ] **Step 2: Replace production demo calls and duplicate DTOs.**
- [ ] **Step 3: Run `node --test frontend/tests/sql-review.test.js`.**
- [ ] **Step 4: Definition of Done: lint/drift and strict tests pass; revisions/digests are immutable and workorder-ready; no execution command exists; audit contains no SQL body; frontend has no production fallback.**
