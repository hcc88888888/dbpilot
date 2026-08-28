# Audit Log Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver searchable audit events, statistics, details, and export Jobs through the generated platform boundary.

**Architecture:** The existing append-only Audit Service remains authoritative; the module adds filtered projections and an export Job that writes an Artifact. It issues no Agent command and never exposes storage references or sensitive detail.

**Tech Stack:** OpenAPI 3.1, generated browser client, Go/PostgreSQL, Audit `RecordOnce`, Job/Artifact, Node `node:test`.

**Spec:** `docs/superpowers/specs/2026-08-28-api-contract-parallel-development-design.md`

## Global Constraints

- Audit rows are append-only, scope-filtered, capped at 100 per page, and include result/request/trace/job/command correlation.
- Export is idempotent, audited, and returns Job; file access uses signed Artifact content routes.
- Details must pass canonical JSON redaction before storage and response.

---

### Task 1: Audit search/statistics/export contract

**Files:**
- Create: `contracts/openapi/modules/audit-log.yaml`, `contracts/examples/audit-log/audit-event.json`, `tests/contracts/audit-log.test.mjs`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Regenerate: `backend/gen/openapi/dbpilot.gen.go`, `frontend/generated/api/src/`, `frontend/generated/api/dist/`

**Interfaces:**
- Produces: `getAuditEvent`, `listAuditStatistics`, `createAuditExport`; reuses `listAuditEvents`.
- Export response is Job and requires `platform.audit.export` plus Idempotency-Key.

- [ ] **Step 1: Write a failing structural test for filters, cursor max 100, trace/result/command fields, export permission and Job response.**
- [ ] **Step 2: Run `node --test tests/contracts/audit-log.test.mjs`; expect failure.**
- [ ] **Step 3: Add/bundle/generate the contract and run `npm run contracts:lint`.**
- [ ] **Step 4: Re-run contract/generated tests; expect pass.**

### Task 2: Projection and export service

**Files:**
- Create: `backend/internal/auditlog/service.go`, `postgres.go`, `handler.go`, `export.go`
- Test: `backend/internal/auditlog/service_test.go`, `postgres_test.go`, `handler_test.go`, `export_test.go`
- Create: `backend/internal/platformdb/migrations/0009_audit_exports.sql`

**Interfaces:**
- Produces: `Service.Export(ctx, scope, actor, Filter, idempotencyKey) (job.Job, error)`.
- Uses: Audit Service/List, Job/Artifact and Audit `RecordOnce`; Agent usage is explicitly none.

- [ ] **Step 1: Write failing tests for scope/cursor isolation, filter bounds, redaction, immutable rows, export dedupe and safe Artifact metadata.**
- [ ] **Step 2: Run `go test ./internal/auditlog ./internal/audit -count=1`; expect failure.**
- [ ] **Step 3: Implement projections/export worker/strict handler.**
- [ ] **Step 4: Run the same command; expect pass.**

### Task 3: Frontend adoption and Definition of Done

**Files:**
- Modify: `frontend/modules/audit-log/audit-log-api.js`, `audit-log.js`, `audit-log.css`
- Test: `frontend/tests/audit-log.test.js`

- [ ] **Step 1: Add failing tests for generated filters/detail/export, result/command trace rendering, Artifact download, and no demo fallback on auth errors.**
- [ ] **Step 2: Replace production demo calls/DTOs.**
- [ ] **Step 3: Run `node --test frontend/tests/audit-log.test.js`.**
- [ ] **Step 4: Definition of Done: contract/drift clean; append-only/live PostgreSQL tests pass; exports are Job+Artifact and audited; secrets/storage refs never appear; generated API is the only production transport.**
