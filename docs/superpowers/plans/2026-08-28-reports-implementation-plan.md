# Reports Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement report templates, generation Jobs, schedules, delivery status, and signed Artifact downloads.

**Architecture:** Template/configuration writes are synchronous and ETag-protected; generation is a Job that reads authorized module projections and optionally issues typed `CollectNow` before rendering. Report bytes live only in Artifact storage.

**Tech Stack:** OpenAPI 3.1, generated browser client, Go/PostgreSQL, Job/outbox, optional Agent v1 `CollectNow`, Artifact/Audit, Node `node:test`.

**Spec:** `docs/superpowers/specs/2026-08-28-api-contract-parallel-development-design.md`

## Global Constraints

- Report content is bounded/redacted and downloaded through signed content routes; storage references never leave the server.
- Template/schedule updates use ETag/If-Match and Idempotency-Key.
- Optional collection requires instance ownership and advertised Agent capability; otherwise generation reports a precise disabled/failure reason.

---

### Task 1: Report contract

**Files:**
- Create: `contracts/openapi/modules/reports.yaml`, `contracts/examples/reports/report-ready.json`, `tests/contracts/reports.test.mjs`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Regenerate: `backend/gen/openapi/dbpilot.gen.go`, `frontend/generated/api/src/`, `frontend/generated/api/dist/`

**Interfaces:**
- Produces: `listReportTemplates`, `createReportTemplate`, `updateReportTemplate`, `generateReport`, `getReport`, `listReports`, `createReportSchedule`, `sendReport`.
- Generate/send return Job and Artifact references; template/schedule updates return ETags.

- [ ] **Step 1: Write a failing structural test for operations, permissions, ETags/idempotency, Job/Artifact, recipient bounds and redacted sections.**
- [ ] **Step 2: Run `node --test tests/contracts/reports.test.mjs`; expect failure.**
- [ ] **Step 3: Add/bundle/generate and lint.**
- [ ] **Step 4: Re-run structural/generated tests; expect pass.**

### Task 2: Generation and scheduling service

**Files:**
- Create: `backend/internal/reports/model.go`, `service.go`, `postgres.go`, `handler.go`, `renderer.go`, `scheduler.go`
- Test: `backend/internal/reports/service_test.go`, `postgres_test.go`, `handler_test.go`, `renderer_test.go`, `scheduler_test.go`
- Create: `backend/internal/platformdb/migrations/0012_reports.sql`

**Interfaces:**
- Produces: `Service.Generate(ctx, scope, actor, GenerateInput) (job.Job, error)` and `Service.Send(...) (job.Job, error)`.
- Uses: Job/Artifact/Audit; optional `CollectNow` is created only for explicitly requested authorized instances and never for static projection-only reports.

- [ ] **Step 1: Write failing tests for ETag conflicts, schedule dedupe, scope/recipient validation, redaction, Artifact integrity, optional Agent capability, retry and cancellation.**
- [ ] **Step 2: Run `go test ./internal/reports -count=1`; expect failure.**
- [ ] **Step 3: Implement services/workers/strict handlers with deterministic rendering.**
- [ ] **Step 4: Run `go test ./internal/reports ./internal/artifact ./internal/job -count=1`; expect pass.**

### Task 3: Frontend adoption and Definition of Done

**Files:**
- Modify: `frontend/modules/reports/reports-api.js`, `reports.js`, `reports.css`
- Test: `frontend/tests/reports.test.js`

- [ ] **Step 1: Add failing tests for generated template/report/schedule/send calls, ETags, Job progress, signed download and permission errors.**
- [ ] **Step 2: Replace production demo calls/DTOs and preserve explicit demo mode only.**
- [ ] **Step 3: Run `node --test frontend/tests/reports.test.js`.**
- [ ] **Step 4: Definition of Done: contract/drift, strict service and scheduler tests pass; generated reports are Artifact-backed and checksum-verified; schedules/idempotency are durable; no secret/storage ref or production demo fallback is exposed.**
