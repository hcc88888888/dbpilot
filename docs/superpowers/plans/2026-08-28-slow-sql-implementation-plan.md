# Slow SQL Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve scoped slow-SQL fingerprints, samples, analyses, acknowledgements, and ignore decisions from durable telemetry.

**Architecture:** The module reads normalized telemetry and creates analysis Jobs when enrichment is long-running. Agent usage is limited to typed `CollectDiagnostic` for an authorized instance; the removed Redis slow-query feature is not restored.

**Tech Stack:** OpenAPI 3.1, generated browser client, Go/PostgreSQL, telemetry, Job/Artifact/Audit, Agent v1 `CollectDiagnostic`.

**Spec:** `docs/superpowers/specs/2026-08-28-api-contract-parallel-development-design.md`

## Global Constraints

- Redis slow-query support remains out of scope.
- SQL samples are redacted/digested; list and analysis queries are tenant/project/instance scoped.
- Long analysis returns Job and stores large plans/evidence as Artifacts.

---

### Task 1: Slow-SQL contract

**Files:**
- Create: `contracts/openapi/modules/slow-sql.yaml`, `contracts/examples/slow-sql/fingerprint.json`, `tests/contracts/slow-sql.test.mjs`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Regenerate: `backend/gen/openapi/dbpilot.gen.go`, `frontend/generated/api/src/`, `frontend/generated/api/dist/`

**Interfaces:**
- Produces: `listSlowSQLFingerprints`, `getSlowSQLFingerprint`, `createSlowSQLAnalysis`, `acknowledgeSlowSQL`, `ignoreSlowSQL`.
- Analysis action returns Job; mutation actions require idempotency and exact permissions.

- [ ] **Step 1: Write the failing structural test for operations, filters, pagination max 100, permissions, Job/Artifact and redacted sample shape.**
- [ ] **Step 2: Run `node --test tests/contracts/slow-sql.test.mjs`; expect failure.**
- [ ] **Step 3: Add/bundle/generate and run contract lint.**
- [ ] **Step 4: Re-run structural/generated tests; expect pass.**

### Task 2: Telemetry query and analysis service

**Files:**
- Create: `backend/internal/slowsql/model.go`, `service.go`, `postgres.go`, `handler.go`
- Test: `backend/internal/slowsql/service_test.go`, `postgres_test.go`, `handler_test.go`
- Create: `backend/internal/platformdb/migrations/0008_slow_sql.sql`

**Interfaces:**
- Produces: `Service.Analyze(ctx, scope, actor, fingerprintID) (job.Job, error)`.
- Uses: typed `CollectDiagnostic{instance_id, diagnostic_kinds:["slow_sql_plan"]}`, target authorizer, Artifact and Audit; never accepts a shell command or raw credential URI.

- [ ] **Step 1: Write failing tests for scope filtering, threshold bounds, redaction, duplicate actions, unsupported Agent capability, timeout and partial evidence.**
- [ ] **Step 2: Run `go test ./internal/slowsql -count=1`; expect failure.**
- [ ] **Step 3: Implement query/service/strict handler plus Job/outbox mapping.**
- [ ] **Step 4: Run `go test ./internal/slowsql ./internal/job -count=1`; expect pass.**

### Task 3: Frontend adoption and Definition of Done

**Files:**
- Modify: `frontend/modules/slow-sql/slow-sql-api.js`, `slow-sql.js`, `slow-sql.css`
- Test: `frontend/tests/slow-sql.test.js`

- [ ] **Step 1: Add failing tests for generated filtering/actions, Job progress, safe DDL/plan rendering, and auth errors.**
- [ ] **Step 2: Replace production demo calls/DTOs and keep demo mode explicit.**
- [ ] **Step 3: Run `node --test frontend/tests/slow-sql.test.js`.**
- [ ] **Step 4: Definition of Done: contract/drift, backend and E2E tests pass; Redis scope is absent; diagnostic commands are authorized/typed; SQL/credentials are redacted; frontend production mode uses generated APIs only.**
