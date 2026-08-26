# DBPilot Oracle and Dameng Adapter Wave Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Extend the database adapter foundation with explicit Oracle and Dameng families while preserving the secure secret, TLS, timeout, read-only template, and capability-matrix contracts.

**Architecture:** Oracle and Dameng adapters reuse the existing `database.Adapter`, `SecretResolver`, `SQLOpener`, and `ExecuteReadOnly` boundaries. Vendor-specific behavior is isolated in family-specific DSN/TLS builders and metric template catalogs; no proprietary driver is forced into the core binary until its licensing, CGO, and Linux packaging constraints are approved.

**Tech Stack:** Go 1.27.0, `database/sql`-compatible injected openers, Oracle pure-Go opener boundary, Dameng runtime driver boundary, Docker or vendor test service when available.

## Constraints

- No credentials or certificate material in policy JSON or logs.
- Oracle/Dameng metric SQL is always selected by registered metric ID.
- Vendor driver names and DSN formats are fixed constants, never policy-controlled.
- Unsupported TLS or driver features fail closed instead of being silently ignored.
- Linux targets remain CentOS 7+ and Kylin V10+ amd64/arm64; CGO implications must be reported explicitly.

### Task 1: Oracle adapter contract and templates

**Files:** `backend/internal/database/oracle.go`, `oracle_test.go`, template catalog files.

- Add `OracleFamily` registration with explicit capabilities.
- Build Oracle service-name/SID DSNs from validated instance fields and runtime secret references.
- Add bounded health and read-only metric templates for sessions, transactions, locks, tablespace, and slow SQL.
- Reject unsupported TLS/driver settings explicitly.
- Test DSN construction, secret resolver use, timeout, sanitized errors, template-only queries, and capability copy semantics.

### Task 2: Dameng adapter contract and templates

**Files:** `backend/internal/database/dameng.go`, `dameng_test.go`, template catalog files.

- Add `DamengFamily` registration with explicit capabilities.
- Keep the DM driver name and DSN construction fixed behind the opener boundary.
- Add bounded templates for sessions, locks, transactions, storage, and slow SQL using DM-compatible syntax.
- Test runtime secret/TLS propagation, unsupported feature rejection, timeout, sanitized errors, and read-only mutation rejection.

### Task 3: Linux packaging and integration evidence

**Files:** `backend/docker/database-adapters/docker-compose.oracle-dameng.yml`, `backend/scripts/verify-oracle-dameng.ps1`, `backend/README.md`.

- Provide opt-in vendor-service integration configuration; do not publish credentials or claim support when images/drivers are unavailable.
- Reuse the Docker Desktop CLI discovery/cleanup pattern.
- Print exact driver, database version, architecture, and CGO mode; fail if a requested adapter silently falls back to another family.
- Record which tests require an Oracle/Dameng licensed environment or Kylin runner.
