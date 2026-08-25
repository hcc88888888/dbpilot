# DBPilot Database Adapter Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Add a secure, capability-driven database adapter layer that supports connection validation, health checks, read-only SQL, and templated metric collection without exposing arbitrary SQL or credentials to policy.

**Architecture:** `internal/database` owns adapter contracts, registry, instance configuration, and bounded query execution. Each engine adapter implements the same interface and exposes a capability matrix. The first delivery supports MySQL/MariaDB/TiDB/OceanBase-compatible protocol and PostgreSQL/openGauss-compatible protocol using injected `database/sql` openers, with Docker integration tests using real services.

**Tech Stack:** Go 1.27.0, `database/sql`, `context`, `crypto/tls`, `net/url`, Docker Compose, MySQL 8, PostgreSQL 16.

**Spec:** `docs/superpowers/specs/2026-08-25-dbpilot-agent-platform-design.md` and `docs/superpowers/plans/2026-08-26-dbpilot-agent-telemetry-engine-foundation.md`.

## Global Constraints

- Linux runtime targets remain CentOS 7+ and Kylin V10+ amd64; Kylin V10+ arm64 remains supported.
- Credentials never enter signed telemetry policy or logs; connection settings use runtime secret references.
- Adapter queries are pre-registered templates selected by metric ID; arbitrary policy SQL is rejected.
- Every connection, ping, query, row scan, and close operation has a bounded context deadline.
- Read-only metrics use a restricted database account and reject mutating statements before execution.
- No shell, raw Vector/OTel YAML, dynamic driver loading, or arbitrary executable paths.

---

### Task 1: Adapter contracts, capability matrix, and registry

**Files:**
- Create: `backend/internal/database/types.go`
- Create: `backend/internal/database/registry.go`
- Create: `backend/internal/database/registry_test.go`

**Interfaces:**
- `type EngineFamily string` with `MySQLFamily`, `PostgresFamily`, `OracleFamily`, `DamengFamily`, `MongoFamily`, `HBaseFamily`, `Neo4JFamily`.
- `type InstanceConfig struct { ID, Family, Address, Database, User, SecretRef string; TLS TLSConfig; ConnectTimeout, QueryTimeout time.Duration }`.
- `type CapabilityMatrix struct { ReadOnlySQL, Metrics, Explain, Transactions bool; MetricIDs []string }`.
- `type Adapter interface { Family() EngineFamily; Capabilities() CapabilityMatrix; Ping(context.Context) error; QueryMetric(context.Context, string, map[string]any) ([]MetricRow, error); Close() error }`.
- `type Registry interface { Register(EngineFamily, Factory) error; Open(context.Context, InstanceConfig) (Adapter, error); Capabilities(EngineFamily) (CapabilityMatrix, bool) }`.

- [ ] **Step 1: Write failing registry and capability tests**

Test duplicate family registration, unsupported family, missing secret reference, invalid address/timeout, immutable capability copies, and adapter close behavior with a fake factory.

- [ ] **Step 2: Run the focused tests and verify failure**

Run: `go test ./internal/database -run 'TestRegistry|TestCapability' -count=1`

Expected: FAIL because the package and registry are missing.

- [ ] **Step 3: Implement typed contracts and registry**

Validate absolute/non-empty instance IDs, URL host/port, positive bounded timeouts, and secret reference format. Keep registry state behind a mutex and return defensive capability copies.

- [ ] **Step 4: Run focused tests and commit**

Run: `go test ./internal/database -run 'TestRegistry|TestCapability' -count=1`.

Commit: `feat: add database adapter contracts and registry`.

### Task 2: Secure SQL template executor and runtime secret boundary

**Files:**
- Create: `backend/internal/database/query.go`
- Create: `backend/internal/database/query_test.go`
- Modify: `backend/internal/policy/model.go`
- Modify: `backend/internal/policy/validate.go`

**Interfaces:**
- `type MetricTemplate struct { ID, Statement string; MaxRows int; ValueColumns []string }`.
- `type TemplateCatalog interface { Lookup(EngineFamily, string) (MetricTemplate, bool) }`.
- `func ExecuteReadOnly(ctx context.Context, db Queryer, family EngineFamily, catalog TemplateCatalog, metricID string, args map[string]any, maxRows int) ([]MetricRow, error)`.

- [ ] **Step 1: Write failing security tests**

Cover unknown metric IDs, arbitrary statement rejection, semicolon/comment/write-keyword rejection, row and column bounds, context timeout propagation, secret references excluded from policy JSON, and metric-name validation.

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/database ./internal/policy -run 'Test(ReadOnly|Template|Secret)' -count=1`.

Expected: FAIL because the executor and policy fields are missing.

- [ ] **Step 3: Implement bounded template execution**

Only resolve statements from the catalog. Accept one `SELECT`/`WITH` statement, strip comments for analysis, reject writes including `INTO`, `OUTFILE`, and `DUMPFILE`, cap rows/columns, scan only declared numeric values, and wrap every operation in a child timeout.

- [ ] **Step 4: Run focused/full policy tests and commit**

Run: `go test ./internal/database ./internal/policy -count=1`.

Commit: `feat: enforce database metric query safety`.

### Task 3: MySQL-family and PostgreSQL-family adapters

**Files:**
- Create: `backend/internal/database/mysql.go`
- Create: `backend/internal/database/postgres.go`
- Create: `backend/internal/database/sql_adapter_test.go`
- Modify: `backend/go.mod`
- Modify: `backend/go.sum`

**Interfaces:**
- `func NewMySQLFactory(opener SQLOpener, catalog TemplateCatalog) Factory`.
- `func NewPostgresFactory(opener SQLOpener, catalog TemplateCatalog) Factory`.
- MySQL-family aliases: MariaDB, TiDB, and OceanBase use the MySQL protocol only when explicitly selected by the instance family.
- PostgreSQL-family aliases: openGauss uses the PostgreSQL protocol only when explicitly selected.

- [ ] **Step 1: Write failing adapter tests**

Use a fake `database/sql` opener and `sqlmock`-style queryer to test DSN/TLS construction, Ping timeout, metric template selection, row conversion, close idempotency, and capability differences between families.

- [ ] **Step 2: Implement adapters**

Keep drivers behind `SQLOpener` so unit tests do not require network services. Register family aliases explicitly; do not infer a family from a user-controlled driver name.

- [ ] **Step 3: Run focused and full tests**

Run: `go test ./internal/database -run 'Test(MySQL|Postgres|Adapter)' -count=1` and `go test ./... -count=1`.

- [ ] **Step 4: Commit adapters**

Commit: `feat: add mysql and postgres database adapters`.

### Task 4: Docker integration verification and operator documentation

**Files:**
- Create: `backend/docker/database-adapters/docker-compose.yml`
- Create: `backend/scripts/verify-database-adapters.ps1`
- Create: `backend/internal/database/integration_test.go`
- Modify: `backend/README.md`

- [ ] **Step 1: Add integration tests**

The test uses environment-provided service addresses and credentials, creates only temporary read-only metric fixtures, executes registered templates, and verifies timeout/read-only behavior. It skips with a clear message when `DBPILOT_DB_INTEGRATION=1` is not set.

- [ ] **Step 2: Add Docker Compose services**

Provide MySQL 8 and PostgreSQL 16 services with healthchecks, isolated network, ephemeral volumes, non-production passwords, and no host port exposure by default.

- [ ] **Step 3: Add Windows PowerShell verifier**

The script locates Docker Desktop CLI, starts the compose project, waits for healthchecks, runs the integration tests with bounded timeout, prints service versions, and always tears down containers. It must fail clearly when Docker is unavailable and never claim Kylin compatibility for database containers.

- [ ] **Step 4: Run verification and commit**

Run: `go test ./... -count=1`, `go vet ./...`, and `powershell -File .\scripts\verify-database-adapters.ps1` with Docker Desktop. Commit: `test: add database adapter Docker integration verification`.
