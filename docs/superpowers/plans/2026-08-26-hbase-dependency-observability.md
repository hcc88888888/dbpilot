# HBase Dependency Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add HBase, HDFS, and ZooKeeper JMX-based observability with dependency topology, unified metrics, health aggregation, and alert context in DBPilot.

**Architecture:** Keep non-SQL component adapters separate from existing SQL adapters. Each adapter reads a read-only, allowlisted JMX/HTTP endpoint and emits the common metric model into the existing Agent spool pipeline. A topology aggregator links HBase to referenced HDFS and ZooKeeper clusters and derives dependency-aware health and alert evidence without executing remediation.

**Tech Stack:** Go 1.25 language floor, OTel Contrib v0.158.0/core v1.64.0, existing Agent spool/runtime, `net/http`, `encoding/json`, Docker-based integration fixtures, PowerShell Kylin verification.

**Spec:** `docs/superpowers/specs/2026-08-26-hbase-dependency-observability-design.md`

## Global Constraints

- Only read-only JMX/HTTP endpoints are permitted; no JMX write operations, shell commands, arbitrary REST paths, scripts, or management mutations.
- Credentials and TLS materials use runtime Secret references and never appear in metrics or logs.
- All requests enforce connection, read, and overall deadlines; retry failures with bounded exponential backoff and report adapter status.
- Metrics are emitted with `cluster`, `component`, `role`, `host`, `instance`, `metric_name`, value, unit, and sample time; optional JMX object/property names are diagnostic only.
- HBase dependency references must resolve through authorized HDFS/ZooKeeper cluster definitions and cannot bypass access control.
- Missing dependencies must not suppress independent HBase samples; health output must mark dependency data incomplete.
- No endpoint-to-endpoint support claim is valid without executable Docker/Kylin evidence; parser/contract tests must be labeled separately.

### Task 1: Common non-SQL component contracts and topology references

**Files:**
- Create: `backend/internal/database/component_types.go`
- Create: `backend/internal/database/component_registry.go`
- Modify: `backend/internal/database/types.go`
- Test: `backend/internal/database/component_registry_test.go`

**Interfaces:**
- Produces `type ComponentAdapter interface { Component() ComponentKind; Capabilities() CapabilityMatrix; Ping(context.Context) error; Collect(context.Context, MetricRequest) ([]MetricSample, error); Close() error }`.
- Produces `ComponentDefinition{ID, Kind, Endpoints, SecretRef, TLSRef, Dependencies}` and `DependencyRef{HDFSClusterID, ZooKeeperClusterID}` with canonical reference validation.

- [ ] Step 1: Add failing tests for component-kind validation, canonical `secret://provider/name` references, dependency authorization, and typed-nil registry rejection.
- [ ] Step 2: Run `go test ./internal/database -run 'Component|Registry'` and confirm failures.
- [ ] Step 3: Implement the contracts and registry using existing SQL registry validation patterns; keep SQL adapters unchanged.
- [ ] Step 4: Run focused tests plus `go vet ./internal/database/...` and confirm pass.
- [ ] Step 5: Commit `feat: add non-sql component adapter contracts`.

### Task 2: Shared JMX JSON client and metric normalization

**Files:**
- Create: `backend/internal/database/jmx_client.go`
- Create: `backend/internal/database/jmx_types.go`
- Test: `backend/internal/database/jmx_client_test.go`

**Interfaces:**
- Consumes `SecretResolver` and `TLSConfig` boundaries already used by SQL adapters.
- Produces `JMXClient.Fetch(ctx context.Context, endpoint Endpoint, allowlist BeanAllowlist) ([]JMXBean, error)` and `NormalizeJMXBeans(...) ([]MetricSample, []ParseIssue, error)`.

- [ ] Step 1: Write tests for `/jmx` JSON decoding, Bean/property allowlists, unit conversion, missing attributes, deadline cancellation, and redacted HTTP errors.
- [ ] Step 2: Run the focused tests and verify they fail before implementation.
- [ ] Step 3: Implement an HTTP client that constructs only validated `/jmx` URLs, resolves Secret/TLS at runtime, applies overall deadlines, and never logs credentials or response bodies.
- [ ] Step 4: Implement normalization into DBPilot metric labels and per-field parse issues; unknown Beans are skipped with status, not remapped.
- [ ] Step 5: Run focused tests, package tests, and `go vet`; commit `feat: add shared jmx metric client`.

### Task 3: HBase JMX adapter

**Files:**
- Create: `backend/internal/database/hbase.go`
- Test: `backend/internal/database/hbase_test.go`
- Modify: `backend/internal/database/component_registry.go`

**Interfaces:**
- Consumes `JMXClient` and `ComponentDefinition` from Tasks 1–2.
- Produces registered `hbase` adapter with allowlisted mappings for JVM, Master, RegionServer, Region/Store, BlockCache, MemStore, WAL, Flush, Compaction, Split, and request latency.

- [ ] Step 1: Add fixture-based tests for Master and RegionServer Bean payloads, role labels, version aliases, missing optional Beans, and independent endpoint failure reporting.
- [ ] Step 2: Run HBase adapter tests and confirm failure.
- [ ] Step 3: Implement fixed Bean/property maps, endpoint iteration, runtime Secret/TLS resolution, and status propagation into the common metric pipeline.
- [ ] Step 4: Verify no arbitrary Bean/property or management operation can be configured; run package tests and vet.
- [ ] Step 5: Commit `feat: add hbase jmx adapter`.

### Task 4: HDFS and ZooKeeper adapters

**Files:**
- Create: `backend/internal/database/hdfs.go`
- Create: `backend/internal/database/zookeeper.go`
- Test: `backend/internal/database/hdfs_test.go`
- Test: `backend/internal/database/zookeeper_test.go`
- Modify: `backend/internal/database/component_registry.go`

**Interfaces:**
- Consumes the shared JMX client and component registry.
- Produces `hdfs` mappings for NameNode/DataNode capacity, blocks, replication, RPC, disk/I/O, and faults; produces `zookeeper` mappings for role/quorum, latency, requests, sessions, connections, ZNodes, Watches, transaction logs, and snapshots.

- [ ] Step 1: Add fixture tests for representative NameNode/DataNode and ZooKeeper JMX payloads, role labels, optional-field handling, and redacted failures.
- [ ] Step 2: Run both focused test files and confirm failures.
- [ ] Step 3: Implement fixed mappings and register both adapters; ZooKeeper's compatibility management endpoint must be an explicit read-only allowlisted path and never a mutation command.
- [ ] Step 4: Run all database package tests and vet; commit `feat: add hdfs and zookeeper adapters`.

### Task 5: Dependency topology, health aggregation, and alert evidence

**Files:**
- Create: `backend/internal/database/dependency_topology.go`
- Create: `backend/internal/database/health_aggregation.go`
- Test: `backend/internal/database/dependency_topology_test.go`
- Test: `backend/internal/database/health_aggregation_test.go`

**Interfaces:**
- Consumes `ComponentDefinition.Dependencies` and normalized `MetricSample` values.
- Produces `ResolveTopology(...)`, `AggregateHealth(...)`, and `BuildDependencyEvidence(...)` with explicit `component_failure`, `dependency_failure`, and `data_incomplete` states.

- [ ] Step 1: Write tests for authorized HBase→HDFS/ZooKeeper resolution, missing dependency samples, deduplication keys, and the four initial evidence rules from the spec.
- [ ] Step 2: Run focused tests and confirm failure.
- [ ] Step 3: Implement topology resolution without credential inheritance, component-local health first, then dependency-aware aggregate health.
- [ ] Step 4: Implement evidence records only; do not execute remediation. Verify alert keys include cluster, component, role, and rule.
- [ ] Step 5: Run package tests and vet; commit `feat: correlate hbase dependency health`.

### Task 6: Spool/runtime integration and Docker/Kylin verification

**Files:**
- Modify: `backend/internal/agent/*` (collector registration/config wiring only)
- Create: `backend/scripts/verify-hbase-dependencies.ps1`
- Create: `backend/deploy/compose/hbase-dependencies.compose.yaml`
- Modify: `backend/README.md`
- Test: `backend/internal/database/dependency_integration_test.go`

**Interfaces:**
- Consumes the three registered adapters and topology aggregator.
- Produces runtime configuration, spool samples/status events, a reproducible integration fixture, and Kylin V10 verification output.

- [ ] Step 1: Add an integration test that serves fixture JMX endpoints, runs the real collector path, verifies HBase/HDFS/ZooKeeper samples and dependency evidence reach spool, and checks restart-safe IDs.
- [ ] Step 2: Run the integration test against the existing Go toolchain/container and confirm it fails before wiring.
- [ ] Step 3: Wire adapters into Agent configuration and collector lifecycle with bounded retries and status propagation.
- [ ] Step 4: Add a Docker fixture with isolated network, no host ports, health checks, non-production read-only credentials, and cleanup failure reporting.
- [ ] Step 5: Run full Go tests/vet, Docker integration, and `verify-hbase-dependencies.ps1` in Kylin V10; record exact results in the SDD progress ledger.
- [ ] Step 6: Commit `test: verify hbase dependency observability runtime`.

## Self-review checklist

- Spec coverage: component adapters, JMX parsing, topology references, health/evidence rules, security, spool integration, Docker/Kylin validation are covered by Tasks 1–6.
- Placeholder scan: no incomplete markers or unspecified implementation steps are used.
- Type consistency: Task 1 defines `ComponentAdapter`, `ComponentDefinition`, and `DependencyRef`; Task 2 defines JMX interfaces; Tasks 3–6 consume those exact boundaries.
