# Host and plugin platform technical debt

## Task 12 template transport bound

- A plugin assignment may contain at most 128 instances, 128 immutable template revisions and 16,384 configured instance-template pairs.
- The canonical persisted template projection is limited to 256 KiB. The fully expanded `ApplyConfiguration`, initial `CollectNow`, resume-cursor and application-ACK protobuf messages are each limited to 4 MiB before a private UDS RPC or partial Agent spool admission.
- Task 12 must measure the deterministic protobuf projection before publishing a reconciliation command. A definition set above either byte bound must be rejected or explicitly paged/reference-shared; it must never be truncated or partially applied.

## TD-PLUGIN-001: Agent and database plugin share one non-root UID

- Affected module: Agent Plugin Supervisor and private plugin runtime.
- Trigger conditions: a signed database plugin is compromised or contains a defect that attempts to access another Agent-owned plugin/runtime file.
- Functional impact: none for the current one-process-per-family monitoring workflow. The shared UID weakens filesystem isolation between the Agent and its child plugin even though both run non-root with zero Linux capabilities, no Docker socket, a clean environment and fixed executable/arguments.
- Severity: medium before production hardening; high if third-party publishers are admitted without equivalent review and signing controls.
- Recommended remediation stage: Task 10/private gateway and systemd sandbox hardening before production rollout. Evaluate a separately approved narrow launcher or per-family service identity, Landlock/seccomp/systemd restrictions, and peer-credential enforcement without making the main Agent root or granting it ambient capabilities.

## TD-BUILD-001: Contract development dependency audit findings

- Affected module: root contract-generation/lint development toolchain installed from `package-lock.json`.
- Trigger conditions: a developer or CI job executes the pinned Node-based contract tooling; the packages are not linked into the Go Agent or Control Plane production binaries.
- Functional impact: none observed. Contract lint, breaking checks, zero-drift generation and all contract tests pass. `npm ci --ignore-scripts` reports 16 moderate and 1 high advisory in the existing dependency graph.
- Severity: medium for the development/CI environment, non-blocking for Task 9 runtime functionality.
- Recommended remediation stage: consolidated dependency maintenance before production release qualification. Upgrade pinned generators/CLI dependencies in a dedicated change and rerun generated-client drift and breaking-contract gates; do not apply `npm audit fix --force` inside a feature branch.

## TD-MYSQL-001: Driver retains active credential strings until pool close

- Affected module: MySQL plugin connection factory (`go-sql-driver/mysql`).
- Trigger conditions: an instance has an active connection pool or a credential rotation closes and replaces that pool.
- Functional impact: none for connection, rotation or cleanup behavior. DBPilot clears lease byte buffers and closes retired pools, but the Go driver must retain an immutable password string internally while a pool can reconnect, so byte-for-byte zeroization cannot be guaranteed by application code.
- Severity: medium hardening limitation; it becomes high only if an attacker already has same-process memory-read capability.
- Recommended remediation stage: production hardening review. Prefer short lease TTLs and process isolation now; evaluate a connector/driver design with replaceable zeroizable credential material before admitting less-trusted plugin publishers.

## TD-TEST-001: MySQL verifier image reference and Windows race gate

- Affected module: Task 13 MySQL/Kylin acceptance tooling.
- Trigger conditions: `mysql:8.4` is republished upstream, or a developer attempts the Go race detector with the repository's default `CGO_ENABLED=0` Windows toolchain.
- Functional impact: none observed in current unit, full Go, Linux amd64/arm64, Kylin V10 and real MySQL 8.4 verification. The mutable image tag weakens long-term reproducibility, and the local Windows race gate is unavailable without an approved C toolchain.
- Severity: low for feature delivery; medium for release-evidence reproducibility.
- Recommended remediation stage: release qualification. Pin the approved MySQL 8 image digest and run `go test -race` for the plugin packages in a dedicated Linux CI runner with CGO enabled.

## TD-MYSQL-002: Shutdown does not count unrelated in-flight unary RPCs

- Affected module: MySQL PluginRuntime shutdown coordination.
- Trigger conditions: shutdown overlaps a direct local unary `CollectNow`, `ValidateInstance` or template trial that was not launched through the managed stream lifecycle.
- Functional impact: normal Supervisor shutdown remains ordered: it cancels and waits for metric streams, then guarded pool close waits for active database rows. The shutdown response does not separately count every non-stream unary handler before returning `drained=true`.
- Severity: low in the current single-Agent private-UDS workflow; an uncoordinated local client can make the drain response precede completion of its own unary RPC.
- Recommended remediation stage: consolidated runtime hardening before production rollout. Add an admission gate plus unary wait group shared by all PluginRuntime handlers, reject new calls after drain begins, and prove the drain timeout covers every accepted handler.

## TD-TEST-002: Exporter retry timing test is scheduler-sensitive

- Affected module: existing exporter unit test `TestSendPendingRetriesUntypedResourceExhaustion`.
- Trigger conditions: the complete Go suite runs many packages concurrently on the Windows development host and the test's short timing window observes only its first attempt.
- Functional impact: none observed in Task 13 or exporter behavior. One full-suite run reported one attempt instead of the expected two; the focused test passed 10/10 repetitions immediately afterward, and a fresh complete-suite rerun passed.
- Severity: low test-reliability issue; it does not affect the MySQL plugin runtime path.
- Recommended remediation stage: consolidated test-harness maintenance. Replace wall-clock retry assertions with an injected clock or synchronization barrier, then retain a separate integration test for real backoff timing.
