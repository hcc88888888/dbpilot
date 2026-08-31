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
