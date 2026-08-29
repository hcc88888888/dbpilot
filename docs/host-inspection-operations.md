# Host inspection operations

DBPilot host inspection is a tenant/project-scoped workflow built on the
production Agent command channel. An immediate or scheduled Run snapshots its
policy, exact item versions, selected Agent identities/capabilities, Job ID and
Command IDs. Each target receives one signed two-phase
`CollectNow{collection_kinds:["host"]}` command. Historical Findings, Reports,
Artifact metadata and Audit events are immutable; operator retry creates a new
Run linked by `retry_of_run_id`.

The MVP evaluates exactly 13 version-one host items: CPU utilization, load per
logical CPU, memory utilization, Swap utilization, worst filesystem space
utilization, worst filesystem inode utilization, Agent heartbeat freshness,
metric freshness, spool utilization, OOM evidence, time synchronization,
trusted database-process presence, and error-log summary. It does not execute
database SQL, shell commands or arbitrary expressions. Read-only/growth
filesystem checks, network connectivity/error checks, critical-port checks and
Agent policy-state checks are the next host-function phase, not MVP coverage.

## Scheduling and target selection

- A scheduled policy uses exactly five cron fields and an explicit IANA TZDB
  timezone such as `Asia/Shanghai` or `UTC`. Six-field cron, descriptors,
  machine-local `Local`, and unknown timezones are rejected.
- Only enabled policies with `next_run_at` due are leased. A stale policy is
  coalesced to the latest scheduled occurrence at or before scheduler `now`,
  then advances directly to the first occurrence after `now`; an outage never
  creates one Run per missed interval. PostgreSQL
  `FOR UPDATE SKIP LOCKED`, a claim token, the exact occurrence and a lease
  deadline prevent two schedulers from creating the same occurrence. The Run,
  TargetRuns, Job and Command outbox rows are committed in the same transaction
  that advances the matching occurrence.
- Explicit Agent IDs and exact `key=value` labels form a union. Labels do not
  perform substring or regex matching. An unknown Agent or an empty resolved
  target set rejects the Run.
- Display name, host and labels are fixed in the TargetRun. Connectivity,
  versioned capabilities and advertised evidence sources are captured from the
  authenticated live session. Operator retry preserves the fixed target IDs
  and descriptive identity but refreshes those live execution facts.
- `target_timeout` and `max_concurrency` are persisted on both Run and Job. The
  Job timeout covers `ceil(targets/max_concurrency)` waves. A transactional
  per-Job prepare slot counts preparing/prepared/start/running/cancelling
  commands, so queued targets wait without duplicate preparation.

## Evidence freshness and authenticated acceptance

A successful Command Result only proves the Agent appended a collection; it is
not inspection evidence by itself. The worker accepts a complete host snapshot
only when all of these fences hold:

1. tenant, project and authenticated Agent identity match the TargetRun;
2. `dbpilot_source_id` is exactly `inspection-host-snapshot`;
3. `sampled_at` is within `[Run.created_at, target evidence deadline]`;
4. server-assigned `accepted_at` is no later than that deadline; and
5. every metric required by the immutable item snapshot exists at one selected
   snapshot timestamp.

The target evidence deadline is its persisted successful collection terminal
time plus `target_timeout`, capped by the batch Job timeout. Time spent queued
for a concurrency slot does not consume this per-target evidence window.
Periodic hostmetrics, same-name metrics from another source, stale samples and
late-ingested backdated samples cannot satisfy an immediate inspection. Before
the deadline an incomplete snapshot releases the worker claim for retry. At or
after the deadline each absent item becomes `missing_data`; the worker does not
send a second collection command.

## Partial success and terminal state

Targets are independent. One failed, timed-out, cancelled or unsupported target
does not cancel its siblings. A successful target needs one Finding for every
item version and no `missing_data` or `unsupported` Finding. Mixed successful
and failed targets produce Run status `partial`; all successful targets produce
`completed`; no successful target produces `failed` (or `cancelled` when every
target was cancelled).

The Job/Command Audit trail retains the original request ID, trace ID, Job ID
and Command ID. The immutable report repeats Job ID, Command references and the
Run Audit correlation without including tenant/project IDs, raw logs,
credentials or connection strings.

## Reports, repair and idempotency

- Report IDs and Artifact IDs are stable:
  `inspection-report-<run>`, `.json`, and `.html`. Only JSON and HTML are
  supported for production inspection reports. Every download request names
  exactly one `html` or `json` format; the server selects that Artifact and
  rejects an unavailable format instead of choosing a preferred file.
- The worker renders from persisted TargetRuns and Findings. Checksum-addressed
  bytes are durably published before Artifact metadata is inserted with an
  identical-checksum CAS. A conflicting checksum never overwrites the original.
- Report insertion, Run terminal status/counters and exact Audit-pending payload
  share one PostgreSQL transaction. If Audit is unavailable, a separate leased
  repair replays only that persisted event; it does not recollect, reevaluate,
  rerender or recreate Artifacts.
- A crash in `generating_report` uses the persisted generation timestamp,
  Findings and TargetRuns, so repaired JSON/HTML bytes and checksums are stable.
- Run idempotency is scoped by tenant, project, authenticated actor, operation
  and key, with an immutable request fingerprint. Repeating the exact request
  returns only that persisted Run and creates no second Run, Job, Command,
  Finding or Report. The same raw key may be used by another actor or operation;
  a different fingerprint in the same exact scope is a conflict. Creation Audit
  targets the actual Run ID and retains the original request/trace.
- An operator retry is allowed only for `failed` or `partial`. It creates new
  Run/Job/Command IDs, pins the original policy/items and fixed target identity,
  refreshes live target execution facts, and links `retry_of_run_id`.

## Retention, backup and restore

There is no automatic inspection-history purge in the MVP. Database triggers
reject mutation/deletion of historical item, target identity, Finding and
Report evidence, and Audit is append-only. Size PostgreSQL and Artifact storage
for the intended retention period and alert on growth.

Back up PostgreSQL and the Artifact root as one recovery set. Restore
PostgreSQL first, then restore checksum-addressed blobs at their recorded
storage references before enabling report downloads or the worker. Never delete
the Agent spool or command journal merely to clear an inspection: unacknowledged
telemetry and Results are recovery evidence. A future scoped archival/purge
workflow must preserve exported report checksums and Audit correlation before
it can bypass the history guards.

## Readiness and health

Startup runs alert/metric, Job, platform and inspection migrations before
listeners, then idempotently seeds the built-in catalog for every configured
scope. Inspection readiness also requires a private Artifact root that passes a
retained-root create/write/file-fsync/link-or-rename/remove/directory-fsync
probe with exact cleanup, plus a resolvable Artifact signing key. An unavailable Agent is reflected in target
connectivity/capabilities; it does not make the whole control plane unready.

Scheduler and worker pass failures are logged and retried on the next bounded
interval. They do not flip global `/readyz` after successful startup. Operators
should monitor:

- queued/collecting/evaluating/generating-report Run age;
- Job target failures and command delivery/execution timeouts;
- `report_audit_pending` count and oldest age;
- Artifact write/signing failures and storage capacity;
- Agent connectivity, command Result replay and spool health findings; and
- `inspection-host-snapshot` acceptance lag and missing-data rate.

Useful read-only PostgreSQL diagnostics, always scoped, are:

```sql
SELECT status, count(*)
FROM inspection_runs
WHERE tenant_id = $1 AND project_id = $2
GROUP BY status;

SELECT count(*), min(finished_at)
FROM inspection_runs
WHERE tenant_id = $1 AND project_id = $2
  AND report_audit_pending = TRUE;

SELECT agent_id, max(sampled_at) AS sampled_at, max(accepted_at) AS accepted_at
FROM metric_samples
WHERE tenant_id = $1 AND project_id = $2
  AND labels ->> 'dbpilot_source_id' = 'inspection-host-snapshot'
GROUP BY agent_id;
```

## Troubleshooting

| Symptom | Checks and action |
| --- | --- |
| Run remains `queued` | Confirm worker loop is running, Job/Command rows exist, the Agent is connected and advertises `collect_now.host.v1`, and no unexpired worker/prepare slot is stranded. Wait for lease expiry before manual intervention. |
| Run remains `collecting` | Inspect Job target states and Agent ResultAck replay. Confirm the exact source and both timestamp fences. Do not copy periodic metrics into the host source. |
| `missing_data` after Command success | Compare Run creation, Job timeout, sample and server acceptance times; verify every selected item metric exists at one snapshot timestamp. |
| Run is `partial` | Inspect each TargetRun. Retry only after fixing failed targets; the retry is a new linked Run and never edits the original report. |
| Run remains `generating_report` | Check Artifact root permissions/capacity and Artifact PostgreSQL readiness. Repair is idempotent; do not delete partially published checksum blobs. |
| Report exists but Audit is pending | Restore Audit storage and allow the repair loop to replay the persisted event. Do not rerun collection. |
| Report download fails | Verify the explicit requested `html` or `json` Artifact exists, plus the signing key, metadata checksum/reference and restored blob bytes. Never replace a conflicting blob in place. |
| Kylin smoke exits early | Inspect the sanitized Agent/gateway log emitted by the verifier, confirm the exact approved image/amd64, and check that Docker can read the private registry image locally. |

## Verification gates

On Windows with Docker Desktop running:

```powershell
powershell -NoProfile -File backend/scripts/verify-host-inspection.ps1
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1
powershell -NoProfile -File backend/scripts/verify-kylin-docker.ps1 `
  -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' `
  -Architecture amd64
```

The PostgreSQL verifier creates one uniquely named, ownership-labelled
`postgres:16-alpine` container, publishes only an ephemeral loopback port, runs
the lifecycle, and removes only its recorded container and anonymous volume in
`finally`; it audits cleanup even after test failure. Contract CI runs this
public PostgreSQL gate. CI does not require credentials for the private Kylin
registry.

The Kylin release gate must use exactly
`cr.kylinos.cn/kylin/kylin-server-platform:v10sp1` on amd64. It runs the
production Agent and native gopsutil reader, preserves the HDFS/JMX dependency
probe, sends signed Prepare/Start for host collection, persists ResultAck in the
real journal, and decodes the retained real spool. Passing evidence includes
non-empty `system.cpu.utilization`, `system.memory.utilization`,
`system.filesystem.utilization`, `system.cpu.load_average.1m_per_cpu`, and a
valid `inspection.snapshot_at`. A static fixture, generic Linux image,
`-SkipKylin`, or an early clean Agent exit is not release evidence.

Docker evidence is not a substitute for final systemd, journald ACL, kernel,
network and real-database evidence on the supported Kylin VM/bare-metal estate.

## Deferred work ledger

These items do not change current host-MVP correctness and therefore follow the
repository feature-first policy. Reassess every row before production rollout.

| Affected module | Trigger conditions | Functional impact today | Severity | Recommended remediation stage |
| --- | --- | --- | --- | --- |
| Inspection catalog/evaluator: SQL database probes | A policy needs PostgreSQL/MySQL/Oracle/etc. configuration or query checks rather than host metrics | Not implemented; the v1 host contract rejects database/probe expressions, so no incorrect SQL is executed | Medium | Separate SQL-probe design before adding public schemas; use allowlisted read-only templates, Adapter capabilities and a new item version/type |
| Inspection adapters: HBase/MongoDB/Neo4j depth | Operators request engine-specific health beyond host/process/log signals | Host findings remain correct but cannot diagnose regions/replicas/graphs/collections | Medium | Adapter-specific inspection phases after host MVP; do not coerce non-SQL engines into SQL probes. Existing HBase dependency telemetry is observability, not full inspection depth |
| Inspection report formats: PDF/Word | A user requests `.pdf` or `.docx` from a production inspection Report | HTML/JSON remain available; UI intentionally exposes no PDF/Word action | Low | Report phase 2 after deterministic renderer, font/template and conversion sandbox design |
| Inspection distribution: email | A user requests report email delivery | Report creation/download works; no production inspection email is sent | Low | Report distribution phase 2 using existing secret-resolved notification controls and Audit |
| Artifact HTTP idempotency and Agent command recovery | Crash/key rotation during Artifact descriptor replay, or expired Prepared cancellation delivery fails | Normal flows are correct; rare recovery may lack exact descriptor snapshot replay or durable `CancelPrepared` retry | Important | Before production rollout; persist exact descriptor response snapshot and durable cancellation delivery state |
| Artifact retention/archival | Immutable Run/Report/Artifact history exceeds the planned capacity | No current data corruption; storage grows because automatic purge is intentionally absent | Medium | Pre-production capacity/retention cycle; design scoped archive/export plus audited purge compatible with history guards |
| Node contract/test dependency security | `npm ci`/audit reaches the previously ledgered vulnerable or deprecated packages (17 findings: 16 moderate, 1 high at the recorded baseline) | No current contract or test failure; build-tool exposure requires triage | High | Before production/toolchain release; audit, upgrade locked dependencies, regenerate and rerun drift/breaking gates |
| Inspection overview aggregation | A project has a very large Run/Report history | Correct bounded sample is returned but pagination-based aggregation can become slow | Low | Consolidated pre-production performance cycle; add scoped aggregate repository queries without changing response semantics |
| Next host-function phase | Operators need read-only/growth filesystem state, network connectivity/errors, critical ports, or Agent policy state | These checks are intentionally absent from the exact 13-item MVP; current findings do not claim them | Functional follow-up | Implement immediately after this MVP with new versioned catalog items and matching collector evidence before describing host inspection as broader coverage |
| Generated TypeScript inspection count maps | A client compiles code using unknown overview count keys | Server runtime validation rejects unknown keys, but generated typing remains overly open | Minor | OpenAPI generator-template cleanup |
| Contract metadata/toolchain | Redocly lint reads the current OpenAPI without `info.license` | Warning only; no runtime functional impact | Minor | Documentation/toolchain cleanup |
| Full environment-gated PostgreSQL module integrations | A change touches scheduler claims, migration upgrades or report repair beyond the lifecycle covered by CI | Unit/SQL-shape and host lifecycle remain covered; the broader opt-in suite must still be run for release | Operational | Release/deployment validation with `verify-inspection-postgres.ps1` in addition to CI host lifecycle |
| Native Kylin service estate | systemd/journald/kernel/eBPF or real database behavior differs from the Docker image | Docker proves binary/protocol/native reader compatibility only | Release gate | Before production rollout on Kylin V10 amd64 VM/bare metal; arm64 requires a native arm64 runner and is not proven by emulation |
