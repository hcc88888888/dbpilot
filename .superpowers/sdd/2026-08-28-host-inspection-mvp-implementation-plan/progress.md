# SDD ledger — plan: docs/superpowers/plans/2026-08-28-host-inspection-mvp-implementation-plan.md

Workspace: `D:/AI/codex/workspace/数据库运维管理系统/.worktrees/contract-foundation`
Branch: `codex/contract-foundation`
Start commit: `af5127b`
Spec: `docs/superpowers/specs/2026-08-28-instance-inspection-design.md`

## Preflight dependency and overlap scan

| Tasks | Producer / consumer or shared surface | Finding |
| --- | --- | --- |
| 1 → 6 | Generated inspection operations and DTOs → strict handlers and frontend client | Consistent; Task 6 consumes only generated Task 1 names. |
| 2 → 3 | Domain values and snapshots → PostgreSQL repository and service | Consistent; Task 3 does not import generated HTTP DTOs. |
| 2 → 5 | Evaluator/catalog → target evaluation and report snapshot | Consistent. |
| 3 ↔ 4 | Both modify `backend/go.mod`/`go.sum` | Deliberately serialized by the plan; production packages otherwise do not overlap. |
| 3 → 5 | Run/target persistence and scheduler → evaluation claims and report persistence | Consistent; Task 5 extends the repository after Task 3 review. |
| 3 → 6 | Inspection service/target resolver → HTTP and production configuration | Consistent; Task 6 owns `AgentAssignment` wiring. |
| 4 → 5 | Fresh host snapshot in metric spool → freshness-fenced evaluation | Consistent; Job Result proves append, evaluator waits for ingested sample time at/after the fence. |
| 4 → 7 | Production host collector → Kylin CollectNow smoke | Consistent. |
| 5 → 6 | Immutable report DTO/Artifacts → API and Report Center | Consistent. |
| 6 → 7 | Complete HTTP/UI lifecycle → E2E verification | Consistent. |
| 3 → 7 | PostgreSQL inspection verifier → final host lifecycle verifier | Consistent; Task 7 extends verification without changing migration ownership. |
| 1 | Contract tests precede canonical schemas and generated output | Internally consistent. |
| 2 | Model/catalog/evaluator tests precede production code | Internally consistent. |
| 3 | Migration/repository/service tests precede implementation; PostgreSQL script is self-cleaning | Internally consistent. |
| 4 | Coordinator, host snapshot and production wiring tests precede implementation | Internally consistent. |
| 5 | Freshness, partial-result, renderer and Artifact tests precede implementation | Internally consistent, subject to filesystem/database boundary ruling below. |
| 6 | Strict handler and frontend tests precede production changes | Internally consistent. |
| 7 | Lifecycle E2E is red before verifier/runtime completion | Internally consistent. |

Ruling: Report bytes and PostgreSQL metadata cannot share one physical transaction; use stable report/Artifact IDs, atomically write checksum-addressed files first, insert metadata with identical-checksum CAS, and commit report snapshot/Run terminal state only after both Artifact records exist — if wrong, a later orphan-file sweeper or transactional object store boundary is required.
Ruling: Report finalization transaction sets durable `report_audit_pending` evidence; a separate stable-dedupe `Audit.RecordOnce` repair clears it, so Audit failure cannot repeat collection/evaluation or lose the report — if wrong, report availability may need to wait for synchronous Audit and reduce resilience.
Ruling: Internal delivery/evaluation/report repair keeps the same Run/Target/Command IDs, while an operator retry of a terminal failed/partial Run creates a new identity linked by `retry_of_run_id` and protected by Idempotency-Key — if wrong, user retry history must be collapsed into the original Run and its immutable report semantics redesigned.
Ruling: Direct host snapshots intentionally coexist with periodic OpenTelemetry hostmetrics; `inspection-host-snapshot` plus the freshness fence identifies on-demand evidence and prevents periodic samples from falsely satisfying an immediate run — if wrong, the telemetry engine needs a receiver-level trigger interface instead of the direct bounded collector.

Deferred per repository priority rule (non-blocking for host inspection): Artifact descriptor exact snapshot replay and durable retry of expired-Prepared `CancelPrepared`; affected modules are Artifact HTTP idempotency and Agent command recovery, triggered only by crash/rotation or cancel-delivery failure, Important severity, recommended before production rollout.

## Task status

Baseline evidence: `backend/scripts/verify-contract-foundation.ps1` exit 0; Node 247 total/246 passed/1 expected Prism skip; all Go packages, Prism mock and PostgreSQL E2E passed.
Deferred per repository priority rule: `npm ci` reports 17 dependency vulnerabilities (16 moderate, 1 high) and deprecated toolchain packages; affected module is the Node contract/test toolchain, triggered during dependency installation, no current functional test failure observed, security severity high pending audit triage, recommended before production/toolchain release.
Deferred per repository priority rule: Redocly emits the existing missing OpenAPI `info.license` warning; affected module is contract metadata, trigger is lint, no runtime functional impact, Minor severity, recommended with documentation cleanup.

- Task 1: complete
- Task 2: complete
- Task 3: complete
- Task 4: complete
- Task 5: complete
- Task 6: complete
- Task 7: complete

Task 1: review found Important — public contract exposes database scope/database types although SQL/database probes are outside the host MVP.
Task 1: review found Important — unrestricted 64 KiB `evidence_selector` admits raw SQL, shell text and executable expressions.
Task 1: review found Important — `source_type` is not coupled to exactly one valid rule shape.
Task 1: review found Important — timezone regex rejects valid IANA identifiers and accepts nonexistent zones.
Task 1: review found Minor — overview count maps allow unknown run/finding keys.
Task 1: Ruling: host MVP contract removes database/probe variants now and later SQL inspection adds them additively, because accepting schema-valid operations that the implementation must reject is a functional defect — if wrong, the SQL plan must reintroduce those schemas and regenerate clients.
Task 1: Ruling: OpenAPI performs broad lexical timezone validation and names custom format `iana-timezone`, while contract tests use Node ICU/TZDB and Task 3 production uses Go `time.LoadLocation`; a regex alone cannot prove timezone existence — if wrong, client-side schema tooling may need a generated timezone catalog.
Task 1: fix round 1/5 (5 addressed, 0 open; commits `7a2c6e2..a54659f`)
Task 1: minor (deferred): generated TypeScript overview count models retain an open `[key: string]: any` index signature even though runtime OpenAPI validation rejects unknown keys; affected module is generated SDK typing, trigger is consumer compile-time use of unknown count keys, no server functional impact, Minor severity, recommended during generator-template cleanup.
Task 1: complete (commits `af5127b..a54659f`, review clean)
Task 1: controller cross-task verification found Important — `CreateInspectionItemRequest` still admits custom metadata/log-summary items without any declarative decision rule, so Task 2 cannot evaluate them deterministically.
Task 1: Ruling: first-stage custom items are metric-only structured rules; metadata and log-summary source types remain response/catalog values for versioned built-in system items, and later approved probe templates are additive — if wrong, custom metadata/log items need a new bounded predicate schema before they can be re-enabled.
Task 1: fix round 2/5 (1 addressed, 0 open; commits `a54659f..22cf9c7`)
Task 1: complete after cross-task repair (commits `af5127b..22cf9c7`, review clean)
Task 2: Ruling: numeric v1 defaults are CPU/memory/filesystem/inode warning 80 and critical 90 percent; load-per-logical-CPU warning 1.0 and critical 2.0; Swap warning 25 and critical 50 percent; spool warning 70 and critical 90 percent — if wrong, catalog version 2 must change thresholds without rewriting historical version 1 findings.
Task 2: Ruling: heartbeat/metric/log freshness absence is `missing_data`; an unadvertised source or unconfigured trusted process allowlist is `unsupported`; OOM evidence count at least 1, unsynchronized time, or configured required-process count 0 is `critical`; log errors at least 1 are critical and warning-only counts at least 1 are warning — if wrong, later item versions must adjust severity while preserving immutable history.
Task 2: review found Important — caller-controlled `System` permits forged or mutated built-in ID/version definitions.
Task 2: review found Important — malformed metadata/log evidence aborts the target or misclassifies invalid domains instead of producing `missing_data`.
Task 2: review found Important — finite inputs can overflow average aggregation to Inf and be misclassified.
Task 2: review found Important — embedded observations and repeated full-snapshot validation are not bounded for per-target evaluation.
Task 2: review found Important — supplied target Agent identity/evidence is not bound to the immutable snapshot target.
Task 2: review found Important — critical log count is not represented or evaluated.
Task 2: review found Important — the 10,000-target bound test fails for invalid IDs rather than the bound.
Task 2: review found Minor — non-terminal targets aggregate to terminal `partial`.
Task 2: Ruling: a system item is valid only when every decision-bearing field exactly matches the canonical built-in ID/version; custom items cannot reuse a built-in ID — if wrong, a future signed catalog extension needs an explicit registry boundary rather than caller-controlled `System`.
Task 2: Ruling: cap embedded observations at 256 per target and 10,000 total per Run snapshot; `EvaluateTarget` resolves and evaluates the canonical snapshot target and only accepts a matching TargetID/AgentID selector, while malformed per-item evidence yields `missing_data` — if wrong, high-cardinality host evidence must move behind a separate bounded store sooner.
Task 2: Ruling: `AggregateRunStatus` returns `evaluating` whenever any target is pending/collecting/evaluating, and produces terminal aggregation only after every target is terminal — if wrong, callers must reject premature aggregation instead of receiving a non-terminal status.
Task 2: fix round 1/5 (5 addressed, 3 open — invalid ID/label metadata/log evidence; average overflow/underflow; target-bound test duplicate identity; commits `e980b17..f856fc8`)
Task 2: fix round 2/5 (3 addressed, 0 open; commits `f856fc8..7c0b6bc`)
Task 2: complete (commits `22cf9c7..7c0b6bc`, review clean)
Task 3: Ruling: `ClaimDuePolicies` only leases and returns a claim token plus scheduled occurrence; the same PostgreSQL transaction that inserts Run/TargetRuns/Job/outbox must verify the claim, advance `next_run_at`, and clear the lease. A duplicate occurrence returns the existing Run and advances only from the matching occurrence — if wrong, scheduler crashes can either skip or duplicate an occurrence.
Task 3: Ruling: Task 1's generated strict interface intentionally leaves the full Go build broken until Task 6 supplies all real inspection handlers; Tasks 2–5 use focused package gates and must not add placeholder handlers, while Task 6 must restore the full-suite gate before completion — if wrong, contract and handler work must be collapsed into one task to preserve buildability at every commit.
Task 3: review found Important — item versions, findings and Run policy/item snapshots lack database mutation guards.
Task 3: review found Important — operator RetryRun drops the original immutable policy snapshot.
Task 3: review found Important — schedule validation accepts machine-local timezone `Local`.
Task 3: review found Important — page `More` is never populated and item cursor `(created_at,item_id)` is not unique across versions.
Task 3: Ruling: item pagination uses the unique descending tuple `(created_at, item_id, version)` while other resources retain `(created_at, id)`; all list queries fetch `limit+1`, trim, set `More`, and derive the next cursor from the last returned row — if wrong, the public cursor format must be versioned before v1 stabilization.
Task 3: fix round 1/5 (2 addressed, 2 open — Target/Run mutation and deletion guards; item cursor SQL/JSON timestamp precision mismatch; commits `4e20ae3..8e0fc2a`)
Task 3: fix round 2/5 (2 addressed, 0 open; commits `8e0fc2a..f19ab4a`)
Task 3: complete (commits `7c0b6bc..f19ab4a`, review clean)
Task 4: Ruling: on-demand host metrics use percent units for CPU/memory/Swap/filesystem/inode, ratio for load-per-logical-CPU, seconds for freshness, bytes/count for storage/process/log values, and carry `inspection.snapshot_at`; metric names exactly match the Task 2 catalog — if wrong, catalog version 2 and ingestion normalization must change together.
Task 4: Ruling: the configured database process-name list is an allowlist of acceptable alternative database executables for the host; `required_process_count` is the number of matching running processes and version 1 checks only whether at least one exists — if wrong, a later item version must model per-process groups/all-required semantics.
Task 4: Ruling: receipt of the signed host CollectNow command is current Agent-control evidence, so the snapshot emits heartbeat age 0; successful creation of this fresh batch emits metric age 0, while spool utilization is read from actual durable spool statistics — if wrong, the control stream and telemetry freshness need separate persisted clocks.
Task 4: review found Important — log/OOM aggregates are computed after the 64-point dimensional truncation and can falsely report healthy.
Task 4: review found Important — production host snapshot uses a fixed 1 MiB default instead of the active signed policy exporter limit.
Task 4: review found Important — coordinator checks collector availability during execution, allowing earlier side effects before a later unavailable kind fails.
Task 4: review found Important — native process reader truncates at 4,096 PIDs before aggregate/allowlist matching and can falsely report a required process missing.
Task 4: review found Minor — observer-failure accounting callback is not panic-protected and can drop the original log batch.
Task 4: Ruling: HostSnapshotCollector reads the active telemetry engine's current signed `BatchMaxBytes` at collection time and fails before append when no active limit is available; it never falls back to a larger static limit — if wrong, early CollectNow commands before policy activation must be queued rather than fail retryably.
Task 4: Ruling: all validated log summaries and all PIDs contribute to aggregate health/process results; cardinality caps apply only to emitted per-dimension detail, never to aggregate correctness — if wrong, host collection needs streaming OS/log reader APIs to retain bounded memory.
Task 4: fix round 1/5 (5 addressed, 0 open; commits `3ba6a6f..ec851c9`)
Task 4: complete (commits `f19ab4a..ec851c9`, review clean)
Task 5: Ruling: `Run.CreatedAt` is the freshness fence and the persisted Job `TimeoutAt` is the target evidence deadline; a successful command waits for at least one `inspection-host-snapshot` sample at/after the fence until that deadline, then evaluates missing sources as `missing_data` without rerunning collection — if wrong, Run schema needs explicit per-target freshness/deadline columns.
Task 5: Ruling: report finalization transaction inserts the immutable completed Report, updates Run terminal/report counters, and writes durable report Audit-pending evidence on the mutable Run; `Audit.RecordOnce` repair clears pending separately — if wrong, synchronous Audit must become part of the report availability boundary.
Task 5: Ruling: Artifact blobs are written under checksum-addressed storage references before metadata insert; stable Artifact IDs use insert-or-compare checksum CAS, so crash retries reuse identical content and conflicting content fails without overwriting — if wrong, storage needs a transactional object-store adapter.
Task 5: review found Critical — metadata/log snapshot metrics are never hydrated into evaluator observations and missing/unsupported findings can be masked by valid siblings.
Task 5: review found Critical — evidence queries are not source-fenced, do not clamp to Run.CreatedAt, and cannot enforce ingestion before Job.TimeoutAt.
Task 5: review found Important — generating_report repair reads Job before using persisted report inputs.
Task 5: review found Important — first checksum directory is not fully crash-durable and process-local check+Rename can overwrite a concurrent/corrupt destination.
Task 5: Ruling: metric ingestion persists authenticated `accepted_at` for every metric sample; worker evidence requires exact Agent scope, `inspection-host-snapshot` source, sampled time within `[Run.CreatedAt, Job.TimeoutAt]`, and accepted time no later than Job.TimeoutAt — if wrong, late or wrong-source telemetry can change immutable inspection history.
Task 5: Ruling: any `missing_data` finding makes the target failed and any `unsupported` finding makes it unsupported even when other items are valid; only a complete set of healthy/warning/critical findings yields succeeded — if wrong, Run completion needs a separate completeness dimension instead of target status precedence.
Task 5: Ruling: blob publication uses retained-root hard-link creation as the atomic no-replace primitive, removes the temporary link after success/collision, and fsyncs root/checksum directories on Linux before every successful return — if wrong, filesystems without hard-link support need an object-store-specific writer.
Task 5: fix round 1/5 (4 addressed, 0 open; commits `14db210..bb66d21`)
Task 5: complete (commits `ec851c9..bb66d21`, review clean)
Task 6: Ruling: every inspection HTTP write uses the existing platform idempotency service and stable Audit dedupe; Run/retry bare-processing reconciliation reads Task 3's persisted idempotency correlation, while create item/policy IDs are deterministic from authenticated scope/actor/operation/idempotency key — if wrong, operation-specific response snapshot tables are required before production.
Task 6: Ruling: CancelInspectionRun requests cancellation of the persisted Job and returns the current Run without fabricating a cancelled terminal state; the Worker follows the real Job/Agent result to terminalize — if wrong, the public contract needs an explicit cancelling Run state.
Task 6: Ruling: production opens one retained Artifact root and one blob-aware Postgres Artifact store shared by download and inspection Worker; injected tests may provide a complete Worker/Artifact boundary, but production readiness cannot advertise inspection without a writable root — if wrong, report generation must move to a separate service.
Task 6: Ruling: scheduler and inspection Worker failures are logged and retried without flipping global HTTP readiness after startup migrations; `/readyz` continues to reflect database and existing alert evaluation readiness — if wrong, inspection worker health needs its own readiness/degraded capability signal.
Task 6: review found Critical — production target snapshots have no advertised sources, so every built-in finding becomes unsupported.
Task 6: review found Important — cancel crash recovery looks up snapshot with the post-cancel Job version instead of immutable original correlation.
Task 6: review found Important — policy UI has no edit/ETag/If-Match flow.
Task 6: review found Important — demo source badge is absent outside overview.
Task 6: review found Important — Report Center derives weekly/success statistics from only five recent rows and reports them as complete.
Task 6: Ruling: an authenticated live Agent session advertising `collect_now` from the production host collector authorizes metric, metadata and log_summary inspection sources in the persisted target snapshot; later partial-source Agents need explicit source capabilities — if wrong, current capability inference overstates an Agent's source support.
Task 6: Ruling: inspection cancel recovery queries the immutable cancellation snapshot by scope/job/actor/operation/idempotency/fingerprint correlation and validates the returned original version rather than reconstructing IfMatch from mutable Job state — if wrong, the job snapshot schema needs a separately persisted request-version field in the idempotency claim.
Task 6: Ruling: configured Report Center labels counts/rates as a bounded recent sample unless/until a server aggregate endpoint exists; it must not call five rows a weekly total — if wrong, users may prefer no overview metric over sample-labelled metrics.
Task 6: fix round 1/5 (4 addressed, 1 open — real generated policy serializer rejects snake_case DTO; editable labels missing; commits `026f739..915595f`)
Task 6: fix round 2/5 (1 addressed, 0 open; commits `915595f..1e9efe4`)
Task 6: complete (commits `bb66d21..1e9efe4`, review clean)
Task 7: Ruling: the completion Kylin check must execute the production Agent and native host reader inside the approved V10 SP1 amd64 image with `CollectNow{host}`; static fixtures or `-SkipKylin` do not satisfy completion — if wrong, a dedicated Kylin VM runner is required instead of Docker evidence.
Task 7: Ruling: GitHub contract CI runs the self-cleaning PostgreSQL host-inspection verifier but does not require the locally approved Kylin registry image; Kylin remains an explicit local/release evidence gate — if wrong, CI must gain authenticated access to the Kylin registry.
Task 7: review found Important — PostgreSQL lifecycle E2E selects only one built-in item/metric instead of a coherent full 13-item host snapshot.
Task 7: fix round 1/5 (1 addressed, 0 open; commits `d656071..2fe36dc`)
Task 7: complete (commits `1e9efe4..2fe36dc`, review clean)

## Final whole-branch review

Final review Critical: filesystem/inode findings use arbitrary latest series and cap mounts before aggregate, allowing a critical database volume to be hidden by a healthy sibling.
Final review Critical: contract permits Run complexity/report content that exceeds renderer/DB caps only after commands complete, leaving permanent generating_report retries; legitimate HTTPS recommendation text is also rejected late.
Final review Important: generic collect_now capability overstates host sources, legacy health behavior regressed, and production process trust is unreachable.
Final review Important: policy/run max_concurrency is accepted but not persisted or enforced; queued targets share an inadequate absolute deadline.
Final review Important: scheduler replays every stale occurrence instead of coalescing to the latest missed one.
Final review Important: operator retry freezes stale dynamic capabilities/sources and drops real request/trace correlation.
Final review Important: Run persistence idempotency is raw-key scoped rather than actor/operation/fingerprint scoped, and creation Audit targets the requested source rather than the new Run.
Final review Important: Artifact readiness proves only readable root, not writable/fsync/remove report storage.
Final review Important: policy UI rejects label-only selectors and ignores pagination beyond first 100 targets/items/policies.
Final review Important: report UI omits evidence/thresholds/target and Job/Command/Audit navigation; download cannot select JSON versus HTML.
Final review Minor: offline Agent lacks `agent_offline` code; host CollectNow result summary still says dependency telemetry; ledger status heading remains stale.
Final review Ruling: filesystem catalog v1 consumes one aggregate worst-case utilization/inode metric computed across every successfully read mount before detail caps; any mount read failure omits the aggregate so the item becomes missing rather than false healthy — if wrong, per-mount Finding expansion is required.
Final review Ruling: Run creation enforces a deterministic combined report budget based on actual target/item snapshots and conservative renderer overhead before any Job/outbox write; permanent renderer validation/size failures terminalize failed instead of retrying — if wrong, findings/report bodies need separate paginated storage.
Final review Ruling: Agent advertises versioned `collect_now.host.v1` and `collect_now.dependencies.v1` alongside generic compatibility; legacy `health` aliases dependency collection, and process allowlist availability is evaluated from authenticated snapshot evidence rather than a control-plane boolean — if wrong, protobuf needs explicit typed source capabilities.
Final review Ruling: max concurrency is persisted on Job/Run and enforced by a transactionally reserved per-Job prepare slot; batch timeout accounts for `ceil(targets/max_concurrency)` waves, while each target evidence deadline derives from its terminal collection time plus target timeout — if wrong, command scheduler must become inspection-specific.
Final review Ruling: scheduler creates only the latest due occurrence and advances directly to the first occurrence after scheduler `now`; it never walks an unbounded backlog — if wrong, operators need an explicit catch-up policy option.
Final review Ruling: operator retry preserves item/policy/target identity but resolves current live execution sources/capabilities for the fixed target IDs and persists real request/trace — if wrong, retry must expose a choice between historical and live capability modes.
Final review Ruling: inspection Run idempotency correlation is scope+actor+operation+key+fingerprint; Audit targets the actual created Run ID — if wrong, raw-key compatibility requires a migration alias.
Final review Ruling: report download takes an explicit `html|json` format selector and report detail exposes safe Finding evidence/thresholds, target navigation, and Job/Command/Audit references — if wrong, clients must fetch and join Run/Artifact resources themselves.

Deferred per repository priority rule: report Audit repair starvation under sustained Run backlog; module inspection Worker, trigger Audit outage plus continuous claims, reports remain available but audit pending can lag, Important recovery, remediate before production with reserved/alternating audit capacity.
Deferred per repository priority rule: metric accepted_at startup backfill/index on large history; module alert migrations, trigger scale upgrade, operational lock/start delay without wrong data, Important operational, stage online/batched migration before production scale.
Deferred next host-function phase: filesystem read-only/growth prediction, explicit network connectivity/error rules, critical port rules, and Agent policy-state rule; module host catalog/collector, current MVP does not claim these checks, functional scope gap, implement immediately after this MVP before calling host巡检 complete.

Final fix wave: complete in implementation commit `33bbaa6`; all contract, Node, Go, PostgreSQL, foundation and exact Kylin gates passed. Detailed evidence is in `final-fix-report.md`.
