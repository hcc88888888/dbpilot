# Host Inspection MVP final whole-branch fix report

## Outcome

- Reviewed base: `2fe36dcf07907db2c2288546c83c4cabe43095f6`.
- Verified implementation commit: `33bbaa6` (`fix: complete host inspection correctness wave`).
- Result: all adjudicated Critical and Important functional findings are fixed. No known functional blocker remains.
- Repository priority was respected: the wave did not expand into the explicitly retained nonfunctional deferrals.

## Finding-by-finding implementation and TDD evidence

### 1. Filesystem aggregate correctness — Critical

Files:

- `backend/internal/agent/host_snapshot_collector.go`
- `backend/internal/agent/host_snapshot_collector_test.go`
- `backend/scripts/verify-kylin-docker.ps1`

Behavior:

- Every discovered mount contributes before any optional detail cap.
- Exactly one catalog `system.filesystem.utilization` and one `system.filesystem.inode_utilization` are emitted, each the maximum across every successful mount read.
- Per-mount utilization uses the non-catalog `dbpilot.inspection.host.filesystem.*` names.
- Any discovered mount read failure marks the filesystem snapshot incomplete and omits both catalog aggregates, allowing the evaluator to produce `missing_data`.
- An empty partition list uses the root-filesystem fallback required by the Kylin/container environment.

RED:

- Focused Go build failed because `FilesystemReadIncomplete` and `readFilesystemObservations` did not exist.
- The existing collector also returned 64 catalog series instead of one worst-case series.

GREEN:

- Critical mount before the sorted detail range, critical mount after the 64-mount detail cap, partial failure, root fallback, aggregate count and detail naming all pass.

Mutation:

- Replacing the utilization reducer `math.Max` with `math.Min` failed both before-cap and after-cap cases (`expected 97, actual 0`).

### 2. Combined report budget and permanent renderer failures — Critical

Files:

- `backend/internal/inspection/report_budget.go`
- `backend/internal/inspection/report_budget_test.go`
- `backend/internal/inspection/service.go`
- `backend/internal/inspection/report.go`
- `backend/internal/inspection/worker.go`
- `backend/internal/inspection/postgres.go`
- `backend/internal/controlplane/problem.go`
- `contracts/openapi/common/inspection.yaml`
- `contracts/openapi/modules/platform.yaml`
- generated Go/TypeScript clients

Behavior:

- A checked estimator runs over the actual item and target snapshots before IDs, Run, Job, commands or outbox rows are created.
- Checked multiplication rejects overflow and more than 10,000 possible Findings.
- The estimate accounts for IDs, item names/categories/documentation, target identity, command identity, repeated recommendations, fixed evidence/threshold/timestamp/reference overhead and worst-case HTML escaping expansion.
- Any JSON or HTML worst case above 1 MiB returns the documented cross-field 422 response.
- `InspectionRun.findings` and `InspectionReport.findings` are capped at 10,000 in canonical OpenAPI.
- Legitimate HTTPS documentation/recommendation text is accepted. Database schemes, JDBC, URI userinfo, credential query keys, authorization/bearer/private-key/raw-log material remain structurally rejected.
- `ErrInvalidReport`, `ErrUnsafeReport` and `ErrReportTooLarge` terminalize the claimed Run as failed. Artifact/storage failures remain retryable in `generating_report`.
- Deterministic pre-side-effect budget failures abort their HTTP idempotency claim rather than leaving it processing.

RED:

- Contract test observed `2,000,000 != 10,000`.
- Go build failed on the absent estimator, overflow errors and permanent `FailReport` repository boundary.
- HTTPS recommendation rendering returned `ErrUnsafeReport` because all `://` text was rejected.
- Worker permanent-error test remained `completed`/repairable rather than failed.

GREEN:

- Accepted/rejected 1 MiB boundary cases, checked overflow, 10,001 Finding rejection, long recommendation, valid HTTPS, pre-ID rejection, structural credential rejection, permanent failure terminalization and temporary Artifact retry all pass.

Mutation:

- Removing the pre-side-effect estimator caused the test ID factory to fire and fail immediately, proving that late renderer rejection cannot satisfy the regression test.

### 3. Versioned capabilities, legacy health and process semantics — Important

Files:

- `backend/internal/agent/collection_coordinator.go`
- `backend/internal/agent/collectnow_executor.go`
- `backend/internal/agent/controlclient.go`
- `backend/internal/agent/commandverify.go`
- `backend/cmd/agent/main_test.go`
- `backend/cmd/controlplane/main.go`
- `backend/internal/inspection/model.go`
- `backend/internal/inspection/evaluator.go`
- `backend/scripts/verify-kylin-docker.ps1`

Behavior:

- Agents advertise generic `collect_now` plus `collect_now.host.v1` and/or `collect_now.dependencies.v1` according to the installed collectors.
- Versioned tokens are accepted by the production command verifier as informational advertisements; generic `collect_now` remains the command authorization.
- Legacy `health` normalizes to dependency collection and succeeds only when the dependency collector exists.
- Host-only, dependency-only and combined result summaries are accurate and fixed.
- The control plane infers metric/metadata/log sources only from `collect_now.host.v1`; a rolling old Agent with generic capability stays online without overclaiming evidence.
- Process allowlist availability and match count come from the authenticated snapshot metrics. Availability `0` is unsupported; availability `1` with zero matches is critical.
- The unreachable control-plane `TrustedProcessAllowlist` field was removed. Legacy target JSON containing it remains readable and no longer reserializes it.

RED:

- `health` was unsupported, host results said dependency telemetry, versioned constants were absent, generic capability populated all sources, and configured process evidence still evaluated unsupported.
- The first Kylin attempt exposed the production verifier rejecting versioned advertisement tokens.
- The second Kylin attempt exposed the smoke gateway still expecting the old dependency summary for a host command.

GREEN:

- Agent/coordinator/executor/control-plane/evaluator tests pass, including generic-required authorization.
- Final Kylin verifies both versioned advertisements and the host/dependency summaries.

Mutation:

- Inferring sources from `collect_now.dependencies.v1` instead of `host.v1` failed the live target source assertion.

### 4. Durable concurrency and deadlines — Important

Files:

- `backend/internal/job/model.go`
- `backend/internal/job/repository.go`
- `backend/internal/job/postgres.go`
- `backend/internal/job/dispatcher.go`
- `backend/internal/job/migrations/0007_inspection_concurrency.sql`
- `backend/internal/inspection/repository.go`
- `backend/internal/inspection/service.go`
- `backend/internal/inspection/postgres.go`
- `backend/internal/inspection/worker.go`
- `backend/internal/inspection/migrations/0006_run_concurrency.sql`
- `backend/scripts/verify-inspection-postgres.ps1`

Behavior:

- `max_concurrency` and `target_timeout_seconds` are persisted and scan-validated on inspection Runs and Jobs.
- New additive migrations backfill existing inspection rows; fresh installation applies the same migrations after the original schema.
- Batch timeout is checked `ceil(targets/max_concurrency) * target_timeout`.
- `ReservePrepareSlot` locks the command and Job in one transaction, counts `preparing|prepared|start_authorized|running|cancelling`, resumes an already reserved command after restart, and moves a new pending command to `preparing` only below the persisted maximum.
- A full slot clears/defer/releases the outbox lease without error and without preparing the command.
- Terminal command phases release capacity for the next target.
- Each successful target’s evidence deadline is `TargetResult.FinishedAt + TargetTimeout`, capped by the batch timeout. Queue wait does not consume that per-target evidence interval.

RED:

- Go tests failed to compile because Run/Job fields and `ReservePrepareSlot` did not exist.

GREEN:

- Unit max=1 dispatches one command, then dispatches the second after terminal release.
- Real PostgreSQL concurrent dispatchers reserve exactly one slot; a new repository instance resumes it after restart; the loser remains deferred; terminalization admits the loser.
- Wave timeout and per-target evidence deadline/cap tests pass.

Mutation:

- Ignoring a denied reservation dispatched two commands and failed `expected 1, actual 2`.

### 5. Scheduler coalescing — Important

Files:

- `backend/internal/inspection/repository.go`
- `backend/internal/inspection/service.go`
- `backend/internal/inspection/postgres.go`
- scheduler unit and PostgreSQL integration tests

Behavior:

- `CoalescedScheduledOccurrences` uses bounded logarithmic schedule queries, not backlog iteration.
- It selects the latest occurrence at or before scheduler `now` and the first occurrence after `now`.
- The originally claimed stale `next_run_at` is retained separately as the transaction CAS fence; the selected occurrence owns Run identity.
- At most one Run is created per policy/pass/outage.

RED:

- Coalescing function and claim fields were absent; prior service used the stale occurrence directly.

GREEN:

- Multi-year every-minute outage, annual Asia/Shanghai schedule, America/New_York DST gap, duplicate occurrence, expired-lease restart and live PostgreSQL one-Run/next-future behavior pass.

Mutation:

- Reassigning the Run occurrence to the stale claim failed with expected scheduler `now`, actual stale time.

### 6. Retry refresh and correlation — Important

Files:

- `backend/internal/inspection/model.go`
- `backend/internal/inspection/service.go`
- `backend/internal/controlplane/inspection_api.go`
- retry unit and PostgreSQL integration tests

Behavior:

- Retry preserves policy/item versions and the original target IDs, display name, host and labels.
- It resolves the current exact target IDs and refreshes connectivity, capabilities and advertised sources only; newly configured targets are not added.
- Original offline/generic evidence can therefore retry as current online `host.v1` evidence.
- Actual request ID and trace ID from the HTTP context are persisted without synthetic replacement.

RED:

- The old method signature had no request/trace inputs and target snapshots remained offline/stale.

GREEN:

- Offline/generic to online/host.v1, fixed target set, preserved descriptive identity and exact request/trace tests pass.

Mutation:

- Reusing the original target snapshot failed `expected online, actual offline`.

### 7. Scoped Run idempotency and created-resource Audit — Important

Files:

- `backend/internal/inspection/repository.go`
- `backend/internal/inspection/service.go`
- `backend/internal/inspection/postgres.go`
- `backend/internal/inspection/migrations/0007_run_idempotency.sql`
- `backend/internal/controlplane/inspection_api.go`
- HTTP and PostgreSQL tests

Behavior:

- Run correlation is exact tenant/project + actor + operation + key, with an immutable `sha256:` fingerprint.
- The old raw-key unique index is replaced additively. Existing rows backfill actor/operation/fingerprint. Historical rows whose old key was null remain readable; new writes require a full correlation.
- Job idempotency uses the actual Run identity, avoiding a second raw-key collision below the Run layer.
- Create ad hoc, run policy and retry do not collide across actors/operations.
- Fingerprint mismatch in the same exact correlation is a conflict.
- HTTP Run IDs are deterministic before the recoverable claim, allowing the original reconciliation payload and Audit to target the actual created Run.
- Crash replay finds only the exact correlation, creates no second Run, and preserves the original request/trace and stable Audit dedupe.

RED:

- New correlation fields/query/migration did not exist; crash replay Audit targeted `ad-hoc` instead of the Run.
- Legacy keyless scan initially returned `invalid inspection value`.

GREEN:

- Real PostgreSQL same-key/different-actor, same-key/different-operation and fingerprint-conflict tests pass.
- HTTP crash replay creates once, audits once, targets the deterministic Run, and retains original request/trace.
- Backfilled keyless row scan passes.

Mutation:

- Reverting Audit resource to the requested source failed `expected inspection-run-..., actual ad-hoc`.

### 8. Writable Artifact readiness — Important

Files:

- `backend/internal/artifact/download_handler.go`
- `backend/internal/artifact/download_handler_test.go`
- `backend/scripts/verify-kylin-docker.ps1`

Behavior:

- `Ready` retains an `os.Root` only after a unique hidden create, write, file fsync, hard-link or atomic rename, remove, and directory sync probe.
- Cleanup runs on every boundary and never alters existing files.
- Link-unavailable filesystems use rename fallback.
- Create/write/file-sync/publish/remove/directory-sync failures are injectable and leave no retained root or probe file.
- Kylin proves a writable Artifact root succeeds/cleans and `/proc` is rejected as read-only.

RED:

- Tests failed to compile because readiness hooks/link boundary did not exist.

GREEN:

- All injected boundary, sentinel preservation and rename fallback tests pass.
- Kylin prints `writable_probe=true cleanup=true read_only_rejected=true`.

Mutation:

- Skipping the probe made every injected-failure case return nil and fail; the mutation test cleanup was made unconditional as a result.

### 9. Policy UI selectors and pagination — Important

Files:

- `frontend/modules/inspection/inspection.js`
- `frontend/tests/inspection.test.js`

Behavior:

- Nonempty labels are a valid selector without explicit targets; both empty is rejected.
- Target pages are followed to 10,000 and item pages to the policy cap of 200 using opaque cursors.
- Repeated/missing cursors, source changes and cap overflow become explicit validation errors rather than silent omission.
- Every page uses the same AbortSignal; scope changes abort the chain and stale versions cannot render.
- Policy lists expose next/previous navigation without interpreting cursor contents.

RED:

- Label-empty submission created a second policy, Target/Item 149 were absent, second-page AbortSignal was never set, and policy next control was absent.

GREEN:

- All four new UI scenarios pass; the complete inspection UI file passes 26/26.

Mutation:

- Returning after the first 100 selection rows failed the Target 149/Item 149 assertions.

### 10. Report detail and explicit format — Important

Files:

- `contracts/openapi/common/inspection.yaml`
- `contracts/openapi/dbpilot-api.yaml`
- `contracts/openapi/modules/platform.yaml`
- pinned generated Go/TypeScript output
- `backend/internal/inspection/report.go`
- `backend/internal/inspection/worker.go`
- `backend/internal/controlplane/inspection_api.go`
- `frontend/modules/inspection/*`
- `frontend/modules/reports/*`

Behavior:

- Additive report DTOs expose immutable snapshot targets, structured `evidence_fields`, thresholds, real Finding IDs, Job ID, target/Command references and Audit correlation.
- Legacy evidence JSON string remains for compatibility.
- HTML visibly renders evidence, thresholds, target summaries, Job, Command and Audit references with template escaping.
- Download body requires named enum `format: html|json`; exact suffix selection rejects unavailable/invalid formats.
- Format is already fingerprinted by the captured JSON body; it is not incorrectly treated as If-Match.
- Inspection UI and Report Center expose separate HTML and JSON actions, render target navigation/evidence/thresholds/references, and escape injected markup.

RED:

- Contract lacked evidence fields, targets, references and request format.
- Go lacked `ReportFinding.ID`, response mapping, exact selector and new service signature.
- UI sent format as the idempotency key, rendered one combined button and omitted evidence/references.
- Application-level JSON download initially returned 400 because format was incorrectly supplied as If-Match fingerprint input; the new test reproduced and fixed it.

GREEN:

- Contract tests 4/4, focused Go renderer/wire/selection/application tests, inspection UI 26/26 and combined inspection/Report Center 52/52 pass.

Mutation:

- Forcing selection to `.html` failed JSON selection (`expected ...json, actual ...html`).

### 11. Minor behavior and documentation

Files:

- `backend/internal/inspection/worker.go`
- `backend/internal/inspection/worker_test.go`
- `backend/internal/agent/collectnow_executor.go`
- `.superpowers/.../progress.md`
- `docs/host-inspection-operations.md`
- authoritative design and implementation-plan documents

Behavior:

- A failed target captured as authenticated offline uses `agent_offline`.
- Host-only CollectNow says host telemetry; dependency and combined summaries remain accurate.
- Ledger Tasks 1–7 show complete.
- The exact 13-item MVP scope is stated. Read-only/growth filesystem, network connectivity/errors, critical ports and Agent policy-state are explicitly queued for the next host-function phase.

RED/GREEN:

- Offline worker test failed `expected agent_offline, actual collection_failed`, then passed after the targeted mapping.

## Additive migration evidence

- `job/migrations/0007_inspection_concurrency.sql`: nullable execution-limit columns for generic Jobs, bounded required values/backfill for `inspection.collect`, and Job/phase count index.
- `inspection/migrations/0006_run_concurrency.sql`: backfills and makes Run timeout/concurrency immutable, bounded and non-null.
- `inspection/migrations/0007_run_idempotency.sql`: safely backfills actor/operation/fingerprint, replaces the raw-key index, and extends immutable Run guards.
- Both upgrade and fresh-install paths are exercised by real PostgreSQL migration setup. Original reviewed migrations were not edited.

## Full verification evidence

### Contracts and generated code

- `npm run contracts:lint`: PASS; only the pre-existing `info.license` warning.
- `npm run contracts:breaking`: PASS.
- Pinned `npm run contracts:generate`: PASS after using the repository Go toolchain on PATH.
- `npm run contracts:verify`: PASS against staged canonical/generated output.
- Canonical schemas were changed first; generated Go/TypeScript files were never hand-edited.

### Node and Go

- Fresh `node --test`: 284 total, 283 passed, 0 failed, 1 expected opt-in Prism skip.
- Foundation separately ran the real Prism test: 1 passed, 0 failed.
- Fresh `go test ./... -count=1`: every package passed.
- Fresh `go vet ./...`: exit 0, no output.
- `git diff --check` and staged diff check: exit 0.

### Real PostgreSQL

- `verify-inspection-postgres.ps1`: PASS.
  - 17 live inspection integration scenarios passed, including atomic rollback, disjoint claims, scheduler restart/coalescing/duplicate, immutable report/history, Audit repair, full 13-item hydration, source/time fences, exact scope, service creation, actor/operation/fingerprint idempotency, retry snapshots and pagination.
  - Durable prepare-slot concurrent dispatcher/restart/release test passed.
  - Platform PostgreSQL integration passed.
- `verify-host-inspection.ps1`: PASS.
  - `run=inspection-e2e-01 status=partial findings=13 reports=1 artifacts=2 commands=inspection-e2e-03,inspection-e2e-04`.

### Foundation

- `verify-contract-foundation.ps1`: PASS.
- Included lint, breaking, drift, Node, Prism, full Go, host lifecycle, seven two-phase recovery scenarios and Job command lifecycle.

### Approved Kylin V10 SP1 amd64

Command used the exact approved image `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1` and `-Architecture amd64`.

Final decoded evidence:

```text
Kylin protocol smoke passed: production_agent=true collect_now_dependencies=true collect_now_host=true result_ack=true
Kylin host snapshot evidence: source=inspection-host-snapshot batch=d7d8cbf1af85fb12a8f5f531594b6eda metrics=26 cpu=1 memory=1 filesystem=1 load=1 snapshot_at=2026-08-29T00:06:55.521596846Z
Kylin artifact readiness evidence: writable_probe=true cleanup=true read_only_rejected=true
Kylin validation passed: ID=kylin VERSION=V10 ARCH=x86_64 journal=opened policy=parsed protocol=two-phase host_snapshot=decoded artifact_readiness=write_fsync_publish_remove native_reader=true
```

The first Kylin run found production verifier rejection of versioned advertisements. The second found the smoke’s stale host-summary assertion. Both received focused RED/GREEN fixes before the final passing run.

## Cleanup evidence

- Host verifier: exact container cleanup passed, anonymous volumes removed (`1`).
- Foundation verifier: exact container cleanup passed, anonymous volumes removed (`1`).
- Kylin verifier: exact container cleanup passed, anonymous volumes `0`.
- Independent final audit: `verifier_containers=0 temporary_directories=0`.
- No broad Docker/container/temp cleanup command was used; each verifier removed only its recorded resources.

## Self-review and residual concerns

Self-review found and fixed four issues before commit: real format download fingerprint misuse, keyless legacy Run scan compatibility, pre-side-effect budget idempotency abort classification, and the production verifier’s handling of versioned collector capabilities/host summary.

No Critical or Important functional finding remains open. Retained concerns are the already documented nonfunctional deferrals:

- Artifact descriptor exact replay and expired-Prepared cancel delivery retry.
- Report Audit repair starvation under sustained backlog.
- Large-history `accepted_at` online migration strategy.
- Node audit baseline: 17 findings (16 moderate, 1 high).
- Existing Redocly `info.license` warning.
- Generated SDK typing cleanup and overview performance.
- Broader PostgreSQL/Kylin VM/bare-metal evidence beyond the required container gates.
- The next host-function phase items explicitly listed above.

Recommended stage remains the one already recorded in the repository ledger: reassess and remediate operationally unacceptable items before production rollout without blocking delivery of the remaining product modules.
