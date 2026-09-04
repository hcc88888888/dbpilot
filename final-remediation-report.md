# Host Platform Final Remediation Report

Status: **DONE**

- Worktree: `D:/AI/codex/workspace/数据库运维管理系统/.worktrees/host-platform-final-remediation`
- Branch: `codex/host-platform-final-remediation`
- Base: `8322241535cce5427b816bdfe1d271d8f4e66e60`
- Final HEAD: `4bdd184`
- Integration action: branch and worktree preserved; no merge and no push.

## Delivered remediation

### Task 1: revoked replay and AgentControl admission races

- Enrollment replay now uses one repeatable-read snapshot and accepts a stored
  issuance only when it is unrevoked and exactly matches the active Host
  generation, SHA-256 leaf fingerprint, and serial.
- Session cleanup uses database-confirmed superseded fingerprint+serial pairs
  and terminates only the matching Registry session. Late cleanup for an old
  leaf preserves a newer session and drains queued messages before cancel.
- AgentControl revalidates the verified leaf immediately after Registry
  registration and removes only the just-registered session when replacement
  or decommission wins the pre-Hello race.
- Real PostgreSQL and mTLS tests cover historical token/CSR replay rejection,
  current-session preservation, replacement/decommission admission, and
  Artifact 403/200 behavior.

### Task 2: validation terminal lifecycle and result trust

- Added forward-only
  `databaseinstance/migrations/0003_validation_correlation.sql` with exact
  active validation Job/command correlation and pending-row backfill.
- Every terminal target path now finalizes the validation projection through
  one idempotent boundary: success, typed failure, rejection, cancel,
  undelivered/prepared/delivery/execution timeout, and timeout repair after an
  Agent disconnect.
- A periodic database repair closes pending validation rows whose immutable
  Job/Outbox is already terminal, preventing permanent `connection_testing`.
- Assignment, instance membership, configuration, operation, active Job, and
  command fences apply to every success and failure. A stale result terminates
  only its own validation row and cannot overwrite a newer generation.
- The Server discards Agent Summary, rejects validation artifacts and
  unexpected typed payloads, and persists only fixed summaries plus
  allowlisted error codes. Serializable concurrent terminal delivery retries
  idempotently.

### Task 3: controlled generation-zero import

- Added forward-only `enrollment/migrations/0005_generation_zero_import.sql`,
  an immutable scoped import record, and a global active-leaf fingerprint
  uniqueness fence.
- The temporary config window requires an exact
  `agent_id -> tenant_id/project_id/host_id` allowlist that matches the static
  Agent scope. Runtime preflight runs after migrations and before listeners.
- The first CA-verified, single-SPIFFE AgentControl or Artifact admission
  atomically claims a generation-zero Host's exact leaf as generation 1 and
  writes one fixed Audit event. Competing, cross-tenant/Agent, and
  decommissioned claims fail closed.
- The exact claim survives restart after the window closes. Canonical
  replacement enrollment advances an imported generation 1 to generation 2
  and precisely terminates the imported leaf.
- The example configuration and host/plugin operations runbook document
  preflight, the migration window, verification, restart persistence, and
  mandatory closure.

### Task 4: immutable Rediscover replay and DTO honesty

- Rediscover derives Job/command identity from immutable request correlation
  and reads the Job plus exact Outbox in one repeatable-read snapshot before
  consulting current Host, policy, or capability state.
- Processing-claim recovery stores Request/Trace plus the fixed Audit payload
  in one immutable envelope, so a lost HTTP response repairs Job/Outbox/Audit
  without reevaluating changed preconditions.
- Bounded OIDC StringOrURI subjects and punctuation-bearing 128-character
  OpenAPI idempotency keys are accepted; resource identifier regexes remain
  limited to resource IDs.
- Internal `plugin_failed` validation no longer serializes as `not_tested`.
  The existing v1 enum uses `unreachable`, while management/capability remain
  `plugin_failed` and the fixed `connection_error:plugin_failed` detail makes
  the cause explicit without changing the OpenAPI contract.

## TDD evidence

Material REDs observed before production changes included:

- historical enrollment replay called negative `TerminateSuperseded` and
  killed the current leaf session;
- replacement/decommission between pre-Hello authorization and registration
  admitted the stale leaf;
- Registry lacked exact fingerprint+serial termination;
- validation Agent Summary entered Job unchanged, validation artifacts were
  accepted, and non-Agent terminal paths left the projection pending;
- real PostgreSQL lacked active validation correlation/terminal repair and 16
  concurrent identical terminals exposed Serializable `40001` failures;
- generation-zero YAML was unknown and the repository exposed no controlled
  import window;
- Rediscover replay rechecked offline Host, changed policy, and disappeared
  capability before locating the committed operation;
- Rediscover rejected a global OIDC subject/OpenAPI key, accepted a Job with
  broken Outbox correlation, and processing recovery stranded Audit in
  `side_effect_committed`;
- `plugin_failed` serialized as `not_tested`.

Each RED has a focused GREEN test on final HEAD.

## Verification evidence

| Gate | Final result |
| --- | --- |
| `go test ./... -count=1` in `backend` | PASS, all Go packages |
| `go vet ./...` in `backend` | PASS, exit 0 |
| `npm test -- --run` in `frontend/app` | PASS, 9 files / 84 tests |
| `npm run build` in `frontend/app` | PASS, TypeScript + Vite |
| `node --test tests/contracts/host-plugin-full-stack.test.mjs` | PASS, 13/13 |
| `git diff --check 8322241...HEAD` | PASS |

The first Task17 contract run was intentionally parallel with two heavy
PostgreSQL suites and hit only the two-second PowerShell fail-closed timing
assertion. The failing case passed alone, and the complete contract then passed
13/13 without parallel load.

### Real PostgreSQL and mTLS

- Full `internal/enrollment` and `internal/agentcontrol` runs passed with the
  dedicated PostgreSQL container, including generation-zero import,
  original-schema upgrade, revoked replay, exact replacement, Registry races,
  and real mTLS Artifact admission.
- Full `internal/pluginassignment` and `internal/databaseinstance` PostgreSQL
  runs passed, including stale failure fencing, no-result timeout/cancel,
  timeout retry, stale old-generation delivery, and 16-way terminal delivery.
- The PostgreSQL HTTP Rediscover test passed: first response lost with HTTP
  500, Host changed offline, retry returned 202, idempotency reached
  `completed`, and Job/Outbox/Audit counts remained exactly one.

### Task17 full-stack

- Official Kylin V10SP1 amd64 Compose acceptance: **PASS**.
- Covered enrollment, discovery, plugin runtime, connection/template paths,
  stop/restart/rollback, Agent restart, Server restart, browser and failure
  canaries on final product code.
- Cleanup audit: **PASS**, exact removal of `28 containers / 4 networks / 23
  volumes / 1 runner image / temporary directory`.

## Protected paths, migrations, secrets, and residuals

- Protected contract/generated matches from base: **0** for `contracts/`,
  `backend/gen/`, `frontend/generated/`, Protobuf, Buf, foundation, and
  generator wrappers. No generator was run.
- Existing migrations modified: **0**.
- Added migrations: exactly 8 (`databaseinstance/0003`,
  `databaseinstance/0003a`, `databaseinstance/0004`,
  `databaseinstance/0005`, `enrollment/0005`, `enrollment/0006`, `job/0007a`,
  and `job/0008`).
- No raw Agent Summary, arbitrary validation artifact, credential, private
  key, certificate material, or raw driver error is written to Job, Audit,
  instance state, or logs by these changes.
- The dedicated PostgreSQL container
  `dbpilot-final-remediation-pg` was verified by exact ownership label and
  removed. Its temporary test data is not recoverable.
- No Task17-owned container, network, volume, or runner image remains.

## Commits

1. `a02220f` `fix(enrollment): close replay and admission races`
2. `78db6b6` `fix(instances): finalize every validation terminal path`
3. `fc194aa` `feat(enrollment): import generation-zero credentials`
4. `5d2bbea` `fix(hosts): replay immutable rediscovery operations`

## Non-blocking technical debt

- Module: `frontend/app` production bundle.
- Trigger: `npm run build`.
- Observation: Vite reports the main minified JavaScript chunk at 544.28 kB,
  above its 500 kB warning threshold.
- Functional impact: none; build, unit tests, browser, and Task17 full-stack
  pass.
- Severity: low / non-blocking performance hardening.
- Recommended stage: consolidated frontend performance pass before production
  rollout, followed by bundle and browser regression verification.

No functional correctness, data-integrity, unsafe-command, secret-exposure,
immutable-replay, credential-admission, validation-lifecycle, or teardown
concern remains open in this remediation scope.

## Fix round 1

Status: **DONE**

Source of truth: `final-remediation-round1-findings.md` — six P1 and two P2
findings verified and closed with strict RED/GREEN evidence.

### Resolved findings

1. AgentControl credential registration now returns the exact created Registry
   session. Post-register reauthorization and failure cleanup use only that
   pointer, so an old registration cannot capture or terminate a replacement.
2. Database validation finalization returns the database-effective fenced
   result. Dispatcher Command status, Job target, fixed summaries/error codes,
   generic Audit, retries, and concurrent delivery all use that effective
   outcome rather than the original Agent claim.
3. Validation recovery now repairs both half-commit directions. Pending
   projection rows consume terminal Job/Outbox state; terminal projection rows
   emit exact Job repair descriptors and idempotently terminalize Job plus
   Outbox. A crash between any repair step remains discoverable next cycle.
4. Immutable terminal command decode validates canonical command structure
   without consulting mutable ownership. Admission/dispatch still use the
   live target authorizer; retire/detach after admission cannot block
   timeout/cancel/rejection/result completion.
5. Command acknowledgement ReasonCode is globally limited to a 128-character
   identifier token at AgentControl and lifecycle boundaries. Validation
   rejection persists only fixed `plugin_failed`, a fixed summary, and fixed
   Audit detail; secret-shaped/control/oversize inputs are rejected before
   persistence.
6. Rediscover replay proves a canonical unknown-free deterministic envelope,
   empty authority fields, the exact 120-second lease, Agent/rule/include
   decisions through a stored SHA-256 correlation, and exactly one Outbox row
   in the repeatable-read operation snapshot.
7. Generation-zero preflight now compares the import row's exact generation,
   fingerprint, and serial with the Host active leaf. New forward-only
   `enrollment/0006_generation_zero_import_immutability.sql` makes import rows
   append-only and rejects UPDATE/DELETE.
8. New forward-only
   `databaseinstance/0004_validation_orphan_guard.sql` fails startup when a
   base-era queued/running instance has no exact pending validation row or when
   a nonpending instance retains active correlation. A persistent shape
   constraint prevents the invalid correlation state from being reintroduced.

### Round 1 TDD and PostgreSQL evidence

Material REDs included: newer-session capture capability; stale-success Job
recorded as succeeded while projection stored `plugin_failed`; both validation
half-commit directions; detach blocking terminal decode; raw/oversize rejection
reason persistence; Rediscover unknown fields/changed lease/rule/include/second
Outbox acceptance; imported Host/import-row mismatch; mutable import rows; and
orphan base-era validation upgrade acceptance.

Focused GREEN and real PostgreSQL/mTLS runs prove:

- exact returned session and replacement-race preservation;
- stale success/failure and 16-way concurrent effective-outcome replay;
- projection-terminal to Job/Outbox repair and the inverse terminal Job/Outbox
  to pending-projection repair;
- terminalization after mutable target rejection;
- fixed rejection persistence with malicious/oversize inputs rejected;
- Rediscover canonical envelope and sole-Outbox verification, including the
  real PostgreSQL lost-response/offline-host HTTP recovery;
- generation-zero corruption/restart/immutability/original-schema upgrade;
- valid pending base-era migration and deterministic orphan startup failure.

### Round 1 final gates

| Gate | Result |
| --- | --- |
| `go test ./... -count=1` | PASS, all Go packages |
| `go vet ./...` | PASS |
| React Vitest | PASS, 84/84 |
| React production build | PASS |
| enrollment + AgentControl real PostgreSQL/mTLS | PASS |
| pluginassignment + databaseinstance real PostgreSQL | PASS |
| Rediscover real PostgreSQL HTTP recovery | PASS |
| Task17 contract | PASS, 13/13 |
| Kylin V10SP1 amd64 Compose full-stack | PASS |
| Task17 cleanup | PASS, 28 containers / 4 networks / 23 volumes / 1 image / temporary directory removed |

Round 1 commits:

1. `090226c` `fix(agentcontrol): retain exact registered session`
2. `c94c1f8` `fix(instances): propagate effective validation outcome`
3. `32840bb` `fix(instances): repair validation half commits`
4. `6ea0fa8` `fix(jobs): structurally decode terminal commands`
5. `52c7061` `fix(jobs): bound rejection reason codes`
6. `36997a2` `fix(hosts): verify immutable rediscovery envelope`
7. `ba74229` `fix(enrollment): make imported credentials immutable`
8. `51e8894` `fix(instances): reject orphan validation upgrades`

Round 1 introduced no contract/generated changes, modified no existing
migration, leaked no raw Agent/driver/secret material, and left no owned Docker
resource. The only non-blocking item remains the pre-existing Vite 544.28 kB
main-chunk warning recorded above.

## Fix round 2

Status: **DONE** on final HEAD `2830833`. All six rereview findings were
verified with focused RED/GREEN tests and closed without contract/generated
changes.

### Resolved findings

1. Agent validation result handling now acquires the durable execution
   token/revision CAS before any projection mutation. A stale token, wrong
   revision, or timeout-versus-late-result race cannot change the instance.
   When the fence computes a different effective terminal classification, the
   exact terminal digest permits only that fenced correction.
2. Validation half-commit recovery uses Job/Outbox as the durable source for
   the exact success, failure, rejection, cancellation, or timeout cause.
   Matching terminal targets finish a stranded nonterminal Job directly;
   independent repair records continue after a bad record, and fixed Audit is
   retained without starvation.
3. Retiring an instance now closes its queued/running validation, target, Job,
   Outbox, projection correlation, and fixed Audit in one SQL transaction.
   New forward-only migration
   `databaseinstance/migrations/0003a_retired_validation_repair.sql` runs
   between `0003` and `0004`, repairs historical retired rows, and rejects
   non-retired validation rows missing their exact Job or Outbox before the
   orphan guard is enforced.
4. Rediscover now writes a versioned `v2` payload-digest key. Canonical
   pre-digest and unversioned-digest Job/sole-Outbox snapshots are verified and
   upgraded once through a serializable, payload-bound CAS. Replay recovery
   does not reevaluate mutable Host/policy/capability state; detectable legacy
   corruption and payload TOCTOU fail closed without upgrading.
5. Generic validation result Audit records the database-effective fenced
   state. A different incoming Agent claim is retained only as the fixed enum
   field `incoming_state`; no raw result or error material is persisted.
6. Migration coverage starts from the real `0002` database-instance schema
   alongside real Host, discovery, Job, target, and Outbox tables. It executes
   `0003`, `0003a`, and `0004` over valid pending, orphan, retired pending,
   missing Job/Outbox, restart, and exact-correlation cases.

### Round 2 TDD and PostgreSQL evidence

Material REDs included: projection mutation before a failed execution fence;
timeout/cancel causes collapsing to failure and a matching terminal target
loop; Retire leaving an active validation/Job behind; real `0002` migration
startup accepting historical invalid state; stale-success Audit using the
incoming claim; and legacy Rediscover records being unavailable or remaining
on an unversioned digest.

Focused GREEN and real PostgreSQL runs prove:

- wrong/stale execution fences cause zero projection writes, including
  timeout-versus-late-result races;
- timeout, cancel, reject, fail, and success causes survive both half-commit
  directions, matching targets converge, and one corrupt repair does not
  starve later records;
- active validation Retire is atomic, while historical retired rows are
  deterministically repaired and real `0002` orphan states fail startup;
- stale success/failure Audit records the effective state;
- pre-digest and unversioned Rediscover records upgrade exactly once to `v2`,
  including a lost HTTP response with a processing owner after the Host became
  offline; unknown fields, changed lease/authority, a second Outbox, and an
  upgrade-time payload race remain unavailable and unmodified.

### Round 2 final gates

| Gate | Result |
| --- | --- |
| `go test ./... -count=1` | PASS, all Go packages |
| `go vet ./...` | PASS |
| React Vitest | PASS, 9 files / 84 tests |
| React production build | PASS |
| enrollment + AgentControl real PostgreSQL/mTLS | PASS |
| pluginassignment + databaseinstance real PostgreSQL | PASS |
| Rediscover real PostgreSQL HTTP recovery/corruption | PASS |
| Task17 contract | PASS, 13/13 |
| Kylin V10SP1 amd64 Compose full-stack | PASS |
| Task17 cleanup | PASS, 28 containers / 4 networks / 23 volumes / 1 image / temporary directory removed |
| `git diff --check 8322241...HEAD` | PASS |

Round 2 commits:

1. `eee79a7` `fix(instances): fence validation result before projection`
2. `7da0663` `fix(instances): preserve validation terminal causes`
3. `d726403` `fix(instances): audit effective validation state`
4. `310f64d` `fix(instances): retire active validations atomically`
5. `2830833` `fix(hosts): upgrade legacy rediscovery digests`

Round 2 introduced no contract/generated changes, modified no existing
migration, matched no private-key material, and left no owned PostgreSQL or
Task17 Docker resource. The dedicated
`dbpilot-final-remediation-r2-pg` container was verified by exact ID and
ownership label before removal; its temporary test data is not recoverable.
The only non-blocking item remains the pre-existing Vite 544.28 kB main-chunk
performance warning.

## Fix round 3

Status: **DONE** on final HEAD `4bdd184`. All six architecture rereview
findings were reproduced and closed with strict RED/GREEN evidence. This round
supersedes Round 2's permissive pre-digest Rediscover upgrade: pre-digest
records now always fail closed because they contain no independent immutable
evidence.

### Resolved findings

1. Validation Agent results use a validation-owned Serializable transaction
   that verifies the execution token/revision, computes the fenced effective
   classification, and commits Command status/digest, validation projection,
   instance state, and fixed validation Audit together. A stale success is
   durably `failed + plugin_failed`; a projection transaction failure leaves
   the Command active rather than committing a raw winner.
2. Every terminal command kind writes a sanitized target descriptor,
   artifacts, fixed terminal Audit metadata, and a reconciliation marker to
   Outbox before a separate Job mutation. The PostgreSQL generic reconciler
   uses a consistent Job-to-Outbox lock order to atomically repair target,
   counters, aggregate status, artifacts, and the marker. Audit uses
   `RecordOnce` followed by a durable recorded fence, so a crash on either side
   converges exactly once without relying on memory `ClaimOutbox` behavior.
3. New forward migrations
   `job/migrations/0007a_retired_validation_terminal_winner.sql` and
   `databaseinstance/migrations/0005_retired_validation_terminal_winner.sql`
   preserve an agreeing terminal Job/Outbox winner, repair the target before
   generic migration enforcement, cohere Job/target/Outbox/counters and the
   retired projection, and fail startup when Job and Outbox winners conflict.
   Fixed idempotent database-instance and terminal-Audit state is created for
   historical cancellation and other terminal outcomes.
4. Canonical pre-digest Rediscover records are no longer treated as their own
   evidence. Canonical and rule/include/Agent/target-tampered variants all fail
   unavailable without mutating the Job. Only an unversioned key containing
   the exact stored command SHA-256 may enter the one-way v2 upgrade CAS.
5. Rediscover idempotency-key upgrade now CASes the expected Job version and
   increments it exactly once. The returned Job and HTTP ETag therefore expose
   the payload-binding state change; concurrent or repeated replay cannot
   silently represent two keys under one public version.
6. The real migration matrix starts from both `0002` and an already-applied
   `0004` state. It covers succeeded, failed, timed-out, cancelled, missing and
   orphan records, conflicting terminal winners, restart idempotence,
   coherent counters, fixed terminal Audit metadata, and exactly-one
   database-instance Audit. Runtime validation Audit continues to record the
   effective fenced state and only the fixed incoming enum when they differ.

### Round 3 TDD and PostgreSQL evidence

Material REDs included: projection failure after raw Command CAS left
`succeeded`; timeout/cancel/prepared/rejection crash windows left Job queued or
cancelling; Round 2's retired repair overwrote a succeeded/failed/timed-out
target and caused the generic migration to reject an otherwise agreeing
Job/Outbox winner; cancellation wrote no historical Audit; canonical and
self-consistently tampered pre-digest Rediscover records upgraded; and a key
upgrade left Job version/ETag unchanged.

Focused GREEN and real PostgreSQL runs prove:

- CAS-to-process-loss, stale success, typed failure, duplicate retry and
  effective validation repair;
- result, undelivered timeout, cancellation, prepared timeout, rejection and
  execution-timeout recovery with target artifacts and exactly-one Audit;
- 20-round heartbeat/result/timeout concurrency without deadlock or divergent
  Job/Command terminal state;
- real Job-0007 plus databaseinstance-0004 deployed-state upgrade for every
  terminal winner, restart, Audit and conflict-fail-closed case;
- pre-digest rule/include/Agent/target tamper rejection and unversioned-digest
  payload TOCTOU rejection;
- real HTTP lost-response processing-owner recovery after the Host became
  offline, with Job version and response ETag advancing from 1 to 2 exactly
  once.

### Round 3 final gates

| Gate | Result |
| --- | --- |
| `go test ./... -count=1` | PASS, all Go packages |
| `go vet ./...` | PASS |
| React Vitest | PASS, 9 files / 84 tests |
| React production build | PASS |
| enrollment + AgentControl real PostgreSQL/mTLS | PASS |
| Job generic terminal PostgreSQL/failpoint/stress | PASS |
| pluginassignment + databaseinstance PostgreSQL/migration matrix | PASS |
| Rediscover real PostgreSQL HTTP recovery/corruption/version CAS | PASS |
| Task17 contract | PASS, 13/13 |
| Kylin V10SP1 amd64 Compose full-stack | PASS |
| Task17 cleanup | PASS, 28 containers / 4 networks / 23 volumes / 1 image / temporary directory removed |
| `git diff --check 8322241...HEAD` | PASS |

Round 3 commits:

1. `3d74d3d` `fix(instances): persist effective validation winner atomically`
2. `d6ae9cb` `fix(jobs): reconcile every terminal command durably`
3. `1b1b9c9` `fix(instances): preserve retired validation winners`
4. `4bdd184` `fix(hosts): require evidence for rediscovery upgrades`

Round 3 introduced no contract/generated changes, modified no existing SQL
migration, matched no private-key material, and left no owned PostgreSQL or
Task17 Docker resource. The dedicated
`dbpilot-final-remediation-r3-pg` container was verified by exact ID and
ownership label before removal; its temporary test data is not recoverable.
The only non-blocking item remains the pre-existing Vite 544.28 kB main-chunk
performance warning.

## Fix round 4

Status: **DONE** on product HEAD `c58d18a`. All five historical-upgrade and
reconciler findings were reproduced against real pre-fix PostgreSQL schemas and
closed without changing an existing migration, contract, generated file, or
future atomic validation path.

### Resolved findings

1. New forward migration
   `databaseinstance/migrations/0006_historical_validation_recovery.sql`
   accepts only an independently terminal `job_targets` row that agrees with
   the Command as effective evidence for a stranded pre-atomic validation. It
   repairs Job, projection, instance and fixed Audit together. A raw terminal
   Command without independent evidence leaves Job and instance unchanged and
   places both validation and generic Command repair in explicit quarantine.
2. New forward migration `job/migrations/0009_historical_terminal_recovery.sql`
   gives pre-`0008` terminal crash rows fixed, non-sensitive target/Audit
   descriptors and a durable pending fence. Startup validates the canonical
   typed Command against the immutable Job action; unknown actions and
   Job/Command action mismatches fail closed on every restart. Generic repair
   then converges Job and Audit exactly once.
3. New forward migration
   `job/migrations/0007_retired_validation_winner_marker.sql` sorts before the
   existing `0007a`, captures a durable retired-validation winner marker, and
   recognizes the exact synthetic cancellation footprint left by an already
   applied `databaseinstance/0003a`. Job-only and Outbox-only winners are made
   coherent before `0007a`; the database-instance forward migration restores
   the marked projection after `0003a/0005`.
4. Generic terminal reconciliation now atomically claims rows with a lease,
   attempt counter and ordered availability key. Transient failures receive a
   bounded backoff; fixed conflicts and exhausted retries receive fixed-reason
   quarantine. A failed oldest row therefore cannot occupy every later batch.
5. Retired-winner migration compares every public Job and target field it may
   change, including summaries, artifacts, finish time and cancellation
   fields. The public Job version/ETag advances exactly once when the externally
   visible historical representation changes; restart is idempotent.

### Round 4 TDD and PostgreSQL evidence

Material REDs included: missing pre-`0008` Audit descriptors; unknown actions
accepted at startup; a canonical Job type paired with the wrong typed Command;
the oldest failpoint/conflict row being selected forever; raw
`CommandSucceeded` being treated as a failed validation; no typed-failure
projection migration; Job-only and Outbox-only winners conflicting after both
pre- and post-`0003a` starting points; and unchanged versions when only
summary, artifacts, finish time or cancellation fields changed.

Focused GREEN and real PostgreSQL runs prove:

- canonical historical actions repair Job and Audit exactly once, while an
  unknown or mismatched action repeatedly fails startup;
- succeeded and typed-failure target evidence repairs pre-atomic validation,
  while an evidence-free raw Command quarantines without changing public Job
  version or instance outcome;
- Job-only and Outbox-only retired winners survive both a pre-`0003a` upgrade
  and an already-applied `0003a/0004` history, including restart;
- PostgreSQL trigger failpoints defer the failed key, allow a later valid key
  to complete, and recover the first key after backoff; a permanent conflict is
  quarantined and cannot starve the later repair;
- summary-only, artifact-only, finish-time-only and cancellation-field-only
  changes each advance Job version from 2 to 3.

### Round 4 final gates

| Gate | Result |
| --- | --- |
| `go test ./... -count=1` | PASS, all Go packages |
| `go vet ./...` | PASS |
| Full Job PostgreSQL migration/failpoint/reconciler suite | PASS |
| Full database-instance PostgreSQL historical migration suite | PASS |
| Full plugin-assignment PostgreSQL suite | PASS |
| Task17 lifecycle contract | PASS, 13/13 |
| Kylin V10SP1 amd64 host-plugin full-stack | PASS |
| Task17 cleanup | PASS; independent post-run container/network/volume/image/temp-directory counts are all 0 |
| `git diff --check 4bdd184...HEAD` | PASS |
| Protected contract/generated/proto/Buf/OpenAPI/foundation paths | PASS, 0 changed |
| Existing SQL migrations modified | PASS, 0; exactly 3 forward migrations added |
| Final Docker residual audit | PASS, all Round 4 and Task17 counts are 0 |

Round 4 product commits:

1. `90f2e40` `fix(jobs): recover historical terminal commands`
2. `c58d18a` `fix(instances): quarantine ambiguous historical validations`

Round 4 persists only fixed action/status/error/quarantine identifiers and
bounded artifact references. It does not derive an effective validation
outcome from raw Command payload, and writes no raw Agent Summary, driver
error, credential, private key or certificate material. The dedicated
PostgreSQL container `dbpilot-final-remediation-r4-pg` was verified by full ID
and ownership label, then removed with its one anonymous volume; its temporary
test data is not recoverable. An independent residual check found zero Round 4
or Task17-owned Docker resources.

## Fix round 5

Status: **DONE** on product HEAD `d25e8fb`. The final two rereview findings
were reproduced first and closed with two additive migrations. No existing
migration or protected contract/generated/proto/foundation path changed.

### Resolved findings

1. New forward migration
   `job/migrations/0007b_validation_target_outbox_bridge.sql` sorts after the
   retired-winner migrations and before the existing `0008`. For an active,
   non-retired historical validation whose Job is still nonterminal, an
   independently terminal Job target is the sole effective-outcome evidence;
   the Job may be nonterminal or already agree with that target. The migration
   normalizes an opposite raw Outbox terminal status/phase to
   that target before `0008` evaluates its conflict guard. Matching evidence is
   unchanged, while a nonterminal target supplies no evidence and remains for
   the later two-sided quarantine migration. The bridge also runs safely when
   the old Job schema is already recorded as applied and is idempotent on
   restart.
2. New forward migration
   `job/migrations/0010_terminal_reconcile_claim_fence.sql` adds a 32-byte
   random claim token paired with each reconciliation lease. Pre-fence leases
   have no provable owner and are released exactly once during migration. The
   claim, success, transient-failure release/backoff, permanent-failure
   quarantine, and completion paths now compare both the unguessable token and
   exact lease generation. A stale worker therefore cannot clear a newer
   lease, increment attempts, back off, quarantine, or complete the Job. The
   Job-to-Outbox lock order is unchanged.

### Round 5 TDD and PostgreSQL evidence

Material REDs included: target-succeeded/Outbox-failed and
target-failed/Outbox-succeeded rows both caused the old `0008` migration to
raise `conflicting terminal Command and Job target winner`; an already-applied
Job schema retained the wrong raw Outbox status; and the ownership test failed
to compile because no claim token/API existed. A first GREEN stress run also
exposed that wall-clock lease validation broke existing deterministic logical
clock tests, so the fence was narrowed to an exact token plus lease-generation
CAS.

Focused GREEN and real PostgreSQL runs prove:

- target success/failure overrides the opposite raw Outbox status before
  `0008`, including when an existing terminal Job agrees with that target;
  matching evidence remains unchanged, and evidence-free rows retain the
  expected validation and Command quarantine;
- the bridge repairs both pre-`0008` and already-applied schemas, and repeated
  migration startup is idempotent;
- lease expiry followed by worker B reclaim gives B a different random token;
  worker A's concurrent late success or failure cannot mutate B's lease,
  attempts or quarantine, while B completes successfully;
- the concurrent reclaim test passed 20/20 stress repetitions;
- a legacy unowned lease is released once, then restart preserves the new
  live token and lease.

### Round 5 final gates

| Gate | Result |
| --- | --- |
| `go test ./... -count=1` | PASS, all Go packages |
| `go vet ./...` | PASS |
| Full Job PostgreSQL migration/failpoint/reconciler suite | PASS, 25.621s |
| Full database-instance PostgreSQL historical migration suite | PASS, 27.057s |
| Full plugin-assignment PostgreSQL suite | PASS, 28.055s |
| Terminal claim concurrent stress | PASS, 20/20 |
| Task17 lifecycle contract | PASS, fresh 13/13 after focused teardown 5/5 |
| Kylin V10SP1 amd64 host-plugin full-stack | PASS |
| Task17 cleanup | PASS; 28 containers / 4 networks / 23 volumes / 1 image / temporary directory removed |
| `git diff --check f96d1eb...HEAD` | PASS |
| Protected contract/generated/proto/Buf/OpenAPI/foundation paths | PASS, 0 changed |
| Existing SQL migrations modified | PASS, 0; exactly 2 forward migrations added |
| Final Docker residual audit | PASS, all Round 5 and Task17 ownership-label counts are 0 |

The first Task17 contract run was 12/13 because one unchanged `pwsh` process
exceeded its two-second fail-closed assertion. The exact failing teardown test
then passed 5/5 focused repetitions and the complete contract passed 13/13;
there is no stable regression evidence, and no unrelated teardown code was
changed.

Round 5 product commits:

1. `f63a91f` `fix(instances): bridge historical validation target outcomes`
2. `3b8d306` `fix(jobs): fence terminal reconciliation claims`
3. `d25e8fb` `fix(instances): accept agreeing historical job evidence`

The dedicated PostgreSQL container
`dbpilot-final-remediation-r5-pg` was verified by exact full ID and
`dbpilot.owner=final-remediation-r5` before removal with its anonymous volume;
the final Round 5 PostgreSQL residual count is zero.

## Post-review closure

Status: **DONE** on product HEAD `b13df20`. The final review's two functional
findings were reproduced and closed before integration.

1. The still-unreleased Round 5 migration
   `0007b_validation_target_outbox_bridge.sql` now compares effective winners:
   raw `rejected` is equivalent to a failed target for conflict detection, but
   the stored Command remains `rejected`. The production migration regression
   proves `0008` retains the fixed `command_rejected` target evidence.
2. New post-`0010` forward migration
   `0011_applied_validation_target_repair.sql` repairs deployments that already
   recorded Job `0008`/`0009` and database-instance `0006`. From the trusted
   terminal target it atomically aligns the Job, raw Command status/phase,
   target descriptor, generic reconcile state, pending command Audit
   descriptor, validation projection, and managed-instance projection before
   dispatcher workers start. It runs only when the already-applied
   database-instance correlation/quarantine columns exist; earlier or new
   schemas remain owned by the original ordered migrations.

The migration fails startup only for an irreparably polluted state where an
append-only Audit event already persists semantics opposite to the trusted
target. This includes the crash window where `audit_events` was written but
the Outbox recorded marker was not. Unrecorded opposite descriptors are
repaired automatically and do not block startup.

Strict TDD evidence:

- RED: failed target plus raw `rejected` was rewritten to `failed`;
- GREEN: raw `rejected` and `command_rejected` survive the real PostgreSQL
  production migration sequence;
- RED: an already-applied opposite descriptor caused the dispatcher to project
  the wrong validation outcome and generic reconciliation conflict, while a
  recorded opposite Audit was accepted;
- GREEN: unrecorded evidence converges through the real dispatcher/reconciler;
  recorded opposite Audit and event-without-marker both fail closed on every
  restart without partial repair; a matching recorded Audit permits the
  remaining state to be repaired while retaining its recorded marker.

Final gates:

| Gate | Result |
| --- | --- |
| Full Job PostgreSQL suite | PASS, 18.177s |
| Full database-instance PostgreSQL suite | PASS, 36.300s |
| `go test ./... -count=1` | PASS |
| `go vet ./...` | PASS |
| Task17 static lifecycle contract | PASS, 13/13 |

Kylin full-stack was not rerun for this closure: on a fresh full-stack database
the Job migrations run before database-instance tables exist, so `0011` is a
deliberate no-op and the changed branch is unreachable. The earlier Round 5
Kylin full-stack and exact cleanup remain the relevant evidence; the fresh
Task17 static contract confirms the topology and teardown paths are unchanged.

Post-review product commits:

1. `7dd9d5f` `fix(instances): preserve historical command rejection`
2. `dc8ac1e` `fix(instances): repair applied validation terminal evidence`
3. `b13df20` `fix(instances): repair matching recorded audit state`

## Final acceptance fix

Status: **DONE** on product HEAD `7c18d8f`.

Migration `0011_applied_validation_target_repair.sql` now classifies every
existing terminal command Audit family by terminal semantics and its published
detail shape: runtime `command.result`, rejected `command.acknowledged`,
delivery/prepared/execution timeouts, cancellation paths, historical recovery,
and database-instance validation events. A semantically matching append-only
event remains byte-for-byte authoritative for action, dedupe key and detail;
the migration reconstructs the Outbox recorded marker from that event and the
dispatcher does not append a second terminal Audit. Only an action/result/shape
that contradicts the trusted terminal target fails startup.

Reviewer four-cell PostgreSQL matrix:

| Cell | Result |
| --- | --- |
| runtime success event, marker null | PASS; original event retained, marker rebuilt, no second `command.result` |
| matching rejected acknowledgement, marker null | PASS; `command.acknowledged` action/dedupe/detail retained, no second acknowledgement |
| opposite acknowledgement, marker null | PASS; deterministic fail-closed |
| wrong database-instance validation action/result | PASS; deterministic fail-closed |

Final acceptance gates:

| Gate | Result |
| --- | --- |
| Full Job PostgreSQL suite | PASS, 17.853s |
| Full database-instance PostgreSQL suite | PASS, 40.191s |
| `go test ./... -count=1` | PASS |
| `go vet ./...` | PASS |
| Task17 static lifecycle contract | PASS, 13/13 |

Kylin full-stack was not rerun because this acceptance change is confined to
the already-applied historical-data branch of `0011`; a fresh full-stack
database still records `0011` as a deliberate no-op before database-instance
tables exist. No runtime topology, Agent, plugin, browser, or teardown path
changed.

Acceptance commit: `7c18d8f` `fix(instances): preserve matching terminal audit evidence`.
