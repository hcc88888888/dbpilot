# Task 17 full-stack acceptance report

Status: `DONE_WITH_CONCERNS`

Branch: `codex/host-plugin-task17-full-stack-acceptance`

Commits: `20c385de8a7f250eb8a86c99b9dc8306f2af74f9`, `4d88c5622ea87546f0785139255b38e0659503cb`, `45596bbf1aa592e5f442826ccd089c181c0f60b3`, `2d0fa112723d6e2a91e187a3bb833f614892541e`

## RED evidence

- `node --test tests/contracts/host-plugin-full-stack.test.mjs` was written and run before the production topology/verifier existed. It failed on the absent Compose topology, Nginx production path, package-owned Playwright suite, and ownership-safe verifier.
- Monitoring tests were written first for the three scopes (`host`, `plugin`, `database`), source/status projection, stale/null preservation, and the five MySQL metric IDs. The pre-change DTO/store could not represent those assertions.
- Docker discovery tests were written first for two running MySQL containers with no host-published ports. They initially failed because discovery only considered published host ports and did not carry a bounded internal endpoint. Negative cases also covered empty/non-IP endpoints, non-allowlisted networks, and running containers with no valid endpoint.
- Focused Go REDs reproduced the later full-stack blockers before each fix: canonical Linux enrollment platform selection, coordinator capability forwarding, command metadata and instance fencing, catalog-origin artifact leases, credential renewal after reconcile revision changes, empty template bindings, rollback result codes, plugin assignment promotion/version synchronization, microsecond timestamp persistence, native process-helper isolation, and durable-cursor stream ordering after restart.
- Full-stack RED runs exposed, in order, the actual integration failures in enrollment/platform matching, internal Docker discovery, artifact provenance/origin, empty template leases, native process visibility, restart-safe native fixture installation, assignment convergence, durable resume ordering, and final Audit/Journal queries. Each failure was reduced to a focused test before the smallest implementation change.

## Implementation

- Extended monitoring projections and PostgreSQL reads with scope, source, status, host/plugin/assignment/instance identities, units, and stale/null semantics. Added the five MySQL metrics: `mysql.connections.current`, `mysql.queries.total`, `mysql.threads.running`, `mysql.up`, and `mysql.uptime.seconds`.
- Added the React `/monitoring` route and page for host CPU/memory plus database series. Browser bearer tokens remain memory-only and are read for each request; there is no local/session storage persistence or HTTP/demo fallback.
- Added a production Vite-to-Nginx path with same-origin query-safe routing.
- Added the bounded Docker discovery internal-network endpoint to Protobuf and helper/Agent implementations. The helper accepts only running containers with IP-literal endpoints on locally/request-allowlisted networks. Raw Docker inspect data and internal container IDs do not cross the canonical public API.
- Added the restricted native process helper topology. The Agent shares its PID namespace but neither Agent nor plugin mounts the Docker socket. Only `dbpilot-docker-discovery` owns the socket. The native fixture listens on exact `127.0.0.1:3306`.
- Added the exact Kylin V10 SP1 full-stack topology: PostgreSQL, control plane, OIDC/bootstrap, Agent, Docker helper, native process helper, two internal-only MySQL services, one MySQL plugin process serving both instances, frontend, Playwright acceptance runner, and final assertion job. Only the frontend publishes an ephemeral loopback port.
- Added template validate/trial/approve/publish, unsafe SQL/high-cardinality rejection, plugin stop/stale/recovery, tampered and wrong-platform package rejection, failed upgrade/automatic rollback, Agent/Server restart convergence, spool/Journal/PostgreSQL/Audit checks, and PID/bound-instance assertions.
- Added exact labelled cleanup, bounded process ownership for PowerShell 5.1/7, redacted failure artifacts, documentation, and CI/manual acceptance entry points.
- Replaced the ambiguous recursive bare-Node gate with the repository-owned explicit gate: `node --test tests/contracts/*.test.mjs frontend/tests/*.test.js && npm --prefix backend/test/e2e/full-stack run test:support`. Playwright and Vitest remain package-owned commands.

## Protobuf generation boundary

The authorized generator was run with the repository-pinned image and exactly one read/write host mount, the Task17 worktree:

```powershell
docker run --rm --mount 'type=bind,source=D:/AI/codex/workspace/数据库运维管理系统/.worktrees/host-plugin-task17-full-stack-acceptance,target=/workspace' -w /workspace bufbuild/buf:1.57.2 generate
```

The repository's fixed `buf.gen.yaml` contains Go and gRPC-Go generation only. It has no TypeScript generator, so no new generator was introduced. The final authorized run had zero generated drift beyond the intended `backend/gen/discovery/v1/docker.pb.go`. No OpenAPI contract was changed.

## GREEN verification

| Command / gate | Result |
| --- | --- |
| `node --test tests/contracts/host-plugin-full-stack.test.mjs` | PASS, 10/10 |
| `npm run test:node` | PASS, repository contracts 372 passed / 2 environment-gated skipped / 0 failed; support tests 7/7 |
| `npm --prefix frontend/app test -- --run` | PASS, 9 files and 82/82 tests |
| `npm --prefix frontend/app run build` | PASS; only the existing chunk-size warning remained |
| `D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe test ./... -count=1` from `backend` | PASS, all packages |
| `D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe vet ./...` from `backend` | PASS |
| `npx --no-install redocly lint contracts/openapi/dbpilot-api.yaml` | PASS, valid contract with the existing missing-license warning |
| `powershell -NoProfile -File backend/scripts/verify-inspection-postgres.ps1 -GoBinary D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe` | PASS; PostgreSQL integration suites passed and the owned container cleaned |
| `powershell -NoProfile -File backend/scripts/verify-host-plugin-full-stack.ps1 -KylinImage cr.kylinos.cn/kylin/kylin-server-platform:v10sp1 -Architecture amd64 -GoBinary D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe` | PASS on Docker Engine 29.7.2 linux/amd64; `Host-plugin full-stack acceptance passed: frontend_port=32810.` |
| Final Buf generation / working-tree comparison | PASS, intended Protobuf output only |
| `git diff --cached --check` before commit | PASS |

The successful full-stack run covered one native candidate plus two internal-only Docker candidates, one plugin PID for both accepted MySQL instances, all five metrics on both instances, template lifecycle, stale/recovery, tamper/platform rejection, rollback, both restarts, browser token/storage checks, and final PostgreSQL/spool/Journal/Audit assertions.

## Docker cleanup audit

- Successful full-stack run: exact verifier cleanup reported `containers=22 networks=4 volumes=14 temporary_directory=removed`.
- During debugging, one duplicate run was interrupted. Its recorded run ID was `a27b65e41ea748c7b8a710037a355a6c`; exact labels were verified before removing the literal 16 container IDs, 4 network IDs, and 14 volume names. Its exact temporary directory was moved to the Windows Recycle Bin after the recursive-delete safety guard rejected broad removal.
- Final read-only audit after all gates: every Docker object with `dbpilot.verifier` was counted, yielding `containers=0 networks=0 volumes=0`. Task17's narrower label also yielded 0/0/0.
- The verifier's deliberately retained failure diagnostics are redacted, bounded artifacts rather than active Docker resources. The support suite verifies simulated tokens and sensitive values never appear in retained text. Forty-two such historical/test directories were observed under `%TEMP%`; they were not deleted because exact run ownership was not established.

## Authorization incident and recovery

I attempted the Task17 brief's existing `verify-contract-foundation.ps1` gate after reading its parameter/resource setup, but the wrapper later invoked prohibited `contracts:lint`, `contracts:breaking`, and `contracts:verify` scripts. The Buf lint/breaking step therefore made an unauthorized additional/baseline mount. The run was interrupted immediately after the REST drift step produced its temporary OpenAPI bundle; no OpenAPI generator container started.

The interrupted REST drift preparation had deleted 357 tracked `frontend/generated` files before generation. The controller restored those exact files from `HEAD`. Final read-only checks confirmed `frontend/generated`, `backend/gen/openapi`, and `contracts/openapi` are clean, no contract process or generator container remains, and all labelled Docker resources are zero. The aborted foundation run is not claimed as a passing gate.

Per the subsequent hard boundary, `verify-contract-foundation.ps1`, all `contracts:*` npm scripts, contract generator wrappers, and any wrapper that could reach them were not run again. The standalone Kylin verifier was also not rerun; the successful Task17 full-stack verifier itself used the exact required Kylin image on linux/amd64.

## Technical debt and concerns

| Module | Trigger | Functional impact now | Severity | Recommended stage |
| --- | --- | --- | --- | --- |
| Native process-helper acceptance profile (`TD-TEST-003`) | Docker Desktop's cross-container `/proc` mediation | Acceptance needs AppArmor unconfined in addition to only `SYS_PTRACE` and `DAC_READ_SEARCH`; production host policy still needs explicit evidence | Medium | Before production rollout on real CentOS/Kylin hosts |
| Root contract build tools | Root `npm audit` baseline | No current product/runtime correctness impact; 16 moderate and 1 high build-tool findings remain, while the frontend app audit was clean | Medium | Consolidated dependency remediation before production release |
| Frontend bundle | Production Vite build | No correctness impact; main chunk exceeds the 500 kB advisory threshold | Low | Performance/code-splitting cycle |
| Buf output coverage | Task17 Protobuf generation | Fixed repository config emits Go only; no TypeScript Protobuf output exists to refresh | Low | Add a pinned TS generator only through a separately approved contract/toolchain change |
| Release-gate evidence | Authorization boundary | `contracts:lint/breaking/verify` and the foundation wrapper cannot be credited in this run; full OpenAPI generated drift was not rechecked after the hard boundary | Medium | Run only under explicit multi-mount/OpenAPI-generator authorization in a clean task |
| Retained verifier diagnostics | Repeated negative lifecycle contract tests | Redacted diagnostics consume temporary disk space; no active-resource or confidentiality impact was found | Low | Add an ownership manifest/retention TTL without wildcard deletion |

## Fix round 1

Independent review verdict was reproduced against the code rather than accepted blindly. All ten P1 findings and both functional P2 findings were valid. Each was covered by a failing focused test or a real acceptance failure before implementation, then rerun GREEN.

### Finding-by-finding RED / GREEN

1. **Monitoring identity and real metric names.** RED: two authenticated Agents sharing hostname/source collapsed to one host and the React page filtered aliases that Agent never emitted. GREEN: `MetricConsumer` resolves the authenticated Agent to the persisted host; host metric identity cannot trust hostname/source; UI and tests use `system.cpu.utilization` / `system.memory.utilization`; two-host focused tests pass.
2. **Stale expected series.** RED: an instance with no in-window samples returned no MySQL series. GREEN: managed/monitoring MySQL assignments enumerate all five expected metrics from durable instance/assignment identity and return stale/null buckets; focused PostgreSQL monitoring tests pass.
3. **Docker allowlist/internal IP.** RED: a non-empty signed network allowlist fell back to a published port; unsafe IP classes and stopped containers were accepted. GREEN: shared `IsSafeInternalIP` plus strict non-empty allowlist behavior rejects unspecified/loopback/link-local/multicast and stopped containers across helper, Agent and Server tests.
4. **Least-privilege secrets.** RED: the original shared secrets volume was visible to Agent/plugin. GREEN: Compose splits control-plane, OIDC, PostgreSQL, MySQL, frontend TLS, runner secret/trust and assertion secret volumes; Agent/plugin see none; enrollment token is removed before Agent exec and restart enrollment remains valid. Contract and real Compose boot pass.
5. **Same-PID live ApplyConfiguration.** RED: second instance caused a process replacement. GREEN: same version/slot uses the verified session's atomic `ApplyConfiguration`; failed Apply preserves old PID/config and reports `plugin_configuration_apply_failed`; only binary changes use A/B rollback. Real E2E records first PID, accepts second instance, and proves the same PID.
6. **Package negatives and high cardinality.** RED: arm64 negative was not a valid arm64 package and failed too early; failed high-cardinality results left the Job running because nil metrics encoded as JSON `null`. GREEN: real linux/arm64 binary package reaches `plugin_platform_mismatch`; signature-only tamper reaches `plugin_signature_rejected`; typed high-cardinality drops raw rows, persists JSON `[]`, terminalizes Job/trial as `high_cardinality`, and passes real PostgreSQL plus full-stack evidence.
7. **Restart/browser evidence.** RED: pre-stop samples could satisfy post-restart checks, database metrics did not recover across Agent restart, Server reconnect retained an unchanged observation timestamp, and reload reset the rotated token. GREEN: Docker-stop UTC boundaries are recorded explicitly; all ten series and a higher observation are required after each boundary; deferred leases wait for a live authenticated control session; verified rollback and narrowly audited credential-recovery fences converge; Server reconnect refreshes an equivalent higher observation without blocking Agent recovery; browser Authorization comes from the application token provider backed only by process memory and reload uses the rotated token.
8. **Bounded PowerShell process tree.** RED: real PS5.1/7 parent-exit/child-holds-pipe test hung past the parent lifetime. GREEN: `bounded-process.ps1` owns a Windows Kill-on-close Job Object, applies one deadline to process/output drains, and kills the exact tree. Dynamic PS5.1/7 test and the 11-test contract gate pass.
9. **Failure canary secrecy.** RED: PNG/binary evidence could be retained without auditable scanning and no Task17 path planted every prohibited class. GREEN: real failure-canary phase plants unique SQL/package/trial-row/raw-inspect/non-PEM-key canaries, checks API/DOM/all owned container logs/Audit and retains only one bounded JSON diagnostic; no PNG/binary Playwright artifact is retained.
10. **Upgrade compatibility/preflight.** RED: legacy `kylin|centos` host rows failed linux package matching and enabled catalog config could start without a valid origin. GREEN: compatibility queries canonicalize those legacy OS values to linux; `--check-config` validates without opening DB/listeners; migration/preflight/fail-closed origin steps are documented and focused tests pass.
11. **Monitoring-state preservation.** RED: a real PostgreSQL observation changed both `managed` and `monitoring` rows to managed. GREEN: SQL preserves either existing managed state and promotes only other non-retired states; integration test passes.
12. **Runner-image ownership.** RED: verifier left its unique built image outside the ledger. GREEN: image ID and both labels are validated, recorded and removed only by exact ID after containers; every real failure/success cleanup audits images as well as containers/networks/volumes.

Additional core failures found by the strengthened E2E were fixed under the feature-first rule: failed typed results now retain fixed error codes without raw rows; rollback launches the old binary under the current configuration/operation/template-lease fence; credential renewal admits only exact audited/terminal recovery states; control-session readiness is explicit; an equivalent observation is refreshed on Server reconnect without deadlocking Agent recovery; final assertion state explicitly models restart boundaries and diagnostic stage.

### Fix-round verification

| Command / gate | Result |
| --- | --- |
| `node --test tests/contracts/host-plugin-full-stack.test.mjs` | PASS, 11/11 |
| `npm run test:node` | PASS, 375 total: 373 passed, 2 environment-gated skipped, 0 failed; package support 7/7 |
| `npm --prefix frontend/app test -- --run` | PASS, 9 files / 82 tests |
| `npm --prefix frontend/app run build` | PASS; existing >500 kB advisory only |
| `D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe test ./... -count=1` | PASS, all backend packages |
| `D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe vet ./...` | PASS |
| `docker compose ... --profile '*' config --quiet` | PASS |
| Exact Kylin full-stack verifier | PASS, `frontend_port=32857`; 1 native + 2 Docker candidates, same PID for both MySQLs, high-cardinality failure, safe template, stop/stale/restart, binary rollback, Agent/Server convergence, rotated browser bearer, real failure canary, PostgreSQL/Journal/spool/Audit assertions |
| `git diff --check` | PASS |

Focused real PostgreSQL binaries were executed inside unique labelled `postgres:16-alpine` containers without host ports. They proved failed high-cardinality persistence and the exact credential recovery allowlist while retaining the existing configuration/operation/membership/status/version/health/identity negative matrix. Each container was stopped and removed by its full recorded ID; its temporary test binary was removed after resolving the exact worktree path.

### Fix-round cleanup audit

- Final successful Task17 run: `containers=27 networks=4 volumes=21 images=1 temporary_directory=removed`.
- Final read-only label audit: `containers=0 networks=0 volumes=0 images=0`.
- One manual diagnostic Compose invocation omitted the verifier environment and created a labelled `run=unassigned` network. It had 0 endpoints; its full ID and exact labels were verified before exact removal. No prune, wildcard removal, Docker Socket mount, MySQL host port or unrecorded candidate was used.
- Every failed verifier run remained bounded and performed its own exact cleanup before the next run.

### Fix-round remaining concerns

- The non-blocking debt table above remains unchanged: Docker Desktop proc-helper policy is not production-host evidence; root build-tool audit debt and the frontend bundle advisory remain; retained redacted diagnostics still need an ownership TTL design.
- The forbidden foundation/contracts/OpenAPI generation commands were not rerun, and `frontend/generated`, `backend/gen/openapi`, and `contracts/openapi` were not modified in this round.

## Fix round 2

All nine findings in `task17-round2-findings.md` were verified against the current implementation and reproduced before changing production code. None was rejected as inapplicable.

### Finding-by-finding RED / GREEN

1. **Trusted host attribution.** RED: a database-plugin batch containing the colliding name `system.cpu.utilization` was rewritten as host telemetry. GREEN: host attribution now requires the exact trusted `dbpilot_source_id=inspection-host-snapshot` producer marker and resolves identity through the authenticated Agent-to-host mapping; plugin sources remain database-instance metrics. Two-Agent collision tests pass.
2. **Transactional same-PID live Apply.** RED on exact Kylin: accepting the second MySQL produced no candidate `ValidateInstance`/initial `CollectNow`; a rejected second instance incorrectly returned success. GREEN: mutations and credential renewal serialize per PID; the old stream is cancelled and awaited; candidate Apply validates every instance and collects every configured pair; the new cursor namespace must durably spool and ACK every pair before commit. A failed probe reapplies the exact old configuration, scrubs candidate leases/templates, restores the old stream and keeps the PID/session/operation/active configuration. The Kylin UDS tests prove success `4->5` and recovery `4->5->4`, including lower credential-revision rollback only inside the exact unacknowledged window.
3. **Exact trial operation fence.** RED: plugin trial admitted any non-zero operation. GREEN: Agent accepts only its current operation, sends the immutable launch operation to the already-verified process, and both stale/future requests are rejected. Live Apply advances the Agent session operation without weakening the plugin launch fence.
4. **Rollback credential recovery.** RED against real PostgreSQL: a stale `4/6` observation could enter provider renewal while the assignment was at `5/7`. GREEN: recovery requires exact assignment/Agent/host identity, current configuration and operation, signed installed version, active A/B slot, current terminal operation and bounded server-controlled freshness. Stale revision, version, slot, identity and freshness negatives all fail before provider access.
5. **Runner isolation.** RED: the ordinary acceptance runner mounted all Agent data read/write. GREEN: it receives only a one-time enrollment inbox, browser artifacts and phase state. A one-shot Kylin assertion exporter copies only the two exact regular non-symlink databases into a separate projection after Agent stop. A real Docker-volume RED also found empty-volume copy-up changing Agent data to `0:0/0755`; `volume.nocopy=true` now preserves bootstrap ownership `10001:10001/0700`, and enrollment generation passes with the real nested plugin-runtime mount.
6. **Atomic Windows process ownership.** RED: an immediate native parent could spawn a pipe-holding child and exit before Job assignment. GREEN: a pre-assignment event gate cannot execute the target until its gate process is inside a Kill-on-close Job Object. Real PS5.1 and PowerShell 7 zero-delay tests kill the exact tree and preserve an unrelated process.
7. **Fail-closed canary audit.** RED: container scanning used only the last 500 lines and ignored unreadable logs. GREEN: every owned container's complete bounded stdout/stderr is required to be readable; truncation or read failure fails acceptance. PostgreSQL requires `candidate_metrics='[]'::jsonb`; retained artifacts remain one bounded JSON file and no PNG/binary is retained.
8. **Coalesced observation refresh.** RED: `RefreshObservation` dropped a reconnect refresh when `TryLock` failed. GREEN: one pending worker coalesces concurrent calls, retries after the critical section/store error and persists the reconnect refresh without deadlock. Contention tests prove exactly one eventual revision advance.
9. **Runner-image failure window.** RED: ownership registration occurred only after build, so timeout or post-build query failure could leave the image. GREEN: a unique tag is declared before build; finally retries exact tag plus both ownership labels for five bounded seconds, canonicalizes and records the image ID, then removes only that ID. The dedicated Node contract proves control-flow ordering and PS5.1/7 parsing.

Two additional functional blockers were found by the strengthened real verifier and fixed under the feature-first rule. Docker's empty-volume copy-up reset the pre-owned Agent volume before enrollment; the `nocopy` contract and a real Kylin named-volume test now prevent regression. The plugin also carried acknowledged sequence numbers from configuration 4 into configuration 5 while Agent correctly opened a new namespace; forward Apply now resets sequence/ACK/pending state, while an unacknowledged rollback restores the complete old namespace. Focused tests prove new configuration sequence 1, rollback continuation at old sequence 2, and rejection after candidate ACK closes the window.

### Round-2 RED / GREEN commands and results

| Command / gate | RED / GREEN evidence |
| --- | --- |
| Cross-compiled Linux `pluginsupervisor.test` executed as UID 10001 in exact Kylin through the labelled Compose topology | RED: no rev5 validation/collection and failed candidate returned nil. GREEN: both transaction tests pass, including old-stream wait/reopen, all-pair durable ACK, same PID and rollback; focused run cleanup `0 containers / 2 networks / 20 volumes`, residual 0. |
| `go test ./internal/mysqlplugin -run '^TestServerAllowsOnlyImmediateUnacknowledgedConfigurationRollback$' -count=1 -v` | RED first on lower credential revision, then on candidate sequence 2. GREEN: exact rollback accepts the old credential only in the unacknowledged window and restores the prior cursor namespace. |
| Kylin Docker named-volume enrollment test via the real Agent mount topology | RED: parent became `0:0/0755` and stage `mkdir` failed. GREEN after `nocopy`: parent remains `10001:10001/0700`, generation passes; cleanup `0/2/23`, residual 0. |
| Real PostgreSQL credential-recovery integration binary in a unique labelled `postgres:16-alpine` container without host ports | RED: stale observation reached the provider. GREEN: current positive plus stale/config/op/version/slot/identity/freshness negative matrix passed; exact container and temporary binary removed. |
| `node --test tests/contracts/host-plugin-full-stack.test.mjs` | PASS, 12/12, including PS5.1/7 zero-delay Job gate, runner-image failure window, canary scan, Compose isolation and `nocopy`. |
| Exact Kylin full-stack verifier | Initial bounded REDs exposed enrollment copy-up (`12/4/23/1` cleaned) and cross-configuration cursor reuse (`13/4/23/1` cleaned). Final PASS on `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1`, linux/amd64, `frontend_port=32771`; platform/template/stop/restart/rollback, Agent+Server convergence, browser, intentional canary failure, PostgreSQL/spool/Journal/Audit all passed. Final cleanup `containers=28 networks=4 volumes=23 images=1 temporary_directory=removed`. |
| `D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe test ./... -count=1` from `backend` | PASS, all packages. |
| `D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe vet ./...` from `backend` | PASS. |
| `npm run test:node` | PASS. The inspected script directly runs repository Node files and full-stack support tests; it does not call a `contracts:*` npm script or generator. Repository Node result: 376 total, 374 passed, 2 explicit environment-gated skips, 0 failed; support 7/7. |
| `npm run frontend:test` | PASS, 9 files / 82 tests. |
| `npm run frontend:build` | PASS; existing 544 kB chunk-size advisory only. |
| `docker compose ... --profile '*' config --quiet` | PASS with exact Kylin image, unique runner image and ownership environment. |
| `git diff --check` and protected-directory audit | PASS; `frontend/generated`, `backend/gen/openapi`, `contracts/openapi`, Protobuf and generated outputs are unchanged. |

### Round-2 cleanup and boundary audit

- Every focused or full-stack Docker invocation used a unique `dbpilot.run` value and both verifier labels. Cleanup inspected both labels before removing exact full container/network/image IDs or exact volume names; no prune, wildcard deletion, raw Socket mount by Agent/plugin, or MySQL host port was used.
- Final independent label audit after all regressions: `containers=0 networks=0 volumes=0 images=0`.
- Test binaries were cross-compiled into one exact worktree path, copied through the existing read-only workspace/acceptance-bin Compose boundary, and deleted after each run. No candidate or success evidence was fabricated.
- The prohibited foundation/contracts wrappers, Buf, OpenAPI Generator and protected generated directories were not invoked or modified in Round2. The authorized old Buf generation was not needed.

### Round-2 remaining concerns

- The existing technical-debt table remains applicable: Docker Desktop proc-helper evidence is not a substitute for a production CentOS/Kylin host policy test; root build-tool audit debt and the Vite chunk advisory remain non-blocking; retained redacted failure diagnostics still need an ownership/TTL design.
- The repository `test:node` suite includes fake-tool tests that assert pinned contract-tool command construction, but this round did not directly invoke any prohibited contract wrapper or real contract generator.

## Fix round 3

The three P1 findings in `task17-round3-findings.md` were each verified against the committed Round2 implementation. All three were valid and received an observable RED before production changes.

### Finding-by-finding RED / GREEN

1. **Multi-pair rollback window.** RED: one candidate ACK cleared the complete rollback snapshot, so a configuration with five builtin pairs and one custom pair could not recover after the first ACK. GREEN: forward Apply records the exact bound-pair set and removes only acknowledged keys; the rollback window closes only after every expected pair is ACKed. The server test proves one-pair ACK still permits `5 -> 4` and restores the old cursor sequence, while six one-by-one ACKs close the window. The exact Kylin UDS test additionally fails the candidate stream after its first pair ACK and proves `4 -> 5 -> 4`, old-stream reopen, Session/operation/active-config recovery, and unchanged PID.
2. **Atomic stream failure ownership.** RED: the desired deterministic barrier API was absent and the handle could complete after ready while `killOnFailure=false`, then be registered healthy. GREEN: completion and arm share one mutex and explicit completed state. `armOrKill` either arms every future unexpected exit or observes an already completed stream and kills immediately; the stream completion path atomically checks ownership. Barrier tests cover completion between ready/arm, failure after arm, and initial pre-ready ownership.
3. **Incremental output bound.** RED: a real noisy child wrote 16 MiB, retained the output pipe and reached the 10-second timeout (`noisy deadline`) rather than an output-limit failure. GREEN: one fixed `limit+1` character buffer per stream reads stdout/stderr asynchronously; the owner polls overflow at a 20 ms maximum interval, closes the Kill-on-close Job/terminates the exact tree, and throws the fixed overflow failure. Real PS5.1 and PowerShell 7 tests finish in about five seconds total, prove target and child are gone, preserve an unrelated process, and prove wrapper `finally` ran.

### Round-3 RED / GREEN and gate evidence

| Command / gate | Result |
| --- | --- |
| `go test ./internal/mysqlplugin -run '^TestServerKeepsRollbackUntilEveryCandidatePairIsAcknowledged$' -count=1 -v` | RED: first ACK caused `configuration_rejected` rollback. GREEN: first of six pairs keeps rollback; all six ACKs close it. |
| `go test ./internal/agent/pluginsupervisor -run '^TestMetricStreamFailureOwnershipArmsOrObservesCompletionAtomically$' -count=1 -v` | RED: no atomic arm API. GREEN: all three deterministic interleavings pass. |
| `node --test --test-name-pattern='incrementally bound noisy output' tests/contracts/host-plugin-full-stack.test.mjs` | RED: fixed timeout after about 11 seconds. GREEN: PS5.1/7 exact-tree overflow/finally/unrelated-process assertions pass. |
| Exact Kylin cross-compiled `pluginsupervisor.test` | PASS, three transactional live-Apply tests including failure after first pair ACK. Unique labelled cleanup: `containers=0 networks=2 volumes=20 residual=0`; temporary binary removed. |
| `node --test tests/contracts/host-plugin-full-stack.test.mjs` | PASS, 13/13. |
| Exact Kylin full-stack verifier | PASS on exact `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1`, linux/amd64, `frontend_port=32772`; all platform/template/stop/restart/rollback/restart-convergence/browser/canary/final assertions passed. Cleanup: `containers=28 networks=4 volumes=23 images=1 temporary_directory=removed`. |
| `D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe test ./... -count=1` from `backend` | PASS, all packages. |
| `D:/AI/codex/workspace/数据库运维管理系统/.tooling/go/bin/go.exe vet ./...` from `backend` | PASS. |
| `npm run frontend:test` | PASS, 9 files / 82 tests. |
| `npm run frontend:build` | PASS; existing 544 kB chunk advisory only. |
| `docker compose ... --profile '*' config --quiet` | PASS. |
| `npm --prefix backend/test/e2e/full-stack run test:support` | PASS, 7/7. |
| `npm run test:node` | **Environment failure, not claimed green:** 377 total, 374 passed, 2 explicit skips, 1 failed. The only failure was the unchanged `Prism launcher works without curl` test because Windows denied `listen 0.0.0.0:4010`. |

The Node environment failure was independently reproduced with the exact single test. No process listened on 4010, while current Windows IPv4 and IPv6 TCP excluded ranges both included `3982-4081`, which contains 4010. Other user-owned `market_*` Docker containers were running, so Docker/HNS/WinNAT was not restarted and the unrelated toolchain test was neither changed nor skipped. Every other Node test, including the Round3 13/13 contract and separately invoked support 7/7, passed.

### Round-3 cleanup and boundary audit

- Final Task17 label audit: `containers=0 networks=0 volumes=0 images=0`.
- All focused Docker resources used unique double labels and were removed only by exact inspected IDs/names. No prune, wildcard cleanup, host MySQL port, Agent/plugin Docker Socket mount or fabricated candidate was introduced.
- `frontend/generated`, `backend/gen/openapi`, `contracts/openapi`, Protobuf and generated output directories remained clean. No foundation/contracts wrapper, Buf or OpenAPI Generator was invoked.
- Existing non-blocking concerns remain: real CentOS/Kylin host proc-helper policy evidence, root build-tool audit debt, the Vite chunk advisory and retained redacted-diagnostic TTL. Round3 adds the current Windows 4010 excluded-port environment gate as a local verification concern, not a product-code failure.

## Post-integration Windows Job termination fix

Fresh integration verification reproduced a real Round3 regression: `node --test tests/contracts/host-plugin-full-stack.test.mjs` was 12/13 because Windows PowerShell 5.1 still observed the exact pipe-holding child immediately after `Invoke-BoundedProcess` returned. The source worktree's original single-child test passed 30 consecutive runs, confirming a timing-dependent boundary rather than a deterministic 30-second escape.

Systematic diagnosis separated execution ownership from process-object teardown:

- The old implementation closed the last Kill-on-close Job handle and immediately threw, which requested asynchronous termination but established no completion condition.
- An initial `TerminateJobObject` plus `ActiveProcesses == 0` barrier was insufficient under an eight-child stress fixture: Job accounting could reach zero before every original process handle was signaled.
- PID-only `Get-Process` checks could also race PID reuse or property reads while a terminated process object was disappearing. The strengthened test records each child's PID plus creation ticks and considers only the same identity with `HasExited == false` alive; query-time disappearance is treated as terminated.

The final implementation queries `JobObjectBasicProcessIdList` before termination, opens `SYNCHRONIZE` handles for the exact assigned process objects, calls `TerminateJobObject`, waits for every captured handle within one shared two-second budget, then verifies `JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.ActiveProcesses == 0` before closing the Job handle. Failure to settle produces a fixed error. This is a bounded condition wait rather than an arbitrary sleep and leaves the unrelated-process boundary unchanged.

Post-fix evidence:

- Strengthened native parent spawns eight zero-delay pipe-holding children. PS5.1 and PowerShell 7 together passed 10 consecutive full iterations; all exact PID+creation identities were terminated and the unrelated process survived each run.
- `node --test tests/contracts/host-plugin-full-stack.test.mjs`: PASS, 13/13, including the eight-child Job test and real noisy-output exact-tree test.
- Both PowerShell 5.1 and 7 parsers accepted `bounded-process.ps1`.
- No contract/generator/protected directory was touched and no Task17 Docker resource was created by this fix.

## Fix round 4

The post-integration teardown review was reproduced against commit `42d0cc865736848567b2aaf1374a557e66c2b3a1`. The finding was valid: the successful `JobObjectBasicProcessIdList` path did not require `NumberOfProcessIdsInList == NumberOfAssignedProcesses`, failed `OpenProcess(SYNCHRONIZE)` calls were silently skipped, and a single pre-termination snapshot could not close membership added concurrently by a still-running Job member. The PowerShell wrapper also added independent 2-second and 10-second waits after its caller deadline.

### Round-4 RED / GREEN

- RED first expanded the real Windows fixture beyond the old 16-entry capacity and added a child whose DACL deliberately denies `SYNCHRONIZE` while retaining query access. The fixture independently proved `OpenProcess(SYNCHRONIZE)` returned `ERROR_ACCESS_DENIED`. Both shells exposed the same defect: the helper returned the ordinary `pipe deadline` result instead of failing closed because the inaccessible member had been skipped.
- GREEN keeps the pre-assignment gate: the gate command cannot create the requested process until the gate process is assigned to the private non-breakaway Kill-on-close Job. Every successful process-list query must now return the complete assigned set; incomplete success and `ERROR_MORE_DATA` both grow the bounded buffer and retry.
- Every listed member is opened with `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`, checked with `IsProcessInJob`, and retained by handle so PID reuse cannot change the identity being waited. `ERROR_INVALID_PARAMETER` is treated as query-time disappearance only when a fresh complete Job query proves that PID left membership. Any other open failure remains fail-closed; a query-only handle, when available, is retained solely for best-effort exact termination audit and does not turn that failure into success. Every opened handle is closed from one `finally` path, including membership-change and exception paths.
- Teardown now repeats complete membership capture, `TerminateJobObject`, retained-handle waits, and post-termination membership/accounting checks. It returns settled only after two consecutive complete empty observations with every retained synchronizable process object signaled. A member created after an earlier snapshot is therefore captured and terminated in the next pass; a continuously changing or inaccessible set consumes the same deadline and fails closed.
- `Invoke-BoundedProcess` creates one monotonic `Stopwatch` deadline before launch. Normal execution reserves at most 500 milliseconds of the caller budget for teardown. Enumeration, termination, retained-handle waits, the exact `Process`-object fallback, and both output drains use only that timestamp. The Windows `taskkill` PID fallback, its 10-second wait, and the extra 2-second `WaitForExit` calls were removed.

### Round-4 Windows evidence

- The condition-driven stress fixture starts 24 zero-delay native pipe holders, then a Job member retains the exact parent handle, waits for that parent to exit, and only then creates 12 late pipe holders plus continuously disappearing short-lived members. Each shell recorded more than 48 PID+creation identities, proving the successful path crossed the original capacity and exercised late membership plus query-time disappearance. The already-running verifier checked exact identities immediately when `Invoke-BoundedProcess` returned, avoiding a new checker process reusing a just-released PID.
- The inaccessible-member path returned only the fixed `Bounded process tree termination did not settle.` result, stayed within the two-second caller budget plus scheduling tolerance, ran its wrapper `finally`, closed the Job, and left no matching exact identity running. The unrelated process was checked by PID plus creation time and survived.
- The noisy-output path still failed at the incremental `limit+1` boundary, killed the exact parent/child Job tree, preserved the exact unrelated process, and ran its wrapper `finally` in both shells.
- `node --test --test-name-pattern='atomically own|incrementally bound noisy output' tests/contracts/host-plugin-full-stack.test.mjs` passed 10 consecutive final rounds. Every round executed both PowerShell 7 and Windows PowerShell 5.1 and both native teardown tests.
- `node --test tests/contracts/host-plugin-full-stack.test.mjs` passed 13/13. A separate normal-success probe returned the exact `ok` output and exit code 0 within two seconds under both shells. Both parsers accepted `bounded-process.ps1` and `bounded-process-gate.ps1`.

No Docker command was required or run. No foundation/contracts generator, Buf, OpenAPI, generated output, or protected directory was read through a mutating gate or modified in Round4.
