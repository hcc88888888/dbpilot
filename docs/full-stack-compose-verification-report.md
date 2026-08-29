# Full-stack Compose verification report

## Outcome

DBPilot's complete Compose acceptance passed on 2026-08-30 (Asia/Shanghai) from
branch `codex/full-stack-acceptance`. The final live verifier used production
control-plane and Agent binaries built with repository-local Go 1.27.0 and ran
them in the exact Kylin V10 SP1 amd64 image. OIDC/browser, Agent mTLS,
telemetry, two-phase command delivery, partial host inspection, restart/spool
recovery, rogue identity rejection, PostgreSQL facts, Agent journal state and
exact cleanup all passed.

Proven functional corrections are committed as `80a55f0`
(`fix: pass full-stack compose acceptance`).

## Runtime identity

| Component | Version / platform | Local image identity |
| --- | --- | --- |
| Docker Engine | 29.7.2, linux/amd64 | n/a |
| Docker Compose | v5.3.1 | n/a |
| Go | go1.27.0 windows/amd64 | n/a |
| Node / npm | v24.14.1 / 11.11.0 | n/a |
| Kylin runtime | `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1`, linux/amd64 | `sha256:812c02a3bdeec0e0bf123e8eece79d69a6ae65a6bb0ca9993ed3965127b2d7f0` |
| Go builder | `golang:1.27.0-bookworm`, linux/amd64 | `sha256:ded31c68586d2e49e760acc2e65a884b23d032e9bbbed0ae0c55abd3fcaf4452` |
| PostgreSQL | `postgres:16-alpine`, linux/amd64 | `sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685` |
| Nginx | `nginx:1.29.1-alpine`, linux/amd64 | `sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8` |
| Playwright | `mcr.microsoft.com/playwright:v1.62.0-noble`, linux/amd64 | `sha256:baed2032d533817f3dbe6425de795788430ba345e819a1201337009ba17c9d07` |

Each listed image ID also matched its local repository digest. No tag was
substituted.

## Final live acceptance evidence

Command:

```powershell
powershell -NoProfile -File backend/scripts/verify-full-stack-compose.ps1 `
  -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' `
  -Architecture amd64 `
  -GoBinary 'D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe'
```

Verifier run label: `2abf60b3b4bb47198537195f61a1a9e8`.

The allowlisted success summary was emitted only after the replay, journal and
final database assertions passed:

| Fact | Validated value |
| --- | --- |
| Inspection Run | `inspection-run-72037355b1636d85c3a79354b4638c7f` |
| Job | `inspection-ce6c7ab3e0cb14555ce16bbb7cbef3f0` |
| Online Command | `inspection-10762d09102d4aca8b1ede2fb0194986` |
| Offline Command | `inspection-e0d59898dd99e0ff2e130388c2100684` |
| Report | `inspection-report-inspection-run-72037355b1636d85c3a79354b4638c7f` |
| Counts | targets=2, findings=13, reports=1, artifacts=2, audits=4 |
| Control-plane stopped | `2026-08-29T20:36:39.260Z` |
| Control-plane restarted | `2026-08-29T20:36:51.604Z` |

The Run was `partial`: the online target succeeded with 13 complete Findings;
the offline target failed with the stable `agent_offline` code and no forged
Finding. The online command completed through Prepare, Start, Result and
ResultAck; the stopped-Agent journal contained the same terminal reported
Command and no pending Result. The restart phase proved a real AgentControl
Heartbeat and an authenticated metric timestamp both advanced, an outage batch
was accepted after restart, and the stopped-Agent spool drained without
duplicate logical facts.

All required fixed phase markers were present, in order:

```text
OIDC acceptance passed
Agent mTLS communication passed
Host inspection browser acceptance passed
Control-plane restart and spool recovery passed
Rogue Agent rejection passed
Database and journal assertions passed
Full-stack cleanup audit passed
```

### Negative authentication

- The untrusted production Agent exited non-zero with the verifier's exact
  allowlisted TLS client-certificate rejection evidence.
- The trusted-certificate/claimed-ID mismatch exited non-zero with exact gRPC
  `PermissionDenied` SPIFFE/Hello mismatch evidence.
- Both rogue identities remained authoritatively offline and created zero
  registry mappings, metric rows, target runs, commands or audit rows.
- Browser wrong-audience and expired tokens returned 401; the missing-permission
  token returned 403; none fell back to demo data.

No raw rogue log, JWT, credential, private key, database password, complete DSN,
log body, evidence value or signature is retained in this report.

## Regression and production gates

| Gate | Result |
| --- | --- |
| `npm run contracts:lint` | PASS; one known `info.license` warning |
| `npm run contracts:breaking` | PASS |
| `npm run contracts:verify` with repo Go 1.27 on `PATH` | PASS; generated output has zero drift |
| `node --test` | PASS: 359 total, 357 passed, 2 intentional opt-in skips, 0 failed |
| `go test ./... -count=1` | PASS for every backend package |
| `go vet ./...` | PASS |
| `docker compose -f backend/docker/full-stack/docker-compose.yml config --quiet` | PASS |
| Three-file Compose/communication/container-safety gate | PASS: 55 total, 54 passed, 1 intentional clean-cache skip, 0 failed |
| `verify-inspection-postgres.ps1` | PASS; built-ins sampled=18, hydrated=9, findings=13 |
| `verify-contract-foundation.ps1` | PASS; Node 357/355/2/0, Go/vet, PostgreSQL E2E, Linux builds and exact cleanup |
| `verify-kylin-docker.ps1` with the exact Kylin image | PASS; production binaries, protocol, host snapshot, journal, policy and Artifact readiness |
| PowerShell AST parse | PASS in PowerShell 7 and Windows PowerShell 5.1 |
| `git diff --check` / staged diff check | PASS; only platform line-ending notices |

The first bare final `contracts:verify` invocation could not locate `go` because
the repository-local toolchain directory was not on that shell's `PATH`.
Prepending the required repository Go 1.27 directory produced the passing result
above; this was an environment invocation error, not contract drift.

## Cleanup and residual audit

The final live verifier reported:

```text
containers=19 networks=3 volumes=10 temporary_directory=removed
```

Independent final label queries found zero verifier containers, networks and
volumes, and the repository contained zero `.tmp-*` verifier directories. One
fake-Docker directory left by an interrupted Task 6 test was removed by exact
validated path; an older unrelated fake-test directory was preserved. The dirty
main checkout was not touched.

## Deferred technical debt

| Affected module | Trigger conditions | Functional impact | Severity | Recommended remediation stage |
| --- | --- | --- | --- | --- |
| Frontend npm dependencies | Running `npm audit` during foundation setup | No current workflow failure; 16 moderate and 1 high advisory remain | Medium | Consolidated dependency-hardening cycle before production rollout |
| OpenAPI metadata | Running Redocly lint | No API/runtime or generated-client failure; `info.license` is absent | Low | Documentation cleanup before external API publication |
| Full-stack runner images | Repeated verifier runs create unique Compose runner tags | No acceptance correctness impact; 42 exact runner tags currently consume image metadata/storage | Minor | Add exact run-owned image removal before making the live gate routine; never prune or wildcard-delete |
| Formal deployment boundaries | Production release outside the isolated Compose acceptance network | Compose does not prove frontend PKCE, PostgreSQL TLS, external secret management, HA/load/soak, or Kylin VM/bare-metal system integration | Medium | Execute the separate documented release gates before production rollout |
