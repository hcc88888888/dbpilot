# DBPilot Full-Stack Docker Compose Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-cleaning Docker Compose environment that runs production DBPilot control plane and Agent binaries in Kylin V10 and proves browser OIDC, gRPC mTLS communication, telemetry, inspection, reports, restart recovery, rogue-certificate rejection, database state, and Agent journal consistency.

**Architecture:** A Go 1.27 builder produces static control-plane, Agent, and fixture binaries into Compose volumes. A bootstrap fixture generates ephemeral PKI, OIDC/JWKS material, signed policy, command keys, configs, and credentials; Kylin runtime containers use those assets with PostgreSQL, Nginx, and a pinned Playwright runner. One PowerShell verifier owns the Compose project, executes normal/fault/browser/database/journal phases, and removes only its recorded containers, networks, volumes, and temporary artifacts.

**Tech Stack:** Go 1.27.0, Docker Compose v2, PostgreSQL 16 Alpine, Kylin V10 SP1 amd64, gRPC/Protobuf mTLS, OIDC discovery/JWKS/RS256, Nginx 1.29.1 Alpine, Playwright 1.62.0 Noble, native JavaScript ES Modules, PowerShell 7, Node `node:test`.

**Spec:** `docs/superpowers/specs/2026-08-29-full-stack-compose-acceptance-design.md`

## Global Constraints

- Work only in the isolated `codex/full-stack-acceptance` worktree; do not modify the dirty `main` checkout.
- Use production `dbpilot-controlplane` and `dbpilot-agent` binaries; no mock control plane or Agent.
- Runtime control plane, valid Agent, rogue Agents, and fixture server use exact image `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1` on amd64.
- Build with exact `golang:1.27.0-bookworm`, non-login `/bin/sh -ec`, `CGO_ENABLED=0`, `GOOS=linux`, `GOARCH=amd64`, `GOAMD64=v1`.
- Browser runner and npm package are exactly Playwright 1.62.0 with image `mcr.microsoft.com/playwright:v1.62.0-noble`.
- Expose only Nginx through a Docker-assigned `127.0.0.1` ephemeral port; PostgreSQL, OIDC, control-plane HTTP/gRPC, and Agent remain internal.
- Browser-to-Nginx loopback HTTP is acceptance-only. Nginx-to-control-plane, control-plane-to-OIDC, and Agent-to-control-plane use TLS/mTLS with bootstrap CA verification.
- PostgreSQL remains internal with `sslmode=disable` for this acceptance environment; production PostgreSQL TLS is a separate release gate.
- Secrets and full JWTs never enter logs, DOM, screenshots, Compose config output, error messages, or Git-tracked files.
- Frontend token injection uses `window.DBPILOT_GET_ACCESS_TOKEN`; no PKCE/login implementation and no static token file.
- Existing explicit demo behavior remains only when no control-plane URL is configured; configured failures never fall back to demo.
- Use condition-based health/readiness polling with bounded timeouts; no fixed long sleeps.
- Every Docker resource has a unique project/ownership label and is removed only by recorded ID/label; never use `docker system prune` or broad name matching.
- Verification failure must still clean containers, networks, volumes, temporary keys, configs, logs, screenshots, and binaries unless explicitly copied as a redacted failure artifact.
- Preserve existing contract, Node, Go, PostgreSQL, foundation, HBase and Kylin verification behavior.
- Follow repository feature-first guidance: fix wrong communication, data, identity, command or cleanup behavior immediately; record non-blocking hardening separately.

## File Structure

### Fixture

- Create `backend/test/fixtures/fullstack/main.go` — subcommand entrypoint.
- Create `backend/test/fixtures/fullstack/bootstrap.go` — PKI, keys, policy, config, state generation.
- Create `backend/test/fixtures/fullstack/oidc.go` — HTTPS discovery/JWKS/token/health server.
- Create `backend/test/fixtures/fullstack/assertions.go` — scoped PostgreSQL and journal assertions.
- Create focused Go tests beside each file.

### Compose runtime

- Create `backend/docker/full-stack/docker-compose.yml` — one-shot builder/bootstrap plus runtime services.
- Create `backend/docker/full-stack/nginx.conf` — static UI, health, and verified HTTPS API proxy.
- Create `backend/docker/full-stack/README.md` — topology and non-production limitations.
- Create `backend/docker/full-stack/runner.Dockerfile` — pinned Playwright runner package installation.

### Browser runner

- Create `backend/test/e2e/full-stack/package.json` and `package-lock.json` with `@playwright/test@1.62.0`.
- Create `backend/test/e2e/full-stack/playwright.config.mjs`.
- Create `backend/test/e2e/full-stack/acceptance.spec.mjs`.
- Modify `frontend/app.js` and frontend tests to propagate `DBPILOT_GET_ACCESS_TOKEN` into inspection/report adapters.

### Orchestration and safety

- Create `backend/scripts/verify-full-stack-compose.ps1`.
- Create `tests/contracts/full-stack-container-safety.test.mjs`.
- Modify `.github/workflows/contracts.yml` only if a Docker-capable job can run the verifier without the private Kylin image; otherwise document it as a local/release gate and keep CI syntax validation only.
- Modify `README.md`, `backend/README.md`, and create `docs/full-stack-compose-acceptance.md`.

---

### Task 1: Build the Bootstrap and HTTPS OIDC Fixture

**Files:**
- Create: `backend/test/fixtures/fullstack/main.go`
- Create: `backend/test/fixtures/fullstack/bootstrap.go`
- Create: `backend/test/fixtures/fullstack/bootstrap_test.go`
- Create: `backend/test/fixtures/fullstack/oidc.go`
- Create: `backend/test/fixtures/fullstack/oidc_test.go`
- Create: `backend/test/fixtures/fullstack/assertions.go`
- Create: `backend/test/fixtures/fullstack/assertions_test.go`

**Interfaces:**
- Consumes: existing policy signing, control-plane configuration, OIDC claim structure, Agent journal schema and PostgreSQL inspection schema.
- Produces:

```go
type BootstrapOptions struct {
    Root string
    Issuer string
    Audience string
    TenantID string
    ProjectID string
    OnlineAgentID string
    OfflineAgentID string
    Now time.Time
    Random io.Reader
}

type BootstrapManifest struct {
    Issuer string `json:"issuer"`
    Audience string `json:"audience"`
    TenantID string `json:"tenant_id"`
    ProjectID string `json:"project_id"`
    OnlineAgentID string `json:"online_agent_id"`
    OfflineAgentID string `json:"offline_agent_id"`
    Files map[string]string `json:"files"`
}

func GenerateBootstrap(context.Context, BootstrapOptions) (BootstrapManifest, error)
func NewOIDCServer(OIDCConfig) (*http.Server, error)
func AssertDatabase(context.Context, *sql.DB, AssertionOptions) error
func AssertJournal(string, JournalAssertion) error
```

- [ ] **Step 1: Write failing deterministic bootstrap tests**

Assert one generated tree contains CA, HTTP/gRPC/OIDC/valid-Agent/mismatched-Agent/untrusted-Agent certs, OIDC RSA key/JWKS, command keys, execution key, Artifact key, signed policy, control-plane/Agent/OIDC configs and a non-secret manifest. Verify modes on Linux-compatible metadata, exact DNS/URI SANs, 15-minute token ceiling, no secret bytes in manifest, and rejection of relative/root/output-with-existing-files paths.

- [ ] **Step 2: Run bootstrap tests and verify RED**

Run: `Push-Location backend; go test ./test/fixtures/fullstack -run TestGenerateBootstrap -count=1 -v; Pop-Location`

Expected: FAIL because the fixture package does not exist.

- [ ] **Step 3: Implement bootstrap with standard-library crypto**

Use Ed25519 for the test CA, TLS certificates, command key and policy key; use RSA-2048/RS256 only for OIDC signing. Write each file through create-exclusive temporary files followed by fsync and rename inside the validated output root. The manifest contains paths and public IDs only; token endpoint credential and private keys are referenced by path, never embedded.

Generate control-plane inventory for `agent-online` and `agent-offline`, Agent policy with host metrics plus a bounded file-log source, database process allowlist containing `dbpilot-agent`, and exact scope `tenant-acceptance/project-acceptance`.

- [ ] **Step 4: Write failing OIDC behavior tests**

Using the generated CA and TLS server, assert discovery/JWKS fields, valid RS256 token claims, wrong-audience/expired/missing-permission variants, token credential rejection, HTTPS-only listener, bounded body/header sizes and redacted logs. Validate tokens with the production `controlplane.NewOIDCTokenVerifier`.

- [ ] **Step 5: Implement OIDC subcommand**

Expose only:

```text
GET  /.well-known/openid-configuration
GET  /jwks
GET  /healthz
POST /token
```

`/token` reads the credential from a 0600 file, accepts a closed `variant` enum, and returns JSON without logging token or credential. Bind `0.0.0.0:9444` inside the Compose network with TLS minimum 1.2.

- [ ] **Step 6: Write and implement database/journal assertion tests**

Database assertions use exact scope and explicit columns to require one Run, two TargetRuns/Commands, 13 online Findings, zero offline Findings, one Report, two Artifacts, Audit correlations, source/accepted timestamps and no duplicates. Journal assertion requires terminal ResultAck-reported command and zero pending Results. Redact DSNs and token bytes from every error.

- [ ] **Step 7: Run fixture tests and static checks**

Run:

```powershell
Push-Location backend
go test ./test/fixtures/fullstack -count=1 -v
go vet ./test/fixtures/fullstack
Pop-Location
```

Expected: PASS.

- [ ] **Step 8: Commit fixture**

```powershell
git add -- backend/test/fixtures/fullstack
git commit -m "test: add full-stack acceptance fixture"
```

### Task 2: Define the Production-Binary Compose Topology

**Files:**
- Create: `backend/docker/full-stack/docker-compose.yml`
- Create: `backend/docker/full-stack/nginx.conf`
- Create: `backend/docker/full-stack/runner.Dockerfile`
- Create: `backend/docker/full-stack/README.md`
- Create: `tests/contracts/full-stack-compose.test.mjs`
- Modify: `tests/contracts/container-safety.test.mjs`

**Interfaces:**
- Consumes: Task 1 fixture subcommands, repository source, exact image tags and existing control-plane/Agent CLIs.
- Produces: Compose services `asset-builder`, `bootstrap`, `postgres`, `oidc`, `controlplane`, `agent`, `frontend`, `acceptance-runner`, `rogue-untrusted`, `rogue-mismatch`, and `assertions`.

- [ ] **Step 1: Write failing Compose structure tests**

Parse `docker compose config --format json` and assert exact images/tags, production binaries, read-only source/runtime mounts, no privileged/cap-add/Docker socket, dedicated network, PostgreSQL without published ports, only frontend loopback ephemeral publication, health checks, dependency conditions, ownership labels, resource limits, `no-new-privileges`, dropped capabilities and read-only root filesystems where supported.

Assert builder command uses `/bin/sh -ec`, exact Go 1.27 variables, and builds all three binaries into a named volume. Assert runtime Kylin services verify OS/arch/version before exec.

- [ ] **Step 2: Run structure tests and verify RED**

Run: `node --test tests/contracts/full-stack-compose.test.mjs`

Expected: FAIL because Compose assets do not exist.

- [ ] **Step 3: Implement Compose services and volumes**

Use named volumes:

```text
acceptance-bin
acceptance-secrets
acceptance-config
acceptance-state
acceptance-artifacts
acceptance-agent-data
acceptance-runner-node-modules
acceptance-go-cache
```

PostgreSQL data uses tmpfs. Runtime binaries/config/secrets are read-only; only Artifact and Agent data volumes are writable by their service. Use service health conditions rather than sleep.

- [ ] **Step 4: Implement Nginx same-origin proxy**

Serve repository frontend read-only, expose `/healthz`, proxy `/api/` to `https://controlplane:8443`, verify hostname and bootstrap CA, disable proxy buffering for streamed/download responses, add safe size/time limits, and do not expose OIDC `/token` or secrets.

- [ ] **Step 5: Implement pinned Playwright runner image**

Use `mcr.microsoft.com/playwright:v1.62.0-noble`, copy only dedicated runner package files, run `npm ci --ignore-scripts`, switch to `pwuser`, and copy the acceptance test. Image/package versions must match exactly.

- [ ] **Step 6: Validate Compose and safety behavior**

Run:

```powershell
docker compose -f backend/docker/full-stack/docker-compose.yml config --quiet
node --test tests/contracts/full-stack-compose.test.mjs tests/contracts/container-safety.test.mjs
```

Expected: PASS without starting runtime services.

- [ ] **Step 7: Commit topology**

```powershell
git add -- backend/docker/full-stack tests/contracts/full-stack-compose.test.mjs tests/contracts/container-safety.test.mjs
git commit -m "test: define full-stack compose topology"
```

### Task 3: Add Frontend Token Injection and Browser Acceptance

**Files:**
- Modify: `frontend/app.js`
- Modify: `frontend/tests/inspection.test.js`
- Modify: `frontend/tests/reports.test.js`
- Create: `frontend/tests/auth-bootstrap.test.js`
- Create: `backend/test/e2e/full-stack/package.json`
- Create: `backend/test/e2e/full-stack/package-lock.json`
- Create: `backend/test/e2e/full-stack/playwright.config.mjs`
- Create: `backend/test/e2e/full-stack/acceptance.spec.mjs`

**Interfaces:**
- Consumes: existing `createInspectionApi({getAccessToken})`, report API, frontend factories, OIDC `/token`, Nginx same-origin `/api`.
- Produces:

```javascript
const getAccessToken = typeof window.DBPILOT_GET_ACCESS_TOKEN === 'function'
  ? window.DBPILOT_GET_ACCESS_TOKEN
  : async () => undefined;
```

The runner accepts `FRONTEND_URL`, `OIDC_URL`, `OIDC_CA_FILE`, `OIDC_CREDENTIAL_FILE`, tenant/project and expected IDs through environment variables.

- [ ] **Step 1: Write failing frontend bootstrap tests**

Assert configured inspection/report adapters receive and invoke the same token provider per request; missing token in configured mode produces fixed unauthenticated state; demo mode remains unchanged; tokens never enter DOM, toast, URL or console. Scope switch aborts requests while token refresh is pending.

- [ ] **Step 2: Run bootstrap tests and verify RED**

Run: `node --test frontend/tests/auth-bootstrap.test.js frontend/tests/inspection.test.js frontend/tests/reports.test.js`

Expected: FAIL because `app.js` does not propagate the provider.

- [ ] **Step 3: Implement narrow token-provider bootstrap**

Read the global function once at DOMContentLoaded and pass it only to adapters that support authenticated generated-client calls. Do not cache token values, read localStorage/sessionStorage, or infer authentication from a token string. Existing validated `DBPILOT_ALERT_CONTEXT` remains the source of scope and UI permissions.

- [ ] **Step 4: Create pinned runner package**

Dedicated package metadata contains exactly `@playwright/test: 1.62.0` and no postinstall script. Generate and commit its lockfile. Configure Chromium-only, one worker, no retries, screenshot/DOM attachment on failure, and disabled success trace/video.

- [ ] **Step 5: Write browser acceptance RED tests**

Test code obtains a short-lived valid token over HTTPS with bootstrap CA, injects `DBPILOT_CONTROL_PLANE_URL=location.origin`, token provider, authenticated scope and permissions before page scripts, then asserts:

- configured control-plane source, two targets and 13 items;
- label-only policy creation and ETag edit;
- immediate online/offline Run becomes partial;
- online target has 13 nonmissing/nonunsupported Findings;
- safe evidence, thresholds, target, Job, Command and Audit references;
- separate HTML and JSON downloads contain the same Run ID;
- missing-permission token yields fixed 403 and no demo fallback;
- wrong-audience and expired tokens yield 401.

- [ ] **Step 6: Run frontend unit tests**

Run: `node --test frontend/tests/*.test.js`

Expected: PASS; Playwright remains RED until full runtime exists.

- [ ] **Step 7: Commit frontend and runner**

```powershell
git add -- frontend/app.js frontend/tests backend/test/e2e/full-stack
git commit -m "test: add authenticated browser acceptance"
```

### Task 4: Add Communication Restart, Rogue-Agent, Database and Journal Phases

**Files:**
- Create: `backend/test/e2e/full-stack/communication.mjs`
- Modify: `backend/test/e2e/full-stack/acceptance.spec.mjs`
- Modify: `backend/test/fixtures/fullstack/assertions.go`
- Modify: `backend/test/fixtures/fullstack/assertions_test.go`
- Modify: `backend/docker/full-stack/docker-compose.yml`
- Create: `tests/contracts/full-stack-communication.test.mjs`

**Interfaces:**
- Consumes: running Compose project, production Agent/control plane, fixture assertion subcommands.
- Produces runner phase commands `normal`, `post-restart`, `unauthorized`; fixture assertions `database`, `journal`, and rogue service exit contracts.

- [ ] **Step 1: Write failing communication phase tests**

Use controlled fake process/Docker outputs to assert the orchestrator requires Hello/online host.v1 before browser work, records pre-restart accepted/spool counters, rejects an unchanged post-restart state, and fails if rogue Agent appears in inventory/data. Test error output redaction.

- [ ] **Step 2: Add normal and post-restart runner phases**

`normal` performs browser workflow and writes a non-secret phase state containing Run/Job/Command IDs, accepted timestamp and journal command ID. `post-restart` requires a newer authenticated accepted timestamp, Agent online/Heartbeat, unchanged terminal command identity and no duplicate Report/Finding/Audit rows.

- [ ] **Step 3: Add rogue Agent services**

`rogue-untrusted` uses an untrusted CA certificate and must fail TLS connection. `rogue-mismatch` uses a trusted certificate whose URI is `agent-certificate-id` but sends Hello `agent-claimed-id`; it must receive PermissionDenied. Both run production Agent binaries with isolated empty state volumes and bounded timeouts.

- [ ] **Step 4: Extend database and journal assertions**

Database assertion requires exact scope and IDs from the non-secret phase state. Journal assertion runs only after the valid Agent is stopped and requires the command completed/reported and no pending Result. Rogue assertions require zero rows/registry mappings for rogue IDs.

- [ ] **Step 5: Run focused fixture/communication tests**

Run:

```powershell
Push-Location backend
go test ./test/fixtures/fullstack -count=1 -v
Pop-Location
node --test tests/contracts/full-stack-communication.test.mjs
```

Expected: PASS without requiring a running Compose project.

- [ ] **Step 6: Commit communication scenarios**

```powershell
git add -- backend/test/fixtures/fullstack backend/test/e2e/full-stack backend/docker/full-stack/docker-compose.yml tests/contracts/full-stack-communication.test.mjs
git commit -m "test: cover full-stack agent communication recovery"
```

### Task 5: Build the Self-Cleaning PowerShell Verifier

**Files:**
- Create: `backend/scripts/verify-full-stack-compose.ps1`
- Create: `tests/contracts/full-stack-container-safety.test.mjs`
- Modify: `backend/scripts/container-safety.ps1`
- Create: `docs/full-stack-compose-acceptance.md`
- Modify: `README.md`
- Modify: `backend/README.md`
- Modify: `.github/workflows/contracts.yml`

**Interfaces:**
- Consumes: Compose topology, runner phases, fixture subcommands, existing ownership helpers.
- Produces one command:

```powershell
powershell -NoProfile -File backend/scripts/verify-full-stack-compose.ps1 `
  -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' `
  -Architecture amd64 `
  -GoBinary 'C:\absolute\go.exe'
```

- [ ] **Step 1: Write failing verifier safety tests**

With a fake Docker executable, assert unique project creation, exact image rejection, ephemeral frontend port discovery, recorded container/network/volume IDs, phase order, control-plane stop/start, valid-Agent stop before journal assertion, failure propagation, environment restoration and `finally` cleanup. A similarly named pre-existing project must remain untouched.

- [ ] **Step 2: Run safety tests and verify RED**

Run: `node --test tests/contracts/full-stack-container-safety.test.mjs`

Expected: FAIL because the verifier is absent.

- [ ] **Step 3: Implement verifier orchestration**

Sequence:

```text
validate Docker/Go/images/repo/worktree
compose config
asset-builder + bootstrap
postgres + oidc
controlplane ready
agent online/host.v1
frontend ready
runner normal
fixture database
stop controlplane
wait for new Agent spool batch
start controlplane and wait ready/online
runner post-restart
rogue-untrusted expected failure
rogue-mismatch expected failure
stop valid Agent
fixture journal + final database
cleanup audit
```

Every wait polls a condition with a deadline and prints only fixed IDs/status. On failure, collect redacted logs and Playwright artifacts into a uniquely named temporary directory, then clean runtime resources. Do not include secret/config volume contents.

- [ ] **Step 4: Add CI syntax/safety gates**

GitHub CI runs Compose config parsing and fake-Docker safety tests. The real full-stack verifier is documented as a local/release job unless the exact private Kylin image is available; do not silently substitute another image.

- [ ] **Step 5: Document use and limitations**

Document prerequisites, exact command, expected phase outputs, troubleshooting, redaction, cleanup, OIDC bootstrap boundary, production TLS differences and why frontend PKCE/framework migration remain separate.

- [ ] **Step 6: Run safety and documentation regression tests**

Run:

```powershell
node --test tests/contracts/full-stack-container-safety.test.mjs tests/contracts/full-stack-compose.test.mjs tests/contracts/full-stack-communication.test.mjs
git diff --check
```

Expected: PASS.

- [ ] **Step 7: Commit verifier and docs**

```powershell
git add -- backend/scripts/verify-full-stack-compose.ps1 backend/scripts/container-safety.ps1 tests/contracts/full-stack-container-safety.test.mjs docs/full-stack-compose-acceptance.md README.md backend/README.md .github/workflows/contracts.yml
git commit -m "test: orchestrate full-stack compose acceptance"
```

### Task 6: Execute the Complete Full-Stack and Regression Gates

**Files:**
- Modify only files required by failures proven in this task.
- Create: `docs/full-stack-compose-verification-report.md`

**Interfaces:**
- Consumes: all Tasks 1–5.
- Produces fresh evidence for normal browser, communication restart, rogue identities, database/journal state and zero-resource cleanup.

- [ ] **Step 1: Run preflight regression gates**

Run:

```powershell
npm run contracts:lint
npm run contracts:breaking
npm run contracts:verify
node --test
Push-Location backend
go test ./... -count=1
go vet ./...
Pop-Location
```

Expected: existing repository gates PASS with one known Redocly license warning and one opt-in Prism skip.

- [ ] **Step 2: Run Compose structure and safety gates**

Run:

```powershell
docker compose -f backend/docker/full-stack/docker-compose.yml config --quiet
node --test tests/contracts/full-stack-compose.test.mjs tests/contracts/full-stack-communication.test.mjs tests/contracts/full-stack-container-safety.test.mjs
```

Expected: PASS.

- [ ] **Step 3: Run actual full-stack acceptance**

Run:

```powershell
powershell -NoProfile -File backend/scripts/verify-full-stack-compose.ps1 `
  -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' `
  -Architecture amd64 `
  -GoBinary 'D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe'
```

Expected output includes fixed phase markers:

```text
OIDC acceptance passed
Agent mTLS communication passed
Host inspection browser acceptance passed
Control-plane restart and spool recovery passed
Rogue Agent rejection passed
Database and journal assertions passed
Full-stack cleanup audit passed
```

- [ ] **Step 4: Run existing production gates**

Run:

```powershell
powershell -NoProfile -File backend/scripts/verify-inspection-postgres.ps1
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1 -GoBinary 'D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe'
powershell -NoProfile -File backend/scripts/verify-kylin-docker.ps1 `
  -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' `
  -Architecture amd64 `
  -GoBinary 'D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe'
```

Expected: all PASS with exact cleanup.

- [ ] **Step 5: Audit final resources and worktree**

Require zero full-stack/inspection/foundation/Kylin verifier containers, networks, temporary volumes and temporary directories. Run `git diff --check` and require only expected tracked changes.

- [ ] **Step 6: Write verification report**

Record image IDs, binary versions, phase IDs, Run/Job/Command/Finding/Report/Artifact counts, restart timestamps, negative-auth results and cleanup counts. Do not record token, private key, database password, full DSN or raw log body.

- [ ] **Step 7: Commit final evidence**

```powershell
git add -- docs/full-stack-compose-verification-report.md
git commit -m "test: verify full-stack compose acceptance"
```

## Dependency and Concurrency Boundaries

- Task 1 is foundational.
- Task 2 starts after Task 1 fixes fixture CLI/config filenames.
- Task 3 may begin after Task 1 but must consume Task 2 service names and Nginx path before final review; execute sequentially to avoid Compose/frontend conflicts.
- Task 4 requires Tasks 1–3.
- Task 5 requires Tasks 2–4.
- Task 6 requires every earlier task.
- Do not run implementation agents concurrently on Compose, fixture, frontend bootstrap, verifier scripts or runner package lock.

## Completion Gate

Completion requires:

- All six tasks have independent spec and quality approval.
- Final whole-branch review has no unadjudicated Critical or Important issue.
- Full-stack normal, restart/spool, rogue-certificate, browser, database and journal phases pass.
- Existing contract, Node, Go, vet, PostgreSQL, foundation and Kylin gates pass.
- Generated files have zero drift.
- No secret appears in tracked files, test output, DOM, screenshot or logs.
- Docker and temporary-resource audit is empty.
- Feature worktree is clean; dirty `main` checkout remains untouched.
