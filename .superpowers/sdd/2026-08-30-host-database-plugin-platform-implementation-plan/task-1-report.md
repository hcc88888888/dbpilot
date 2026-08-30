# Task 1 report: Host, discovery, plugin and template contracts

## Status and commits

- Status: complete
- Base: `91d1c1157e7b4083d1e4e77d610bb6d1959d6a2d`
- Implementation commit: `2fa4ba3d4248ef7ad4187765caaf58f4652d7f74`
- Implementation commit subject: `feat: define host and plugin platform contracts`

## Delivered contract surfaces

- Added bounded, closed OpenAPI DTOs for managed hosts, discovery candidates, managed database instances, plugin definitions/versions/assignments/observations, and metric template revisions.
- Added named path-item modules and wired 23 canonical paths into `platform.yaml`.
- Added exact permission metadata, mandatory `Idempotency-Key` on every write, and `If-Match` on conditional mutations.
- Added `AgentEnrollment.Enroll`, typed host/discovery/plugin observations, six typed Agent commands, and live-stream-only credential/artifact lease request-response messages.
- Added `PluginRuntime` with Handshake, ApplyConfiguration, ValidateInstance, CollectNow, StreamMetrics, GetHealth, and Shutdown.
- Added restricted `DockerDiscovery` Snapshot/Watch contracts without mutation, exec, socket, tenant, or project fields.
- Regenerated Go OpenAPI/permission/protobuf packages and TypeScript source plus compiled distribution output.

Global constraints retained:

- No string command, arbitrary shell, executable path, script body, install hook, or post-install hook was added.
- A persisted `CommandEnvelope` carries artifact IDs/digests and desired state, never a short-lived URL or lease payload.
- Credential and artifact leases exist only as correlated AgentControl stream messages with nonce, IDs, revision, and expiry.
- REST catalog and management responses contain references/digests, not secrets, signed URLs, private keys, or storage paths.
- Contracts represent one assignment per host/Agent/database family; the plugin configuration carries multiple instances for the single family runtime.

## TDD evidence

### RED

Command:

```powershell
node --test tests/contracts/host-plugin-contracts.test.mjs tests/contracts/openapi.test.mjs tests/contracts/agent-proto.test.mjs
```

Environment correction: the first attempt failed because the linked worktree lacked `node_modules`; `npm install` restored the repository-declared test dependencies. The valid RED rerun produced:

```text
tests 9
pass 5
fail 4
```

The four expected failures were:

- `listHosts is exposed`
- missing `HostStatus` and the other new bounded DTOs
- missing `contracts/protobuf/dbpilot/agent/v1/enrollment.proto`
- missing `contracts/protobuf/dbpilot/plugin/v1/plugin.proto`

All existing inspection/Agent contract tests remained green, proving the failures came from the absent Task 1 contract surface.

### GREEN

Command:

```powershell
node --test tests/contracts/host-plugin-contracts.test.mjs tests/contracts/openapi.test.mjs tests/contracts/agent-proto.test.mjs
```

Result:

```text
tests 9
pass 9
fail 0
```

## Generation and verification evidence

The local Codex shell did not initially expose the installed Go and Docker binaries on `PATH`. The repository scripts were rerun unchanged with these installed tool directories prepended for the process:

- Go: `C:\Users\Chris\.cache\codex-runtimes\go1.27.0\go\bin`
- Docker: `C:\Users\Chris\AppData\Local\Programs\DockerDesktop\resources\bin`

Commands and results:

```powershell
npm run contracts:generate
```

- PASS after extracting inline plugin platform/slot enums into named component schemas compatible with the repository's open-enum post-processor.
- TypeScript compilation completed inside the generator.

```powershell
npm run contracts:lint
```

- PASS.
- One already-recorded warning remains: root `info` has no `license` field.

```powershell
npm run contracts:breaking
```

- PASS against `refs/remotes/origin/main` using pinned Buf `1.57.2`.

```powershell
npm run contracts:verify
```

- The first run reported intentional uncommitted generated drift (`backend/gen/agent/v1/command.pb.go`).
- After staging the canonical contract/generated/test surface, rerunning the same command passed with zero additional drift.

Final generated-client checks:

```powershell
node --test tests/contracts/host-plugin-contracts.test.mjs tests/contracts/openapi.test.mjs tests/contracts/agent-proto.test.mjs tests/contracts/generated-rest.test.mjs
Push-Location backend
go test ./gen/... -count=1
Pop-Location
```

Result:

```text
Node: 11 tests, 11 pass, 0 fail
Go: agent/v1, discovery/v1, openapi and plugin/v1 generated packages compile; openapi tests pass
```

`git diff --cached --check` passed before the implementation commit.

## Generated files

Generated Go output:

- `backend/gen/openapi/dbpilot.gen.go`
- `backend/gen/openapi/permissions.gen.go`
- `backend/gen/agent/v1/{command,inventory,enrollment,enrollment_grpc}.pb.go` (with existing command/inventory regenerated)
- `backend/gen/discovery/v1/{docker,docker_grpc}.pb.go`
- `backend/gen/plugin/v1/{health,instance,metrics,plugin,plugin_grpc}.pb.go`

Generated TypeScript output:

- `frontend/generated/api/src/apis/DefaultApi.ts`
- `frontend/generated/api/dist/apis/DefaultApi.{js,d.ts}`
- New model source and compiled pairs for Host, DiscoveryCandidate, ManagedDatabaseInstance, PluginDefinition, PluginVersion, PluginAssignment, PluginObservedState, MetricTemplate, MetricTemplateRevision, their pages/requests, and all named status/value enums.
- Regenerated source/dist model indexes and `.openapi-generator/FILES`.

The implementation commit contains 191 files: 33,433 insertions and 2,506 deletions, primarily deterministic generated output.

## Assumptions

- Permission literals follow the repository's existing colon-delimited feature convention: `hosts:*`, `discovery:*`, `database-instances:*`, `plugins:*`, and `metric-templates:*`.
- Database family and variant identifiers are bounded strings instead of closed enums so later signed plugin families can be added without falsely claiming production support; lifecycle/status vocabularies are closed enums.
- `PluginArtifactLeaseResponse.download_url` is permitted only on the non-persistent AgentControl response. It is deliberately absent from `CommandEnvelope` and every REST catalog/assignment DTO.
- Credential references use bounded `secret://` references. Resolved username/secret bytes appear only in non-persistent protobuf lease/private-UDS messages.
- The REST surface includes host decommission because Task 2's declared service consumes that operation, while the spec's listed host paths were described as the principal rather than exhaustive resource set.

## Deferred technical debt

| Affected module | Trigger | Functional impact | Severity | Recommended stage |
| --- | --- | --- | --- | --- |
| Root OpenAPI metadata | `npm run contracts:lint` | None; Redocly emits the pre-existing `info.license` warning | Low | Contract metadata cleanup before production documentation publication |
| Contract development dependencies | `npm install` / `npm audit` | None in generated runtime artifacts; npm reported 16 moderate and 1 high advisory in the existing locked toolchain | Medium | Consolidated dependency/toolchain remediation before production rollout |

No Task 1 functional correctness debt remains known. No Task 2 work was started.
