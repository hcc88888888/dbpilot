# DBPilot Host and Database Plugin Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a production-oriented host-first management flow in which DBPilot discovers native and Docker MySQL instances, deploys one Server-managed MySQL plugin process per Agent host, collects host plus database metrics, and exposes the complete workflow through a gradually migrated React frontend.

**Architecture:** The Server owns host, candidate, instance, plugin, template and desired-state records; the Agent reconciles signed typed commands, supervises signed plugin packages in A/B slots, and accepts canonical metrics over a private Unix-socket gRPC protocol. Host collection and native discovery remain Agent core capabilities, Docker discovery is isolated in one restricted helper per Docker host, and database plugins never contact the Server directly. New Server HTTP APIs are OpenAPI-first and transport-neutral; new frontend pages use React/TypeScript/Vite while legacy modules remain mounted during migration.

**Tech Stack:** Go 1.27.0, standard `net/http`, OpenAPI 3.1, oapi-codegen, OpenAPI Generator TypeScript Fetch, Protobuf/Buf, gRPC, PostgreSQL 16, bbolt, Ed25519 signatures, Unix domain sockets, MySQL 8/go-sql-driver/mysql, React 19, TypeScript 5.9, Vite 7, React Router 7, TanStack Query 5, Vitest, Testing Library, Docker Compose, Kylin V10 SP1 amd64, PowerShell 5.1/7.

**Spec:** `docs/superpowers/specs/2026-08-30-host-database-plugin-platform-design.md`

## Global Constraints

- Read the complete spec before every task; the spec is authoritative when this plan omits explanatory text.
- Target Agent/plugin platforms are CentOS 7+ and Kylin V10+; first production evidence is linux/amd64 on exact `cr.kylinos.cn/kylin/kylin-server-platform:v10sp1`.
- One Agent maps to one tenant/project in this phase.
- Host metrics and native discovery remain Agent core; database metrics execute only in independent database plugin processes.
- At most one active process exists per Agent and database plugin family; one process must serve multiple instances.
- Do not use Go `plugin`, arbitrary shell, arbitrary executable commands, install hooks, dynamic scripts, or plugin-to-Server connections.
- Server hosts plugin packages; Agent never downloads plugins from GitHub, registries, or arbitrary URLs.
- Agent and database plugins never mount or open the raw Docker Socket; only `dbpilot-docker-discovery` owns that boundary.
- New HTTP APIs are canonical OpenAPI operations with generated Go/TypeScript outputs; do not add legacy hand-written DTO routes.
- New Server Application Services and repositories must not depend on `http.Request`, `http.ResponseWriter`, Chi, Gin, Echo or framework contexts.
- Browser access tokens remain memory-only and are read per request; no localStorage/sessionStorage token persistence and no HTTP-to-demo fallback.
- Plugin packages, credentials, SQL bodies, signed URLs, private keys, raw Docker inspect data and raw trial rows must not enter logs, Audit details, DOM, retained artifacts or error strings.
- Every write endpoint requires idempotency; conditional updates require ETag/If-Match.
- Every Docker verifier owns a unique labelled project and removes only exact recorded resources; no prune, wildcard deletion or Docker Socket mount.
- Follow strict TDD for every task: prove RED, implement the smallest correct change, rerun focused tests, then relevant regressions.
- Preserve the repository feature-first rule: functional correctness blockers are fixed immediately; non-blocking hardening is recorded with module, trigger, impact, severity and remediation stage.

## Planned File Structure

```text
contracts/
  openapi/common/{hosts,discovery,database-instances,plugins,metric-templates}.yaml
  openapi/modules/{hosts,discovery,database-instances,plugins,metric-templates}.yaml
  protobuf/dbpilot/agent/v1/{command,enrollment,inventory}.proto
  protobuf/dbpilot/plugin/v1/{plugin,instance,metrics,health}.proto
  protobuf/dbpilot/discovery/v1/docker.proto

backend/internal/
  enrollment/
  hostinventory/
  discovery/
  databaseinstance/
  plugincatalog/
  pluginassignment/
  metrictemplate/
  credentiallease/
  reconciliation/
  agent/{discovery,pluginsupervisor,plugingateway,pluginstate,credentialcache}/
  dockerdiscovery/
  mysqlplugin/

backend/cmd/
  dbpilot-plugin-mysql/
  dbpilot-docker-discovery/

frontend/app/
  src/{shell,auth,routing,api,components,features}/
  package.json
  package-lock.json
  vite.config.ts
  tsconfig.json

backend/docker/host-plugin-full-stack/
  docker-compose.yml
  nginx.conf
  runner.Dockerfile
```

---

### Task 1: Define Host, Discovery, Plugin and Template Contracts

**Files:**
- Create: `contracts/openapi/common/hosts.yaml`
- Create: `contracts/openapi/common/discovery.yaml`
- Create: `contracts/openapi/common/database-instances.yaml`
- Create: `contracts/openapi/common/plugins.yaml`
- Create: `contracts/openapi/common/metric-templates.yaml`
- Create: `contracts/openapi/modules/hosts.yaml`
- Create: `contracts/openapi/modules/discovery.yaml`
- Create: `contracts/openapi/modules/database-instances.yaml`
- Create: `contracts/openapi/modules/plugins.yaml`
- Create: `contracts/openapi/modules/metric-templates.yaml`
- Modify: `contracts/openapi/modules/platform.yaml`
- Modify: `contracts/openapi/dbpilot-api.yaml`
- Create: `contracts/protobuf/dbpilot/agent/v1/enrollment.proto`
- Modify: `contracts/protobuf/dbpilot/agent/v1/inventory.proto`
- Modify: `contracts/protobuf/dbpilot/agent/v1/command.proto`
- Create: `contracts/protobuf/dbpilot/plugin/v1/plugin.proto`
- Create: `contracts/protobuf/dbpilot/plugin/v1/instance.proto`
- Create: `contracts/protobuf/dbpilot/plugin/v1/metrics.proto`
- Create: `contracts/protobuf/dbpilot/plugin/v1/health.proto`
- Create: `contracts/protobuf/dbpilot/discovery/v1/docker.proto`
- Modify generated outputs under: `backend/gen/`, `frontend/generated/`
- Test: `tests/contracts/openapi.test.mjs`
- Test: `tests/contracts/agent-proto.test.mjs`
- Create: `tests/contracts/host-plugin-contracts.test.mjs`

**Interfaces:**
- Consumes: existing tenant/project identifiers, Problem, Page, Job, Artifact, Audit and Agent v1 two-phase command envelope.
- Produces: canonical REST DTOs and the following protobuf services/messages used by every later task.

```proto
service AgentEnrollment {
  rpc Enroll(EnrollAgentRequest) returns (EnrollAgentResponse);
}

service PluginRuntime {
  rpc Handshake(PluginHandshakeRequest) returns (PluginHandshakeResponse);
  rpc ApplyConfiguration(ApplyPluginConfigurationRequest) returns (ApplyPluginConfigurationResponse);
  rpc ValidateInstance(ValidatePluginInstanceRequest) returns (ValidatePluginInstanceResponse);
  rpc CollectNow(CollectPluginMetricsRequest) returns (CollectPluginMetricsResponse);
  rpc StreamMetrics(StreamPluginMetricsRequest) returns (stream PluginMetricBatch);
  rpc GetHealth(GetPluginHealthRequest) returns (PluginHealth);
  rpc Shutdown(ShutdownPluginRequest) returns (ShutdownPluginResponse);
}

service DockerDiscovery {
  rpc Snapshot(DockerSnapshotRequest) returns (DockerSnapshotResponse);
  rpc Watch(DockerWatchRequest) returns (stream DockerEvent);
}
```

AgentControl extensions produced by this task are exact typed messages:

```proto
message HostObservation {}
message DiscoveryReport {}
message PluginObservation {}
message CredentialLeaseRequest {}
message CredentialLeaseResponse {}
message PluginArtifactLeaseRequest {}
message PluginArtifactLeaseResponse {}
```

```go
type ManagedHost struct{}
type DiscoveryCandidate struct{}
type ManagedDatabaseInstance struct{}
type PluginDefinition struct{}
type PluginVersion struct{}
type PluginAssignment struct{}
type PluginObservedState struct{}
type MetricTemplateRevision struct{}
```

- [ ] **Step 1: Write failing structural contract tests**

Add tests that bundle the OpenAPI and assert exact operations, permissions, Idempotency-Key/If-Match rules, closed status enums, bounded strings/arrays and no secret-bearing response fields. Add protobuf tests that require typed `DiscoverDatabases`, `ReconcilePlugin`, `ApplyPluginConfiguration`, `ValidateDatabaseInstance`, `DrainPlugin` and `CollectDatabaseMetrics` commands; require non-persistent `CredentialLeaseRequest/Response` and `PluginArtifactLeaseRequest/Response`; reject any string command, shell or arbitrary executable addition.

```javascript
test('plugin reconciliation is typed and never exposes arbitrary execution', async () => {
  const command = await readFile('contracts/protobuf/dbpilot/agent/v1/command.proto', 'utf8');
  assert.match(command, /ReconcilePlugin reconcile_plugin/);
  assert.doesNotMatch(command, /shell_command|executable_path|script_body/);
});
```

- [ ] **Step 2: Run contract tests and verify RED**

Run: `node --test tests/contracts/host-plugin-contracts.test.mjs tests/contracts/openapi.test.mjs tests/contracts/agent-proto.test.mjs`

Expected: FAIL because host/plugin schemas and typed messages are absent.

- [ ] **Step 3: Implement canonical schemas and protobuf definitions**

Define every field, enum, maximum, permission and response described in the spec. Path modules export named path-item mappings and `platform.yaml` references them per path. Reserve protobuf field ranges before adding new oneof entries. Credential and Artifact lease messages contain correlation nonce, IDs, revision and expiration; they never contain an HTTP URL inside a persisted Command.

- [ ] **Step 4: Regenerate clients and fix generated compilation**

Run:

```powershell
npm run contracts:generate
npm run contracts:lint
npm run contracts:breaking
npm run contracts:verify
node --test tests/contracts/host-plugin-contracts.test.mjs tests/contracts/openapi.test.mjs tests/contracts/agent-proto.test.mjs tests/contracts/generated-rest.test.mjs
Push-Location backend
go test ./gen/... -count=1
Pop-Location
```

Expected: PASS with zero generated drift; only the already recorded `info.license` warning may remain.

- [ ] **Step 5: Commit**

```powershell
git add -- contracts backend/gen frontend/generated tests/contracts
git commit -m "feat: define host and plugin platform contracts"
```

---

### Task 2: Implement PostgreSQL Host Inventory and Scoped Host APIs

**Files:**
- Create: `backend/internal/hostinventory/model.go`
- Create: `backend/internal/hostinventory/model_test.go`
- Create: `backend/internal/hostinventory/repository.go`
- Create: `backend/internal/hostinventory/postgres.go`
- Create: `backend/internal/hostinventory/postgres_test.go`
- Create: `backend/internal/hostinventory/postgres_integration_test.go`
- Create: `backend/internal/hostinventory/service.go`
- Create: `backend/internal/hostinventory/service_test.go`
- Create: `backend/internal/hostinventory/migrate.go`
- Create: `backend/internal/hostinventory/migrations/0001_host_inventory.sql`
- Create: `backend/internal/controlplane/host_api.go`
- Create: `backend/internal/controlplane/host_api_test.go`
- Modify: `backend/internal/controlplane/services.go`
- Modify: `backend/cmd/controlplane/main.go`

**Interfaces:**
- Consumes: generated `ManagedHost`, project scope, authenticated principal, Audit and idempotency services.
- Produces:

```go
type HostStatus string
const (
    HostPending HostStatus = "pending"
    HostEnrolling HostStatus = "enrolling"
    HostOnline HostStatus = "online"
    HostStale HostStatus = "stale"
    HostOffline HostStatus = "offline"
    HostDecommissioned HostStatus = "decommissioned"
)

type Observation struct {
    HostID, AgentID, AgentVersion, Hostname, OS, OSVersion, Kernel, Architecture string
    Capabilities []string
    ObservedAt time.Time
}

type Service interface {
    RecordObservation(context.Context, Observation) (Host, error)
    List(context.Context, platformscope.Scope, Filter) (Page, error)
    Get(context.Context, platformscope.Scope, string) (Host, error)
    Decommission(context.Context, platformscope.Scope, string, uint64) (Host, error)
}
```

- [ ] **Step 1: Write failing model and migration tests**

Test status transitions, bounded inventory fields, exact scope, monotonic observation revision, stale/offline classification, host uniqueness, append-only observations and migration constraints.

```go
func TestClassifyHostRequiresRealHeartbeat(t *testing.T) {
    got := ClassifyHost(now, Host{LastHelloAt: now, LastHeartbeatAt: time.Time{}}, time.Minute, 5*time.Minute)
    require.Equal(t, HostOffline, got)
}
```

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/hostinventory ./internal/controlplane -run 'Test(Host|ManagedHost)' -count=1 -v; Pop-Location`

Expected: FAIL because package and handler are absent.

- [ ] **Step 3: Implement domain, PostgreSQL repository and service**

Use tenant/project predicates in every SQL statement. Store observations separately from current host projection. Decommission uses ETag CAS and records Audit once. Never authorize through hostname, IP or machine-id.

- [ ] **Step 4: Implement generated host handlers and composition**

Map generated request DTOs into `hostinventory.Service`; enforce generated permissions and pagination. Add `hostinventory.RunMigrations` to the control-plane readiness migration sequence and inject the service through `controlplane.Services`.

- [ ] **Step 5: Run focused and PostgreSQL tests**

```powershell
Push-Location backend
go test ./internal/hostinventory ./internal/controlplane ./cmd/controlplane -count=1
go vet ./internal/hostinventory ./internal/controlplane ./cmd/controlplane
Pop-Location
powershell -NoProfile -File backend/scripts/verify-inspection-postgres.ps1
```

Expected: PASS and exact PostgreSQL cleanup.

- [ ] **Step 6: Commit**

```powershell
git add -- backend/internal/hostinventory backend/internal/controlplane backend/cmd/controlplane
git commit -m "feat: add scoped host inventory"
```

---

### Task 3: Add One-Time Agent Enrollment and Host Observation

**Files:**
- Create: `backend/internal/enrollment/model.go`
- Create: `backend/internal/enrollment/service.go`
- Create: `backend/internal/enrollment/service_test.go`
- Create: `backend/internal/enrollment/postgres.go`
- Create: `backend/internal/enrollment/postgres_test.go`
- Create: `backend/internal/enrollment/migrate.go`
- Create: `backend/internal/enrollment/migrations/0001_agent_enrollment.sql`
- Create: `backend/internal/enrollment/grpc.go`
- Create: `backend/internal/enrollment/grpc_test.go`
- Create: `backend/internal/controlplane/enrollment_api.go`
- Create: `backend/internal/controlplane/enrollment_api_test.go`
- Create: `backend/cmd/agent/enroll.go`
- Create: `backend/cmd/agent/enroll_test.go`
- Modify: `backend/cmd/agent/main.go`
- Modify: `backend/cmd/controlplane/main.go`
- Modify: `backend/internal/agentcontrol/server.go`
- Modify: `backend/internal/agentcontrol/server_test.go`

**Interfaces:**
- Consumes: Task 1 `AgentEnrollment` protobuf and Task 2 enrollment/host records.
- Produces:

```go
type TokenStore interface {
    Create(context.Context, EnrollmentToken) error
    Consume(context.Context, [32]byte, time.Time) (EnrollmentGrant, error)
}

type CertificateIssuer interface {
    SignAgentCSR(context.Context, EnrollmentGrant, []byte) (certificatePEM, chainPEM []byte, expiresAt time.Time, err error)
}
```

CLI:

```text
dbpilot-agent enroll --server <host:port> --ca-file <abs> --token-file <abs> --agent-id <id> --output-dir <abs>
```

- [ ] **Step 1: Write failing enrollment security tests**

Require token hashes only, single consumption, expiry, scope binding, Ed25519 CSR proof, canonical SPIFFE `spiffe://dbpilot.local/agent/<agent-id>`, create-exclusive 0600 key/cert files, no token/cert private material in errors, and rejection of path/symlink collisions.

```go
func TestEnrollmentTokenCannotBeConsumedTwice(t *testing.T) {
    first := consume(t, token)
    require.NotEmpty(t, first.CertificatePEM)
    _, err := service.Enroll(ctx, requestFor(token))
    require.ErrorIs(t, err, ErrEnrollmentTokenInvalid)
}
```

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/enrollment ./cmd/agent -run TestEnroll -count=1 -v; Pop-Location`

Expected: FAIL because enrollment service and CLI are absent.

- [ ] **Step 3: Implement enrollment service and TLS-only listener**

Add a separately configured TLS server-auth enrollment listener; it must not share the mTLS AgentControl listener. Agent generates its private key locally, sends CSR plus one-time token, verifies the returned chain and writes files atomically. Server consumes the token transactionally before returning the certificate.

- [ ] **Step 4: Connect Hello/Heartbeat to Host Inventory**

On authenticated Hello, require the Agent inventory observation and update Host `last_hello_at`; only a real Heartbeat updates `last_heartbeat_at`. Do not seed heartbeat from Hello. Existing AgentControl ingress must remain non-blocking when observers are slow.

- [ ] **Step 5: Run focused, race-relevant and Kylin build tests**

```powershell
Push-Location backend
go test ./internal/enrollment ./internal/agentcontrol ./internal/hostinventory ./cmd/agent ./cmd/controlplane -count=1
go vet ./internal/enrollment ./internal/agentcontrol ./cmd/agent ./cmd/controlplane
$env:CGO_ENABLED='0'; $env:GOOS='linux'; $env:GOARCH='amd64'
go build ./cmd/agent ./cmd/controlplane
Pop-Location
```

Expected: PASS without writing enrollment token or private key to output.

- [ ] **Step 6: Commit**

```powershell
git add -- backend/internal/enrollment backend/internal/agentcontrol backend/internal/hostinventory backend/cmd/agent backend/cmd/controlplane
git commit -m "feat: enroll agents and record host liveness"
```

---

### Task 4: Implement Native Database Process Discovery

**Files:**
- Create: `backend/internal/discovery/model.go`
- Create: `backend/internal/discovery/model_test.go`
- Create: `backend/internal/discovery/rules.go`
- Create: `backend/internal/discovery/rules_test.go`
- Create: `backend/internal/discovery/fingerprint.go`
- Create: `backend/internal/discovery/fingerprint_test.go`
- Create: `backend/internal/discovery/postgres.go`
- Create: `backend/internal/discovery/postgres_test.go`
- Create: `backend/internal/discovery/migrate.go`
- Create: `backend/internal/discovery/migrations/0001_discovery_candidates.sql`
- Create: `backend/internal/agent/discovery/native_linux.go`
- Create: `backend/internal/agent/discovery/native_other.go`
- Create: `backend/internal/agent/discovery/native_linux_test.go`
- Create: `backend/internal/agent/discovery/coordinator.go`
- Create: `backend/internal/agent/discovery/coordinator_test.go`
- Modify: `backend/internal/agent/controlclient.go`
- Create: `backend/internal/controlplane/discovery_api.go`
- Create: `backend/internal/controlplane/discovery_api_test.go`

**Interfaces:**
- Consumes: signed `DiscoveryRuleSet`, Task 1 discovery report messages, Task 2 host scope.
- Produces:

```go
type NativeReader interface {
    Processes(context.Context) ([]ProcessObservation, error)
    ListeningEndpoints(context.Context, int) ([]EndpointObservation, error)
    SystemdUnit(context.Context, int) (string, bool, error)
}

type Detector interface {
    Discover(context.Context, []Rule) ([]CandidateObservation, error)
}

func Fingerprint(hostID string, observation CandidateObservation) ([32]byte, error)
```

- [ ] **Step 1: Write failing discovery and redaction tests**

Use a fake `/proc` reader to prove MySQL process+port detection, PID-independent fingerprinting, candidate disappearance, exact dedupe, bounded evidence, RE2 rule validation and credential redaction from cmdline. Require no subprocess/shell calls in the implementation.

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/discovery ./internal/agent/discovery -count=1 -v; Pop-Location`

Expected: FAIL because discovery packages are absent.

- [ ] **Step 3: Implement signed rules, Linux reader and coordinator**

Read only allowlisted `/proc` and systemd D-Bus facts. Normalize endpoints and sockets. The coordinator scans on enrollment and a bounded ticker, and responds to `DiscoverDatabases` by running the same code path. Reports carry observation revision and fixed evidence fields only.

- [ ] **Step 4: Persist candidates and expose APIs**

Upsert by scope+fingerprint, preserve first_seen, advance last_seen/revision, and transition absent candidates to disappeared only after the configured grace. Implement list/get/ignore operations; acceptance is deferred to Task 6 so it can create a database instance transactionally.

- [ ] **Step 5: Run Linux/Kylin discovery probe**

Add `backend/scripts/verify-native-discovery.ps1` that cross-builds Agent and a controlled non-secret `mysqld`-named fixture, runs both inside exact Kylin, asserts a single candidate, and cleans exact resources.

Run: `powershell -NoProfile -File backend/scripts/verify-native-discovery.ps1 -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'`

Expected: PASS with no command-line secret in output.

- [ ] **Step 6: Commit**

```powershell
git add -- backend/internal/discovery backend/internal/agent/discovery backend/internal/agent/controlclient.go backend/internal/controlplane/discovery_api* backend/scripts/verify-native-discovery.ps1
git commit -m "feat: discover native database processes"
```

---

### Task 5: Build the Restricted Docker Discovery Helper

**Files:**
- Create: `backend/internal/dockerdiscovery/client.go`
- Create: `backend/internal/dockerdiscovery/client_test.go`
- Create: `backend/internal/dockerdiscovery/redact.go`
- Create: `backend/internal/dockerdiscovery/redact_test.go`
- Create: `backend/internal/dockerdiscovery/server.go`
- Create: `backend/internal/dockerdiscovery/server_test.go`
- Create: `backend/cmd/dbpilot-docker-discovery/main.go`
- Create: `backend/cmd/dbpilot-docker-discovery/main_test.go`
- Create: `packaging/systemd/dbpilot-docker-discovery.service`
- Create: `packaging/systemd/dbpilot-docker-discovery.env.example`
- Create: `backend/internal/agent/discovery/docker_client.go`
- Create: `backend/internal/agent/discovery/docker_client_test.go`
- Modify: `backend/internal/agent/discovery/coordinator.go`
- Create: `backend/scripts/verify-docker-discovery.ps1`
- Modify: `tests/contracts/container-safety.test.mjs`

**Interfaces:**
- Consumes: Task 1 `DockerDiscovery` protobuf and Task 4 candidate normalization.
- Produces:

```go
type Engine interface {
    ListContainers(context.Context) ([]ContainerObservation, error)
    InspectContainer(context.Context, string) (ContainerObservation, error)
    Events(context.Context, time.Time) (<-chan ContainerEvent, <-chan error)
}
```

- [ ] **Step 1: Write failing Docker API allowlist and redaction tests**

Start a fake Unix HTTP server. Require only GET `/containers/json`, GET `/containers/{fixed-id}/json`, GET `/events`, GET `/info`; reject path injection, query expansion, POST/DELETE/exec/logs/archive/stats, environment output, unapproved labels and credential-bearing command arguments.

```go
func TestClientNeverUsesMutatingDockerEndpoints(t *testing.T) {
    paths := recordDockerRequests(t, client.Snapshot(ctx))
    for _, request := range paths {
        require.Equal(t, http.MethodGet, request.Method)
        require.NotContains(t, request.URL.Path, "/exec")
    }
}
```

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/dockerdiscovery ./cmd/dbpilot-docker-discovery ./internal/agent/discovery -run TestDocker -count=1 -v; Pop-Location`

Expected: FAIL because helper is absent.

- [ ] **Step 3: Implement helper, private UDS server and hardening unit**

The helper alone opens the configured Docker Unix socket. It serves Agent over a separate 0600 Unix socket, validates peer UID, uses bounded response sizes/timeouts and returns allowlisted DTOs. The systemd unit runs non-root where host policy permits Docker access, clears capabilities and applies the spec hardening directives.

- [ ] **Step 4: Integrate Agent Docker discovery**

If helper is absent/unhealthy, report capability reason without failing Native Discovery. Merge Docker observations through the same Task 4 fingerprint/dedupe pipeline. Do not let Server remotely install or grant Docker Socket access.

- [ ] **Step 5: Run exact Docker discovery verification**

The verifier starts two MySQL containers with ownership labels, starts the helper with a fixture Docker API proxy, proves two redacted candidates and event reconciliation, attempts forbidden endpoints, and removes exact resources.

Run: `powershell -NoProfile -File backend/scripts/verify-docker-discovery.ps1`

Expected: PASS; Agent container has no Docker Socket mount.

- [ ] **Step 6: Commit**

```powershell
git add -- backend/internal/dockerdiscovery backend/cmd/dbpilot-docker-discovery backend/internal/agent/discovery packaging/systemd backend/scripts/verify-docker-discovery.ps1 tests/contracts/container-safety.test.mjs
git commit -m "feat: discover Docker database containers safely"
```

---

### Task 6: Add Managed Database Instances and Candidate Acceptance

**Files:**
- Create: `backend/internal/databaseinstance/model.go`
- Create: `backend/internal/databaseinstance/model_test.go`
- Create: `backend/internal/databaseinstance/repository.go`
- Create: `backend/internal/databaseinstance/postgres.go`
- Create: `backend/internal/databaseinstance/postgres_test.go`
- Create: `backend/internal/databaseinstance/postgres_integration_test.go`
- Create: `backend/internal/databaseinstance/service.go`
- Create: `backend/internal/databaseinstance/service_test.go`
- Create: `backend/internal/databaseinstance/migrate.go`
- Create: `backend/internal/databaseinstance/migrations/0001_database_instances.sql`
- Create: `backend/internal/controlplane/database_instance_api.go`
- Create: `backend/internal/controlplane/database_instance_api_test.go`
- Modify: `backend/internal/controlplane/discovery_api.go`
- Modify: `backend/internal/controlplane/services.go`
- Modify: `backend/cmd/controlplane/main.go`

**Interfaces:**
- Consumes: Task 4/5 candidates, credential/tls references and OpenAPI DTOs.
- Produces:

```go
type Service interface {
    AcceptCandidate(context.Context, platformscope.Scope, string, AcceptCandidateRequest) (Instance, error)
    List(context.Context, platformscope.Scope, Filter) (Page, error)
    Get(context.Context, platformscope.Scope, string) (Instance, error)
    Update(context.Context, platformscope.Scope, string, uint64, Update) (Instance, error)
    Retire(context.Context, platformscope.Scope, string, uint64) (Instance, error)
}
```

- [ ] **Step 1: Write failing acceptance transaction tests**

Require exact candidate scope/status/revision, canonical endpoint, `secret://` credential ref, candidate→accepted and instance creation in one transaction, duplicate endpoint rejection, Audit/idempotency repair, no plaintext credentials and second MySQL instance reusing the same future assignment key `(agent_id,mysql)`.

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/databaseinstance ./internal/discovery ./internal/controlplane -run 'Test(AcceptCandidate|DatabaseInstance)' -count=1 -v; Pop-Location`

Expected: FAIL because instance service is absent.

- [ ] **Step 3: Implement instance domain, repository and service**

Persist family and variant separately. The instance stores references, never resolved secrets. Capability state starts `plugin_not_installed`. Use ETag CAS for updates and stable idempotency fingerprints for candidate acceptance.

- [ ] **Step 4: Implement APIs and migrations**

Wire generated list/get/update/retire/test-connection operations. The test-connection operation creates a Job placeholder consumed after Task 7; until plugin assignment exists it returns a fixed `plugin_not_installed` Problem rather than pretending success.

- [ ] **Step 5: Run PostgreSQL integration and regressions**

Run: `Push-Location backend; go test ./internal/databaseinstance ./internal/discovery ./internal/controlplane ./cmd/controlplane -count=1; Pop-Location`

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add -- backend/internal/databaseinstance backend/internal/discovery backend/internal/controlplane backend/cmd/controlplane
git commit -m "feat: accept and manage database instances"
```

---

### Task 7: Implement Plugin Catalog, Package Verification and Upload

**Files:**
- Create: `backend/internal/plugincatalog/model.go`
- Create: `backend/internal/plugincatalog/model_test.go`
- Create: `backend/internal/plugincatalog/package.go`
- Create: `backend/internal/plugincatalog/package_test.go`
- Create: `backend/internal/plugincatalog/signature.go`
- Create: `backend/internal/plugincatalog/signature_test.go`
- Create: `backend/internal/plugincatalog/postgres.go`
- Create: `backend/internal/plugincatalog/postgres_test.go`
- Create: `backend/internal/plugincatalog/service.go`
- Create: `backend/internal/plugincatalog/service_test.go`
- Create: `backend/internal/plugincatalog/migrate.go`
- Create: `backend/internal/plugincatalog/migrations/0001_plugin_catalog.sql`
- Create: `backend/internal/controlplane/plugin_catalog_api.go`
- Create: `backend/internal/controlplane/plugin_catalog_api_test.go`
- Modify: `backend/internal/controlplane/services.go`
- Modify: `backend/cmd/controlplane/main.go`

**Interfaces:**
- Consumes: existing Artifact blob service and Task 1 generated plugin endpoints.
- Produces:

```go
type PackageVerifier interface {
    Verify(context.Context, io.Reader, int64) (VerifiedPackage, error)
}

type Service interface {
    Upload(context.Context, platformscope.Scope, UploadMetadata, io.Reader) (PluginVersion, error)
    Approve(context.Context, platformscope.Scope, string, uint64) (PluginVersion, error)
    Revoke(context.Context, platformscope.Scope, string, uint64, string) (PluginVersion, error)
    ListVersions(context.Context, platformscope.Scope, VersionFilter) (VersionPage, error)
}
```

- [ ] **Step 1: Write failing malicious-package tests**

Cover absolute paths, `..`, duplicate entries, symlink/hardlink, oversized file/count/expanded size, manifest mismatch, missing binary, executable digest mismatch, wrong platform, unknown publisher, invalid Ed25519 signature, scripts/hooks and secret-looking manifest fields.

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/plugincatalog -count=1 -v; Pop-Location`

Expected: FAIL because catalog package is absent.

- [ ] **Step 3: Implement streaming verification and Artifact persistence**

Bound compressed upload and expanded tar size. Stream to create-exclusive temp Artifact, compute SHA-256, validate each tar header before extraction, parse canonical manifest, verify publisher signature, then publish immutable Artifact metadata. Never extract into the runtime plugin directory on Server.

- [ ] **Step 4: Implement catalog APIs and approval workflow**

Upload is multipart/streaming and requires plugin publish permission. Approval/revocation uses If-Match and Audit. Responses expose IDs/digests/capabilities, never storage paths or signature bytes.

- [ ] **Step 5: Run package, API and Artifact regressions**

Run: `Push-Location backend; go test ./internal/plugincatalog ./internal/artifact ./internal/controlplane ./cmd/controlplane -count=1; Pop-Location`

Expected: PASS with fixed/redacted errors.

- [ ] **Step 6: Commit**

```powershell
git add -- backend/internal/plugincatalog backend/internal/artifact backend/internal/controlplane backend/cmd/controlplane
git commit -m "feat: manage signed database plugins"
```

---

### Task 8: Implement Plugin Assignment and Server Reconciliation

**Files:**
- Create: `backend/internal/pluginassignment/model.go`
- Create: `backend/internal/pluginassignment/model_test.go`
- Create: `backend/internal/pluginassignment/postgres.go`
- Create: `backend/internal/pluginassignment/postgres_test.go`
- Create: `backend/internal/pluginassignment/postgres_integration_test.go`
- Create: `backend/internal/pluginassignment/service.go`
- Create: `backend/internal/pluginassignment/service_test.go`
- Create: `backend/internal/pluginassignment/migrate.go`
- Create: `backend/internal/pluginassignment/migrations/0001_plugin_assignments.sql`
- Create: `backend/internal/reconciliation/plugin.go`
- Create: `backend/internal/reconciliation/plugin_test.go`
- Create: `backend/internal/controlplane/plugin_assignment_api.go`
- Create: `backend/internal/controlplane/plugin_assignment_api_test.go`
- Modify: `backend/internal/databaseinstance/service.go`
- Modify: `backend/internal/job/dispatcher.go`
- Modify: `backend/internal/commandvalidation/validation.go`
- Modify: `backend/cmd/controlplane/main.go`

**Interfaces:**
- Consumes: Task 6 instance `(agent_id,database_family)` and Task 7 available plugin version.
- Produces:

```go
type Reconciler interface {
    Reconcile(context.Context, time.Time, int) (ReconcileResult, error)
}

type AssignmentService interface {
    EnsureForInstance(context.Context, databaseinstance.Instance) (Assignment, error)
    SetDesiredState(context.Context, platformscope.Scope, string, uint64, DesiredState) (Assignment, error)
    RecordObservation(context.Context, PluginObservation) error
}
```

- [ ] **Step 1: Write failing desired/observed state tests**

Require one assignment per Agent/family, two MySQL instances reuse it, revision monotonicity, available-version enforcement, no duplicate Job for matching state, stale observation handling, `SKIP LOCKED` claims, lease expiry, idempotent command payload and revoked-version behavior.

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/pluginassignment ./internal/reconciliation -count=1 -v; Pop-Location`

Expected: FAIL because packages are absent.

- [ ] **Step 3: Implement assignment persistence and service**

Use unique `(tenant_id,project_id,agent_id,database_family)`. Configuration contains instance IDs and template revision IDs but no secret values. Desired changes increment operation/config revisions atomically.

Wire a provisioning coordinator into candidate acceptance so candidate transition, instance creation and `EnsureForInstance` assignment creation commit in one PostgreSQL transaction. If assignment planning fails, neither candidate nor instance is committed. Two accepted MySQL instances on the same Agent must reference the same assignment row.

- [ ] **Step 4: Implement ReconcilePlugin Job/Command generation**

Create a typed command only when observed state differs. Reuse existing Job/Outbox and Prepare→Start. Command includes Artifact ID/digest, not a signed URL. Add command validation and exact capability name `plugin.reconcile.v1`.

- [ ] **Step 5: Implement assignment APIs and worker lifecycle**

Expose list/get/set desired state/reconcile actions. Start a bounded reconciliation worker after migrations and stop it through control-plane context cancellation.

- [ ] **Step 6: Run PostgreSQL race and command lifecycle tests**

Run: `Push-Location backend; go test ./internal/pluginassignment ./internal/reconciliation ./internal/job ./internal/commandvalidation ./internal/controlplane -count=1; Pop-Location`

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add -- backend/internal/pluginassignment backend/internal/reconciliation backend/internal/databaseinstance backend/internal/job backend/internal/commandvalidation backend/internal/controlplane backend/cmd/controlplane
git commit -m "feat: reconcile plugin desired state"
```

---

### Task 9: Build the Agent Plugin Supervisor and A/B Slots

**Files:**
- Create: `backend/internal/agent/pluginsupervisor/model.go`
- Create: `backend/internal/agent/pluginsupervisor/model_test.go`
- Create: `backend/internal/agent/pluginsupervisor/install.go`
- Create: `backend/internal/agent/pluginsupervisor/install_test.go`
- Create: `backend/internal/agent/pluginsupervisor/process_linux.go`
- Create: `backend/internal/agent/pluginsupervisor/process_other.go`
- Create: `backend/internal/agent/pluginsupervisor/process_linux_test.go`
- Create: `backend/internal/agent/pluginsupervisor/supervisor.go`
- Create: `backend/internal/agent/pluginsupervisor/supervisor_test.go`
- Create: `backend/internal/agent/pluginstate/store.go`
- Create: `backend/internal/agent/pluginstate/store_test.go`
- Modify: `backend/internal/agent/commandverify.go`
- Modify: `backend/internal/agent/controlclient.go`
- Modify: `backend/cmd/agent/main.go`

**Interfaces:**
- Consumes: Task 8 `ReconcilePlugin` command and Task 7 verified manifest contract.
- Produces:

```go
type Supervisor interface {
    Prepare(context.Context, ReconcileRequest) (PreparedChange, error)
    Start(context.Context, PreparedChange, ExecutionFence) (ObservedState, error)
    Stop(context.Context) error
    Observe() []PluginObservation
}

type ProcessRunner interface {
    Start(context.Context, Executable, LaunchConfiguration) (Process, error)
}
```

- [ ] **Step 1: Write failing filesystem and process safety tests**

Cover path traversal, symlink/hardlink, existing file collision, digest/signature mismatch, executable mode, incomplete fsync/rename, inactive slot install, one active family process, no shell, fixed argv, non-root UID, graceful drain, crash restart, five-failure circuit and state recovery.

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/agent/pluginsupervisor ./internal/agent/pluginstate -count=1 -v; Pop-Location`

Expected: FAIL because Supervisor is absent.

- [ ] **Step 3: Implement package lease/download and atomic slots**

After Start fence, request `PluginArtifactLease` over AgentControl, download only from the returned DBPilot Server URL with existing CA, verify digest/signature again, install inactive slot, fsync and atomically switch only after health succeeds.

- [ ] **Step 4: Implement process supervision, drain, circuit and rollback**

Use `exec.CommandContext` with a fixed verified path and arguments; never `/bin/sh`. Track PID/start/restarts and bound output. On upgrade failure switch active back and reapply old configuration. Persist only non-secret state.

- [ ] **Step 5: Register typed executor and observations**

Implement a `ReconcilePlugin` executor under the existing two-phase registry. Add plugin observations to Heartbeat/Inventory with bounded counts and fixed errors.

- [ ] **Step 6: Run Linux and Kylin supervisor probes**

Cross-build a deterministic fixture plugin, prove install/start/single-process/rollback/circuit inside exact Kylin, and verify zero resources.

- [ ] **Step 7: Commit**

```powershell
git add -- backend/internal/agent/pluginsupervisor backend/internal/agent/pluginstate backend/internal/agent/commandverify.go backend/internal/agent/controlclient.go backend/cmd/agent
git commit -m "feat: supervise signed database plugins"
```

---

### Task 10: Implement the Private Plugin gRPC Gateway

**Files:**
- Create: `backend/internal/agent/plugingateway/client.go`
- Create: `backend/internal/agent/plugingateway/client_test.go`
- Create: `backend/internal/agent/plugingateway/peer_linux.go`
- Create: `backend/internal/agent/plugingateway/peer_other.go`
- Create: `backend/internal/agent/plugingateway/peer_linux_test.go`
- Create: `backend/internal/agent/plugingateway/metrics.go`
- Create: `backend/internal/agent/plugingateway/metrics_test.go`
- Modify: `backend/internal/agent/pluginsupervisor/supervisor.go`
- Modify: `backend/cmd/agent/main.go`

**Interfaces:**
- Consumes: generated PluginRuntime client and Task 9 launched process metadata.
- Produces:

```go
type Gateway interface {
    Handshake(context.Context, ExpectedPlugin) (Capabilities, error)
    ApplyConfiguration(context.Context, PluginConfiguration) error
    ValidateInstance(context.Context, string) (ValidationResult, error)
    CollectNow(context.Context, []string) error
    RunMetricStream(context.Context, MetricSink) error
    Shutdown(context.Context, time.Duration) error
}
```

- [ ] **Step 1: Write failing Unix peer and protocol tests**

Require socket 0600 under private runtime root, SO_PEERCRED PID/UID, `/proc/<pid>/exe` digest, launch nonce inherited FD, exact plugin/family/version/protocol, bounded messages, revision fencing, two-instance configuration and rejection of plugin-supplied scope fields.

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/agent/plugingateway -count=1 -v; Pop-Location`

Expected: FAIL because gateway is absent.

- [ ] **Step 3: Implement UDS dial, peer verification and handshake**

Dial only the expected Unix socket with insecure transport confined to filesystem permissions, then independently verify peer credentials and nonce. Reject TCP addresses and symlink sockets.

- [ ] **Step 4: Implement configuration and metric normalization**

Apply complete revisions atomically. Validate metric names/types/labels/timestamps, overwrite scope/Agent/host/instance from assignment, and append canonical batches to existing spool before acknowledgement.

- [ ] **Step 5: Run Linux protocol fixture**

Run a fixture plugin as the same non-root user, then negative PID/UID/executable/nonce/protocol cases. Verify metric batch reaches spool and no plugin connects to Server.

- [ ] **Step 6: Commit**

```powershell
git add -- backend/internal/agent/plugingateway backend/internal/agent/pluginsupervisor backend/cmd/agent
git commit -m "feat: connect agents to local database plugins"
```

---

### Task 11: Add Non-Persistent Credential Leases

**Files:**
- Create: `backend/internal/credentiallease/model.go`
- Create: `backend/internal/credentiallease/service.go`
- Create: `backend/internal/credentiallease/service_test.go`
- Create: `backend/internal/credentiallease/audit.go`
- Create: `backend/internal/credentiallease/audit_test.go`
- Create: `backend/internal/agent/credentialcache/cache.go`
- Create: `backend/internal/agent/credentialcache/cache_test.go`
- Modify: `backend/internal/agentcontrol/server.go`
- Modify: `backend/internal/agentcontrol/server_test.go`
- Modify: `backend/internal/agent/controlclient.go`
- Modify: `backend/internal/agent/plugingateway/client.go`
- Modify: `backend/cmd/controlplane/main.go`
- Modify: `backend/cmd/agent/main.go`

**Interfaces:**
- Consumes: Task 1 lease messages, Task 6 instance refs and Task 8 assignment revision.
- Produces:

```go
type SecretProvider interface {
    Resolve(context.Context, string) (Credential, error)
}

type Service interface {
    Lease(context.Context, AuthenticatedAgent, LeaseRequest) (Lease, error)
}
```

- [ ] **Step 1: Write failing secret non-persistence tests**

Require Agent/instance/assignment/revision match, TTL, nonce correlation, no lease in Job/Outbox/Audit detail/idempotency, no body logging, memory-only Agent cache, expiry zeroization, rotation and no secret in plugin state/errors.

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/credentiallease ./internal/agent/credentialcache ./internal/agentcontrol ./internal/agent -run 'TestCredential|TestLease' -count=1 -v; Pop-Location`

Expected: FAIL because lease service is absent.

- [ ] **Step 3: Implement Server lease validation and AgentControl response**

Handle lease messages outside Job persistence. Resolve `secret://` only after scope/assignment checks. Audit IDs/revision/result only. Bound TTL and response size; fixed errors conceal provider details.

- [ ] **Step 4: Implement Agent cache and plugin delivery**

Cache by instance+credential revision until expiry, never disk. Deliver through ApplyConfiguration over verified UDS. On removal/expiry overwrite buffers where practical and close plugin connection pools through a new config revision.

- [ ] **Step 5: Run secret scans and regressions**

Run focused tests plus `rg` scans for fixture secrets in tracked output. Verify server/Agent logs and retained artifacts contain no test credential.

- [ ] **Step 6: Commit**

```powershell
git add -- backend/internal/credentiallease backend/internal/agent/credentialcache backend/internal/agentcontrol backend/internal/agent backend/cmd
git commit -m "feat: lease database credentials to plugins"
```

---

### Task 12: Implement Metric Template Validation, Trial, Approval and Publication

**Files:**
- Create: `backend/internal/metrictemplate/model.go`
- Create: `backend/internal/metrictemplate/model_test.go`
- Create: `backend/internal/metrictemplate/validation.go`
- Create: `backend/internal/metrictemplate/validation_test.go`
- Create: `backend/internal/metrictemplate/postgres.go`
- Create: `backend/internal/metrictemplate/postgres_test.go`
- Create: `backend/internal/metrictemplate/postgres_integration_test.go`
- Create: `backend/internal/metrictemplate/service.go`
- Create: `backend/internal/metrictemplate/service_test.go`
- Create: `backend/internal/metrictemplate/migrate.go`
- Create: `backend/internal/metrictemplate/migrations/0001_metric_templates.sql`
- Create: `backend/internal/controlplane/metric_template_api.go`
- Create: `backend/internal/controlplane/metric_template_api_test.go`
- Modify: `backend/internal/pluginassignment/service.go`
- Modify: `backend/cmd/controlplane/main.go`

**Interfaces:**
- Consumes: Task 1 DTOs, Task 6 instances, Task 8 Jobs and Task 10 plugin CollectNow/ValidateInstance path.
- Produces:

```go
type DialectValidator interface {
    ValidateReadOnly(context.Context, TemplateDefinition) (ValidatedDefinition, error)
}

type Service interface {
    CreateDraft(context.Context, platformscope.Scope, Draft) (Revision, error)
    Validate(context.Context, platformscope.Scope, string, uint64) (Revision, error)
    StartTrial(context.Context, platformscope.Scope, string, TrialRequest) (job.Job, error)
    Approve(context.Context, platformscope.Scope, string, uint64, Actor) (Revision, error)
    Publish(context.Context, platformscope.Scope, string, uint64, PublishScope) (Revision, error)
}
```

- [ ] **Step 1: Write failing workflow and safety tests**

Require exact states, immutable revisions, creator/approver separation, AST single read-only query, 5s default/30s max timeout, rows/columns/labels/cardinality bounds, no raw trial rows, plugin/version compatibility and unpublished revision rejection.

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/metrictemplate ./internal/controlplane -run TestMetricTemplate -count=1 -v; Pop-Location`

Expected: FAIL because template service is absent.

- [ ] **Step 3: Implement workflow, persistence and fixed validation**

Store query text only in the protected revision record; Audit stores digest. The Server validator performs structural/bound checks, while the plugin performs the authoritative dialect AST check again before trial/publication use.

- [ ] **Step 4: Implement trial as a bounded Job**

Trial targets one managed instance, requests one execution, and stores only mapped candidate metrics plus row/column/count/duration diagnostics. Raw rows and driver messages are discarded before Result.

- [ ] **Step 5: Publish through assignment revisions**

Publication updates applicable instance template profiles and increments configuration revision, causing Task 8 reconciliation. Rollback selects a prior approved revision and creates a new monotonic publication revision.

- [ ] **Step 6: Run PostgreSQL and API tests**

Run: `Push-Location backend; go test ./internal/metrictemplate ./internal/pluginassignment ./internal/controlplane ./cmd/controlplane -count=1; Pop-Location`

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add -- backend/internal/metrictemplate backend/internal/pluginassignment backend/internal/controlplane backend/cmd/controlplane
git commit -m "feat: manage approved metric templates"
```

---

### Task 13: Build the Multi-Instance MySQL Plugin

**Files:**
- Create: `backend/internal/mysqlplugin/model.go`
- Create: `backend/internal/mysqlplugin/config.go`
- Create: `backend/internal/mysqlplugin/config_test.go`
- Create: `backend/internal/mysqlplugin/connections.go`
- Create: `backend/internal/mysqlplugin/connections_test.go`
- Create: `backend/internal/mysqlplugin/templates.go`
- Create: `backend/internal/mysqlplugin/templates_test.go`
- Create: `backend/internal/mysqlplugin/collector.go`
- Create: `backend/internal/mysqlplugin/collector_test.go`
- Create: `backend/internal/mysqlplugin/server.go`
- Create: `backend/internal/mysqlplugin/server_test.go`
- Create: `backend/cmd/dbpilot-plugin-mysql/main.go`
- Create: `backend/cmd/dbpilot-plugin-mysql/main_test.go`
- Create: `backend/test/fixtures/mysql-plugin/main.go`
- Create: `backend/scripts/verify-mysql-plugin.ps1`

**Interfaces:**
- Consumes: PluginRuntime service, CredentialLease payload, Task 12 published templates and go-sql-driver/mysql.
- Produces one linux plugin binary and the five canonical metrics:

```text
mysql.up
mysql.connections.current
mysql.queries.total
mysql.threads.running
mysql.uptime.seconds
```

- [ ] **Step 1: Write failing built-in metric and multi-instance tests**

Use sqlmock/fake opener to assert status mapping, metric types/units, counter reset, timestamp, two independent instance pools, per-instance timeout/circuit, plugin-wide semaphore and one failed instance not affecting another.

- [ ] **Step 2: Run tests and verify RED**

Run: `Push-Location backend; go test ./internal/mysqlplugin ./cmd/dbpilot-plugin-mysql -count=1 -v; Pop-Location`

Expected: FAIL because plugin is absent.

- [ ] **Step 3: Implement immutable built-in catalog and collector**

Register fixed template IDs and result mappings. Use one connection per instance for collection, bounded ping, no arbitrary statement input for built-ins, canonical metrics only and fixed/redacted errors.

- [ ] **Step 4: Implement configuration swap and PluginRuntime server**

Validate all instances/revisions/leases/templates in memory, build new pools, test them, then atomically swap and close old pools. Serve UDS with mode 0600, launch nonce and health/stream semantics from Task 10.

- [ ] **Step 5: Implement custom MySQL template AST enforcement**

Use `vitess.io/vitess/go/vt/sqlparser` behind a small `MySQLStatementParser` interface and pin its exact resolved version in `go.mod`. Reject DDL/DML/DCL, multi-statement, INTO OUTFILE/DUMPFILE, locks, procedures/functions with side effects and unbounded mappings. Repeat all Server hard limits.

- [ ] **Step 6: Run real two-MySQL Docker verification**

The verifier starts two MySQL 8 containers, launches one plugin, applies two instances, requires one PID/bound count 2, changes one connection count, collects all five metrics from both, proves isolation on one bad credential and exact cleanup.

Run: `powershell -NoProfile -File backend/scripts/verify-mysql-plugin.ps1`

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add -- backend/internal/mysqlplugin backend/cmd/dbpilot-plugin-mysql backend/test/fixtures/mysql-plugin backend/scripts/verify-mysql-plugin.ps1
git commit -m "feat: collect multi-instance MySQL metrics"
```

---

### Task 14: Create the React/TypeScript/Vite Application Shell

**Files:**
- Create: `frontend/app/package.json`
- Create: `frontend/app/package-lock.json`
- Create: `frontend/app/tsconfig.json`
- Create: `frontend/app/vite.config.ts`
- Create: `frontend/app/index.html`
- Create: `frontend/app/src/main.tsx`
- Create: `frontend/app/src/shell/AppShell.tsx`
- Create: `frontend/app/src/auth/AuthProvider.tsx`
- Create: `frontend/app/src/auth/oidc.ts`
- Create: `frontend/app/src/routing/router.tsx`
- Create: `frontend/app/src/api/client.ts`
- Create: `frontend/app/src/components/{PageHeader,DataTable,FilterBar,StatusTag,FormField,Drawer,ConfirmDialog,PermissionGate,AsyncBoundary}.tsx`
- Create: `frontend/app/src/styles/tokens.css`
- Create: `frontend/app/src/test/setup.ts`
- Create: `frontend/app/src/shell/AppShell.test.tsx`
- Create: `frontend/app/src/auth/AuthProvider.test.tsx`
- Create: `frontend/app/src/legacy/LegacyModuleHost.tsx`
- Modify: root `package.json`
- Modify: `.github/workflows/contracts.yml`

**Interfaces:**
- Consumes: existing generated TypeScript client, DBPilot CSS variables and OIDC claims.
- Produces:

```ts
export type ProjectContext = {
  authenticated: true;
  tenantId: string;
  projectId: string;
  permissions: ReadonlySet<string>;
};

export function useProjectContext(): ProjectContext;
export function useAccessToken(): () => Promise<string | undefined>;
```

- [ ] **Step 1: Add failing frontend shell/auth tests**

Assert Authorization Code+PKCE configuration, memory-only token storage, generated-client per-request token, project switch cancellation/cache clearing, permission gates, 401/403 no demo fallback and legacy mount isolation.

- [ ] **Step 2: Run tests and verify RED**

Run: `npm --prefix frontend/app test -- --run`

Expected: FAIL because React app is absent.

- [ ] **Step 3: Install exact major-compatible dependencies and commit lock**

Run from `frontend/app`:

```powershell
npm install --save-exact react@19 react-dom@19 react-router-dom@7 @tanstack/react-query@5 oidc-client-ts@3
npm install --save-dev --save-exact vite@7 @vitejs/plugin-react@5 typescript@5.9.2 vitest@3 @testing-library/react@16 @testing-library/user-event@14 jsdom@26
```

Commit the resolved exact versions in `package.json` and `package-lock.json`; do not use caret/tilde ranges or postinstall scripts.

- [ ] **Step 4: Implement shell, auth, routing and generated API boundary**

Keep tokens in React memory state only. Nginx same-origin `/api` is the production base. Build project/permission context from validated claims. Implement LegacyModuleHost without giving old modules direct token/storage access.

- [ ] **Step 5: Implement minimal internal components and visual tokens**

Reuse current colors/spacing and restrained enterprise style. Components must have keyboard/focus/ARIA tests and no raw HTML insertion for Server values.

- [ ] **Step 6: Run frontend and legacy regressions**

```powershell
npm --prefix frontend/app test -- --run
npm --prefix frontend/app run build
node --test frontend/tests
```

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add -- frontend/app package.json .github/workflows/contracts.yml
git commit -m "feat: add React management shell"
```

---

### Task 15: Implement React Host, Discovery and Instance Management

**Files:**
- Create: `frontend/app/src/features/hosts/{api,queries,HostListPage,HostDetailPage,types}.tsx`
- Create: `frontend/app/src/features/hosts/HostPages.test.tsx`
- Create: `frontend/app/src/features/discovery/{api,queries,CandidateListPage,CandidateDetailDrawer,AcceptCandidateWizard,types}.tsx`
- Create: `frontend/app/src/features/discovery/DiscoveryPages.test.tsx`
- Create: `frontend/app/src/features/instances/{api,queries,InstanceListPage,InstanceDetailPage,ConnectionTestPanel,types}.tsx`
- Create: `frontend/app/src/features/instances/InstancePages.test.tsx`
- Modify: `frontend/app/src/routing/router.tsx`
- Modify: `frontend/app/src/shell/AppShell.tsx`

**Interfaces:**
- Consumes: Task 1 generated host/discovery/instance clients and Task 14 shell.
- Produces routes `/hosts`, `/hosts/:id`, `/discovery`, `/instances`, `/instances/:id`.

- [ ] **Step 1: Write failing workflow tests**

Cover host status/metrics/plugin summary, native/Docker candidate filters, confidence/evidence, ignore, duplicate warning, accept wizard, credential reference selection, provisioning/connection status, stale/offline honesty, permission denial and project switch abort.

- [ ] **Step 2: Run tests and verify RED**

Run: `npm --prefix frontend/app test -- --run src/features/hosts src/features/discovery src/features/instances`

Expected: FAIL because pages are absent.

- [ ] **Step 3: Implement generated-client query hooks and pages**

Use TanStack Query keys containing tenant/project/resource filters. Mutations carry Idempotency-Key/If-Match and invalidate exact keys. Never construct duplicate DTOs or fall back demo in configured mode.

- [ ] **Step 4: Implement acceptance wizard states**

Make candidate confirmation, endpoint, variant, credential ref, TLS ref and review explicit steps. Show only fixed errors and Job progress. Never render secret values or full discovery command lines.

- [ ] **Step 5: Run accessibility/build tests**

Run feature tests, full React tests and `npm --prefix frontend/app run build`.

- [ ] **Step 6: Commit**

```powershell
git add -- frontend/app/src/features frontend/app/src/routing frontend/app/src/shell
git commit -m "feat: manage hosts and database instances"
```

---

### Task 16: Implement React Plugin and Metric Template Management

**Files:**
- Create: `frontend/app/src/features/plugins/{api,queries,PluginCatalogPage,PluginVersionDrawer,AssignmentPage,RolloutDialog,types}.tsx`
- Create: `frontend/app/src/features/plugins/PluginPages.test.tsx`
- Create: `frontend/app/src/features/templates/{api,queries,TemplateListPage,TemplateEditor,TrialPanel,ApprovalDrawer,PublishDialog,types}.tsx`
- Create: `frontend/app/src/features/templates/TemplatePages.test.tsx`
- Modify: `frontend/app/src/routing/router.tsx`
- Modify: `frontend/app/src/shell/AppShell.tsx`

**Interfaces:**
- Consumes: Task 7/8/12 APIs and Task 14 shared components.
- Produces routes `/plugins`, `/plugins/:id`, `/plugin-assignments`, `/metric-templates`, `/metric-templates/:id`.

- [ ] **Step 1: Write failing plugin/template UI tests**

Cover upload progress without file content logging, platform/signature/status display, deployment/stop/upgrade/rollback confirmation, desired/observed drift, circuit state, multi-instance count, template draft/validate/trial/approve/publish/rollback, self-approval denial and no raw trial rows.

- [ ] **Step 2: Run tests and verify RED**

Run: `npm --prefix frontend/app test -- --run src/features/plugins src/features/templates`

Expected: FAIL because pages are absent.

- [ ] **Step 3: Implement plugin catalog and assignment pages**

Use Artifact upload operation with bounded client file validation; Server remains authoritative. Render Job progress and observed state separately. Disable invalid transitions based on permissions and ETag.

- [ ] **Step 4: Implement template workflow pages**

Use a code editor configured as plain text without executing SQL. Show AST/bound diagnostics, mapped candidate metrics and counts only. Approval and publication are distinct actions.

- [ ] **Step 5: Run full React regression/build**

Run: `npm --prefix frontend/app test -- --run; npm --prefix frontend/app run build`

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add -- frontend/app/src/features frontend/app/src/routing frontend/app/src/shell
git commit -m "feat: manage plugins and metric templates"
```

---

### Task 17: Integrate Monitoring and Build the Full Production Acceptance Gate

**Files:**
- Modify: `backend/internal/monitoring/model.go`
- Modify: `backend/internal/monitoring/postgres.go`
- Modify: `backend/internal/controlplane/monitoring_http.go`
- Modify: `frontend/app/src/routing/router.tsx`
- Create: `frontend/app/src/features/monitoring/MonitoringPage.tsx`
- Create: `frontend/app/src/features/monitoring/MonitoringPage.test.tsx`
- Create: `backend/docker/host-plugin-full-stack/docker-compose.yml`
- Create: `backend/docker/host-plugin-full-stack/nginx.conf`
- Create: `backend/docker/host-plugin-full-stack/runner.Dockerfile`
- Create: `backend/test/e2e/host-plugin-full-stack/package.json`
- Create: `backend/test/e2e/host-plugin-full-stack/package-lock.json`
- Create: `backend/test/e2e/host-plugin-full-stack/playwright.config.mjs`
- Create: `backend/test/e2e/host-plugin-full-stack/acceptance.spec.mjs`
- Create: `backend/scripts/verify-host-plugin-full-stack.ps1`
- Create: `tests/contracts/host-plugin-full-stack.test.mjs`
- Create: `docs/host-database-plugin-operations.md`
- Modify: `README.md`
- Modify: `backend/README.md`
- Modify: `.github/workflows/contracts.yml`

**Interfaces:**
- Consumes: all prior tasks.
- Produces the complete first-release verification command:

```powershell
powershell -NoProfile -File backend/scripts/verify-host-plugin-full-stack.ps1 `
  -KylinImage 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' `
  -Architecture amd64 `
  -GoBinary 'C:\absolute\go.exe'
```

- [ ] **Step 1: Write failing monitoring and Compose contracts**

Require monitoring DTOs to distinguish host/plugin/database scope, preserve stale instead of zero, and expose five MySQL metrics. Parse Compose config to require exact images, only frontend loopback publication, no Agent/plugin Docker Socket, one helper, one MySQL plugin for two MySQL services, read-only artifacts/config/secrets and exact writable volumes.

- [ ] **Step 2: Run contracts and verify RED**

Run: `node --test tests/contracts/host-plugin-full-stack.test.mjs`

Expected: FAIL because topology and verifier are absent.

- [ ] **Step 3: Implement React monitoring page and Nginx build path**

Show host CPU/memory and database metric series with source/status. Migrate the real monitoring route to React while legacy modules remain mounted. Build Vite assets and serve them through query-safe same-origin Nginx logging.

- [ ] **Step 4: Implement self-cleaning full-stack verifier**

Sequence:

```text
build production Server/Agent/Helper/MySQL plugin
bootstrap PKI/OIDC/plugin publisher/package/enrollment token
start PostgreSQL + Server
enroll Kylin Agent
start restricted Docker Helper
verify host online + CPU/memory
discover native fixture + two Docker MySQL candidates
accept first candidate
verify Server deploys one MySQL plugin
accept second candidate
verify same plugin PID and bound_instance_count=2
verify five metrics for both instances
create/validate/trial/approve/publish custom template
reject unsafe SQL and high-cardinality trial
stop plugin and verify database metrics become stale
restart plugin and recover collection
attempt tampered/wrong-platform package
perform failed upgrade and automatic rollback
restart Agent and Server, verify desired/observed convergence
run final PostgreSQL/spool/journal/Audit assertions
clean exact resources and audit zero residuals
```

The verifier uses unique labels, bounded waits, safe failure artifacts, PS5.1/7-compatible process ownership and no broad deletion.

- [ ] **Step 5: Run complete release gates**

```powershell
npm run contracts:lint
npm run contracts:breaking
npm run contracts:verify
node --test
npm --prefix frontend/app test -- --run
npm --prefix frontend/app run build
Push-Location backend
go test ./... -count=1
go vet ./...
Pop-Location
powershell -NoProfile -File backend/scripts/verify-inspection-postgres.ps1
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1
powershell -NoProfile -File backend/scripts/verify-kylin-docker.ps1 -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' -Architecture amd64
powershell -NoProfile -File backend/scripts/verify-host-plugin-full-stack.ps1 -KylinImage 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' -Architecture amd64
```

Expected: all PASS, generated drift zero, and all verifier resources cleaned.

- [ ] **Step 6: Write and verify production operations documentation**

Document enrollment, Helper privilege boundary, plugin publisher keys, package upload, credential providers, template approval, rollout/rollback, circuit reset, backup/restore ordering, metric retention, CentOS/Kylin installation and release evidence still required on real hosts.

- [ ] **Step 7: Commit final integration**

```powershell
git add -- backend/internal/monitoring backend/internal/controlplane frontend/app backend/docker/host-plugin-full-stack backend/test/e2e/host-plugin-full-stack backend/scripts/verify-host-plugin-full-stack.ps1 tests/contracts/host-plugin-full-stack.test.mjs docs README.md backend/README.md .github/workflows/contracts.yml
git commit -m "test: verify host and database plugin platform"
```

## Spec Coverage Map

| Spec area | Implementing tasks |
| --- | --- |
| Confirmed architectural decisions and trust boundaries | Tasks 1, 3, 5, 7–11 |
| Host enrollment, inventory and liveness | Tasks 2–3 |
| Native process discovery | Task 4 |
| Restricted Docker discovery | Task 5 |
| Candidate dedupe and database instance management | Tasks 4–6, 8 |
| Plugin package, signatures, versions and revocation | Task 7 |
| Desired/observed state and reconciliation | Task 8 |
| Agent install slots, process lifecycle, circuit and rollback | Task 9 |
| Unix-socket plugin protocol and canonical metrics | Task 10 |
| Non-persistent credential leases and rotation | Task 11 |
| Metric template validation/trial/approval/publication | Task 12 |
| Multi-instance MySQL plugin and five metrics | Task 13 |
| React/TypeScript/Vite migration and OIDC PKCE | Task 14 |
| Host/discovery/instance pages | Task 15 |
| Plugin/template pages | Task 16 |
| Monitoring integration, full acceptance and operations | Task 17 |
| Framework-neutral Server boundaries | Tasks 2–8, 11–12 |
| Security, Audit, redaction and exact cleanup | Every task; final proof in Task 17 |

## Dependency and Concurrency Boundaries

- Task 1 is foundational and must complete before all other tasks.
- Task 2 depends on Task 1.
- Task 3 depends on Tasks 1–2.
- Task 4 depends on Tasks 1–3.
- Task 5 depends on Tasks 1 and 4; it may be implemented after Task 4 review.
- Task 6 depends on Tasks 2 and 4/5 candidate contracts.
- Task 7 depends on Task 1 and existing Artifact infrastructure; after Task 1 it can run in parallel with Tasks 2–5 only if it does not modify control-plane composition concurrently.
- Task 8 depends on Tasks 6–7 and must own changes to Job/command validation during its review window.
- Tasks 9–10 are sequential because they share Agent Supervisor and composition files.
- Task 11 depends on Tasks 6, 8 and 10.
- Task 12 depends on Tasks 6, 8, 10 and 11.
- Task 13 depends on Tasks 9–12.
- Task 14 depends only on Task 1 generated clients and can begin after Task 1, but Tasks 15–16 wait for their backend APIs.
- Task 15 depends on Tasks 2, 4, 5 and 6 plus Task 14.
- Task 16 depends on Tasks 7, 8 and 12 plus Task 14.
- Task 17 depends on every prior task.
- Never run two agents concurrently against `contracts/openapi`, `contracts/protobuf`, generated outputs, `backend/cmd/controlplane/main.go`, `backend/cmd/agent/main.go`, `frontend/app/src/shell`, root package locks or either full-stack Compose file.

## Completion Gate

- Every task has an independent spec-compliance review and code-quality review.
- Host enrollment, native discovery, Docker discovery, candidate acceptance, plugin deployment, multi-instance reuse, five MySQL metrics, custom template publication and React rendering are proven by real processes.
- One MySQL plugin PID serves two MySQL instances on one Agent.
- Host CPU/memory and `mysql.connections.current` traverse Agent/plugin → spool → mTLS → Server → PostgreSQL → API → browser.
- Tampered packages, wrong platform, unsafe templates, high cardinality, stale revisions, duplicate commands and unauthorized actions fail with fixed/redacted errors.
- Credentials and plugin/download signatures never enter persisted state, logs, DOM, Audit details or failure artifacts.
- Existing monitoring, alert, inspection, Job/Command, Artifact/Audit, Kylin and full-stack gates remain green.
- Generated OpenAPI/Protobuf clients have zero drift.
- Final Docker/temp resource audit is empty.
- Final whole-branch review has no unadjudicated Critical or Important issue.
