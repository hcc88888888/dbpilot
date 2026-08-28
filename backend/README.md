# DBPilot Agent telemetry foundation

For production alert-control-plane deployment, PostgreSQL retention,
identity/inventory integration, notification security, backup/restore, and the
Docker/Kylin evidence boundary, see
[`docs/alert-control-plane-operations.md`](docs/alert-control-plane-operations.md).

`dbpilot-agent` is a single embedded telemetry process for Linux. It does not
install, start, expose, or depend on Vector or a standalone OpenTelemetry
Collector process.

## Supported platforms and installation

Release builds support CentOS 7+ and Kylin V10+ on amd64. The build also emits
arm64 artifacts, but arm64 runtime support requires evidence from a native
arm64 Kylin runner or VM before release. Install the matching binary at
`/usr/local/bin/dbpilot-agent`, install
`packaging/systemd/dbpilot-agent.service`, copy the example configuration to
`/etc/dbpilot/agent.yaml`, and create a non-login `dbpilot` user.

The service writes only to `/var/lib/dbpilot-agent`. Make that directory and
the configuration/TLS directories owned by `dbpilot:dbpilot`; use mode 0700
for the data directory and 0600 for private keys and configuration. Do not run
the service as root. For journald collection, grant read access through the
host's `systemd-journal` group or an equivalent ACL before starting the unit.

```sh
systemctl daemon-reload
systemctl enable --now dbpilot-agent
systemctl status dbpilot-agent
```

## Bootstrap configuration and trust

The required bootstrap fields are Agent ID, DBPilot server address, CA,
certificate, private-key, policy-public-key, data directory, and allowed log
roots. All secret and data paths must be absolute. The Agent rejects a missing
TLS file, relative path, a world-writable Linux data directory, and an empty
allowed-root list when file collection is enabled.

The bootstrap file is not a policy surface. DBPilot supplies signed, versioned
policy envelopes; the Agent verifies them before activation and only accepts
the closed source kinds `FILE_LOG`, `JOURNALD`, `HOST_METRICS`, `PROMETHEUS`,
`HTTP_JSON_METRICS`, `SQL_METRICS`, and `PLUGIN_METRICS`. It never accepts raw
collector documents, arbitrary executables, or shell commands.

On startup the Agent verifies and activates its last valid stored policy when
the server is unavailable. A newer remote policy is atomically checked before
it replaces the active pipeline; a failed candidate leaves the prior pipeline
running and reports `ROLLED_BACK`. Reverting policy requires a newly signed,
monotonically higher policy version rather than an unsigned local edit.

Telemetry leaves only through mutually authenticated DBPilot gRPC. Configure
the CA, Agent certificate, and Agent key from the bootstrap configuration;
the gateway authenticates the SPIFFE Agent identity in the client certificate.

## Spool and health behavior

Payloads are stored in CRC-protected segment files under the data directory;
bbolt stores only state, checkpoints, indexes, and deduplication metadata.
Accepted batches are removed only after the gateway acknowledgement. During an
outage, collectors continue and the exporter retries from the spool. Metrics
and ordinary logs may be evicted under the signed capacity limit; unacknowledged
audit logs are never silently discarded. Important health findings include
`AUDIT_SPOOL_FULL`, `AUDIT_SPOOL_IO_FAILURE`, `CORRUPT_SEGMENT`, and telemetry
permanent-rejection findings.

Upgrade by stopping the unit, replacing the binary, and starting it again;
the local spool and last known valid policy allow recovery. To roll back a
binary, restore the prior binary and restart the unit. Do not delete the data
directory unless intentionally discarding pending telemetry.

## Build and smoke evidence

Use an absolute Go 1.27.0 executable path. The build emits both
`dbpilot-controlplane` and `dbpilot-agent` for linux/amd64 and linux/arm64,
always with `CGO_ENABLED=0`, plus SHA-256 files:

```powershell
powershell -File .\scripts\build-linux.ps1 -OutputDirectory "$pwd\bin" -Version 0.1.0-test -GoBinary 'C:\absolute\path\to\go.exe'
```

The smoke commands to record on dedicated Linux VMs are:

```sh
dbpilot-agent --version
dbpilot-agent --config /etc/dbpilot/agent.yaml
systemctl restart dbpilot-agent
journalctl -u dbpilot-agent --since '5 minutes ago'
```

Run those commands on CentOS 7 amd64, Kylin V10 amd64, and Kylin V10 arm64
with a real mTLS test gateway and journald permissions. This Windows worktree
cannot record those Linux-specific systemd/journald results; release approval
requires attaching the three runner logs.

### Windows Docker/Kylin verification

Windows development can verify both Linux executables inside the exact
`cr.kylinos.cn/kylin/kylin-server-platform:v10sp1` image. The verifier builds
both architectures, executes each selected-architecture binary with `--version`, starts the Agent with a signed
sample policy, proves its bbolt command journal opens and closes, and runs a
real mTLS AgentControl probe against the production Agent. The probe requires
the Agent to advertise `collect_now`, sends signed Prepare and fenced Start,
runs the configured JMX-backed `DependencyCollector`, verifies the typed
Result, returns ResultAck, and then confirms the journal marks that exact result
reported. It also resolves the command execution-token and Artifact signing
credentials, validates the private Artifact storage root, and starts the
control plane through readiness initialization until the expected PostgreSQL
connection failure. It rejects missing Docker/images, non-Kylin
`/etc/os-release`, architecture mismatches, and unexpected startup failures;
it requires the exact Kylin V10/Tercel release identity, always removes only
the uniquely named container it created plus temporary keys/binaries, and never
substitutes a generic Linux image.

```powershell
powershell -NoProfile -File .\scripts\verify-kylin-docker.ps1 `
  -Image 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' `
  -Architecture amd64
```

This container check covers executable compatibility and bootstrap startup.
Systemd, journald ACLs, kernel metrics, eBPF, and real Kylin service behavior
must still be verified on Kylin V10 amd64/arm64 VM or bare-metal runners.
An arm64 invocation is accepted only on a native arm64 Docker host; emulation
is not production runtime evidence.

## Contract and command lifecycle workflow

Edit only the canonical OpenAPI/Protobuf sources under `../contracts`, then run
from the repository root:

```powershell
npm ci
npm run contracts:lint
npm run contracts:breaking
npm run contracts:generate
npm run contracts:verify
node --test
Push-Location backend; go test ./...; Pop-Location
npm run contracts:mock:test
powershell -NoProfile -File backend/scripts/verify-contract-foundation.ps1
```

Commit the generated Go strict server/client, permissions, protobuf, and
TypeScript client trees. Do not hand-edit `gen/` or `frontend/generated/`.
The standard Node suite intentionally reports one skipped Prism integration;
the explicit mock test is the live, self-cleaning Prism check.

Agent Hello capability negotiation is authoritative: the dispatcher sends only
typed command envelopes the live Agent advertised. Delivery is at-least-once;
`command_outbox.id` is the immutable `command_id`, while the first fully signed
envelope is atomically persisted and reused byte-for-byte for every Prepare
retry. The signed envelope has a fixed 24-hour delivery deadline beginning at
first preparation. Prepare only synchronously stores the complete envelope and
digest in the Agent bbolt journal. It never invokes an executor.

After `CommandPrepared`, the control plane locks the Job, target, and command in
PostgreSQL. If cancellation has not won, it atomically commits
`start_authorized`, a random execution-token hash/ciphertext, the execution
revision, and the initial deadline before sending `CommandStart`. Only an exact
token/revision match may enter running. If cancellation commits first, no Start
fence is created and an unfenced Cancel removes the Agent's prepared entry. If
Start commits first, cancellation replays the identical persisted Start before
sending a fenced Cancel; the final Job state follows the Agent's honest Result,
including success after a late cancellation request.

Active heartbeats carry the execution token and revision. PostgreSQL renewal
increments the recovery revision and clears any timeout claim. A timeout worker
may finalize only when its claim token, claimed deadline, and claimed recovery
revision still match, so stale workers cannot overwrite a heartbeat or Result.
Execution results are also fenced by token/revision and keep large output in
Artifact references rather than inline payloads.

The Agent retains every terminal Result until `CommandResultAcknowledgement`
has `persisted=true` and the exact result digest. The control plane emits that
Ack only after the Command/Job/target/Artifact references and idempotent Audit
evidence are durable. A crash before Ack causes reconnect replay of the same
Result. If an Agent process restarts with a running journal entry, it does not
run the executor again: it reports `EXECUTION_INTERRUPTED`, the control plane
records durable timed-out evidence, and operators must inspect the target
database before deciding whether remediation or a new command is safe.

The control plane reads an Ed25519 PKCS#8 signing key once from
`command.signing_private_key_ref` and a separate exact 32-byte AES key from
`command.execution_token_key_ref`; Agents receive only the matching PKIX public
key. Arbitrary shell commands are never part of the protocol.

HTTP idempotency persists the phases `processing → side_effect_committed →
audited → completed`. Cancellation responses and Artifact download descriptors
are stored before Audit. A same-fingerprint retry from
`side_effect_committed` uses the original request/trace identity and stable
Audit dedupe key to repair Audit and complete the saved response without
repeating Job cancellation or signing a second descriptor. A bare `processing`
row has no proof that a side effect committed and is therefore not guessed or
automatically reclaimed.

Artifact readiness is a startup boundary: the local storage root must be a
private, openable directory and the signing Credential Reference must resolve
to an acceptable key before the capability or HTTP download path becomes
ready. Startup fails closed rather than advertising an unusable Artifact
service.

The current `/api/v1` contract has one pre-stable migration window. After
workorder, SQL window, SQL review, slow SQL, audit log, locks, schema diff and
reports all use generated clients and strict handlers, v1 changes are
additive-only.

## Database adapter integration verification

The database adapter integration suite uses disposable MySQL 8 and PostgreSQL
16 containers on a dedicated Docker network. The containers publish no host
ports, use tmpfs-backed data directories, and create restricted non-production
reader accounts. They are database test fixtures, not Kylin compatibility
containers and do not make any claim about Kylin support.

Run the Windows verifier from `backend` with Docker Desktop running:

```powershell
powershell -File .\scripts\verify-database-adapters.ps1
```

The verifier locates Docker Desktop, waits for service health, reports both
server versions, runs the real integration test in the isolated Compose
network, and removes the containers and temporary data on every exit path.
For a manually managed environment, set `DBPILOT_DB_INTEGRATION=1`,
`DBPILOT_MYSQL_ADDRESS`, `DBPILOT_MYSQL_DATABASE`, `DBPILOT_MYSQL_USER`,
`DBPILOT_MYSQL_ADMIN_USER`, `DBPILOT_POSTGRES_ADDRESS`,
`DBPILOT_POSTGRES_DATABASE`, `DBPILOT_POSTGRES_USER`,
`DBPILOT_POSTGRES_ADMIN_USER`, `DBPILOT_SECRET_INTEGRATION_MYSQL`,
`DBPILOT_SECRET_INTEGRATION_MYSQL_ADMIN`,
`DBPILOT_SECRET_INTEGRATION_POSTGRES`, and
`DBPILOT_SECRET_INTEGRATION_POSTGRES_ADMIN` before running `go test
./internal/database`. The test only uses pre-registered metric templates and
resolves credentials through the runtime `secret://integration/...` boundary;
do not put credentials in telemetry policy documents or logs.

## HBase dependency observability runtime

The Agent registers trusted `hbase`, `hdfs`, and `zookeeper` component
definitions from `agent.yaml` and wires them into the production `Runtime`.
`component_secrets.provider: environment` resolves a reference such as
`secret://hbase/reader` from `DBPILOT_SECRET_HBASE_READER`; secret values are
never stored in the configuration or spool. Definitions use only
allowlisted read-only `/jmx` (or the ZooKeeper read-only monitor compatibility
path) endpoints and canonical runtime Secret/TLS references. The collector
resolves HBase dependency IDs before collection, registers HDFS and ZooKeeper
before HBase, applies bounded request deadlines and exponential retry, and
runs under the Agent lifecycle. Shutdown closes these adapters before the
existing telemetry engine stops and before the spool is sealed.

Each collection writes a deterministic JSON envelope to the existing metric
spool. It includes normalized samples, per-component `ok`/`partial`/`failed`
status events, role-and-host-level health, and correlation-only dependency evidence.
The batch ID includes a durable monotonic collection sequence. The Agent
advances that sequence only after the batch append succeeds, so an interrupted
append/checkpoint boundary replays the same ID safely after restart, while a
new same-clock collection receives a distinct ID.
Endpoint URLs, response bodies, credentials, and TLS material are excluded
from the envelope and status errors.

The disposable Compose fixture uses three authenticated static JMX services
plus one deliberately unavailable HBase endpoint on
one dedicated bridge network. It publishes no host ports, runs the fixtures
read-only without Linux capabilities, and health-checks every service. Run the
Windows verifier from `backend`:

```powershell
powershell -File .\scripts\verify-hbase-dependencies.ps1 `
  -DockerBinary "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin\docker.exe" `
  -GoBinary 'C:\absolute\path\to\go.exe'
```

By default the script cross-builds and starts the actual `dbpilot-agent`
binary, loads a generated restricted `agent.yaml`, collects the fixture JMX
endpoints through the production `Runtime`, stops the Agent with SIGTERM, and
decodes the resulting dependency batch from the spool inside the approved
`cr.kylinos.cn/kylin/kylin-server-platform:v10sp1` Kylin V10 image. Pass a
different approved image with `-KylinImage`; use `-SkipKylin` only for a local
Docker fixture check. Every exit path removes the Kylin container, Compose
containers, networks, and disposable Go cache volumes, and reports cleanup
failures.

This fixture proves parser/contract and Agent runtime-path behavior; its static
JMX services are not full HBase, HDFS, or ZooKeeper distributions. A production
endpoint-to-endpoint support claim still requires matching-version clusters and
Kylin V10 VM or bare-metal evidence with real service health, networking, and
credentials.
