# Host and database plugin operations

This runbook covers the first production profile: DBPilot Server, one
unprivileged Agent per host, the optional restricted Docker discovery helper,
and one independently supervised database-plugin process per Agent and
database family. The first release evidence is Linux amd64 on the exact image
`cr.kylinos.cn/kylin/kylin-server-platform:v10sp1`; supported installation
targets are CentOS 7+ and Kylin V10+.

## Trust and privilege boundaries

- Host metrics and native discovery stay in Agent core. Database SQL and
  database metrics run only in the independent database-plugin process.
- One plugin process serves every accepted instance of the same database
  family on an Agent. Never deploy a process per database instance.
- The Agent and database plugins must not mount, open, or proxy the raw Docker
  Socket. Only `dbpilot-docker-discovery` may have that mount.
- Install the Agent as a dedicated non-root identity with no Linux
  capabilities. Install the Docker helper as a different identity and allow
  only that identity into the Docker Socket group. The helper verifies the
  Agent UID/GID with `SO_PEERCRED` and returns only allowlisted, bounded
  discovery fields.
- Restrict the helper to explicitly configured Docker network names. Internal
  endpoints must contain a literal container-network IP and port; empty,
  hostname-only, non-IP, or non-allowlisted network observations are rejected.
- Keep configuration, trust roots, plugin packages, and secret mounts
  read-only. Give the Agent separate writable roots for its spool, command
  journal, plugin slots/state, and private plugin runtime sockets.

The packaged systemd profiles and installation details are in
`backend/packaging/systemd/README-native-discovery.md` and
`backend/packaging/systemd/README-docker-discovery.md`.

## Enrollment

1. Install the optional native and Docker helpers before enrollment and verify
   their socket ownership locally. Server cannot grant host privileges.
2. Create a one-time enrollment through the canonical host-enrollment API.
   Deliver the token through a protected file, never a command line or log.
3. Run `dbpilot-agent enroll` with absolute CA, token, and output-directory
   paths. It collects canonical `linux/amd64` platform inventory, creates a
   local Ed25519 key, proves CSR ownership, and writes the returned Agent
   certificate with private permissions.
4. Delete the consumed enrollment-token file. Start the Agent with the issued
   mTLS material and verify the Host becomes online with non-empty CPU and
   memory observations.
5. Confirm native discovery and, when enabled, Docker discovery have separate
   source results. A helper failure must not stop core telemetry or native
   discovery.

Re-enrollment creates a new one-time token and certificate generation. Do not
copy an Agent data directory, private key, spool, or journal to another host or
Agent identity.

### One-time generation-zero upgrade window

Use this window only for a pre-feature Host that is already persisted with
credential generation `0`, has no enrollment issuance, and still owns its
original CA-trusted Agent leaf. Prefer canonical re-enrollment whenever the
Agent can receive a one-time token.

1. Back up PostgreSQL and record the exact `agent_id`, `tenant_id`,
   `project_id`, and persisted `host_id` for every eligible active Host. Do not
   use labels, hostnames, globs, or a tenant-wide switch as import scope.
2. Add `enrollment.generation_zero_import.enabled: true` and one exact entry
   under `targets` for each recorded Agent. The Agent must also exist in the
   static `agents` map with the same tenant and project. Run the offline
   configuration check:

   ```bash
   dbpilot-controlplane --config /etc/dbpilot/controlplane.yaml --check-config
   ```

3. Restart the Server. After migrations, startup preflight verifies each
   target is either an eligible generation-zero Host with no issuance/import,
   or the same already-imported generation-one Host. A missing, moved,
   decommissioned, normally enrolled, or later-generation target prevents
   listeners from opening.
4. Start one listed Agent at a time with its existing client certificate. The
   normal mTLS chain verification and unique `spiffe://dbpilot.local/agent/...`
   SAN check run before import. PostgreSQL atomically claims that exact leaf's
   SHA-256 fingerprint and serial as generation `1`, writes one
   `agent_credential_imports` record, and writes the fixed
   `host.credential_generation_zero_imported` Audit event. A competing leaf,
   Agent, scope, or concurrent claim fails closed.
5. Verify the listed Host is generation `1`, its AgentControl session and
   Artifact requests succeed only with the claimed leaf, and the import/Audit
   counts are exactly one. Restart once while the window is still enabled to
   verify the persisted claim is accepted without a second import.
6. Close the window immediately: stop the Server, set `enabled: false`, remove
   every target, rerun `--check-config`, and restart. Keep it closed. Exact-leaf
   admission remains available from the persisted Host projection; a different
   leaf now requires canonical replacement enrollment.

Never reopen the window for a decommissioned Host, delete an import record to
retry a different certificate, or copy the claimed private key to another
Agent. Investigate a failed preflight from the scoped Host/import/issuance and
Audit records without printing certificate material.

## Plugin publishers and packages

Configure at least one Ed25519 publisher public key before enabling the plugin
catalog. Keep publisher private keys outside Server and Agent hosts. Rotate by
adding the new public key, publishing packages signed by it, moving assignments
to those packages, and only then removing the old trust root.

Upload the deterministic `.tar.gz` with the canonical plugin-version API. The
Server and Agent independently verify the logical-content signature, manifest,
platform binary, archive paths, sizes, and SHA-256 values. Approve and publish
are separate authorized transitions; only `available` versions can be newly
assigned. Tampered packages and a package without `linux/amd64` must fail
closed. Never include package bytes, private keys, signed download URLs, or
archive contents in logs, Audit details, Problems, or retained failure
artifacts.

The control plane's `artifact.plugin_lease_origin` must be the direct HTTPS
origin reachable by Agents with their client certificate, not a browser TLS
terminator. Configure the same origin as the Agent plugin
`artifact_origin`. Short-lived lease URLs and headers remain memory-only.

Before upgrading a deployment that already has `plugin_catalog.enabled: true`,
add `artifact.plugin_lease_origin` and run the offline preflight before stopping
the old Server:

```bash
dbpilot-controlplane --config /etc/dbpilot/controlplane.yaml --check-config
```

The command parses known fields and validates the complete configuration but
does not open PostgreSQL, load runtime secrets, or bind listeners. A missing or
non-HTTPS Agent-reachable origin fails with a fixed configuration error; do not
derive it from a browser URL or wildcard listener. After preflight succeeds,
restart the Server and confirm the Agent's `plugin.artifact_origin` names the
same direct mTLS origin. Existing enrolled rows whose historical
`operating_system` is `kylin` or `centos` are compatibility-mapped to the
canonical execution OS `linux` for package selection; their displayed distro
and version fields remain unchanged.

## Credentials

Database instances store only an opaque `secret://` credential reference and,
optionally, a separate TLS reference. The current production provider resolves
an allowlisted reference from a Server environment variable and sends an
operation-bound, short-lived credential lease over the authenticated control
stream. Do not put usernames/passwords, credential references, or lease
material in telemetry policy, plugin configuration files, Audit detail, DOM,
or logs.

Rotate a credential in the provider, increment its provider revision, and
observe successful lease renewal and healthy collection before revoking the
old database credential. A new reconcile operation uses its live command
execution fence; renewal of the same revision uses the durable prior-lease
audit fence. Repeated `waiting_credentials` is an actionable failure: verify
the assignment operation revision, credential provider binding, Agent session,
and hashed credential-lease Audit records without printing the secret.

## Discovery and instance acceptance

Review candidate family, variant, endpoint, evidence summary, confidence, and
source freshness before accepting it. For Docker candidates, the API exposes
only the allowlisted internal address and container identity; raw inspect data
and the internal container ID never leave the discovery domain.

Accepting the first candidate creates a managed instance and one family
assignment. Accepting a second MySQL candidate on the same Agent must reuse the
assignment and PID while increasing `bound_instance_count` to two. A matching
healthy plugin observation proves `ValidateInstance` and advances all exact
assignment members to `managed`.

## Metric templates

Built-in MySQL collection exposes exactly:

- `mysql.up`
- `mysql.connections.current`
- `mysql.queries.total`
- `mysql.threads.running`
- `mysql.uptime.seconds`

For a custom template, create a revision, run Server-side MySQL AST validation,
run a bounded trial against one managed instance, and require a different
authorized approver before publish. Trials retain only mapped aggregate metric
metadata; raw SQL rows and SQL bodies must not enter Audit or retained
artifacts. Unsafe/multi-statement/write SQL and high-cardinality output fail
closed. Published immutable revision IDs are carried by assignment
configuration; changing a template creates a new revision.

## Rollout, stop, rollback, and circuit reset

Use the assignment API with `If-Match` and a unique idempotency key. Observe
desired version/state, configuration and operation revisions, installed
version, PID, health, bound count, and last fixed error code. Stop drains the
process without synthesizing database metric zeroes; retained series become
`stale` with null buckets while Agent host telemetry remains live. Restart must
reuse the assignment and recover credential leases and collection.

An upgrade installs into the inactive slot. Failed start or handshake restores
the prior signed slot and reports `plugin_upgrade_rolled_back`; verify the old
installed version and all bound instances before restoring the desired version.
Five failures inside the configured window open the circuit. Investigate the
fixed error code, then use the canonical assignment reconcile action after the
cause is removed; do not delete slot/state files or edit revisions manually.

## Backup, restore, and retention

Back up in this order:

1. quiesce control-plane mutation/reconciliation workers;
2. take a transactionally consistent PostgreSQL backup;
3. copy the immutable artifact blob root corresponding to that database
   snapshot and verify checksums;
4. stop each Agent and separately back up its identity-bound data root if local
   command-journal/spool recovery is required.

Restore PostgreSQL first, then the exact artifact blobs, verify migrations and
catalog-to-blob checksums, and start Server. Restore an Agent data root only to
the same Agent/Host identity with private ownership; then start local helpers
and the Agent and wait for desired/observed convergence. Never restore a spool
without its journal/checkpoints or delete an unacknowledged spool to make a
health check green.

Retain Audit and plugin/catalog lifecycle records according to the production
audit policy. Apply metric-sample retention only after required reporting
windows; keep `monitoring_instances` state so an empty display range remains a
known stale/offline series. Artifact deletion requires proving no available,
desired, active, or rollback slot references the package. Raw trial rows,
credential material, and signed URLs have no retention class because they must
never be persisted.

## Release verification

On a prepared Windows amd64 runner with Docker Desktop and the exact local
Kylin image:

```powershell
powershell -NoProfile -File backend/scripts/verify-host-plugin-full-stack.ps1 `
  -KylinImage 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1' `
  -Architecture amd64 `
  -GoBinary 'C:\absolute\go.exe'
```

The verifier owns a unique labelled Compose project, publishes only the
frontend on an ephemeral loopback port, records exact container/network/volume
IDs, removes only those resources, and audits zero residuals. It never prunes,
uses wildcard deletion, or mounts the Docker Socket outside the restricted
helper. Failure artifacts are redacted and must be reviewed before retention.

This gate proves the exact Kylin container/linux-amd64 topology. Production
release still requires real CentOS 7 amd64 and Kylin V10 amd64 VM or bare-metal
evidence for systemd, journald/ACLs, kernel/procfs behavior, local Docker Socket
policy, filesystem ownership, restart/upgrade, and backup/restore. Arm64 is not
production-supported until the equivalent native Kylin arm64 evidence exists.
