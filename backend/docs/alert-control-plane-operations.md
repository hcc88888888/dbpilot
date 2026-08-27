# Alert control-plane operations

This guide covers the production PostgreSQL-backed alert control plane, its
authenticated Agent inventory, notification egress, recovery, and the limits
of the Docker/Kylin compatibility verifier.

## Runtime boundary and readiness

Run the control plane on a private management network. Expose the HTTPS API
only through the approved enterprise ingress and the gRPC listener only to
enrolled Agents. Both listeners require TLS; Agent ingestion always requires a
verified SPIFFE client certificate. In `identity.mode: mtls`, the HTTPS API
also requires a verified client certificate whose URI is present in the
configured principal inventory.

`GET /healthz` proves only that the HTTP process can answer. The listeners bind
only after migrations succeed. Once bound, `GET /readyz` requires a successful
PostgreSQL ping, one complete evaluation/list/dispatch pass for every configured
scope, no current evaluator error, and zero failed rules. An evaluation, event
listing, dispatch, or database failure makes readiness fail closed. Although
the readiness predicate also compares the evaluator's `queue_depth` field with
zero, the production evaluator does not currently populate that field, and the
notification retry backlog is not a readiness input. Monitor retry-scheduled
deliveries separately. The scoped `overview` response reports evaluator health;
alert on sustained unready state and inspect database reachability, evaluator
failures, late runs, dispatcher errors, and retry backlog before restarting.

Use a rollout that waits for `/readyz` before adding an instance to service.
During planned database maintenance, remove instances from service first and
allow their bounded shutdown to stop evaluation and retry workers.

## PostgreSQL migrations, partitions, and retention

The server runs embedded migrations before it binds either listener. Back up
the database before upgrading, deploy one control-plane instance first, wait
for readiness, and then roll the remaining instances. Never edit an applied
migration. Diagnose and correct the database or release artifact if migration
startup fails.

`metric_samples` is range-partitioned by `sampled_at`. The initial migration
creates the installation day plus six future daily partitions; production
operations must create future daily partitions before telemetry reaches them.
Run a daily privileged maintenance job that creates at least seven days ahead,
verifies the partition bounds, and alerts before the newest partition is less
than 48 hours away. The control-plane database role should not own this DDL
job.

Retention is an operator policy, not a control-plane background task. Apply it
per data class and compliance requirement:

- Drop expired `metric_samples_YYYYMMDD` partitions after the metric-retention
  window. Do not issue a large row delete against the partitioned parent.
- Delete terminal `notification_deliveries` only after their associated
  `in_app_notifications` retention permits it. Retain retry-scheduled and
  attempting rows.
- Retain `alert_events` long enough for incident history and delete only
  resolved events whose notification history and audit requirements are met.
- Treat `alert_audit_log` as immutable compliance data. Archive and verify it
  before any authorized expiry; application operators must not update rows.
- Expire `ingest_batch_dedup` only after the maximum Agent replay/spool window.
  Deleting it too early can re-accept an old batch.

Run retention with tenant/project predicates where rows are deleted, bounded
batches, statement timeouts, and pre/post row counts. Test the exact procedure
on a restored backup before production use.

## Inventory and role integration

The `agents` map is the authoritative Agent-to-scope inventory. Its key must
equal the final path segment of the verified Agent certificate URI
`spiffe://dbpilot/agent/<agent-id>`. The mapped `tenant_id` and `project_id`
are applied server-side; telemetry payloads cannot claim or override scope.
Treat an inventory move as a security change: stop the Agent, revoke or rotate
its certificate, change the assignment, verify no pending spool belongs to the
old scope, and then reenroll it.

For operator API identity, integrate the enterprise certificate issuer or a
trusted `PrincipalResolver` adapter. Static mTLS principals support either
`platform_admin: true` or an explicit list of tenant/project assignments. Use
least privilege and test a same-tenant, different-project request for HTTP 403
before rollout. `local_headers` is a loopback-only development mode; never
place it behind a proxy that accepts caller-supplied identity headers.

Changes to rules, policies, templates, silences, and manual event transitions
carry the authenticated subject into the audit transaction. Do not bypass the
scoped HTTP API with direct application-table writes.

The packaged non-root Agent service layout must create its data directory and
the private embedded-collector file-storage directory before dropping
privileges. The latter is `dbpilot-spool/<sha256(agent-id)>`, owned by the
Agent account, with no group or other write permission. The compatibility
verifier performs this installation step and then proves that the production
policy engine starts as uid 65532. Treat a missing or wrongly owned directory
as a packaging failure; do not run the Agent as root to work around it.

## Secret references and rotation

Notification policies store references, never resolved values. The production
resolver accepts `env://NAME`; `NAME` must identify a process environment
entry provisioned by the platform secret manager. The API exposes only
`has_secret`, and delivery responses omit the retry envelope, request body, and
secret reference. TLS certificates, private keys, and CA bundles are absolute
file paths in the server and Agent bootstrap configuration. Compose secrets in
the verifier are disposable test credentials, not a production secret format.

For SMTP/Webhook credential rotation, provision the new value under the same
environment name, roll the control-plane instances, verify a canary delivery,
and then revoke the old value. If the secret name changes, update the policy
reference through the scoped API only after all instances can resolve it. For
certificate or CA rotation, distribute the new CA trust first, overlap old and
new identities, rotate leaf certificates and inventory, verify both listeners,
then remove the old CA. Never print secret values, private keys, rendered
delivery bodies, or database URLs containing passwords in diagnostics.

## SMTP and Webhook egress policy

SMTP delivery requires TLS. Configure an implicit-TLS or STARTTLS endpoint,
the exact TLS server name, a valid sender mailbox, and an approved CA chain.
Restrict the account to sending DBPilot notifications and monitor 4xx retries
and terminal TLS/authentication failures.

Webhook targets must be HTTPS, use an exact lowercase hostname on
`webhook_allowlist`, resolve only to globally routable addresses, and must not
redirect. DBPilot validates DNS again at dial time and signs the rendered body
with `X-DBPilot-Timestamp` and `X-DBPilot-Signature`. The receiver must verify
the HMAC over the raw body, reject stale timestamps, deduplicate by delivery
identity, cap request size, and avoid logging evidence bodies. A private,
loopback, link-local, documentation, or special-use destination is rejected
even when its hostname is allowlisted.

The repository's SMTP and Webhook sinks are verifier fixtures only. They store
hashes and counters, publish no host ports, and are not production relays.

## Backup and restore ordering

Back up PostgreSQL with a transactionally consistent physical backup or
`pg_dump` including schema, partition children, sequences, constraints, and
data. Back up the control-plane configuration, Agent inventory, certificate
inventory, and secret-manager metadata separately. Verify all backup artifacts
and record the migration version; do not place resolved secrets in the database
backup bundle.

Restore in this order:

1. Stop control-plane writers and keep Agents disconnected; preserve Agent
   spools.
2. Restore PostgreSQL schema and data, including metric partitions, delivery
   leases/idempotency keys, dedup state, and audit records.
3. Restore secret-manager entries and TLS/CA files at their referenced paths,
   then restore identity and Agent inventory configuration.
4. Start one control-plane instance. Let forward migrations complete, verify
   PostgreSQL counts and constraints, and require `/readyz` success.
5. Start the remaining control-plane instances, then reconnect Agents in
   batches so durable spools replay against restored dedup state.
6. Verify firing/resolved events, pending retries, in-app records, audit
   continuity, and future metric partitions before reopening operator access.

Never restore only `notification_deliveries` without events, policies,
templates, and audit records. Never discard Agent spools merely to make a
restore appear quiet.

## Docker/Kylin evidence and release approval

From `backend`, run the disposable evidence suite with explicit binaries and
an approved, locally available Kylin V10 image:

```powershell
powershell -File .\scripts\verify-alert-control-plane.ps1 `
  -GoBinary '<absolute go.exe>' `
  -DockerBinary '<absolute docker.exe>' `
  -KylinImage 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'
```

The verifier rejects a missing/non-Kylin image, any Compose host-port
publication, a non-internal fixture network, or a generated secret found in
service logs. A successful run requires both Compose and production-Agent logs
to be collected; log acquisition failure fails the secret-echo gate closed.
Failure diagnostics remain best-effort and sanitized. The verifier runs
PostgreSQL 16, the real control plane, hash-only SMTP and Webhook sinks, and a
real `dbpilot-agent` process in Kylin; the lifecycle test uses the production
HTTPS and mTLS gRPC listeners. The control plane emits a body-free acceptance
record only after authenticating the Agent's policy-status RPC, and the verifier
waits for the real Agent's version-1 record before reporting mTLS evidence. A
deterministic metric envelope is sent by the fixture's Agent identity over that
same mTLS gRPC listener because the current host-metrics spool record is OTLP
protobuf while the control-plane metric envelope is strict JSON. This is a
documented compatibility gap, not evidence that host-metrics replay is
end-to-end. Every path removes the Agent, containers, network, named volumes,
and temporary certificates.

This is Docker compatibility and protocol evidence only. It does not approve
systemd units, journald ACLs, SELinux policy, kernel/cgroup metrics, DNS and
firewall policy, enterprise PKI integration, SMTP/Webhook routes, storage
performance, backup tooling, HA/failover, or time synchronization on an actual
Kylin host. Release approval still requires the supported Kylin V10 VM or
bare-metal matrix, running the packaged non-root service with production-like
PKI, PostgreSQL, network controls, restart/upgrade/rollback, Agent spool replay,
notification egress, backup/restore, and sustained-load evidence.

## Incident checks

- `/healthz` 200 and `/readyz` 503: inspect PostgreSQL, migration output, the
  last all-scope evaluator pass, failed rules, and dispatcher errors.
- Events fire but no notification is delivered: inspect scoped delivery status,
  policy/template enablement, active silences, secret availability, SMTP TLS,
  Webhook allowlist/DNS, and retry due time. Do not replay by editing rows.
- Duplicate or missing telemetry: verify Agent SPIFFE ID and inventory scope,
  clock synchronization, spool health, and `ingest_batch_dedup` retention.
- Recovery never occurs: confirm fresh samples are inside the rule evaluation
  window, aggregation and missing-data policy are intended, and evaluator
  readiness is healthy.
