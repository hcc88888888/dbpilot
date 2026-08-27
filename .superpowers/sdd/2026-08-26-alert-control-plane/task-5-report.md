# Task 5 Report: Production control-plane HTTP and gRPC server

## Status

Implemented and verified. The production control plane now exposes scoped alert/configuration APIs over HTTPS, serves the authenticated telemetry contract over a separate mTLS gRPC listener, runs PostgreSQL migrations before binding either listener, composes the trusted Agent metric consumer, and owns evaluator/notification retry lifecycle under context cancellation.

The pre-existing untracked `backend/internal/telemetry/dbpilot-spool/` directory was not read, modified, staged, or committed.

## Changes

- Added a replaceable `PrincipalResolver` and a local-only header adapter for `X-DBPilot-Subject`, `X-DBPilot-Platform-Admin`, and comma-separated `tenant/project` assignments in `X-DBPilot-Projects`.
- Rejected blank, whitespace-padded, malformed, comma-injected, and multi-valued identity headers. Project membership is converted to the existing tenant-qualified `Scope.Key`; a bare project ID is not accepted.
- Added `RequireScope` authorization middleware. It authenticates before any repository call, derives tenant/project exclusively from URL path variables, and returns stable JSON `401`, `403`, or `400` errors.
- Added all scoped HTTP routes for overview, alert list/detail, acknowledge/recover, delivery history, rule CRUD/enable, notification-policy CRUD, template CRUD, and silence CRUD. Both concise (`/policies`, `/templates`) and explicit (`/notification-policies`, `/notification-templates`) route names use the same handlers.
- Added strict JSON request DTOs that exclude `scope`, `id`, audit actor, timestamps, and internal fields; unknown fields and trailing documents are rejected. Request bodies are capped at 1 MiB, rule durations accept duration strings or integer nanoseconds, and Go time serialization provides RFC3339/RFC3339Nano output.
- Added repository-generated cryptographic IDs. Write contexts carry the authenticated subject into the existing audit boundary; event acknowledge/recover uses atomic `PutEventAndAudit`.
- Revalidated every repository response against the requested scope before serialization or a follow-on write. An out-of-contract repository cannot leak or mutate a record from another scope.
- Preserved Task 4 Secret boundaries: policy JSON exposes only `has_secret`, delivery retry envelopes remain hidden, and API errors never serialize dependency errors.
- Extended the PostgreSQL adapter with scoped event lookup, list/get/delete policy/template/silence operations, rule deletion, and scoped delivery history. Configuration deletion writes an immutable audit row in the same transaction.
- Added embedded, serialized, exactly-once migration execution. New migration `0003_ingest_dedup.sql` provides shared PostgreSQL ingest-batch deduplication; production composition does not use `MemoryDeduplicator` or alter the test gateway.
- Added production server composition with strict PostgreSQL URL/Webhook allowlist/TLS validation, HTTPS and mTLS gRPC listeners on separate addresses, TLS 1.2 minimum, verified client certificates, authenticated Agent inventory mapping, metric consumer, PostgreSQL repository, evaluator, in-app/Webhook/optional SMTP channels, and dispatcher.
- Added fail-closed dedup behavior: an unavailable shared dedup lookup returns a retryable rejected acknowledgement instead of accepting a batch without shared state.
- Added immediate and periodic evaluator/dispatch and retry loops tied to the run context. Signal cancellation stops both listeners and loops. `/healthz` is process liveness; `/readyz` requires completed migrations, PostgreSQL reachability, and healthy evaluator state.
- Added a strict example YAML configuration with TLS material references, trusted Agent-to-scope inventory, Webhook allowlist, evaluator/retry periods, optional SMTP settings, and an explicit warning that header identity is only a local adapter.

## Interfaces

- `controlplane.PrincipalResolver.ResolvePrincipal(*http.Request) (alert.Principal, error)`
- `controlplane.HeaderPrincipalResolver`
- `controlplane.RequireScope(ScopedHandler) http.Handler`
- `controlplane.NewHTTPHandler(Services, PrincipalResolver) http.Handler`
- `alert.ControlPlaneRepository`
- `alert.RunMigrations(context.Context, *sql.DB) error`
- `main.NewServer(Config) (*Server, error)`
- `(*Server).Run(context.Context) error`

## TDD evidence

- Auth RED: `go test ./internal/controlplane -run TestHeaderPrincipalResolver -count=1` failed to compile because header constants/resolver did not exist; it passed after the strict adapter implementation.
- HTTP RED: `go test ./internal/controlplane ./cmd/controlplane -count=1` failed because `NewHTTPHandler`, `Services`, and the command package did not exist. The handler suite then passed after scoped routes and JSON middleware were implemented.
- Lifecycle RED: `go test ./cmd/controlplane -count=1` failed because `Config`, `NewServer`, and `Server.Run` did not exist. It passed after configuration, migration/listener ordering, TLS server composition, and cancellation were implemented.
- Scope mutation RED: a repository returning an event from another tenant produced HTTP 200; after response-scope validation the same test returns a sanitized 500 and does not serialize the foreign tenant.
- Dedup outage RED: a PostgreSQL lookup error was treated as a cache miss; after fail-closed handling it returns `Accepted=false`, `Retryable=true`, and the stable `DEDUP_UNAVAILABLE` code.
- Lifecycle tests use injected fake listeners and migration/ping functions. No real external listener, SMTP request, Webhook request, or database connection is used.

## Verification

From `backend`:

- `..\..\..\.tooling\go\bin\go.exe test ./cmd/controlplane ./internal/controlplane ./... -count=1` — PASS; every reported package passed, with generated/fixture packages reporting no test files.
- `..\..\..\.tooling\go\bin\go.exe vet ./...` — PASS, no diagnostics.
- `git diff --check` — PASS; only Windows LF/CRLF conversion warnings were emitted.

## Self-review

- Authentication and authorization run before repository calls; URL scope is the only scope accepted by handlers.
- Header identity is isolated behind an interface and is not reused for Agent authentication. gRPC Agent identity still comes exclusively from verified SPIFFE client certificates and configured inventory.
- The production server uses the existing `ingest.Service` and `MetricConsumer`; `cmd/telemetry-test-gateway` remains unchanged and test-only.
- PostgreSQL migrations and readiness complete before either listener is created. HTTP-bind success followed by gRPC-bind failure closes the first listener; context cancellation closes both.
- HTTP and gRPC TLS configurations enforce TLS 1.2 minimum; gRPC enforces verified client certificates.
- API writes attach the authenticated actor and use existing repository/audit transactions. The handler does not write audit rows independently of the state mutation.
- Repository reads and SQL predicates contain tenant and project; scanned values are revalidated before returning and again before HTTP serialization.
- Secret references are accepted only as configuration inputs, stored through Task 4 models, and excluded from policy/delivery JSON. No Secret resolver value is logged or retained by the API.
- Evaluator and retry loops terminate with their context. Dispatcher calls use Task 4 typed deliveries and idempotency; no raw external-send shortcut was added.
- Repository IDs use the existing cryptographic ID generator; request bodies cannot choose IDs or scope.

## Scope note and concerns

The Task 5 file list named only `repository.go` as an alert-package modification, but the reviewed Tasks 1–4 adapter did not expose the list/get/delete methods required by the mandated CRUD routes, and no durable production ingest deduplicator existed. The implementation therefore made the minimal directly related additions to `postgres.go`, the audit action allowlist, and a forward `0003` migration. Omitting these changes would require bypassing the scoped repository/audit boundary or using the explicitly test-only in-memory deduplicator, both prohibited by the task.

No unresolved implementation concern remains. Live PostgreSQL migration execution was not environment-enabled in this task run; migration ordering/rollback behavior is unit-covered at the server boundary, while the full Go suite and existing environment-gated PostgreSQL tests remain available for the Task 6 end-to-end environment.

## Review remediation (2026-08-27)

This section supersedes the original report's descriptions of default header authentication, best-effort PostgreSQL deduplication, migration-only readiness, and the absence of live PostgreSQL verification. All C1/C2/I1/I2/I3/M1/M2 findings in `task-5-review.md` were addressed.

### Security and durability

- Production startup is now fail-closed unless code injects a trusted resolver or YAML explicitly selects a supported identity mode. The example uses HTTP mTLS with a verified certificate-URI-to-principal inventory. `local_headers` is accepted only on a loopback listener, and caller headers can no longer grant platform-admin privileges.
- Added a verified-client-certificate resolver that requires a TLS verified chain, exactly one certificate URI, and an exact provisioned principal mapping. HTTP mTLS always uses `RequireAndVerifyClientCert` and configured client CAs.
- Production metric ingestion no longer uses `Lookup -> Consume -> Remember`. `AppendBatch` reserves `(agent_id,batch_id)`, writes every metric sample, marks the reservation accepted, and commits in one PostgreSQL transaction. Unique-key contention serializes independent instances; any payload, state-update, or commit failure rolls back and produces no accepted acknowledgement.
- Production opaque log batches use a context-aware, single-statement durable accept operation whose database errors also prevent acknowledgement. The legacy `BatchDeduplicator`/`MemoryDeduplicator` path remains solely for the unchanged local contract-test gateway.
- Kept the already-committed `0003_ingest_dedup.sql` immutable and added forward migration `0004_atomic_ingest_batch.sql`. It removes legacy rejected rows, converts accepted acknowledgements to the new state model, and drops the obsolete best-effort acknowledgement columns.

### Readiness, API boundary, and lifecycle

- `evaluation_scopes` now uses an explicit `tenant_id`/`project_id` snake-case YAML DTO. Startup rejects invalid or duplicate entries and rejects an empty effective evaluation scope set.
- Readiness remains false until one complete all-scope evaluation/list/dispatch pass succeeds. Per-scope errors are joined without allowing a later successful scope to erase an earlier failure; a later fully successful pass restores readiness.
- API router-generated wrong-method, unknown-path, and automatic-redirect responses are normalized to the JSON error envelope with stable `405 method_not_allowed` or `404 not_found` codes.
- Every JSON write endpoint requires `application/json` (parameters such as UTF-8 are accepted), returning `415 unsupported_media_type` otherwise. Bodies over 1 MiB return `413 payload_too_large`; malformed, unknown-field, and trailing-document inputs remain `400 invalid_request`.
- Server shutdown and listener-error paths cancel the run context first, stop listeners, wait up to five seconds for evaluator/retry workers, and close the owned database only after workers exit. A blocking-worker lifecycle test proves `Run` does not return early.

### Added regression evidence

- Trusted HTTP identity: missing adapter fails startup; local headers require explicit loopback mode and cannot self-assert admin; mTLS uses only a verified, assigned certificate URI.
- Durable ingest: atomic metric consumer delegation, no acknowledgement on atomic commit error, retry after failure, transaction rollback on metric failure or lost reservation update, committed-duplicate behavior, and no acknowledgement on durable log dedup failure.
- Real PostgreSQL: two independent connection pools concurrently submit the same metric batch and produce exactly one accepted reservation and one metric row. An injected database trigger then forces a metric write failure, proves the reservation rolled back, and proves a second instance can retry successfully.
- Readiness/config: startup-before-first-pass, partial multi-scope failure, later recovery, snake-case strict decoding, and empty/invalid/duplicate scope rejection.
- HTTP/lifecycle: JSON 404/405/abnormal-slash handling, 415/413 classification, and worker-exit-before-`Run`-return.

### Final verification

From `backend` after remediation:

- `go test ./cmd/controlplane ./internal/controlplane ./internal/ingest ./internal/alert -count=1` — PASS.
- `go test ./... -count=1` — PASS for every package; generated/fixture packages report no test files.
- `go vet ./...` — PASS with no diagnostics.
- With a disposable PostgreSQL 16 container and two independent pools: `DBPILOT_ALERT_POSTGRES_INTEGRATION=1 go test ./internal/alert -run TestPostgresMetricBatchDedupIsAtomicAcrossInstances -count=1 -v` — PASS, including forced rollback and cross-instance retry. The explicitly named temporary container was stopped and removed after the test.
- `git diff --check` — PASS apart from Git's informational Windows LF/CRLF conversion warnings.
- `go test -race ...` could not run in this Windows environment because the bundled toolchain has CGO disabled; the ordinary focused/full suites and real PostgreSQL concurrency test passed.

The pre-existing untracked `backend/internal/telemetry/dbpilot-spool/` directory was not read, modified, staged, or committed during remediation. No unresolved remediation concern remains.
