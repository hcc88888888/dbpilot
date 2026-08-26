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
