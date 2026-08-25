# DBPilot Embedded Collector Host and Spool Exporter

## Goal

Close the Task 8 blocker by making `telemetry.EmbeddedBuilder` start real embedded collection components and route collected records into the DBPilot spool/export path. The agent must not report `ACTIVE` while running a no-op candidate.

## Scope

- Add a concrete collector host that consumes the typed `RuntimeConfig` produced by `telemetry.Compile`.
- Instantiate the supported embedded OTel receivers/processors from the closed catalog, with a DBPilot consumer/export adapter that appends bounded LOG/METRIC/AUDIT_LOG batches to `spool.Store`.
- Make candidate `Start`, `Healthy`, and `Stop` reflect actual component lifecycle; startup or health failure must roll back through existing `telemetry.Engine`.
- Replace the manual-append end-to-end test with a runtime test that activates a signed policy, starts a file receiver, observes a spool batch, and sends it through the acknowledged exporter.
- Keep policy surface typed and closed; no raw OTel/Vector YAML, shell, or dynamic component loading.

## Acceptance

- `EmbeddedBuilder.Build` rejects invalid/unsupported component graphs and returns a candidate owning concrete running components.
- `Start` starts receivers and the spool exporter; `Healthy` fails if any required component is not running; `Stop` cancels and closes all components.
- A temporary file source produces a persisted spool batch with authenticated source/agent metadata.
- Existing `go test ./...`, `go vet ./...`, static Linux builds, and focused lifecycle tests pass.
- No `vector`, `otelcol`, shell invocation, or arbitrary executable appears in runtime code or policy input.
