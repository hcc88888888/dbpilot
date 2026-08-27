# DBPilot Alert Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a DBPilot-owned monitoring and alerting control plane that turns authenticated Agent metrics into tenant-scoped alert events, notifications, audit records, and self-developed alert-center APIs.

**Architecture:** Add a production `controlplane` server beside the existing test-only telemetry gateway. Its HTTP API applies an explicit tenant/project principal before calling domain services. Metric samples, rules, events, notifications, silences, and audit records are held behind repository interfaces; PostgreSQL is the first implementation, while the evaluator depends only on the sample query interface. The first delivery wave ends in a complete backend loop and deployment verification; a follow-up plan will build detailed frontend pages and Prometheus/Alertmanager adapters on these stable APIs.

**Tech Stack:** Go 1.25, PostgreSQL 16, `database/sql` with `github.com/lib/pq`, standard-library `net/http`, existing gRPC telemetry contract, Docker Compose, Kylin V10 Docker validation.

**Spec:** `docs/superpowers/specs/2026-08-26-alert-control-plane-design.md`

## Global Constraints

- DBPilot control plane is the alert fact source; no component may bypass tenant, project, authorization, audit, or event-state rules.
- Phase 1 supports threshold, duration, missing-data, rate, and `avg`, `max`, `min`, `sum`, `count`; it does not implement PromQL, cross-metric expressions, dynamic baselines, or AI attribution.
- Server configuration, event, rule, notification, silence, and audit data are PostgreSQL-backed; metric interfaces must not expose PostgreSQL-specific types.
- All APIs are tenant/project scoped. Platform administrators may cross scopes; project members may access only authorized project IDs.
- Secrets are references only. SMTP passwords, Webhook tokens, credentials, endpoint response bodies, and TLS material must not appear in API responses, logs, metrics, or audit bodies.
- Webhooks require HTTPS, a configured hostname allowlist, HMAC signing, no redirects, and rejection of private-network destinations.
- Existing `cmd/telemetry-test-gateway` remains test-only and must not be converted into the production control-plane server.
- Agent builds remain Linux-compatible for CentOS 7+ and Kylin V10+; Docker/Kylin validation is evidence of container compatibility, not a replacement for VM/bare-metal approval.

---

## File Structure

| Path | Responsibility |
| --- | --- |
| `backend/internal/alert/model.go` | Stable domain values, request types, state transitions, normalized labels, and fingerprints. |
| `backend/internal/alert/repository.go` | Storage-neutral repository, sample store, and transaction interfaces consumed by services. |
| `backend/internal/alert/postgres.go` | PostgreSQL mapping and schema migration runner; never leaks SQL rows to callers. |
| `backend/internal/alert/metric_store.go` | Metric batch decoding and normalized sample write/query implementation. |
| `backend/internal/alert/evaluator.go` | Rule validation, aggregation, rate, missing-data behavior, event lifecycle, and evaluator health. |
| `backend/internal/alert/notification.go` | Policy matching, template rendering, silence evaluation, idempotent delivery and bounded retry. |
| `backend/internal/controlplane/auth.go` | Principal extraction and project authorization middleware. |
| `backend/internal/controlplane/http.go` | Scoped JSON HTTP handlers and route registration. |
| `backend/internal/controlplane/ingest.go` | Authenticated metric-batch consumer attached to the existing gRPC ingest path. |
| `backend/cmd/controlplane/main.go` | Production server composition, startup migration, gRPC and HTTP listener lifecycle. |
| `backend/deploy/compose/alert-control-plane.compose.yaml` | Isolated PostgreSQL, SMTP, and Webhook fixtures with no published host ports. |
| `backend/scripts/verify-alert-control-plane.ps1` | Windows Docker/Kylin repeatable end-to-end verifier and cleanup owner. |
| `backend/docs/alert-control-plane-operations.md` | Operator configuration, migration, key rotation, health, and validation instructions. |

### Task 1: Alert domain contracts, access scope, and PostgreSQL persistence

**Files:**
- Create: `backend/internal/alert/model.go`
- Create: `backend/internal/alert/repository.go`
- Create: `backend/internal/alert/postgres.go`
- Create: `backend/internal/alert/migrations/0001_alert_control_plane.sql`
- Create: `backend/internal/alert/model_test.go`
- Create: `backend/internal/alert/postgres_test.go`
- Modify: `backend/go.mod`

**Interfaces:**
- Consumes: authenticated Agent ID from `internal/ingest.Service`; tenant/project assignment is supplied by the production inventory resolver, never claimed by an Agent payload.
- Produces: `type Scope struct { TenantID, ProjectID string }`, `type Principal struct { Subject string; PlatformAdmin bool; Projects map[string]struct{} }`, `func (p Principal) Allows(scope Scope) bool`, `type AlertRule`, `type AlertEvent`, `type NotificationPolicy`, `type NotificationTemplate`, `type Silence`, and `type AuditRecord`.
- Produces: `type Repository interface { CreateRule(context.Context, AlertRule) (AlertRule, error); UpdateRule(context.Context, AlertRule) (AlertRule, error); ListRules(context.Context, Scope) ([]AlertRule, error); GetRule(context.Context, Scope, string) (AlertRule, error); PutEvent(context.Context, AlertEvent) (AlertEvent, error); FindEventByFingerprint(context.Context, Scope, string) (AlertEvent, bool, error); ListEvents(context.Context, Scope, EventFilter) ([]AlertEvent, error); AppendAudit(context.Context, AuditRecord) error }`.

- [ ] **Step 1: Write the failing domain tests**

```go
func TestRuleValidateRejectsUnsafeOrIncompleteDefinition(t *testing.T) {
    rule := alert.AlertRule{Scope: alert.Scope{TenantID: "t1", ProjectID: "p1"},
        Name: "cpu", Metric: "host.cpu", Aggregation: "avg", Operator: ">",
        Threshold: 80, EvaluationEvery: time.Minute, For: time.Minute,
        MissingData: "ignore", Severity: "critical"}
    require.NoError(t, rule.Validate())
    rule.Aggregation = "promql"
    require.Error(t, rule.Validate())
}

func TestFingerprintIgnoresLabelOrder(t *testing.T) {
    require.Equal(t, alert.EventFingerprint(alert.Scope{"t1", "p1"}, "r1", map[string]string{"host": "a", "role": "db"}),
        alert.EventFingerprint(alert.Scope{"t1", "p1"}, "r1", map[string]string{"role": "db", "host": "a"}))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./internal/alert -run 'TestRuleValidate|TestFingerprint' -count=1`

Expected: FAIL because `internal/alert` does not exist.

- [ ] **Step 3: Write the domain implementation**

```go
type EventState string
const (
    EventPending EventState = "pending"
    EventFiring EventState = "firing"
    EventAcknowledged EventState = "acknowledged"
    EventResolved EventState = "resolved"
)

func (e AlertEvent) Transition(next EventState, at time.Time, actor string) (AlertEvent, error) {
    // Permit pending->firing/resolved, firing->acknowledged/resolved,
    // acknowledged->resolved; preserve FirstSeen and set transition timestamps.
}
```

Implement allowlisted aggregation, operators, severities, missing-data policies, non-empty scope/metric/name checks, durations greater than zero, valid notification policy IDs, and canonical sorted label serialization before SHA-256 fingerprinting.

- [ ] **Step 4: Add storage-neutral contracts and migration**

Create tables `alert_rules`, `alert_events`, `notification_policies`, `notification_templates`, `alert_silences`, `notification_deliveries`, `alert_audit_log`, and `metric_samples`. Add scope columns and indexes beginning with `(tenant_id, project_id)`. Partition `metric_samples` by day on `sampled_at`; create the next seven daily partitions transactionally in the migration runner. Use `JSONB` only for normalized labels/evidence, never to replace searchable scope/status fields.

- [ ] **Step 5: Implement PostgreSQL repository tests with sqlmock and migration statement checks**

```go
func TestPostgresRepositoryScopesEventLookup(t *testing.T) {
    db, mock, _ := sqlmock.New()
    mock.ExpectQuery("SELECT .* FROM alert_events WHERE tenant_id = \\\\$1 AND project_id = \\\\$2 AND fingerprint = \\\\$3")
    _, _, err := alert.NewPostgresRepository(db).FindEventByFingerprint(ctx, alert.Scope{"t1", "p1"}, "fp")
    require.NoError(t, err)
}
```

Verify every public read/write method includes both scope fields and all SQL uses positional parameters.

- [ ] **Step 6: Run test to verify it passes**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./internal/alert -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/go.mod backend/go.sum backend/internal/alert
git commit -m "feat: add alert domain persistence contracts"
```

### Task 2: Metric sample ingestion and query boundary

**Files:**
- Create: `backend/internal/alert/metric_store.go`
- Create: `backend/internal/alert/metric_store_test.go`
- Create: `backend/internal/controlplane/ingest.go`
- Create: `backend/internal/controlplane/ingest_test.go`
- Modify: `backend/internal/ingest/service.go`
- Modify: `backend/internal/ingest/service_test.go`

**Interfaces:**
- Consumes: Task 1 `Scope`, repository transaction support, Agent-authenticated `MetricBatch` from `telemetryv1.TelemetryIngest`.
- Produces: `type MetricSample struct { Scope Scope; AgentID, InstanceID, Component, Role, Host, Name string; Labels map[string]string; Value float64; SampledAt time.Time }`, `type MetricStore interface { Append(context.Context, []MetricSample) error; Query(context.Context, MetricQuery) ([]MetricSample, error) }`, and `type AgentScopeResolver interface { ScopeForAgent(context.Context, string) (Scope, error) }`.
- Produces: `type MetricBatchConsumer interface { ConsumeMetricBatch(context.Context, string, []byte, time.Time) error }`; `ingest.Service` invokes it only after certificate validation, checksum validation, and durable deduplication.

- [ ] **Step 1: Write the failing metric tests**

```go
func TestMetricConsumerRejectsPayloadScopeClaim(t *testing.T) {
    consumer := controlplane.NewMetricConsumer(resolverFor("agent-a", alert.Scope{"t1", "p1"}), store)
    err := consumer.ConsumeMetricBatch(ctx, "agent-a", []byte(`{"tenant_id":"other","samples":[]}`), now)
    require.ErrorContains(t, err, "scope claim")
}

func TestMetricStoreQueryFiltersScopeMetricLabelsAndWindow(t *testing.T) {
    samples, err := store.Query(ctx, alert.MetricQuery{Scope: alert.Scope{"t1", "p1"}, Name: "db.connections", From: from, To: to, Labels: map[string]string{"instance":"db-1"}})
    require.NoError(t, err)
    require.Len(t, samples, 1)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./internal/controlplane ./internal/alert -run 'TestMetric' -count=1`

Expected: FAIL because the consumer and store are missing.

- [ ] **Step 3: Add the consumer hook to authenticated ingest**

```go
type MetricBatchConsumer interface {
    ConsumeMetricBatch(context.Context, string, []byte, time.Time) error
}

func NewService(identities IdentityResolver, dedup BatchDeduplicator, metrics MetricBatchConsumer) *Service
```

Call `ConsumeMetricBatch` after the existing authorization/checksum/dedup checks and before acknowledging a new batch. Preserve no-op behavior when the consumer is nil so existing test gateway tests remain valid. Do not parse metrics in the test gateway.

- [ ] **Step 4: Implement strict decode, normalization, and persistence**

Accept a documented JSON envelope with only `samples`; each sample must have `name`, finite numeric `value`, RFC3339 timestamp, and labels. Reject unknown top-level fields, embedded tenant/project/agent identity claims, timestamps more than five minutes in the future, empty metric names, labels larger than 64 entries, and labels with keys outside `[a-zA-Z_][a-zA-Z0-9_]*`. Resolve scope only with `AgentScopeResolver`. Persist labels as canonical JSON and query them with portable Go post-filtering where needed.

- [ ] **Step 5: Add deduplication and failure-path tests**

Assert a duplicate gRPC batch does not append twice, an invalid envelope returns an ingest error, an unknown Agent scope is rejected, and an unavailable store returns an error without recording an accepted batch.

- [ ] **Step 6: Run tests to verify they pass**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./internal/ingest ./internal/controlplane ./internal/alert -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/internal/ingest backend/internal/controlplane backend/internal/alert
git commit -m "feat: ingest scoped alert metrics"
```

### Task 3: Rule evaluator, event state machine, and immutable audit trail

**Files:**
- Create: `backend/internal/alert/evaluator.go`
- Create: `backend/internal/alert/evaluator_test.go`
- Create: `backend/internal/alert/audit.go`
- Create: `backend/internal/alert/audit_test.go`
- Modify: `backend/internal/alert/repository.go`
- Modify: `backend/internal/alert/postgres.go`

**Interfaces:**
- Consumes: Task 1 `AlertRule`, `AlertEvent`, `EventFingerprint`, `Repository`; Task 2 `MetricStore.Query`.
- Produces: `type Evaluator struct`, `func (e *Evaluator) EvaluateScope(context.Context, Scope, time.Time) (EvaluationSummary, error)`, `type EvaluationEvidence struct { WindowStart, WindowEnd time.Time; Samples int; Aggregate *float64; Missing bool; Rate *float64 }`, and `func (e *Evaluator) Health() EvaluatorHealth`.
- Produces: `type AuditWriter interface { AppendAudit(context.Context, AuditRecord) error }`; every state/configuration action has an immutable record with actor, time, scope, target, action, and sanitized details.

- [ ] **Step 1: Write the failing evaluator tests**

```go
func TestEvaluatorPromotesOnlyAfterForDuration(t *testing.T) {
    fx := newEvaluatorFixture(t, ruleWith(For: time.Minute))
    fx.Append(sampleAt(fx.Now, 91))
    fx.Evaluate(); require.Equal(t, alert.EventPending, fx.Event("cpu").State)
    fx.Now = fx.Now.Add(time.Minute)
    fx.Append(sampleAt(fx.Now, 91))
    fx.Evaluate(); require.Equal(t, alert.EventFiring, fx.Event("cpu").State)
}
func TestEvaluatorMissingDataPolicies(t *testing.T) {
    for _, want := range []alert.EventState{alert.EventPending, alert.EventResolved} {
        fx := newEvaluatorFixture(t, ruleWith(MissingData: map[alert.EventState]string{
            alert.EventPending: "alert", alert.EventResolved: "resolve"}[want]))
        fx.Evaluate(); require.Equal(t, want, fx.Event("cpu").State)
    }
}
func TestEvaluatorUsesSameEventForEquivalentLabelOrder(t *testing.T) {
    fx := newEvaluatorFixture(t, defaultRule())
    fx.Append(sample(fx.Now, map[string]string{"host": "a", "role": "db"})); fx.Evaluate()
    fx.Append(sample(fx.Now.Add(time.Minute), map[string]string{"role": "db", "host": "a"})); fx.Evaluate()
    require.Len(t, fx.Events(), 1)
}
func TestEvaluatorResolvesTheExistingEvent(t *testing.T) {
    fx := newFiringEvaluatorFixture(t); eventID := fx.Event("cpu").ID
    fx.Append(sampleAt(fx.Now, 1)); fx.Evaluate()
    require.Equal(t, eventID, fx.Event("cpu").ID); require.Equal(t, alert.EventResolved, fx.Event("cpu").State)
}
func TestEvaluatorComputesRateFromFixedWindow(t *testing.T) {
    fx := newEvaluatorFixture(t, rateRule()); fx.Append(sampleAt(fx.Now, 10)); fx.Append(sampleAt(fx.Now.Add(10*time.Second), 30))
    fx.Now = fx.Now.Add(10*time.Second); fx.Evaluate(); require.Equal(t, 2.0, *fx.Event("rate").Evidence.Rate)
}
func TestEvaluatorHealthReportsLateAndFailedRuns(t *testing.T) {
    fx := newEvaluatorFixture(t, invalidAtRuntimeRule()); fx.Evaluate()
    require.True(t, fx.Evaluator.Health().FailedRules > 0)
}
```

Use a deterministic fake clock and in-memory `MetricStore`/repository fixtures; no wall-clock sleeps and no PostgreSQL dependency belong in these unit tests.

- [ ] **Step 2: Run evaluator tests to verify failure**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./internal/alert -run TestEvaluator -count=1`

Expected: FAIL because `Evaluator` is undefined.

- [ ] **Step 3: Implement aggregation and condition evaluation**

```go
func aggregate(kind string, samples []MetricSample) (float64, error)
func rate(samples []MetricSample) (float64, error)
func compare(value, threshold float64, operator string) bool
```

Filter samples by scope, metric, label selector, and interval `[now-window, now]`. Group by canonical resource labels. Apply `avg`, `max`, `min`, `sum`, or `count`; for rate sort by timestamp and divide the endpoint value difference by elapsed seconds. Store a complete sanitized evidence snapshot with the event.

- [ ] **Step 4: Implement lifecycle and failure isolation**

For a true condition, create `pending` once and promote only when its continuous true duration reaches `rule.For`; refresh `LastSeen` on the same fingerprint. For a false condition, resolve an existing pending/firing/acknowledged event, preserving its ID and writing recovery evidence. For no samples, follow `MissingData` exactly. Continue evaluating unrelated rules after a rule failure, record a system evaluator finding, and expose last-run latency/error/queue depth through `Evaluator.Health`.

- [ ] **Step 5: Append transactional audit records**

Ensure `rule.created`, `rule.updated`, `event.pending`, `event.firing`, `event.acknowledged`, `event.resolved`, and `evaluation.failed` are append-only audit actions. Tests must confirm evidence has redacted fields and a repository failure rolls back both event and audit write.

- [ ] **Step 6: Run tests to verify they pass**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./internal/alert ./internal/ingest ./... -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/internal/alert
git commit -m "feat: evaluate alert rules and event lifecycle"
```

### Task 4: Notification policies, templates, silences, and secure deliveries

**Files:**
- Create: `backend/internal/alert/notification.go`
- Create: `backend/internal/alert/notification_test.go`
- Create: `backend/internal/alert/webhook.go`
- Create: `backend/internal/alert/webhook_test.go`
- Modify: `backend/internal/alert/repository.go`
- Modify: `backend/internal/alert/postgres.go`

**Interfaces:**
- Consumes: Task 1 policy/template/silence models and repository; Task 3 event transitions/audit actions.
- Produces: `type Dispatcher struct`, `func (d *Dispatcher) Dispatch(context.Context, AlertEvent, EventState) error`, `type DeliveryChannel interface { Name() string; Deliver(context.Context, DeliveryRequest) error }`, `type SecretResolver interface { Resolve(context.Context, string) ([]byte, error) }`, and `func (d *Dispatcher) RetryDue(context.Context, time.Time) error`.
- Produces: `type WebhookAllowlist interface { Allows(host string) bool }`; URL validation occurs before any network request.

- [ ] **Step 1: Write the failing notification tests**

```go
func TestDispatcherSilenceSuppressesDeliveryButWritesAudit(t *testing.T) {
    fx := newDispatchFixture(t); fx.AddSilence(activeFingerprintSilence(fx.Event))
    require.NoError(t, fx.Dispatcher.Dispatch(context.Background(), fx.Event, alert.EventFiring))
    require.Empty(t, fx.Channel.Requests()); require.Equal(t, "delivery.suppressed", fx.LastAudit().Action)
}
func TestDispatcherUsesEventStateChannelIdempotencyKey(t *testing.T) {
    fx := newDispatchFixture(t)
    require.NoError(t, fx.Dispatcher.Dispatch(context.Background(), fx.Event, alert.EventFiring))
    require.NoError(t, fx.Dispatcher.Dispatch(context.Background(), fx.Event, alert.EventFiring))
    require.Len(t, fx.Channel.Requests(), 1)
}
func TestWebhookRejectsHTTPRedirectPrivateIPAndUnlistedHost(t *testing.T) {
    for _, rawURL := range []string{"http://allowed.example/hook", "https://127.0.0.1/hook", "https://blocked.example/hook"} {
        require.Error(t, alert.ValidateWebhookURL(rawURL, allowlist("allowed.example"), publicResolver))
    }
}
func TestWebhookSignsCanonicalBodyWithReferencedSecret(t *testing.T) {
    request := webhookRequest(t, "https://allowed.example/hook", []byte("secret"))
    require.NotEmpty(t, request.Header.Get("X-DBPilot-Signature"))
    require.NotEmpty(t, request.Header.Get("X-DBPilot-Timestamp"))
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./internal/alert -run 'TestDispatcher|TestWebhook' -count=1`

Expected: FAIL because dispatcher and secure Webhook channel are absent.

- [ ] **Step 3: Implement routing and templates**

Match enabled policies within the event scope by severity, labels, project, and configured UTC time window. Render only predefined placeholders (`event.id`, `event.state`, `event.severity`, `resource.*`, `evidence.aggregate`, `event.url`); unknown placeholders are validation errors. Store SMTP and Webhook connection authentication exclusively as Secret references and return only `has_secret: true` in API-safe views.

- [ ] **Step 4: Implement silence and delivery persistence**

Match a non-expired silence against fingerprint, labels, resource, or scope. Write a `delivery.suppressed` audit row and a suppressed delivery record but do not call channels. For non-silenced events, derive idempotency key `sha256(eventID + state + channel + templateVersion)`, persist an `attempting` record before send, and set final status after send.

- [ ] **Step 5: Implement in-app, SMTP, and Webhook channels**

In-app delivery persists a user-visible notification record. SMTP uses TLS and a secret-resolved password. Webhook validates `https`, hostname allowlist, a public resolved address (reject loopback/link-local/private/unspecified IPv4 and IPv6), disables redirects, sets 10-second timeout, signs body `HMAC-SHA256` using the referenced secret, and sends `X-DBPilot-Timestamp` plus `X-DBPilot-Signature`.

- [ ] **Step 6: Implement bounded retries and audit**

Retry retryable failures at 1 minute, 5 minutes, and 30 minutes, then mark `abandoned`. Do not retry validation failures or 4xx Webhook results except 408, 429, and 5xx. Persist and audit every retry/final abandonment with a sanitized error class, never a response body or secret.

- [ ] **Step 7: Run tests to verify they pass**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./internal/alert -count=1`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add backend/internal/alert
git commit -m "feat: deliver alert notifications securely"
```

### Task 5: Production control-plane HTTP and gRPC server

**Files:**
- Create: `backend/internal/controlplane/auth.go`
- Create: `backend/internal/controlplane/auth_test.go`
- Create: `backend/internal/controlplane/http.go`
- Create: `backend/internal/controlplane/http_test.go`
- Create: `backend/cmd/controlplane/main.go`
- Create: `backend/cmd/controlplane/main_test.go`
- Create: `backend/config/controlplane.yaml.example`
- Modify: `backend/internal/alert/repository.go`

**Interfaces:**
- Consumes: Tasks 1–4 services; Task 2 `AgentScopeResolver`; existing gRPC `TelemetryIngest` service.
- Produces: routes under `/api/v1/tenants/{tenantID}/projects/{projectID}` and an HTTP principal contract `X-DBPilot-Subject`, `X-DBPilot-Platform-Admin`, `X-DBPilot-Projects` for local deployment tests; production deployments replace the header extractor with the enterprise identity adapter.
- Produces: `func NewHTTPHandler(Services, PrincipalResolver) http.Handler`, `func NewServer(Config) (*Server, error)`, and `func (s *Server) Run(context.Context) error`.

- [ ] **Step 1: Write failing handler tests**

```go
func TestRuleCreateRejectsPrincipalOutsideProject(t *testing.T) {
    response := request(t, handler, "POST", "/api/v1/tenants/t1/projects/p2/rules", memberFor("p1"), validRuleBody())
    require.Equal(t, http.StatusForbidden, response.Code)
}
func TestEventAcknowledgeWritesActorAndReturnsScopedEvent(t *testing.T) {
    response := request(t, handler, "POST", eventPath("t1", "p1", "e1")+"/acknowledge", memberFor("p1"), nil)
    require.Equal(t, http.StatusOK, response.Code); require.Equal(t, "actor-1", fixture.LastAudit().Actor)
}
func TestAlertOverviewContainsEventCountsAndEvaluatorHealth(t *testing.T) {
    response := request(t, handler, "GET", "/api/v1/tenants/t1/projects/p1/overview", memberFor("p1"), nil)
    require.Equal(t, http.StatusOK, response.Code); require.JSONEq(t, `{"events":{"firing":1},"evaluator":{"healthy":true}}`, response.Body.String())
}
```

Cover `GET /overview`, `GET /alerts`, `GET /alerts/{id}`, `POST /alerts/{id}/acknowledge`, rule CRUD plus enable, policy CRUD, template CRUD, silence CRUD, and `GET /alerts/{id}/deliveries`. Test status codes `400`, `401`, `403`, `404`, and redacted serialization.

- [ ] **Step 2: Run tests to verify missing server failure**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./internal/controlplane ./cmd/controlplane -count=1`

Expected: FAIL because HTTP handler and server do not exist.

- [ ] **Step 3: Implement principal extraction and scope middleware**

```go
func RequireScope(next ScopedHandler) http.Handler {
    // Parse URL scope, resolve authenticated principal, return 401/403 before service calls.
}
```

Reject blank, malformed, or multi-valued identity headers. Make the identity adapter an interface so headers are only a local test/deployment adapter. Do not allow scope fields from JSON bodies to override the URL scope.

- [ ] **Step 4: Implement JSON handlers and composition**

Use `http.ServeMux`, strict JSON decoding with unknown-field rejection, RFC3339 output, request-size limits, consistent `{ "error": { "code", "message" } }` errors, and repository-generated IDs. Bind HTTP and gRPC to separately configured addresses; run migrations before listeners start; initialize the authenticated ingest service with the metric consumer; run evaluator and dispatcher retry loops with context cancellation. `/healthz` verifies process liveness and `/readyz` verifies PostgreSQL migration/readiness and evaluator health.

- [ ] **Step 5: Add command lifecycle/configuration tests**

Assert invalid database URL, absent Webhook allowlist, missing required TLS material reference, migration failure, and canceled context all return deterministic errors without listeners leaking. Use fake services/listeners, not real external network calls.

- [ ] **Step 6: Run tests to verify they pass**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./cmd/controlplane ./internal/controlplane ./... -count=1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/internal/controlplane backend/cmd/controlplane backend/config
git commit -m "feat: expose alert control plane APIs"
```

### Task 6: Docker/Kylin end-to-end evidence and operations guide

**Files:**
- Create: `backend/deploy/compose/alert-control-plane.compose.yaml`
- Create: `backend/deploy/compose/fixtures/smtp_sink.go`
- Create: `backend/deploy/compose/fixtures/webhook_sink.go`
- Create: `backend/scripts/verify-alert-control-plane.ps1`
- Create: `backend/docs/alert-control-plane-operations.md`
- Create: `backend/test/e2e/alert_control_plane_test.go`
- Modify: `backend/README.md`

**Interfaces:**
- Consumes: Tasks 1–5 public API and Agent metric envelope.
- Produces: repeatable command `powershell -File .\\scripts\\verify-alert-control-plane.ps1 -GoBinary '<absolute go.exe>' -DockerBinary '<absolute docker.exe>' -KylinImage 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'`.

- [ ] **Step 1: Write the failing end-to-end test**

```go
func TestAlertControlPlaneLifecycle(t *testing.T) {
    requireEnv(t, "DBPILOT_ALERT_E2E")
    api := newE2EClient(t)
    rule := api.CreateRule(scopeT1P1, thresholdRule("db.connections", 80))
    agent := newMTLSAgent(t, "agent-t1-p1")
    agent.PushMetric(metricEnvelope("db.connections", 91))
    event := api.EventEventually(scopeT1P1, rule.ID, alert.EventFiring)
    require.Eventually(t, func() bool { return api.HasDeliveries(event.ID, "in_app", "smtp", "webhook") }, time.Minute, time.Second)
    api.CreateSilence(scopeT1P1, fingerprintSilence(event.Fingerprint))
    agent.PushMetric(metricEnvelope("db.connections", 92))
    require.True(t, api.HasSuppressedDelivery(event.ID))
    agent.PushMetric(metricEnvelope("db.connections", 1))
    require.Equal(t, alert.EventResolved, api.EventEventually(scopeT1P1, rule.ID, alert.EventResolved).State)
    require.Equal(t, http.StatusForbidden, api.GetAs(memberFor("p2"), eventPath("t1", "p1", event.ID)).StatusCode)
}
```

Gate it with `DBPILOT_ALERT_E2E=1`; skip with an explicit message otherwise. The test must call production control-plane listeners, not package-private service methods.

- [ ] **Step 2: Run it without fixtures to verify skip gate**

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./test/e2e -run TestAlertControlPlaneLifecycle -count=1`

Expected: SKIP with `DBPILOT_ALERT_E2E=1 required`.

- [ ] **Step 3: Build isolated Compose fixtures**

Define PostgreSQL 16, SMTP sink, Webhook sink, and control-plane services on a dedicated bridge network with `internal: true`, no `ports`, named disposable volumes, non-root service users where supported, health checks, and fixture-only credentials supplied through Compose secrets/environment. The Webhook sink records headers/body hashes only; it must not log bodies containing event evidence.

- [ ] **Step 4: Implement cleanup-safe verifier**

The PowerShell script locates explicit Go/Docker binaries, starts Compose, waits for health, builds and starts `dbpilot-agent` in the approved Kylin V10 container, provisions mTLS test materials in a temporary directory, executes the e2e test, captures sanitized service logs on failure, and removes containers/networks/volumes/temp data in `finally`. It rejects a missing Kylin image, non-Kylin `/etc/os-release`, published host ports, or secret echo in logs.

- [ ] **Step 5: Document operations**

Document PostgreSQL migrations/retention, inventory Agent-to-scope mapping, role integration points, secret reference formats and rotation, SMTP/Webhook security policy, evaluator health interpretation, backup/restore ordering, and the distinction between Docker/Kylin compatibility evidence and required Kylin VM/bare-metal approval.

- [ ] **Step 6: Run quality gate**

Run: `powershell -File .\\scripts\\verify-alert-control-plane.ps1 -GoBinary '..\\..\\..\\.tooling\\go\\bin\\go.exe' -DockerBinary "$env:LOCALAPPDATA\\Programs\\DockerDesktop\\resources\\bin\\docker.exe" -KylinImage 'cr.kylinos.cn/kylin/kylin-server-platform:v10sp1'`

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe vet ./...`

Run: `..\\..\\..\\.tooling\\go\\bin\\go.exe test ./... -count=1`

Expected: verifier prints firing, notification, silence, recovery, authorization, and cleanup evidence; vet and tests PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/deploy backend/scripts/verify-alert-control-plane.ps1 backend/docs backend/test/e2e backend/README.md
git commit -m "test: verify alert control plane lifecycle"
```

## Deferred Follow-up Plans

After this plan is accepted, create independent plans for:

1. The self-developed enterprise-backoffice pages: monitoring overview, alert list/detail, rule/policy/template/silence management, using the stable HTTP API above and the existing DBPilot visual system.
2. Prometheus exposition/query compatibility and Alertmanager inbound Webhook transformation, with conformance fixtures and no bypass of `Scope`, `Principal`, `AlertEvent`, or audit rules.

## Self-Review

- **Spec coverage:** Tasks 1–2 cover PostgreSQL persistence, scope boundaries, and Agent metric ingress. Task 3 covers threshold/duration/missing/rate/aggregation, stable fingerprints, event lifecycle, evidence, and evaluator health. Task 4 covers policy/template/silence, in-app/email/Webhook, retry, security, and delivery audit. Task 5 covers all required backend APIs, roles, and server readiness. Task 6 covers real Agent path, Docker, Kylin, notification outcomes, and operator documentation. Detailed frontend pages and Prometheus/Alertmanager protocol compatibility are independent subsystems, intentionally deferred after delivery of the required stable API and compatibility boundary.
- **Placeholder scan:** no `TODO`, `TBD`, “implement later”, or undefined hand-off terms remain in executable tasks.
- **Type consistency:** `Scope`, `MetricStore`, `AgentScopeResolver`, `Repository`, `Evaluator`, `Dispatcher`, `Principal`, and `AlertEvent` are introduced before tasks that consume them. API handlers receive services rather than database-specific values.
