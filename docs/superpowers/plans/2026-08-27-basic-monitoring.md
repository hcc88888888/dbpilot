# DBPilot Basic Monitoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn identity-validated Agent metrics into a scoped monitoring query API and a specialized DBPilot basic-monitoring workbench for MySQL, PostgreSQL, and Oracle.

**Architecture:** Introduce a storage-neutral monitoring query boundary beside the alert repository. The control-plane HTTP layer validates bounded time/range parameters, applies tenant/project/instance authorization, and returns normalized overview, instance, series, and capability DTOs. The existing static frontend receives a dedicated `monitoring-api.js` adapter and `monitoring-center.js` controller; it never queries Agent, databases, or VictoriaMetrics directly.

**Tech Stack:** Go 1.27, existing PostgreSQL repository/migrations and gRPC ingest path, static HTML/CSS/vanilla JavaScript, browser Fetch/AbortController, Node.js built-in `node:test`; no new frontend framework or message queue.

**Spec:** `docs/superpowers/specs/2026-08-27-basic-monitoring-design.md`

## Global Constraints

- 首期覆盖 MySQL、PostgreSQL、Oracle，并保留其他数据库适配器的统一指标扩展点。
- 前端不直接访问 Agent、数据库或 VictoriaMetrics；所有查询走租户/项目作用域控制面 API。
- 时间范围默认最近 1 小时，最大 7 天；缺失桶明确为 `null`，不补造 0。
- 采样超过两个采集周期未更新标记为“数据陈旧”，不伪装为健康。
- 服务端错误、凭据、连接串和原始 Agent payload 不进入前端 DTO、日志或审计摘要。
- 查询限制最大时间范围、实例数、指标数、聚合桶数和响应大小，超限返回稳定错误。
- 前端演示模式标注 `source: "demo"`，HTTP 请求失败时不得回退到演示数据。
- 不新增 PromQL 编辑器、复杂图表编排、写入代理、慢 SQL、巡检、报告或消息队列功能。
- 保留未跟踪的 `backend/internal/telemetry/dbpilot-spool/`，不得修改、删除或暂存。

---

## File Structure

| File | Responsibility |
| --- | --- |
| `backend/internal/monitoring/model.go` | Monitoring DTOs, bounded query types, metric health/aggregation helpers. |
| `backend/internal/monitoring/store.go` | Storage-neutral `QueryStore` interface plus in-memory implementation for deterministic tests. |
| `backend/internal/monitoring/postgres.go` | PostgreSQL metric sample and instance queries; redacted DTO mapping. |
| `backend/internal/monitoring/model_test.go` | Range, stale-sample, missing-bucket, and capability tests. |
| `backend/internal/monitoring/postgres_test.go` | Query/store contract tests with `sqlmock`-style existing test seams or repository fixture. |
| `backend/internal/controlplane/monitoring_http.go` | Scoped monitoring handlers and query parameter validation. |
| `backend/internal/controlplane/http.go` | Route registration and monitoring service wiring. |
| `backend/internal/controlplane/monitoring_http_test.go` | HTTP contract, scope, pagination, unauthorized, and error tests. |
| `backend/internal/controlplane/services.go` | Add monitoring query dependency to service composition without changing existing alert APIs. |
| `monitoring-api.js` | Browser adapter, demo fixtures, HTTP paths, DTO sanitization and fixed errors. |
| `monitoring-center.js` | Monitoring workbench state, renderers, filters, range switch and safe field presentation. |
| `monitoring-center.css` | Specialized dashboard/table/detail responsive styles. |
| `index.html` | Load monitoring assets in deterministic order. |
| `app.js` | Route `monitoring` sidebar entry to the specialized workbench. |
| `tests/monitoring-api.test.js` | Node adapter tests. |
| `tests/monitoring-center.test.js` | Node pure helper and event-flow tests. |
| `docs/basic-monitoring-operations.md` | Runtime limits, storage configuration, and demo/production behavior. |

### Task 1: Monitoring model, bounded query contract, and storage adapter

**Files:**
- Create: `backend/internal/monitoring/model.go`
- Create: `backend/internal/monitoring/store.go`
- Create: `backend/internal/monitoring/model_test.go`

**Interfaces:**
- Consumes: `alert.Scope`, `alert.MetricSample`, existing adapter capability metadata.
- Produces: `monitoring.QueryStore` with `Overview(ctx, scope, RangeQuery)`, `ListInstances(ctx, scope, InstanceQuery)`, `GetInstance(ctx, scope, instanceID, RangeQuery)`, `Series(ctx, scope, SeriesQuery)`, and `Capabilities(ctx, scope)`.
- Produces: `monitoring.RangeQuery{From, To time.Time, Step time.Duration}` and normalized DTOs `Overview`, `Instance`, `Series`, `Capability`.

- [ ] **Step 1: Write failing tests for range limits, stale state, and missing buckets**

```go
func TestRangeQueryValidateDefaultsAndRejectsMoreThanSevenDays(t *testing.T) {
    now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
    query := RangeQuery{To: now}
    require.NoError(t, query.Validate(now))
    require.Equal(t, now.Add(-time.Hour), query.From)
    require.ErrorIs(t, (RangeQuery{From: now.Add(-8 * 24 * time.Hour), To: now}).Validate(now), ErrRangeTooLarge)
}

func TestClassifySampleMarksTwoIntervalsWithoutUpdateAsStale(t *testing.T) {
    status := ClassifySample(time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC), time.Date(2026, 8, 27, 9, 29, 0, 0, time.UTC), 15*time.Minute)
    require.Equal(t, StatusStale, status)
}

func TestBuildSeriesPreservesMissingBucketsAsNull(t *testing.T) {
    series := BuildSeries("host.cpu", time.Unix(0, 0).UTC(), time.Unix(120, 0).UTC(), time.Minute, []SamplePoint{{At: time.Unix(0, 0).UTC(), Value: 12}})
    require.Len(t, series.Buckets, 3)
    require.Nil(t, series.Buckets[1].Value)
}
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./internal/monitoring -run 'TestRangeQuery|TestClassifySample|TestBuildSeries' -v`

Expected: FAIL because the monitoring package and its contracts do not exist.

- [ ] **Step 3: Implement the storage-neutral model and in-memory query store**

```go
const (
    DefaultRange = time.Hour
    MaximumRange = 7 * 24 * time.Hour
    MaximumBuckets = 1000
)

type QueryStore interface {
    Overview(context.Context, alert.Scope, RangeQuery) (Overview, error)
    ListInstances(context.Context, alert.Scope, InstanceQuery) (InstancePage, error)
    GetInstance(context.Context, alert.Scope, string, RangeQuery) (InstanceDetail, error)
    Series(context.Context, alert.Scope, SeriesQuery) (Series, error)
    Capabilities(context.Context, alert.Scope) ([]Capability, error)
}
```

Validate UTC-normalized ranges, `from < to`, `to-from <= 7d`, positive step, and a computed bucket count no greater than 1000. Make `ClassifySample` return `healthy`, `stale`, or `offline` from last sample and heartbeat timestamps. Make `BuildSeries` allocate every bucket and leave missing `Value *float64` nil. The in-memory store must filter by exact scope and instance ID, return stable `nextOffset`, and copy maps/slices before returning.

- [ ] **Step 4: Run model tests to verify they pass**

Run: `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./internal/monitoring -run 'TestRangeQuery|TestClassifySample|TestBuildSeries' -v`

Expected: PASS.

- [ ] **Step 5: Add tests for DTO redaction and cross-scope rejection**

```go
func TestInstanceDTONeverCarriesRawPayloadOrSecret(t *testing.T) {
    got := RedactInstance(Instance{Labels: map[string]string{"password": "hidden", "engine": "mysql"}, RawPayload: "secret"})
    require.NotContains(t, got.Labels, "password")
    require.Empty(t, got.RawPayload)
}
```

- [ ] **Step 6: Run the complete monitoring package suite and commit**

Run: `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./internal/monitoring -count=1`

Expected: PASS with clean output.

```bash
git add backend/internal/monitoring
git commit -m "feat(monitoring): add bounded query model and store"
```

### Task 2: Scoped Control Plane monitoring API

**Files:**
- Create: `backend/internal/monitoring/postgres.go`
- Create: `backend/internal/controlplane/monitoring_http.go`
- Create: `backend/internal/controlplane/monitoring_http_test.go`
- Modify: `backend/internal/controlplane/services.go`
- Modify: `backend/internal/controlplane/http.go`
- Modify: `backend/internal/alert/migrations/` with one versioned metric/instance migration only if the existing repository has no compatible tables

**Interfaces:**
- Consumes: Task 1 `monitoring.QueryStore` and `RangeQuery`.
- Produces: scoped routes `GET /monitoring/overview`, `GET /monitoring/instances`, `GET /monitoring/instances/{id}`, `GET /monitoring/series`, and `GET /monitoring/capabilities` under `/api/v1/tenants/{tenantID}/projects/{projectID}`.
- Produces: stable API errors for bad range, unauthorized scope, missing instance, and bounded query overflow.

- [ ] **Step 1: Write failing HTTP contract tests**

```go
func TestMonitoringRoutesUseScopeAndRejectCrossProjectInstance(t *testing.T) {
    fixture := monitoringFixture(t)
    response := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/monitoring/overview?from=2026-08-27T09:00:00Z&to=2026-08-27T10:00:00Z", memberFor("t1", "p1"), nil)
    require.Equal(t, http.StatusOK, response.Code)
    response = fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/monitoring/instances/other", memberFor("t1", "p1"), nil)
    require.Equal(t, http.StatusNotFound, response.Code)
}

func TestMonitoringRoutesRejectRangeAndQueryOverflow(t *testing.T) {
    fixture := monitoringFixture(t)
    response := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/monitoring/series?from=2026-08-01T00:00:00Z&to=2026-08-10T00:00:00Z", memberFor("t1", "p1"), nil)
    require.Equal(t, http.StatusBadRequest, response.Code)
}
```

- [ ] **Step 2: Run the focused HTTP tests to verify they fail**

Run: `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./internal/controlplane -run TestMonitoringRoutes -v`

Expected: FAIL because monitoring routes and fixture store wiring are absent.

- [ ] **Step 3: Implement PostgreSQL query mapping and scoped handlers**

Implement query parameters with RFC3339 parsing, `step` duration parsing, `limit` 1–200, `offset` >= 0, and engine/status allowlists. Resolve scope exclusively from authenticated path middleware. Use `respondScoped`/existing fixed API error mapping, redact server errors, and enforce the Task 1 range caps before querying. Return `source: "control-plane"`, `scope`, DTO payload, and `next_offset`; never echo request scope claims from stored samples. If no metric table exists, add a migration containing tenant/project/instance/sample indexes and bounded retention metadata, without changing alert tables.

- [ ] **Step 4: Run HTTP tests and existing control-plane tests**

Run: `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./internal/controlplane -count=1`

Expected: PASS.

- [ ] **Step 5: Add typed DTO contract tests for stale, offline, missing, and capability responses**

```go
func TestMonitoringResponseMarksMissingValueNullAndStaleInstance(t *testing.T) {
    fixture := monitoringFixture(t)
    response := fixture.request(http.MethodGet, "/api/v1/tenants/t1/projects/p1/monitoring/instances/db-1?from=2026-08-27T09:00:00Z&to=2026-08-27T10:00:00Z", memberFor("t1", "p1"), nil)
    require.Equal(t, http.StatusOK, response.Code)
    require.Contains(t, response.Body.String(), `"status":"stale"`)
    require.Contains(t, response.Body.String(), `"value":null`)
}
```

- [ ] **Step 6: Run full Go suite and commit**

Run: `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./... -count=1`

Expected: PASS.

```bash
git add backend/internal/monitoring backend/internal/controlplane backend/internal/alert/migrations
git commit -m "feat(monitoring): expose scoped control plane queries"
```

### Task 3: Self-developed monitoring frontend

**Files:**
- Create: `monitoring-api.js`
- Create: `monitoring-center.js`
- Create: `monitoring-center.css`
- Create: `tests/monitoring-api.test.js`
- Create: `tests/monitoring-center.test.js`
- Modify: `index.html`
- Modify: `app.js`

**Interfaces:**
- Consumes: Task 2 routes and normalized JSON DTOs.
- Produces: `window.DBPilotMonitoringApi.create({ baseUrl?, fetchImpl?, available? })` and `window.DBPilotMonitoringCenter.create({ root, api, scope, permissions, onToast })`.
- Produces: views `overview`, `instances`, `instance-detail`; helpers `validateRange`, `safeMetricValue`, `formatMonitoringStatus`, and `buildMonitoringQuery`.

- [ ] **Step 1: Write failing adapter and helper tests**

```js
test('monitoring HTTP paths are always scoped and demo data is explicit', async () => {
  const seen = [];
  const api = createMonitoringApi({ baseUrl: 'https://control.example', fetchImpl: async (url) => { seen.push(url); return new Response(JSON.stringify({ items: [] })); } });
  await api.getOverview({ tenantId: 't/1', projectId: 'p 1' }, { from: '2026-08-27T09:00:00Z', to: '2026-08-27T10:00:00Z' });
  assert.equal(seen[0], 'https://control.example/api/v1/tenants/t%2F1/projects/p%201/monitoring/overview?from=2026-08-27T09%3A00%3A00Z&to=2026-08-27T10%3A00%3A00Z');
});

test('range validation rejects more than seven days and preserves missing values', () => {
  assert.equal(validateRange('2026-08-01T00:00:00Z', '2026-08-10T00:00:00Z').kind, 'range-too-large');
  assert.equal(safeMetricValue(null), '—');
});
```

- [ ] **Step 2: Run frontend tests to verify they fail**

Run: `node --test tests/monitoring-api.test.js tests/monitoring-center.test.js`

Expected: FAIL with module-not-found for `monitoring-api.js`.

- [ ] **Step 3: Implement adapter with demo/HTTP separation and stable errors**

Implement `getOverview`, `listInstances`, `getInstance`, `getSeries`, and `getCapabilities`. Use the validated scope supplied by the controller, URL-encode path IDs, build only allowlisted query fields, and map HTTP `400/401/403/404/413/5xx` to fixed user-safe errors. Demo responses carry `source: "demo"`; an HTTP rejection never switches adapter mode. Strip raw payload, secret, token, password, connection-string, and server-error fields from all returned DTOs.

- [ ] **Step 4: Implement the specialist workbench**

Render health cards, source badge, time range control, instance filters, instance table, metric trend panel, status text, stale/offline labels, null-value gaps, loading/empty/error/unauthorized states, retry button, and instance detail drawer. On scope/range change abort the prior request, clear selected instance and series, then reload overview/list. Use `permissions.manage` only for custom metric entry visibility; never imply it grants backend authorization. Route `monitoring` sidebar item here and leave all other generic feature routes intact.

- [ ] **Step 5: Run frontend suite and syntax checks**

Run: `node --test tests/monitoring-api.test.js tests/monitoring-center.test.js tests/alert-api.test.js tests/alert-center.test.js`

Expected: PASS.

Run: `node --check monitoring-api.js; node --check monitoring-center.js; node --check app.js`

Expected: all commands exit 0.

- [ ] **Step 6: Commit frontend monitoring workbench**

```bash
git add index.html app.js monitoring-api.js monitoring-center.js monitoring-center.css tests/monitoring-api.test.js tests/monitoring-center.test.js
git commit -m "feat(monitoring): add self-developed monitoring workbench"
```

### Task 4: Integration, operations documentation, and browser acceptance

**Files:**
- Create: `docs/basic-monitoring-operations.md`
- Modify: `backend/internal/controlplane/monitoring_http_test.go` for Agent-to-query integration fixture
- Modify: `tests/monitoring-center.test.js` for browser event regressions found during acceptance
- Modify: `monitoring-center.js` or `monitoring-center.css` only for scoped acceptance defects

**Interfaces:**
- Consumes: Task 1–3 query/store/API/frontend interfaces.
- Produces: verified end-to-end metric flow, documented limits/configuration, and a browser-verified monitoring page.

- [ ] **Step 1: Add Agent/ingest-to-query integration coverage**

```go
func TestMetricIngestFeedsMonitoringQueriesWithResolvedScope(t *testing.T) {
    fixture := monitoringFixture(t)
    err := fixture.consumer.ConsumeMetricBatch(context.Background(), "agent-a", []byte(`{"samples":[{"name":"host.cpu","value":42,"sampled_at":"2026-08-27T09:59:00Z","labels":{"instance":"mysql-1","engine":"mysql"}}]}`), fixture.now)
    require.NoError(t, err)
    result, err := fixture.store.ListInstances(context.Background(), alert.Scope{TenantID: "t1", ProjectID: "p1"}, monitoring.InstanceQuery{Limit: 20})
    require.NoError(t, err)
    require.Equal(t, "mysql-1", result.Items[0].ID)
}
```

- [ ] **Step 2: Run backend and frontend automated verification**

Run: `D:\AI\codex\workspace\数据库运维管理系统\.tooling\go\bin\go.exe test ./... -count=1`

Expected: PASS.

Run: `node --test tests/*.test.js`

Expected: PASS.

Run: `node --check monitoring-api.js; node --check monitoring-center.js; node --check app.js; git diff --check`

Expected: all commands exit 0 and diff check has no output.

- [ ] **Step 3: Verify browser flows**

Start `python -m http.server 4173` from the worktree and open the page in the in-app browser. Select `基础监控`; verify `监控概览`, `实例列表`, and `实例详情` display domain-specific content, `演示数据` is visible in demo mode, range switching reloads without stale data, null gaps are not rendered as zero, stale/offline text is visible, and 390px width keeps filters/table/detail readable. Inject a forbidden adapter response and confirm a fixed permission message with retry and no demo fallback.

- [ ] **Step 4: Document operation and safety limits**

Document metric names, default/max range, step/bucket limits, stale classification, storage selection, source badge semantics, authorization behavior, retention, and troubleshooting. Explicitly state that the UI is not a direct VictoriaMetrics/Agent client and that raw payload/credentials are never exposed.

- [ ] **Step 5: Commit integration documentation and acceptance fixes**

```bash
git add backend/internal/controlplane/monitoring_http_test.go tests/monitoring-center.test.js monitoring-center.js monitoring-center.css docs/basic-monitoring-operations.md
git commit -m "test(monitoring): verify end-to-end monitoring flow"
```

## Plan Self-Review

### Spec coverage

- Agent → ingest → query → frontend data flow: Tasks 1, 2, and 4.
- MySQL/PostgreSQL/Oracle capability catalog and extension point: Tasks 1–3.
- Overview, instances, latest values, trends, missing buckets, stale/offline state: Tasks 1–3.
- Scope/instance authorization, bounded ranges, response limits, fixed errors: Tasks 1–2.
- Demo marker/no fallback, safe DTOs, responsive pages and permission states: Task 3 and 4.
- Storage-neutral in-memory/VictoriaMetrics replacement boundary and operations documentation: Tasks 1, 2, and 4.

No requirement is unassigned.

### Placeholder scan

The plan contains no deferred-work markers, vague implementation directives, or undefined task hand-offs. Every task has files, interfaces, executable tests, expected results, and a commit boundary.

### Type consistency

Task 1 `QueryStore`, `RangeQuery`, `InstanceQuery`, `SeriesQuery`, `Overview`, `InstancePage`, `InstanceDetail`, `Series`, and `Capability` are consumed by Task 2. Task 2 route DTOs are consumed by Task 3 adapter methods. Task 3 controller outputs are verified by Task 4 browser and event tests. Names and scope parameters remain consistent throughout.
