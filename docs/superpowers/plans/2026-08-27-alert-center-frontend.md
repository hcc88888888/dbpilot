# DBPilot Alert Center Frontend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace DBPilot's generic alert-management tab with a self-developed, production-oriented alert center that works in demo mode and against the delivered scoped control-plane APIs.

**Architecture:** Add a standalone `alert-api.js` adapter that owns scope-safe URL construction, DTO sanitization, demo data, and stable API errors. Add `alert-center.js` as a small stateful UI controller that renders specialized views into the existing feature-page region and delegates actions to the adapter. Keep the existing static-page approach: `app.js` only owns the dashboard and routes the `alerts-config` sidebar item into the new controller, while `alert-center.css` contains the module-specific responsive styles.

**Tech Stack:** Static HTML5, CSS3, browser-native ES modules/Fetch/AbortController, Node.js built-in `node:test` and `node:assert/strict`; no framework, package manager, build step, or additional runtime dependency.

**Spec:** `docs/superpowers/specs/2026-08-27-alert-center-frontend-design.md`

## Global Constraints

- Preserve the existing dark sidebar, light content area, compact cards, and restrained blue enterprise visual system.
- Do not add Vue, React, a frontend build tool, or any third-party browser dependency.
- Every backend request must use `/api/v1/tenants/{tenantId}/projects/{projectId}` from current UI scope; never take scope from a form field or URL query parameter.
- Use demo data only when HTTP mode is deliberately not configured; demo responses must expose `source: "demo"` and UI must visibly label them as local demo data.
- HTTP `401`, `403`, `404`, `409`, `413`, `415`, and `5xx` errors must remain HTTP errors; never silently return demo data after an HTTP failure.
- Never render Secret values, tokens, connection strings, raw delivery request bodies, or raw server error messages.
- Frontend controls provide misuse prevention only; back-end authorization remains authoritative. Mutations must reload server state after success.
- Do not modify or stage the pre-existing `backend/internal/telemetry/dbpilot-spool/` output directory.
- This plan does not add Prometheus queries, Alertmanager protocol compatibility, or fix the separately registered backend final-review items.

---

## File Structure

| File | Responsibility |
| --- | --- |
| `index.html` | Load the alert module scripts and module-specific stylesheet after the existing page assets. |
| `app.js` | Keep dashboard behavior; replace the generic `alerts-config` branch with `window.DBPilotAlertCenter.open()` and preserve the existing sidebar active state. |
| `alert-api.js` | Define `window.DBPilotAlertApi.create(options)`, demo/HTTP implementations, response normalization, safe error mapping, and scoped request construction. |
| `alert-center.js` | Define `window.DBPilotAlertCenter.create(options)`, route/view state, safe DOM rendering, filters, forms, mutation handlers, and scope switching. |
| `alert-center.css` | Specialized alert-center layout, table, detail, drawer, statuses, loading/empty/error states, and small-screen behavior. |
| `tests/alert-api.test.js` | Node tests for scope paths, demo marker, response sanitization, and stable HTTP error mapping. |
| `tests/alert-center.test.js` | Node tests for pure presentation/validation helpers exported by the UI module. |

### Task 1: Scoped API adapter and DTO safety boundary

**Files:**
- Create: `alert-api.js`
- Create: `tests/alert-api.test.js`
- Modify: `index.html:112` to load `alert-api.js` before `app.js`

**Interfaces:**
- Consumes: control-plane routes registered in `backend/internal/controlplane/http.go`.
- Produces: `window.DBPilotAlertApi.create({ baseUrl?: string, fetchImpl?: typeof fetch }): AlertApi`.
- Produces: `AlertApi` methods `getOverview(scope, signal)`, `listAlerts(scope, filters, cursor, signal)`, `getAlert(scope, id, signal)`, `acknowledgeAlert(scope, id, disposition, signal)`, `resolveAlert(scope, id, disposition, signal)`, `listRules(scope, signal)`, `saveRule(scope, rule, signal)`, `setRuleEnabled(scope, id, enabled, signal)`, `listNotificationPolicies(scope, signal)`, `saveNotificationPolicy(scope, policy, signal)`, `listTemplates(scope, signal)`, `saveTemplate(scope, template, signal)`, `listSilences(scope, signal)`, `saveSilence(scope, silence, signal)`, and `endSilence(scope, id, signal)`.
- Produces: `ApiFailure` shaped as `{ kind: "unauthorized" | "forbidden" | "not-found" | "conflict" | "validation" | "unavailable" | "network", message: string, status?: number }`.

- [ ] **Step 1: Write failing adapter tests for scoped URLs, demo mode, and secret stripping**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAlertApi } from '../alert-api.js';

test('HTTP adapter escapes scope and never accepts a response scope override', async () => {
  const requested = [];
  const api = createAlertApi({
    baseUrl: 'https://control.example',
    fetchImpl: async (url) => {
      requested.push(url);
      return new Response(JSON.stringify({ scope: { tenant_id: 'other', project_id: 'other' }, items: [] }));
    },
  });
  const result = await api.listAlerts({ tenantId: 'east/ops', projectId: 'core db' }, {}, null);
  assert.equal(requested[0], 'https://control.example/api/v1/tenants/east%2Fops/projects/core%20db/alerts');
  assert.deepEqual(result.scope, { tenantId: 'east/ops', projectId: 'core db' });
});

test('demo adapter marks data as demo and removes unsafe delivery fields', async () => {
  const api = createAlertApi();
  const detail = await api.getAlert({ tenantId: 'demo', projectId: 'production' }, 'alert-1');
  assert.equal(detail.source, 'demo');
  assert.equal('secret_ref' in detail.deliveries[0], false);
  assert.equal('body' in detail.deliveries[0], false);
});
```

- [ ] **Step 2: Run adapter tests to verify they fail**

Run: `node --test tests/alert-api.test.js`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `../alert-api.js`.

- [ ] **Step 3: Implement the adapter with the actual control-plane endpoint mapping**

```js
export function createAlertApi({ baseUrl = '', fetchImpl = globalThis.fetch } = {}) {
  const isHttp = Boolean(baseUrl);
  const request = (scope, path, init = {}, signal) => {
    const prefix = `/api/v1/tenants/${encodeURIComponent(scope.tenantId)}/projects/${encodeURIComponent(scope.projectId)}`;
    return fetchImpl(`${baseUrl}${prefix}${path}`, { ...init, signal }).then(normalizeHttp);
  };
  return isHttp ? createHttpAdapter(request) : createDemoAdapter();
}

function safeDelivery(value) {
  const { secret_ref, secretRef, body, request, response, ...safe } = value;
  return safe;
}
```

Implement `GET /overview`, `GET /alerts`, `GET /alerts/{id}`, `POST /alerts/{id}/acknowledge`, `POST /alerts/{id}/resolve`, `GET|POST|PUT /rules`, `POST /rules/{id}/enable`, `GET|POST|PUT /notification-policies`, `GET|POST|PUT /templates`, and `GET|POST|PUT|DELETE /silences`. Map any delete used for `endSilence` to `DELETE /silences/{id}`. The current HTTP endpoint supports `state`, `limit`, and `offset`; expose the spec's `cursor` API as an opaque `offset:<number>` token, map it to those query parameters, and preserve the server's stable `last_seen DESC, id ASC` order. Apply the other UI filter fields to normalized returned items until a later server-side filtering API is delivered. Normalize list responses to `{ source, scope, items, nextCursor }`; set `scope` from the passed argument rather than the response payload. Give errors only fixed Chinese messages, for example `403 -> "当前账号没有该项目的操作权限"` and `409 -> "对象已更新或存在引用冲突，请刷新后重试"`.

- [ ] **Step 4: Run the adapter tests to verify they pass**

Run: `node --test tests/alert-api.test.js`

Expected: PASS with both tests green.

- [ ] **Step 5: Add regression tests for HTTP error mapping and mutation request bodies**

```js
test('HTTP failure never falls back to demo data', async () => {
  const api = createAlertApi({
    baseUrl: 'https://control.example',
    fetchImpl: async () => new Response('{}', { status: 403 }),
  });
  await assert.rejects(
    () => api.listRules({ tenantId: 't1', projectId: 'p1' }),
    (error) => error.kind === 'forbidden' && error.message === '当前账号没有该项目的操作权限',
  );
});
```

- [ ] **Step 6: Run the full adapter suite**

Run: `node --test tests/alert-api.test.js`

Expected: PASS with scoped URL, demo safety, error mapping, and mutation tests green.

- [ ] **Step 7: Commit the adapter boundary**

```bash
git add index.html alert-api.js tests/alert-api.test.js
git commit -m "feat(alerts): add scoped frontend API adapter"
```

### Task 2: Alert-center controller, state model, and specialist navigation

**Files:**
- Create: `alert-center.js`
- Create: `tests/alert-center.test.js`
- Modify: `app.js:20-29` to open the alert controller for `alerts-config` rather than generate generic feature cards
- Modify: `index.html:113` to load `alert-center.js` before `app.js`
- Create: `alert-center.css`
- Modify: `index.html:13` to load `alert-center.css` after `enterprise-theme.css`

**Interfaces:**
- Consumes: `window.DBPilotAlertApi.create(options)` from Task 1.
- Produces: `window.DBPilotAlertCenter.create({ root, api, scope, permissions, onToast }): AlertCenter`.
- Produces: `AlertCenter.open(view?: AlertView): Promise<void>`, `AlertCenter.setScope(scope): Promise<void>`, and `AlertCenter.destroy(): void`.
- Produces: exported pure helpers `formatSeverity(value)`, `validateReason(value)`, `validateRule(input)`, and `safeText(value)` for Node tests.
- `AlertView` values are exactly `overview`, `alerts`, `alert-detail`, `rules`, `policies`, `templates`, and `silences`.

- [ ] **Step 1: Write failing pure-helper tests for user-safe rendering and form validation**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { formatSeverity, safeText, validateReason, validateRule } from '../alert-center.js';

test('safeText prevents markup from becoming alert-detail HTML', () => {
  assert.equal(safeText('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
});

test('rule validation requires metric, positive threshold, duration, period, and policy references', () => {
  assert.deepEqual(validateRule({ metric: '', threshold: 0, for: 'soon', evaluationEvery: '', notificationPolicyIds: [] }), {
    metric: '请选择指标', threshold: '阈值必须大于 0', for: '持续时长格式应为 5m 或 1h', evaluationEvery: '请选择评估周期', notificationPolicyIds: '至少选择一个通知策略',
  });
});
```

- [ ] **Step 2: Run UI-helper tests to verify they fail**

Run: `node --test tests/alert-center.test.js`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `../alert-center.js`.

- [ ] **Step 3: Implement the controller shell and replace the generic alert route**

```js
export function createAlertCenter({ root, api, scope, permissions = { manage: false }, onToast = () => {} }) {
  let currentScope = { ...scope };
  let aborter = null;
  let currentView = 'overview';
  return {
    open: async (view = 'overview') => { currentView = view; await renderCurrent(); },
    setScope: async (nextScope) => { aborter?.abort(); currentScope = { ...nextScope }; await renderCurrent(); },
    destroy: () => aborter?.abort(),
  };
}

function validateReason(value) {
  return /(?:password|token|secret|postgres(?:ql)?:\/\/[^\s]+)/i.test(value) ? '原因中不能包含凭据或连接串' : '';
}
```

In `app.js`, instantiate once with `root: featurePage`, `api: window.DBPilotAlertApi.create({ baseUrl: window.DBPILOT_CONTROL_PLANE_URL || '' })`, demo scope `{ tenantId: 'demo', projectId: 'production' }`, and `permissions: { manage: true }`. When sidebar key is `alerts-config`, hide dashboard banners/stat cards, call `alertCenter.open('overview')`, and do not call the generic `openFeature` renderer. Add alert-center internal nav with all seven exact `AlertView` values, plus a compact current tenant/project label and visible `演示数据` source badge.

- [ ] **Step 4: Run the UI-helper tests to verify they pass**

Run: `node --test tests/alert-center.test.js`

Expected: PASS with escaping and validation tests green.

- [ ] **Step 5: Add focused CSS for module layout and small screens**

```css
.alert-center { display: grid; gap: 20px; }
.alert-workbench { display: grid; grid-template-columns: 208px minmax(0, 1fr); gap: 20px; }
.alert-detail-grid { display: grid; grid-template-columns: minmax(0, 1.45fr) minmax(260px, .85fr); gap: 16px; }
@media (max-width: 860px) {
  .alert-workbench, .alert-detail-grid { grid-template-columns: 1fr; }
  .alert-subnav { overflow-x: auto; white-space: nowrap; }
}
```

Include text-and-color status tags, disabled-management explanation, loading skeleton, empty state, retryable stable error state, reusable drawer/modal layer, toast progress state, and focus-visible outlines. Do not redefine global sidebar styles.

- [ ] **Step 6: Run all frontend unit tests and a static syntax check**

Run: `node --test tests/alert-api.test.js tests/alert-center.test.js`

Expected: PASS.

Run: `node --check alert-api.js; node --check alert-center.js; node --check app.js`

Expected: all commands exit 0.

- [ ] **Step 7: Commit the alert-center shell**

```bash
git add index.html app.js alert-center.js alert-center.css tests/alert-center.test.js
git commit -m "feat(alerts): add specialist alert center shell"
```

### Task 3: Monitoring overview, alert list, and safe event detail lifecycle

**Files:**
- Modify: `alert-center.js` to implement `overview`, `alerts`, and `alert-detail` renderers and mutation handlers
- Modify: `alert-center.css` to implement overview cards, filter bar, cursor pager, evidence, delivery, and audit timeline components
- Modify: `tests/alert-center.test.js` to cover list/query and disposition validation helpers

**Interfaces:**
- Consumes: Task 1 `getOverview`, `listAlerts`, `getAlert`, `acknowledgeAlert`, and `resolveAlert` methods.
- Consumes: Task 2 `AlertCenter.open(view)`, `safeText`, and `validateReason`.
- Produces: `buildAlertFilters(formData): { state?: string, severity?: string, rule?: string, resource?: string, from?: string, to?: string }` and `validateDisposition({ category, reason }): Record<string, string>`.
- Produces: alert row navigation via `open('alert-detail')` with an internal selected event id, never an unscoped URL parameter.

- [ ] **Step 1: Write failing tests for list filters and secret-safe disposition input**

```js
test('buildAlertFilters removes empty fields and keeps the selected time range', () => {
  assert.deepEqual(buildAlertFilters(new Map([['state', 'firing'], ['severity', ''], ['from', '2026-08-27T00:00']])), {
    state: 'firing', from: '2026-08-27T00:00',
  });
});

test('disposition validation requires category and rejects a token-like reason', () => {
  assert.deepEqual(validateDisposition({ category: '', reason: 'token=abc.def.ghi' }), {
    category: '请选择处置分类', reason: '原因中不能包含凭据或连接串',
  });
});
```

- [ ] **Step 2: Run the focused tests to verify they fail**

Run: `node --test tests/alert-center.test.js`

Expected: FAIL because `buildAlertFilters` and `validateDisposition` are not exported.

- [ ] **Step 3: Render the overview and alert list with per-view states and cursor pagination**

```js
async function renderAlerts() {
  const result = await api.listAlerts(currentScope, filters, cursor, signal);
  root.innerHTML = renderAlertList({ items: result.items, nextCursor: result.nextCursor, filters, source: result.source });
}

function buildAlertFilters(entries) {
  return Object.fromEntries([...entries].filter(([, value]) => String(value).trim() !== ''));
}
```

Render overview health summary, state counts, evaluation health, a 24-hour text/area trend, focal instances, and recent events. Render alert list filters for state, severity, rule, resource, and time, a table with text severity labels, an empty state, a dedicated failed-state retry button, and `上一页`/`下一页` controls backed by the adapter's opaque offset cursor. Keep source data localized to the current scope; on `setScope`, abort old fetches, clear selected event and cursor history, then reload the active view.

- [ ] **Step 4: Render alert details and lifecycle actions without unsafe fields**

```js
async function submitDisposition(action, id, form) {
  const disposition = { category: form.category.value, reason: form.reason.value.trim() };
  const errors = validateDisposition(disposition);
  if (Object.keys(errors).length) return showFormErrors(errors);
  setBusy(form, true);
  await (action === 'acknowledge'
    ? api.acknowledgeAlert(currentScope, id, disposition, signal)
    : api.resolveAlert(currentScope, id, disposition, signal));
  onToast(action === 'acknowledge' ? '告警已确认并写入审计记录' : '告警已恢复并写入审计记录');
  await open('alert-detail');
}
```

Use a top status/action bar; evidence, resource labels, root-cause hint and disposition timeline in the main column; deliveries and related rule in the secondary column. Do not include `secret_ref`, `body`, `request`, `response`, token-like label values, or raw server messages in detail markup. When the selected event returns `not-found` or `forbidden`, clear selection, return to the list, and toast `对象已被删除或无权访问`.

- [ ] **Step 5: Run focused UI tests and inspect safe field output**

Run: `node --test tests/alert-center.test.js`

Expected: PASS.

Run: `node --check alert-center.js`

Expected: exit 0.

- [ ] **Step 6: Commit the event workbench**

```bash
git add alert-center.js alert-center.css tests/alert-center.test.js
git commit -m "feat(alerts): add alert lifecycle workbench"
```

### Task 4: Rule and notification-policy management views

**Files:**
- Modify: `alert-center.js` to implement `rules` and `policies` list/drawer/form renderers and save/enable actions
- Modify: `alert-center.css` to style rule evaluation summaries, selector chips, drawer forms, and policy delivery summaries
- Modify: `tests/alert-center.test.js` to cover duration, selector, and notification-policy form validation

**Interfaces:**
- Consumes: Task 1 `listRules`, `saveRule`, `setRuleEnabled`, `listNotificationPolicies`, and `saveNotificationPolicy`.
- Consumes: Task 2 `validateRule(input)` and management permission `permissions.manage`.
- Produces: `validatePolicy(input): Record<string, string>` and `sanitizePolicyForDisplay(policy): SafePolicy` where `SafePolicy` has `secretConfigured: boolean` but never has a secret value/reference.

- [ ] **Step 1: Write failing validation tests for rule duration and safe policy display**

```js
test('valid rule has bounded duration fields and a policy reference', () => {
  assert.deepEqual(validateRule({ metric: 'db.connections', threshold: 80, for: '10m', evaluationEvery: '1m', notificationPolicyIds: ['policy-1'] }), {});
});

test('policy display exposes configuration state but never a secret reference', () => {
  const safe = sanitizePolicyForDisplay({ name: '值班 Webhook', secret_ref: 'env://DBPILOT_TOKEN', target: 'https://hooks.example/ops' });
  assert.equal(safe.secretConfigured, true);
  assert.equal('secret_ref' in safe, false);
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/alert-center.test.js`

Expected: FAIL because `sanitizePolicyForDisplay` is not exported or policy validation is absent.

- [ ] **Step 3: Build the rule list, enable toggle, and validated editor drawer**

```js
function validateRule(input) {
  const errors = {};
  if (!input.metric) errors.metric = '请选择指标';
  if (!(Number(input.threshold) > 0)) errors.threshold = '阈值必须大于 0';
  if (!/^\d+[smhd]$/.test(input.for)) errors.for = '持续时长格式应为 5m 或 1h';
  if (!/^\d+[smhd]$/.test(input.evaluationEvery)) errors.evaluationEvery = '请选择评估周期';
  if (!input.notificationPolicyIds?.length) errors.notificationPolicyIds = '至少选择一个通知策略';
  return errors;
}
```

Show metric, aggregation, operator, threshold, evaluation period, lookback, duration, missing-data strategy, severity, label selector, policy references, enabled state, and updated time as rule-specific fields. Display a plain-language evaluation summary before save. Disable create/edit/enable controls when `permissions.manage` is false and place `需要项目管理权限` beside the controls. On a successful save or enable change, close the drawer, toast success, and reload `listRules`; on conflict preserve drawer values and show the fixed conflict message.

- [ ] **Step 4: Build the notification-policy list and validated editor drawer**

```js
function sanitizePolicyForDisplay(policy) {
  const { secret_ref, secretRef, ...safe } = policy;
  return { ...safe, secretConfigured: Boolean(secret_ref || secretRef) };
}

function validatePolicy(input) {
  const errors = {};
  if (!input.name?.trim()) errors.name = '请填写策略名称';
  if (!['webhook', 'email', 'sms'].includes(input.channel)) errors.channel = '请选择通知渠道';
  if (!input.target?.trim()) errors.target = '请填写渠道目标';
  if (!input.templateId) errors.templateId = '请选择通知模板';
  return errors;
}
```

Display route label matchers, severity scope, delivery channel/target, template name, enabled state, and only the `Secret 已配置` or `Secret 未配置` state. The form may submit a secret reference only from a masked/selectable field; it must never prefill an existing secret reference in edit mode. Render no webhook URL query values containing token-like keys. Reload policies after a successful save.

- [ ] **Step 5: Run all frontend tests and syntax checks**

Run: `node --test tests/alert-api.test.js tests/alert-center.test.js`

Expected: PASS.

Run: `node --check alert-center.js`

Expected: exit 0.

- [ ] **Step 6: Commit rules and policies**

```bash
git add alert-center.js alert-center.css tests/alert-center.test.js
git commit -m "feat(alerts): add rule and policy management views"
```

### Task 5: Template and silence management with audit-safe actions

**Files:**
- Modify: `alert-center.js` to implement `templates` and `silences` renderers, editors, previews, and end-silence confirmation
- Modify: `alert-center.css` to style template preview, variable chips, active/history silence states, and confirmation dialog
- Modify: `tests/alert-center.test.js` to cover template and silence form validation

**Interfaces:**
- Consumes: Task 1 `listTemplates`, `saveTemplate`, `listSilences`, `saveSilence`, and `endSilence`.
- Consumes: Task 2 `safeText`, `validateReason`, and `permissions.manage`.
- Produces: `validateTemplate(input): Record<string, string>`, `validateSilence(input): Record<string, string>`, and `isActiveSilence(silence, now): boolean`.

- [ ] **Step 1: Write failing template and silence validation tests**

```js
test('template validation requires name, subject, and body', () => {
  assert.deepEqual(validateTemplate({ name: '', subject: '', body: '' }), {
    name: '请填写模板名称', subject: '请填写通知标题', body: '请填写通知正文',
  });
});

test('silence must have matcher, future end time, and an ordinary-text reason', () => {
  assert.deepEqual(validateSilence({ matchers: {}, startsAt: '2026-08-27T10:00', endsAt: '2026-08-27T09:00', reason: 'secret=abc' }), {
    matchers: '至少添加一个匹配条件', endsAt: '结束时间必须晚于开始时间', reason: '原因中不能包含凭据或连接串',
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test tests/alert-center.test.js`

Expected: FAIL because template and silence validators are not exported.

- [ ] **Step 3: Implement templates as list plus side editor and variable-aware preview**

```js
function validateTemplate(input) {
  const errors = {};
  if (!input.name?.trim()) errors.name = '请填写模板名称';
  if (!input.subject?.trim()) errors.subject = '请填写通知标题';
  if (!input.body?.trim()) errors.body = '请填写通知正文';
  return errors;
}

function renderTemplatePreview(template) {
  return safeText(template.subject).replaceAll('{{event.id}}', 'alert-20260827-01');
}
```

Show name, revision, updated time, allowed variables (`{{event.id}}`, `{{event.state}}`, `{{event.severity}}`, `{{resource.name}}`), subject, and a text-only preview. Escape all template content in preview; do not execute templates or render HTML. Save only after client validation; reload templates after successful save. Disable management actions with the same project-management copy when appropriate.

- [ ] **Step 4: Implement silence list, editor, and explicit end confirmation**

```js
function isActiveSilence(silence, now = new Date()) {
  return new Date(silence.startsAt) <= now && now < new Date(silence.endsAt);
}

async function confirmEndSilence(id) {
  if (!window.confirm('结束静默后，匹配的告警将恢复通知。是否继续？')) return;
  await api.endSilence(currentScope, id, signal);
  onToast('静默已结束并写入审计记录');
  await open('silences');
}
```

Render separate active and history rows with matcher chips, creator, reason, starts/ends, and lifecycle timestamps. The editor supports a structured key/value matcher list, starts/ends, and reason. A successful save or end refreshes the list; conflict keeps entered data and gives the stable conflict message. Do not show any raw server audit payload.

- [ ] **Step 5: Run test suite and syntax checks**

Run: `node --test tests/alert-api.test.js tests/alert-center.test.js`

Expected: PASS.

Run: `node --check alert-center.js`

Expected: exit 0.

- [ ] **Step 6: Commit templates and silences**

```bash
git add alert-center.js alert-center.css tests/alert-center.test.js
git commit -m "feat(alerts): add template and silence management views"
```

### Task 6: Browser acceptance verification and integration polish

**Files:**
- Modify: `app.js` only if browser verification finds an alert-route integration defect
- Modify: `alert-center.js` only if browser verification finds an interaction, state, or scope-reset defect
- Modify: `alert-center.css` only if browser verification finds a responsive or visual usability defect
- Modify: `tests/alert-api.test.js` or `tests/alert-center.test.js` for every behavior defect corrected in this task

**Interfaces:**
- Consumes: all Task 1-5 public adapter and controller interfaces.
- Produces: a verified static application where all seven specialist views are accessible from the alert workbench and all blocked/failed states are safe and understandable.

- [ ] **Step 1: Start a local static server and open the application**

```powershell
$job = Start-Job { Set-Location 'D:\AI\codex\workspace\数据库运维管理系统\.worktrees\alert-control-plane'; python -m http.server 4173 }
```

Open `http://127.0.0.1:4173/index.html` in the in-app browser. Select `告警管理` in the sidebar and confirm the dashboard cards are hidden while the alert workbench opens with the visible `演示数据` marker.

- [ ] **Step 2: Manually verify each specialized view and lifecycle**

Use the alert workbench sub-navigation to open, in order: `监控概览`, `告警列表`, one `告警详情`, `规则管理`, `通知策略`, `模板管理`, and `静默管理`. Confirm each has domain-specific content rather than generic feature cards. In demo mode, acknowledge one alert, resolve another, create/edit a rule, toggle a rule, save a notification policy, save a template, create a silence, and end that silence; each action must show progress, a short success toast, then refreshed data.

- [ ] **Step 3: Verify failure and permission states using adapter injection in browser devtools**

Temporarily create the controller with a test adapter method that rejects `{ kind: 'forbidden', message: '当前账号没有该项目的操作权限' }`; verify the view shows the fixed message and retry button without demo data. Recreate with `permissions: { manage: false }`; verify all create/edit/enable/end controls are disabled and labelled `需要项目管理权限`.

- [ ] **Step 4: Verify responsive layout and unsafe-field exclusion**

At 390px viewport width, confirm sub-navigation remains horizontally usable, list filters stack, detail panels become one column, and primary action buttons remain visible. Inspect demo alert detail and notification policy DOM: no `secret_ref`, `token`, `password`, raw delivery `body`, `request`, or `response` field may be visible. Enter `token=abc.def.ghi` as a disposition reason and verify client validation prevents submission.

- [ ] **Step 5: Add a regression test for every defect found, then run automated verification**

```powershell
node --test tests/alert-api.test.js tests/alert-center.test.js
node --check alert-api.js
node --check alert-center.js
node --check app.js
git diff --check
```

Expected: all test and syntax commands pass; `git diff --check` has no output.

- [ ] **Step 6: Stop the local static server**

```powershell
Stop-Job $job
Remove-Job $job
```

- [ ] **Step 7: Commit browser-polish changes**

```bash
git add index.html app.js alert-api.js alert-center.js alert-center.css tests/alert-api.test.js tests/alert-center.test.js
git commit -m "test(alerts): verify alert center frontend"
```

## Plan Self-Review

### Spec coverage

- Seven specialist pages and replacement of the generic alert feature path: Tasks 2-5.
- Scoped API access, demo identity, context-reset behavior, and no HTTP-to-demo fallback: Tasks 1-3.
- Alert lifecycle, evidence, root-cause/disposition timeline, delivery history, and safe detail rendering: Task 3.
- Rules, policies, templates, and silences with specialist list/editor behavior: Tasks 4-5.
- Permission states, loading/empty/error/unauthorized handling, conflict handling, retries, and responsive use: Tasks 2-6.
- Secret/raw-message exclusion and reason validation: Tasks 1, 3-6.
- No framework or Prometheus/Alertmanager protocol scope expansion: Global Constraints and all tasks.

No spec requirements are unassigned.

### Placeholder scan

Checked the plan for deferred-work markers, vague error-handling directions, vague validation directions, and cross-task shorthand. No prohibited placeholder wording remains.

### Type consistency

`createAlertApi`, `createAlertCenter`, `AlertView`, `validateRule`, `validatePolicy`, `validateTemplate`, `validateSilence`, `validateDisposition`, `safeText`, and `validateReason` are introduced before later tasks consume them. All save/enable/end mutation names match the Task 1 adapter interface.
