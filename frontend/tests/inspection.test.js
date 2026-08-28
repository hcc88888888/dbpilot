import test from 'node:test';
import assert from 'node:assert/strict';
import { createInspectionApi } from '../modules/inspection/inspection-api.js';
import {
  createInspectionCenter,
  inspectionFailureMessage,
  renderInspectionOverviewMarkup,
  renderInspectionPolicyMarkup,
  renderInspectionReportMarkup,
  renderInspectionRunMarkup,
} from '../modules/inspection/inspection.js';

test('inspection api uses the generated scoped client with idempotency etag and abort options', async () => {
  const calls = [];
  const options = [];
  const fake = {
    forScope(scope) {
      calls.push({ method: 'scope', scope });
      return {
        inspection: {
          createInspectionRun(value, requestOptions) { calls.push({ method: 'create', value, requestOptions }); return Promise.resolve({ id: 'run-1' }); },
          updateInspectionPolicy(value, requestOptions) { calls.push({ method: 'update', value, requestOptions }); return Promise.resolve({ id: 'policy-1', version: 4 }); },
          cancelInspectionRun(value, requestOptions) { calls.push({ method: 'cancel', value, requestOptions }); return Promise.resolve({ id: 'run-1', status: 'collecting' }); },
        },
        requestOptions(value) { options.push(value); return { options: value }; },
      };
    },
  };
  const signal = new AbortController().signal;
  const api = createInspectionApi({ baseUrl: 'https://control.example', controlPlaneClient: fake });
  const scope = { tenantId: 'tenant-a', projectId: 'project-a' };
  await api.createRun(scope, { target_ids: ['agent-1'], item_versions: [{ item_id: 'cpu', version: 1 }] }, 'idem-run', signal);
  await api.updatePolicy(scope, 'policy-1', { name: 'Daily' }, '"3"', 'idem-policy', signal);
  await api.cancelRun(scope, 'run-1', 'idem-cancel', signal);

  assert.deepEqual(calls[0], { method: 'scope', scope });
  assert.deepEqual(calls.find((call) => call.method === 'create').value, { idempotencyKey: 'idem-run', createInspectionRunRequest: { target_ids: ['agent-1'], item_versions: [{ item_id: 'cpu', version: 1 }] } });
  assert.deepEqual(calls.find((call) => call.method === 'update').value, { policyId: 'policy-1', idempotencyKey: 'idem-policy', ifMatch: '"3"', updateInspectionPolicyRequest: { name: 'Daily' } });
  assert.deepEqual(calls.find((call) => call.method === 'cancel').value, { runId: 'run-1', idempotencyKey: 'idem-cancel' });
  assert.deepEqual(options, [
    { idempotencyKey: 'idem-run', signal },
    { idempotencyKey: 'idem-policy', etag: '"3"', signal },
    { idempotencyKey: 'idem-cancel', signal },
  ]);
});

test('configured inspection errors never fall back to demo data', async () => {
  const forbidden = Object.assign(new Error('unsafe server detail'), { kind: 'forbidden' });
  const client = {
    forScope() {
      return { inspection: { getInspectionOverview: () => Promise.reject(forbidden) }, requestOptions: (value) => value };
    },
  };
  const api = createInspectionApi({ baseUrl: 'https://control.example', controlPlaneClient: client });
  await assert.rejects(api.getOverview({ tenantId: 't', projectId: 'p' }), (error) => error === forbidden);
  assert.equal(inspectionFailureMessage(forbidden), '当前账号没有该项目的巡检查看权限');
});

test('configured inspection api keeps the generated client default token resolver', () => {
  assert.doesNotThrow(() => createInspectionApi({ baseUrl: 'https://control.example', fetchImpl: async () => new Response('{}') }));
});

test('inspection api normalizes generated Date fields without losing timestamps', async () => {
  const createdAt = new Date('2026-08-29T08:00:00Z');
  const client = { forScope: () => ({ inspection: { listInspectionRuns: () => Promise.resolve({ items: [{ id: 'run-1', createdAt }], page: { limit: 50, hasMore: false } }) }, requestOptions: (value) => value }) };
  const api = createInspectionApi({ baseUrl: 'https://control.example', controlPlaneClient: client });
  const page = await api.listRuns({ tenantId: 't', projectId: 'p' });
  assert.equal(page.items[0].created_at, '2026-08-29T08:00:00.000Z');
});

test('getPolicy reads the exact ETag from the generated raw response', async () => {
  const seen = [];
  const signal = new AbortController().signal;
  const client = { forScope: () => ({
    inspection: { getInspectionPolicyRaw(parameters, options) { seen.push({ parameters, options }); return Promise.resolve({ raw: { headers: new Headers({ ETag: '"17"' }) }, value: async () => ({ id: 'policy-1', version: 17, name: 'Daily' }) }); } },
    requestOptions: (value) => ({ requestOptions: value }),
  }) };
  const api = createInspectionApi({ baseUrl: 'https://control.example', controlPlaneClient: client });
  const policy = await api.getPolicy({ tenantId: 't', projectId: 'p' }, 'policy-1', signal);
  assert.equal(policy.etag, '"17"');
  assert.deepEqual(seen[0].parameters, { policyId: 'policy-1' });
  assert.deepEqual(seen[0].options, { requestOptions: { signal } });
});

test('overview renders explicit health levels and partial state', () => {
  const markup = renderInspectionOverviewMarkup({
    source: 'control-plane', target_count: 4, online_target_count: 3,
    finding_level_counts: { healthy: 8, warning: 2, critical: 1, unsupported: 3, missing_data: 4 },
    latest_run_status_counts: { completed: 2, partial: 1, failed: 1 },
  });
  for (const expected of ['健康', '警告', '严重', '不支持', '数据缺失', '部分完成']) assert.match(markup, new RegExp(expected));
});

test('policy form exposes accessible target and item selection and escapes names', () => {
  const markup = renderInspectionPolicyMarkup({
    policies: [{ id: 'policy-1', name: '<img src=x onerror=alert(1)>', version: 3, enabled: true, target_ids: ['agent-1'], item_versions: [{ item_id: 'cpu', version: 1 }] }],
    targets: [{ agent_id: 'agent-1', display_name: 'Primary DB', host: 'db-1.example' }],
    items: [{ id: 'cpu', version: 1, name: 'CPU utilization' }],
  }, { manage: true, execute: true });
  assert.match(markup, /aria-label="巡检目标"/);
  assert.match(markup, /aria-label="巡检项"/);
  assert.match(markup, /data-inspection-policy-save/);
  assert.match(markup, /data-inspection-policy-run="policy-1"/);
  assert.doesNotMatch(markup, /<img src=x/);
  assert.match(markup, /&lt;img src=x/);
});

test('policy edit form is prefilled and retains the server ETag', () => {
  const markup = renderInspectionPolicyMarkup({
    policies: [{ id: 'policy-1', name: 'Daily', version: 3, enabled: true, target_ids: ['agent-1'], item_versions: [{ item_id: 'cpu', version: 1 }] }],
    targets: [{ agent_id: 'agent-1', display_name: 'Primary DB', host: 'db-1.example' }],
    items: [{ id: 'cpu', version: 1, name: 'CPU utilization' }],
    editing_policy: { id: 'policy-1', name: 'Daily', enabled: true, etag: '"3"', labels: { role: 'database' }, target_ids: ['agent-1'], item_versions: [{ item_id: 'cpu', version: 1 }], target_timeout_seconds: 120, max_concurrency: 4, schedule: { cron: '0 2 * * *', timezone: 'Asia/Shanghai' } },
  }, { manage: true, execute: true });
  assert.match(markup, /data-inspection-policy-edit="policy-1"/);
  assert.match(markup, /value="Daily"/);
  assert.match(markup, /value="0 2 \* \* \*"/);
  assert.match(markup, /name="enabled" checked/);
  assert.match(markup, /name="target_timeout_seconds"[^>]*value="120"/);
  assert.match(markup, /name="max_concurrency"[^>]*value="4"/);
  assert.match(markup, /data-inspection-policy-etag="&quot;3&quot;"/);
  assert.match(markup, /value="agent-1" checked/);
  assert.match(markup, /value="cpu:1" checked/);
});

test('policy editing updates with exact ETag and refreshes instead of overwriting on 412', async () => {
  const calls = [];
  const toasts = [];
  let conflict = false;
  const api = {
    async listPolicies() { calls.push({ method: 'list' }); return { source: 'control-plane', items: [{ id: 'policy-1', name: 'Daily', version: 3 }] }; },
    async listTargets() { return { source: 'control-plane', items: [] }; },
    async listItems() { return { source: 'control-plane', items: [] }; },
    async getPolicy(scope, id, signal) { calls.push({ method: 'get', scope: { ...scope }, id, signal }); return { id, name: 'Daily', enabled: true, target_ids: [], item_versions: [], etag: '"3"' }; },
    async updatePolicy(scope, id, value, etag, key, signal) { calls.push({ method: 'update', scope: { ...scope }, id, value, etag, key, signal }); if (conflict) throw { kind: 'conflict', status: 412 }; return { id, version: 4 }; },
  };
  const root = { innerHTML: '', addEventListener() {} };
  const center = createInspectionCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' }, permissions: { view: true, manage: true }, onToast: (value) => toasts.push(value) });
  center.open('policies');
  await new Promise((resolve) => setTimeout(resolve, 0));
  await center.editPolicy('policy-1');
  await center.savePolicy({ name: 'Updated', enabled: true, target_ids: [], item_versions: [] });
  const update = calls.find((call) => call.method === 'update');
  assert.equal(update.etag, '"3"');
  assert.match(update.key, /^policy-update-/);

  await center.editPolicy('policy-1');
  conflict = true;
  const listsBefore = calls.filter((call) => call.method === 'list').length;
  await center.savePolicy({ name: 'Stale', enabled: true, target_ids: [], item_versions: [] });
  assert.equal(calls.filter((call) => call.method === 'update').length, 2);
  assert.equal(calls.filter((call) => call.method === 'list').length > listsBefore, true);
  assert.equal(toasts.at(-1), '策略已被其他操作者更新，已刷新最新版本');
});

test('scope change aborts an in-flight policy edit load', async () => {
  let editSignal;
  const api = {
    async getOverview() { return { source: 'control-plane' }; },
    getPolicy(_scope, _id, signal) { editSignal = signal; return new Promise(() => {}); },
  };
  const root = { innerHTML: '', addEventListener() {} };
  const center = createInspectionCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' }, permissions: { view: true, manage: true } });
  center.editPolicy('policy-1');
  center.setScope({ tenantId: 't2', projectId: 'p2' });
  assert.equal(editSignal.aborted, true);
});

test('run detail renders progress, partial unsupported missing data and permission-gated actions safely', () => {
  const markup = renderInspectionRunMarkup({
    id: 'run-1', status: 'partial', target_count: 3, completed_target_count: 2, failed_target_count: 1,
    targets: [
      { target_id: 'agent-1', agent_id: 'agent-1', status: 'succeeded' },
      { target_id: 'agent-2', agent_id: 'agent-2', status: 'unsupported', error_code: 'unsupported' },
      { target_id: 'agent-3', agent_id: 'agent-3', status: 'failed', error_code: 'missing_data' },
    ],
    findings: [{ id: 'finding-1', target_id: 'agent-3', item_id: 'cpu', item_version: 1, level: 'missing_data', summary: '<script>alert(1)</script>', recommendation: 'collect evidence' }],
  }, { execute: true });
  assert.match(markup, /部分完成/);
  assert.match(markup, /不支持/);
  assert.match(markup, /数据缺失/);
  assert.match(markup, /2 \/ 3/);
  assert.match(markup, /data-inspection-retry="run-1"/);
  assert.doesNotMatch(markup, /<script>alert/);
});

test('report detail renders immutable findings and only HTML JSON download affordance', () => {
  const markup = renderInspectionReportMarkup({
    id: 'report-1', run_id: 'run-1', status: 'completed', summary: 'warning=1', generated_at: '2026-08-29T08:00:00Z',
    artifacts: [{ artifact_id: 'report-1.html', kind: 'inspection-report' }, { artifact_id: 'report-1.json', kind: 'inspection-report' }],
    findings: [{ id: 'finding-1', target_id: 'agent-1', item_id: 'cpu', item_version: 1, level: 'warning', summary: 'CPU high', recommendation: 'Reduce load' }],
  });
  assert.match(markup, /HTML \/ JSON/);
  assert.match(markup, /CPU high/);
  assert.match(markup, /data-inspection-report-download="report-1"/);
  assert.doesNotMatch(markup, /PDF|Word|邮件/);
});

test('scope change aborts inspection load and reloads only the new scope', () => {
  const calls = [];
  const api = { getOverview(scope, signal) { calls.push({ scope: { ...scope }, signal }); return new Promise(() => {}); } };
  const root = { innerHTML: '', addEventListener() {} };
  const center = createInspectionCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  const first = calls[0];
  center.setScope({ tenantId: 't2', projectId: 'p2' });
  assert.equal(first.signal.aborted, true);
  assert.deepEqual(calls.at(-1).scope, { tenantId: 't2', projectId: 'p2' });
});

test('missing inspection view permission fails closed before loading data', () => {
  let calls = 0;
  const api = { getOverview() { calls += 1; return Promise.resolve({}); } };
  const root = { innerHTML: '', addEventListener() {} };
  const center = createInspectionCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' }, permissions: { view: false } });
  center.open('overview');
  assert.equal(calls, 0);
  assert.match(root.innerHTML, /没有该项目的巡检查看权限/);
});

test('shared inspection shell labels demo source in every view', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const page = { source: 'demo', items: [] };
  const api = {
    async getOverview() { return { source: 'demo', finding_level_counts: {}, latest_run_status_counts: {} }; },
    async listPolicies() { return page; }, async listTargets() { return page; }, async listItems() { return page; },
    async listRuns() { return page; }, async getRun() { return { source: 'demo', id: 'run-1', status: 'partial', target_count: 1 }; },
    async getReport() { return { source: 'demo', id: 'report-1', run_id: 'run-1', status: 'completed', findings: [] }; },
  };
  const center = createInspectionCenter({ root, api, scope: { tenantId: 'demo', projectId: 'production' }, permissions: { view: true } });
  for (const openView of [
    () => center.open('overview'),
    () => center.open('policies'),
    () => center.open('runs'),
    () => center.openRun('run-1'),
    () => center.openReport('report-1'),
  ]) {
    openView();
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.match(root.innerHTML, /ins-shell-source demo/);
    assert.match(root.innerHTML, /演示数据 · 非生产/);
  }
});
