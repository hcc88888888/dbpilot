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

test('overview renders explicit health levels, partial state, and source label', () => {
  const markup = renderInspectionOverviewMarkup({
    source: 'control-plane', target_count: 4, online_target_count: 3,
    finding_level_counts: { healthy: 8, warning: 2, critical: 1, unsupported: 3, missing_data: 4 },
    latest_run_status_counts: { completed: 2, partial: 1, failed: 1 },
  });
  for (const expected of ['健康', '警告', '严重', '不支持', '数据缺失', '部分完成', '控制面服务']) assert.match(markup, new RegExp(expected));
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
