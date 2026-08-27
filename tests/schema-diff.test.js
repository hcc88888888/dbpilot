import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildDiffFilters,
  createSchemaDiffCenter,
  diffStatusLabel,
  objectStatusLabel,
  objectTypeLabel,
  renderDiffDetailMarkup,
  renderDiffListMarkup,
  schemaDiffFailureMessage,
  schemaDiffSourceLabel,
  validateDiffRequest,
} from '../schema-diff.js';
import { createSchemaDiffApi } from '../schema-diff-api.js';

test('diff, object status, and object type labels map to fixed Chinese text', () => {
  assert.deepEqual(['completed', 'running'].map(diffStatusLabel), ['已完成', '对比中']);
  assert.equal(diffStatusLabel('unknown-status'), '未知');
  assert.deepEqual(['added', 'removed', 'changed', 'identical'].map(objectStatusLabel), ['新增', '删除', '变更', '一致']);
  assert.equal(objectStatusLabel('unknown-status'), '未知');
  assert.deepEqual(
    ['table', 'index', 'view', 'procedure', 'function', 'trigger'].map(objectTypeLabel),
    ['表', '索引', '视图', '存储过程', '函数', '触发器'],
  );
  assert.equal(objectTypeLabel('sequence'), 'sequence');
});

test('validateDiffRequest rejects identical instances, missing instances, empty types and empty title', () => {
  const same = validateDiffRequest({ title: 't', source_instance_id: 'a', target_instance_id: 'a', object_types: ['table'] });
  assert.equal(same.target_instance_id, '源实例与目标实例不能相同');
  const missing = validateDiffRequest({ title: 't', source_instance_id: '', target_instance_id: 'b', object_types: ['table'] });
  assert.equal(missing.source_instance_id, '请选择源实例');
  assert.equal(validateDiffRequest({ title: 't', source_instance_id: 'a', target_instance_id: '', object_types: ['table'] }).target_instance_id, '请选择目标实例');
  const noTypes = validateDiffRequest({ title: 't', source_instance_id: 'a', target_instance_id: 'b', object_types: [] });
  assert.equal(noTypes.object_types, '请至少选择一种对象类型');
  const noTitle = validateDiffRequest({ title: '', source_instance_id: 'a', target_instance_id: 'b', object_types: ['table'] });
  assert.equal(noTitle.title, '请填写对比标题');
  assert.deepEqual(
    validateDiffRequest({ title: '订单主库 → 分析从库 结构对比', source_instance_id: 'mysql-prod-order-01', target_instance_id: 'mysql-analytics-replica', object_types: ['table', 'view'] }),
    {},
  );
});

test('buildDiffFilters drops empty values and passes through valid filters', () => {
  assert.deepEqual(
    buildDiffFilters({ status: 'completed', search: '   ', page: 2, pageSize: 8 }),
    { status: 'completed', page: 2, pageSize: 8 },
  );
  assert.deepEqual(buildDiffFilters(new Map([['status', ''], ['search', '订单']])), { search: '订单' });
});

test('renderDiffListMarkup labels demo source and renders Chinese status labels', () => {
  const markup = renderDiffListMarkup({
    items: [{
      id: 'SCD-20260828-001', title: '订单主库 → 分析从库 结构对比',
      source: { instance_id: 'mysql-prod-order-01', instance_name: '订单主库' },
      target: { instance_id: 'mysql-analytics-replica', instance_name: '分析从库' },
      status: 'completed', summary: { added: 2, removed: 1, changed: 4, identical: 37 },
      created_at: '2026-08-28T09:02:00Z',
    }],
    source: 'demo',
    filters: {},
    page: 1,
    pageSize: 8,
    total: 1,
    totalPages: 1,
  });
  assert.match(markup, /演示数据/);
  assert.match(markup, /已完成/);
  assert.match(markup, /SCD-20260828-001/);
  assert.match(markup, /订单主库/);
  assert.match(markup, /分析从库/);
  assert.match(markup, /scd-cell-pending">7<\/span>/);
});

test('renderDiffListMarkup escapes user content', () => {
  const markup = renderDiffListMarkup({
    items: [{
      id: 'SCD-2', title: '<script>alert(1)</script>',
      source: { instance_id: 'mysql-prod-order-01', instance_name: '订单主库' },
      target: { instance_id: 'mysql-analytics-replica', instance_name: '分析从库' },
      status: 'running', summary: {}, created_at: '2026-08-28T09:02:00Z',
    }],
    source: 'demo',
    filters: {},
  });
  assert.doesNotMatch(markup, /<script>alert\(1\)<\/script>/);
  assert.match(markup, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(markup, /对比中/);
});

test('renderDiffDetailMarkup renders summary counts, object rows, changes and DDL', () => {
  const markup = renderDiffDetailMarkup({
    id: 'SCD-20260828-001', title: '订单主库 → 分析从库 结构对比',
    source: { instance_id: 'mysql-prod-order-01', instance_name: '订单主库' },
    target: { instance_id: 'mysql-analytics-replica', instance_name: '分析从库' },
    created_by: '张运维', created_at: '2026-08-28T09:02:00Z', status: 'completed',
    summary: { added: 2, removed: 1, changed: 4, identical: 37 },
    objects: [
      { object_type: 'table', schema: 'orders', name: 'order_items', status: 'changed', changes: ['新增列 refund_amount DECIMAL(10,2)', '列 status 类型变更'] },
      { object_type: 'index', schema: 'orders', name: 'idx_created_at', status: 'added', changes: ['新增索引'] },
      { object_type: 'view', schema: 'analytics', name: 'v_order_summary', status: 'removed', changes: ['目标端不存在'] },
      { object_type: 'table', schema: 'orders', name: 'orders', status: 'identical', changes: [] },
    ],
    generated_ddl: 'ALTER TABLE orders.order_items\n  ADD COLUMN refund_amount DECIMAL(10,2);',
    synced_at: '',
  }, { canManage: true });
  assert.match(markup, /差异摘要/);
  assert.match(markup, /订单主库/);
  assert.match(markup, /张运维/);
  assert.match(markup, /order_items/);
  assert.match(markup, /新增列 refund_amount/);
  assert.match(markup, /无差异/);
  assert.match(markup, /ALTER TABLE orders\.order_items/);
  assert.match(markup, /data-scd-sync/);
  assert.match(markup, /data-scd-copy-ddl/);
});

test('renderDiffDetailMarkup escapes changes and DDL content, and hides sync without permission', () => {
  const markup = renderDiffDetailMarkup({
    id: 'SCD-1', title: 'x', status: 'completed',
    summary: { added: 0, removed: 0, changed: 0, identical: 0 },
    objects: [{ object_type: 'table', schema: 'orders', name: 't', status: 'changed', changes: ['新增列 <img src=x onerror=alert(1)>'] }],
    generated_ddl: 'ALTER TABLE <script>alert(1)</script>',
    synced_at: '',
  }, { canManage: false });
  assert.doesNotMatch(markup, /<script>alert\(1\)<\/script>/);
  assert.match(markup, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(markup, /<img src=x onerror=alert\(1\)>/);
  assert.match(markup, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(markup, /data-scd-sync/);
});

test('createSchemaDiffCenter renders overview stats and demo source badge', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const api = {
    async getOverview() {
      return {
        source: 'demo',
        total_diffs: 6,
        pending_changes: 13,
        synced_diffs: 2,
        recent_at: '2026-08-28T09:02:00Z',
        recent: [{
          id: 'SCD-20260828-001', title: '订单主库 → 分析从库 结构对比',
          source: { instance_id: 'mysql-prod-order-01', instance_name: '订单主库' },
          target: { instance_id: 'mysql-analytics-replica', instance_name: '分析从库' },
          status: 'completed', summary: { added: 2, removed: 1, changed: 4, identical: 37 },
          created_at: '2026-08-28T09:02:00Z',
        }],
      };
    },
  };
  const center = createSchemaDiffCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /对比任务/);
  assert.match(root.innerHTML, /待处理差异/);
  assert.match(root.innerHTML, /已同步任务/);
  assert.match(root.innerHTML, /最近对比/);
  assert.match(root.innerHTML, /演示数据/);
  assert.match(root.innerHTML, /订单主库 → 分析从库 结构对比/);
});

test('forbidden responses keep a fixed permission error with retry and no demo fallback', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const forbidden = Object.assign(new Error('unsafe server detail'), { kind: 'forbidden' });
  const api = { getOverview() { return Promise.reject(forbidden); } };
  const center = createSchemaDiffCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /当前账号没有该项目的操作权限/);
  assert.match(root.innerHTML, /data-schemadiff-retry/);
  assert.doesNotMatch(root.innerHTML, /演示数据/);
  assert.doesNotMatch(root.innerHTML, /unsafe server detail/);
});

test('scope change aborts the previous load and reloads with the new scope', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const calls = [];
  const pending = () => new Promise(() => {});
  const api = {
    getOverview(scope, signal) { calls.push(['overview', { ...scope }, signal]); return pending(); },
  };
  const center = createSchemaDiffCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  const firstSignal = calls[0][2];
  center.setScope({ tenantId: 't2', projectId: 'p2' });
  assert.equal(firstSignal.aborted, true);
  assert.equal(calls.some(([, scoped]) => scoped.tenantId === 't2' && scoped.projectId === 'p2'), true);
  assert.equal(center.getState().view, 'overview');
});

test('source and failure labels are safe and fixed', () => {
  assert.equal(schemaDiffSourceLabel('demo'), '演示数据');
  assert.equal(schemaDiffSourceLabel('http'), '控制面服务');
  assert.equal(schemaDiffSourceLabel('control-plane'), '控制面服务');
  assert.equal(schemaDiffFailureMessage({ kind: 'forbidden', message: 'password=unsafe' }), '当前账号没有该项目的操作权限');
  assert.equal(schemaDiffFailureMessage({ kind: 'network', message: 'token=unsafe' }), '无法连接控制面服务，请检查网络后重试');
  assert.equal(schemaDiffFailureMessage({ kind: 'unknown' }), '结构对比数据加载失败，请稍后重试');
});

test('demo adapter exposes at least six diffs', async () => {
  const api = createSchemaDiffApi();
  const result = await api.listDiffs({ tenantId: 't1', projectId: 'p1' }, {});
  assert.ok(result.items.length >= 6);
  assert.equal(result.source, 'demo');
  assert.equal(result.scope.tenantId, 't1');
  const statuses = new Set(result.items.map((diff) => diff.status));
  assert.ok(statuses.has('completed'), 'missing completed');
  assert.ok(statuses.has('running'), 'missing running');
});

test('demo listDiffs filters by status and search', async () => {
  const api = createSchemaDiffApi();
  const completed = await api.listDiffs({ tenantId: 't1', projectId: 'p1' }, { status: 'completed' });
  assert.ok(completed.items.length >= 4);
  assert.ok(completed.items.every((diff) => diff.status === 'completed'));
  const searched = await api.listDiffs({ tenantId: 't1', projectId: 'p1' }, { search: '用户中心' });
  assert.ok(searched.items.length >= 1);
});

test('demo createDiff validates, returns running, then completes with objects and DDL', async () => {
  const api = createSchemaDiffApi();
  await assert.rejects(
    api.createDiff({ tenantId: 't1', projectId: 'p1' }, {
      title: 't', source_instance_id: 'mysql-prod-order-01', target_instance_id: 'mysql-prod-order-01', object_types: ['table'],
    }),
    (error) => error.kind === 'validation',
  );
  const created = await api.createDiff({ tenantId: 't1', projectId: 'p1' }, {
    title: '订单主库 → 分析从库 结构对比',
    source_instance_id: 'mysql-prod-order-01',
    target_instance_id: 'mysql-analytics-replica',
    object_types: ['table', 'index'],
  });
  assert.equal(created.status, 'running');
  await new Promise((resolve) => setTimeout(resolve, 1300));
  const completed = await api.getDiff({ tenantId: 't1', projectId: 'p1' }, created.id);
  assert.equal(completed.status, 'completed');
  assert.ok(completed.summary.added + completed.summary.removed + completed.summary.changed + completed.summary.identical > 0);
  assert.ok(completed.objects.length > 0);
  assert.ok(completed.generated_ddl.length > 0);
  assert.equal(completed.source, 'demo');
});

test('demo applyDiff writes synced_at and history, then conflicts on repeat', async () => {
  const api = createSchemaDiffApi();
  const list = await api.listDiffs({ tenantId: 't1', projectId: 'p1' }, {});
  const unsynced = list.items.find((diff) => diff.status === 'completed' && !diff.synced_at);
  assert.ok(unsynced, 'expected an unsynced completed diff');
  const applied = await api.applyDiff({ tenantId: 't1', projectId: 'p1' }, unsynced.id);
  assert.ok(applied.synced_at);
  assert.ok(applied.history.some((entry) => entry.status === 'synced'));
  await assert.rejects(
    api.applyDiff({ tenantId: 't1', projectId: 'p1' }, unsynced.id),
    (error) => error.kind === 'conflict',
  );
});

test('demo diff DTOs redact credential fields', async () => {
  const api = createSchemaDiffApi();
  const list = await api.listDiffs({ tenantId: 't1', projectId: 'p1' }, {});
  assert.ok(!JSON.stringify(list).includes('token'));
  assert.ok(!JSON.stringify(list).includes('password'));
});

test('http adapter maps createDiff to POST /schema-diff/diffs under the scope prefix', async () => {
  let requested;
  const fetchImpl = async (url, init) => {
    requested = { url, init };
    return { ok: true, status: 200, json: async () => ({ diff: { id: 'SCD-1', status: 'running' } }) };
  };
  const api = createSchemaDiffApi({ baseUrl: 'https://ctl.example/', fetchImpl });
  const result = await api.createDiff({ tenantId: 't1', projectId: 'p1' }, {
    title: 't', source_instance_id: 'a', target_instance_id: 'b', object_types: ['table'],
  });
  assert.equal(requested.url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/schema-diff/diffs');
  assert.equal(requested.init.method, 'POST');
  assert.equal(result.source, 'http');
  assert.equal(result.id, 'SCD-1');
});

test('http adapter redacts secret fields and routes apply to POST .../apply', async () => {
  let requested;
  const fetchImpl = async (url, init) => {
    requested = { url, init };
    return {
      ok: true,
      status: 200,
      json: async () => ({ diff: { id: 'SCD-1', status: 'completed', connection_string: 'mysql://u:p@h', token: 'abc' } }),
    };
  };
  const api = createSchemaDiffApi({ baseUrl: 'https://ctl.example/', fetchImpl });
  const result = await api.getDiff({ tenantId: 't1', projectId: 'p1' }, 'SCD-1');
  assert.ok(!JSON.stringify(result).includes('connection_string'));
  assert.ok(!JSON.stringify(result).includes('token'));
  assert.ok(!JSON.stringify(result).includes('abc'));
  await api.applyDiff({ tenantId: 't1', projectId: 'p1' }, 'SCD-1');
  assert.equal(requested.url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/schema-diff/diffs/SCD-1/apply');
  assert.equal(requested.init.method, 'POST');
});

test('unavailable adapter rejects every method with a fixed error', async () => {
  const api = createSchemaDiffApi({ available: false });
  await assert.rejects(
    api.getOverview({ tenantId: 't', projectId: 'p' }),
    (error) => error.kind === 'unavailable' && error.message === '结构对比服务暂时不可用，请稍后重试',
  );
  await assert.rejects(api.createDiff({ tenantId: 't', projectId: 'p' }, {}), (error) => error.kind === 'unavailable');
  await assert.rejects(api.applyDiff({ tenantId: 't', projectId: 'p' }, 'x'), (error) => error.kind === 'unavailable');
});

async function flush() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}
