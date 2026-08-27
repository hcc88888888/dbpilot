import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildLockFilters,
  createLocksCenter,
  formatDuration,
  lockModeLabel,
  lockStatusLabel,
  lockTypeLabel,
  locksFailureMessage,
  locksSourceLabel,
  renderLockDetailMarkup,
  renderLockListMarkup,
} from '../locks.js';
import { createLocksApi, redactLocksDTO } from '../locks-api.js';

test('lock type / status / mode labels map to fixed Chinese text with safe fallbacks', () => {
  assert.deepEqual(
    ['lock-wait', 'deadlock', 'long-txn', 'uncommitted'].map(lockTypeLabel),
    ['锁等待', '死锁', '长事务', '未提交事务'],
  );
  assert.equal(lockTypeLabel('nope'), '未知');
  assert.equal(lockTypeLabel(null), '未知');
  assert.deepEqual(
    ['active', 'resolved'].map(lockStatusLabel),
    ['进行中', '已解除'],
  );
  assert.equal(lockStatusLabel('nope'), '未知');
  assert.equal(lockModeLabel('X'), '排他锁');
  assert.equal(lockModeLabel('S'), '共享锁');
  assert.equal(lockModeLabel('IX'), '意向排他');
  assert.equal(lockModeLabel('IS'), '意向共享');
  assert.equal(lockModeLabel('RX'), '行排他');
  assert.equal(lockModeLabel('RS'), '行共享');
  assert.equal(lockModeLabel('ZZ'), 'ZZ');
  assert.equal(lockModeLabel(''), '未知');
});

test('formatDuration formats ms values and falls back for invalid input', () => {
  assert.equal(formatDuration(452000), '7.5min');
  assert.equal(formatDuration(128000), '2.1min');
  assert.equal(formatDuration(850), '850ms');
  assert.equal(formatDuration(2500), '2.5s');
  assert.equal(formatDuration(3600000), '1h');
  assert.equal(formatDuration(86400000), '1d');
  assert.equal(formatDuration(null), '—');
  assert.equal(formatDuration(undefined), '—');
  assert.equal(formatDuration('abc'), '—');
  assert.equal(formatDuration(-1), '—');
  assert.equal(formatDuration(Number.NaN), '—');
});

test('buildLockFilters drops empty values and passes through valid filters', () => {
  assert.deepEqual(
    buildLockFilters({ type: '', instance_id: 'mysql-prod-order-01', status: 'active', search: '   ', page: 2, pageSize: 12 }),
    { instance_id: 'mysql-prod-order-01', status: 'active', page: 2, pageSize: 12 },
  );
  assert.deepEqual(buildLockFilters(new Map([['type', ''], ['status', 'resolved']])), { status: 'resolved' });
});

test('renderLockListMarkup labels demo source and renders Chinese type/status labels', () => {
  const markup = renderLockListMarkup({
    items: [{
      id: 'LCK-20260828-001', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      type: 'lock-wait', status: 'active', summary: 'UPDATE orders 行锁互相等待',
      first_seen: '2026-08-28T02:12:00Z', duration_ms: 452000,
    }],
    source: 'demo',
    filters: {},
    page: 1,
    pageSize: 12,
    total: 1,
    totalPages: 1,
  });
  assert.match(markup, /演示数据/);
  assert.match(markup, /锁等待/);
  assert.match(markup, /进行中/);
  assert.match(markup, /LCK-20260828-001/);
  assert.match(markup, /7\.5min/);
  assert.match(markup, /data-locks-item="LCK-20260828-001"/);
});

test('renderLockListMarkup escapes summary and instance content', () => {
  const markup = renderLockListMarkup({
    items: [{
      id: 'LCK-2', instance_id: 'x', instance_name: '<img src=x onerror=alert(1)>', engine: 'MySQL',
      type: 'deadlock', status: 'resolved', summary: '<script>alert(1)</script>',
      first_seen: '2026-08-28T02:12:00Z', duration_ms: 100,
    }],
    source: 'demo',
    filters: {},
  });
  assert.doesNotMatch(markup, /<script>alert\(1\)<\/script>/);
  assert.match(markup, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(markup, /<img src=x onerror=alert\(1\)>/);
  assert.match(markup, /已解除/);
});

test('renderLockDetailMarkup shows blocker vs waiter, lock objects with Chinese modes, and escapes names', () => {
  const markup = renderLockDetailMarkup({
    id: 'LCK-20260828-001', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
    type: 'lock-wait', status: 'active',
    first_seen: '2026-08-28T02:12:00Z', last_seen: '2026-08-28T09:58:00Z', duration_ms: 452000,
    summary: 'UPDATE orders 行锁互相等待',
    blocker: { session_id: '1042', user: 'app_order', host: '10.0.1.8:52341', sql: 'UPDATE orders SET status = \'PAID\' WHERE order_id = 1;', txn_age_ms: 452000, state: 'running' },
    waiter: { session_id: '2217', user: 'app_order', host: '10.0.1.9:52399', sql: 'UPDATE orders SET status = \'SHIPPED\' WHERE order_id = 1;', wait_ms: 128000, state: 'waiting' },
    objects: [{ schema: '<b>x</b>', table: 'orders<script>', lock_mode: 'X', index: '' }, { schema: 'public', table: 'inventory', lock_mode: 'IX', index: 'idx_sku' }],
  });
  assert.match(markup, /阻塞者/);
  assert.match(markup, /等待者/);
  assert.match(markup, /1042/);
  assert.match(markup, /2217/);
  assert.match(markup, /UPDATE orders SET status = &#39;PAID&#39;/);
  assert.match(markup, /事务年龄/);
  assert.match(markup, /等待时长/);
  assert.match(markup, /7\.5min/);
  assert.match(markup, /排他锁/);
  assert.match(markup, /意向排他/);
  assert.match(markup, /&lt;b&gt;x&lt;\/b&gt;\.orders&lt;script&gt;/);
  assert.doesNotMatch(markup, /<script>/);
});

test('renderLockDetailMarkup renders deadlock replay text in an escaped pre block', () => {
  const markup = renderLockDetailMarkup({
    id: 'LCK-20260828-006', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
    type: 'deadlock', status: 'resolved',
    first_seen: '2026-08-28T07:32:00Z', last_seen: '2026-08-28T07:32:41Z', duration_ms: 41000,
    summary: '环形等锁触发死锁',
    blocker: { session_id: '1', sql: 'UPDATE inventory SET qty = qty - 1;', txn_age_ms: 41000, state: 'running' },
    waiter: { session_id: '2', sql: 'UPDATE orders SET status = 1;', wait_ms: 6000, state: 'waiting' },
    objects: [],
    detail: '死锁检测触发 <script>alert(1)</script>\n事务 A 回滚。',
  });
  assert.match(markup, /死锁回放/);
  assert.match(markup, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(markup, /<script>/);
});

test('source and failure labels are safe and fixed', () => {
  assert.equal(locksSourceLabel('demo'), '演示数据');
  assert.equal(locksSourceLabel('http'), '控制面服务');
  assert.equal(locksSourceLabel('control-plane'), '控制面服务');
  assert.equal(locksSourceLabel('nope'), '来源未确认');
  assert.equal(locksFailureMessage({ kind: 'forbidden', message: 'password=unsafe' }), '当前账号没有该项目的操作权限');
  assert.equal(locksFailureMessage({ kind: 'network', message: 'token=unsafe' }), '无法连接控制面服务，请检查网络后重试');
  assert.equal(locksFailureMessage({ kind: 'unknown' }), '锁透视数据加载失败，请稍后重试');
});

test('createLocksCenter renders overview stats, active events, deadlock timeline and demo badge', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const api = {
    async getOverview() {
      return {
        source: 'demo',
        stats: { lock_waits: 3, deadlocks_today: 2, long_txns: 2, uncommitted: 1 },
        active: [{
          id: 'LCK-20260828-001', type: 'lock-wait', status: 'active', summary: 'UPDATE orders 行锁互相等待',
          instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
          first_seen: '2026-08-28T02:12:00Z', duration_ms: 452000,
        }],
        deadlocks: [{
          id: 'LCK-20260828-006', type: 'deadlock', status: 'active', summary: '环形等锁触发死锁',
          instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
          first_seen: '2026-08-28T07:32:00Z', duration_ms: 41000,
        }],
      };
    },
  };
  const center = createLocksCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /当前锁等待/);
  assert.match(root.innerHTML, /今日死锁/);
  assert.match(root.innerHTML, /长事务/);
  assert.match(root.innerHTML, /未提交事务/);
  assert.match(root.innerHTML, /活跃锁事件/);
  assert.match(root.innerHTML, /死锁时间线/);
  assert.match(root.innerHTML, /演示数据/);
  assert.match(root.innerHTML, /t1 \/ p1/);
});

test('forbidden responses keep a fixed permission error with retry and no demo fallback', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const forbidden = Object.assign(new Error('unsafe server detail'), { kind: 'forbidden' });
  const api = { getOverview() { return Promise.reject(forbidden); } };
  const center = createLocksCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /当前账号没有该项目的操作权限/);
  assert.match(root.innerHTML, /data-locks-retry/);
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
  const center = createLocksCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  const firstSignal = calls[0][2];
  center.setScope({ tenantId: 't2', projectId: 'p2' });
  assert.equal(firstSignal.aborted, true);
  assert.equal(calls.some(([, scoped]) => scoped.tenantId === 't2' && scoped.projectId === 'p2'), true);
  assert.equal(center.getState().view, 'overview');
});

test('demo adapter exposes at least ten events covering every type and status', async () => {
  const api = createLocksApi();
  const result = await api.listLocks({ tenantId: 't1', projectId: 'p1' }, {});
  assert.ok(result.items.length >= 10);
  assert.equal(result.source, 'demo');
  assert.equal(result.scope.tenantId, 't1');
  for (const type of ['lock-wait', 'deadlock', 'long-txn', 'uncommitted']) {
    const filtered = await api.listLocks({ tenantId: 't1', projectId: 'p1' }, { type });
    assert.ok(filtered.items.length >= 1, `missing type ${type}`);
    assert.ok(filtered.items.every((item) => item.type === type));
  }
  for (const status of ['active', 'resolved']) {
    const filtered = await api.listLocks({ tenantId: 't1', projectId: 'p1' }, { status });
    assert.ok(filtered.items.length >= 1, `missing status ${status}`);
    assert.ok(filtered.items.every((item) => item.status === status));
  }
});

test('demo listLocks filters by instance and search, and paginates by offset/limit', async () => {
  const api = createLocksApi();
  const scoped = { tenantId: 't1', projectId: 'p1' };
  const instance = await api.listLocks(scoped, { instance_id: 'oracle-finance-01' });
  assert.ok(instance.items.length >= 1);
  assert.ok(instance.items.every((item) => item.instance_id === 'oracle-finance-01'));
  const searched = await api.listLocks(scoped, { search: '死锁' });
  assert.ok(searched.items.length >= 1);
  const firstPage = await api.listLocks(scoped, { offset: 0, limit: 5 });
  const secondPage = await api.listLocks(scoped, { offset: 5, limit: 5 });
  assert.equal(firstPage.items.length, 5);
  assert.equal(secondPage.items.length, 5);
  const firstIds = new Set(firstPage.items.map((item) => item.id));
  assert.ok(secondPage.items.every((item) => !firstIds.has(item.id)));
  const paged = await api.listLocks(scoped, { page: 1, pageSize: 12 });
  assert.equal(paged.items.length, 12);
  assert.ok(paged.total >= 12);
});

test('demo getOverview returns stats, active events and deadlock timeline', async () => {
  const api = createLocksApi();
  const overview = await api.getOverview({ tenantId: 't1', projectId: 'p1' });
  assert.equal(overview.source, 'demo');
  assert.ok(overview.stats.lock_waits >= 1);
  assert.ok(overview.stats.deadlocks_today >= 1);
  assert.ok(overview.stats.long_txns >= 1);
  assert.ok(overview.stats.uncommitted >= 1);
  assert.ok(overview.active.length <= 6);
  assert.ok(overview.active.every((item) => item.status === 'active'));
  assert.ok(overview.deadlocks.length >= 1);
  assert.ok(overview.deadlocks.every((item) => item.type === 'deadlock'));
  const detail = await api.getLock({ tenantId: 't1', projectId: 'p1' }, 'LCK-20260828-001');
  assert.equal(detail.id, 'LCK-20260828-001');
  assert.ok(detail.blocker.session_id);
  assert.ok(detail.waiter.session_id);
  await assert.rejects(
    api.getLock({ tenantId: 't1', projectId: 'p1' }, 'LCK-NOPE'),
    (error) => error.kind === 'not-found',
  );
});

test('demo redacts sensitive keys from DTOs', () => {
  const redacted = redactLocksDTO({
    id: 'LCK-1',
    summary: '正常摘要',
    password: 'unsafe-password',
    secret_ref: 'env://DBPILOT_TOKEN',
    connection_string: 'mysql://user:secret@db.example/app',
    audit: { token: 'x' },
    scope: { tenantId: 'evil' },
  });
  assert.ok(!JSON.stringify(redacted).includes('unsafe-password'));
  assert.ok(!JSON.stringify(redacted).includes('env://DBPILOT_TOKEN'));
  assert.ok(!JSON.stringify(redacted).includes('mysql://user:secret'));
  assert.ok(!('scope' in redacted));
  assert.ok(!('audit' in redacted));
  assert.equal(redacted.id, 'LCK-1');
});

test('unavailable adapter rejects every method with a fixed error', async () => {
  const api = createLocksApi({ available: false });
  await assert.rejects(
    api.getOverview({ tenantId: 't', projectId: 'p' }),
    (error) => error.kind === 'unavailable' && error.message === '锁透视服务暂时不可用，请稍后重试',
  );
  await assert.rejects(api.listLocks({ tenantId: 't', projectId: 'p' }, {}), (error) => error.kind === 'unavailable');
  await assert.rejects(api.getLock({ tenantId: 't', projectId: 'p' }, 'LCK-1'), (error) => error.kind === 'unavailable');
});

test('http adapter maps overview, list and detail to REST endpoints', async () => {
  const requested = [];
  const fetchImpl = async (url, init) => {
    requested.push({ url, init });
    const body = url.endsWith('/locks/events/LCK-1')
      ? { id: 'LCK-1', type: 'deadlock', status: 'active' }
      : { items: [{ id: 'LCK-1', type: 'deadlock', status: 'active' }], total: 1 };
    return { ok: true, status: 200, json: async () => body };
  };
  const api = createLocksApi({ baseUrl: 'https://ctl.example/', fetchImpl });
  const overview = await api.getOverview({ tenantId: 't1', projectId: 'p1' });
  assert.equal(requested[0].url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/locks/overview');
  assert.equal(overview.source, 'http');
  const list = await api.listLocks({ tenantId: 't1', projectId: 'p1' }, { type: 'deadlock', page: 2, pageSize: 12 });
  assert.equal(requested[1].url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/locks/events?type=deadlock&page=2&pageSize=12');
  assert.equal(list.source, 'http');
  assert.equal(list.items.length, 1);
  const detail = await api.getLock({ tenantId: 't1', projectId: 'p1' }, 'LCK-1');
  assert.equal(requested[2].url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/locks/events/LCK-1');
  assert.equal(detail.source, 'http');
  assert.equal(detail.id, 'LCK-1');
});

async function flush() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}
