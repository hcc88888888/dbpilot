import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildSlowSqlFilters,
  createSlowSqlCenter,
  formatDuration,
  formatMilliseconds,
  renderSlowSqlDetailMarkup,
  renderSlowSqlListMarkup,
  slowSqlFailureMessage,
  slowSqlSourceLabel,
  slowSqlStateLabel,
  suggestionKindLabel,
  validateThreshold,
} from '../slow-sql.js';
import { createSlowSqlApi, redactSlowSqlDTO } from '../slow-sql-api.js';

test('formatDuration / formatMilliseconds format ms values with safe fallback', () => {
  assert.equal(formatMilliseconds(850), '850ms');
  assert.equal(formatMilliseconds(2500), '2.5s');
  assert.equal(formatMilliseconds(3600000), '1h');
  assert.equal(formatDuration(850), '850ms');
  assert.equal(formatDuration(2500), '2.5s');
  assert.equal(formatDuration(3600000), '1h');
  assert.equal(formatMilliseconds(null), '—');
  assert.equal(formatMilliseconds(undefined), '—');
  assert.equal(formatMilliseconds('abc'), '—');
  assert.equal(formatMilliseconds(-1), '—');
  assert.equal(formatMilliseconds(Number.NaN), '—');
});

test('slowSqlStateLabel / suggestionKindLabel map to fixed Chinese text', () => {
  assert.deepEqual(
    ['open', 'acknowledged', 'ignored'].map(slowSqlStateLabel),
    ['待处理', '已处理', '已忽略'],
  );
  assert.equal(slowSqlStateLabel('nope'), '未知');
  assert.equal(slowSqlStateLabel(null), '未知');
  assert.equal(suggestionKindLabel('index'), '索引建议');
  assert.equal(suggestionKindLabel('rewrite'), '改写建议');
  assert.equal(suggestionKindLabel('stats'), '统计信息');
  assert.equal(suggestionKindLabel('nope'), '未知');
});

test('validateThreshold rejects non-number, negative, and oversized values', () => {
  assert.equal(validateThreshold('abc').kind, 'invalid-number');
  assert.equal(validateThreshold('-5').kind, 'negative');
  assert.equal(validateThreshold('90000000').kind, 'too-large');
  assert.equal(validateThreshold('800').kind, 'valid');
  assert.equal(validateThreshold('800').value, 800);
  assert.equal(validateThreshold(86400000).kind, 'valid');
  assert.equal(validateThreshold(86400001).kind, 'too-large');
  assert.equal(validateThreshold('').kind, 'valid');
  assert.equal(validateThreshold(undefined).kind, 'valid');
});

test('buildSlowSqlFilters drops empty values and passes through valid filters', () => {
  assert.deepEqual(
    buildSlowSqlFilters({ instance_id: '', state: 'open', min_duration: '800', search: '   ', page: 2, pageSize: 10 }),
    { state: 'open', min_duration: '800', page: 2, pageSize: 10 },
  );
  assert.deepEqual(buildSlowSqlFilters(new Map([['state', ''], ['engine', 'MySQL']])), { engine: 'MySQL' });
});

test('renderSlowSqlListMarkup labels demo source and renders Chinese status labels', () => {
  const markup = renderSlowSqlListMarkup({
    items: [{
      id: 'SSQ-20260828-001', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      sql_fingerprint: 'SELECT * FROM orders WHERE status = ? AND created_at > ?',
      avg_duration_ms: 850, max_duration_ms: 2100, exec_count: 12400, total_duration_ms: 10540000,
      last_seen: '2026-08-28T09:58:00Z', state: 'open',
    }],
    source: 'demo',
    filters: {},
    page: 1,
    pageSize: 10,
    total: 1,
    totalPages: 1,
    sortBy: 'total',
  });
  assert.match(markup, /演示数据/);
  assert.match(markup, /待处理/);
  assert.match(markup, /SSQ-20260828-001/);
  assert.match(markup, /850ms/);
  assert.match(markup, /data-slowsql-item="SSQ-20260828-001"/);
});

test('renderSlowSqlListMarkup escapes SQL fingerprint and instance content', () => {
  const markup = renderSlowSqlListMarkup({
    items: [{
      id: 'SSQ-2', instance_id: 'x', instance_name: '<img src=x onerror=alert(1)>', engine: 'MySQL',
      sql_fingerprint: '<script>alert(1)</script>',
      avg_duration_ms: 100, max_duration_ms: 100, exec_count: 1, total_duration_ms: 100,
      last_seen: '2026-08-28T09:00:00Z', state: 'open',
    }],
    source: 'demo',
    filters: {},
  });
  assert.doesNotMatch(markup, /<script>alert\(1\)<\/script>/);
  assert.match(markup, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(markup, /<img src=x onerror=alert\(1\)>/);
  assert.match(markup, /待处理/);
});

test('renderSlowSqlDetailMarkup shows suggestion badge, DDL, trend bars, and actions', () => {
  const markup = renderSlowSqlDetailMarkup({
    id: 'SSQ-20260828-001', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
    database: 'shop', table_name: 'orders',
    sql_fingerprint: 'SELECT * FROM orders WHERE status = ? AND created_at > ?',
    sql_sample: 'SELECT * FROM orders WHERE status = "PAID" AND created_at > "2026-08-01"',
    avg_duration_ms: 850, max_duration_ms: 2100, exec_count: 12400, total_duration_ms: 10540000, sample_count: 12400,
    first_seen: '2026-08-28T02:12:00Z', last_seen: '2026-08-28T09:58:00Z', state: 'open',
    trend: {
      buckets: Array.from({ length: 7 }, (_, index) => ({ at: `2026-08-28T${String(4 + index).padStart(2, '0')}:00:00Z`, avg: 850 + index * 40, count: 100 + index })),
    },
    suggestion: { kind: 'index', message: '建议在 orders.status 上创建索引', ddl: 'ALTER TABLE orders ADD INDEX idx_status (status);' },
  }, { canManage: true });
  assert.match(markup, /索引建议/);
  assert.match(markup, /ALTER TABLE orders ADD INDEX idx_status/);
  assert.match(markup, /ssq-bar/);
  assert.match(markup, /data-slowsql-ack="SSQ-20260828-001"/);
  assert.match(markup, /data-slowsql-ignore="SSQ-20260828-001"/);
  assert.match(markup, /SELECT \* FROM orders WHERE status/);
  assert.match(markup, /执行统计/);
  assert.match(markup, /耗时趋势/);
});

test('renderSlowSqlDetailMarkup hides action buttons without manage permission', () => {
  const markup = renderSlowSqlDetailMarkup({
    id: 'SSQ-1', sql_fingerprint: 'SELECT 1', state: 'open', trend: { buckets: [] },
  }, { canManage: false });
  assert.doesNotMatch(markup, /data-slowsql-ack/);
  assert.doesNotMatch(markup, /data-slowsql-ignore/);
  assert.match(markup, /当前账号没有该项目的操作权限/);
});

test('renderSlowSqlDetailMarkup skips the suggestion card when kind is empty', () => {
  const markup = renderSlowSqlDetailMarkup({
    id: 'SSQ-1', sql_fingerprint: 'SELECT 1', state: 'open', trend: { buckets: [] },
    suggestion: { kind: '', message: '无', ddl: '' },
  }, { canManage: true });
  assert.doesNotMatch(markup, /优化建议/);
});

test('source and failure labels are safe and fixed', () => {
  assert.equal(slowSqlSourceLabel('demo'), '演示数据');
  assert.equal(slowSqlSourceLabel('http'), '控制面服务');
  assert.equal(slowSqlSourceLabel('control-plane'), '控制面服务');
  assert.equal(slowSqlFailureMessage({ kind: 'forbidden', message: 'password=unsafe' }), '当前账号没有该项目的操作权限');
  assert.equal(slowSqlFailureMessage({ kind: 'network', message: 'token=unsafe' }), '无法连接控制面服务，请检查网络后重试');
  assert.equal(slowSqlFailureMessage({ kind: 'unknown' }), '慢 SQL 数据加载失败，请稍后重试');
});

test('createSlowSqlCenter renders overview stats and demo source badge', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const api = {
    async getOverview() {
      return {
        source: 'demo',
        stats: { total: 12, new_today: 4, avg_duration_ms: 850, total_ratio: 70 },
        top: [{
          id: 'SSQ-20260828-001', sql_fingerprint: 'SELECT * FROM orders WHERE status = ?',
          instance_name: '订单主库', engine: 'MySQL', total_duration_ms: 10540000, exec_count: 12400,
        }],
        distribution: { open: 6, acknowledged: 3, ignored: 3 },
      };
    },
  };
  const center = createSlowSqlCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /慢 SQL 总数/);
  assert.match(root.innerHTML, /今日新增/);
  assert.match(root.innerHTML, /平均耗时/);
  assert.match(root.innerHTML, /演示数据/);
  assert.match(root.innerHTML, /Top 慢 SQL 排行/);
  assert.match(root.innerHTML, /状态分布/);
  assert.match(root.innerHTML, /850ms/);
  assert.match(root.innerHTML, /t1 \/ p1/);
});

test('forbidden responses keep a fixed permission error with retry and no demo fallback', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const forbidden = Object.assign(new Error('unsafe server detail'), { kind: 'forbidden' });
  const api = { getOverview() { return Promise.reject(forbidden); } };
  const center = createSlowSqlCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /当前账号没有该项目的操作权限/);
  assert.match(root.innerHTML, /data-slowsql-retry/);
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
  const center = createSlowSqlCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  const firstSignal = calls[0][2];
  center.setScope({ tenantId: 't2', projectId: 'p2' });
  assert.equal(firstSignal.aborted, true);
  assert.equal(calls.some(([, scoped]) => scoped.tenantId === 't2' && scoped.projectId === 'p2'), true);
  assert.equal(center.getState().view, 'overview');
});

test('demo adapter exposes at least ten items covering every state', async () => {
  const api = createSlowSqlApi();
  const result = await api.listSlowSql({ tenantId: 't1', projectId: 'p1' }, {});
  assert.ok(result.items.length >= 10);
  assert.equal(result.source, 'demo');
  assert.equal(result.scope.tenantId, 't1');
  for (const state of ['open', 'acknowledged', 'ignored']) {
    const filtered = await api.listSlowSql({ tenantId: 't1', projectId: 'p1' }, { state });
    assert.ok(filtered.items.length >= 1, `missing state ${state}`);
    assert.ok(filtered.items.every((item) => item.state === state));
  }
});

test('demo listSlowSql filters by threshold, sorts, and paginates', async () => {
  const api = createSlowSqlApi();
  const filtered = await api.listSlowSql({ tenantId: 't1', projectId: 'p1' }, { min_duration: 1000 });
  assert.ok(filtered.items.length >= 1);
  assert.ok(filtered.items.every((item) => item.avg_duration_ms >= 1000));
  const sorted = await api.listSlowSql({ tenantId: 't1', projectId: 'p1' }, { sortBy: 'avg', pageSize: 20 });
  for (let index = 1; index < sorted.items.length; index += 1) {
    assert.ok(sorted.items[index - 1].avg_duration_ms >= sorted.items[index].avg_duration_ms);
  }
  const searched = await api.listSlowSql({ tenantId: 't1', projectId: 'p1' }, { search: 'orders' });
  assert.ok(searched.items.length >= 1);
  const page = await api.listSlowSql({ tenantId: 't1', projectId: 'p1' }, { page: 1, pageSize: 10 });
  assert.equal(page.items.length, 10);
  assert.equal(page.total, 12);
});

test('demo ack/ignore transition states and write back', async () => {
  const api = createSlowSqlApi();
  const list = await api.listSlowSql({ tenantId: 't1', projectId: 'p1' }, {});
  const open = list.items.find((item) => item.state === 'open');
  const acked = await api.ackSlowSql({ tenantId: 't1', projectId: 'p1' }, open.id);
  assert.equal(acked.state, 'acknowledged');
  const ignored = await api.ignoreSlowSql({ tenantId: 't1', projectId: 'p1' }, open.id);
  assert.equal(ignored.state, 'ignored');
  await assert.rejects(
    api.getSlowSql({ tenantId: 't1', projectId: 'p1' }, 'SSQ-NOPE'),
    (error) => error.kind === 'not-found',
  );
});

test('demo redacts sensitive keys from DTOs', () => {
  const redacted = redactSlowSqlDTO({
    id: 'SSQ-1',
    sql_fingerprint: 'SELECT 1',
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
  assert.equal(redacted.id, 'SSQ-1');
});

test('unavailable adapter rejects every method with a fixed error', async () => {
  const api = createSlowSqlApi({ available: false });
  await assert.rejects(
    api.getOverview({ tenantId: 't', projectId: 'p' }),
    (error) => error.kind === 'unavailable' && error.message === '慢 SQL 治理服务暂时不可用，请稍后重试',
  );
  await assert.rejects(api.listSlowSql({ tenantId: 't', projectId: 'p' }, {}), (error) => error.kind === 'unavailable');
  await assert.rejects(api.ackSlowSql({ tenantId: 't', projectId: 'p' }, 'SSQ-1'), (error) => error.kind === 'unavailable');
});

test('http adapter maps listSlowSql and ack/ignore to REST endpoints', async () => {
  const requested = [];
  const fetchImpl = async (url, init) => {
    requested.push({ url, init });
    return { ok: true, status: 200, json: async () => ({ items: [{ id: 'SSQ-1', state: 'open', avg_duration_ms: 100 }], total: 1 }) };
  };
  const api = createSlowSqlApi({ baseUrl: 'https://ctl.example/', fetchImpl });
  const list = await api.listSlowSql({ tenantId: 't1', projectId: 'p1' }, { state: 'open', page: 2, pageSize: 10 });
  assert.equal(requested[0].url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/slow-sql/items?state=open&page=2&pageSize=10');
  assert.equal(list.source, 'http');
  assert.equal(list.items.length, 1);
  await api.ackSlowSql({ tenantId: 't1', projectId: 'p1' }, 'SSQ-1');
  assert.equal(requested[1].url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/slow-sql/items/SSQ-1/ack');
  assert.equal(requested[1].init.method, 'POST');
  await api.ignoreSlowSql({ tenantId: 't1', projectId: 'p1' }, 'SSQ-1');
  assert.equal(requested[2].url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/slow-sql/items/SSQ-1/ignore');
  await api.getSlowSql({ tenantId: 't1', projectId: 'p1' }, 'SSQ-1');
  assert.equal(requested[3].url.endsWith('/items/SSQ-1'), true);
});

async function flush() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}
