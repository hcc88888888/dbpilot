import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildQueryPayload,
  createSqlWindowCenter,
  csvEscape,
  detectStatementType,
  extractColumns,
  renderHistoryMarkup,
  renderPlanMarkup,
  renderQueryResultMarkup,
  safeText,
  sqlFailureMessage,
  sqlSourceLabel,
  validateSql,
} from '../sql-window.js';
import { createSqlWindowApi } from '../sql-window-api.js';

const scope = { tenantId: 'tenant-a', projectId: 'project-a' };

test('validateSql rejects empty, oversized, and credential-bearing SQL', () => {
  assert.equal(validateSql('').kind, 'validation');
  assert.equal(validateSql('   ').kind, 'validation');
  assert.equal(validateSql('x'.repeat(20001)).kind, 'validation');
  assert.equal(validateSql('SELECT * FROM users WHERE password = "x"').kind, 'validation');
  assert.equal(validateSql('SHOW VARIABLES LIKE "token"').kind, 'validation');
  assert.equal(validateSql('SELECT connectionstring FROM t').kind, 'validation');
  const valid = validateSql('SELECT * FROM users LIMIT 5');
  assert.equal(valid.kind, 'valid');
  assert.equal(valid.sql, 'SELECT * FROM users LIMIT 5');
});

test('detectStatementType recognizes common SQL statement families', () => {
  assert.equal(detectStatementType('SELECT * FROM users'), 'select');
  assert.equal(detectStatementType('WITH active AS (SELECT 1) SELECT * FROM active'), 'select');
  assert.equal(detectStatementType('SHOW TABLES'), 'show');
  assert.equal(detectStatementType('SHOW PROCESSLIST'), 'show');
  assert.equal(detectStatementType('EXPLAIN SELECT * FROM users'), 'explain');
  assert.equal(detectStatementType('INSERT INTO users (id) VALUES (1)'), 'insert');
  assert.equal(detectStatementType('UPDATE users SET name = \'a\''), 'update');
  assert.equal(detectStatementType('DELETE FROM users'), 'delete');
  assert.equal(detectStatementType('ALTER TABLE users ADD COLUMN x INT'), 'ddl');
  assert.equal(detectStatementType('CREATE INDEX idx ON users(id)'), 'ddl');
  assert.equal(detectStatementType('DROP TABLE users'), 'ddl');
  assert.equal(detectStatementType('TRUNCATE TABLE users'), 'ddl');
  assert.equal(detectStatementType('VACUUM users'), 'other');
});

test('extractColumns reads select fields before from and falls back to defaults for star', () => {
  assert.deepEqual(extractColumns('SELECT id, name FROM users WHERE status = 1'), [
    { name: 'id', type: 'int' },
    { name: 'name', type: 'varchar' },
  ]);
  assert.equal(extractColumns('SELECT * FROM orders').some((column) => column.name === 'id'), true);
  assert.equal(extractColumns('SHOW TABLES'), null);
});

test('csvEscape quotes delimiters and escapes double quotes while leaving plain values bare', () => {
  assert.equal(csvEscape('a,b'), '"a,b"');
  assert.equal(csvEscape('say "hi"'), '"say ""hi"""');
  assert.equal(csvEscape('line1\nline2'), '"line1\nline2"');
  assert.equal(csvEscape(42), '42');
  assert.equal(csvEscape('plain'), 'plain');
});

test('renderQueryResultMarkup labels demo results, renders columns and escaped cells, and surfaces warnings and truncation', () => {
  const markup = renderQueryResultMarkup({
    columns: [{ name: 'id', type: 'int' }, { name: 'note', type: 'text' }],
    data: [[1, '<script>alert(1)</script>']],
    warning: '高危语句，演示模式未真正执行',
    truncated: true,
    duration_ms: 42,
  }, 'demo');
  assert.match(markup, /演示数据/);
  assert.match(markup, /<th[^>]*>id/);
  assert.match(markup, /<th[^>]*>note/);
  assert.match(markup, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(markup, /<script>alert/);
  assert.match(markup, /sqlw-warning/);
  assert.match(markup, /高危语句，演示模式未真正执行/);
  assert.match(markup, /sqlw-truncated/);
  assert.match(markup, /42/);
});

test('renderPlanMarkup indents child nodes by parent relation and shows type, table, and cost', () => {
  const markup = renderPlanMarkup({
    total_cost: 145.5,
    total_rows: 12000,
    sql: 'SELECT * FROM orders WHERE created_at > NOW()',
    nodes: [
      { id: 1, parent: null, type: 'Seq Scan', table: 'orders', rows: 12000, cost: 100.25, detail: 'Seq Scan on orders' },
      { id: 2, parent: 1, type: 'Index Scan', table: 'orders_idx', rows: 500, cost: 12.75, detail: 'Index Scan using orders_idx' },
    ],
  }, 'http');
  assert.match(markup, /Seq Scan/);
  assert.match(markup, /orders/);
  assert.match(markup, /cost=100\.25/);
  assert.match(markup, /cost=12\.75/);
  assert.match(markup, /data-depth="0"/);
  assert.match(markup, /data-depth="1"/);
  assert.match(markup, /控制面服务/);
  assert.match(markup, /145\.5/);
  assert.match(markup, /12000/);
});

test('renderHistoryMarkup lists truncated SQL summaries and a clear-history action', () => {
  const longSql = 'SELECT id, name, status FROM orders ORDER BY created_at DESC, status ASC LIMIT 100';
  const markup = renderHistoryMarkup({ source: 'demo', items: [
    { id: 'h1', sql: longSql, instance_id: 'mysql-prod-order-01', engine: 'mysql', run_at: '2026-08-27T09:00:00Z', duration_ms: 120, rows: 34 },
  ] }, 'demo');
  assert.match(markup, /演示数据/);
  assert.match(markup, /data-sqlwindow-clear-history/);
  assert.match(markup, /data-sqlwindow-history="h1"/);
  assert.match(markup, /mysql-prod-order-01/);
  const summary = markup.match(/class="sqlw-history-sql">([^<]+)</)?.[1] ?? '';
  assert.equal(summary.length, 61);
  assert.equal(summary.endsWith('…'), true);
  assert.equal(summary.includes('LIMIT 100'), false);
});

test('source and fixed failures have safe labels', () => {
  assert.equal(sqlSourceLabel('demo'), '演示数据');
  assert.equal(sqlSourceLabel('http'), '控制面服务');
  assert.equal(sqlSourceLabel(null), '来源未确认');
  assert.equal(sqlFailureMessage({ kind: 'forbidden' }), '当前账号没有该项目的操作权限');
  assert.equal(sqlFailureMessage({ kind: 'network', message: 'password=unsafe' }), '无法连接控制面服务，请检查网络后重试');
});

test('safeText prevents database cells from becoming markup', () => {
  assert.equal(safeText('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
});

test('buildQueryPayload keeps instance id and sql while rejecting invalid sql', () => {
  assert.deepEqual(buildQueryPayload({ instanceId: 'mysql-prod-order-01', sql: 'SELECT 1' }), {
    instance_id: 'mysql-prod-order-01', sql: 'SELECT 1',
  });
  assert.deepEqual(buildQueryPayload({ instanceId: '', sql: 'SELECT 1' }), {
    instance_id: null, sql: 'SELECT 1',
  });
  assert.equal(buildQueryPayload({ sql: 'password = 1' }).error, 'validation');
});

test('createSqlWindowCenter renders editor and instance dropdown on overview with a healthy api', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const api = {
    runQuery() { return Promise.resolve({ source: 'demo', columns: [{ name: 'a', type: 'int' }], data: [[1]] }); },
    explainQuery() { return Promise.resolve({ source: 'demo', nodes: [] }); },
    listHistory() { return Promise.resolve({ source: 'demo', items: [] }); },
    clearHistory() { return Promise.resolve({ source: 'demo' }); },
  };
  const center = createSqlWindowCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.match(root.innerHTML, /sqlw-textarea/);
  assert.match(root.innerHTML, /data-sqlwindow-editor/);
  assert.match(root.innerHTML, /mysql-prod-order-01/);
  assert.match(root.innerHTML, /data-sqlwindow-run/);
  assert.equal(center.getState().view, 'overview');
});

test('forbidden api responses keep a fixed permission error with retry and no demo fallback', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const forbidden = Object.assign(new Error('unsafe server detail'), { kind: 'forbidden' });
  const api = {
    runQuery() { return Promise.reject(forbidden); },
    explainQuery() { return Promise.reject(forbidden); },
    listHistory() { return Promise.reject(forbidden); },
    clearHistory() { return Promise.reject(forbidden); },
  };
  const center = createSqlWindowCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.match(root.innerHTML, /当前账号没有该项目的操作权限/);
  assert.match(root.innerHTML, /data-sqlwindow-retry/);
  assert.doesNotMatch(root.innerHTML, /演示数据/);
  assert.doesNotMatch(root.innerHTML, /unsafe server detail/);
});

test('scope change aborts the previous request and reloads with the new scope', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const calls = [];
  const pending = () => new Promise(() => {});
  const api = {
    listHistory(scopeValue, query, signal) { calls.push(['history', { ...scopeValue }, query, signal]); return pending(); },
    runQuery() { return pending(); },
    explainQuery() { return pending(); },
    clearHistory() { return Promise.resolve({ source: 'http' }); },
  };
  const center = createSqlWindowCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  const firstSignal = calls[0][3];
  center.setScope({ tenantId: 't2', projectId: 'p2' });
  assert.equal(firstSignal.aborted, true);
  assert.equal(calls.some(([, scoped]) => scoped.tenantId === 't2' && scoped.projectId === 'p2'), true);
});

test('demo api marks source demo, validates sql, redacts secrets, and records history', async () => {
  const api = createSqlWindowApi();
  const result = await api.runQuery(scope, { instance_id: 'mysql-prod-order-01', sql: 'SELECT * FROM orders LIMIT 5' });
  assert.equal(result.source, 'demo');
  assert.deepEqual(result.scope, scope);
  assert.equal(result.columns.length > 0, true);
  assert.ok(Array.isArray(result.data));
  assert.equal(result.data.length <= 5, true);

  await assert.rejects(
    api.runQuery(scope, { instance_id: 'mysql-prod-order-01', sql: 'SELECT password FROM users' }),
    (error) => error.kind === 'validation',
  );

  const safe = await api.runQuery(scope, { instance_id: '', sql: 'SELECT * FROM secrets' });
  assert.equal(JSON.stringify(safe).includes('password'), false);

  const history = await api.listHistory(scope, { limit: 20 });
  assert.equal(history.source, 'demo');
  assert.equal(history.items.some((item) => item.sql === 'SELECT * FROM orders LIMIT 5'), true);
  assert.equal(history.items.some((item) => item.sql === 'SELECT * FROM secrets'), true);
});

test('demo plan builds a parent-linked node tree with totals', async () => {
  const api = createSqlWindowApi();
  const plan = await api.explainQuery(scope, { instance_id: 'mysql-prod-order-01', sql: 'SELECT count(*) FROM orders JOIN order_items ON 1 = 1' });
  assert.equal(plan.source, 'demo');
  assert.equal(plan.nodes.length >= 3, true);
  const ids = new Set(plan.nodes.map((node) => node.id));
  assert.equal(plan.nodes.every((node) => node.parent === null || ids.has(node.parent)), true);
  assert.equal(typeof plan.total_cost, 'number');
  assert.equal(typeof plan.total_rows, 'number');
  assert.equal(plan.nodes.some((node) => node.type === 'Hash Join'), true);
});

test('sql-window http adapter scopes all paths and POSTs JSON bodies', async () => {
  const seen = [];
  const api = createSqlWindowApi({
    baseUrl: 'https://control.example',
    fetchImpl: async (url, init) => {
      seen.push([url, init]);
      return new Response(JSON.stringify({ source: 'http', columns: [{ name: 'a', type: 'int' }], data: [[1]] }));
    },
  });
  await api.runQuery(scope, { instance_id: 'mysql-prod-order-01', sql: 'SELECT 1' });
  const [url, init] = seen[0];
  assert.equal(url, 'https://control.example/api/v1/tenants/tenant-a/projects/project-a/sql-window/query');
  assert.equal(init.method, 'POST');
  assert.deepEqual(JSON.parse(init.body), { instance_id: 'mysql-prod-order-01', sql: 'SELECT 1' });
});

test('unavailable production bootstrap does not issue a request or use demo data', async () => {
  let calls = 0;
  const api = createSqlWindowApi({ baseUrl: 'https://control.example', available: false, fetchImpl: async () => { calls += 1; } });
  await assert.rejects(api.runQuery(scope, { sql: 'SELECT 1' }), { kind: 'unavailable' });
  await assert.rejects(api.listHistory(scope), { kind: 'unavailable' });
  assert.equal(calls, 0);
});
