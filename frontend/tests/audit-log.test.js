import test from 'node:test';
import assert from 'node:assert/strict';
import {
  auditActionLabel,
  auditFailureMessage,
  auditResultLabel,
  auditSourceLabel,
  buildAuditFilters,
  createAuditCenter,
  renderAuditDetailMarkup,
  renderAuditListMarkup,
  renderAuditOverviewMarkup,
  safeText,
  validateAuditRange,
} from '../modules/audit-log/audit-log.js';
import { createAuditApi } from '../modules/audit-log/audit-log-api.js';

test('audit action and result labels map to Chinese with unknown fallbacks', () => {
  assert.equal(auditActionLabel('login'), '登录');
  assert.equal(auditActionLabel('query'), '查询');
  assert.equal(auditActionLabel('dml'), '数据变更');
  assert.equal(auditActionLabel('alert.resolve'), '告警解决');
  assert.equal(auditActionLabel('ticket.approve'), '工单审批');
  assert.equal(auditActionLabel('unknown.op'), '未知操作');
  assert.equal(auditResultLabel('success'), '成功');
  assert.equal(auditResultLabel('denied'), '已拒绝');
  assert.equal(auditResultLabel('failed'), '失败');
  assert.equal(auditResultLabel('mystery'), '未知');
});

test('audit range validation rejects invalid dates and reversed ordering', () => {
  assert.equal(validateAuditRange('not-a-date', '2026-08-28T10:00:00Z').kind, 'invalid-date');
  assert.equal(validateAuditRange('2026-08-28T10:00:00Z', 'not-a-date').kind, 'invalid-date');
  assert.equal(validateAuditRange('2026-08-28T10:00:00Z', '2026-08-28T09:00:00Z').kind, 'invalid-range');
  assert.equal(validateAuditRange('2026-08-28T09:00:00Z', '2026-08-28T10:00:00Z').kind, 'valid');
  assert.equal(validateAuditRange('', '').kind, 'valid');
  assert.equal(validateAuditRange('2026-08-28T09:00:00Z', '').kind, 'valid');
});

test('audit filter builder drops empty fields and keeps valid values', () => {
  assert.deepEqual(buildAuditFilters(new Map([
    ['action', 'query'],
    ['result', ''],
    ['actor', '   '],
    ['instance_id', 'mysql-demo-01'],
    ['from', '2026-08-28T00:00'],
  ])), {
    action: 'query',
    instance_id: 'mysql-demo-01',
    from: '2026-08-28T00:00',
  });
});

test('audit list markup labels demo source, maps action labels, and escapes user content', () => {
  const markup = renderAuditListMarkup({
    source: 'demo',
    total: 1,
    offset: 0,
    limit: 15,
    items: [{
      id: 'AUD-1',
      at: '2026-08-28T09:00:00Z',
      action: 'login',
      resource_name: '控制台',
      instance_name: '',
      actor: '<img src=x onerror=alert(1)>',
      source_ip: '10.0.0.1',
      result: 'success',
    }],
  });
  assert.match(markup, /演示数据/);
  assert.match(markup, /登录/);
  assert.match(markup, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(markup, /<img src=x/);
});

test('audit list pager renders disabled bounds without controller-local state', () => {
  const markup = renderAuditListMarkup({ items: [], source: 'demo', total: 0, offset: 0, limit: 15 });
  assert.match(markup, /data-audit-page="" disabled/);
  assert.match(markup, /第 1 \/ 1 页/);
});

test('audit detail markup shows failure reason banner and safely renders nested parameters', () => {
  const markup = renderAuditDetailMarkup({
    id: 'AUD-3',
    at: '2026-08-28T09:30:00Z',
    actor: 'lin.yao',
    actor_type: 'user',
    action: 'query',
    resource_type: 'instance',
    resource_id: 'mysql-demo-01',
    resource_name: '订单主库',
    instance_id: 'mysql-demo-01',
    instance_name: '订单主库',
    result: 'failed',
    reason: '命中敏感表脱敏策略，已阻断查询',
    source_ip: '10.24.1.88',
    client: 'Web Console',
    detail: { sql: 'SELECT * FROM orders', params: { user: '<img onerror=x>' } },
  });
  assert.match(markup, /命中敏感表脱敏策略，已阻断查询/);
  assert.match(markup, /audit-failure/);
  assert.match(markup, /user/);
  assert.match(markup, /&lt;img onerror=x&gt;/);
  assert.doesNotMatch(markup, /<img onerror=x>/);
  assert.match(markup, /原始 JSON/);
  assert.match(markup, /SELECT \* FROM orders/);
});

test('audit detail markup renders success entries without a failure banner', () => {
  const markup = renderAuditDetailMarkup({
    id: 'AUD-1',
    at: '2026-08-28T09:00:00Z',
    actor: 'chris.peng',
    action: 'login',
    result: 'success',
    detail: {},
  });
  assert.doesNotMatch(markup, /audit-failure/);
  assert.match(markup, /成功/);
});

test('safeText escapes markup characters', () => {
  assert.equal(safeText('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
  assert.equal(safeText('a&b"c\'d'), 'a&amp;b&quot;c&#39;d');
});

test('overview markup renders stat cards, distribution bars, and recent timeline', () => {
  const markup = renderAuditOverviewMarkup({
    source: 'demo',
    today_operations: 4,
    failed_denied: 1,
    instance_count: 2,
    actor_count: 3,
    distribution: [{ action: 'login', count: 2 }, { action: 'query', count: 2 }],
    recent: [{ id: 'AUD-1', at: '2026-08-28T09:00:00Z', action: 'login', actor: 'chris.peng', resource_name: '控制台' }],
  }, { manage: false });
  assert.match(markup, /今日操作数/);
  assert.match(markup, /<strong>4<\/strong>/);
  assert.match(markup, /操作类型分布/);
  assert.match(markup, /audit-bar-track/);
  assert.match(markup, /最近审计/);
  assert.match(markup, /chris\.peng/);
});

test('audit center overview renders expected markup from a demo source', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const api = {
    async getOverview() {
      return {
        source: 'demo',
        today_operations: 4,
        failed_denied: 1,
        instance_count: 2,
        actor_count: 3,
        distribution: [{ action: 'login', count: 2 }, { action: 'query', count: 2 }],
        recent: [{ id: 'AUD-1', at: '2026-08-28T09:00:00Z', action: 'login', actor: 'chris.peng', resource_name: '控制台' }],
      };
    },
    async listEntries() { return { source: 'demo', items: [], total: 0 }; },
  };
  const center = createAuditCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /演示数据/);
  assert.match(root.innerHTML, /今日操作数/);
  assert.match(root.innerHTML, /操作类型分布/);
  assert.match(root.innerHTML, /最近审计/);
});

test('forbidden audit responses keep a fixed permission error with retry and no demo fallback', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const forbidden = Object.assign(new Error('unsafe server detail'), { kind: 'forbidden' });
  const api = {
    getOverview() { return Promise.reject(forbidden); },
    listEntries() { return Promise.reject(forbidden); },
    getEntry() { return Promise.reject(forbidden); },
  };
  const center = createAuditCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /当前账号没有该项目的操作权限/);
  assert.match(root.innerHTML, /data-audit-retry/);
  assert.doesNotMatch(root.innerHTML, /unsafe server detail/);
  assert.doesNotMatch(root.innerHTML, /演示数据/);
});

test('scope change aborts the previous audit load and reloads scoped data', async () => {
  const roots = [];
  const root = {
    innerHTML: '',
    addEventListener(type, handler) { roots.push([type, handler]); },
  };
  const calls = [];
  const pending = () => new Promise(() => {});
  const api = {
    getOverview(scope, signal) { calls.push(['overview', { ...scope }, signal]); return pending(); },
    listEntries(scope, filters, signal) { calls.push(['list', { ...scope }, filters, signal]); return pending(); },
  };
  const center = createAuditCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' }, permissions: {} });
  center.open('overview');
  const firstSignal = calls[0][2];
  center.setScope({ tenantId: 't2', projectId: 'p2' });
  assert.equal(firstSignal.aborted, true);
  assert.equal(calls.some(([, scoped]) => scoped.tenantId === 't2' && scoped.projectId === 'p2'), true);
  assert.equal(roots.some(([type]) => type === 'click'), true);
  assert.equal(roots.some(([type]) => type === 'change'), true);
});

test('source and failure helpers never leak server error details', () => {
  assert.equal(auditSourceLabel('demo'), '演示数据');
  assert.equal(auditSourceLabel('control-plane'), '控制面服务');
  assert.equal(auditSourceLabel('http'), '控制面服务');
  assert.equal(auditSourceLabel(''), '来源未确认');
  assert.equal(auditFailureMessage({ kind: 'network', message: 'password=unsafe' }), '无法连接控制面服务，请检查网络后重试');
  assert.equal(auditFailureMessage({ kind: 'forbidden', message: 'db password=unsafe' }), '当前账号没有该项目的操作权限');
  assert.equal(auditFailureMessage({ kind: 'unavailable', message: 'token leaked' }, '审计数据'), '审计服务暂时不可用，请稍后重试');
});

test('demo api returns explicitly marked audit data with at least twelve entries', async () => {
  const api = createAuditApi();
  const scope = { tenantId: 'demo', projectId: 'production' };
  const overview = await api.getOverview(scope);
  assert.equal(overview.source, 'demo');
  assert.equal(overview.today_operations >= 12, true);
  assert.deepEqual(overview.scope, { tenantId: 'demo', projectId: 'production' });
  const list = await api.listEntries(scope, { action: 'query', limit: 5 });
  assert.equal(list.source, 'demo');
  assert.equal(list.items.length > 0, true);
  assert.equal(list.items.every((item) => item.action === 'query'), true);
  assert.equal(list.items.length <= 5, true);
});

test('demo api filters by result, actor keyword, time range, and pagination', async () => {
  const api = createAuditApi();
  const scope = { tenantId: 'demo', projectId: 'production' };
  const denied = await api.listEntries(scope, { result: 'denied' });
  assert.equal(denied.items.length > 0, true);
  assert.equal(denied.items.every((item) => item.result === 'denied'), true);

  const actor = await api.listEntries(scope, { actor: 'chris' });
  assert.equal(actor.items.length > 0, true);
  assert.equal(actor.items.every((item) => item.actor.toLowerCase().includes('chris')), true);

  const ranged = await api.listEntries(scope, { from: '2026-08-28T08:30:00Z', to: '2026-08-28T09:30:00Z' });
  assert.equal(ranged.items.length > 0, true);
  assert.equal(ranged.items.every((item) => Date.parse(item.at) >= Date.parse('2026-08-28T08:30:00Z') && Date.parse(item.at) <= Date.parse('2026-08-28T09:30:00Z')), true);

  const paged = await api.listEntries(scope, { limit: 5, offset: 5 });
  assert.equal(paged.items.length <= 5, true);
  assert.equal(paged.offset, 5);
  assert.equal(paged.total >= 12, true);
});

test('demo api rejects unknown entry ids with not-found', async () => {
  const api = createAuditApi();
  await assert.rejects(api.getEntry({ tenantId: 'demo', projectId: 'production' }, 'AUD-NOPE'), (error) => error.kind === 'not-found');
});

test('demo api validates required tenant and project scope', async () => {
  const api = createAuditApi();
  await assert.rejects(api.getOverview({}), (error) => error.kind === 'validation');
  await assert.rejects(api.listEntries({ tenantId: 't1' }), (error) => error.kind === 'validation');
});

test('http adapter targets the audit endpoints and redacts secret-like fields', async () => {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return {
      ok: true,
      status: 200,
      async json() {
        return { items: [{ id: 'AUD-1', detail: { sql: 'select 1', password: 'unsafe', token: 'jwt' } }] };
      },
    };
  };
  const api = createAuditApi({ baseUrl: 'https://cp.example', fetchImpl });
  const result = await api.listEntries({ tenantId: 't1', projectId: 'p1' }, { action: 'query' });
  assert.match(calls[0], /\/api\/v1\/tenants\/t1\/projects\/p1\/audit\/entries/);
  assert.equal('password' in result.items[0].detail, false);
  assert.equal('token' in result.items[0].detail, false);
  assert.equal(result.source, 'control-plane');
});

test('http adapter maps 403 to a user-safe forbidden error', async () => {
  const fetchImpl = async () => ({ ok: false, status: 403 });
  const api = createAuditApi({ baseUrl: 'https://cp.example', fetchImpl });
  await assert.rejects(api.getOverview({ tenantId: 't1', projectId: 'p1' }), (error) => {
    assert.equal(error.kind, 'forbidden');
    assert.equal(error.message, '当前账号没有该项目的操作权限');
    return true;
  });
});

test('unavailable adapter always rejects with a fixed unavailable error', async () => {
  const api = createAuditApi({ available: false });
  const scope = { tenantId: 't1', projectId: 'p1' };
  await assert.rejects(api.getOverview(scope), (error) => error.kind === 'unavailable');
  await assert.rejects(api.listEntries(scope), (error) => error.kind === 'unavailable');
  await assert.rejects(api.getEntry(scope, 'AUD-1'), (error) => error.kind === 'unavailable');
});

function flush() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}
