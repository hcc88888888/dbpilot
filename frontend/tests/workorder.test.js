import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildTicketFilters,
  createWorkOrderCenter,
  renderTicketDetailMarkup,
  renderTicketListMarkup,
  riskLabel,
  ticketStatusLabel,
  ticketTypeLabel,
  validateTicket,
  workOrderFailureMessage,
  workOrderSourceLabel,
} from '../workorder.js';
import { createWorkOrderApi } from '../workorder-api.js';

test('validateTicket rejects empty title, empty SQL, and credential-bearing SQL', () => {
  const empty = validateTicket({ title: '', sql: '', reason: '' });
  assert.equal(empty.title, '请填写工单标题');
  assert.equal(empty.sql, '请填写变更 SQL');
  assert.equal(empty.reason, '请填写变更原因');
  const credentialSql = validateTicket({ title: 't', sql: "SET PASSWORD = 'secret-1'", reason: 'r' });
  assert.equal(credentialSql.sql, 'SQL 中不能包含密码或凭据');
  const credentialReason = validateTicket({ title: 't', sql: 'SELECT 1', reason: '需要 token=abc 才能连接' });
  assert.equal(credentialReason.reason, '原因中不能包含密码或凭据');
  const credentialRollback = validateTicket({ title: 't', sql: 'SELECT 1', reason: 'r', rollback_sql: 'dsn=mysql://u:p@h/db' });
  assert.equal(credentialRollback.rollback_sql, '回滚 SQL 中不能包含密码或凭据');
});

test('validateTicket accepts a complete safe ticket', () => {
  assert.deepEqual(validateTicket({
    title: '订单主库增加索引',
    sql: 'ALTER TABLE orders ADD INDEX idx_channel (channel, created_at);',
    reason: '渠道组合查询频繁，提升查询性能',
    rollback_sql: 'ALTER TABLE orders DROP INDEX idx_channel;',
  }), {});
});

test('buildTicketFilters drops empty values and passes through valid filters', () => {
  assert.deepEqual(
    buildTicketFilters({ status: '', type: 'DDL', instance_id: 'mysql-prod-order-01', search: '   ', page: 2, pageSize: 10 }),
    { type: 'DDL', instance_id: 'mysql-prod-order-01', page: 2, pageSize: 10 },
  );
  assert.deepEqual(buildTicketFilters(new Map([['status', ''], ['type', 'DML']])), { type: 'DML' });
});

test('renderTicketListMarkup labels demo source and renders Chinese status labels', () => {
  const markup = renderTicketListMarkup({
    items: [{
      id: 'WO-20260828-001', title: '订单主库增加索引', type: 'DDL', engine: 'MySQL',
      instance_id: 'mysql-prod-order-01', instance_name: '订单主库', risk: 'high', status: 'pending',
      created_by: '张运维', created_at: '2026-08-28T09:00:00Z',
    }],
    source: 'demo',
    filters: {},
    page: 1,
    pageSize: 10,
    total: 1,
    totalPages: 1,
  });
  assert.match(markup, /演示数据/);
  assert.match(markup, /待审批/);
  assert.match(markup, /DDL 结构变更/);
  assert.match(markup, /高风险/);
  assert.match(markup, /WO-20260828-001/);
  assert.match(markup, /张运维/);
});

test('renderTicketListMarkup escapes user content', () => {
  const markup = renderTicketListMarkup({
    items: [{
      id: 'WO-2', title: '<script>alert(1)</script>', type: 'DML', engine: 'MySQL',
      instance_id: 'mysql-prod-order-01', instance_name: '订单主库', risk: 'low', status: 'executed',
      created_by: 'hacker<img src=x onerror=alert(1)>', created_at: '2026-08-28T09:00:00Z',
    }],
    source: 'demo',
    filters: {},
  });
  assert.doesNotMatch(markup, /<script>alert\(1\)<\/script>/);
  assert.match(markup, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(markup, /<img src=x onerror=alert\(1\)>/);
  assert.match(markup, /已执行/);
});

test('status, type, and risk labels map to fixed Chinese text', () => {
  assert.deepEqual(
    ['pending', 'approved', 'rejected', 'executing', 'executed', 'failed', 'rolled_back'].map(ticketStatusLabel),
    ['待审批', '已批准', '已拒绝', '执行中', '已执行', '执行失败', '已回滚'],
  );
  assert.equal(ticketTypeLabel('DDL'), 'DDL 结构变更');
  assert.equal(ticketTypeLabel('DML'), 'DML 数据变更');
  assert.equal(ticketTypeLabel('DCL'), 'DCL 权限变更');
  assert.equal(riskLabel('high'), '高风险');
  assert.equal(riskLabel('medium'), '中风险');
  assert.equal(riskLabel('low'), '低风险');
});

test('source and failure labels are safe and fixed', () => {
  assert.equal(workOrderSourceLabel('demo'), '演示数据');
  assert.equal(workOrderSourceLabel('http'), '控制面服务');
  assert.equal(workOrderFailureMessage({ kind: 'forbidden', message: 'password=unsafe' }), '当前账号没有该项目的操作权限');
  assert.equal(workOrderFailureMessage({ kind: 'network', message: 'token=unsafe' }), '无法连接控制面服务，请检查网络后重试');
  assert.equal(workOrderFailureMessage({ kind: 'unknown' }), '工单数据加载失败，请稍后重试');
});

test('createWorkOrderCenter renders overview stats and demo source badge', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const api = {
    async getOverview() {
      return {
        source: 'demo',
        stats: { pending: 3, executing: 1, executed_today: 5, rolled_back: 2 },
        recent: [{
          id: 'WO-20260828-001', title: '订单主库增加索引', type: 'DDL', engine: 'MySQL',
          instance_id: 'mysql-prod-order-01', instance_name: '订单主库', risk: 'high', status: 'pending',
          created_by: '张运维', created_at: '2026-08-28T09:00:00Z',
        }],
        distribution: { pending: 3, approved: 2, rejected: 1, executing: 1, executed: 5, failed: 1, rolled_back: 2 },
      };
    },
  };
  const center = createWorkOrderCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /待审批/);
  assert.match(root.innerHTML, /执行中/);
  assert.match(root.innerHTML, /今日完成/);
  assert.match(root.innerHTML, /回滚次数/);
  assert.match(root.innerHTML, /演示数据/);
  assert.match(root.innerHTML, /近期工单/);
  assert.match(root.innerHTML, /状态分布/);
});

test('forbidden responses keep a fixed permission error with retry and no demo fallback', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const forbidden = Object.assign(new Error('unsafe server detail'), { kind: 'forbidden' });
  const api = { getOverview() { return Promise.reject(forbidden); } };
  const center = createWorkOrderCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /当前账号没有该项目的操作权限/);
  assert.match(root.innerHTML, /data-workorder-retry/);
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
  const center = createWorkOrderCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  const firstSignal = calls[0][2];
  center.setScope({ tenantId: 't2', projectId: 'p2' });
  assert.equal(firstSignal.aborted, true);
  assert.equal(calls.some(([, scoped]) => scoped.tenantId === 't2' && scoped.projectId === 'p2'), true);
  assert.equal(center.getState().view, 'overview');
});

test('renderTicketDetailMarkup renders SQL, log timeline, history, and context actions', () => {
  const markup = renderTicketDetailMarkup({
    id: 'WO-1', title: '订单主库增加索引', type: 'DDL', engine: 'MySQL',
    instance_id: 'mysql-prod-order-01', instance_name: '订单主库', risk: 'high', status: 'approved',
    sql: 'ALTER TABLE orders ADD INDEX idx_channel (channel, created_at);',
    rollback_sql: 'ALTER TABLE orders DROP INDEX idx_channel;',
    reason: '提升查询性能',
    created_by: '张运维', created_at: '2026-08-28T09:00:00Z',
    approver: '王审批', approved_at: '2026-08-28T09:30:00Z',
    log: [{ at: '2026-08-28T09:00:00Z', level: 'info', message: '工单已提交' }],
    history: [{ status: 'approved', at: '2026-08-28T09:30:00Z', by: '王审批', note: '审批通过' }],
  }, { canManage: true });
  assert.match(markup, /变更 SQL/);
  assert.match(markup, /ALTER TABLE orders ADD INDEX/);
  assert.match(markup, /回滚 SQL/);
  assert.match(markup, /执行日志/);
  assert.match(markup, /审批流历史/);
  assert.match(markup, /data-wo-action="execute"/);
  assert.match(markup, /工单已提交/);
});

test('renderTicketDetailMarkup hides action buttons without manage permission', () => {
  const markup = renderTicketDetailMarkup({ id: 'WO-1', status: 'approved' }, { canManage: false });
  assert.doesNotMatch(markup, /data-wo-action/);
  assert.match(markup, /当前账号没有该项目的操作权限/);
});

test('demo adapter exposes at least nine tickets covering every status', async () => {
  const api = createWorkOrderApi();
  const result = await api.listTickets({ tenantId: 't1', projectId: 'p1' }, {});
  assert.ok(result.items.length >= 9);
  const statuses = new Set(result.items.map((ticket) => ticket.status));
  for (const status of ['pending', 'approved', 'rejected', 'executing', 'executed', 'failed', 'rolled_back']) {
    assert.ok(statuses.has(status), `missing status ${status}`);
  }
  assert.equal(result.source, 'demo');
  assert.equal(result.scope.tenantId, 't1');
});

test('demo createTicket stores a safe DTO and drops credential fields', async () => {
  const api = createWorkOrderApi();
  await api.createTicket({ tenantId: 't1', projectId: 'p1' }, {
    title: '增加索引', type: 'DDL', engine: 'MySQL', instance_id: 'mysql-prod-order-01',
    sql: 'ALTER TABLE orders ADD INDEX idx (created_at);', reason: '提升性能', risk: 'low',
    connection_string: 'mysql://user:secret@db.example/app',
  });
  const result = await api.listTickets({ tenantId: 't1', projectId: 'p1' }, { search: '增加索引' });
  assert.ok(result.items.length >= 1);
  assert.ok(!JSON.stringify(result).includes('secret'));
  assert.ok(!JSON.stringify(result).includes('connection_string'));
});

test('demo approve/reject/execute/rollback transition statuses with conflict guards', async () => {
  const api = createWorkOrderApi();
  const list = await api.listTickets({ tenantId: 't1', projectId: 'p1' }, {});
  const pending = list.items.find((ticket) => ticket.status === 'pending');
  const approved = await api.approveTicket({ tenantId: 't1', projectId: 'p1' }, pending.id, { approver: '王审批', note: '同意' });
  assert.equal(approved.status, 'approved');
  await assert.rejects(
    api.approveTicket({ tenantId: 't1', projectId: 'p1' }, pending.id, {}),
    (error) => error.kind === 'conflict',
  );
  const executed = await api.executeTicket({ tenantId: 't1', projectId: 'p1' }, pending.id, { executor: '李执行' });
  assert.equal(executed.status, 'executed');
  assert.ok(executed.duration_ms > 0);
  const rolledBack = await api.rollbackTicket({ tenantId: 't1', projectId: 'p1' }, pending.id, { executor: '李执行' });
  assert.equal(rolledBack.status, 'rolled_back');
  assert.ok(rolledBack.history.some((entry) => entry.status === 'rolled_back'));
});

test('unavailable adapter rejects every method with a fixed error', async () => {
  const api = createWorkOrderApi({ available: false });
  await assert.rejects(
    api.getOverview({ tenantId: 't', projectId: 'p' }),
    (error) => error.kind === 'unavailable' && error.message === '工单服务暂时不可用，请稍后重试',
  );
  await assert.rejects(api.createTicket({ tenantId: 't', projectId: 'p' }, {}), (error) => error.kind === 'unavailable');
});

test('http adapter maps createTicket to POST /tickets under the scope prefix', async () => {
  let requested;
  const fetchImpl = async (url, init) => {
    requested = { url, init };
    return { ok: true, status: 200, json: async () => ({ ticket: { id: 'WO-1', status: 'pending' } }) };
  };
  const api = createWorkOrderApi({ baseUrl: 'https://ctl.example/', fetchImpl });
  const result = await api.createTicket({ tenantId: 't1', projectId: 'p1' }, {
    title: '增加索引', sql: 'ALTER TABLE orders ADD INDEX idx (created_at);', reason: '提升性能',
  });
  assert.equal(requested.url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/tickets');
  assert.equal(requested.init.method, 'POST');
  assert.equal(result.source, 'http');
  assert.equal(result.status, 'pending');
});

async function flush() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}
