import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildReviewFilters,
  createSqlReviewCenter,
  evaluateSqlReview,
  renderReviewDetailMarkup,
  renderReviewListMarkup,
  riskLevelLabel,
  reviewStatusLabel,
  severityLabel,
  simulateRuleEngine,
  sqlReviewFailureMessage,
  sqlReviewSourceLabel,
  validateReviewSubmission,
} from '../sql-review.js';
import { createSqlReviewApi } from '../sql-review-api.js';

const RULES = [
  { id: 'R-001', name: '禁止 SELECT *', category: '查询规范', severity: 'warning', description: '', enabled: true },
  { id: 'R-002', name: '查询必须限制返回行数', category: '查询规范', severity: 'warning', description: '', enabled: true },
  { id: 'R-003', name: '禁止无 WHERE 的 DELETE/UPDATE', category: '高危变更', severity: 'error', description: '', enabled: true },
  { id: 'R-004', name: '禁止模糊查询全表扫描', category: '查询规范', severity: 'info', description: '', enabled: true },
  { id: 'R-005', name: '禁止破坏性语句', category: '高危变更', severity: 'error', description: '', enabled: true },
  { id: 'R-006', name: 'DDL 变更建议先备份', category: 'DDL 规范', severity: 'info', description: '', enabled: true },
  { id: 'R-007', name: '禁止 SQL 中出现凭据', category: '安全规范', severity: 'error', description: '', enabled: true },
];

test('simulateRuleEngine hits SELECT *, missing LIMIT, and clean SQL', () => {
  const selectStar = simulateRuleEngine('SELECT * FROM orders;', RULES);
  assert.ok(selectStar.some((hit) => hit.rule_id === 'R-001' && hit.severity === 'warning'));
  assert.ok(selectStar.some((hit) => hit.rule_id === 'R-002' && hit.message.includes('LIMIT')));

  const clean = simulateRuleEngine("SELECT id, order_no FROM orders WHERE created_at > '2026-08-01' LIMIT 100;", RULES);
  assert.equal(clean.length, 0);
  assert.equal(clean.some((hit) => hit.severity === 'error'), false);
});

test('simulateRuleEngine flags DELETE without WHERE and credential literals as errors', () => {
  const deleteHits = simulateRuleEngine('DELETE FROM orders;', RULES);
  assert.ok(deleteHits.some((hit) => hit.rule_id === 'R-003' && hit.severity === 'error'));

  const updateHits = simulateRuleEngine("UPDATE users SET status = 'active';", RULES);
  assert.ok(updateHits.some((hit) => hit.rule_id === 'R-003' && hit.severity === 'error'));

  const credential = simulateRuleEngine("SELECT * FROM users WHERE password = 'abc123' LIMIT 5;", RULES);
  assert.ok(credential.some((hit) => hit.rule_id === 'R-007' && hit.severity === 'error'));

  const destructive = simulateRuleEngine('TRUNCATE TABLE archive_orders;', RULES);
  assert.ok(destructive.some((hit) => hit.rule_id === 'R-005' && hit.severity === 'error'));
});

test('errors drive high risk and lower the score', () => {
  const assessed = evaluateSqlReview('DELETE FROM orders;', RULES);
  assert.equal(assessed.risk, 'high');
  assert.ok(assessed.score < 100);
  assert.equal(assessed.summary.errors, 1);

  const clean = evaluateSqlReview("SELECT id FROM orders WHERE id > 0 LIMIT 10;", RULES);
  assert.equal(clean.risk, 'low');
  assert.equal(clean.score, 100);
});

test('status, risk, and severity labels map to fixed Chinese text with fallback', () => {
  assert.deepEqual(['pending', 'reviewing', 'approved', 'rejected'].map(reviewStatusLabel), ['待审核', '审核中', '已批准', '已拒绝']);
  assert.equal(reviewStatusLabel('unknown'), '未知');
  assert.deepEqual(['high', 'medium', 'low'].map(riskLevelLabel), ['高风险', '中风险', '低风险']);
  assert.equal(riskLevelLabel('nope'), '未知');
  assert.deepEqual(['error', 'warning', 'info'].map(severityLabel), ['错误', '警告', '提示']);
  assert.equal(severityLabel('x'), '未知');
});

test('validateReviewSubmission rejects empty title, empty SQL, and credential-bearing SQL', () => {
  const empty = validateReviewSubmission({ title: '', sql: '' });
  assert.equal(empty.title, '请填写审核标题');
  assert.equal(empty.sql, '请填写待审核 SQL');
  const credential = validateReviewSubmission({ title: 't', sql: "SET PASSWORD = 'secret-1'" });
  assert.equal(credential.sql, 'SQL 中不能包含密码或凭据');
  assert.deepEqual(validateReviewSubmission({
    title: '订单主库增加索引',
    sql: 'ALTER TABLE orders ADD INDEX idx_channel (channel, created_at);',
  }), {});
});

test('buildReviewFilters drops empty values and passes through valid filters', () => {
  assert.deepEqual(
    buildReviewFilters({ status: '', risk: 'high', instance_id: 'mysql-prod-order-01', search: '   ', page: 2, pageSize: 10 }),
    { risk: 'high', instance_id: 'mysql-prod-order-01', page: 2, pageSize: 10 },
  );
  assert.deepEqual(buildReviewFilters(new Map([['status', ''], ['risk', 'low']])), { risk: 'low' });
});

test('renderReviewListMarkup labels demo source and renders Chinese status labels', () => {
  const markup = renderReviewListMarkup({
    items: [{
      id: 'SRV-20260828-001', title: '订单主库清理草稿订单', engine: 'MySQL',
      instance_id: 'mysql-prod-order-01', instance_name: '订单主库', risk: 'high', score: 70,
      status: 'pending', submitter: '张运维', submitted_at: '2026-08-28T09:00:00Z',
    }],
    source: 'demo',
    filters: {},
    page: 1,
    pageSize: 10,
    total: 1,
    totalPages: 1,
  });
  assert.match(markup, /演示数据/);
  assert.match(markup, /待审核/);
  assert.match(markup, /高风险/);
  assert.match(markup, /SRV-20260828-001/);
  assert.match(markup, /张运维/);
  assert.match(markup, /data-sqlreview-review="SRV-20260828-001"/);
});

test('renderReviewListMarkup escapes user content', () => {
  const markup = renderReviewListMarkup({
    items: [{
      id: 'SRV-2', title: '<script>alert(1)</script>', engine: 'MySQL',
      instance_id: 'mysql-prod-order-01', instance_name: '订单主库', risk: 'low', score: 95,
      status: 'approved', submitter: 'hacker<img src=x onerror=alert(1)>', submitted_at: '2026-08-28T09:00:00Z',
    }],
    source: 'demo',
    filters: {},
  });
  assert.doesNotMatch(markup, /<script>alert\(1\)<\/script>/);
  assert.match(markup, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.doesNotMatch(markup, /<img src=x onerror=alert\(1\)>/);
  assert.match(markup, /已批准/);
});

test('renderReviewDetailMarkup renders score, risk, hits, and escapes hit messages', () => {
  const markup = renderReviewDetailMarkup({
    id: 'SRV-1', title: '订单主库清理草稿订单', engine: 'MySQL',
    instance_id: 'mysql-prod-order-01', instance_name: '订单主库', risk: 'high', score: 40,
    status: 'pending', sql: 'DELETE FROM orders;', submitter: '张运维', submitted_at: '2026-08-28T09:00:00Z',
    reviewer: '', reviewed_at: '',
    summary: { errors: 1, warnings: 0, infos: 0 },
    hits: [{
      rule_id: 'R-003', rule_name: '禁止无 WHERE 的 DELETE/UPDATE', severity: 'error',
      message: '<script>alert(1)</script> 高危变更缺少 WHERE 条件', position: 0, suggestion: '补充 WHERE 并二次确认',
    }],
    history: [{ status: 'pending', at: '2026-08-28T09:00:00Z', by: '张运维', note: '提交 SQL 审核' }],
  }, { canManage: true });

  assert.match(markup, />40</);
  assert.match(markup, /高风险/);
  assert.match(markup, /禁止无 WHERE 的 DELETE\/UPDATE/);
  assert.match(markup, /补充 WHERE 并二次确认/);
  assert.match(markup, /审核摘要/);
  assert.doesNotMatch(markup, /<script>alert\(1\)<\/script>/);
  assert.match(markup, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(markup, /data-sqlreview-action="approve"/);
  assert.match(markup, /data-sqlreview-action="reject"/);
});

test('renderReviewDetailMarkup hides actions without manage permission', () => {
  const markup = renderReviewDetailMarkup({ id: 'SRV-1', status: 'pending' }, { canManage: false });
  assert.doesNotMatch(markup, /data-sqlreview-action/);
  assert.match(markup, /当前账号没有该项目的操作权限/);
});

test('createSqlReviewCenter renders overview stats and demo source badge', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const api = {
    async getOverview() {
      return {
        source: 'demo',
        stats: { pending: 3, high_risk: 2, approved_today_rate: 67, approved_today: 2, reviewed_today: 3, rules_total: 12, rules_enabled: 10 },
        recent: [{
          id: 'SRV-20260828-001', title: '订单主库清理草稿订单', engine: 'MySQL', instance_id: 'mysql-prod-order-01',
          instance_name: '订单主库', risk: 'high', status: 'pending', submitter: '张运维', submitted_at: '2026-08-28T09:00:00Z',
        }],
        top_rules: [{ rule_name: '禁止 SELECT *', count: 4 }, { rule_name: '禁止破坏性语句', count: 2 }],
      };
    },
  };
  const center = createSqlReviewCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /待审核/);
  assert.match(root.innerHTML, /高风险/);
  assert.match(root.innerHTML, /今日审核通过率/);
  assert.match(root.innerHTML, /规则总数启用数/);
  assert.match(root.innerHTML, /演示数据/);
  assert.match(root.innerHTML, /近期审核/);
  assert.match(root.innerHTML, /规则命中 Top/);
  assert.match(root.innerHTML, /禁止 SELECT \*/);
});

test('forbidden responses keep a fixed permission error with retry and no demo fallback', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const forbidden = Object.assign(new Error('unsafe server detail'), { kind: 'forbidden' });
  const api = { getOverview() { return Promise.reject(forbidden); } };
  const center = createSqlReviewCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  await flush();
  assert.match(root.innerHTML, /当前账号没有该项目的操作权限/);
  assert.match(root.innerHTML, /data-sqlreview-retry/);
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
  const center = createSqlReviewCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  const firstSignal = calls[0][2];
  center.setScope({ tenantId: 't2', projectId: 'p2' });
  assert.equal(firstSignal.aborted, true);
  assert.equal(calls.some(([, scoped]) => scoped.tenantId === 't2' && scoped.projectId === 'p2'), true);
  assert.equal(center.getState().view, 'overview');
});

test('source and failure labels are safe and fixed', () => {
  assert.equal(sqlReviewSourceLabel('demo'), '演示数据');
  assert.equal(sqlReviewSourceLabel('http'), '控制面服务');
  assert.equal(sqlReviewSourceLabel('control-plane'), '控制面服务');
  assert.equal(sqlReviewFailureMessage({ kind: 'forbidden', message: 'password=unsafe' }), '当前账号没有该项目的操作权限');
  assert.equal(sqlReviewFailureMessage({ kind: 'network', message: 'token=unsafe' }), '无法连接控制面服务，请检查网络后重试');
  assert.equal(sqlReviewFailureMessage({ kind: 'unknown' }), 'SQL 审核数据加载失败，请稍后重试');
});

test('demo adapter exposes at least eight reviews covering every status', async () => {
  const api = createSqlReviewApi();
  const result = await api.listReviews({ tenantId: 't1', projectId: 'p1' }, {});
  assert.ok(result.items.length >= 8);
  const statuses = new Set(result.items.map((review) => review.status));
  for (const status of ['pending', 'reviewing', 'approved', 'rejected']) {
    assert.ok(statuses.has(status), `missing status ${status}`);
  }
  assert.equal(result.source, 'demo');
  assert.equal(result.scope.tenantId, 't1');
});

test('demo adapter exposes at least ten rules', async () => {
  const api = createSqlReviewApi();
  const result = await api.listRules({ tenantId: 't1', projectId: 'p1' });
  assert.ok(result.items.length >= 10);
  assert.equal(result.source, 'demo');
});

test('demo submitReview runs the rule engine, keeps pending, and drops credential fields', async () => {
  const api = createSqlReviewApi();
  const created = await api.submitReview({ tenantId: 't1', projectId: 'p1' }, {
    title: '订单主库增加索引',
    instance_id: 'mysql-prod-order-01',
    sql: 'ALTER TABLE orders ADD INDEX idx_channel (channel, created_at);',
    connection_string: 'mysql://user:secret@db.example/app',
  });
  assert.equal(created.status, 'pending');
  assert.equal(created.risk, 'low');
  assert.ok(created.hits.length >= 1);
  const listed = await api.listReviews({ tenantId: 't1', projectId: 'p1' }, { search: '订单主库增加索引' });
  assert.ok(listed.items.length >= 1);
  assert.ok(!JSON.stringify(listed).includes('secret'));
  assert.ok(!JSON.stringify(listed).includes('connection_string'));
});

test('demo approve/reject transition statuses with conflict guards', async () => {
  const api = createSqlReviewApi();
  const list = await api.listReviews({ tenantId: 't1', projectId: 'p1' }, { status: 'pending' });
  const pending = list.items.find((review) => review.status === 'pending');
  const approved = await api.approveReview({ tenantId: 't1', projectId: 'p1' }, pending.id, { reviewer: '王审批', note: '同意' });
  assert.equal(approved.status, 'approved');
  assert.ok(approved.reviewed_at);
  assert.ok(approved.history.some((entry) => entry.status === 'approved'));
  await assert.rejects(
    api.approveReview({ tenantId: 't1', projectId: 'p1' }, pending.id, {}),
    (error) => error.kind === 'conflict',
  );
  const reviewing = (await api.listReviews({ tenantId: 't1', projectId: 'p1' }, { status: 'reviewing' })).items[0];
  const rejected = await api.rejectReview({ tenantId: 't1', projectId: 'p1' }, reviewing.id, { reviewer: '王审批' });
  assert.equal(rejected.status, 'rejected');
  assert.ok(rejected.history.some((entry) => entry.status === 'rejected'));
});

test('demo setRuleEnabled toggles a rule', async () => {
  const api = createSqlReviewApi();
  const rules = await api.listRules({ tenantId: 't1', projectId: 'p1' });
  const target = rules.items[0];
  const updated = await api.setRuleEnabled({ tenantId: 't1', projectId: 'p1' }, target.id, !target.enabled);
  assert.equal(updated.enabled, !target.enabled);
});

test('unavailable adapter rejects every method with a fixed error', async () => {
  const api = createSqlReviewApi({ available: false });
  await assert.rejects(
    api.getOverview({ tenantId: 't', projectId: 'p' }),
    (error) => error.kind === 'unavailable' && error.message === 'SQL 审核服务暂时不可用，请稍后重试',
  );
  await assert.rejects(api.submitReview({ tenantId: 't', projectId: 'p' }, {}), (error) => error.kind === 'unavailable');
  await assert.rejects(api.listRules({ tenantId: 't', projectId: 'p' }), (error) => error.kind === 'unavailable');
});

test('http adapter maps submitReview to POST /sql-review/reviews under the scope prefix', async () => {
  let requested;
  const fetchImpl = async (url, init) => {
    requested = { url, init };
    return { ok: true, status: 200, json: async () => ({ review: { id: 'SRV-1', status: 'pending', risk: 'low', score: 97 } }) };
  };
  const api = createSqlReviewApi({ baseUrl: 'https://ctl.example/', fetchImpl });
  const result = await api.submitReview({ tenantId: 't1', projectId: 'p1' }, {
    title: '增加索引', instance_id: 'mysql-prod-order-01', sql: 'ALTER TABLE orders ADD INDEX idx (created_at);',
  });
  assert.equal(requested.url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/sql-review/reviews');
  assert.equal(requested.init.method, 'POST');
  assert.equal(result.source, 'http');
  assert.equal(result.status, 'pending');
});

test('http adapter encodes review filters and maps approve to POST', async () => {
  let requested;
  const fetchImpl = async (url, init) => {
    requested = { url, init };
    return { ok: true, status: 200, json: async () => ({ review: { id: 'SRV-1', status: 'approved', reviewer: '王审批' } }) };
  };
  const api = createSqlReviewApi({ baseUrl: 'https://ctl.example/', fetchImpl });
  await api.approveReview({ tenantId: 't1', projectId: 'p1' }, 'SRV-1', { reviewer: '王审批', note: '同意' });
  assert.equal(requested.url, 'https://ctl.example/api/v1/tenants/t1/projects/p1/sql-review/reviews/SRV-1/approve');
  assert.equal(requested.init.method, 'POST');

  requested = null;
  await api.listReviews({ tenantId: 't1', projectId: 'p1' }, { status: 'pending', risk: 'high', page: 2, pageSize: 10 });
  assert.match(requested.url, /sql-review\/reviews\?/);
  assert.match(requested.url, /status=pending/);
  assert.match(requested.url, /risk=high/);
  assert.match(requested.url, /page=2/);
  assert.match(requested.url, /page_size=10/);
});

async function flush() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}
