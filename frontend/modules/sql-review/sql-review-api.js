import { evaluateSqlReview } from './sql-review.js';

const SQL_REVIEW_ERRORS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '审核记录不存在或已无权访问',
  conflict: '审核记录状态已更新，请刷新后重试',
  validation: '审核内容不符合要求，请修改后重试',
  unavailable: 'SQL 审核服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const SQL_REVIEW_SENSITIVE_PATTERN = /(?:\b(?:password|passwd|pwd|token|secret|credential|api[_\s-]?key)\b|connectionstring|dsn)/i;

const DEFAULT_PAGE_SIZE = 10;
const CURRENT_ACTOR = 'ops-01';

const INSTANCES = [
  { id: 'mysql-prod-order-01', name: '订单主库', engine: 'MySQL' },
  { id: 'pgsql-user-primary', name: '用户中心', engine: 'PostgreSQL' },
  { id: 'redis-session-01', name: '缓存集群', engine: 'Redis' },
  { id: 'mysql-analytics-replica', name: '分析从库', engine: 'MySQL' },
];

const REVIEW_FILTER_FIELDS = ['status', 'risk', 'instance_id', 'search'];
const CREATE_FIELDS = ['title', 'engine', 'instance_id', 'sql', 'submitter'];

/**
 * Create the only frontend boundary for SQL review data.
 * A configured base URL selects the real control-plane API; otherwise the
 * adapter supplies explicitly marked, safe local demo data.
 */
export function createSqlReviewApi({ baseUrl = '', fetchImpl = globalThis.fetch, available = true } = {}) {
  if (!available) return createUnavailableAdapter();
  if (!baseUrl) return createDemoAdapter();
  if (typeof fetchImpl !== 'function') throw sqlReviewFailure('network');

  const base = baseUrl.replace(/\/+$/, '');
  const request = async (scope, path, init = {}, signal) => {
    const safeScope = cleanScope(scope);
    const prefix = `/api/v1/tenants/${encodeURIComponent(safeScope.tenantId)}/projects/${encodeURIComponent(safeScope.projectId)}`;
    let response;
    try {
      response = await fetchImpl(`${base}${prefix}${path}`, { ...init, signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      if (error?.kind && SQL_REVIEW_ERRORS[error.kind]) throw error;
      throw sqlReviewFailure('network');
    }
    if (!response.ok) throw failureForStatus(response.status);
    if (response.status === 204) return undefined;
    try {
      return await response.json();
    } catch {
      throw sqlReviewFailure('unavailable', response.status);
    }
  };

  return createHttpAdapter(request);
}

function createHttpAdapter(request) {
  return {
    async getOverview(scope, signal) {
      return normalizeEntity(await request(scope, '/sql-review/overview', {}, signal), scope, 'http');
    },

    async listReviews(scope, filters = {}, signal) {
      const query = reviewQuery(filters);
      const response = await request(scope, `/sql-review/reviews${query}`, {}, signal);
      return normalizeList(response, scope, 'http', listMeta(response, filters));
    },

    async getReview(scope, id, signal) {
      return normalizeEntity(await request(scope, `/sql-review/reviews/${encodeURIComponent(String(id))}`, {}, signal), scope, 'http');
    },

    async submitReview(scope, value, signal) {
      return normalizeEntity(await request(scope, '/sql-review/reviews', jsonRequest('POST', pickDTO(value, CREATE_FIELDS)), signal), scope, 'http');
    },

    async approveReview(scope, id, input = {}, signal) {
      return normalizeEntity(await request(scope, `/sql-review/reviews/${encodeURIComponent(String(id))}/approve`, jsonRequest('POST', { reviewer: String(input.reviewer ?? '').trim(), note: String(input.note ?? '').trim() }), signal), scope, 'http');
    },

    async rejectReview(scope, id, input = {}, signal) {
      return normalizeEntity(await request(scope, `/sql-review/reviews/${encodeURIComponent(String(id))}/reject`, jsonRequest('POST', { reviewer: String(input.reviewer ?? '').trim(), note: String(input.note ?? '').trim() }), signal), scope, 'http');
    },

    async listRules(scope, signal) {
      return normalizeList(await request(scope, '/sql-review/rules', {}, signal), scope, 'http');
    },

    async setRuleEnabled(scope, id, enabled, signal) {
      return normalizeEntity(await request(scope, `/sql-review/rules/${encodeURIComponent(String(id))}/enable`, jsonRequest('POST', { enabled: Boolean(enabled) }), signal), scope, 'http');
    },
  };
}

function createUnavailableAdapter() {
  const unavailable = async () => { throw sqlReviewFailure('unavailable'); };
  return {
    getOverview: unavailable,
    listReviews: unavailable,
    getReview: unavailable,
    submitReview: unavailable,
    approveReview: unavailable,
    rejectReview: unavailable,
    listRules: unavailable,
    setRuleEnabled: unavailable,
  };
}

function createDemoAdapter() {
  const store = { reviews: [], rules: buildDemoRules() };
  store.reviews = buildDemoReviews(store.rules);
  const now = () => new Date().toISOString();
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const findReview = (id) => {
    const review = store.reviews.find((item) => item.id === String(id));
    if (!review) throw sqlReviewFailure('not-found');
    return review;
  };

  return {
    async getOverview(scope) {
      const reviews = store.reviews;
      const rules = store.rules;
      const reviewedToday = reviews.filter((review) => review.reviewed_at && String(review.reviewed_at).startsWith(DEMO_DATE)).length;
      const approvedToday = reviews.filter((review) => review.status === 'approved' && review.reviewed_at && String(review.reviewed_at).startsWith(DEMO_DATE)).length;
      const stats = {
        pending: reviews.filter((review) => review.status === 'pending').length,
        high_risk: reviews.filter((review) => review.risk === 'high').length,
        approved_today_rate: reviewedToday ? Math.round(approvedToday / reviewedToday * 100) : 0,
        approved_today: approvedToday,
        reviewed_today: reviewedToday,
        rules_total: rules.length,
        rules_enabled: rules.filter((rule) => rule.enabled).length,
      };
      const recent = [...reviews].sort(bySubmittedAtDesc).slice(0, 5);
      return normalizeEntity({ stats, recent, top_rules: topRuleCounts(reviews) }, scope, 'demo');
    },

    async listReviews(scope, filters = {}) {
      const filtered = filterDemoReviews(store.reviews, filters);
      const page = boundedPage(filters.page);
      const pageSize = boundedPageSize(filters.pageSize);
      const total = filtered.length;
      const totalPages = Math.max(1, Math.ceil(total / pageSize));
      const items = [...filtered].sort(bySubmittedAtDesc).slice((page - 1) * pageSize, page * pageSize);
      return normalizeList(items, scope, 'demo', { total, page, pageSize, totalPages });
    },

    async getReview(scope, id) {
      return normalizeEntity(findReview(id), scope, 'demo');
    },

    async submitReview(scope, value) {
      if (invalidReviewPayload(value)) throw sqlReviewFailure('validation');
      const at = now();
      const submitter = String(value?.submitter ?? '').trim() || CURRENT_ACTOR;
      const instanceId = String(value?.instance_id ?? '').trim();
      const instance = INSTANCES.find((item) => item.id === instanceId);
      const sql = String(value?.sql ?? '');
      await delay(600); // 模拟规则引擎静态扫描
      const assessment = evaluateSqlReview(sql, store.rules);
      const review = {
        id: nextReviewID(store.reviews),
        title: String(value?.title ?? '').trim(),
        engine: instance?.engine ?? '',
        instance_id: instanceId,
        instance_name: instance?.name ?? instanceId,
        sql,
        status: 'pending',
        submitter,
        submitted_at: at,
        reviewer: '',
        reviewed_at: '',
        risk: assessment.risk,
        score: assessment.score,
        hits: assessment.hits,
        summary: assessment.summary,
        history: [{ status: 'pending', at, by: submitter, note: '提交 SQL 审核' }],
      };
      store.reviews.unshift(review);
      return normalizeEntity(review, scope, 'demo');
    },

    async approveReview(scope, id, input = {}) {
      const review = findReview(id);
      if (review.status !== 'pending' && review.status !== 'reviewing') throw sqlReviewFailure('conflict');
      const at = now();
      const reviewer = String(input?.reviewer ?? '').trim() || CURRENT_ACTOR;
      review.status = 'approved';
      review.reviewer = reviewer;
      review.reviewed_at = at;
      review.history.push({ status: 'approved', at, by: reviewer, note: String(input?.note ?? '').trim() || '审核通过' });
      return normalizeEntity(review, scope, 'demo');
    },

    async rejectReview(scope, id, input = {}) {
      const review = findReview(id);
      if (review.status !== 'pending' && review.status !== 'reviewing') throw sqlReviewFailure('conflict');
      const at = now();
      const reviewer = String(input?.reviewer ?? '').trim() || CURRENT_ACTOR;
      review.status = 'rejected';
      review.reviewer = reviewer;
      review.reviewed_at = at;
      review.history.push({ status: 'rejected', at, by: reviewer, note: String(input?.note ?? '').trim() || '审核拒绝' });
      return normalizeEntity(review, scope, 'demo');
    },

    async listRules(scope) {
      const items = [...store.rules].sort(byRuleID);
      return normalizeList(items, scope, 'demo', { total: items.length, page: 1, pageSize: items.length, totalPages: 1 });
    },

    async setRuleEnabled(scope, id, enabled) {
      const rule = store.rules.find((item) => item.id === String(id));
      if (!rule) throw sqlReviewFailure('not-found');
      rule.enabled = Boolean(enabled);
      return normalizeEntity(rule, scope, 'demo');
    },
  };
}

const DEMO_DATE = '2026-08-28';

function buildDemoRules() {
  return [
    { id: 'R-001', name: '禁止 SELECT *', category: '查询规范', severity: 'warning', description: 'SELECT 必须显式列出返回字段', enabled: true },
    { id: 'R-002', name: '查询必须限制返回行数', category: '查询规范', severity: 'warning', description: 'SELECT 查询建议添加 LIMIT 限制', enabled: true },
    { id: 'R-003', name: '禁止无 WHERE 的 DELETE/UPDATE', category: '高危变更', severity: 'error', description: 'DML 变更必须携带 WHERE 条件', enabled: true },
    { id: 'R-004', name: '禁止模糊查询全表扫描', category: '查询规范', severity: 'info', description: 'LIKE 前置通配符可能导致全表扫描', enabled: true },
    { id: 'R-005', name: '禁止破坏性语句', category: '高危变更', severity: 'error', description: 'DROP TABLE / TRUNCATE 属于破坏性操作', enabled: true },
    { id: 'R-006', name: 'DDL 变更建议先备份', category: 'DDL 规范', severity: 'info', description: '结构变更前建议确认备份策略', enabled: true },
    { id: 'R-007', name: '禁止 SQL 中出现凭据', category: '安全规范', severity: 'error', description: 'SQL 文本中不得包含密码或凭据字面量', enabled: true },
    { id: 'R-008', name: '禁止无条件子查询', category: '查询规范', severity: 'warning', description: '子查询应带有过滤条件并控制结果集', enabled: true },
    { id: 'R-009', name: 'JOIN 必须指定连接条件', category: '查询规范', severity: 'warning', description: 'JOIN 查询应显式声明 ON 连接条件', enabled: true },
    { id: 'R-010', name: '避免 OR 拼接过滤条件', category: '查询规范', severity: 'info', description: '多条件 OR 可能绕过索引', enabled: true },
    { id: 'R-011', name: 'DML 需评估影响行数', category: '高危变更', severity: 'warning', description: '批量变更建议先执行 SELECT 评估影响范围', enabled: true },
    { id: 'R-012', name: '禁止修改主键列', category: '高危变更', severity: 'error', description: 'UPDATE 不应修改主键或唯一键列', enabled: false },
  ];
}

function buildDemoReviews(rules) {
  return [
    reviewSpec({ id: 'SRV-20260828-001', title: '订单主库清理草稿订单', engine: 'MySQL', instance_id: 'mysql-prod-order-01', sql: 'DELETE FROM orders;', status: 'pending', submitter: '张运维', submitted_at: '2026-08-28T09:05:00Z' }),
    reviewSpec({ id: 'SRV-20260828-002', title: '用户中心导出近三个月注册用户', engine: 'PostgreSQL', instance_id: 'pgsql-user-primary', sql: "SELECT * FROM users WHERE created_at >= NOW() - INTERVAL '3 months';", status: 'reviewing', submitter: '陈数据', submitted_at: '2026-08-28T08:40:00Z' }),
    reviewSpec({ id: 'SRV-20260828-003', title: '分析从库全表重建压缩', engine: 'MySQL', instance_id: 'mysql-analytics-replica', sql: 'ALTER TABLE orders ENGINE=InnoDB, ROW_FORMAT=COMPRESSED;', status: 'approved', submitter: '李执行', submitted_at: '2026-08-28T07:50:00Z', reviewer: '王审批', reviewed_at: '2026-08-28T08:10:00Z', history_note: '同意，注意在业务低峰执行' }),
    reviewSpec({ id: 'SRV-20260828-004', title: '缓存集群评估会话键规模', engine: 'Redis', instance_id: 'redis-session-01', sql: 'KEYS session:*', status: 'approved', submitter: '张运维', submitted_at: '2026-08-28T07:20:00Z', reviewer: '王审批', reviewed_at: '2026-08-28T07:35:00Z', history_note: '只读评估，通过' }),
    reviewSpec({ id: 'SRV-20260828-005', title: '订单主库修复重复订单状态', engine: 'MySQL', instance_id: 'mysql-prod-order-01', sql: "UPDATE orders SET order_status = 'paid';", status: 'rejected', submitter: '陈数据', submitted_at: '2026-08-28T06:45:00Z', reviewer: '王审批', reviewed_at: '2026-08-28T07:00:00Z', history_note: 'UPDATE 缺少 WHERE，风险不可控' }),
    reviewSpec({ id: 'SRV-20260828-006', title: '用户中心账号查询优化', engine: 'PostgreSQL', instance_id: 'pgsql-user-primary', sql: "SELECT id, nickname FROM users WHERE nickname LIKE '%张%' ORDER BY id;", status: 'reviewing', submitter: '陈数据', submitted_at: '2026-08-28T06:10:00Z' }),
    reviewSpec({ id: 'SRV-20260828-007', title: '分析从库归档订单明细', engine: 'MySQL', instance_id: 'mysql-analytics-replica', sql: "SELECT id, order_no, amount FROM order_detail WHERE created_at >= '2026-05-01' AND created_at < '2026-08-01' LIMIT 1000;", status: 'approved', submitter: '李执行', submitted_at: '2026-08-27T15:30:00Z', reviewer: '王审批', reviewed_at: '2026-08-27T16:00:00Z', history_note: '查询已加 LIMIT，通过' }),
    reviewSpec({ id: 'SRV-20260828-008', title: '订单主库季度归档清理', engine: 'MySQL', instance_id: 'mysql-prod-order-01', sql: 'TRUNCATE TABLE archive_orders;', status: 'rejected', submitter: '张运维', submitted_at: '2026-08-27T14:00:00Z', reviewer: '王审批', reviewed_at: '2026-08-27T14:20:00Z', history_note: 'TRUNCATE 属于破坏性语句，请走工单审批' }),
    reviewSpec({ id: 'SRV-20260828-009', title: '用户中心查询单个账号', engine: 'PostgreSQL', instance_id: 'pgsql-user-primary', sql: "SELECT id, email FROM users WHERE email = 'demo@example.com' AND status = 1 LIMIT 1;", status: 'pending', submitter: '陈数据', submitted_at: '2026-08-27T11:00:00Z' }),
    reviewSpec({ id: 'SRV-20260828-010', title: '分析从库订单表增加统计字段', engine: 'MySQL', instance_id: 'mysql-analytics-replica', sql: 'ALTER TABLE orders ADD COLUMN channel_count INT DEFAULT 0;', status: 'approved', submitter: '李执行', submitted_at: '2026-08-27T09:30:00Z', reviewer: '王审批', reviewed_at: '2026-08-27T09:50:00Z', history_note: '低风险 DDL，通过' }),
  ].map((spec) => completeReview(spec, rules));
}

function reviewSpec(spec) {
  return spec;
}

function completeReview(spec, rules) {
  const assessment = evaluateSqlReview(spec.sql, rules);
  const history = [{ status: 'pending', at: spec.submitted_at, by: spec.submitter, note: '提交 SQL 审核' }];
  if (spec.status === 'reviewing') history.push({ status: 'reviewing', at: spec.submitted_at, by: '规则引擎', note: '静态扫描完成，等待人工复核' });
  if (spec.status === 'approved') history.push({ status: 'approved', at: spec.reviewed_at, by: spec.reviewer, note: spec.history_note ?? '审核通过' });
  if (spec.status === 'rejected') history.push({ status: 'rejected', at: spec.reviewed_at, by: spec.reviewer, note: spec.history_note ?? '审核拒绝' });
  return {
    ...spec,
    reviewer: spec.reviewer ?? '',
    reviewed_at: spec.reviewed_at ?? '',
    risk: assessment.risk,
    score: assessment.score,
    hits: assessment.hits,
    summary: assessment.summary,
    history,
  };
}

function topRuleCounts(reviews, limit = 5) {
  const counts = new Map();
  reviews.forEach((review) => {
    (Array.isArray(review.hits) ? review.hits : []).forEach((hit) => {
      const name = hit.rule_name ?? hit.rule_id ?? '未知规则';
      counts.set(name, (counts.get(name) ?? 0) + 1);
    });
  });
  return [...counts.entries()]
    .map(([rule_name, count]) => ({ rule_name, count }))
    .sort((left, right) => right.count - left.count)
    .slice(0, limit);
}

function filterDemoReviews(reviews, filters = {}) {
  const status = String(filters.status ?? '').trim();
  const risk = String(filters.risk ?? '').trim();
  const instanceId = String(filters.instance_id ?? '').trim();
  const search = String(filters.search ?? '').trim().toLowerCase();
  return reviews.filter((review) => {
    if (status && review.status !== status) return false;
    if (risk && review.risk !== risk) return false;
    if (instanceId && review.instance_id !== instanceId) return false;
    if (search && !`${review.title}\n${review.sql}\n${review.id}`.toLowerCase().includes(search)) return false;
    return true;
  });
}

function invalidReviewPayload(value) {
  const title = String(value?.title ?? '').trim();
  const sql = String(value?.sql ?? '').trim();
  if (!title || !sql) return true;
  return SQL_REVIEW_SENSITIVE_PATTERN.test(sql);
}

function normalizeList(response, scope, source = 'http', meta = {}) {
  const rawItems = Array.isArray(response) ? response : Array.isArray(response?.items) ? response.items : [];
  return {
    source,
    scope: cleanScope(scope),
    items: rawItems.map((item) => redactDTO(item)),
    ...meta,
  };
}

function normalizeEntity(response, scope, source = 'http') {
  const value = response && typeof response === 'object' && response.review && typeof response.review === 'object' ? response.review : response;
  return { ...redactDTO(value), source, scope: cleanScope(scope) };
}

function redactDTO(value) {
  if (Array.isArray(value)) return value.map(redactDTO);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (isUnsafeSqlReviewKey(key)) return [];
    return [[key, redactDTO(item)]];
  }));
}

function isUnsafeSqlReviewKey(key) {
  const normalized = String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalized === 'scope' || normalized === 'audit' || normalized === 'auditdetails') return true;
  return /(secret|token|password|credential|authorization|apikey|privatekey|connectionstring|dsn)/.test(normalized);
}

function reviewQuery(filters = {}) {
  const query = [];
  for (const key of REVIEW_FILTER_FIELDS) {
    const value = filters[key];
    if (value != null && String(value).trim() !== '') query.push(`${key}=${encodeURIComponent(String(value).trim())}`);
  }
  const page = boundedPage(filters.page);
  const pageSize = boundedPageSize(filters.pageSize);
  query.push(`page=${page}`, `page_size=${pageSize}`);
  return `?${query.join('&')}`;
}

function listMeta(response, filters) {
  const rawItems = Array.isArray(response) ? response : Array.isArray(response?.items) ? response.items : [];
  const page = boundedPage(filters?.page);
  const pageSize = boundedPageSize(filters?.pageSize);
  const total = Number(response?.total ?? rawItems.length) || rawItems.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  return { total, page, pageSize, totalPages };
}

function boundedPage(value) {
  const number = Number(value ?? 1);
  return Number.isInteger(number) && number >= 1 ? number : 1;
}

function boundedPageSize(value) {
  const number = Number(value ?? DEFAULT_PAGE_SIZE);
  if (!Number.isInteger(number) || number < 1) return DEFAULT_PAGE_SIZE;
  return Math.min(number, 100);
}

function bySubmittedAtDesc(left, right) {
  return String(right.submitted_at).localeCompare(String(left.submitted_at));
}

function byRuleID(left, right) {
  return String(left.id).localeCompare(String(right.id));
}

function nextReviewID(reviews) {
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  let max = 0;
  reviews.forEach((review) => {
    const match = /SRV-(\d{8})-(\d{3})$/.exec(String(review.id ?? ''));
    if (match && match[1] === today) max = Math.max(max, Number(match[2]));
  });
  return `SRV-${today}-${String(max + 1).padStart(3, '0')}`;
}

function pickDTO(value, fields) {
  if (!value || typeof value !== 'object') return {};
  return Object.fromEntries(fields.filter((field) => value[field] !== undefined).map((field) => [field, value[field]]));
}

function jsonRequest(method, body) {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

function cleanScope(scope) {
  return { tenantId: scope?.tenantId, projectId: scope?.projectId };
}

function failureForStatus(status) {
  if (status === 401) return sqlReviewFailure('unauthorized', status);
  if (status === 403) return sqlReviewFailure('forbidden', status);
  if (status === 404) return sqlReviewFailure('not-found', status);
  if (status === 409) return sqlReviewFailure('conflict', status);
  if (status === 400 || status === 413 || status === 415 || status === 422) return sqlReviewFailure('validation', status);
  return sqlReviewFailure('unavailable', status);
}

function sqlReviewFailure(kind, status) {
  const message = SQL_REVIEW_ERRORS[kind] ?? SQL_REVIEW_ERRORS.unavailable;
  return status == null ? { kind, message } : { kind, message, status };
}

if (typeof window !== 'undefined') {
  window.DBPilotSqlReviewApi = { create: createSqlReviewApi };
}
