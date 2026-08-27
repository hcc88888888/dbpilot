const SLOW_SQL_ERRORS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '慢 SQL 记录不存在或已无权访问',
  conflict: '慢 SQL 记录状态已更新，请刷新后重试',
  validation: '慢 SQL 查询参数不符合要求，请修改后重试',
  unavailable: '慢 SQL 治理服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const LIST_FIELDS = ['engine', 'instance_id', 'state', 'min_duration', 'search', 'sortBy', 'page', 'pageSize'];
const DEFAULT_PAGE_SIZE = 10;
const MAX_PAGE_SIZE = 100;
const RATIO_BASELINE_MS = 100_000_000;
const DEMO_DATE = '2026-08-28';
const SORT_KEY = { avg: 'avg_duration_ms', total: 'total_duration_ms', count: 'exec_count' };

/**
 * Create the only frontend boundary for slow-SQL governance data.
 * A configured base URL selects the real control-plane API; otherwise the
 * adapter supplies explicitly marked, safe local demo data.
 */
export function createSlowSqlApi({ baseUrl = '', fetchImpl = globalThis.fetch, available = true } = {}) {
  if (!available) return createUnavailableAdapter();
  if (!baseUrl) return createDemoAdapter();
  if (typeof fetchImpl !== 'function') throw slowSqlFailure('network');

  const base = baseUrl.replace(/\/+$/, '');
  const request = async (scope, path, init = {}, signal) => {
    const safeScope = cleanScope(scope);
    if (!safeScope.tenantId || !safeScope.projectId) throw slowSqlFailure('validation');
    const prefix = `/api/v1/tenants/${encodeURIComponent(safeScope.tenantId)}/projects/${encodeURIComponent(safeScope.projectId)}`;
    let response;
    try {
      response = await fetchImpl(`${base}${prefix}${path}`, { ...init, signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      if (error?.kind && SLOW_SQL_ERRORS[error.kind]) throw error;
      throw slowSqlFailure('network');
    }
    if (!response.ok) throw failureForStatus(response.status);
    if (response.status === 204) return undefined;
    try {
      return await response.json();
    } catch {
      throw slowSqlFailure('unavailable', response.status);
    }
  };

  return createHttpAdapter(request);
}

function createHttpAdapter(request) {
  return {
    async getOverview(scope, signal) {
      return normalizeEntity(await request(scope, '/slow-sql/overview', {}, signal), scope, 'http');
    },

    async listSlowSql(scope, filters = {}, signal) {
      const query = listQuery(filters);
      const response = await request(scope, `/slow-sql/items${query}`, {}, signal);
      return normalizeList(response, scope, 'http', listMeta(response, filters));
    },

    async getSlowSql(scope, id, signal) {
      if (id == null || String(id).trim() === '') return Promise.reject(slowSqlFailure('validation'));
      return normalizeEntity(await request(scope, `/slow-sql/items/${encodeURIComponent(String(id))}`, {}, signal), scope, 'http');
    },

    async ackSlowSql(scope, id, signal) {
      if (id == null || String(id).trim() === '') return Promise.reject(slowSqlFailure('validation'));
      return normalizeEntity(await request(scope, `/slow-sql/items/${encodeURIComponent(String(id))}/ack`, { method: 'POST' }, signal), scope, 'http');
    },

    async ignoreSlowSql(scope, id, signal) {
      if (id == null || String(id).trim() === '') return Promise.reject(slowSqlFailure('validation'));
      return normalizeEntity(await request(scope, `/slow-sql/items/${encodeURIComponent(String(id))}/ignore`, { method: 'POST' }, signal), scope, 'http');
    },
  };
}

function createUnavailableAdapter() {
  const unavailable = async () => { throw slowSqlFailure('unavailable'); };
  return {
    getOverview: unavailable,
    listSlowSql: unavailable,
    getSlowSql: unavailable,
    ackSlowSql: unavailable,
    ignoreSlowSql: unavailable,
  };
}

function createDemoAdapter() {
  const store = { items: buildDemoItems() };
  return {
    async getOverview(scope) {
      const items = store.items;
      const totalDuration = items.reduce((sum, item) => sum + Number(item.total_duration_ms), 0);
      const stats = {
        total: items.length,
        new_today: items.filter((item) => String(item.first_seen).startsWith(DEMO_DATE)).length,
        avg_duration_ms: Math.round(items.reduce((sum, item) => sum + Number(item.avg_duration_ms), 0) / items.length),
        total_ratio: Math.min(100, Math.round(totalDuration / RATIO_BASELINE_MS * 100)),
      };
      const top = sortDemoItems(items, 'total').slice(0, 5);
      const distribution = {
        open: items.filter((item) => item.state === 'open').length,
        acknowledged: items.filter((item) => item.state === 'acknowledged').length,
        ignored: items.filter((item) => item.state === 'ignored').length,
      };
      return normalizeEntity({ stats, top, distribution }, scope, 'demo');
    },

    async listSlowSql(scope, filters = {}) {
      const filtered = filterDemoItems(store.items, filters);
      const sortBy = SORT_KEY[filters.sortBy] ? String(filters.sortBy) : 'total';
      const page = Math.max(1, Number(filters.page) || 1);
      const pageSize = boundedPageSize(filters.pageSize);
      const total = filtered.length;
      const totalPages = Math.max(1, Math.ceil(total / pageSize));
      const items = sortDemoItems(filtered, sortBy).slice((page - 1) * pageSize, page * pageSize);
      return normalizeList(items, scope, 'demo', { total, page, pageSize, totalPages });
    },

    async getSlowSql(scope, id) {
      const item = store.items.find((entry) => entry.id === String(id));
      if (!item) throw slowSqlFailure('not-found');
      return normalizeEntity(item, scope, 'demo');
    },

    async ackSlowSql(scope, id) {
      const item = store.items.find((entry) => entry.id === String(id));
      if (!item) throw slowSqlFailure('not-found');
      item.state = 'acknowledged';
      return normalizeEntity(item, scope, 'demo');
    },

    async ignoreSlowSql(scope, id) {
      const item = store.items.find((entry) => entry.id === String(id));
      if (!item) throw slowSqlFailure('not-found');
      item.state = 'ignored';
      return normalizeEntity(item, scope, 'demo');
    },
  };
}

function buildDemoItems() {
  return [
    demoSlowSql({
      id: 'SSQ-20260828-001', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      database: 'shop', table_name: 'orders',
      fingerprint: 'SELECT * FROM orders WHERE status = ? AND created_at > ?',
      sample: 'SELECT * FROM orders WHERE status = "PAID" AND created_at > "2026-08-01" ORDER BY created_at DESC LIMIT 200',
      avg: 850, max: 2100, count: 12400,
      first: '2026-08-28T02:12:00Z', last: '2026-08-28T09:58:00Z', state: 'open',
      suggestion: { kind: 'index', message: '建议在 orders.status 与 created_at 上创建联合索引，避免按状态与时间过滤时回表扫描。', ddl: 'ALTER TABLE orders ADD INDEX idx_status_created (status, created_at);' },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-002', instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL',
      database: 'users', table_name: 'users',
      fingerprint: 'SELECT * FROM users WHERE email = ? ORDER BY last_login DESC LIMIT 50',
      sample: "SELECT * FROM users WHERE email = 'demo@example.com' ORDER BY last_login DESC LIMIT 50",
      avg: 620, max: 980, count: 8600,
      first: '2026-08-28T01:30:00Z', last: '2026-08-28T09:45:00Z', state: 'open',
      suggestion: { kind: 'index', message: 'email 列缺少索引导致按邮箱查询走全表扫描，建议建立唯一索引。', ddl: 'CREATE UNIQUE INDEX idx_users_email ON users (email);' },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-003', instance_id: 'oracle-finance-01', instance_name: '财务核心库', engine: 'Oracle',
      database: 'fincore', table_name: 'ledger',
      fingerprint: 'SELECT * FROM ledger WHERE account_id = ? AND settled_at >= ?',
      sample: "SELECT * FROM ledger WHERE account_id = 1002334 AND settled_at >= TO_DATE('2026-01-01','YYYY-MM-DD')",
      avg: 1500, max: 4200, count: 3200,
      first: '2026-08-27T22:10:00Z', last: '2026-08-28T09:52:00Z', state: 'open',
      suggestion: { kind: 'rewrite', message: 'ledger 表按账期分区，建议在查询条件中显式带上分区裁剪并改写为等值谓词。', ddl: "SELECT * FROM ledger PARTITION FOR (DATE '2026-08-01') WHERE account_id = :aid;" },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-004', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      database: 'shop', table_name: 'order_detail',
      fingerprint: 'SELECT * FROM order_detail WHERE order_id = ?',
      sample: 'SELECT * FROM order_detail WHERE order_id = 9038451',
      avg: 430, max: 760, count: 15200,
      first: '2026-08-28T00:05:00Z', last: '2026-08-28T09:40:00Z', state: 'acknowledged',
      suggestion: { kind: 'index', message: 'order_detail 缺少 order_id 索引，建议补充单列索引。', ddl: 'ALTER TABLE order_detail ADD INDEX idx_order_id (order_id);' },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-005', instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL',
      database: 'session', table_name: 'session_log',
      fingerprint: 'DELETE FROM session_log WHERE expire_at < NOW()',
      sample: 'DELETE FROM session_log WHERE expire_at < NOW()',
      avg: 2800, max: 9800, count: 240,
      first: '2026-08-26T14:20:00Z', last: '2026-08-27T18:30:00Z', state: 'ignored',
      suggestion: { kind: 'rewrite', message: '全表过期删除每次锁大量行，建议按主键分批删除以控制锁粒度。', ddl: 'DELETE FROM session_log WHERE ctid IN (SELECT ctid FROM session_log WHERE expire_at < NOW() ORDER BY id LIMIT 1000);' },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-006', instance_id: 'mysql-analytics-replica', instance_name: '分析从库', engine: 'MySQL',
      database: 'analytics', table_name: 'orders',
      fingerprint: 'SELECT * FROM orders WHERE channel = ? AND created_at BETWEEN ? AND ?',
      sample: 'SELECT * FROM orders WHERE channel = "app" AND created_at BETWEEN "2026-08-01" AND "2026-08-28"',
      avg: 980, max: 1750, count: 7200,
      first: '2026-08-28T03:40:00Z', last: '2026-08-28T09:36:00Z', state: 'open',
      suggestion: { kind: 'index', message: '渠道加时间区间过滤未走索引，建议建组合索引。', ddl: 'ALTER TABLE orders ADD INDEX idx_channel_created (channel, created_at);' },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-007', instance_id: 'oracle-finance-01', instance_name: '财务核心库', engine: 'Oracle',
      database: 'fincore', table_name: 'settlement',
      fingerprint: 'SELECT COUNT(*) FROM settlement WHERE trans_dt = :d',
      sample: "SELECT COUNT(*) FROM settlement WHERE trans_dt = TO_DATE('2026-08-27','YYYY-MM-DD')",
      avg: 3100, max: 5200, count: 4100,
      first: '2026-08-27T20:00:00Z', last: '2026-08-28T09:30:00Z', state: 'open',
      suggestion: { kind: 'stats', message: 'settlement 表统计信息过期导致优化器选择错误执行计划，建议重新收集统计信息并启用直方图。', ddl: "EXEC DBMS_STATS.GATHER_TABLE_STATS('FINCORE', 'SETTLEMENT', cascade => TRUE);" },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-008', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      database: 'shop', table_name: 'pay_records',
      fingerprint: 'SELECT * FROM pay_records WHERE user_id = ? AND paid_at >= ?',
      sample: 'SELECT * FROM pay_records WHERE user_id = 88213 AND paid_at >= "2026-07-01"',
      avg: 560, max: 990, count: 9800,
      first: '2026-08-27T16:10:00Z', last: '2026-08-28T09:22:00Z', state: 'acknowledged',
      suggestion: { kind: 'index', message: '用户维度的支付查询缺少索引，建议添加联合索引。', ddl: 'ALTER TABLE pay_records ADD INDEX idx_user_paid (user_id, paid_at);' },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-009', instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL',
      database: 'users', table_name: 'addresses',
      fingerprint: 'SELECT * FROM addresses WHERE user_id = ?',
      sample: 'SELECT * FROM addresses WHERE user_id = 55670',
      avg: 350, max: 610, count: 13600,
      first: '2026-08-27T12:00:00Z', last: '2026-08-28T09:10:00Z', state: 'acknowledged',
      suggestion: { kind: 'index', message: 'addresses.user_id 缺少索引，建议补充。', ddl: 'CREATE INDEX idx_addresses_user_id ON addresses (user_id);' },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-010', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      database: 'shop', table_name: 'orders',
      fingerprint: 'UPDATE orders SET order_status = ? WHERE order_id = ?',
      sample: 'UPDATE orders SET order_status = "CANCELLED" WHERE order_id = 9038452',
      avg: 720, max: 1900, count: 5600,
      first: '2026-08-25T09:00:00Z', last: '2026-08-26T20:15:00Z', state: 'ignored',
      suggestion: { kind: 'index', message: 'UPDATE 的 WHERE 条件依赖 order_id 主键，需确认无大事务阻塞后保持现状。', ddl: 'ALTER TABLE orders ADD INDEX idx_order_id (order_id);' },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-011', instance_id: 'oracle-finance-01', instance_name: '财务核心库', engine: 'Oracle',
      database: 'fincore', table_name: 'accounts',
      fingerprint: "SELECT * FROM accounts WHERE customer_no LIKE ? || '%'",
      sample: "SELECT * FROM accounts WHERE customer_no LIKE '110239%'",
      avg: 1900, max: 3600, count: 1800,
      first: '2026-08-27T08:30:00Z', last: '2026-08-28T08:55:00Z', state: 'open',
      suggestion: { kind: 'rewrite', message: '客户号前缀查询可改写为范围谓词以利用索引区间扫描。', ddl: "SELECT * FROM accounts WHERE customer_no >= :prefix AND customer_no < :prefix_upper;" },
    }),
    demoSlowSql({
      id: 'SSQ-20260828-012', instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL',
      database: 'users', table_name: 'profiles',
      fingerprint: 'SELECT p.*, u.email FROM profiles p LEFT JOIN users u ON u.id = p.user_id',
      sample: 'SELECT p.*, u.email FROM profiles p LEFT JOIN users u ON u.id = p.user_id',
      avg: 1150, max: 2800, count: 4200,
      first: '2026-08-26T10:00:00Z', last: '2026-08-27T16:00:00Z', state: 'ignored',
      suggestion: { kind: 'rewrite', message: '无过滤条件的全表 LEFT JOIN 数据膨胀，建议按更新时间窗口裁剪。', ddl: "SELECT p.*, u.email FROM profiles p LEFT JOIN users u ON u.id = p.user_id WHERE p.updated_at >= NOW() - INTERVAL '7 days';" },
    }),
  ].map(completeDemoItem);
}

function demoSlowSql({ id, instance_id, instance_name, engine, database, table_name, fingerprint, sample, avg, max, count, first, last, state, suggestion }) {
  return { id, instance_id, instance_name, engine, database, table_name, fingerprint, sample, avg, max, count, first, last, state, suggestion };
}

function completeDemoItem(item) {
  const avg = Number(item.avg) || 0;
  const count = Number(item.count) || 0;
  return {
    id: item.id,
    instance_id: item.instance_id,
    instance_name: item.instance_name,
    engine: item.engine,
    database: item.database,
    table_name: item.table_name,
    sql_fingerprint: item.fingerprint,
    sql_sample: item.sample,
    avg_duration_ms: avg,
    max_duration_ms: item.max,
    exec_count: count,
    total_duration_ms: avg * count,
    sample_count: count,
    first_seen: item.first,
    last_seen: item.last,
    state: item.state,
    trend: demoTrend(avg, count),
    suggestion: item.suggestion ? { ...item.suggestion } : { kind: '', message: '', ddl: '' },
  };
}

function demoTrend(avg, count) {
  const base = new Date('2026-08-28T04:00:00Z');
  return {
    buckets: Array.from({ length: 7 }, (_, index) => {
      const wave = 0.82 + Math.sin(index * 1.1) * 0.22 + index * 0.045;
      return {
        at: new Date(base.getTime() + index * 3_600_000).toISOString(),
        avg: Math.max(10, Math.round(avg * wave)),
        count: Math.max(1, Math.round(count * (0.85 + index * 0.05))),
      };
    }),
  };
}

function filterDemoItems(items, filters = {}) {
  const search = String(filters.search ?? '').trim().toLowerCase();
  const minDuration = Number(filters.min_duration);
  return items.filter((item) => {
    if (filters.engine && item.engine !== filters.engine) return false;
    if (filters.instance_id && item.instance_id !== filters.instance_id) return false;
    if (filters.state && item.state !== filters.state) return false;
    if (Number.isFinite(minDuration) && minDuration > 0 && Number(item.avg_duration_ms) < minDuration) return false;
    if (search) {
      const haystack = `${item.id} ${item.sql_fingerprint} ${item.sql_sample} ${item.instance_name} ${item.database} ${item.table_name}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });
}

function sortDemoItems(items, sortBy) {
  const key = SORT_KEY[sortBy] ?? SORT_KEY.total;
  return [...items].sort((left, right) => Number(right[key]) - Number(left[key]));
}

function listQuery(filters = {}) {
  const query = [];
  for (const field of LIST_FIELDS) {
    const value = filters[field];
    if (value === undefined || value === null || String(value).trim() === '') continue;
    query.push(`${encodeURIComponent(field)}=${encodeURIComponent(String(value))}`);
  }
  return query.length ? `?${query.join('&')}` : '';
}

function listMeta(response, filters = {}) {
  const raw = response && typeof response === 'object' ? response : {};
  const total = Number(raw.total) || 0;
  const pageSize = boundedPageSize(filters.pageSize);
  return {
    total,
    page: Number(filters.page) || 1,
    pageSize,
    totalPages: total ? Math.max(1, Math.ceil(total / pageSize)) : 1,
  };
}

function normalizeList(response, scope, source = 'http', meta = {}) {
  const raw = response && typeof response === 'object' ? response : {};
  const rawItems = Array.isArray(raw) ? raw : Array.isArray(raw.items) ? raw.items : [];
  const items = rawItems.map((item) => redactSlowSqlDTO(item));
  const total = Number(raw.total ?? meta.total ?? items.length) || items.length;
  return {
    source,
    scope: cleanScope(scope),
    items,
    total,
    page: Number(raw.page ?? meta.page ?? 1) || 1,
    pageSize: Number(raw.pageSize ?? meta.pageSize ?? DEFAULT_PAGE_SIZE) || DEFAULT_PAGE_SIZE,
    totalPages: Number(raw.totalPages ?? meta.totalPages ?? 1) || 1,
  };
}

function normalizeEntity(value, scope, source = 'http') {
  const resource = redactSlowSqlDTO(value);
  return { ...resource, source, scope: cleanScope(scope) };
}

export function redactSlowSqlDTO(value) {
  if (Array.isArray(value)) return value.map(redactSlowSqlDTO);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (unsafeSlowSqlKey(key)) return [];
    return [[key, redactSlowSqlDTO(item)]];
  }));
}

function unsafeSlowSqlKey(key) {
  const normalized = String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalized === 'scope' || normalized === 'audit' || normalized === 'auditdetails') return true;
  return /(secret|token|password|credential|authorization|apikey|privatekey|dsn|connectionstring)/.test(normalized);
}

function boundedPageSize(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1) return DEFAULT_PAGE_SIZE;
  return Math.min(number, MAX_PAGE_SIZE);
}

function cleanScope(scope) {
  return {
    tenantId: typeof scope?.tenantId === 'string' ? scope.tenantId.trim() : '',
    projectId: typeof scope?.projectId === 'string' ? scope.projectId.trim() : '',
  };
}

function failureForStatus(status) {
  if (status === 401) return slowSqlFailure('unauthorized', status);
  if (status === 403) return slowSqlFailure('forbidden', status);
  if (status === 404) return slowSqlFailure('not-found', status);
  if (status === 409) return slowSqlFailure('conflict', status);
  if (status === 400 || status === 413 || status === 415 || status === 422) return slowSqlFailure('validation', status);
  return slowSqlFailure('unavailable', status);
}

function slowSqlFailure(kind, status) {
  return status == null ? { kind, message: SLOW_SQL_ERRORS[kind] } : { kind, message: SLOW_SQL_ERRORS[kind], status };
}

if (typeof window !== 'undefined') {
  window.DBPilotSlowSqlApi = { create: createSlowSqlApi };
}
