const LOCKS_ERRORS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '锁事件不存在或已无权访问',
  conflict: '锁事件状态已更新，请刷新后重试',
  validation: '锁事件查询参数不符合要求，请修改后重试',
  unavailable: '锁透视服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const LIST_FIELDS = ['type', 'instance_id', 'status', 'search', 'offset', 'limit', 'page', 'pageSize'];
const DEFAULT_PAGE_SIZE = 12;
const MAX_PAGE_SIZE = 100;
const DEMO_DATE = '2026-08-28';

/**
 * Create the only frontend boundary for lock-insight data.
 * A configured base URL selects the real control-plane API; otherwise the
 * adapter supplies explicitly marked, safe local demo data.
 */
export function createLocksApi({ baseUrl = '', fetchImpl = globalThis.fetch, available = true } = {}) {
  if (!available) return createUnavailableAdapter();
  if (!baseUrl) return createDemoAdapter();
  if (typeof fetchImpl !== 'function') throw locksFailure('network');

  const base = baseUrl.replace(/\/+$/, '');
  const request = async (scope, path, init = {}, signal) => {
    const safeScope = cleanScope(scope);
    if (!safeScope.tenantId || !safeScope.projectId) throw locksFailure('validation');
    const prefix = `/api/v1/tenants/${encodeURIComponent(safeScope.tenantId)}/projects/${encodeURIComponent(safeScope.projectId)}`;
    let response;
    try {
      response = await fetchImpl(`${base}${prefix}${path}`, { ...init, signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      if (error?.kind && LOCKS_ERRORS[error.kind]) throw error;
      throw locksFailure('network');
    }
    if (!response.ok) throw failureForStatus(response.status);
    if (response.status === 204) return undefined;
    try {
      return await response.json();
    } catch {
      throw locksFailure('unavailable', response.status);
    }
  };

  return createHttpAdapter(request);
}

function createHttpAdapter(request) {
  return {
    async getOverview(scope, signal) {
      return normalizeEntity(await request(scope, '/locks/overview', {}, signal), scope, 'http');
    },

    async listLocks(scope, filters = {}, signal) {
      const query = listQuery(filters);
      const response = await request(scope, `/locks/events${query}`, {}, signal);
      return normalizeList(response, scope, 'http', listMeta(response, filters));
    },

    async getLock(scope, id, signal) {
      if (id == null || String(id).trim() === '') return Promise.reject(locksFailure('validation'));
      return normalizeEntity(await request(scope, `/locks/events/${encodeURIComponent(String(id))}`, {}, signal), scope, 'http');
    },
  };
}

function createUnavailableAdapter() {
  const unavailable = async () => { throw locksFailure('unavailable'); };
  return {
    getOverview: unavailable,
    listLocks: unavailable,
    getLock: unavailable,
  };
}

function createDemoAdapter() {
  const store = { items: buildDemoEvents() };
  return {
    async getOverview(scope) {
      const items = store.items;
      const active = items.filter((item) => item.status === 'active');
      const stats = {
        lock_waits: items.filter((item) => item.type === 'lock-wait' && item.status === 'active').length,
        deadlocks_today: items.filter((item) => item.type === 'deadlock' && String(item.first_seen).startsWith(DEMO_DATE)).length,
        long_txns: items.filter((item) => item.type === 'long-txn' && item.status === 'active').length,
        uncommitted: items.filter((item) => item.type === 'uncommitted' && item.status === 'active').length,
      };
      const activeList = [...active]
        .sort((left, right) => String(right.first_seen).localeCompare(String(left.first_seen)))
        .slice(0, 6);
      const deadlocks = items
        .filter((item) => item.type === 'deadlock')
        .sort((left, right) => String(left.first_seen).localeCompare(String(right.first_seen)));
      return normalizeEntity({ stats, active: activeList, deadlocks }, scope, 'demo');
    },

    async listLocks(scope, filters = {}) {
      const filtered = filterDemoEvents(store.items, filters);
      const { offset, limit, page, pageSize } = demoPage(filters);
      const items = filtered.slice(offset, offset + limit);
      return normalizeList(items, scope, 'demo', { total: filtered.length, page, pageSize });
    },

    async getLock(scope, id) {
      const item = store.items.find((entry) => entry.id === String(id));
      if (!item) throw locksFailure('not-found');
      return normalizeEntity(item, scope, 'demo');
    },
  };
}

function buildDemoEvents() {
  return [
    demoLock({
      id: 'LCK-20260828-001', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      type: 'lock-wait', status: 'active',
      first: '2026-08-28T02:12:00Z', last: '2026-08-28T09:58:00Z', duration: 452000,
      summary: 'UPDATE orders 与并发事务在行锁上互相等待，写入被阻塞',
      blocker: { session_id: '1042', user: 'app_order', host: '10.0.1.8:52341', sql: 'UPDATE orders SET status = \'PAID\' WHERE order_id = 9038451 AND status = \'PENDING\';', txn_age_ms: 452000, state: 'running' },
      waiter: { session_id: '2217', user: 'app_order', host: '10.0.1.9:52399', sql: 'UPDATE orders SET status = \'SHIPPED\' WHERE order_id = 9038451;', wait_ms: 128000, state: 'waiting' },
      objects: [{ schema: 'shop', table: 'orders', lock_mode: 'X', index: '' }],
    }),
    demoLock({
      id: 'LCK-20260828-002', instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL',
      type: 'lock-wait', status: 'active',
      first: '2026-08-28T06:40:00Z', last: '2026-08-28T09:51:00Z', duration: 680000,
      summary: 'users 表 UPDATE 与 VACUUM 冲突，事务等待行级锁释放',
      blocker: { session_id: '3301', user: 'svc_profile', host: '10.0.2.11:44211', sql: 'UPDATE users SET last_login = NOW() WHERE id = 55670;', txn_age_ms: 680000, state: 'sleep' },
      waiter: { session_id: '4410', user: 'svc_order', host: '10.0.2.12:44288', sql: 'SELECT * FROM users WHERE id = 55670 FOR UPDATE;', wait_ms: 216000, state: 'waiting' },
      objects: [{ schema: 'public', table: 'users', lock_mode: 'X', index: 'users_pkey' }],
    }),
    demoLock({
      id: 'LCK-20260828-003', instance_id: 'oracle-finance-01', instance_name: '财务核心库', engine: 'Oracle',
      type: 'lock-wait', status: 'active',
      first: '2026-08-28T08:05:00Z', last: '2026-08-28T09:47:00Z', duration: 388000,
      summary: 'ledger 表行级排他锁争用，批处理任务阻塞在线记账',
      blocker: { session_id: '889', user: 'batch_settle', host: '10.0.3.7:1521', sql: "UPDATE ledger SET settled_at = SYSDATE WHERE account_id = 1002334 AND settled_at IS NULL;", txn_age_ms: 388000, state: 'running' },
      waiter: { session_id: '1204', user: 'app_teller', host: '10.0.3.9:1521', sql: "UPDATE ledger SET memo = 'POS' WHERE trans_no = 'P2026082808134';", wait_ms: 94000, state: 'waiting' },
      objects: [{ schema: 'FINCORE', table: 'ledger', lock_mode: 'RX', index: 'ledger_pk' }],
    }),
    demoLock({
      id: 'LCK-20260828-004', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      type: 'lock-wait', status: 'resolved',
      first: '2026-08-27T22:20:00Z', last: '2026-08-28T00:58:00Z', duration: 132000,
      summary: '支付回调与库存扣减在 order_detail 上短时等锁，已自动解除',
      blocker: { session_id: '751', user: 'app_pay', host: '10.0.1.6:52111', sql: 'UPDATE order_detail SET pay_status = 1 WHERE order_id = 9038200;', txn_age_ms: 132000, state: 'sleep' },
      waiter: { session_id: '803', user: 'app_stock', host: '10.0.1.7:52122', sql: 'UPDATE order_detail SET stock_status = 0 WHERE order_id = 9038200;', wait_ms: 21000, state: 'waiting' },
      objects: [{ schema: 'shop', table: 'order_detail', lock_mode: 'X', index: 'idx_order_id' }],
    }),
    demoLock({
      id: 'LCK-20260828-005', instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL',
      type: 'lock-wait', status: 'resolved',
      first: '2026-08-27T19:10:00Z', last: '2026-08-27T19:32:00Z', duration: 96000,
      summary: 'addresses 表外键检查短暂等待，主事务提交后解除',
      blocker: { session_id: '2051', user: 'svc_order', host: '10.0.2.5:44201', sql: 'INSERT INTO addresses (user_id, city) VALUES (55670, \'Hangzhou\');', txn_age_ms: 96000, state: 'sleep' },
      waiter: { session_id: '2133', user: 'svc_profile', host: '10.0.2.6:44209', sql: 'DELETE FROM addresses WHERE id = 88122;', wait_ms: 41000, state: 'waiting' },
      objects: [{ schema: 'public', table: 'addresses', lock_mode: 'S', index: 'addresses_pkey' }],
    }),
    demoLock({
      id: 'LCK-20260828-006', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      type: 'deadlock', status: 'active',
      first: '2026-08-28T07:32:00Z', last: '2026-08-28T07:32:41Z', duration: 41000,
      summary: '库存事务与订单事务互相持有对方所需行锁，触发死锁回滚',
      blocker: { session_id: '3901', user: 'app_stock', host: '10.0.1.5:52133', sql: 'UPDATE inventory SET qty = qty - 1 WHERE sku_id = 3301 AND qty > 0;', txn_age_ms: 41000, state: 'running' },
      waiter: { session_id: '3908', user: 'app_order', host: '10.0.1.8:52366', sql: 'UPDATE orders SET status = \'PAID\' WHERE order_id = 9038440;', wait_ms: 6000, state: 'waiting' },
      objects: [{ schema: 'shop', table: 'orders', lock_mode: 'X', index: '' }, { schema: 'shop', table: 'inventory', lock_mode: 'X', index: 'idx_sku' }],
      detail: '2026-08-28 07:32:35 死锁检测触发\n事务 A (session 3901)：持有 inventory 行锁，等待 orders 行锁\n事务 B (session 3908)：持有 orders 行锁，等待 inventory 行锁\n选择事务 B 回滚以解除死锁，orders 行锁被释放。',
    }),
    demoLock({
      id: 'LCK-20260828-007', instance_id: 'oracle-finance-01', instance_name: '财务核心库', engine: 'Oracle',
      type: 'deadlock', status: 'resolved',
      first: '2026-08-27T23:41:00Z', last: '2026-08-27T23:42:00Z', duration: 19000,
      summary: '对账任务与结算任务环形等锁，Oracle 自动回滚牺牲会话',
      blocker: { session_id: '301', user: 'batch_recon', host: '10.0.3.11:1521', sql: "UPDATE settlement SET recon_flag = 1 WHERE trans_dt = DATE '2026-08-27';", txn_age_ms: 19000, state: 'running' },
      waiter: { session_id: '305', user: 'batch_settle', host: '10.0.3.12:1521', sql: "UPDATE settlement SET settle_flag = 1 WHERE trans_dt = DATE '2026-08-27';", wait_ms: 9000, state: 'waiting' },
      objects: [{ schema: 'FINCORE', table: 'settlement', lock_mode: 'RX', index: 'settlement_pk' }],
      detail: '2026-08-27 23:41:52 ORA-00060 死锁检测\n事务 A 持有 settlement 会话级行锁，等待同一行会话级锁\n事务 B 持有 settlement 会话级行锁，等待同一行会话级锁\n选择事务 A 回滚。',
    }),
    demoLock({
      id: 'LCK-20260828-008', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      type: 'deadlock', status: 'resolved',
      first: '2026-08-28T04:18:00Z', last: '2026-08-28T04:18:22Z', duration: 22000,
      summary: '优惠券核销与订单取消互相等锁，InnoDB 牺牲重试次数少的事务',
      blocker: { session_id: '1188', user: 'app_coupon', host: '10.0.1.9:52370', sql: 'UPDATE coupon_usage SET used = 1 WHERE coupon_id = 88213 AND user_id = 55670;', txn_age_ms: 22000, state: 'running' },
      waiter: { session_id: '1190', user: 'app_order', host: '10.0.1.10:52371', sql: 'UPDATE orders SET status = \'CANCELLED\' WHERE order_id = 9038431;', wait_ms: 8000, state: 'waiting' },
      objects: [{ schema: 'shop', table: 'coupon_usage', lock_mode: 'X', index: 'idx_coupon_user' }, { schema: 'shop', table: 'orders', lock_mode: 'X', index: '' }],
      detail: '2026-08-28 04:18:20 死锁检测触发\n事务 A 持有 coupon_usage 行锁，等待 orders 行锁\n事务 B 持有 orders 行锁，等待 coupon_usage 行锁\n选择事务 A 回滚。',
    }),
    demoLock({
      id: 'LCK-20260828-009', instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL',
      type: 'long-txn', status: 'active',
      first: '2026-08-28T08:22:00Z', last: '2026-08-28T09:55:00Z', duration: 5580000,
      summary: '导出任务事务长时间未提交，持续持有快照与行锁',
      blocker: { session_id: '5001', user: 'svc_export', host: '10.0.2.20:44300', sql: 'SELECT * FROM users WHERE created_at >= NOW() - INTERVAL \'30 days\';', txn_age_ms: 5580000, state: 'sleep' },
      waiter: { session_id: '5012', user: 'svc_profile', host: '10.0.2.21:44301', sql: 'UPDATE users SET email_verified = TRUE WHERE id = 77882;', wait_ms: 1290000, state: 'waiting' },
      objects: [{ schema: 'public', table: 'users', lock_mode: 'S', index: 'users_pkey' }],
    }),
    demoLock({
      id: 'LCK-20260828-010', instance_id: 'oracle-finance-01', instance_name: '财务核心库', engine: 'Oracle',
      type: 'long-txn', status: 'active',
      first: '2026-08-28T07:00:00Z', last: '2026-08-28T09:48:00Z', duration: 6480000,
      summary: '月末批量任务长事务，undo 段持续膨胀并阻塞并发写入',
      blocker: { session_id: '420', user: 'batch_monthly', host: '10.0.3.20:1521', sql: 'BEGIN UPDATE accounts SET balance = balance * 1.002 WHERE branch_id = 100; UPDATE accounts_ledger SET flag = 1; END;', txn_age_ms: 6480000, state: 'running' },
      waiter: { session_id: '428', user: 'app_teller', host: '10.0.3.21:1521', sql: "UPDATE accounts SET balance = balance - 1200 WHERE account_no = '622200001';", wait_ms: 960000, state: 'waiting' },
      objects: [{ schema: 'FINCORE', table: 'accounts', lock_mode: 'RX', index: 'accounts_pk' }],
    }),
    demoLock({
      id: 'LCK-20260828-011', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      type: 'long-txn', status: 'resolved',
      first: '2026-08-27T21:00:00Z', last: '2026-08-28T01:20:00Z', duration: 4680000,
      summary: '数据同步事务长时间运行后已提交，期间持有部分行锁',
      blocker: { session_id: '666', user: 'sync_worker', host: '10.0.1.3:52009', sql: 'INSERT INTO orders_history SELECT * FROM orders WHERE created_at < NOW() - INTERVAL 365 DAY;', txn_age_ms: 4680000, state: 'sleep' },
      waiter: { session_id: '689', user: 'app_order', host: '10.0.1.4:52011', sql: 'UPDATE orders SET status = \'PAID\' WHERE order_id = 9038001;', wait_ms: 220000, state: 'waiting' },
      objects: [{ schema: 'shop', table: 'orders', lock_mode: 'S', index: '' }],
    }),
    demoLock({
      id: 'LCK-20260828-012', instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL',
      type: 'uncommitted', status: 'active',
      first: '2026-08-28T09:12:00Z', last: '2026-08-28T09:59:00Z', duration: 2820000,
      summary: '会话持有未提交事务，产生的锁快照阻塞清理与并发写入',
      blocker: { session_id: '7701', user: 'app_refund', host: '10.0.1.12:52401', sql: 'UPDATE pay_records SET refund_status = 1 WHERE trans_no = \'P2026082810001\';', txn_age_ms: 2820000, state: 'sleep' },
      waiter: { session_id: '7712', user: 'app_order', host: '10.0.1.13:52402', sql: 'UPDATE orders SET status = \'PAID\' WHERE order_id = 9038455;', wait_ms: 330000, state: 'waiting' },
      objects: [{ schema: 'shop', table: 'pay_records', lock_mode: 'X', index: 'idx_trans_no' }],
    }),
    demoLock({
      id: 'LCK-20260828-013', instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL',
      type: 'uncommitted', status: 'resolved',
      first: '2026-08-27T18:30:00Z', last: '2026-08-27T18:45:00Z', duration: 540000,
      summary: '手动 psql 会话遗留未提交事务，回滚后锁立即释放',
      blocker: { session_id: '98', user: 'dba_ops', host: '10.0.2.2:44330', sql: 'UPDATE users SET role = \'ops\' WHERE id = 1;', txn_age_ms: 540000, state: 'sleep' },
      waiter: { session_id: '103', user: 'svc_order', host: '10.0.2.3:44331', sql: 'UPDATE users SET last_login = NOW() WHERE id = 1;', wait_ms: 360000, state: 'waiting' },
      objects: [{ schema: 'public', table: 'users', lock_mode: 'X', index: 'users_pkey' }],
    }),
  ].map(completeDemoLock);
}

function demoLock({ id, instance_id, instance_name, engine, type, status, first, last, duration, summary, blocker, waiter, objects, detail = '' }) {
  return { id, instance_id, instance_name, engine, type, status, first, last, duration, summary, blocker, waiter, objects, detail };
}

function completeDemoLock(item) {
  return {
    id: item.id,
    instance_id: item.instance_id,
    instance_name: item.instance_name,
    engine: item.engine,
    type: item.type,
    status: item.status,
    first_seen: item.first,
    last_seen: item.last,
    duration_ms: Number(item.duration) || 0,
    summary: item.summary,
    blocker: item.blocker ? { ...item.blocker } : {},
    waiter: item.waiter ? { ...item.waiter } : {},
    objects: Array.isArray(item.objects) ? item.objects.map((entry) => ({ ...entry })) : [],
    detail: String(item.detail ?? ''),
  };
}

function filterDemoEvents(items, filters = {}) {
  const search = String(filters.search ?? '').trim().toLowerCase();
  return items.filter((item) => {
    if (filters.type && item.type !== filters.type) return false;
    if (filters.instance_id && item.instance_id !== filters.instance_id) return false;
    if (filters.status && item.status !== filters.status) return false;
    if (search) {
      const haystack = `${item.id} ${item.summary} ${item.instance_name} ${item.engine} ${item.blocker?.sql ?? ''} ${item.waiter?.sql ?? ''}`.toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });
}

function demoPage(filters = {}) {
  const hasOffset = filters.offset != null && String(filters.offset).trim() !== '';
  const hasLimit = filters.limit != null && String(filters.limit).trim() !== '';
  const pageSize = boundedPageSize(hasLimit ? filters.limit : filters.pageSize);
  if (hasOffset) {
    const offset = Math.max(0, Number(filters.offset) || 0);
    const page = Math.floor(offset / pageSize) + 1;
    return { offset, limit: pageSize, page, pageSize };
  }
  const page = Math.max(1, Number(filters.page) || 1);
  return { offset: (page - 1) * pageSize, limit: pageSize, page, pageSize };
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
  const pageSize = boundedPageSize(filters.pageSize ?? filters.limit);
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
  const items = rawItems.map((item) => redactLocksDTO(item));
  const total = Number(raw.total ?? meta.total ?? items.length) || items.length;
  const pageSize = boundedPageSize(raw.pageSize ?? meta.pageSize);
  const page = Math.max(1, Number(raw.page ?? meta.page ?? 1) || 1);
  return {
    source,
    scope: cleanScope(scope),
    items,
    total,
    page,
    pageSize,
    totalPages: Math.max(1, Math.ceil(total / pageSize)),
  };
}

function normalizeEntity(value, scope, source = 'http') {
  const resource = redactLocksDTO(value);
  return { ...resource, source, scope: cleanScope(scope) };
}

export function redactLocksDTO(value) {
  if (Array.isArray(value)) return value.map(redactLocksDTO);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (unsafeLocksKey(key)) return [];
    return [[key, redactLocksDTO(item)]];
  }));
}

function unsafeLocksKey(key) {
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
  if (status === 401) return locksFailure('unauthorized', status);
  if (status === 403) return locksFailure('forbidden', status);
  if (status === 404) return locksFailure('not-found', status);
  if (status === 409) return locksFailure('conflict', status);
  if (status === 400 || status === 413 || status === 415 || status === 422) return locksFailure('validation', status);
  return locksFailure('unavailable', status);
}

function locksFailure(kind, status) {
  return status == null ? { kind, message: LOCKS_ERRORS[kind] } : { kind, message: LOCKS_ERRORS[kind], status };
}

if (typeof window !== 'undefined') {
  window.DBPilotLocksApi = { create: createLocksApi };
}
