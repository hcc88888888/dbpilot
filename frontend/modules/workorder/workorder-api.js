const WORKORDER_ERRORS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '工单不存在或已无权访问',
  conflict: '工单状态已更新，请刷新后重试',
  validation: '工单内容不符合要求，请修改后重试',
  unavailable: '工单服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const WORKORDER_SENSITIVE_PATTERN = /(?:\b(?:password|passwd|pwd|token|secret|credential|api[_\s-]?key)\b|connectionstring|dsn)/i;

const DEFAULT_PAGE_SIZE = 10;
const CURRENT_ACTOR = 'ops-01';

const INSTANCE_NAMES = {
  'mysql-prod-order-01': '订单主库',
  'pgsql-user-primary': '用户中心',
  'redis-session-01': '缓存集群',
  'mysql-analytics-replica': '分析从库',
};

const CREATE_FIELDS = ['title', 'type', 'engine', 'instance_id', 'sql', 'rollback_sql', 'reason', 'risk', 'created_by'];
const TICKET_FILTER_FIELDS = ['status', 'type', 'instance_id', 'search'];

/**
 * Create the only frontend boundary for work-order data.
 * A configured base URL selects the real control-plane API; otherwise the
 * adapter supplies explicitly marked, safe local demo data.
 */
export function createWorkOrderApi({ baseUrl = '', fetchImpl = globalThis.fetch, available = true } = {}) {
  if (!available) return createUnavailableAdapter();
  if (!baseUrl) return createDemoAdapter();
  if (typeof fetchImpl !== 'function') throw workOrderFailure('network');

  const base = baseUrl.replace(/\/+$/, '');
  const request = async (scope, path, init = {}, signal) => {
    const safeScope = cleanScope(scope);
    const prefix = `/api/v1/tenants/${encodeURIComponent(safeScope.tenantId)}/projects/${encodeURIComponent(safeScope.projectId)}`;
    let response;
    try {
      response = await fetchImpl(`${base}${prefix}${path}`, { ...init, signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      if (error?.kind && WORKORDER_ERRORS[error.kind]) throw error;
      throw workOrderFailure('network');
    }
    if (!response.ok) throw failureForStatus(response.status);
    if (response.status === 204) return undefined;
    try {
      return await response.json();
    } catch {
      throw workOrderFailure('unavailable', response.status);
    }
  };

  return createHttpAdapter(request);
}

function createHttpAdapter(request) {
  return {
    async getOverview(scope, signal) {
      return normalizeEntity(await request(scope, '/overview', {}, signal), scope, 'http');
    },

    async listTickets(scope, filters = {}, signal) {
      const page = ticketPage(filters);
      const response = await request(scope, `/tickets${page.query}`, {}, signal);
      return normalizeList(response, scope, 'http', listMeta(response, page));
    },

    async getTicket(scope, id, signal) {
      return normalizeEntity(await request(scope, `/tickets/${encodeURIComponent(String(id))}`, {}, signal), scope, 'http');
    },

    async createTicket(scope, value, signal) {
      return normalizeEntity(await request(scope, '/tickets', jsonRequest('POST', pickDTO(value, CREATE_FIELDS)), signal), scope, 'http');
    },

    async approveTicket(scope, id, input = {}, signal) {
      return normalizeEntity(await request(scope, `/tickets/${encodeURIComponent(String(id))}/approve`, jsonRequest('POST', { approver: String(input.approver ?? '').trim(), note: String(input.note ?? '').trim() }), signal), scope, 'http');
    },

    async rejectTicket(scope, id, input = {}, signal) {
      return normalizeEntity(await request(scope, `/tickets/${encodeURIComponent(String(id))}/reject`, jsonRequest('POST', { approver: String(input.approver ?? '').trim(), note: String(input.note ?? '').trim() }), signal), scope, 'http');
    },

    async executeTicket(scope, id, input = {}, signal) {
      return normalizeEntity(await request(scope, `/tickets/${encodeURIComponent(String(id))}/execute`, jsonRequest('POST', { executor: String(input.executor ?? '').trim() }), signal), scope, 'http');
    },

    async rollbackTicket(scope, id, input = {}, signal) {
      return normalizeEntity(await request(scope, `/tickets/${encodeURIComponent(String(id))}/rollback`, jsonRequest('POST', { executor: String(input.executor ?? '').trim() }), signal), scope, 'http');
    },
  };
}

function createUnavailableAdapter() {
  const unavailable = async () => { throw workOrderFailure('unavailable'); };
  return {
    getOverview: unavailable,
    listTickets: unavailable,
    getTicket: unavailable,
    createTicket: unavailable,
    approveTicket: unavailable,
    rejectTicket: unavailable,
    executeTicket: unavailable,
    rollbackTicket: unavailable,
  };
}

function createDemoAdapter() {
  const store = { tickets: buildDemoTickets() };
  const now = () => new Date().toISOString();
  const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const findTicket = (id) => {
    const ticket = store.tickets.find((item) => item.id === String(id));
    if (!ticket) throw workOrderFailure('not-found');
    return ticket;
  };

  return {
    async getOverview(scope) {
      const tickets = store.tickets;
      const stats = {
        pending: tickets.filter((ticket) => ticket.status === 'pending').length,
        executing: tickets.filter((ticket) => ticket.status === 'executing').length,
        executed_today: tickets.filter((ticket) => ticket.status === 'executed' && isToday(ticket.executed_at)).length,
        rolled_back: tickets.filter((ticket) => ticket.status === 'rolled_back').length,
      };
      const distribution = { pending: 0, approved: 0, rejected: 0, executing: 0, executed: 0, failed: 0, rolled_back: 0 };
      tickets.forEach((ticket) => { if (distribution[ticket.status] != null) distribution[ticket.status] += 1; });
      const recent = [...tickets].sort(byCreatedAtDesc).slice(0, 5);
      return normalizeEntity({ stats, distribution, recent }, scope, 'demo');
    },

    async listTickets(scope, filters = {}) {
      const filtered = filterDemoTickets(store.tickets, filters);
      const page = boundedPage(filters.page);
      const pageSize = boundedPageSize(filters.pageSize);
      const total = filtered.length;
      const totalPages = Math.max(1, Math.ceil(total / pageSize));
      const items = [...filtered].sort(byCreatedAtDesc).slice((page - 1) * pageSize, page * pageSize);
      return normalizeList(items, scope, 'demo', { total, page, pageSize, totalPages });
    },

    async getTicket(scope, id) {
      return normalizeEntity(findTicket(id), scope, 'demo');
    },

    async createTicket(scope, value) {
      if (invalidTicketPayload(value)) throw workOrderFailure('validation');
      const at = now();
      const createdBy = String(value?.created_by ?? '').trim() || CURRENT_ACTOR;
      const ticket = {
        id: nextTicketID(store.tickets),
        title: String(value?.title ?? '').trim(),
        type: String(value?.type ?? '').trim(),
        engine: String(value?.engine ?? '').trim(),
        instance_id: String(value?.instance_id ?? '').trim(),
        instance_name: INSTANCE_NAMES[value?.instance_id] ?? String(value?.instance_id ?? ''),
        sql: String(value?.sql ?? ''),
        rollback_sql: String(value?.rollback_sql ?? ''),
        reason: String(value?.reason ?? '').trim(),
        risk: String(value?.risk ?? '').trim(),
        status: 'pending',
        created_by: createdBy,
        created_at: at,
        approver: null,
        approved_at: null,
        executor: null,
        executed_at: null,
        duration_ms: null,
        affected_rows: null,
        log: [{ at, level: 'info', message: '工单已提交' }],
        history: [{ status: 'pending', at, by: createdBy, note: '提交变更工单' }],
      };
      store.tickets.unshift(ticket);
      return normalizeEntity(ticket, scope, 'demo');
    },

    async approveTicket(scope, id, input = {}) {
      const ticket = findTicket(id);
      if (ticket.status !== 'pending') throw workOrderFailure('conflict');
      const at = now();
      const approver = String(input?.approver ?? '').trim() || CURRENT_ACTOR;
      ticket.status = 'approved';
      ticket.approver = approver;
      ticket.approved_at = at;
      ticket.history.push({ status: 'approved', at, by: approver, note: String(input?.note ?? '').trim() || '审批通过' });
      ticket.log.push({ at, level: 'info', message: '工单已批准' });
      return normalizeEntity(ticket, scope, 'demo');
    },

    async rejectTicket(scope, id, input = {}) {
      const ticket = findTicket(id);
      if (ticket.status !== 'pending') throw workOrderFailure('conflict');
      const at = now();
      const approver = String(input?.approver ?? '').trim() || CURRENT_ACTOR;
      ticket.status = 'rejected';
      ticket.approver = approver;
      ticket.rejected_at = at;
      ticket.history.push({ status: 'rejected', at, by: approver, note: String(input?.note ?? '').trim() || '审批拒绝' });
      ticket.log.push({ at, level: 'warn', message: '工单被拒绝' });
      return normalizeEntity(ticket, scope, 'demo');
    },

    async executeTicket(scope, id, input = {}) {
      const ticket = findTicket(id);
      if (ticket.status !== 'approved') throw workOrderFailure('conflict');
      const at = now();
      const executor = String(input?.executor ?? '').trim() || CURRENT_ACTOR;
      ticket.status = 'executing';
      ticket.executor = executor;
      ticket.executing_at = at;
      ticket.history.push({ status: 'executing', at, by: executor, note: '开始执行变更' });
      ticket.log.push({ at, level: 'info', message: '开始执行变更' });
      await delay(1000);
      const doneAt = now();
      const duration_ms = Math.round(300 + Math.random() * 2400);
      const affected_rows = Math.round(Math.random() * 800);
      ticket.status = 'executed';
      ticket.executed_at = doneAt;
      ticket.duration_ms = duration_ms;
      ticket.affected_rows = affected_rows;
      ticket.history.push({ status: 'executed', at: doneAt, by: executor, note: '变更执行完成' });
      ticket.log.push({ at: doneAt, level: 'info', message: `执行完成，影响 ${affected_rows} 行，耗时 ${duration_ms} ms` });
      return normalizeEntity(ticket, scope, 'demo');
    },

    async rollbackTicket(scope, id, input = {}) {
      const ticket = findTicket(id);
      if (ticket.status !== 'executed') throw workOrderFailure('conflict');
      const at = now();
      const executor = String(input?.executor ?? '').trim() || CURRENT_ACTOR;
      ticket.status = 'rolled_back';
      ticket.executor = executor;
      ticket.rolled_back_at = at;
      ticket.history.push({ status: 'rolled_back', at, by: executor, note: '执行回滚变更' });
      ticket.log.push({ at, level: 'warn', message: '变更已回滚' });
      return normalizeEntity(ticket, scope, 'demo');
    },
  };
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
  const value = response && typeof response === 'object' && response.ticket && typeof response.ticket === 'object' ? response.ticket : response;
  return { ...redactDTO(value), source, scope: cleanScope(scope) };
}

function redactDTO(value) {
  if (Array.isArray(value)) return value.map(redactDTO);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (isUnsafeWorkOrderKey(key)) return [];
    return [[key, redactDTO(item)]];
  }));
}

function isUnsafeWorkOrderKey(key) {
  const normalized = String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalized === 'scope' || normalized === 'audit' || normalized === 'auditdetails') return true;
  return /(secret|token|password|credential|authorization|apikey|privatekey|connectionstring|dsn)/.test(normalized);
}

function ticketPage(filters = {}) {
  const query = [];
  for (const key of TICKET_FILTER_FIELDS) {
    const value = filters[key];
    if (value != null && String(value).trim() !== '') query.push(`${key}=${encodeURIComponent(String(value).trim())}`);
  }
  const page = boundedPage(filters.page);
  const pageSize = boundedPageSize(filters.pageSize);
  query.push(`page=${page}`, `page_size=${pageSize}`);
  return { page, pageSize, query: `?${query.join('&')}` };
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

function listMeta(response, page) {
  const rawItems = Array.isArray(response) ? response : Array.isArray(response?.items) ? response.items : [];
  const total = Number(response?.total ?? rawItems.length) || rawItems.length;
  const totalPages = Math.max(1, Math.ceil(total / page.pageSize));
  return { total, page: page.page, pageSize: page.pageSize, totalPages };
}

function filterDemoTickets(tickets, filters = {}) {
  const status = String(filters.status ?? '').trim();
  const type = String(filters.type ?? '').trim();
  const instanceId = String(filters.instance_id ?? '').trim();
  const search = String(filters.search ?? '').trim().toLowerCase();
  return tickets.filter((ticket) => {
    if (status && ticket.status !== status) return false;
    if (type && ticket.type !== type) return false;
    if (instanceId && ticket.instance_id !== instanceId) return false;
    if (search && !`${ticket.title}\n${ticket.sql}\n${ticket.id}`.toLowerCase().includes(search)) return false;
    return true;
  });
}

function invalidTicketPayload(value) {
  const title = String(value?.title ?? '').trim();
  const sql = String(value?.sql ?? '').trim();
  const reason = String(value?.reason ?? '').trim();
  if (!title || !sql || !reason) return true;
  return WORKORDER_SENSITIVE_PATTERN.test(sql) || WORKORDER_SENSITIVE_PATTERN.test(reason);
}

function byCreatedAtDesc(left, right) {
  return String(right.created_at).localeCompare(String(left.created_at));
}

function isToday(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return false;
  const now = new Date();
  return date.getFullYear() === now.getFullYear() && date.getMonth() === now.getMonth() && date.getDate() === now.getDate();
}

function nextTicketID(tickets) {
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  let max = 0;
  tickets.forEach((ticket) => {
    const match = /WO-(\d{8})-(\d{3})$/.exec(String(ticket.id ?? ''));
    if (match && match[1] === today) max = Math.max(max, Number(match[2]));
  });
  return `WO-${today}-${String(max + 1).padStart(3, '0')}`;
}

function buildDemoTickets() {
  return [
    ticketSpec({ id: 'WO-20260828-001', title: '订单主库 orders 表增加订单渠道索引', type: 'DDL', engine: 'MySQL', instance_id: 'mysql-prod-order-01', sql: 'ALTER TABLE orders ADD INDEX idx_channel (channel, created_at);', rollback_sql: 'ALTER TABLE orders DROP INDEX idx_channel;', reason: '渠道组合字段查询频繁，增加二级索引降低延迟', risk: 'high', status: 'pending', created_by: '张运维', created_at: '2026-08-28T09:02:00Z' }),
    ticketSpec({ id: 'WO-20260828-002', title: '订单主库支付回调数据订正', type: 'DML', engine: 'MySQL', instance_id: 'mysql-prod-order-01', sql: "UPDATE orders SET pay_status = 'paid' WHERE order_no = 'SO20260827-1042' AND pay_status = 'unpaid';", rollback_sql: "UPDATE orders SET pay_status = 'unpaid' WHERE order_no = 'SO20260827-1042';", reason: '支付网关回调丢失，人工订正订单支付状态', risk: 'medium', status: 'approved', created_by: '张运维', created_at: '2026-08-28T08:30:00Z', approver: '王审批', approved_at: '2026-08-28T08:45:00Z' }),
    ticketSpec({ id: 'WO-20260828-003', title: '用户中心 users 表新增实名标识列', type: 'DDL', engine: 'PostgreSQL', instance_id: 'pgsql-user-primary', sql: 'ALTER TABLE users ADD COLUMN verified_at timestamptz;', rollback_sql: 'ALTER TABLE users DROP COLUMN verified_at;', reason: '实名认证能力上线，需记录认证时间', risk: 'high', status: 'executing', created_by: '陈数据', created_at: '2026-08-28T07:40:00Z', approver: '王审批', approved_at: '2026-08-28T08:00:00Z', executor: '李执行', executing_at: '2026-08-28T09:55:00Z' }),
    ticketSpec({ id: 'WO-20260828-004', title: '用户中心批量修复手机号空值', type: 'DML', engine: 'PostgreSQL', instance_id: 'pgsql-user-primary', sql: "UPDATE users SET phone = '400-000-0000' WHERE phone IS NULL AND status = 'active';", rollback_sql: '', reason: '客服导出报表需要手机号非空', risk: 'low', status: 'executed', created_by: '陈数据', created_at: '2026-08-28T06:20:00Z', approver: '王审批', approved_at: '2026-08-28T06:35:00Z', executor: '李执行', executing_at: '2026-08-28T06:40:00Z', executed_at: '2026-08-28T06:41:20Z', duration_ms: 1250, affected_rows: 342 }),
    ticketSpec({ id: 'WO-20260828-005', title: '分析从库授予只读账号权限', type: 'DCL', engine: 'MySQL', instance_id: 'mysql-analytics-replica', sql: "GRANT SELECT ON analytics.* TO 'bi_reader'@'%';", rollback_sql: "REVOKE SELECT ON analytics.* FROM 'bi_reader'@'%';", reason: 'BI 报表账号需要读取分析库', risk: 'medium', status: 'rejected', created_by: '陈数据', created_at: '2026-08-28T06:10:00Z', approver: '王审批', rejected_at: '2026-08-28T06:25:00Z' }),
    ticketSpec({ id: 'WO-20260828-006', title: '缓存集群 session 键内存策略调整', type: 'DDL', engine: 'Redis', instance_id: 'redis-session-01', sql: 'CONFIG SET maxmemory-policy allkeys-lru;', rollback_sql: 'CONFIG SET maxmemory-policy noeviction;', reason: '会话键积压导致内存告警，调整淘汰策略', risk: 'medium', status: 'executed', created_by: '张运维', created_at: '2026-08-28T05:30:00Z', approver: '王审批', approved_at: '2026-08-28T05:42:00Z', executor: '李执行', executing_at: '2026-08-28T05:45:00Z', executed_at: '2026-08-28T05:45:08Z', duration_ms: 800, affected_rows: 0 }),
    ticketSpec({ id: 'WO-20260828-007', title: '订单主库清理三个月前孤儿订单', type: 'DML', engine: 'MySQL', instance_id: 'mysql-prod-order-01', sql: "DELETE FROM orders WHERE status = 'draft' AND created_at < NOW() - INTERVAL 90 DAY LIMIT 5000;", rollback_sql: '', reason: '归档流程已上线，清理历史草稿订单', risk: 'high', status: 'failed', created_by: '张运维', created_at: '2026-08-28T04:10:00Z', approver: '王审批', approved_at: '2026-08-28T04:22:00Z', executor: '李执行', executing_at: '2026-08-28T04:25:00Z', failed_at: '2026-08-28T04:25:30Z', affected_rows: 0 }),
    ticketSpec({ id: 'WO-20260828-008', title: '分析从库 orders 大表重建压缩', type: 'DDL', engine: 'MySQL', instance_id: 'mysql-analytics-replica', sql: 'ALTER TABLE orders ENGINE=InnoDB, ROW_FORMAT=COMPRESSED;', rollback_sql: 'ALTER TABLE orders ENGINE=InnoDB, ROW_FORMAT=DYNAMIC;', reason: '表碎片率高，重建以回收空间', risk: 'high', status: 'rolled_back', created_by: '陈数据', created_at: '2026-08-28T03:00:00Z', approver: '王审批', approved_at: '2026-08-28T03:15:00Z', executor: '李执行', executing_at: '2026-08-28T03:20:00Z', executed_at: '2026-08-28T03:28:00Z', rolled_back_at: '2026-08-28T04:05:00Z', duration_ms: 480000, affected_rows: 0 }),
    ticketSpec({ id: 'WO-20260828-009', title: '缓存集群评估失效会话键规模', type: 'DML', engine: 'Redis', instance_id: 'redis-session-01', sql: 'EVAL "local keys = redis.call(\'keys\', \'session:*\'); return #keys" 0', rollback_sql: '', reason: '评估失效会话键规模，为淘汰策略做准备', risk: 'high', status: 'pending', created_by: '李执行', created_at: '2026-08-28T02:30:00Z' }),
    ticketSpec({ id: 'WO-20260828-010', title: '用户中心收回临时 DBA 监控权限', type: 'DCL', engine: 'PostgreSQL', instance_id: 'pgsql-user-primary', sql: 'REVOKE pg_monitor FROM temp_dba;', rollback_sql: 'GRANT pg_monitor TO temp_dba;', reason: '紧急运维窗口结束，收回临时监控权限', risk: 'low', status: 'executed', created_by: '王审批', created_at: '2026-08-28T01:40:00Z', approver: '王审批', approved_at: '2026-08-28T01:42:00Z', executor: '李执行', executing_at: '2026-08-28T01:45:00Z', executed_at: '2026-08-28T01:45:05Z', duration_ms: 420, affected_rows: 0 }),
    ticketSpec({ id: 'WO-20260828-011', title: '订单主库订单状态批次修正', type: 'DML', engine: 'MySQL', instance_id: 'mysql-prod-order-01', sql: "UPDATE orders SET order_status = 'shipped' WHERE ship_date < NOW() - INTERVAL 2 DAY AND order_status = 'paid';", rollback_sql: "UPDATE orders SET order_status = 'paid' WHERE order_status = 'shipped';", reason: '物流同步故障后的状态对齐', risk: 'medium', status: 'approved', created_by: '张运维', created_at: '2026-08-27T23:10:00Z', approver: '王审批', approved_at: '2026-08-28T00:05:00Z' }),
  ].map(completeTicket);
}

function ticketSpec(spec) {
  return spec;
}

function completeTicket(spec) {
  const history = [];
  const log = [];
  const push = (status, at, by, note, level = 'info', message) => {
    history.push({ status, at, by, note });
    log.push({ at, level, message: message ?? note });
  };
  const approver = spec.approver ?? '王审批';
  const executor = spec.executor ?? '李执行';
  push('pending', spec.created_at, spec.created_by, '提交变更工单', 'info', '工单已提交');
  if (spec.status === 'approved' || spec.status === 'executing' || spec.status === 'executed' || spec.status === 'rolled_back') {
    push('approved', spec.approved_at, approver, '审批通过', 'info', '工单已批准');
  } else if (spec.status === 'rejected') {
    push('rejected', spec.rejected_at, approver, '审批拒绝：权限范围超出项目要求', 'warn', '工单被拒绝');
  }
  if (spec.status === 'executing' || spec.status === 'executed' || spec.status === 'rolled_back') {
    push('executing', spec.executing_at, executor, '开始执行变更', 'info', '开始执行变更');
  }
  if (spec.status === 'executed' || spec.status === 'rolled_back') {
    push('executed', spec.executed_at, executor, '变更执行完成', 'info', `执行完成，影响 ${spec.affected_rows ?? 0} 行`);
  }
  if (spec.status === 'rolled_back') {
    push('rolled_back', spec.rolled_back_at, executor, '执行回滚变更', 'warn', '变更已回滚');
  }
  if (spec.status === 'failed') {
    push('executing', spec.executing_at, executor, '开始执行变更', 'info', '开始执行变更');
    history.push({ status: 'failed', at: spec.failed_at, by: executor, note: '执行失败：目标实例连接超时' });
    log.push({ at: spec.failed_at, level: 'error', message: '执行失败，已终止' });
  }
  return {
    ...spec,
    approver: spec.approver ?? null,
    executor: spec.executor ?? null,
    log,
    history,
  };
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
  if (status === 401) return workOrderFailure('unauthorized', status);
  if (status === 403) return workOrderFailure('forbidden', status);
  if (status === 404) return workOrderFailure('not-found', status);
  if (status === 409) return workOrderFailure('conflict', status);
  if (status === 400 || status === 413 || status === 415 || status === 422) return workOrderFailure('validation', status);
  return workOrderFailure('unavailable', status);
}

function workOrderFailure(kind, status) {
  const message = WORKORDER_ERRORS[kind] ?? WORKORDER_ERRORS.unavailable;
  return status == null ? { kind, message } : { kind, message, status };
}

if (typeof window !== 'undefined') {
  window.DBPilotWorkOrderApi = { create: createWorkOrderApi };
}
