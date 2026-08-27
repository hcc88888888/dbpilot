const AUDIT_ERRORS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '请求的审计记录不存在或已无权访问',
  conflict: '审计记录已更新或存在引用冲突，请刷新后重试',
  validation: '审计查询参数不符合要求，请修改后重试',
  unavailable: '审计服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const AUDIT_LIST_FIELDS = ['action', 'result', 'instance_id', 'actor', 'query', 'from', 'to', 'offset', 'limit'];
const DEMO_LIMIT = 15;
const MAX_LIMIT = 500;
const DEMO_TODAY = '2026-08-28T10:00:00Z';

/**
 * Create the only frontend boundary for audit-log data.
 * A configured base URL selects the real control-plane API; otherwise the
 * adapter supplies explicitly marked, safe local demo data.
 */
export function createAuditApi({ baseUrl = '', fetchImpl = globalThis.fetch, available = true } = {}) {
  if (!available) return createUnavailableAdapter();
  if (!baseUrl) return createDemoAdapter();
  if (typeof fetchImpl !== 'function') throw auditFailure('network');

  const base = baseUrl.replace(/\/+$/, '');
  const request = async (scope, path, query = {}, signal) => {
    const safeScope = auditScope(scope);
    const prefix = `/api/v1/tenants/${encodeURIComponent(safeScope.tenantId)}/projects/${encodeURIComponent(safeScope.projectId)}`;
    let response;
    try {
      response = await fetchImpl(`${base}${prefix}${path}${queryString(query)}`, { signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      if (error?.kind && AUDIT_ERRORS[error.kind]) throw error;
      throw auditFailure('network');
    }
    if (!response?.ok) throw failureForStatus(response?.status);
    try {
      return normalizeResponse(await response.json(), safeScope);
    } catch (error) {
      if (error?.kind) throw error;
      throw auditFailure('unavailable', response.status);
    }
  };

  return {
    getOverview(scope, signal) {
      return request(scope, '/audit/overview', {}, signal);
    },
    listEntries(scope, filters = {}, signal) {
      return request(scope, '/audit/entries', pickQuery(filters, AUDIT_LIST_FIELDS), signal);
    },
    getEntry(scope, id, signal) {
      if (id == null || String(id).trim() === '') return Promise.reject(auditFailure('validation'));
      return request(scope, `/audit/entries/${encodeURIComponent(String(id))}`, {}, signal);
    },
  };
}

function createUnavailableAdapter() {
  const unavailable = async () => { throw auditFailure('unavailable'); };
  return {
    getOverview: unavailable,
    listEntries: unavailable,
    getEntry: unavailable,
  };
}

function createDemoAdapter() {
  const entries = buildDemoEntries();
  return {
    async getOverview(scope) {
      const today = demoTodayEntries(entries);
      const instanceIds = new Set(today.map((item) => item.instance_id).filter(Boolean));
      const actors = new Set(today.map((item) => item.actor));
      const sorted = [...today].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
      const instances = [...new Map(
        today.filter((item) => item.instance_id).map((item) => [item.instance_id, { id: item.instance_id, name: item.instance_name || item.instance_id }]),
      ).values()];
      return envelope(scope, {
        today_operations: today.length,
        failed_denied: today.filter((item) => item.result !== 'success').length,
        instance_count: instanceIds.size,
        actor_count: actors.size,
        instances,
        distribution: aggregateByAction(today),
        recent: sorted.slice(0, 6),
      });
    },

    async listEntries(scope, filters = {}) {
      const filtered = filterDemoEntries(entries, filters);
      const limit = clampLimit(filters.limit);
      const offset = clampOffset(filters.offset);
      const items = filtered.slice(offset, offset + limit);
      return envelope(scope, { items, total: filtered.length, offset, limit });
    },

    async getEntry(scope, id) {
      const item = entries.find((entry) => entry.id === id);
      if (!item) throw auditFailure('not-found');
      return envelope(scope, { entry: item });
    },
  };
}

function buildDemoEntries() {
  return [
    demoEntry('AUD-20260828-001', '2026-08-28T08:02:00Z', 'chris.peng', 'user', 'login', 'console', 'console', '运维控制台', '', '', 'success', '', '10.24.1.88', 'Web Console', { method: 'password', session_id: 'sess-a1b2' }),
    demoEntry('AUD-20260828-002', '2026-08-28T08:15:00Z', 'chris.peng', 'user', 'query', 'instance', 'mysql-demo-01', '订单主库', 'mysql-demo-01', '订单主库', 'success', '', '10.24.1.88', 'Web Console', { sql: 'SELECT * FROM orders WHERE user_id = ? LIMIT 20', rows: 12, duration_ms: 34 }),
    demoEntry('AUD-20260828-003', '2026-08-28T08:18:00Z', 'lin.yao', 'user', 'query', 'instance', 'mysql-demo-01', '订单主库', 'mysql-demo-01', '订单主库', 'denied', '命中敏感表脱敏策略，已阻断查询', '10.24.1.92', 'CLI', { sql: 'SELECT id_card FROM customers WHERE id = ?', policy: 'sensitive-columns' }),
    demoEntry('AUD-20260828-004', '2026-08-28T08:24:00Z', 'zhao.qi', 'user', 'dml', 'instance', 'mysql-demo-01', '订单主库', 'mysql-demo-01', '订单主库', 'success', '', '10.24.1.96', 'Web Console', { sql: 'UPDATE orders SET status = ? WHERE id = ?', rows: 2, duration_ms: 18 }),
    demoEntry('AUD-20260828-005', '2026-08-28T08:31:00Z', 'chen.chen', 'user', 'ddl', 'instance', 'mysql-demo-01', '订单主库', 'mysql-demo-01', '订单主库', 'success', '', '10.24.1.77', 'CLI', { sql: 'ALTER TABLE orders ADD INDEX idx_created_at (created_at)', duration_ms: 320 }),
    demoEntry('AUD-20260828-006', '2026-08-28T08:40:00Z', 'wang.fang', 'user', 'grant', 'account', 'acc-report-bot', '报表服务账号', 'mysql-demo-01', '订单主库', 'success', '', '10.24.1.105', 'Web Console', { principal: 'report_bot', role: 'readonly', database: 'orders' }),
    demoEntry('AUD-20260828-007', '2026-08-28T08:42:00Z', 'wang.fang', 'user', 'revoke', 'account', 'acc-legacy-app', '遗留应用账号', 'mysql-demo-01', '订单主库', 'success', '', '10.24.1.105', 'Web Console', { principal: 'legacy_app', role: 'readwrite', database: 'orders' }),
    demoEntry('AUD-20260828-008', '2026-08-28T08:47:00Z', 'liu.feng', 'user', 'export', 'report', 'rpt-daily-sales', '日销售报表', 'postgres-demo-01', '用户中心', 'success', '', '10.24.1.118', 'Web Console', { format: 'csv', rows: 1024, recipients: ['ops@example.com'] }),
    demoEntry('AUD-20260828-009', '2026-08-28T08:50:00Z', 'schedule-bot', 'system', 'backup', 'instance', 'mysql-demo-01', '订单主库', 'mysql-demo-01', '订单主库', 'success', '', '10.24.1.20', 'DBPilot Agent', { method: 'physical', retention_days: 30, size_mb: 5120 }),
    demoEntry('AUD-20260828-010', '2026-08-28T08:53:00Z', 'schedule-bot', 'system', 'restore', 'instance', 'postgres-demo-01', '用户中心', 'postgres-demo-01', '用户中心', 'failed', '备份文件校验失败，已终止恢复', '10.24.1.20', 'DBPilot Agent', { backup_id: 'bk-20260828-0900', target_instance: 'postgres-demo-01', attempt: 2 }),
    demoEntry('AUD-20260828-011', '2026-08-28T08:55:00Z', 'chris.peng', 'user', 'config', 'policy', 'pol-query-timeout', '查询超时策略', '', '', 'success', '', '10.24.1.88', 'Web Console', { setting: 'query_timeout_seconds', from: 30, to: 60 }),
    demoEntry('AUD-20260828-012', '2026-08-28T08:58:00Z', 'zhao.qi', 'user', 'alert.ack', 'rule', 'rule-repl-delay', '复制延迟规则', 'mysql-demo-01', '订单主库', 'success', '', '10.24.1.96', 'Web Console', { alert_id: 'alert-20260828-01', note: '值班已接管' }),
    demoEntry('AUD-20260828-013', '2026-08-28T09:02:00Z', 'dbpilot-agent', 'agent', 'alert.resolve', 'rule', 'rule-repl-delay', '复制延迟规则', 'mysql-demo-01', '订单主库', 'success', '', '10.24.1.20', 'DBPilot Agent', { alert_id: 'alert-20260828-01', auto: true, latency_recovered_ms: 126000 }),
    demoEntry('AUD-20260828-014', '2026-08-28T09:05:00Z', 'sun.yang', 'user', 'ticket.approve', 'ticket', 'tck-20260828-03', '订单库索引变更工单', 'mysql-demo-01', '订单主库', 'success', '', '10.24.1.130', 'Web Console', { ticket_id: 'TCK-20260828-03', sql: 'ALTER TABLE orders ADD INDEX ...', instance: 'mysql-demo-01' }),
    demoEntry('AUD-20260828-015', '2026-08-28T09:08:00Z', 'chen.chen', 'user', 'dcl', 'instance', 'mysql-prod-order-01', '生产订单主库', 'mysql-prod-order-01', '生产订单主库', 'denied', '当前账号无权变更生产库权限', '10.24.1.77', 'CLI', { role: 'superuser', database: 'orders' }),
    demoEntry('AUD-20260828-016', '2026-08-28T09:12:00Z', 'lin.yao', 'user', 'logout', 'console', 'console', '运维控制台', '', '', 'success', '', '10.24.1.92', 'Web Console', { session_id: 'sess-b3c4' }),
    demoEntry('AUD-20260828-017', '2026-08-28T09:16:00Z', 'chris.peng', 'user', 'query', 'instance', 'postgres-demo-01', '用户中心', 'postgres-demo-01', '用户中心', 'failed', 'SQL 语法错误', '10.24.1.88', 'CLI', { sql: 'SELECT * FRM users', error: 'syntax error' }),
    demoEntry('AUD-20260828-018', '2026-08-28T09:20:00Z', 'schedule-bot', 'system', 'restore', 'instance', 'postgres-demo-01', '用户中心', 'postgres-demo-01', '用户中心', 'denied', '恢复目标实例仍处于运行状态', '10.24.1.20', 'DBPilot Agent', { backup_id: 'bk-20260828-0900', target_instance: 'postgres-demo-01' }),
  ];
}

function demoEntry(id, at, actor, actorType, action, resourceType, resourceId, resourceName, instanceId, instanceName, result, reason, sourceIp, client, detail) {
  return {
    id, at, actor, actor_type: actorType, action, resource_type: resourceType, resource_id: resourceId,
    resource_name: resourceName, instance_id: instanceId, instance_name: instanceName,
    result, reason, source_ip: sourceIp, client, detail,
  };
}

function demoTodayEntries(entries) {
  const now = new Date(DEMO_TODAY);
  const start = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 0, 0, 0, 0).getTime();
  const end = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999).getTime();
  return entries.filter((item) => {
    const at = Date.parse(item.at);
    return at >= start && at <= end;
  });
}

function aggregateByAction(items) {
  const counts = new Map();
  for (const item of items) {
    counts.set(item.action, (counts.get(item.action) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count);
}

function filterDemoEntries(items, filters = {}) {
  if (!filters || typeof filters !== 'object') return items;
  const action = String(filters.action ?? '').trim();
  const result = String(filters.result ?? '').trim();
  const instanceId = String(filters.instance_id ?? '').trim();
  const actor = String(filters.actor ?? '').trim().toLowerCase();
  const query = String(filters.query ?? '').trim().toLowerCase();
  const from = validDate(filters.from);
  const to = validDate(filters.to);
  return items.filter((item) => {
    if (action && item.action !== action) return false;
    if (result && item.result !== result) return false;
    if (instanceId && item.instance_id !== instanceId) return false;
    if (actor && !String(item.actor).toLowerCase().includes(actor)) return false;
    if (query && !JSON.stringify(item).toLowerCase().includes(query)) return false;
    if (from && Date.parse(item.at) < from.getTime()) return false;
    if (to && Date.parse(item.at) > to.getTime()) return false;
    return true;
  });
}

function clampLimit(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1) return DEMO_LIMIT;
  return Math.min(number, MAX_LIMIT);
}

function clampOffset(value) {
  const number = Number(value);
  return Number.isInteger(number) && number >= 0 ? number : 0;
}

function validDate(value) {
  if (value == null || value === '') return null;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date : null;
}

function envelope(scope, value) {
  return normalizeResponse({ source: 'demo', ...value }, auditScope(scope), 'demo');
}

function normalizeResponse(value, scope, forcedSource) {
  const safe = redactAuditDTO(value && typeof value === 'object' ? value : {});
  const source = forcedSource ?? (safe.source === 'demo' ? 'demo' : 'control-plane');
  return { ...safe, source, scope: { ...scope } };
}

export function redactAuditDTO(value) {
  if (Array.isArray(value)) return value.map(redactAuditDTO);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (unsafeAuditKey(key)) return [];
    return [[key, redactAuditDTO(item)]];
  }));
}

function unsafeAuditKey(key) {
  const normalized = String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalized === 'scope' || normalized === 'audit' || normalized === 'auditdetails') return true;
  return /(secret|token|password|credential|authorization|apikey|privatekey|dsn|connectionstring)/.test(normalized);
}

function pickQuery(value, fields) {
  if (!value || typeof value !== 'object') return {};
  return Object.fromEntries(fields.flatMap((field) => {
    const item = value[field];
    return item === undefined || item === null || item === '' ? [] : [[field, item]];
  }));
}

function queryString(query) {
  const entries = Object.entries(query);
  if (!entries.length) return '';
  return `?${entries.map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`).join('&')}`;
}

function auditScope(scope) {
  const tenantId = typeof scope?.tenantId === 'string' ? scope.tenantId.trim() : '';
  const projectId = typeof scope?.projectId === 'string' ? scope.projectId.trim() : '';
  if (!tenantId || !projectId) throw auditFailure('validation');
  return { tenantId, projectId };
}

function failureForStatus(status) {
  if (status === 401) return auditFailure('unauthorized', status);
  if (status === 403) return auditFailure('forbidden', status);
  if (status === 404) return auditFailure('not-found', status);
  if (status === 409) return auditFailure('conflict', status);
  if (status === 400 || status === 413 || status === 415 || status === 422) return auditFailure('validation', status);
  return auditFailure('unavailable', status);
}

function auditFailure(kind, status) {
  const error = new Error(AUDIT_ERRORS[kind] ?? AUDIT_ERRORS.unavailable);
  error.kind = kind;
  if (status != null) error.status = status;
  return error;
}

if (typeof window !== 'undefined') {
  window.DBPilotAuditApi = { create: createAuditApi };
}
