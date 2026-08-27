const SQL_WINDOW_ERRORS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '请求的 SQL 对象不存在或已无权访问',
  conflict: 'SQL 会话已失效或存在冲突，请刷新后重试',
  validation: 'SQL 内容不符合执行要求，请修改后重试',
  unavailable: 'SQL 执行服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const MAX_SQL_LENGTH = 20000;
const MAX_HISTORY_ITEMS = 20;
const MAX_HISTORY_LIMIT = 100;
const CREDENTIAL_PATTERN = /(?:\b(?:password|passwd|pwd|token|secret|credential|api[_\s-]?key)\b|connectionstring)/i;

export const DEMO_INSTANCES = [
  { id: 'mysql-prod-order-01', name: '订单主库', engine: 'mysql' },
  { id: 'pgsql-user-primary', name: '用户中心', engine: 'postgres' },
  { id: 'redis-session-01', name: '缓存集群', engine: 'redis' },
  { id: 'mysql-analytics-replica', name: '分析从库', engine: 'mysql' },
];

const DEFAULT_COLUMNS = [
  { name: 'id', type: 'int' },
  { name: 'name', type: 'varchar' },
  { name: 'status', type: 'varchar' },
  { name: 'created_at', type: 'timestamp' },
];

/**
 * Create the only frontend boundary for sql-window execution data.
 * A configured base URL selects the real control-plane API; otherwise the
 * adapter supplies explicitly marked, safe local demo data.
 */
export function createSqlWindowApi({ baseUrl = '', fetchImpl = globalThis.fetch, available = true } = {}) {
  if (!available) return createUnavailableAdapter();
  if (!baseUrl) return createDemoAdapter();
  if (typeof fetchImpl !== 'function') throw sqlWindowFailure('network');

  const base = baseUrl.replace(/\/+$/, '');
  const request = async (scope, path, init = {}, signal) => {
    const safeScope = sqlWindowScope(scope);
    const prefix = `/api/v1/tenants/${encodeURIComponent(safeScope.tenantId)}/projects/${encodeURIComponent(safeScope.projectId)}`;
    let response;
    try {
      response = await fetchImpl(`${base}${prefix}${path}`, { ...init, signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      if (error?.kind && SQL_WINDOW_ERRORS[error.kind]) throw error;
      throw sqlWindowFailure('network');
    }
    if (!response?.ok) throw failureForStatus(response?.status);
    if (response.status === 204) return undefined;
    try {
      return await response.json();
    } catch {
      throw sqlWindowFailure('unavailable', response.status);
    }
  };

  return createHttpAdapter(request);
}

function createHttpAdapter(request) {
  const queryPayload = (value) => {
    const checked = validateSql(value?.sql);
    if (checked.kind !== 'valid') throw sqlWindowFailure('validation');
    return { instance_id: String(value?.instance_id ?? '').trim(), sql: checked.sql };
  };

  return {
    async runQuery(scope, payload = {}, signal) {
      return normalizeEntity(await request(scope, '/sql-window/query', jsonRequest('POST', queryPayload(payload)), signal), scope, 'http');
    },

    async explainQuery(scope, payload = {}, signal) {
      return normalizeEntity(await request(scope, '/sql-window/explain', jsonRequest('POST', queryPayload(payload)), signal), scope, 'http');
    },

    async listHistory(scope, { limit } = {}, signal) {
      const count = boundedLimit(limit ?? MAX_HISTORY_ITEMS);
      const query = `?limit=${encodeURIComponent(count)}`;
      return normalizeList(await request(scope, `/sql-window/history${query}`, {}, signal), scope, 'http');
    },

    async clearHistory(scope, signal) {
      await request(scope, '/sql-window/history', { method: 'DELETE' }, signal);
      return { source: 'http', scope: cleanScope(scope) };
    },
  };
}

function createUnavailableAdapter() {
  const unavailable = async () => { throw sqlWindowFailure('unavailable'); };
  return {
    runQuery: unavailable,
    explainQuery: unavailable,
    listHistory: unavailable,
    clearHistory: unavailable,
  };
}

function createDemoAdapter() {
  const history = [];
  let sequence = 0;

  const envelope = (scope, value) => {
    const resource = redactDTO(value && typeof value === 'object' ? value : {});
    return { ...resource, source: 'demo', scope: cleanScope(scope) };
  };

  return {
    async runQuery(scope, payload = {}) {
      const checked = validateSql(payload?.sql);
      if (checked.kind !== 'valid') throw sqlWindowFailure('validation');
      const instance = resolveInstance(payload?.instance_id);
      const result = simulateRunQuery(instance, checked.sql, ++sequence);
      history.unshift(historyItemFromResult(result));
      if (history.length > MAX_HISTORY_ITEMS) history.length = MAX_HISTORY_ITEMS;
      return envelope(scope, result);
    },

    async explainQuery(scope, payload = {}) {
      const checked = validateSql(payload?.sql);
      if (checked.kind !== 'valid') throw sqlWindowFailure('validation');
      const instance = resolveInstance(payload?.instance_id);
      const plan = simulatePlan(instance, checked.sql, ++sequence);
      history.unshift(historyItemFromPlan(plan));
      if (history.length > MAX_HISTORY_ITEMS) history.length = MAX_HISTORY_ITEMS;
      return envelope(scope, plan);
    },

    async listHistory(scope, { limit } = {}) {
      const count = boundedLimit(limit ?? MAX_HISTORY_ITEMS);
      return envelope(scope, { items: history.slice(0, count) });
    },

    async clearHistory(scope) {
      history.length = 0;
      return { source: 'demo', scope: cleanScope(scope) };
    },
  };
}

function resolveInstance(instanceId) {
  return DEMO_INSTANCES.find((item) => item.id === instanceId) ?? DEMO_INSTANCES[0];
}

function historyItemFromResult(result) {
  return {
    id: result.id,
    sql: result.sql,
    instance_id: result.instance_id,
    engine: result.engine,
    run_at: result.run_at,
    duration_ms: result.duration_ms,
    rows: result.rows,
  };
}

function historyItemFromPlan(plan) {
  return {
    id: plan.id,
    sql: plan.sql,
    instance_id: plan.instance_id,
    engine: plan.engine,
    run_at: plan.run_at,
    duration_ms: plan.duration_ms,
    rows: plan.total_rows,
  };
}

export function validateSql(rawSql) {
  const sql = String(rawSql ?? '').trim();
  if (!sql) return { kind: 'validation', reason: 'SQL 不能为空' };
  if (sql.length > MAX_SQL_LENGTH) return { kind: 'validation', reason: 'SQL 长度不能超过 20000 字符' };
  if (CREDENTIAL_PATTERN.test(sql)) return { kind: 'validation', reason: 'SQL 中不能包含凭据或连接串' };
  return { kind: 'valid', sql };
}

export function detectStatementType(sql) {
  const text = String(sql ?? '').trim();
  if (!text) return 'unknown';
  const lower = text.toLowerCase();
  if (/^explain\b/.test(lower)) return 'explain';
  if (/^show\b/.test(lower)) return 'show';
  if (/^insert\b/.test(lower)) return 'insert';
  if (/^update\b/.test(lower)) return 'update';
  if (/^delete\b/.test(lower)) return 'delete';
  if (/^(alter|create|drop|truncate)\b/.test(lower)) return 'ddl';
  if (/\bselect\b/.test(lower)) return 'select';
  return 'other';
}

export function extractColumns(sql) {
  const text = String(sql ?? '').trim();
  if (!/^select\b/i.test(text)) return null;
  const match = /^\s*select\s+([\s\S]*?)\s+from\s+/i.exec(text);
  if (!match) return null;
  let selectPart = match[1];
  const cut = selectPart.search(/\b(?:where|group\s+by|order\s+by|having|limit|union|offset|fetch)\b/i);
  if (cut >= 0) selectPart = selectPart.slice(0, cut);
  if (/\*/.test(selectPart)) return DEFAULT_COLUMNS.map((column) => ({ ...column }));
  const fields = selectPart.split(',').map((field) => field.trim()).filter(Boolean);
  if (!fields.length) return null;
  return fields.map((field) => {
    const alias = /(?:^|\s)as\s+([A-Za-z_][A-Za-z0-9_$]*)\s*$/i.exec(field) || /\s+([A-Za-z_][A-Za-z0-9_$]*)\s*$/.exec(field);
    const rawName = field.split('.').pop()?.trim() ?? '';
    return { name: alias ? alias[1] : rawName, type: inferColumnType(field) };
  });
}

function inferColumnType(field) {
  const text = String(field ?? '').toLowerCase();
  if (/\b(count|sum|avg|min|max|num|qty|total)\b|\bid\b/.test(text)) return 'int';
  if (/\b(price|amount|rate|score|cost|value)\b/.test(text)) return 'decimal';
  if (/(_at|time|date)/.test(text)) return 'timestamp';
  if (/\b(bool|flag|is_|has_)/.test(text)) return 'boolean';
  return 'varchar';
}

function simulateRunQuery(instance, sql, sequence) {
  const type = detectStatementType(sql);
  const base = {
    id: `qr-${sequence}`,
    instance_id: instance.id,
    instance_name: instance.name,
    engine: instance.engine,
    sql,
    run_at: new Date().toISOString(),
    status: 'success',
    truncated: false,
    warning: '',
  };
  switch (type) {
    case 'select': {
      const columns = extractColumns(sql) ?? [{ name: 'result', type: 'text' }];
      const limit = limitForSql(sql);
      const count = limit ? Math.max(1, Math.min(limit, 3 + Math.floor(Math.random() * 8))) : 3 + Math.floor(Math.random() * 8);
      return { ...base, columns, data: generateRows(columns, count), rows: count, duration_ms: randomDuration() };
    }
    case 'show':
      return { ...base, ...simulateShow(instance, sql) };
    case 'insert':
    case 'update':
    case 'delete': {
      const affected = Math.floor(Math.random() * 100) + 1;
      return { ...base, columns: [{ name: 'affected_rows', type: 'int' }], data: [[affected]], rows: 1, duration_ms: randomDuration() };
    }
    case 'ddl':
      return { ...base, columns: [{ name: 'result', type: 'text' }], data: [['OK']], rows: 1, duration_ms: randomDuration(), warning: '高危语句，演示模式未真正执行' };
    default:
      return { ...base, columns: [{ name: 'result', type: 'text' }], data: [['执行成功']], rows: 1, duration_ms: randomDuration() };
  }
}

function simulateShow(instance, sql) {
  const lower = String(sql).toLowerCase();
  if (/\bshow\s+tables\b/.test(lower)) {
    const tables = ['orders', 'order_items', 'customers', 'products', 'payments', 'inventory', 'users', 'sessions'];
    const columns = [{ name: `Tables_in_${instance.id}`, type: 'varchar' }];
    const data = tables.map((table) => [table]);
    return { columns, data, rows: data.length, duration_ms: randomDuration() };
  }
  if (/\bshow\s+processlist\b/.test(lower)) {
    const columns = [
      { name: 'Id', type: 'int' },
      { name: 'User', type: 'varchar' },
      { name: 'Host', type: 'varchar' },
      { name: 'Command', type: 'varchar' },
      { name: 'Time', type: 'int' },
      { name: 'State', type: 'varchar' },
      { name: 'Info', type: 'text' },
    ];
    const users = ['app_user', 'replica', 'analyst', 'dba'];
    const commands = ['Query', 'Sleep', 'Idle'];
    const states = ['Waiting for table lock', 'Sending data', '', ''];
    const infos = ['SELECT * FROM orders WHERE ...', '', '', 'SHOW PROCESSLIST'];
    const data = Array.from({ length: 4 }, (_, index) => [
      String(Math.floor(Math.random() * 900) + 100),
      users[index % users.length],
      '10.0.0.1',
      commands[index % commands.length],
      String(Math.floor(Math.random() * 120)),
      states[index % states.length],
      infos[index % infos.length],
    ]);
    return { columns, data, rows: data.length, duration_ms: randomDuration() };
  }
  const columns = [{ name: 'Variable_name', type: 'varchar' }, { name: 'Value', type: 'varchar' }];
  const data = [['version', '8.4.3'], ['max_connections', '500'], ['wait_timeout', '28800'], ['innodb_buffer_pool_size', '134217728']];
  return { columns, data, rows: data.length, duration_ms: randomDuration() };
}

function simulatePlan(instance, sql, sequence) {
  const sourceSql = String(sql ?? '').trim().replace(/^\s*explain\b/i, '').trim() || 'SELECT ...';
  const table = extractTableName(sourceSql) ?? 'users';
  const rootType = planRootType(sourceSql);
  const randRows = () => Math.floor(Math.random() * 200000) + 50;
  const randCost = () => Number((Math.random() * 5000).toFixed(2));
  let nextId = 0;
  const make = (type, nodeTable, parent, detail) => ({ id: nextId += 1, parent, type, table: nodeTable, rows: randRows(), cost: randCost(), detail });

  const nodes = [make(rootType, table, null, `${rootType} on ${table}`)];
  const rootId = nodes[0].id;
  nodes.push(make('Seq Scan', table, rootId, `Seq Scan on ${table}`));
  nodes.push(make('Index Scan', `${table}_idx`, rootId, `Index Scan using ${table}_idx`));
  if (rootType !== 'Nested Loop') {
    nodes.push(make('Nested Loop', `${table}_items`, rootId, 'Nested Loop'));
  }
  if (nodes.length < 5) {
    nodes.push(make('Index Scan', `${table}_pk`, nodes[1].id, `Index Scan using ${table}_pk`));
  }

  const totalCost = Number(nodes.reduce((sum, node) => sum + Number(node.cost || 0), 0).toFixed(2));
  const totalRows = nodes.reduce((sum, node) => sum + Number(node.rows || 0), 0);
  return {
    id: `plan-${sequence}`,
    instance_id: instance.id,
    instance_name: instance.name,
    engine: instance.engine,
    sql: sourceSql,
    run_at: new Date().toISOString(),
    duration_ms: randomDuration(),
    total_cost: totalCost,
    total_rows: totalRows,
    nodes,
  };
}

function planRootType(sql) {
  const lower = String(sql ?? '').toLowerCase();
  if (/\bjoin\b/.test(lower)) return 'Hash Join';
  if (/\b(group\s+by|aggregate|count|sum|avg|min|max)\b/.test(lower)) return 'Aggregate';
  if (/\border\s+by\b/.test(lower)) return 'Sort';
  return 'Seq Scan';
}

function extractTableName(sql) {
  const match = /\bfrom\s+([A-Za-z_][A-Za-z0-9_$]*)/i.exec(String(sql ?? ''));
  return match ? match[1] : null;
}

function limitForSql(sql) {
  const match = /limit\s+(\d+)(?:\s*,\s*(\d+))?/i.exec(String(sql ?? ''));
  if (!match) return null;
  return Math.max(1, Math.min(Number(match[2] || match[1]), 100));
}

function generateRows(columns, count) {
  return Array.from({ length: count }, (_, index) => columns.map((column) => demoValue(column.type, index)));
}

function demoValue(type, index) {
  const text = String(type ?? 'text').toLowerCase();
  if (text.includes('bool')) return Math.random() > 0.5 ? 'true' : 'false';
  if (text.includes('int')) return String(Math.floor(Math.random() * 90000) + 1);
  if (text.includes('float') || text.includes('double') || text.includes('decimal') || text.includes('numeric')) return (Math.random() * 1000).toFixed(2);
  if (text.includes('timestamp') || text.includes('date') || text.includes('time')) {
    const date = new Date(Date.now() - Math.floor(Math.random() * 30) * 86400000);
    return date.toISOString().replace('T', ' ').slice(0, 19);
  }
  if (text.includes('json')) return '{"demo":true}';
  return `demo-${index + 1}-${Math.random().toString(36).slice(2, 6)}`;
}

function randomDuration() {
  return Math.floor(Math.random() * 171) + 30;
}

function boundedLimit(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > MAX_HISTORY_LIMIT) throw sqlWindowFailure('validation');
  return number;
}

function normalizeEntity(response, scope, source = 'http') {
  const resource = redactDTO(response && typeof response === 'object' ? response : {});
  return { ...resource, source, scope: cleanScope(scope) };
}

function normalizeList(response, scope, source = 'http') {
  const rawItems = Array.isArray(response) ? response : Array.isArray(response?.items) ? response.items : [];
  const items = rawItems.map((item) => redactDTO(item));
  return { source, scope: cleanScope(scope), items };
}

export function redactSqlWindowDTO(value) {
  if (Array.isArray(value)) return value.map(redactSqlWindowDTO);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (unsafeDTOKey(key)) return [];
    return [[key, redactSqlWindowDTO(item)]];
  }));
}

const redactDTO = redactSqlWindowDTO;

function unsafeDTOKey(key) {
  const normalized = String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalized === 'scope' || normalized === 'audit' || normalized === 'auditdetails') return true;
  return /(dsn|secret|token|password|credential|authorization|apikey|privatekey|connectionstring)/.test(normalized);
}

function jsonRequest(method, body) {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

function sqlWindowScope(scope) {
  const tenantId = typeof scope?.tenantId === 'string' ? scope.tenantId.trim() : '';
  const projectId = typeof scope?.projectId === 'string' ? scope.projectId.trim() : '';
  if (!tenantId || !projectId) throw sqlWindowFailure('validation');
  return { tenantId, projectId };
}

function cleanScope(scope) {
  return { tenantId: scope?.tenantId, projectId: scope?.projectId };
}

function failureForStatus(status) {
  if (status === 401) return sqlWindowFailure('unauthorized', status);
  if (status === 403) return sqlWindowFailure('forbidden', status);
  if (status === 404) return sqlWindowFailure('not-found', status);
  if (status === 409) return sqlWindowFailure('conflict', status);
  if (status === 400 || status === 413 || status === 415 || status === 422) return sqlWindowFailure('validation', status);
  return sqlWindowFailure('unavailable', status);
}

function sqlWindowFailure(kind, status) {
  const error = new Error(SQL_WINDOW_ERRORS[kind] ?? SQL_WINDOW_ERRORS.unavailable);
  error.kind = kind;
  if (status != null) error.status = status;
  return error;
}

if (typeof window !== 'undefined') {
  window.DBPilotSqlWindowApi = { create: createSqlWindowApi };
}
