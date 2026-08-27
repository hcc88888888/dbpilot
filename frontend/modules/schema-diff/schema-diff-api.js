const SCHEMA_DIFF_ERRORS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '对比任务不存在或已无权访问',
  conflict: '对比任务状态已更新，请刷新后重试',
  validation: '对比请求参数不符合要求，请修改后重试',
  unavailable: '结构对比服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const DEFAULT_PAGE_SIZE = 8;
const CURRENT_ACTOR = 'ops-01';

const INSTANCES = {
  'mysql-prod-order-01': { instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL' },
  'pgsql-user-primary': { instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL' },
  'redis-session-01': { instance_id: 'redis-session-01', instance_name: '缓存集群', engine: 'Redis' },
  'mysql-analytics-replica': { instance_id: 'mysql-analytics-replica', instance_name: '分析从库', engine: 'MySQL' },
};

const CREATE_FIELDS = ['title', 'source_instance_id', 'target_instance_id', 'object_types'];
const DIFF_FILTER_FIELDS = ['status', 'search'];

/**
 * Create the only frontend boundary for schema-diff data.
 * A configured base URL selects the real control-plane API; otherwise the
 * adapter supplies explicitly marked, safe local demo data.
 */
export function createSchemaDiffApi({ baseUrl = '', fetchImpl = globalThis.fetch, available = true } = {}) {
  if (!available) return createUnavailableAdapter();
  if (!baseUrl) return createDemoAdapter();
  if (typeof fetchImpl !== 'function') throw schemaDiffFailure('network');

  const base = baseUrl.replace(/\/+$/, '');
  const request = async (scope, path, init = {}, signal) => {
    const safeScope = cleanScope(scope);
    const prefix = `/api/v1/tenants/${encodeURIComponent(safeScope.tenantId)}/projects/${encodeURIComponent(safeScope.projectId)}`;
    let response;
    try {
      response = await fetchImpl(`${base}${prefix}${path}`, { ...init, signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      if (error?.kind && SCHEMA_DIFF_ERRORS[error.kind]) throw error;
      throw schemaDiffFailure('network');
    }
    if (!response.ok) throw failureForStatus(response.status);
    if (response.status === 204) return undefined;
    try {
      return await response.json();
    } catch {
      throw schemaDiffFailure('unavailable', response.status);
    }
  };

  return createHttpAdapter(request);
}

function createHttpAdapter(request) {
  return {
    async getOverview(scope, signal) {
      return normalizeEntity(await request(scope, '/schema-diff/overview', {}, signal), scope, 'http');
    },

    async listDiffs(scope, filters = {}, signal) {
      const page = diffQuery(filters);
      const response = await request(scope, `/schema-diff/diffs${page.query}`, {}, signal);
      return normalizeList(response, scope, 'http', listMeta(response, page));
    },

    async getDiff(scope, id, signal) {
      return normalizeEntity(await request(scope, `/schema-diff/diffs/${encodeURIComponent(String(id))}`, {}, signal), scope, 'http');
    },

    async createDiff(scope, value, signal) {
      return normalizeEntity(await request(scope, '/schema-diff/diffs', jsonRequest('POST', pickDTO(value, CREATE_FIELDS)), signal), scope, 'http');
    },

    async applyDiff(scope, id, signal) {
      return normalizeEntity(await request(scope, `/schema-diff/diffs/${encodeURIComponent(String(id))}/apply`, jsonRequest('POST', {}), signal), scope, 'http');
    },
  };
}

function createUnavailableAdapter() {
  const unavailable = async () => { throw schemaDiffFailure('unavailable'); };
  return {
    getOverview: unavailable,
    listDiffs: unavailable,
    getDiff: unavailable,
    createDiff: unavailable,
    applyDiff: unavailable,
  };
}

function createDemoAdapter() {
  const store = { diffs: buildDemoDiffs() };
  const now = () => new Date().toISOString();

  const findDiff = (id) => {
    const diff = store.diffs.find((item) => item.id === String(id));
    if (!diff) throw schemaDiffFailure('not-found');
    return diff;
  };

  return {
    async getOverview(scope) {
      const diffs = store.diffs;
      const pendingChanges = diffs.reduce((sum, diff) => sum
        + (diff.summary?.added ?? 0)
        + (diff.summary?.removed ?? 0)
        + (diff.summary?.changed ?? 0), 0);
      const recent = [...diffs].sort(byCreatedAtDesc).slice(0, 5);
      const overview = {
        total_diffs: diffs.length,
        pending_changes: pendingChanges,
        synced_diffs: diffs.filter((diff) => diff.synced_at).length,
        recent_at: diffs.length ? recent[0]?.created_at ?? null : null,
        recent,
      };
      return normalizeEntity(overview, scope, 'demo');
    },

    async listDiffs(scope, filters = {}) {
      const filtered = filterDemoDiffs(store.diffs, filters);
      const page = boundedPage(filters.page);
      const pageSize = boundedPageSize(filters.pageSize);
      const total = filtered.length;
      const totalPages = Math.max(1, Math.ceil(total / pageSize));
      const items = [...filtered].sort(byCreatedAtDesc).slice((page - 1) * pageSize, page * pageSize);
      return normalizeList(items, scope, 'demo', { total, page, pageSize, totalPages });
    },

    async getDiff(scope, id) {
      return normalizeEntity(findDiff(id), scope, 'demo');
    },

    async createDiff(scope, value) {
      const input = {
        title: String(value?.title ?? '').trim(),
        source_instance_id: String(value?.source_instance_id ?? '').trim(),
        target_instance_id: String(value?.target_instance_id ?? '').trim(),
        object_types: Array.isArray(value?.object_types) ? value.object_types.map(String) : [],
      };
      const source = INSTANCES[input.source_instance_id];
      const target = INSTANCES[input.target_instance_id];
      if (!input.title || !source || !target || source.instance_id === target.instance_id || !input.object_types.length) {
        throw schemaDiffFailure('validation');
      }
      const at = now();
      const createdBy = String(value?.created_by ?? '').trim() || CURRENT_ACTOR;
      const diff = {
        id: nextDiffID(store.diffs),
        title: input.title,
        source: instanceRef(source),
        target: instanceRef(target),
        created_by: createdBy,
        created_at: at,
        status: 'running',
        summary: { added: 0, removed: 0, changed: 0, identical: 0 },
        objects: [],
        generated_ddl: '',
        synced_at: '',
        history: [{ status: 'running', at, by: createdBy, note: '开始结构对比' }],
      };
      store.diffs.unshift(diff);
      // 模拟约 1 秒的对比耗时：后台将 running 转为 completed。
      const timer = setTimeout(() => completeDemoDiff(diff, input.object_types), 1000);
      if (typeof timer.unref === 'function') timer.unref();
      return normalizeEntity(diff, scope, 'demo');
    },

    async applyDiff(scope, id) {
      const diff = findDiff(id);
      if (diff.status !== 'completed' || diff.synced_at) throw schemaDiffFailure('conflict');
      const at = now();
      diff.synced_at = at;
      diff.history.push({ status: 'synced', at, by: CURRENT_ACTOR, note: '已同步到目标实例' });
      return normalizeEntity(diff, scope, 'demo');
    },
  };
}

function completeDemoDiff(diff, objectTypes) {
  const types = Array.isArray(objectTypes) && objectTypes.length ? objectTypes : Object.keys(DEMO_OBJECT_TEMPLATES);
  const objects = types.flatMap((type) => (DEMO_OBJECT_TEMPLATES[type] ?? []).map((item) => ({ ...item, object_type: type })));
  const summary = { added: 0, removed: 0, changed: 0, identical: 0 };
  objects.forEach((item) => { if (summary[item.status] != null) summary[item.status] += 1; });
  diff.objects = objects;
  diff.summary = summary;
  diff.generated_ddl = demoGeneratedDDL(objects);
  diff.status = 'completed';
  diff.history.push({ status: 'completed', at: new Date().toISOString(), by: CURRENT_ACTOR, note: '结构对比完成' });
}

const DEMO_OBJECT_TEMPLATES = {
  table: [
    { schema: 'orders', name: 'order_items', status: 'changed', changes: ['新增列 refund_amount DECIMAL(10,2)', '列 status 类型 VARCHAR(20) → VARCHAR(32)'] },
    { schema: 'orders', name: 'orders', status: 'identical', changes: [] },
    { schema: 'orders', name: 'refunds', status: 'added', changes: ['目标端新增表'] },
    { schema: 'orders', name: 'legacy_orders', status: 'removed', changes: ['目标端不存在'] },
  ],
  index: [
    { schema: 'orders', name: 'idx_created_at', status: 'added', changes: ['新增索引'] },
    { schema: 'orders', name: 'idx_user_id', status: 'identical', changes: [] },
    { schema: 'orders', name: 'idx_legacy_status', status: 'removed', changes: ['目标端不存在'] },
  ],
  view: [
    { schema: 'analytics', name: 'v_order_summary', status: 'removed', changes: ['目标端不存在'] },
    { schema: 'analytics', name: 'v_order_totals', status: 'changed', changes: ['字段定义变更'] },
  ],
  procedure: [
    { schema: 'orders', name: 'sp_refresh_orders', status: 'identical', changes: [] },
    { schema: 'orders', name: 'sp_archive_orders', status: 'changed', changes: ['参数列表变更'] },
  ],
  function: [
    { schema: 'orders', name: 'fn_order_amount', status: 'identical', changes: [] },
    { schema: 'orders', name: 'fn_discount_rate', status: 'changed', changes: ['返回值类型变更'] },
  ],
  trigger: [
    { schema: 'orders', name: 'trg_after_order_insert', status: 'identical', changes: [] },
    { schema: 'orders', name: 'trg_before_refund', status: 'added', changes: ['新增触发器'] },
  ],
};

function demoGeneratedDDL(objects) {
  const statements = objects.flatMap((item) => {
    if (item.status === 'identical') return [];
    const subject = `${item.schema}.${item.name}`;
    if (item.status === 'removed') return [`DROP ${item.object_type === 'table' ? 'TABLE' : item.object_type.toUpperCase()} ${subject};`];
    const lines = (item.changes ?? []).map((change) => `  ${change}`);
    const keyword = item.object_type === 'table' ? 'TABLE' : item.object_type.toUpperCase();
    return [`ALTER ${keyword} ${subject}`, ...lines];
  });
  return statements.join('\n') || '-- 未生成 DDL';
}

function instanceRef(instance) {
  return { instance_id: instance.instance_id, instance_name: instance.instance_name };
}

function normalizeList(response, scope, source = 'http', meta = {}) {
  const rawItems = Array.isArray(response) ? response : Array.isArray(response?.items) ? response.items : [];
  return {
    source,
    scope: cleanScope(scope),
    items: rawItems.map(redactDTO),
    ...meta,
  };
}

function normalizeEntity(response, scope, source = 'http') {
  const value = response && typeof response === 'object' && response.diff && typeof response.diff === 'object' ? response.diff : response;
  return { ...redactDTO(value), source, scope: cleanScope(scope) };
}

function redactDTO(value) {
  if (Array.isArray(value)) return value.map(redactDTO);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (isUnsafeSchemaDiffKey(key)) return [];
    return [[key, redactDTO(item)]];
  }));
}

function isUnsafeSchemaDiffKey(key) {
  const normalized = String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalized === 'scope' || normalized === 'audit' || normalized === 'auditdetails') return true;
  return /(secret|token|password|credential|authorization|apikey|privatekey|connectionstring|dsn)/.test(normalized);
}

function diffQuery(filters = {}) {
  const query = [];
  for (const key of DIFF_FILTER_FIELDS) {
    const value = filters[key];
    if (value != null && String(value).trim() !== '') query.push(`${key}=${encodeURIComponent(String(value).trim())}`);
  }
  const page = boundedPage(filters.page);
  const pageSize = boundedPageSize(filters.pageSize);
  query.push(`page=${page}`, `page_size=${pageSize}`);
  return { page, pageSize, query: query.length ? `?${query.join('&')}` : '' };
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

function filterDemoDiffs(diffs, filters = {}) {
  const status = String(filters.status ?? '').trim();
  const search = String(filters.search ?? '').trim().toLowerCase();
  return diffs.filter((diff) => {
    if (status && diff.status !== status) return false;
    if (search && !`${diff.title}\n${diff.id}\n${diff.source?.instance_name ?? ''}\n${diff.target?.instance_name ?? ''}`.toLowerCase().includes(search)) return false;
    return true;
  });
}

function byCreatedAtDesc(left, right) {
  return String(right.created_at).localeCompare(String(left.created_at));
}

function nextDiffID(diffs) {
  const today = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  let max = 0;
  diffs.forEach((diff) => {
    const match = /SCD-(\d{8})-(\d{3})$/.exec(String(diff.id ?? ''));
    if (match && match[1] === today) max = Math.max(max, Number(match[2]));
  });
  return `SCD-${today}-${String(max + 1).padStart(3, '0')}`;
}

function buildDemoDiffs() {
  const objects = [
    { object_type: 'table', schema: 'orders', name: 'order_items', status: 'changed', changes: ['新增列 refund_amount DECIMAL(10,2)', '列 status 类型 VARCHAR(20) → VARCHAR(32)'] },
    { object_type: 'index', schema: 'orders', name: 'idx_created_at', status: 'added', changes: ['新增索引'] },
    { object_type: 'view', schema: 'analytics', name: 'v_order_summary', status: 'removed', changes: ['目标端不存在'] },
    { object_type: 'table', schema: 'orders', name: 'orders', status: 'identical', changes: [] },
    { object_type: 'table', schema: 'orders', name: 'refunds', status: 'added', changes: ['目标端新增表'] },
    { object_type: 'index', schema: 'orders', name: 'idx_user_id', status: 'identical', changes: [] },
    { object_type: 'table', schema: 'orders', name: 'payments', status: 'changed', changes: ['列 currency 新增默认值 CNY'] },
    { object_type: 'trigger', schema: 'orders', name: 'trg_after_order_insert', status: 'identical', changes: [] },
    { object_type: 'function', schema: 'orders', name: 'fn_order_amount', status: 'changed', changes: ['返回值精度 DECIMAL(10,2) → DECIMAL(14,2)'] },
  ];
  const generated = demoGeneratedDDL(objects);
  return [
    {
      id: 'SCD-20260828-001',
      title: '订单主库 → 分析从库 结构对比',
      source: instanceRef(INSTANCES['mysql-prod-order-01']),
      target: instanceRef(INSTANCES['mysql-analytics-replica']),
      created_by: '张运维',
      created_at: '2026-08-28T09:02:00Z',
      status: 'completed',
      summary: diffSummary(objects),
      objects,
      generated_ddl: generated,
      synced_at: '2026-08-28T10:00:00Z',
      history: [
        { status: 'running', at: '2026-08-28T09:02:00Z', by: '张运维', note: '开始结构对比' },
        { status: 'completed', at: '2026-08-28T09:03:12Z', by: '张运维', note: '结构对比完成' },
        { status: 'synced', at: '2026-08-28T10:00:00Z', by: '张运维', note: '已同步到目标实例' },
      ],
    },
    {
      id: 'SCD-20260828-002',
      title: '订单主库 → 用户中心 结构对比',
      source: instanceRef(INSTANCES['mysql-prod-order-01']),
      target: instanceRef(INSTANCES['pgsql-user-primary']),
      created_by: '陈数据',
      created_at: '2026-08-28T08:20:00Z',
      status: 'completed',
      summary: { added: 1, removed: 2, changed: 3, identical: 41 },
      objects: [
        { object_type: 'table', schema: 'users', name: 'users', status: 'changed', changes: ['列 phone 新增唯一索引'] },
        { object_type: 'index', schema: 'users', name: 'idx_email', status: 'identical', changes: [] },
        { object_type: 'view', schema: 'public', name: 'v_user_active', status: 'removed', changes: ['目标端不存在'] },
        { object_type: 'procedure', schema: 'public', name: 'sp_user_cleanup', status: 'removed', changes: ['目标端不存在'] },
        { object_type: 'table', schema: 'audit', name: 'audit_login', status: 'added', changes: ['目标端新增表'] },
        { object_type: 'table', schema: 'users', name: 'user_address', status: 'changed', changes: ['列 province 长度 VARCHAR(32) → VARCHAR(64)'] },
        { object_type: 'function', schema: 'public', name: 'fn_user_age', status: 'identical', changes: [] },
        { object_type: 'index', schema: 'users', name: 'idx_created_at', status: 'changed', changes: ['索引列顺序调整'] },
      ],
      generated_ddl: 'ALTER TABLE users.users\n  ADD UNIQUE INDEX uq_phone (phone);\nALTER TABLE users.user_address\n  MODIFY COLUMN province VARCHAR(64);\nALTER TABLE users.users\n  DROP VIEW v_user_active;',
      synced_at: '',
      history: [
        { status: 'running', at: '2026-08-28T08:20:00Z', by: '陈数据', note: '开始结构对比' },
        { status: 'completed', at: '2026-08-28T08:21:05Z', by: '陈数据', note: '结构对比完成' },
      ],
    },
    {
      id: 'SCD-20260828-003',
      title: '用户中心 → 分析从库 结构对比',
      source: instanceRef(INSTANCES['pgsql-user-primary']),
      target: instanceRef(INSTANCES['mysql-analytics-replica']),
      created_by: '李执行',
      created_at: '2026-08-28T07:15:00Z',
      status: 'running',
      summary: { added: 0, removed: 0, changed: 0, identical: 0 },
      objects: [],
      generated_ddl: '',
      synced_at: '',
      history: [
        { status: 'running', at: '2026-08-28T07:15:00Z', by: '李执行', note: '开始结构对比' },
      ],
    },
    {
      id: 'SCD-20260828-004',
      title: '订单主库 → 分析从库 结构对比',
      source: instanceRef(INSTANCES['mysql-prod-order-01']),
      target: instanceRef(INSTANCES['mysql-analytics-replica']),
      created_by: '王审批',
      created_at: '2026-08-28T06:30:00Z',
      status: 'completed',
      summary: { added: 0, removed: 0, changed: 1, identical: 52 },
      objects: [
        { object_type: 'table', schema: 'orders', name: 'orders', status: 'identical', changes: [] },
        { object_type: 'table', schema: 'orders', name: 'order_items', status: 'identical', changes: [] },
        { object_type: 'index', schema: 'orders', name: 'idx_created_at', status: 'identical', changes: [] },
        { object_type: 'table', schema: 'orders', name: 'payments', status: 'changed', changes: ['列 pay_channel 类型 VARCHAR(16) → VARCHAR(24)'] },
        { object_type: 'view', schema: 'analytics', name: 'v_order_summary', status: 'identical', changes: [] },
        { object_type: 'trigger', schema: 'orders', name: 'trg_after_order_insert', status: 'identical', changes: [] },
        { object_type: 'function', schema: 'orders', name: 'fn_order_amount', status: 'identical', changes: [] },
        { object_type: 'index', schema: 'orders', name: 'idx_user_id', status: 'identical', changes: [] },
      ],
      generated_ddl: 'ALTER TABLE orders.payments\n  MODIFY COLUMN pay_channel VARCHAR(24);',
      synced_at: '2026-08-28T06:35:00Z',
      history: [
        { status: 'running', at: '2026-08-28T06:30:00Z', by: '王审批', note: '开始结构对比' },
        { status: 'completed', at: '2026-08-28T06:30:58Z', by: '王审批', note: '结构对比完成' },
        { status: 'synced', at: '2026-08-28T06:35:00Z', by: '王审批', note: '已同步到目标实例' },
      ],
    },
    {
      id: 'SCD-20260828-005',
      title: '分析从库 → 订单主库 结构对比',
      source: instanceRef(INSTANCES['mysql-analytics-replica']),
      target: instanceRef(INSTANCES['mysql-prod-order-01']),
      created_by: '张运维',
      created_at: '2026-08-28T05:00:00Z',
      status: 'completed',
      summary: { added: 3, removed: 0, changed: 2, identical: 60 },
      objects: [
        { object_type: 'table', schema: 'analytics', name: 'orders_daily', status: 'added', changes: ['目标端新增表'] },
        { object_type: 'table', schema: 'analytics', name: 'sales_by_region', status: 'added', changes: ['目标端新增表'] },
        { object_type: 'index', schema: 'analytics', name: 'idx_orders_daily_date', status: 'added', changes: ['新增索引'] },
        { object_type: 'table', schema: 'orders', name: 'orders', status: 'changed', changes: ['列 order_status 类型 VARCHAR(16) → VARCHAR(32)'] },
        { object_type: 'view', schema: 'analytics', name: 'v_order_totals', status: 'changed', changes: ['字段定义变更'] },
        { object_type: 'function', schema: 'analytics', name: 'fn_daily_revenue', status: 'identical', changes: [] },
        { object_type: 'procedure', schema: 'analytics', name: 'sp_refresh_daily', status: 'identical', changes: [] },
        { object_type: 'table', schema: 'analytics', name: 'dims', status: 'identical', changes: [] },
      ],
      generated_ddl: 'CREATE TABLE analytics.orders_daily (\n  dt DATE NOT NULL,\n  amount DECIMAL(14,2)\n);\nCREATE INDEX idx_orders_daily_date ON analytics.orders_daily(dt);\nALTER TABLE orders.orders\n  MODIFY COLUMN order_status VARCHAR(32);',
      synced_at: '',
      history: [
        { status: 'running', at: '2026-08-28T05:00:00Z', by: '张运维', note: '开始结构对比' },
        { status: 'completed', at: '2026-08-28T05:01:20Z', by: '张运维', note: '结构对比完成' },
      ],
    },
    {
      id: 'SCD-20260828-006',
      title: '缓存集群 → 用户中心 结构对比',
      source: instanceRef(INSTANCES['redis-session-01']),
      target: instanceRef(INSTANCES['pgsql-user-primary']),
      created_by: '陈数据',
      created_at: '2026-08-28T03:40:00Z',
      status: 'running',
      summary: { added: 0, removed: 0, changed: 0, identical: 0 },
      objects: [],
      generated_ddl: '',
      synced_at: '',
      history: [
        { status: 'running', at: '2026-08-28T03:40:00Z', by: '陈数据', note: '开始结构对比' },
      ],
    },
  ];
}

function diffSummary(objects) {
  const summary = { added: 0, removed: 0, changed: 0, identical: 0 };
  objects.forEach((item) => { if (summary[item.status] != null) summary[item.status] += 1; });
  return summary;
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
  if (status === 401) return schemaDiffFailure('unauthorized', status);
  if (status === 403) return schemaDiffFailure('forbidden', status);
  if (status === 404) return schemaDiffFailure('not-found', status);
  if (status === 409) return schemaDiffFailure('conflict', status);
  if (status === 400 || status === 413 || status === 415 || status === 422) return schemaDiffFailure('validation', status);
  return schemaDiffFailure('unavailable', status);
}

function schemaDiffFailure(kind, status) {
  const message = SCHEMA_DIFF_ERRORS[kind] ?? SCHEMA_DIFF_ERRORS.unavailable;
  return status == null ? { kind, message } : { kind, message, status };
}

if (typeof window !== 'undefined') {
  window.DBPilotSchemaDiffApi = { create: createSchemaDiffApi };
}
