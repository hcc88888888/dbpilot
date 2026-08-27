const MONITORING_ERRORS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的查看权限',
  'not-found': '请求的监控对象不存在或已无权访问',
  validation: '监控查询范围或参数不符合要求',
  'query-limit': '监控查询结果过大，请缩短时间范围或增大采样步长',
  unavailable: '监控服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const RANGE_FIELDS = ['from', 'to', 'step'];
const INSTANCE_FIELDS = ['engine', 'status', 'limit', 'offset'];
const SERIES_FIELDS = ['instance_id', 'metric', ...RANGE_FIELDS];

export function createMonitoringApi({ baseUrl = '', fetchImpl = globalThis.fetch, available = true } = {}) {
  if (!available) return unavailableAdapter();
  if (!baseUrl) return demoAdapter();
  if (typeof fetchImpl !== 'function') throw monitoringFailure('network');

  const base = baseUrl.replace(/\/+$/, '');
  const request = async (scope, path, query = {}, signal) => {
    const safeScope = monitoringScope(scope);
    const prefix = `/api/v1/tenants/${encodeURIComponent(safeScope.tenantId)}/projects/${encodeURIComponent(safeScope.projectId)}`;
    let response;
    try {
      response = await fetchImpl(`${base}${prefix}${path}${queryString(query)}`, { signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw error;
      if (error?.kind && MONITORING_ERRORS[error.kind]) throw error;
      throw monitoringFailure('network');
    }
    if (!response?.ok) throw failureForStatus(response?.status);
    try {
      return normalizeResponse(await response.json(), safeScope);
    } catch (error) {
      if (error?.kind) throw error;
      throw monitoringFailure('unavailable', response.status);
    }
  };

  return {
    getOverview(scope, query = {}, signal) {
      return request(scope, '/monitoring/overview', pickQuery(query, RANGE_FIELDS), signal);
    },
    listInstances(scope, query = {}, signal) {
      return request(scope, '/monitoring/instances', pickQuery(query, INSTANCE_FIELDS), signal);
    },
    getInstance(scope, id, query = {}, signal) {
      if (id == null || String(id).trim() === '') return Promise.reject(monitoringFailure('validation'));
      return request(scope, `/monitoring/instances/${encodeURIComponent(String(id))}`, pickQuery(query, RANGE_FIELDS), signal);
    },
    getSeries(scope, query = {}, signal) {
      const normalized = { ...query, instance_id: query.instance_id ?? query.instanceId };
      return request(scope, '/monitoring/series', pickQuery(normalized, SERIES_FIELDS), signal);
    },
    getCapabilities(scope, signal) {
      return request(scope, '/monitoring/capabilities', {}, signal);
    },
  };
}

function unavailableAdapter() {
  const unavailable = async () => { throw monitoringFailure('unavailable'); };
  return {
    getOverview: unavailable,
    listInstances: unavailable,
    getInstance: unavailable,
    getSeries: unavailable,
    getCapabilities: unavailable,
  };
}

function demoAdapter() {
  const now = new Date('2026-08-27T10:00:00Z');
  const instances = [
    demoInstance('mysql-demo-01', 'mysql', '8.4.3', 'healthy', now, { 'host.cpu': 34.8, 'db.connections': 128 }),
    demoInstance('postgres-demo-01', 'postgres', '17.5', 'stale', new Date(now - 35 * 60_000), { 'host.cpu': 62.1, 'db.connections': 84 }),
    demoInstance('oracle-demo-01', 'oracle', '19c', 'offline', new Date(now - 3 * 60 * 60_000), { 'host.cpu': null, 'db.connections': null }),
  ];
  const capabilities = [
    { engine: 'mysql', metrics: true, custom_metrics: true, metric_ids: ['host.cpu', 'host.memory', 'db.connections', 'db.qps'] },
    { engine: 'postgres', metrics: true, custom_metrics: true, metric_ids: ['host.cpu', 'host.memory', 'db.connections', 'db.transactions'] },
    { engine: 'oracle', metrics: true, custom_metrics: true, metric_ids: ['host.cpu', 'host.memory', 'db.sessions', 'db.wait_time'] },
  ];

  const envelope = (scope, value) => normalizeResponse({ source: 'demo', ...value }, monitoringScope(scope), 'demo');
  return {
    async getOverview(scope, query = {}) {
      const range = demoRange(query, now);
      return envelope(scope, {
        ...range,
        total_instances: instances.length,
        healthy: 1,
        stale: 1,
        offline: 1,
        instances,
        trend: demoSeries('host.cpu', range.from, range.to, query.step),
      });
    },
    async listInstances(scope, query = {}) {
      const filtered = instances.filter((item) => (!query.engine || item.engine === query.engine) && (!query.status || item.status === query.status));
      const offset = Number(query.offset) || 0;
      const limit = Number(query.limit) || 50;
      const items = filtered.slice(offset, offset + limit);
      return envelope(scope, { items, next_offset: offset + items.length < filtered.length ? offset + items.length : 0 });
    },
    async getInstance(scope, id, query = {}) {
      const instance = instances.find((item) => item.id === id);
      if (!instance) throw monitoringFailure('not-found');
      const range = demoRange(query, now);
      return envelope(scope, { instance, metrics: [demoSeries('host.cpu', range.from, range.to, query.step), demoSeries('db.connections', range.from, range.to, query.step)] });
    },
    async getSeries(scope, query = {}) {
      if (!instances.some((item) => item.id === (query.instanceId ?? query.instance_id))) throw monitoringFailure('not-found');
      const range = demoRange(query, now);
      return envelope(scope, { series: demoSeries(query.metric || 'host.cpu', range.from, range.to, query.step) });
    },
    async getCapabilities(scope) {
      return envelope(scope, { items: capabilities });
    },
  };
}

function demoInstance(id, engine, version, status, lastSampleAt, latest) {
  return {
    id,
    engine,
    version,
    host: `${id}.internal`,
    status,
    last_sample_at: lastSampleAt.toISOString(),
    last_heartbeat_at: status === 'offline' ? lastSampleAt.toISOString() : '2026-08-27T09:59:00.000Z',
    collect_every: 300_000_000_000,
    latest,
  };
}

function demoRange(query, now) {
  const to = validDate(query.to) ?? now;
  const from = validDate(query.from) ?? new Date(to - 60 * 60_000);
  return { from: from.toISOString(), to: to.toISOString() };
}

function demoSeries(name, fromValue, toValue, step = '5m') {
  const from = validDate(fromValue) ?? new Date('2026-08-27T09:00:00Z');
  const to = validDate(toValue) ?? new Date('2026-08-27T10:00:00Z');
  const span = Math.max(1, to - from);
  const buckets = Array.from({ length: 13 }, (_, index) => ({
    at: new Date(from.getTime() + span * index / 12).toISOString(),
    value: index === 4 || index === 9 ? null : Number((32 + Math.sin(index / 2) * 14 + index * 1.3).toFixed(1)),
  }));
  return { name, unit: name === 'host.cpu' ? '%' : '', aggregation: 'avg', from: from.toISOString(), to: to.toISOString(), step, buckets };
}

function normalizeResponse(value, scope, forcedSource) {
  const safe = redactMonitoringDTO(value && typeof value === 'object' ? value : {});
  const source = forcedSource ?? (safe.source === 'demo' ? 'demo' : 'control-plane');
  const result = { ...safe, source, scope: { ...scope } };
  if ('next_offset' in result) result.nextOffset = result.next_offset;
  return result;
}

export function redactMonitoringDTO(value) {
  if (Array.isArray(value)) return value.map(redactMonitoringDTO);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (unsafeMonitoringKey(key)) return [];
    return [[key, redactMonitoringDTO(item)]];
  }));
}

function unsafeMonitoringKey(key) {
  const normalized = String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalized === 'scope' || normalized === 'audit' || normalized === 'auditdetails') return true;
  return /(rawpayload|servererror|errorsummary|secret|token|password|credential|authorization|apikey|privatekey|connectionstring|dsn)/.test(normalized);
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

function monitoringScope(scope) {
  const tenantId = typeof scope?.tenantId === 'string' ? scope.tenantId.trim() : '';
  const projectId = typeof scope?.projectId === 'string' ? scope.projectId.trim() : '';
  if (!tenantId || !projectId) throw monitoringFailure('validation');
  return { tenantId, projectId };
}

function validDate(value) {
  const result = value instanceof Date ? new Date(value) : new Date(value);
  return Number.isFinite(result.getTime()) ? result : null;
}

function failureForStatus(status) {
  if (status === 401) return monitoringFailure('unauthorized', status);
  if (status === 403) return monitoringFailure('forbidden', status);
  if (status === 404) return monitoringFailure('not-found', status);
  if (status === 413) return monitoringFailure('query-limit', status);
  if (status === 400 || status === 415 || status === 422) return monitoringFailure('validation', status);
  return monitoringFailure('unavailable', status);
}

function monitoringFailure(kind, status) {
  const error = new Error(MONITORING_ERRORS[kind] ?? MONITORING_ERRORS.unavailable);
  error.kind = kind;
  if (status != null) error.status = status;
  return error;
}

if (typeof window !== 'undefined') {
  window.DBPilotMonitoringApi = { create: createMonitoringApi };
}
