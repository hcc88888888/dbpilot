const ERROR_MESSAGES = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '请求的对象不存在或已无权访问',
  conflict: '对象已更新或存在引用冲突，请刷新后重试',
  validation: '请求参数或内容不符合要求，请修改后重试',
  unavailable: '服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const DEFAULT_ALERT_LIMIT = 100;

/**
 * Create the only frontend boundary for alert-control-plane data.
 * A configured base URL selects the real control-plane API; otherwise the
 * adapter supplies explicitly marked, safe local demo data.
 */
export function createAlertApi({ baseUrl = '', fetchImpl = globalThis.fetch } = {}) {
  if (!baseUrl) return createDemoAdapter();
  if (typeof fetchImpl !== 'function') throw apiFailure('network');

  const base = baseUrl.replace(/\/+$/, '');
  const request = async (scope, path, init = {}, signal) => {
    const prefix = `/api/v1/tenants/${encodeURIComponent(scope.tenantId)}/projects/${encodeURIComponent(scope.projectId)}`;
    let response;
    try {
      response = await fetchImpl(`${base}${prefix}${path}`, { ...init, signal });
    } catch (error) {
      if (error && ERROR_MESSAGES[error.kind]) throw error;
      throw apiFailure('network');
    }
    if (!response.ok) throw failureForStatus(response.status);
    if (response.status === 204) return undefined;
    try {
      return await response.json();
    } catch {
      throw apiFailure('unavailable', response.status);
    }
  };

  return createHttpAdapter(request);
}

function createHttpAdapter(request) {
  const getList = (path) => async (scope, signal) => normalizeList(await request(scope, path, {}, signal), scope, null);
  const save = (collection) => async (scope, value, signal) => {
    const payload = writePayload(collection, value);
    const id = value?.id;
    const path = id ? `/${collection}/${encodeURIComponent(id)}` : `/${collection}`;
    const method = id ? 'PUT' : 'POST';
    return normalizeEntity(await request(scope, path, jsonRequest(method, payload), signal), scope);
  };

  return {
    async getOverview(scope, signal) {
      return normalizeEntity(await request(scope, '/overview', {}, signal), scope);
    },

    async listAlerts(scope, filters = {}, cursor = null, signal) {
      const page = alertPage(filters, cursor);
      const response = await request(scope, `/alerts${page.query}`, {}, signal);
      return normalizeList(response, scope, page, filters);
    },

    async getAlert(scope, id, signal) {
      return normalizeEntity(await request(scope, `/alerts/${encodeURIComponent(id)}`, {}, signal), scope);
    },

    async acknowledgeAlert(scope, id, disposition, signal) {
      return normalizeEntity(await request(scope, `/alerts/${encodeURIComponent(id)}/acknowledge`, jsonRequest('POST', dispositionPayload(disposition)), signal), scope);
    },

    async resolveAlert(scope, id, disposition, signal) {
      return normalizeEntity(await request(scope, `/alerts/${encodeURIComponent(id)}/resolve`, jsonRequest('POST', dispositionPayload(disposition)), signal), scope);
    },

    listRules: getList('/rules'),
    saveRule: save('rules'),

    async setRuleEnabled(scope, id, enabled, signal) {
      return normalizeEntity(await request(scope, `/rules/${encodeURIComponent(id)}/enable`, jsonRequest('POST', { enabled: Boolean(enabled) }), signal), scope);
    },

    listNotificationPolicies: getList('/notification-policies'),
    saveNotificationPolicy: save('notification-policies'),
    listTemplates: getList('/templates'),
    saveTemplate: save('templates'),
    listSilences: getList('/silences'),
    saveSilence: save('silences'),

    async endSilence(scope, id, signal) {
      await request(scope, `/silences/${encodeURIComponent(id)}`, { method: 'DELETE' }, signal);
      return { source: 'http', scope: cleanScope(scope), id };
    },
  };
}

function createDemoAdapter() {
  const store = {
    alerts: [{ id: 'alert-1', title: '复制延迟过高', state: 'firing', severity: 'critical', last_seen: '2026-08-27T09:30:00Z' }],
    rules: [{ id: 'rule-1', name: '复制延迟', enabled: true, severity: 'critical' }],
    notificationPolicies: [{ id: 'policy-1', name: '值班通知', channel: 'webhook', enabled: true, has_secret: true }],
    templates: [{ id: 'template-1', name: '默认模板', subject: '数据库告警', body: '{{event.id}}' }],
    silences: [{ id: 'silence-1', matchers: { 'label.instance': 'mysql-demo-01' }, reason: '演示维护窗口' }],
  };

  const list = (key) => async (scope) => normalizeList(store[key], scope, null);
  const save = (key, collection, prefix) => async (scope, value) => {
    const payload = writePayload(collection, value);
    const id = value?.id || `${prefix}-${store[key].length + 1}`;
    const index = store[key].findIndex((item) => item.id === id);
    const next = { ...payload, id };
    if (index === -1) store[key].push(next);
    else store[key][index] = next;
    return normalizeEntity(next, scope, 'demo');
  };

  return {
    async getOverview(scope) {
      return normalizeEntity({ events: { firing: store.alerts.length }, evaluator: { healthy: true } }, scope, 'demo');
    },

    async listAlerts(scope, filters = {}, cursor = null) {
      const page = alertPage(filters, cursor);
      const items = filterAlertItems(store.alerts, filters).slice(page.offset, page.offset + page.limit);
      return normalizeList(items, scope, page, {}, 'demo');
    },

    async getAlert(scope, id) {
      const item = store.alerts.find((alert) => alert.id === id);
      if (!item) throw apiFailure('not-found');
      return normalizeEntity({
        ...item,
        deliveries: [{ id: 'delivery-1', status: 'delivered', secret_ref: 'env://DBPILOT_WEBHOOK_TOKEN', body: 'sensitive request body', request: { token: 'unsafe' }, response: { status: 200 } }],
      }, scope, 'demo');
    },

    async acknowledgeAlert(scope, id, disposition) {
      return transitionDemoAlert(store, scope, id, 'acknowledged', disposition);
    },

    async resolveAlert(scope, id, disposition) {
      return transitionDemoAlert(store, scope, id, 'resolved', disposition);
    },

    listRules: list('rules'),
    saveRule: save('rules', 'rules', 'rule'),
    async setRuleEnabled(scope, id, enabled) {
      const rule = store.rules.find((item) => item.id === id);
      if (!rule) throw apiFailure('not-found');
      rule.enabled = Boolean(enabled);
      return normalizeEntity(rule, scope, 'demo');
    },
    listNotificationPolicies: list('notificationPolicies'),
    saveNotificationPolicy: save('notificationPolicies', 'notification-policies', 'policy'),
    listTemplates: list('templates'),
    saveTemplate: save('templates', 'templates', 'template'),
    listSilences: list('silences'),
    saveSilence: save('silences', 'silences', 'silence'),
    async endSilence(scope, id) {
      const index = store.silences.findIndex((item) => item.id === id);
      if (index === -1) throw apiFailure('not-found');
      store.silences.splice(index, 1);
      return { source: 'demo', scope: cleanScope(scope), id };
    },
  };
}

function alertPage(filters, cursor) {
  const limit = boundedLimit(filters?.limit ?? filters?.pageSize ?? DEFAULT_ALERT_LIMIT);
  const offset = parseCursor(cursor);
  const query = [];
  const states = filters?.state ?? filters?.states;
  if (states) {
    const value = Array.isArray(states) ? states.join(',') : states;
    query.push(`state=${encodeURIComponent(value)}`);
  }
  if (filters?.limit != null || filters?.pageSize != null) query.push(`limit=${limit}`);
  if (offset > 0) query.push(`offset=${offset}`);
  return { limit, offset, query: query.length ? `?${query.join('&')}` : '' };
}

function boundedLimit(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > 500) throw apiFailure('validation');
  return number;
}

function parseCursor(cursor) {
  if (cursor == null || cursor === '') return 0;
  const match = /^offset:(\d+)$/.exec(cursor);
  if (!match) throw apiFailure('validation');
  const offset = Number(match[1]);
  if (!Number.isSafeInteger(offset)) throw apiFailure('validation');
  return offset;
}

function normalizeList(response, scope, page, filters = {}, source = 'http') {
  const rawItems = Array.isArray(response) ? response : Array.isArray(response?.items) ? response.items : [];
  const items = filterAlertItems(rawItems, filters).map((item) => safeResource(item, scope));
  const nextCursor = page && rawItems.length === page.limit ? `offset:${page.offset + rawItems.length}` : null;
  return { source, scope: cleanScope(scope), items, nextCursor };
}

function normalizeEntity(response, scope, source = 'http') {
  const resource = safeResource(response, scope);
  return { ...resource, source, scope: cleanScope(scope) };
}

function safeResource(value) {
  return redactDTO(value);
}

function safeDelivery(value) {
  return redactDTO(value, true);
}

function redactDTO(value, inDelivery = false) {
  if (Array.isArray(value)) return value.map((item) => redactDTO(item, inDelivery));
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (isSecretConfigurationMarker(key)) return [['has_secret', Boolean(item)]];
    if (isUnsafeDTOKey(key, inDelivery)) return [];
    if (key === 'deliveries') return [[key, Array.isArray(item) ? item.map(safeDelivery) : []]];
    return [[key, redactDTO(item, inDelivery)]];
  }));
}

function isSecretConfigurationMarker(key) {
  const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase();
  return normalized === 'hassecret' || normalized === 'secretconfigured';
}

function isUnsafeDTOKey(key, inDelivery) {
  const normalized = key.replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalized === 'scope' || normalized === 'audit' || normalized === 'auditdetails') return true;
  if (normalized === 'dsn' || /(secret|token|password|credential|authorization|apikey|privatekey|connectionstring)/.test(normalized)) return true;
  if (!inDelivery) return false;
  return normalized === 'body' || normalized === 'request' || normalized === 'response' || normalized.includes('requestbody') || normalized.includes('responsebody') || normalized.includes('requestpayload');
}

function filterAlertItems(items, filters = {}) {
  if (!filters || typeof filters !== 'object') return items;
  const states = filterValues(filters.state ?? filters.states);
  const severities = filterValues(filters.severity);
  const ruleIDs = filterValues(filters.ruleId ?? filters.rule_id);
  const query = String(filters.query ?? filters.search ?? '').trim().toLowerCase();
  return items.filter((item) => {
    if (states.length && !states.includes(item.state)) return false;
    if (severities.length && !severities.includes(item.severity)) return false;
    if (ruleIDs.length && !ruleIDs.includes(item.rule_id ?? item.ruleId)) return false;
    if (query && !JSON.stringify(item).toLowerCase().includes(query)) return false;
    return true;
  });
}

function filterValues(value) {
  if (value == null || value === '') return [];
  return (Array.isArray(value) ? value : [value]).map(String);
}

function writePayload(collection, value) {
  switch (collection) {
    case 'rules':
      return pickDTO(value, ['name', 'metric', 'aggregation', 'operator', 'threshold', 'evaluation_every', 'lookback_window', 'for', 'missing_data', 'severity', 'notification_policy_ids', 'labels', 'enabled']);
    case 'notification-policies':
      return pickDTO(value, ['name', 'channel', 'target', 'secret_ref', 'template_id', 'severities', 'match_labels', 'window_start_utc', 'window_end_utc', 'enabled']);
    case 'templates':
      return pickDTO(value, ['name', 'subject', 'body']);
    case 'silences':
      return pickDTO(value, ['matchers', 'starts_at', 'ends_at', 'reason']);
    default:
      return {};
  }
}

function pickDTO(value, fields) {
  if (!value || typeof value !== 'object') return {};
  return Object.fromEntries(fields.filter((field) => value[field] !== undefined).map((field) => [field, value[field]]));
}

function dispositionPayload(value) {
  return { category: value?.category ?? '', reason: value?.reason ?? '' };
}

function jsonRequest(method, body) {
  return { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
}

function cleanScope(scope) {
  return { tenantId: scope?.tenantId, projectId: scope?.projectId };
}

function failureForStatus(status) {
  if (status === 401) return apiFailure('unauthorized', status);
  if (status === 403) return apiFailure('forbidden', status);
  if (status === 404) return apiFailure('not-found', status);
  if (status === 409) return apiFailure('conflict', status);
  if (status === 400 || status === 413 || status === 415 || status === 422) return apiFailure('validation', status);
  return apiFailure('unavailable', status);
}

function apiFailure(kind, status) {
  return status == null ? { kind, message: ERROR_MESSAGES[kind] } : { kind, message: ERROR_MESSAGES[kind], status };
}

async function transitionDemoAlert(store, scope, id, state, disposition) {
  const alert = store.alerts.find((item) => item.id === id);
  if (!alert) throw apiFailure('not-found');
  alert.state = state;
  alert.disposition = dispositionPayload(disposition);
  return normalizeEntity(alert, scope, 'demo');
}

if (typeof window !== 'undefined') {
  window.DBPilotAlertApi = { create: createAlertApi };
}
