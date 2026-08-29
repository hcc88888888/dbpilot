import { createControlPlaneClient } from '../../shared/control-plane-client.js';

export function createInspectionApi({ baseUrl = '', available = true, controlPlaneClient, fetchImpl = globalThis.fetch, getAccessToken } = {}) {
  if (!available) return unavailableInspectionApi();
  if (!String(baseUrl).trim()) return demoInspectionApi();
  const client = controlPlaneClient ?? createControlPlaneClient({ baseUrl, fetchImpl, getAccessToken });
  const scoped = (scope) => client.forScope(normalizeScope(scope));
  const read = async (scope, method, parameters, signal) => {
    const boundary = scoped(scope);
    const options = boundary.requestOptions({ signal });
    const value = parameters === undefined
      ? await boundary.inspection[method](options)
      : await boundary.inspection[method](parameters, options);
    return normalize(value, 'control-plane');
  };
  const write = async (scope, method, parameters, { idempotencyKey, etag, signal }) => {
    const boundary = scoped(scope);
    const optionValues = { idempotencyKey, signal, ...(etag === undefined ? {} : { etag }) };
    return normalize(await boundary.inspection[method](parameters, boundary.requestOptions(optionValues)), 'control-plane');
  };
  return {
    getOverview: (scope, signal) => read(scope, 'getInspectionOverview', undefined, signal),
    listItems: (scope, page = {}, signal) => read(scope, 'listInspectionItems', pageParams(page), signal),
    createItem: (scope, value, key, signal) => write(scope, 'createInspectionItem', { idempotencyKey: key, createInspectionItemRequest: inspectionItemRequest(value) }, { idempotencyKey: key, signal }),
    listTargets: (scope, page = {}, signal) => read(scope, 'listInspectionTargets', pageParams(page), signal),
    listPolicies: (scope, page = {}, signal) => read(scope, 'listInspectionPolicies', pageParams(page), signal),
    async getPolicy(scope, id, signal) {
      const boundary = scoped(scope);
      const response = await boundary.inspection.getInspectionPolicyRaw({ policyId: requiredID(id) }, boundary.requestOptions({ signal }));
      const etag = response?.raw?.headers?.get?.('ETag');
      if (!etag) throw Object.assign(new Error('policy ETag unavailable'), { kind: 'unavailable' });
      return { ...normalize(await response.value(), 'control-plane'), etag };
    },
    createPolicy: (scope, value, key, signal) => write(scope, 'createInspectionPolicy', { idempotencyKey: key, createInspectionPolicyRequest: inspectionPolicyRequest(value) }, { idempotencyKey: key, signal }),
    updatePolicy: (scope, id, value, etag, key, signal) => write(scope, 'updateInspectionPolicy', { policyId: requiredID(id), idempotencyKey: key, ifMatch: etag, updateInspectionPolicyRequest: inspectionPolicyRequest(value) }, { idempotencyKey: key, etag, signal }),
    runPolicy: (scope, id, key, signal) => write(scope, 'runInspectionPolicy', { policyId: requiredID(id), idempotencyKey: key }, { idempotencyKey: key, signal }),
    listRuns: (scope, page = {}, signal) => read(scope, 'listInspectionRuns', pageParams(page), signal),
    getRun: (scope, id, signal) => read(scope, 'getInspectionRun', { runId: requiredID(id) }, signal),
    createRun: (scope, value, key, signal) => write(scope, 'createInspectionRun', { idempotencyKey: key, createInspectionRunRequest: inspectionRunRequest(value) }, { idempotencyKey: key, signal }),
    cancelRun: (scope, id, key, signal) => write(scope, 'cancelInspectionRun', { runId: requiredID(id), idempotencyKey: key }, { idempotencyKey: key, signal }),
    retryRun: (scope, id, key, signal) => write(scope, 'retryInspectionRun', { runId: requiredID(id), idempotencyKey: key }, { idempotencyKey: key, signal }),
    listReports: (scope, page = {}, signal) => read(scope, 'listInspectionReports', pageParams(page), signal),
    getReport: (scope, id, signal) => read(scope, 'getInspectionReport', { reportId: requiredID(id) }, signal),
    downloadReport: (scope, id, format, key, signal) => write(scope, 'createInspectionReportDownload', { reportId: requiredID(id), idempotencyKey: key, inspectionReportDownloadRequest: generatedModel({ format: inspectionReportFormat(format) }) }, { idempotencyKey: key, signal }),
  };
}

function unavailableInspectionApi() {
  const unavailable = async () => { throw Object.assign(new Error('inspection unavailable'), { kind: 'unavailable' }); };
  return Object.fromEntries(['getOverview', 'listItems', 'createItem', 'listTargets', 'listPolicies', 'getPolicy', 'createPolicy', 'updatePolicy', 'runPolicy', 'listRuns', 'getRun', 'createRun', 'cancelRun', 'retryRun', 'listReports', 'getReport', 'downloadReport'].map((name) => [name, unavailable]));
}

function demoInspectionApi() {
  const now = '2026-08-29T08:00:00Z';
  const item = { id: 'host.cpu.utilization', version: 1, name: 'CPU utilization', category: 'host', source_type: 'metric', enabled: true };
  const target = { agent_id: 'agent-demo-1', display_name: '演示数据库主机', host: 'db-demo.local', labels: { role: 'database' }, connectivity: 'online', capabilities: ['host.inspect'] };
  const policy = { id: 'policy-demo-1', name: '每日主机巡检', enabled: true, version: 1, target_ids: [target.agent_id], labels: {}, item_versions: [{ item_id: item.id, version: 1 }], target_timeout_seconds: 60, max_concurrency: 1, created_at: now, updated_at: now, etag: '"1"' };
  const run = { id: 'run-demo-1', status: 'partial', target_count: 2, completed_target_count: 1, failed_target_count: 1, created_at: now, report_id: 'report-demo-1', targets: [{ target_id: target.agent_id, agent_id: target.agent_id, status: 'succeeded' }, { target_id: 'agent-demo-2', agent_id: 'agent-demo-2', status: 'failed', error_code: 'missing_data' }], findings: [{ id: 'finding-demo-1', target_id: 'agent-demo-2', item_id: item.id, item_version: 1, level: 'missing_data', summary: '数据缺失', recommendation: '检查 Agent 采集状态' }] };
  const report = { id: 'report-demo-1', run_id: run.id, status: 'completed', summary: 'healthy=1 missing_data=1', generated_at: now, artifacts: [{ artifact_id: 'report-demo-1.html', kind: 'inspection-report' }, { artifact_id: 'report-demo-1.json', kind: 'inspection-report' }], findings: run.findings };
  const page = (items) => ({ source: 'demo', items, page: { limit: 50, has_more: false } });
  return {
    async getOverview() { return { source: 'demo', target_count: 2, online_target_count: 1, finding_level_counts: { healthy: 1, warning: 0, critical: 0, unsupported: 0, missing_data: 1 }, latest_run_status_counts: { partial: 1 } }; },
    async listItems() { return page([item]); }, async listTargets() { return page([target]); }, async listPolicies() { return page([policy]); }, async getPolicy() { return { ...policy, source: 'demo' }; },
    async listRuns() { return page([run]); }, async getRun() { return { ...run, source: 'demo' }; }, async listReports() { return page([report]); }, async getReport() { return { ...report, source: 'demo' }; },
    async createItem() { return { ...item, source: 'demo' }; }, async createPolicy() { return { ...policy, source: 'demo' }; }, async updatePolicy() { return { ...policy, source: 'demo' }; }, async runPolicy() { return { ...run, source: 'demo' }; }, async createRun() { return { ...run, source: 'demo' }; }, async cancelRun() { return { ...run, source: 'demo' }; }, async retryRun() { return { ...run, source: 'demo' }; }, async downloadReport(_scope, _id, format) { return { source: 'demo', url: `#demo-inspection-report-${inspectionReportFormat(format)}`, expires_at: now }; },
  };
}

// Generated request serializers read camelCase model properties and also
// spread enumerable properties. Defining the exact model fields as
// non-enumerable keeps serializer access intact while preventing camelCase
// transport keys from leaking into additionalProperties:false JSON bodies.
function generatedModel(values) {
  const model = {};
  for (const [name, value] of Object.entries(values)) {
    Object.defineProperty(model, name, { value, enumerable: false, writable: false, configurable: false });
  }
  return model;
}

function inspectionPolicyItem(value = {}) {
  return generatedModel({ itemId: value.item_id, version: value.version });
}

function inspectionSchedule(value) {
  if (!value) return undefined;
  return generatedModel({ cron: value.cron, timezone: value.timezone });
}

function inspectionPolicyRequest(value = {}) {
  return generatedModel({
    name: value.name,
    enabled: value.enabled,
    schedule: inspectionSchedule(value.schedule),
    itemVersions: Array.isArray(value.item_versions) ? value.item_versions.map(inspectionPolicyItem) : [],
    targetIds: Array.isArray(value.target_ids) ? [...value.target_ids] : [],
    labels: copyRecord(value.labels),
    targetTimeoutSeconds: value.target_timeout_seconds,
    maxConcurrency: value.max_concurrency,
  });
}

function inspectionMetricRule(value) {
  if (!value) return undefined;
  return generatedModel({
    metricName: value.metric_name,
    labels: copyRecord(value.labels),
    window: value.window,
    aggregation: value.aggregation,
    operator: value.operator,
    warningThreshold: value.warning_threshold,
    criticalThreshold: value.critical_threshold,
  });
}

function inspectionItemRequest(value = {}) {
  return generatedModel({
    name: value.name,
    description: value.description,
    category: value.category,
    scopeType: value.scope_type,
    sourceType: value.source_type,
    requiredCapabilities: Array.isArray(value.required_capabilities) ? [...value.required_capabilities] : undefined,
    metricRule: inspectionMetricRule(value.metric_rule),
    evidenceSelector: value.evidence_selector ? generatedModel({ fields: new Set(value.evidence_selector.fields ?? []) }) : undefined,
    recommendationTemplate: value.recommendation_template,
    documentationUrl: value.documentation_url,
  });
}

function inspectionRunRequest(value = {}) {
  return generatedModel({
    targetIds: Array.isArray(value.target_ids) ? [...value.target_ids] : [],
    itemVersions: Array.isArray(value.item_versions) ? value.item_versions.map(inspectionPolicyItem) : [],
    targetTimeoutSeconds: value.target_timeout_seconds,
    maxConcurrency: value.max_concurrency,
  });
}

function inspectionReportFormat(value) {
  const format = String(value ?? '').trim().toLowerCase();
  if (format !== 'html' && format !== 'json') throw Object.assign(new Error('invalid inspection report format'), { kind: 'validation' });
  return format;
}

function copyRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, String(item)]));
}

function normalize(value, source) {
  const normalized = normalizeValue(value);
  return normalized && typeof normalized === 'object' && !Array.isArray(normalized) ? { ...normalized, source } : normalized;
}
function normalizeValue(value) {
  if (Array.isArray(value)) return value.map((item) => normalizeValue(item));
  if (value instanceof Date) return value.toISOString();
  if (!value || typeof value !== 'object') return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) result[toSnakeCase(key)] = normalizeValue(item);
  return result;
}
function toSnakeCase(value) { return String(value).replace(/[A-Z]/g, (character) => `_${character.toLowerCase()}`); }
function normalizeScope(scope) {
  const tenantId = String(scope?.tenantId ?? '').trim();
  const projectId = String(scope?.projectId ?? '').trim();
  if (!tenantId || !projectId) throw Object.assign(new Error('invalid scope'), { kind: 'validation' });
  return { tenantId, projectId };
}
function pageParams(value) {
  const result = {};
  if (value?.cursor) result.cursor = String(value.cursor);
  if (Number.isInteger(value?.limit)) result.limit = value.limit;
  return result;
}
function requiredID(value) {
  const id = String(value ?? '').trim();
  if (!id) throw Object.assign(new Error('invalid id'), { kind: 'validation' });
  return id;
}

if (typeof window !== 'undefined') window.DBPilotInspectionApi = { create: createInspectionApi };
