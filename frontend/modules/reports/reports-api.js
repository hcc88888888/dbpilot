import { createControlPlaneClient } from '../../shared/control-plane-client.js';

const REPORTS_ERRORS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '请求的报告或模板不存在或已无权访问',
  conflict: '报告对象已更新或存在引用冲突，请刷新后重试',
  validation: '请求参数或内容不符合要求，请修改后重试',
  unavailable: '报告服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const REPORT_TYPE_TITLES = { inspection: '巡检', monitoring: '监控', alert: '告警', performance: '性能' };
const REPORT_TYPE_SET = new Set(['inspection', 'monitoring', 'alert', 'performance']);

const DEMO_INSTANCES = {
  'mysql-prod-order-01': '订单主库 MySQL',
  'pgsql-user-primary': '用户中心 PostgreSQL',
  'redis-session-01': '缓存集群 Redis',
  'mysql-analytics-replica': '分析从库 MySQL',
};

/**
 * Create the only frontend boundary for report-center data. A configured base
 * URL selects the real control-plane API; otherwise the adapter supplies
 * explicitly marked, safe local demo data.
 */
export function createReportsApi({ baseUrl = '', fetchImpl = globalThis.fetch, available = true, controlPlaneClient, getAccessToken } = {}) {
  if (!available) return createUnavailableAdapter();
  if (!baseUrl) return createDemoAdapter();
  if (typeof fetchImpl !== 'function') throw reportsFailure('network');

  return createInspectionReportsAdapter(controlPlaneClient ?? createControlPlaneClient({ baseUrl, fetchImpl, getAccessToken }));
}

function createInspectionReportsAdapter(client) {
  const boundary = (scope) => client.forScope(cleanScope(scope));
  const read = async (scope, method, parameters, signal) => {
    const scoped = boundary(scope);
    const options = scoped.requestOptions({ signal });
    try {
      return parameters === undefined
        ? await scoped.inspection[method](options)
        : await scoped.inspection[method](parameters, options);
    } catch (error) {
      if (error?.name === 'AbortError' || error?.kind) throw error;
      throw reportsFailure('network');
    }
  };
  return {
    async getOverview(scope, signal) {
      const response = await read(scope, 'listInspectionReports', { limit: 5 }, signal);
      const items = inspectionReportItems(response).map(mapInspectionReport);
      const ready = items.filter((item) => item.status === 'ready').length;
      const failed = items.filter((item) => item.status === 'failed').length;
      const completed = ready + failed;
      const sampleLimit = Number(response?.page?.limit) || 5;
      const sampleHasMore = response?.page?.hasMore === true || response?.page?.has_more === true;
      return { source: 'control-plane', scope: cleanScope(scope), stats: { recent_loaded_count: items.length, recent_ready_count: ready, recent_sample_success_rate: completed ? Math.round(ready / completed * 1000) / 10 : null, sample_limit: sampleLimit, sample_has_more: sampleHasMore }, recent_reports: items };
    },
    async listReports(scope, filters = {}, signal) {
      if (filters.type && filters.type !== 'inspection') return { source: 'control-plane', scope: cleanScope(scope), items: [], nextCursor: null };
      const parameters = {};
      if (filters.cursor) parameters.cursor = String(filters.cursor);
      if (Number.isInteger(filters.limit)) parameters.limit = filters.limit;
      const response = await read(scope, 'listInspectionReports', parameters, signal);
      return { source: 'control-plane', scope: cleanScope(scope), items: inspectionReportItems(response).map(mapInspectionReport), nextCursor: response?.page?.nextCursor ?? response?.page?.next_cursor ?? null };
    },
    async getReport(scope, id, signal) {
      const value = await read(scope, 'getInspectionReport', { reportId: requiredReportID(id) }, signal);
      return { ...mapInspectionReport(value), source: 'control-plane', scope: cleanScope(scope) };
    },
    async downloadReport(scope, id, format, idempotencyKey, signal) {
      const selectedFormat = String(format ?? '').toLowerCase();
      if (selectedFormat !== 'html' && selectedFormat !== 'json') throw reportsFailure('validation');
      const scoped = boundary(scope);
      return scoped.inspection.createInspectionReportDownload(
        { reportId: requiredReportID(id), idempotencyKey, inspectionReportDownloadRequest: { format: selectedFormat } },
        scoped.requestOptions({ idempotencyKey, signal }),
      );
    },
    async listTemplates(scope) { return { source: 'control-plane', scope: cleanScope(scope), items: [], nextCursor: null }; },
    async generateReport() { throw reportsFailure('unavailable'); },
    async sendReportEmail() { throw reportsFailure('unavailable'); },
    async saveTemplate() { throw reportsFailure('unavailable'); },
    async setTemplateEnabled() { throw reportsFailure('unavailable'); },
  };
}

function createUnavailableAdapter() {
  const unavailable = async () => { throw reportsFailure('unavailable'); };
  return {
    getOverview: unavailable,
    listReports: unavailable,
    getReport: unavailable,
    downloadReport: unavailable,
    generateReport: unavailable,
    sendReportEmail: unavailable,
    listTemplates: unavailable,
    saveTemplate: unavailable,
    setTemplateEnabled: unavailable,
  };
}

function createDemoAdapter() {
  const store = createDemoStore();

  return {
    async getOverview(scope) {
      return normalizeDemoOverview(store, scope);
    },

    async listReports(scope, filters = {}) {
      const page = reportsPage(filters);
      const filtered = filterReportItems(store.reports, filters);
      const items = filtered.slice(page.offset, page.offset + page.limit).map((item) => ({ ...redactDTO(item), source: 'demo' }));
      const nextCursor = page.offset + items.length < filtered.length ? `offset:${page.offset + items.length}` : null;
      return { source: 'demo', scope: cleanScope(scope), items, nextCursor };
    },

    async getReport(scope, id) {
      const report = store.reports.find((item) => item.id === id);
      if (!report) throw reportsFailure('not-found');
      return { ...redactDTO(report), source: 'demo', scope: cleanScope(scope) };
    },

    async downloadReport(scope, id) {
      const report = store.reports.find((item) => item.id === id);
      if (!report) throw reportsFailure('not-found');
      return { source: 'demo', scope: cleanScope(scope), url: `#demo-report-${encodeURIComponent(id)}`, expires_at: new Date(Date.now() + 300000).toISOString() };
    },

    async generateReport(scope, value) {
      const type = String(value?.type ?? '').trim();
      const instance_id = String(value?.instance_id ?? '').trim();
      if (!REPORT_TYPE_SET.has(type) || !instance_id) throw reportsFailure('validation');
      const template_id = String(value?.template_id ?? '').trim();
      const template = store.templates.find((item) => item.id === template_id);
      const now = new Date();
      const id = `RPT-${demoDate(now)}-${String(++store.seed).padStart(3, '0')}`;
      const report = {
        id,
        title: `${REPORT_TYPE_TITLES[type]}报告 · ${DEMO_INSTANCES[instance_id] ?? instance_id}`,
        type,
        status: 'generating',
        instance_id,
        instance_name: DEMO_INSTANCES[instance_id] ?? instance_id,
        created_by: 'demo@dbpilot.local',
        created_at: now.toISOString(),
        generated_at: '',
        format: 'pdf',
        size_kb: 0,
        failure: '',
        highlights: [],
        issues_count: 0,
        template_id: template?.id ?? '',
        email: { recipients: [], sent_at: '' },
      };
      store.reports.unshift(report);
      const timer = setTimeout(() => {
        const current = store.reports.find((item) => item.id === id);
        if (!current) return;
        current.status = 'ready';
        current.generated_at = new Date().toISOString();
        current.size_kb = 240 + Math.floor(Math.random() * 400);
        current.highlights = ['实例整体运行平稳', '指标采集完整', '风险与建议见报告正文'];
        current.issues_count = Math.floor(Math.random() * 3);
      }, 1500);
      if (typeof timer.unref === 'function') timer.unref();
      return { ...redactDTO(report), source: 'demo', scope: cleanScope(scope) };
    },

    async sendReportEmail(scope, id, value) {
      const recipients = emailRecipients(value);
      if (!recipients.length || recipients.some((item) => !VALID_EMAIL_PATTERN.test(item))) throw reportsFailure('validation');
      const report = store.reports.find((item) => item.id === id);
      if (!report) throw reportsFailure('not-found');
      report.email = { recipients, sent_at: new Date().toISOString() };
      report.status = 'sent';
      return { ...redactDTO(report), source: 'demo', scope: cleanScope(scope) };
    },

    async listTemplates(scope) {
      const items = store.templates.map((item) => ({ ...redactDTO(item), source: 'demo' }));
      return { source: 'demo', scope: cleanScope(scope), items, nextCursor: null };
    },

    async saveTemplate(scope, value) {
      const id = String(value?.id ?? '').trim();
      const exists = store.templates.some((item) => item.id === id);
      const nextId = id && exists ? id : `TPL-${String(store.templateSeed++).padStart(3, '0')}`;
      const next = { ...pickTemplateFields(value), id: nextId };
      const index = store.templates.findIndex((item) => item.id === nextId);
      if (index === -1) store.templates.push(next);
      else store.templates[index] = next;
      return { ...redactDTO(next), source: 'demo', scope: cleanScope(scope) };
    },

    async setTemplateEnabled(scope, id, enabled) {
      const template = store.templates.find((item) => item.id === id);
      if (!template) throw reportsFailure('not-found');
      template.enabled = Boolean(enabled);
      return { ...redactDTO(template), source: 'demo', scope: cleanScope(scope) };
    },
  };
}

function createDemoStore() {
  const reports = [
    { id: 'RPT-20260828-001', title: '订单主库巡检报告', type: 'inspection', status: 'ready', instance_id: 'mysql-prod-order-01', instance_name: '订单主库 MySQL', created_by: 'demo@dbpilot.local', created_at: '2026-08-28T08:05:00Z', generated_at: '2026-08-28T08:06:12Z', format: 'pdf', size_kb: 1286, failure: '', highlights: ['实例整体运行平稳', '复制延迟保持在 0.5s 以内', '发现 2 个需要关注的问题'], issues_count: 2, email: { recipients: [], sent_at: '' } },
    { id: 'RPT-20260828-002', title: '用户中心慢查询分析', type: 'performance', status: 'generating', instance_id: 'pgsql-user-primary', instance_name: '用户中心 PostgreSQL', created_by: 'demo@dbpilot.local', created_at: '2026-08-28T09:12:00Z', generated_at: '', format: 'pdf', size_kb: 0, failure: '', highlights: [], issues_count: 0, email: { recipients: [], sent_at: '' } },
    { id: 'RPT-20260827-003', title: '缓存集群连接数监控周报', type: 'monitoring', status: 'sent', instance_id: 'redis-session-01', instance_name: '缓存集群 Redis', created_by: 'demo@dbpilot.local', created_at: '2026-08-27T15:00:00Z', generated_at: '2026-08-27T15:01:30Z', format: 'word', size_kb: 842, failure: '', highlights: ['连接数峰值 1840，处于安全水位', '内存命中率 98.6%'], issues_count: 0, email: { recipients: ['oncall@example.com', 'dba@example.com'], sent_at: '2026-08-27T15:05:00Z' } },
    { id: 'RPT-20260827-004', title: '分析从库磁盘水位巡检', type: 'inspection', status: 'ready', instance_id: 'mysql-analytics-replica', instance_name: '分析从库 MySQL', created_by: 'demo@dbpilot.local', created_at: '2026-08-27T11:30:00Z', generated_at: '2026-08-27T11:31:40Z', format: 'pdf', size_kb: 968, failure: '', highlights: ['磁盘使用率 71%，建议关注增长趋势', '慢查询 3 条，集中在夜间批量任务'], issues_count: 3, email: { recipients: [], sent_at: '' } },
    { id: 'RPT-20260826-005', title: '本周告警汇总', type: 'alert', status: 'sent', instance_id: 'mysql-prod-order-01', instance_name: '订单主库 MySQL', created_by: 'demo@dbpilot.local', created_at: '2026-08-26T20:00:00Z', generated_at: '2026-08-26T20:02:10Z', format: 'pdf', size_kb: 2054, failure: '', highlights: ['本周共触发 12 条告警', '其中 2 条为紧急级别'], issues_count: 12, email: { recipients: ['oncall@example.com'], sent_at: '2026-08-26T20:05:00Z' } },
    { id: 'RPT-20260826-006', title: '订单主库锁等待回放', type: 'performance', status: 'generating', instance_id: 'mysql-prod-order-01', instance_name: '订单主库 MySQL', created_by: 'demo@dbpilot.local', created_at: '2026-08-26T18:45:00Z', generated_at: '', format: 'word', size_kb: 0, failure: '', highlights: [], issues_count: 0, email: { recipients: [], sent_at: '' } },
    { id: 'RPT-20260825-007', title: '用户中心备份完整性检查', type: 'inspection', status: 'failed', instance_id: 'pgsql-user-primary', instance_name: '用户中心 PostgreSQL', created_by: 'demo@dbpilot.local', created_at: '2026-08-25T02:00:00Z', generated_at: '2026-08-25T02:01:00Z', format: 'word', size_kb: 0, failure: '备份文件校验失败：日志缺失', highlights: [], issues_count: 0, email: { recipients: [], sent_at: '' } },
    { id: 'RPT-20260825-008', title: '缓存集群内存命中率监控', type: 'monitoring', status: 'ready', instance_id: 'redis-session-01', instance_name: '缓存集群 Redis', created_by: 'demo@dbpilot.local', created_at: '2026-08-25T10:00:00Z', generated_at: '2026-08-25T10:01:20Z', format: 'pdf', size_kb: 610, failure: '', highlights: ['内存命中率 98.6%', '热点 key 命中集中'], issues_count: 1, email: { recipients: [], sent_at: '' } },
    { id: 'RPT-20260824-009', title: '分析从库复制状态监控', type: 'monitoring', status: 'sent', instance_id: 'mysql-analytics-replica', instance_name: '分析从库 MySQL', created_by: 'demo@dbpilot.local', created_at: '2026-08-24T22:00:00Z', generated_at: '2026-08-24T22:01:00Z', format: 'word', size_kb: 732, failure: '', highlights: ['复制通道运行正常', '延迟均值 0.8s'], issues_count: 0, email: { recipients: ['dba@example.com'], sent_at: '2026-08-24T22:04:00Z' } },
  ];
  const templates = [
    { id: 'TPL-001', name: '标准巡检模板', type: 'inspection', subject: '【DBPilot】{instance} {date} 巡检报告', sections: ['实例概览', '资源使用率', '复制与备份状态', '风险与建议'], enabled: true },
    { id: 'TPL-002', name: '慢查询分析模板', type: 'performance', subject: '【DBPilot】{instance} 慢查询分析', sections: ['慢查询 Top N', '执行计划分析', '优化建议'], enabled: true },
    { id: 'TPL-003', name: '实例监控周报模板', type: 'monitoring', subject: '【DBPilot】{instance} 监控周报 {date}', sections: ['运行概览', '关键指标趋势', '事件与变更'], enabled: true },
    { id: 'TPL-004', name: '告警汇总模板', type: 'alert', subject: '【DBPilot】告警汇总 {date}', sections: ['告警分布', '严重级别统计', '处理状态'], enabled: false },
    { id: 'TPL-005', name: '快速巡检模板', type: 'inspection', subject: '【DBPilot】快速巡检 {instance}', sections: ['实例健康检查', '关键指标'], enabled: true },
  ];
  return { reports, templates, seed: reports.length, templateSeed: templates.length + 1 };
}

function normalizeDemoOverview(store, scope) {
  const reports = store.reports;
  const now = Date.now();
  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const generatedThisWeek = reports.filter((item) => {
    const at = Date.parse(item.created_at);
    return Number.isFinite(at) && now - at <= weekMs;
  }).length;
  const pendingSend = reports.filter((item) => item.status === 'ready').length;
  const finished = reports.filter((item) => item.status === 'ready' || item.status === 'sent' || item.status === 'failed');
  const successRate = finished.length ? Math.round(finished.filter((item) => item.status !== 'failed').length / finished.length * 1000) / 10 : 100;
  const recent = reports.slice().sort(byCreatedDesc).slice(0, 5);
  return {
    source: 'demo',
    scope: cleanScope(scope),
    stats: { generated_this_week: generatedThisWeek, pending_send: pendingSend, template_count: store.templates.length, success_rate: successRate },
    recent_reports: recent.map((item) => ({ ...redactDTO(item), source: 'demo' })),
  };
}

function redactDTO(value) {
  if (Array.isArray(value)) return value.map((item) => redactDTO(item));
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    if (unsafeReportKey(key)) return [];
    return [[key, redactDTO(item)]];
  }));
}

function unsafeReportKey(key) {
  const normalized = String(key).replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalized === 'scope' || normalized === 'audit' || normalized === 'auditdetails') return true;
  return /(secret|token|password|credential|authorization|apikey|privatekey|dsn|connectionstring)/.test(normalized);
}

function filterReportItems(items, filters = {}) {
  const type = String(filters?.type ?? '').trim();
  const status = String(filters?.status ?? '').trim();
  const query = String(filters?.query ?? filters?.search ?? '').trim().toLowerCase();
  return items.filter((item) => {
    if (type && item.type !== type) return false;
    if (status && item.status !== status) return false;
    if (query) {
      const haystack = JSON.stringify({ id: item.id, title: item.title, instance_name: item.instance_name, instance_id: item.instance_id }).toLowerCase();
      if (!haystack.includes(query)) return false;
    }
    return true;
  });
}

function reportsPage(filters) {
  const limit = boundedLimit(filters?.limit ?? 10);
  const cursorOffset = /^offset:(\d+)$/.exec(String(filters?.cursor ?? ''));
  const offset = cursorOffset ? Number(cursorOffset[1]) : Math.max(0, Number(filters?.offset) || 0);
  return { limit, offset };
}

function boundedLimit(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > 100) return 10;
  return number;
}

function pickTemplateFields(value) {
  return pickDTO(value, ['name', 'type', 'subject', 'sections', 'enabled']);
}

function pickDTO(value, fields) {
  if (!value || typeof value !== 'object') return {};
  return Object.fromEntries(fields.filter((field) => value[field] !== undefined).map((field) => [field, value[field]]));
}

function emailRecipients(value) {
  const raw = value?.recipients;
  if (Array.isArray(raw)) return raw.map((item) => String(item ?? '').trim()).filter(Boolean);
  return String(raw ?? '').split(',').map((item) => item.trim()).filter(Boolean);
}

function cleanScope(scope) {
  return {
    tenantId: typeof scope?.tenantId === 'string' ? scope.tenantId.trim() : '',
    projectId: typeof scope?.projectId === 'string' ? scope.projectId.trim() : '',
  };
}

function byCreatedDesc(a, b) {
  return Date.parse(b.created_at ?? '') - Date.parse(a.created_at ?? '');
}

function demoDate(date) {
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${date.getFullYear()}${month}${day}`;
}

const VALID_EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function reportsFailure(kind, status) {
  return status == null ? { kind, message: REPORTS_ERRORS[kind] } : { kind, message: REPORTS_ERRORS[kind], status };
}

function inspectionReportItems(response) {
  if (Array.isArray(response)) return response;
  return Array.isArray(response?.items) ? response.items : [];
}

function mapInspectionReport(value = {}) {
  const id = String(value.id ?? '');
  const runId = String(value.runId ?? value.run_id ?? '');
  const rawStatus = String(value.status ?? '');
  const status = rawStatus === 'completed' ? 'ready' : rawStatus === 'failed' ? 'failed' : 'generating';
  const summary = String(value.summary ?? '');
  const findings = Array.isArray(value.findings) ? value.findings : [];
  const highlights = findings.length ? findings.map((finding) => String(finding.summary ?? '')).filter(Boolean) : summary ? [summary] : [];
  const issues = findings.length
    ? findings.filter((finding) => !['healthy'].includes(String(finding.level ?? ''))).length
    : ['warning', 'critical', 'unsupported', 'missing_data'].reduce((total, level) => total + summaryCount(summary, level), 0);
  const generatedAt = value.generatedAt ?? value.generated_at ?? '';
  const artifacts = Array.isArray(value.artifacts) ? value.artifacts.map((item) => ({ artifact_id: item.artifactId ?? item.artifact_id ?? '', kind: item.kind ?? '' })) : [];
  return {
    id, run_id: runId, title: `主机巡检报告 · ${runId || id}`, type: 'inspection', status,
    instance_id: '', instance_name: '主机巡检目标', created_by: 'inspection-worker', created_at: generatedAt, generated_at: generatedAt,
    format: 'html/json', size_kb: 0, failure: rawStatus === 'failed' ? summary : '', highlights, issues_count: issues,
    inspection_artifact: true, artifacts, findings: redactDTO(findings), source: 'control-plane',
  };
}

function summaryCount(summary, level) {
  const match = new RegExp(`(?:^|\\s)${level}=(\\d+)(?:\\s|$)`).exec(summary);
  return match ? Number(match[1]) : 0;
}

function requiredReportID(value) {
  const id = String(value ?? '').trim();
  if (!id) throw reportsFailure('validation');
  return id;
}

if (typeof window !== 'undefined') {
  window.DBPilotReportsApi = { create: createReportsApi };
}
