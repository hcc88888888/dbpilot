import test from 'node:test';
import assert from 'node:assert/strict';
import { createReportsApi } from '../modules/reports/reports-api.js';
import {
  buildReportFilters,
  createReportsCenter,
  renderReportDetailMarkup,
  renderReportListMarkup,
  reportStatusLabel,
  reportTypeLabel,
  reportsFailureMessage,
  reportsSourceLabel,
  safeText,
  validateEmailList,
  validateReportTemplate,
} from '../modules/reports/reports.js';

test('report type and status labels render Chinese with unknown fallbacks', () => {
  assert.equal(reportTypeLabel('inspection'), '巡检');
  assert.equal(reportTypeLabel('monitoring'), '监控');
  assert.equal(reportTypeLabel('alert'), '告警');
  assert.equal(reportTypeLabel('performance'), '性能');
  assert.equal(reportTypeLabel('unknown'), '未知');

  assert.equal(reportStatusLabel('generating'), '生成中');
  assert.equal(reportStatusLabel('ready'), '待发送');
  assert.equal(reportStatusLabel('failed'), '生成失败');
  assert.equal(reportStatusLabel('sent'), '已发送');
  assert.equal(reportStatusLabel('weird'), '未知');
});

test('safeText escapes markup that could become HTML', () => {
  assert.equal(safeText('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
  assert.equal(safeText(`title & "quoted"`), 'title &amp; &quot;quoted&quot;');
});

test('template validation requires name, subject, and at least one section', () => {
  assert.deepEqual(validateReportTemplate({ name: '', subject: '', sections: [] }), {
    name: '请填写模板名称',
    subject: '请填写邮件主题',
    sections: '至少添加一个章节',
  });
  assert.deepEqual(validateReportTemplate({ name: '巡检', subject: '', sections: [] }), {
    subject: '请填写邮件主题',
    sections: '至少添加一个章节',
  });
});

test('template validation rejects credential patterns in the subject', () => {
  for (const subject of ['连接串 postgres://operator:password@db.example/app', 'password=abc123', '请使用 token 鉴权', '内部 secret 请勿外传']) {
    assert.deepEqual(validateReportTemplate({ name: '巡检', subject, sections: ['实例概览'] }), {
      subject: '主题中不能包含凭据或敏感信息',
    });
  }
});

test('template validation accepts a valid template with sections', () => {
  assert.deepEqual(validateReportTemplate({
    name: '标准巡检模板',
    type: 'inspection',
    subject: '【DBPilot】{instance} {date} 巡检报告',
    sections: ['实例概览', '风险与建议'],
  }), {});
});

test('email list validation accepts valid comma-separated emails', () => {
  assert.equal(validateEmailList('dba@example.com, oncall@example.com'), '');
  assert.equal(validateEmailList(' dba@example.com '), '');
  assert.equal(validateEmailList('dba@example.com'), '');
});

test('email list validation rejects missing at-sign, spaces, and empties', () => {
  assert.match(validateEmailList('dba.example.com'), /包含无效的邮箱/);
  assert.match(validateEmailList('a@b.com, bad address@example.com'), /包含无效的邮箱/);
  assert.equal(validateEmailList('   '), '至少输入一个收件人');
  assert.equal(validateEmailList(''), '至少输入一个收件人');
});

test('report filters drop empty values and keep valid ones', () => {
  assert.deepEqual(buildReportFilters([['type', 'inspection'], ['status', ''], ['query', 'slow']]), { type: 'inspection', query: 'slow' });
  assert.deepEqual(buildReportFilters({ type: '', status: 'ready', query: '  ' }), { status: 'ready' });
  assert.deepEqual(buildReportFilters({ offset: 0, limit: 10, type: 'alert' }), { offset: 0, limit: 10, type: 'alert' });
});

test('report list markup labels demo source and Chinese status and escapes script titles', () => {
  const markup = renderReportListMarkup({
    source: 'demo',
    items: [{
      id: 'RPT-1', title: '<script>alert(1)</script>', type: 'inspection', status: 'ready',
      instance_name: '订单主库 MySQL', format: 'pdf', generated_at: '2026-08-28T08:06:12Z',
    }],
  });
  assert.match(markup, /演示数据/);
  assert.match(markup, /待发送/);
  assert.match(markup, /巡检/);
  assert.match(markup, /订单主库 MySQL/);
  assert.match(markup, /&lt;script&gt;/);
  assert.doesNotMatch(markup, /<script>alert/);
});

test('report list markup hides email actions without manage permission', () => {
  const markup = renderReportListMarkup({
    source: 'control-plane',
    items: [{ id: 'RPT-1', title: '巡检报告', type: 'inspection', status: 'ready', instance_name: '订单主库 MySQL', format: 'pdf', generated_at: '2026-08-28T08:06:12Z' }],
  }, {}, { manage: false });
  assert.doesNotMatch(markup, /data-reports-email/);
  assert.match(markup, /控制面服务/);
});

test('report detail shows highlights, issues count, and sent recipients', () => {
  const markup = renderReportDetailMarkup({
    id: 'RPT-1', title: '订单主库巡检报告', type: 'inspection', status: 'sent',
    instance_name: '订单主库 MySQL', created_by: 'demo@dbpilot.local',
    generated_at: '2026-08-28T08:06:12Z', format: 'pdf', size_kb: 1286,
    highlights: ['实例整体运行平稳', '发现 2 个需要关注的问题'], issues_count: 2,
    email: { recipients: ['oncall@example.com', 'dba@example.com'], sent_at: '2026-08-28T09:00:00Z' },
  });
  assert.match(markup, /实例整体运行平稳/);
  assert.match(markup, /问题数 2/);
  assert.match(markup, /oncall@example\.com/);
  assert.match(markup, /dba@example\.com/);
  assert.match(markup, /已发送/);
});

test('report detail shows a send-email button when distribution is pending and manage is granted', () => {
  const markup = renderReportDetailMarkup({
    id: 'RPT-2', title: '巡检报告', type: 'inspection', status: 'ready',
    instance_name: '订单主库 MySQL', generated_at: '2026-08-28T08:06:12Z', format: 'pdf', size_kb: 500,
    highlights: [], issues_count: 0, email: { recipients: [], sent_at: '' },
  }, { manage: true });
  assert.match(markup, /尚未发送邮件/);
  assert.match(markup, /data-reports-email="RPT-2"/);
});

test('failure messages and source labels never leak error detail', () => {
  assert.equal(reportsSourceLabel('demo'), '演示数据');
  assert.equal(reportsSourceLabel('control-plane'), '控制面服务');
  assert.equal(reportsSourceLabel(null), '来源未确认');
  assert.equal(reportsFailureMessage({ kind: 'forbidden', message: 'password=unsafe' }), '当前账号没有该项目的操作权限');
  assert.equal(reportsFailureMessage({ kind: 'network', message: 'token leaked' }), '无法连接控制面服务，请检查网络后重试');
  assert.equal(reportsFailureMessage({ kind: 'unknown' }, '报告'), '暂时无法加载报告');
});

test('center renders overview markers from a fake scoped api', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const api = {
    async getOverview(scope) {
      assert.deepEqual(scope, { tenantId: 't1', projectId: 'p1' });
      return {
        source: 'demo',
        stats: { generated_this_week: 16, pending_send: 2, template_count: 5, success_rate: 92.3 },
        recent_reports: [{ id: 'RPT-1', title: '订单主库巡检报告', type: 'inspection', status: 'ready', created_at: '2026-08-28T08:06:12Z' }],
      };
    },
  };
  const center = createReportsCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' }, permissions: { manage: true } });
  center.open('overview');
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.match(root.innerHTML, /本周生成/);
  assert.match(root.innerHTML, /rpt-stats/);
  assert.match(root.innerHTML, /订单主库巡检报告/);
  assert.match(root.innerHTML, /演示数据/);
  assert.match(root.innerHTML, /data-reports-generate/);
});

test('forbidden overview keeps a fixed permission message with retry and no demo fallback', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const forbidden = { kind: 'forbidden', message: 'server: 权限不足 password=unsafe' };
  const api = {
    getOverview() { return Promise.reject(forbidden); },
  };
  const center = createReportsCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' }, permissions: { manage: false } });
  center.open('overview');
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.match(root.innerHTML, /当前账号没有该项目的操作权限/);
  assert.match(root.innerHTML, /data-reports-retry/);
  assert.doesNotMatch(root.innerHTML, /password=unsafe/);
  assert.doesNotMatch(root.innerHTML, /演示数据/);
  assert.doesNotMatch(root.innerHTML, /data-reports-generate/);
});

test('scope change aborts the previous load and reloads scoped data', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const calls = [];
  const pending = () => new Promise(() => {});
  const api = {
    getOverview(scope, signal) {
      calls.push({ scope: { ...scope }, signal });
      return pending();
    },
  };
  const center = createReportsCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' } });
  center.open('overview');
  const first = calls[0];
  center.setScope({ tenantId: 't2', projectId: 'p2' });

  assert.equal(first.signal.aborted, true);
  assert.equal(calls.some((call) => call.scope.tenantId === 't2' && call.scope.projectId === 'p2'), true);
});

test('demo adapter provides scoped overview, filtered reports, and templates', async () => {
  const api = createReportsApi();
  const scope = { tenantId: 't1', projectId: 'p1' };
  const overview = await api.getOverview(scope);
  assert.equal(overview.source, 'demo');
  assert.deepEqual(overview.scope, scope);
  assert.equal(overview.stats.template_count, 5);
  assert.equal(overview.recent_reports.length, 5);

  const page = await api.listReports(scope, { type: 'inspection' });
  assert.equal(page.source, 'demo');
  assert.equal(page.items.length > 0, true);
  assert.equal(page.items.every((item) => item.type === 'inspection'), true);

  const templates = await api.listTemplates(scope);
  assert.equal(templates.items.length, 5);
});

test('demo generateReport starts generating and email send marks sent', async () => {
  const api = createReportsApi();
  const scope = { tenantId: 't1', projectId: 'p1' };
  const created = await api.generateReport(scope, { type: 'inspection', instance_id: 'mysql-prod-order-01', template_id: 'TPL-001' });
  assert.equal(created.status, 'generating');
  assert.equal(created.source, 'demo');
  assert.equal(created.instance_name, '订单主库 MySQL');

  const sent = await api.sendReportEmail(scope, 'RPT-20260828-001', { recipients: 'a@example.com,b@example.com' });
  assert.equal(sent.status, 'sent');
  assert.deepEqual(sent.email.recipients, ['a@example.com', 'b@example.com']);
});

test('demo sendReportEmail rejects malformed recipients and missing reports', async () => {
  const api = createReportsApi();
  const scope = { tenantId: 't1', projectId: 'p1' };
  await assert.rejects(api.sendReportEmail(scope, 'RPT-20260828-001', { recipients: 'not-an-email' }), { kind: 'validation' });
  await assert.rejects(api.sendReportEmail(scope, 'RPT-MISSING', { recipients: 'a@example.com' }), { kind: 'not-found' });
});

test('unavailable adapter never issues a request', async () => {
  let calls = 0;
  const api = createReportsApi({ baseUrl: 'https://control.example', available: false, fetchImpl: async () => { calls += 1; } });
  await assert.rejects(api.listReports({ tenantId: 't', projectId: 'p' }), { kind: 'unavailable' });
  assert.equal(calls, 0);
});

test('http adapter maps report routes to scoped control-plane paths', async () => {
  const seen = [];
  const api = createReportsApi({
    baseUrl: 'https://control.example/',
    fetchImpl: async (url) => {
      seen.push(url);
      return new Response(JSON.stringify({ items: [] }));
    },
  });
  const scope = { tenantId: 't1', projectId: 'p1' };
  await api.listReports(scope, { type: 'inspection', status: 'ready', offset: 0, limit: 10 });
  assert.equal(seen[0], 'https://control.example/api/v1/tenants/t1/projects/p1/inspection-reports?limit=10');
});

test('http DTO normalization strips secrets recursively', async () => {
  const api = createReportsApi({
    baseUrl: 'https://control.example',
    fetchImpl: async () => new Response(JSON.stringify({
      items: [{
        id: 'inspection-report-run-1', run_id: 'run-1', status: 'completed', summary: 'healthy=1', generated_at: '2026-08-28T08:06:12Z',
        artifacts: [{ artifact_id: 'inspection-report-run-1.html', kind: 'inspection-report' }],
        password: 'unsafe', connection_string: 'postgres://unsafe', audit: { actor: 'unsafe' },
      }],
      page: { limit: 50, has_more: false },
    })),
  });
  const page = await api.listReports({ tenantId: 't', projectId: 'p' }, {});
  const encoded = JSON.stringify(page);
  assert.equal(encoded.includes('unsafe'), false);
  assert.equal(page.items[0].inspection_artifact, true);
  assert.equal('password' in page.items[0], false);
});

test('configured report center maps real inspection reports through the generated scoped client', async () => {
  const calls = [];
  const options = [];
  const client = {
    forScope(scope) {
      calls.push({ method: 'scope', scope });
      return {
        inspection: {
          listInspectionReports(value, requestOptions) { calls.push({ method: 'list', value, requestOptions }); return Promise.resolve({ items: [{ id: 'inspection-report-run-1', run_id: 'run-1', status: 'completed', summary: 'warning=1', generated_at: '2026-08-29T08:00:00Z', artifacts: [{ artifact_id: 'inspection-report-run-1.html', kind: 'inspection-report' }] }], page: { limit: 10, has_more: false } }); },
          getInspectionReport(value, requestOptions) { calls.push({ method: 'get', value, requestOptions }); return Promise.resolve({ id: value.reportId, run_id: 'run-1', status: 'completed', artifacts: [] }); },
          createInspectionReportDownload(value, requestOptions) { calls.push({ method: 'download', value, requestOptions }); return Promise.resolve({ url: 'https://control.example/download', expires_at: '2026-08-29T08:05:00Z' }); },
        },
        requestOptions(value) { options.push(value); return { options: value }; },
      };
    },
  };
  const api = createReportsApi({ baseUrl: 'https://control.example', controlPlaneClient: client });
  const scope = { tenantId: 'tenant-a', projectId: 'project-a' };
  const signal = new AbortController().signal;
  const page = await api.listReports(scope, { limit: 10 }, signal);
  const detail = await api.getReport(scope, 'inspection-report-run-1', signal);
  const download = await api.downloadReport(scope, 'inspection-report-run-1', 'json', 'download-key', signal);

  assert.equal(page.items[0].inspection_artifact, true);
  assert.equal(page.items[0].format, 'html/json');
  assert.equal(detail.inspection_artifact, true);
  assert.equal(download.url, 'https://control.example/download');
  assert.deepEqual(calls.find((call) => call.method === 'list').value, { limit: 10 });
  assert.deepEqual(calls.find((call) => call.method === 'download').value, { reportId: 'inspection-report-run-1', idempotencyKey: 'download-key', inspectionReportDownloadRequest: { format: 'json' } });
  assert.deepEqual(options.at(-1), { idempotencyKey: 'download-key', signal });
});

test('real inspection report detail removes PDF Word and email actions', () => {
  const markup = renderReportDetailMarkup({
    id: 'inspection-report-run-1', title: '主机巡检报告', type: 'inspection', status: 'ready', format: 'html/json', inspection_artifact: true,
    generated_at: '2026-08-29T08:00:00Z', highlights: ['warning=1'], issues_count: 1,
  }, { manage: true });
  assert.match(markup, /HTML \/ JSON/);
  assert.match(markup, /data-reports-download="inspection-report-run-1" data-reports-format="html"/);
  assert.match(markup, /data-reports-download="inspection-report-run-1" data-reports-format="json"/);
  assert.doesNotMatch(markup, /PDF|Word|data-reports-email|邮件分发/);
});

test('configured inspection report center hides unsupported generation and template workflows', async () => {
  const root = { innerHTML: '', addEventListener() {} };
  const api = { async getOverview() { return { source: 'control-plane', stats: {}, recent_reports: [] }; } };
  const center = createReportsCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' }, permissions: { manage: true } });
  center.open('overview');
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.doesNotMatch(root.innerHTML, /data-reports-view="templates"/);
  assert.doesNotMatch(root.innerHTML, /data-reports-generate/);
  assert.match(root.innerHTML, /HTML \/ JSON/);
});

test('configured report overview exposes bounded recent-sample statistics, never weekly totals', async () => {
  const items = [
    { id: 'r1', run_id: 'run-1', status: 'completed', summary: 'healthy=1', generated_at: '2020-01-01T00:00:00Z', artifacts: [] },
    { id: 'r2', run_id: 'run-2', status: 'completed', summary: 'warning=1', generated_at: '2020-01-02T00:00:00Z', artifacts: [] },
    { id: 'r3', run_id: 'run-3', status: 'failed', summary: 'failed', generated_at: '2020-01-03T00:00:00Z', artifacts: [] },
    { id: 'r4', run_id: 'run-4', status: 'generating', summary: '', generated_at: '2020-01-04T00:00:00Z', artifacts: [] },
    { id: 'r5', run_id: 'run-5', status: 'completed', summary: 'healthy=1', generated_at: '2020-01-05T00:00:00Z', artifacts: [] },
  ];
  const client = { forScope: () => ({ inspection: { listInspectionReports: () => Promise.resolve({ items, page: { limit: 5, hasMore: true, nextCursor: 'more' } }) }, requestOptions: (value) => value }) };
  const api = createReportsApi({ baseUrl: 'https://control.example', controlPlaneClient: client });
  const overview = await api.getOverview({ tenantId: 't', projectId: 'p' });
  assert.deepEqual(overview.stats, { recent_loaded_count: 5, recent_ready_count: 3, recent_sample_success_rate: 75, sample_limit: 5, sample_has_more: true });
  assert.equal('generated_this_week' in overview.stats, false);
  assert.equal('success_rate' in overview.stats, false);

  const root = { innerHTML: '', addEventListener() {} };
  const center = createReportsCenter({ root, api: { async getOverview() { return overview; } }, scope: { tenantId: 't', projectId: 'p' } });
  center.open('overview');
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.match(root.innerHTML, /近期加载/);
  assert.match(root.innerHTML, /近期就绪/);
  assert.match(root.innerHTML, /近期样本成功率/);
  assert.match(root.innerHTML, /仅展示最近 5 条/);
  assert.doesNotMatch(root.innerHTML, /本周生成|生成成功率/);
});
