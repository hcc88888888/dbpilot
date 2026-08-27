const REPORT_TYPE_LABELS = { inspection: '巡检', monitoring: '监控', alert: '告警', performance: '性能' };
const REPORT_STATUS_LABELS = { generating: '生成中', ready: '待发送', failed: '生成失败', sent: '已发送' };
const REPORT_VIEWS = ['overview', 'reports', 'report-detail', 'templates'];
const REPORT_PAGE_SIZE = 10;

const REPORT_INSTANCES = [
  { id: 'mysql-prod-order-01', name: 'mysql-prod-order-01 订单主库 MySQL' },
  { id: 'pgsql-user-primary', name: 'pgsql-user-primary 用户中心 PostgreSQL' },
  { id: 'redis-session-01', name: 'redis-session-01 缓存集群 Redis' },
  { id: 'mysql-analytics-replica', name: 'mysql-analytics-replica 分析从库 MySQL' },
];

const SENSITIVE_REPORT_PATTERN = /(?:\b(?:password|passwd|pwd|token|secret|authorization|credential|api[_\s-]?key|access[_\s-]?key|client[_\s-]?secret)\b|\b[a-z][a-z0-9+.-]*:\/\/[^\s/@:]+(?::[^\s/@]*)?@[^\s/]+)/i;
const VALID_EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function reportTypeLabel(value) {
  return REPORT_TYPE_LABELS[value] ?? '未知';
}

export function reportStatusLabel(value) {
  return REPORT_STATUS_LABELS[value] ?? '未知';
}

export function reportsSourceLabel(source) {
  if (source === 'demo') return '演示数据';
  if (source === 'control-plane') return '控制面服务';
  return '来源未确认';
}

export function reportsFailureMessage(error, subject = '报告') {
  if (error?.kind === 'forbidden') return '当前账号没有该项目的操作权限';
  if (error?.kind === 'unauthorized') return '登录状态已失效，请重新登录';
  if (error?.kind === 'not-found') return '请求的报告或模板不存在或已无权访问';
  if (error?.kind === 'validation') return '请求参数或内容不符合要求，请修改后重试';
  if (error?.kind === 'network') return '无法连接控制面服务，请检查网络后重试';
  return `暂时无法加载${subject}`;
}

export function buildReportFilters(entries) {
  const source = entries instanceof Map
    ? entries
    : Array.isArray(entries)
      ? new Map(entries)
      : new Map(Object.entries(entries ?? {}));
  return Object.fromEntries([...source].filter(([, value]) => String(value ?? '').trim() !== ''));
}

export function validateReportTemplate(input = {}) {
  const errors = {};
  if (!String(input.name ?? '').trim()) errors.name = '请填写模板名称';
  const subject = String(input.subject ?? '').trim();
  if (!subject) errors.subject = '请填写邮件主题';
  else if (SENSITIVE_REPORT_PATTERN.test(subject)) errors.subject = '主题中不能包含凭据或敏感信息';
  const sections = Array.isArray(input.sections)
    ? input.sections.map((item) => String(item ?? '').trim()).filter(Boolean)
    : String(input.sections ?? '').split('\n').map((item) => item.trim()).filter(Boolean);
  if (!sections.length) errors.sections = '至少添加一个章节';
  return errors;
}

export function validateEmailList(input) {
  const text = String(input ?? '').trim();
  if (!text) return '至少输入一个收件人';
  const emails = text.split(',').map((item) => item.trim()).filter(Boolean);
  if (!emails.length) return '至少输入一个收件人';
  const invalid = emails.filter((email) => !VALID_EMAIL_PATTERN.test(email));
  if (invalid.length) return `包含无效的邮箱：${invalid.join('、')}`;
  return '';
}

export function renderReportListMarkup(response = {}, filters = {}, permissions = {}) {
  const source = response?.source ? `<span class="rpt-source ${safeText(response.source)}">${safeText(reportsSourceLabel(response.source))}</span>` : '';
  const manage = permissions.manage === true;
  const items = Array.isArray(response?.items) ? response.items : [];
  const rows = items.map((item) => reportRow(item, manage)).join('');
  const empty = items.length ? '' : '<div class="rpt-empty"><h3>暂无报告</h3><p>当前筛选条件下没有可展示的报告。</p></div>';
  return `<div class="rpt-table-meta">${source}<span class="rpt-count">共 ${items.length} 条</span></div>
    <div class="rpt-table" role="table">
      <div class="rpt-table-row head" role="row"><span>编号</span><span>标题</span><span>类型</span><span>实例</span><span>状态</span><span>格式</span><span>生成时间</span><span>操作</span></div>
      ${rows}
    </div>${empty}${renderPager(response, filters)}`;
}

export function renderReportDetailMarkup(report = {}, permissions = {}) {
  if (!report?.id) return '<div class="rpt-state"><h3>报告不存在</h3><p>未找到要查看的报告。</p></div>';
  const highlights = Array.isArray(report.highlights) ? report.highlights : [];
  const issues = Number(report.issues_count) || 0;
  const email = report.email ?? {};
  const recipients = Array.isArray(email.recipients) ? email.recipients : [];
  const sent = Boolean(email.sent_at);
  const canSendEmail = permissions.manage === true && !sent;
  return `<div class="rpt-detail-head">
      <button class="rpt-back" data-reports-view="reports">← 报告列表</button>
      <span class="rpt-tag ${safeText(report.status)}">${safeText(reportStatusLabel(report.status))}</span>
      <h3>${safeText(report.title)}</h3>
      <div class="rpt-actions">${report.status === 'ready' || report.status === 'sent' ? `<button class="rpt-btn-secondary" data-reports-download="${safeText(report.id)}">下载</button>` : ''}</div>
    </div>
    <div class="rpt-meta-grid">${metaItem('报告编号', report.id)}${metaItem('报告类型', reportTypeLabel(report.type))}${metaItem('所属实例', report.instance_name || report.instance_id || '—')}${metaItem('创建人', report.created_by || '—')}${metaItem('生成时间', formatReportTime(report.generated_at || report.created_at))}${metaItem('文件格式', formatReportLabel(report.format))}${metaItem('文件大小', report.size_kb ? `${report.size_kb} KB` : '—')}</div>
    ${report.failure ? `<div class="rpt-alert">${safeText(report.failure)}</div>` : ''}
    <article class="rpt-panel"><div class="rpt-panel-head"><div><span class="rpt-kicker">HIGHLIGHTS</span><h3>报告要点</h3></div><span class="rpt-issue-count ${issues > 0 ? 'danger' : ''}">问题数 ${issues}</span></div>${highlights.length ? `<ul class="rpt-highlights">${highlights.map((item) => `<li>${safeText(item)}</li>`).join('')}</ul>` : '<p class="rpt-muted">暂无要点。</p>'}</article>
    <article class="rpt-panel"><div class="rpt-panel-head"><div><span class="rpt-kicker">DISTRIBUTION</span><h3>邮件分发</h3></div></div>${sent ? `<p class="rpt-muted">已于 ${safeText(formatReportTime(email.sent_at))} 发送给：</p><ul class="rpt-recipients">${recipients.map((item) => `<li>${safeText(item)}</li>`).join('')}</ul>` : `<p class="rpt-muted">尚未发送邮件。</p>${canSendEmail ? `<button class="rpt-btn-primary" data-reports-email="${safeText(report.id)}">发送邮件</button>` : ''}`}</article>`;
}

export function createReportsCenter({ root, api, scope, permissions = {}, onToast = () => {} } = {}) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('reports root is required');
  if (!api) throw new TypeError('reports api is required');

  const state = {
    view: 'overview',
    scope: normalizeScope(scope),
    permissions: { manage: permissions.manage === true },
    filters: { type: '', status: '', query: '', page: 1 },
    source: null,
    overview: null,
    reports: null,
    detail: null,
    templates: null,
    selectedReportId: null,
    emailReportId: null,
    templateEditing: null,
    modal: null,
    loading: false,
    error: null,
  };
  let activeRequest = null;
  let requestVersion = 0;

  root.addEventListener('click', (event) => {
    const target = event.target;
    if (!target || typeof target.closest !== 'function') return;
    if (target.classList?.contains('rpt-modal')) {
      state.modal = null;
      render();
      return;
    }
    const match = target.closest('[data-reports-view],[data-reports-report],[data-reports-retry],[data-reports-generate],[data-reports-modal-close],[data-reports-email],[data-reports-download],[data-reports-template-new],[data-reports-template-edit],[data-reports-template-toggle],[data-reports-pager]');
    if (!match) return;
    if (match.dataset.reportsView) {
      switchView(match.dataset.reportsView);
    } else if (match.dataset.reportsReport) {
      openReportDetail(match.dataset.reportsReport);
    } else if (match.hasAttribute('data-reports-retry')) {
      reload();
    } else if (match.hasAttribute('data-reports-generate')) {
      openGenerateModal();
    } else if (match.hasAttribute('data-reports-modal-close')) {
      state.modal = null;
      render();
    } else if (match.dataset.reportsEmail) {
      openEmailModal(match.dataset.reportsEmail);
    } else if (match.dataset.reportsDownload) {
      onToast(`报告 ${match.dataset.reportsDownload} 的下载已开始`);
    } else if (match.hasAttribute('data-reports-template-new')) {
      openTemplateForm(null);
    } else if (match.dataset.reportsTemplateEdit) {
      openTemplateForm(match.dataset.reportsTemplateEdit);
    } else if (match.dataset.reportsTemplateToggle) {
      handleTemplateToggle(match.dataset.reportsTemplateToggle, match.dataset.enabled === 'true');
    } else if (match.dataset.reportsPager) {
      handlePager(match.dataset.reportsPager);
    }
  });

  root.addEventListener('change', (event) => {
    const target = event.target;
    if (!target?.dataset?.reportsFilter) return;
    state.filters[target.dataset.reportsFilter] = target.value;
    if (target.dataset.reportsFilter !== 'query') state.filters.page = 1;
    reload();
  });

  root.addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    const target = event.target;
    if (target?.dataset?.reportsFilter === 'query') {
      event.preventDefault();
      reload();
    }
  });

  root.addEventListener('submit', (event) => {
    const form = typeof event.target?.closest === 'function' ? event.target.closest('[data-rpt-form]') : null;
    if (!form) return;
    event.preventDefault();
    const kind = form.dataset.rptForm;
    if (kind === 'generate') handleGenerate(form);
    else if (kind === 'email') handleEmail(form);
    else if (kind === 'template') handleTemplateSave(form);
  });

  function open(view = 'overview') {
    const normalized = REPORT_VIEWS.includes(view) ? view : 'overview';
    if (normalized !== 'report-detail') state.selectedReportId = null;
    state.view = normalized;
    state.detail = null;
    state.modal = null;
    reload();
  }

  function setScope(nextScope) {
    state.scope = normalizeScope(nextScope);
    state.view = 'overview';
    state.selectedReportId = null;
    state.detail = null;
    state.overview = null;
    state.reports = null;
    state.templates = null;
    state.filters = { type: '', status: '', query: '', page: 1 };
    state.modal = null;
    reload();
  }

  function switchView(view) {
    if (view === 'report-detail') return;
    state.view = ['overview', 'reports', 'templates'].includes(view) ? view : 'overview';
    state.selectedReportId = null;
    state.detail = null;
    state.modal = null;
    reload();
  }

  function openReportDetail(id) {
    state.selectedReportId = String(id);
    state.view = 'report-detail';
    state.detail = null;
    state.error = null;
    state.modal = null;
    reload();
  }

  function handlePager(direction) {
    const next = direction === 'next' ? state.filters.page + 1 : Math.max(1, state.filters.page - 1);
    state.filters.page = next;
    reload();
  }

  function openGenerateModal() {
    state.modal = 'generate';
    render();
    if (!state.templates && api.listTemplates) {
      api.listTemplates(state.scope).then((response) => {
        if (state.modal !== 'generate') return;
        state.templates = response;
        render();
      }).catch(() => {});
    }
  }

  function openEmailModal(id) {
    state.emailReportId = String(id);
    state.modal = 'email';
    render();
  }

  function openTemplateForm(id) {
    state.templateEditing = null;
    if (id) {
      const found = (Array.isArray(state.templates?.items) ? state.templates.items : []).find((item) => item.id === id);
      state.templateEditing = found ? { ...found } : { id };
    }
    state.modal = 'template-form';
    render();
  }

  function handleGenerate(form) {
    const formData = new FormData(form);
    const type = String(formData.get('type') || '').trim();
    const instance_id = String(formData.get('instance_id') || '').trim();
    const template_id = String(formData.get('template_id') || '').trim();
    if (!type || !instance_id) {
      onToast('请选择报告类型与目标实例');
      return;
    }
    state.modal = null;
    render();
    api.generateReport(state.scope, { type, instance_id, template_id })
      .then(() => {
        onToast('报告已开始生成');
        state.view = 'reports';
        state.detail = null;
        reload();
      })
      .catch((error) => handleActionError(error));
  }

  function handleEmail(form) {
    const formData = new FormData(form);
    const recipients = String(formData.get('recipients') || '').trim();
    const validation = validateEmailList(recipients);
    if (validation) {
      onToast(validation);
      return;
    }
    state.modal = null;
    render();
    api.sendReportEmail(state.scope, state.emailReportId, { recipients: recipients.split(',').map((item) => item.trim()).filter(Boolean) })
      .then(() => {
        onToast('邮件已发送');
        reload();
      })
      .catch((error) => handleActionError(error));
  }

  function handleTemplateSave(form) {
    const formData = new FormData(form);
    const value = {
      name: String(formData.get('name') || '').trim(),
      type: String(formData.get('type') || '').trim(),
      subject: String(formData.get('subject') || '').trim(),
      sections: String(formData.get('sections') || '').split('\n').map((item) => item.trim()).filter(Boolean),
    };
    if (state.templateEditing?.id) value.id = state.templateEditing.id;
    const errors = validateReportTemplate(value);
    if (Object.keys(errors).length) {
      onToast(Object.values(errors)[0]);
      return;
    }
    const editing = Boolean(state.templateEditing?.id);
    state.modal = null;
    render();
    api.saveTemplate(state.scope, value)
      .then(() => {
        onToast(editing ? '模板已更新' : '模板已创建');
        state.templateEditing = null;
        reload();
      })
      .catch((error) => handleActionError(error));
  }

  function handleTemplateToggle(id, enabled) {
    api.setTemplateEnabled(state.scope, id, !enabled)
      .then(() => {
        onToast(enabled ? '模板已停用' : '模板已启用');
        reload();
      })
      .catch((error) => handleActionError(error));
  }

  function handleActionError(error) {
    onToast(reportsFailureMessage(error, '报告'));
  }

  async function reload() {
    abortActive();
    const controller = new AbortController();
    activeRequest = controller;
    const version = ++requestVersion;
    state.loading = true;
    state.error = null;
    state.source = null;
    render();
    try {
      const response = await loadViewData(controller.signal);
      if (version !== requestVersion || controller.signal.aborted) return;
      applyViewData(response);
      state.loading = false;
      render();
    } catch (error) {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.loading = false;
      state.error = error;
      render();
    }
  }

  function loadViewData(signal) {
    if (state.view === 'reports') {
      const offset = (state.filters.page - 1) * REPORT_PAGE_SIZE;
      return api.listReports(state.scope, buildReportFilters([['type', state.filters.type], ['status', state.filters.status], ['query', state.filters.query], ['offset', offset], ['limit', REPORT_PAGE_SIZE]]), signal);
    }
    if (state.view === 'report-detail') return api.getReport(state.scope, state.selectedReportId, signal);
    if (state.view === 'templates') return api.listTemplates(state.scope, signal);
    return api.getOverview(state.scope, signal);
  }

  function applyViewData(response) {
    state.source = response?.source ?? null;
    if (state.view === 'overview') state.overview = response;
    else if (state.view === 'reports') state.reports = response;
    else if (state.view === 'report-detail') state.detail = response;
    else if (state.view === 'templates') state.templates = response;
  }

  function abortActive() {
    activeRequest?.abort();
    activeRequest = null;
  }

  function render() {
    root.innerHTML = renderWorkbench();
  }

  function renderWorkbench() {
    const source = state.source ? `<span class="rpt-source ${safeText(state.source)}">${safeText(reportsSourceLabel(state.source))}</span>` : '';
    const body = state.error
      ? renderReportsError(state.error)
      : state.loading && !hasData()
        ? renderLoading()
        : state.view === 'reports'
          ? renderReportsView(state.reports ?? {})
          : state.view === 'report-detail'
            ? renderReportDetailView(state.detail ?? {})
            : state.view === 'templates'
              ? renderTemplatesView(state.templates ?? {})
              : renderOverviewView(state.overview ?? {});
    return `<section class="rpt-center">
    <div class="rpt-hero"><div><span class="eyebrow">DBPILOT · REPORT CENTER</span><h2>报告中心</h2><p>统一管理巡检与运维报告，按模板生成、下载并邮件分发。</p></div><div class="rpt-hero-meta">${source}<span class="rpt-scope">${safeText(state.scope.tenantId)} / ${safeText(state.scope.projectId)}</span></div></div>
    <div class="rpt-toolbar"><nav class="rpt-tabs" aria-label="报告视图"><button class="${state.view === 'overview' ? 'active' : ''}" data-reports-view="overview">报告概览</button><button class="${state.view === 'reports' || state.view === 'report-detail' ? 'active' : ''}" data-reports-view="reports">报告列表</button><button class="${state.view === 'templates' ? 'active' : ''}" data-reports-view="templates">模板管理</button></nav>${state.view === 'reports' && state.permissions.manage === true ? '<button class="rpt-btn-primary" data-reports-generate>＋ 生成报告</button>' : ''}</div>
    ${state.loading && hasData() ? '<div class="rpt-progress" role="status">正在刷新…</div>' : ''}
    ${body}
    ${renderModal()}
  </section>`;
  }

  function hasData() {
    return Boolean(state.overview || state.reports || state.detail || state.templates);
  }

  function renderLoading() {
    return '<div class="rpt-state" role="status"><span class="rpt-spinner"></span><h3>正在加载报告数据</h3><p>查询当前项目的报告与模板，请稍候。</p></div>';
  }

  function renderReportsError(error) {
    const unauthorized = error?.kind === 'unauthorized' || error?.kind === 'forbidden';
    return `<div class="rpt-state error ${unauthorized ? 'unauthorized' : ''}" role="alert"><span class="rpt-state-icon">${unauthorized ? '⌾' : '!'}</span><h3>${unauthorized ? '无法查看此项目' : '报告数据加载失败'}</h3><p>${safeText(reportsFailureMessage(error, '报告数据'))}</p><button class="rpt-btn-primary" data-reports-retry>重试</button></div>`;
  }

  function renderOverviewView(overview = {}) {
    const stats = overview?.stats ?? {};
    const recent = Array.isArray(overview?.recent_reports) ? overview.recent_reports : [];
    return `<div class="rpt-overview">
    <div class="rpt-section-head"><div><h3>报告概览</h3><p>报告生成、分发与模板使用情况的整体视图。</p></div>${state.permissions.manage === true ? '<button class="rpt-btn-primary" data-reports-generate>立即生成报告</button>' : ''}</div>
    <div class="rpt-stats">
      ${statCard('本周生成', stats.generated_this_week ?? 0, 'week')}
      ${statCard('待发送', stats.pending_send ?? 0, 'pending')}
      ${statCard('报告模板', stats.template_count ?? 0, 'template')}
      ${statCard('生成成功率', formatSuccessRate(stats.success_rate), 'rate')}
    </div>
    <article class="rpt-panel"><div class="rpt-panel-head"><div><span class="rpt-kicker">RECENT REPORTS</span><h3>最近报告</h3></div><button class="rpt-link-btn" data-reports-view="reports">查看全部 →</button></div>${renderRecentReportRows(recent)}</article>
  </div>`;
  }

  function renderReportsView(response = {}) {
    return `<div class="rpt-reports">
    <div class="rpt-section-head"><div><h3>报告列表</h3><p>按类型、状态与关键字筛选报告，进入详情完成下载与邮件分发。</p></div><div class="rpt-filters">
      <label>类型<select class="rpt-select" data-reports-filter="type"><option value="">全部</option>${typeOptions(state.filters.type)}</select></label>
      <label>状态<select class="rpt-select" data-reports-filter="status"><option value="">全部</option>${statusOptions(state.filters.status)}</select></label>
      <label>搜索<input class="rpt-input" type="search" data-reports-filter="query" value="${safeText(state.filters.query)}" placeholder="标题 / 编号 / 实例"></label>
    </div></div>
    <article class="rpt-panel rpt-table-wrap">${renderReportListMarkup(response, state.filters, state.permissions)}</article>
  </div>`;
  }

  function renderReportDetailView(response = {}) {
    return `<div class="rpt-detail">${renderReportDetailMarkup(response, state.permissions)}</div>`;
  }

  function renderTemplatesView(response = {}) {
    return `<div class="rpt-templates">
    <div class="rpt-section-head"><div><h3>报告模板</h3><p>维护报告生成模板，主题支持 {instance} {date} 占位符。</p></div>${state.permissions.manage === true ? '<button class="rpt-btn-primary" data-reports-template-new>＋ 新建模板</button>' : ''}</div>
    <article class="rpt-panel rpt-table-wrap">${renderTemplateListMarkup(response)}</article>
  </div>`;
  }

  function renderModal() {
    if (state.modal === 'generate') return renderGenerateModal();
    if (state.modal === 'email') return renderEmailModal();
    if (state.modal === 'template-form') return renderTemplateFormModal();
    return '';
  }

  function renderGenerateModal() {
    const templates = Array.isArray(state.templates?.items) ? state.templates.items : [];
    return `<div class="rpt-modal" role="dialog" aria-modal="true"><div class="rpt-modal-box">
    <div class="rpt-modal-head"><h3>生成报告</h3><button class="rpt-modal-close" data-reports-modal-close aria-label="关闭">×</button></div>
    <form class="rpt-form" data-rpt-form="generate">
      <label>报告类型<select class="rpt-select" name="type">${typeOptions('inspection')}</select></label>
      <label>目标实例<select class="rpt-select" name="instance_id"><option value="">请选择实例</option>${REPORT_INSTANCES.map((item) => `<option value="${safeText(item.id)}">${safeText(item.name)}</option>`).join('')}</select></label>
      <label>报告模板<select class="rpt-select" name="template_id"><option value="">使用默认模板</option>${templates.map((item) => `<option value="${safeText(item.id)}">${safeText(item.name)}</option>`).join('')}</select></label>
      <div class="rpt-form-actions"><button type="button" class="rpt-btn-secondary" data-reports-modal-close>取消</button><button type="submit" class="rpt-btn-primary">生成</button></div>
    </form>
  </div></div>`;
  }

  function renderEmailModal() {
    const report = findReport(state.emailReportId);
    return `<div class="rpt-modal" role="dialog" aria-modal="true"><div class="rpt-modal-box">
    <div class="rpt-modal-head"><h3>发送邮件</h3><button class="rpt-modal-close" data-reports-modal-close aria-label="关闭">×</button></div>
    <form class="rpt-form" data-rpt-form="email">
      ${report ? `<p class="rpt-muted">报告：${safeText(report.title)}</p>` : ''}
      <label>收件人（多个邮箱用逗号分隔）<input class="rpt-input" name="recipients" required placeholder="oncall@example.com, dba@example.com"></label>
      <div class="rpt-form-actions"><button type="button" class="rpt-btn-secondary" data-reports-modal-close>取消</button><button type="submit" class="rpt-btn-primary">发送</button></div>
    </form>
  </div></div>`;
  }

  function renderTemplateFormModal() {
    const value = state.templateEditing ?? {};
    const sections = Array.isArray(value.sections) ? value.sections.join('\n') : '';
    return `<div class="rpt-modal" role="dialog" aria-modal="true"><div class="rpt-modal-box">
    <div class="rpt-modal-head"><h3>${value.id ? '编辑模板' : '新建模板'}</h3><button class="rpt-modal-close" data-reports-modal-close aria-label="关闭">×</button></div>
    <form class="rpt-form" data-rpt-form="template">
      <label>模板名称<input class="rpt-input" name="name" required value="${safeText(value.name ?? '')}" placeholder="如：标准巡检模板"></label>
      <label>报告类型<select class="rpt-select" name="type">${typeOptions(value.type || 'inspection')}</select></label>
      <label>邮件主题<input class="rpt-input" name="subject" required value="${safeText(value.subject ?? '')}" placeholder="支持 {instance} {date} 占位符"></label>
      <label>报告章节（每行一个）<textarea class="rpt-textarea" name="sections" rows="5" placeholder="实例概览\n资源使用率\n风险与建议">${safeText(sections)}</textarea></label>
      <div class="rpt-form-actions"><button type="button" class="rpt-btn-secondary" data-reports-modal-close>取消</button><button type="submit" class="rpt-btn-primary">保存</button></div>
    </form>
  </div></div>`;
  }

  function findReport(id) {
    if (state.detail?.id === id) return state.detail;
    return (Array.isArray(state.reports?.items) ? state.reports.items : []).find((item) => item.id === id) ?? null;
  }

  render();
  return {
    open,
    setScope,
    refresh: reload,
    getState: () => ({ ...state, scope: { ...state.scope }, filters: { ...state.filters }, permissions: { ...state.permissions } }),
  };
}

function reportRow(report, manage) {
  return `<div class="rpt-table-row" role="row">
    <span>${safeText(report.id)}</span>
    <span><button class="rpt-title-link" data-reports-report="${safeText(report.id)}">${safeText(report.title)}</button></span>
    <span>${safeText(reportTypeLabel(report.type))}</span>
    <span>${safeText(report.instance_name || report.instance_id || '—')}</span>
    <span><i class="rpt-tag ${safeText(report.status)}">${safeText(reportStatusLabel(report.status))}</i></span>
    <span>${safeText(formatReportLabel(report.format))}</span>
    <span>${safeText(formatReportTime(report.generated_at || report.created_at))}</span>
    <span class="rpt-actions">${reportActions(report, manage)}</span>
  </div>`;
}

function reportActions(report, manage) {
  const actions = [`<button class="rpt-link-btn" data-reports-report="${safeText(report.id)}">查看</button>`];
  if (report.status === 'ready' || report.status === 'sent') {
    actions.push(`<button class="rpt-link-btn" data-reports-download="${safeText(report.id)}">下载</button>`);
  }
  if (report.status === 'ready' && manage) {
    actions.push(`<button class="rpt-link-btn" data-reports-email="${safeText(report.id)}">发送邮件</button>`);
  }
  return actions.join('');
}

function renderRecentReportRows(reports) {
  if (!reports.length) return '<div class="rpt-empty compact"><p>本周还没有生成任何报告。</p></div>';
  return `<div class="rpt-recent-list">${reports.map((report) => `<div class="rpt-recent-row"><button class="rpt-title-link" data-reports-report="${safeText(report.id)}">${safeText(report.title)}</button><span>${safeText(reportTypeLabel(report.type))}</span><span class="rpt-tag ${safeText(report.status)}">${safeText(reportStatusLabel(report.status))}</span><span>${safeText(formatReportTime(report.created_at))}</span></div>`).join('')}</div>`;
}

function renderTemplateListMarkup(response = {}) {
  const items = Array.isArray(response?.items) ? response.items : [];
  const rows = items.map((template) => {
    const sections = Array.isArray(template.sections) ? template.sections : [];
    const enabled = template.enabled === true;
    const toggleLabel = enabled ? '停用' : '启用';
    return `<div class="rpt-table-row" role="row">
      <span><b>${safeText(template.name)}</b><small>${safeText(template.id)}</small></span>
      <span>${safeText(reportTypeLabel(template.type))}</span>
      <span>${safeText(template.subject)}</span>
      <span>${sections.length} 章</span>
      <span><i class="rpt-tag ${enabled ? 'enabled' : 'disabled'}">${enabled ? '已启用' : '已停用'}</i></span>
      <span class="rpt-actions"><button class="rpt-link-btn" data-reports-template-edit="${safeText(template.id)}">编辑</button><button class="rpt-link-btn" data-reports-template-toggle="${safeText(template.id)}" data-enabled="${enabled}">${toggleLabel}</button></span>
    </div>`;
  }).join('');
  return `<div class="rpt-table-meta"><span class="rpt-count">共 ${items.length} 个模板</span></div>
    <div class="rpt-table" role="table">
      <div class="rpt-table-row head" role="row"><span>名称</span><span>类型</span><span>主题</span><span>章节</span><span>状态</span><span>操作</span></div>
      ${rows}
    </div>${items.length ? '' : '<div class="rpt-empty"><h3>暂无模板</h3><p>尚未创建报告模板。</p></div>'}`;
}

function renderPager(response = {}, filters = {}) {
  const page = Number(filters.page) || 1;
  const nextCursor = response?.nextCursor ?? null;
  const prevDisabled = page <= 1;
  return `<div class="rpt-pager"><button class="rpt-btn-secondary" data-reports-pager="prev" ${prevDisabled ? 'disabled' : ''}>上一页</button><span class="rpt-page">第 ${page} 页</span><button class="rpt-btn-secondary" data-reports-pager="next" ${nextCursor ? '' : 'disabled'}>下一页</button></div>`;
}

function statCard(label, value, tone) {
  return `<article class="rpt-stat-card ${tone}"><span>${safeText(label)}</span><strong>${safeText(String(value))}</strong><i></i></article>`;
}

function metaItem(label, value) {
  return `<div class="rpt-meta-item"><dt>${safeText(label)}</dt><dd>${safeText(String(value ?? '—'))}</dd></div>`;
}

function typeOptions(selected) {
  return Object.entries(REPORT_TYPE_LABELS).map(([key, label]) => `<option value="${key}" ${selected === key ? 'selected' : ''}>${label}</option>`).join('');
}

function statusOptions(selected) {
  return Object.entries(REPORT_STATUS_LABELS).map(([key, label]) => `<option value="${key}" ${selected === key ? 'selected' : ''}>${label}</option>`).join('');
}

function formatReportLabel(value) {
  return { pdf: 'PDF', word: 'Word' }[value] ?? (value ? String(value) : '—');
}

function formatSuccessRate(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  return `${number}%`;
}

function formatReportTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  return date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
}

function normalizeScope(scope) {
  return {
    tenantId: typeof scope?.tenantId === 'string' && scope.tenantId.trim() ? scope.tenantId.trim() : '未配置',
    projectId: typeof scope?.projectId === 'string' && scope.projectId.trim() ? scope.projectId.trim() : '未配置',
  };
}

if (typeof window !== 'undefined') {
  window.DBPilotReportsCenter = { create: createReportsCenter };
}
