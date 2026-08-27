const AUDIT_ACTIONS = [
  ['login', '登录'],
  ['logout', '登出'],
  ['query', '查询'],
  ['dml', '数据变更'],
  ['ddl', '结构变更'],
  ['dcl', '权限变更'],
  ['config', '配置修改'],
  ['backup', '备份'],
  ['restore', '恢复'],
  ['grant', '授权'],
  ['revoke', '回收权限'],
  ['export', '数据导出'],
  ['alert.ack', '告警确认'],
  ['alert.resolve', '告警解决'],
  ['ticket.approve', '工单审批'],
];

const ACTION_LABELS = Object.fromEntries(AUDIT_ACTIONS);
const RESULT_LABELS = { success: '成功', denied: '已拒绝', failed: '失败' };
const RESOURCE_TYPE_LABELS = {
  console: '控制台',
  instance: '实例',
  rule: '告警规则',
  ticket: '工单',
  policy: '策略',
  report: '报告',
  account: '账号',
};

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function auditActionLabel(action) {
  return ACTION_LABELS[action] ?? '未知操作';
}

export function auditResultLabel(result) {
  return RESULT_LABELS[result] ?? '未知';
}

export function auditSourceLabel(source) {
  if (source === 'demo') return '演示数据';
  if (source === 'http' || source === 'control-plane') return '控制面服务';
  return '来源未确认';
}

export function auditFailureMessage(error, subject = '审计数据') {
  if (error?.kind === 'forbidden') return '当前账号没有该项目的操作权限';
  return {
    unauthorized: '登录状态已失效，请重新登录',
    'not-found': '审计记录不存在或已无权访问',
    validation: '审计查询参数不符合要求',
    unavailable: '审计服务暂时不可用，请稍后重试',
    network: '无法连接控制面服务，请检查网络后重试',
  }[error?.kind] ?? `${subject}加载失败，请稍后重试`;
}

export function buildAuditFilters(entries) {
  return Object.fromEntries([...entries].filter(([, value]) => String(value ?? '').trim() !== ''));
}

export function validateAuditRange(fromValue, toValue) {
  const from = fromValue == null || fromValue === '' ? null : new Date(fromValue);
  const to = toValue == null || toValue === '' ? null : new Date(toValue);
  if (from && !Number.isFinite(from.getTime())) return { kind: 'invalid-date', field: 'from' };
  if (to && !Number.isFinite(to.getTime())) return { kind: 'invalid-date', field: 'to' };
  if (from && to && from.getTime() > to.getTime()) return { kind: 'invalid-range' };
  return { kind: 'valid', from: from ? from.toISOString() : '', to: to ? to.toISOString() : '' };
}

export function renderAuditOverviewMarkup(value = {}, permissions = {}, source = '') {
  const distribution = Array.isArray(value?.distribution) ? value.distribution : [];
  const recent = Array.isArray(value?.recent) ? value.recent : [];
  const maxCount = Math.max(1, ...distribution.map((item) => Number(item.count)));
  return `<div class="audit-overview">
    <div class="audit-section-head"><div><h3>审计概览</h3><p>统计当前项目今日的敏感操作、权限变更与配置修改记录。</p></div></div>
    <div class="audit-stats">
      ${statCard('今日操作数', value?.today_operations ?? 0, 'total')}
      ${statCard('失败与拒绝', value?.failed_denied ?? 0, 'failed')}
      ${statCard('涉及实例数', value?.instance_count ?? 0, 'instances')}
      ${statCard('操作者数', value?.actor_count ?? 0, 'actors')}
    </div>
    <article class="audit-panel"><div class="audit-panel-head"><div><span class="audit-kicker">ACTIVITY MIX</span><h3>操作类型分布</h3></div></div>
      ${distribution.length ? `<div class="audit-bars">${distribution.map((item) => `<div class="audit-bar-row"><span class="audit-bar-label">${safeText(auditActionLabel(item.action))}</span><span class="audit-bar-track"><i style="width:${Math.max(2, Math.round(Number(item.count) / maxCount * 100))}%"></i></span><span class="audit-bar-count">${safeText(String(item.count))}</span></div>`).join('')}</div>` : '<div class="audit-empty compact"><p>暂无操作分布。</p></div>'}
    </article>
    <article class="audit-panel"><div class="audit-panel-head"><div><span class="audit-kicker">RECENT</span><h3>最近审计</h3></div><button data-audit-view="audit-log">查看全部 →</button></div>
      ${recent.length ? `<div class="audit-timeline">${recent.map((item) => `<div class="audit-timeline-item"><span class="audit-time">${safeText(formatAuditTime(item.at))}</span><span class="audit-actor">${safeText(item.actor)}</span><span class="audit-action">${safeText(auditActionLabel(item.action))}</span><span class="audit-object">${safeText(item.resource_name || '—')}</span></div>`).join('')}</div>` : '<div class="audit-empty compact"><p>暂无审计记录。</p></div>'}
    </article>
  </div>`;
}

export function renderAuditListMarkup({ items = [], source = '', total = 0, offset = 0, limit = 15, filters = {} } = {}) {
  const safeLimit = limit > 0 ? limit : 15;
  const page = safeLimit ? Math.floor(offset / safeLimit) + 1 : 1;
  const pages = safeLimit ? Math.max(1, Math.ceil(total / safeLimit)) : 1;
  const prevPage = page > 1 ? page - 1 : null;
  const nextPage = page < pages ? page + 1 : null;
  return `<article class="audit-panel audit-table-wrap">
    <div class="audit-panel-head"><div><span class="audit-kicker">ENTRIES</span><h3>审计记录</h3></div><span class="audit-source ${safeText(source)}">${safeText(auditSourceLabel(source))}</span></div>
    <div class="audit-table" role="table">
      <div class="audit-table-row head" role="row"><span>时间</span><span>操作</span><span>对象</span><span>实例</span><span>操作者</span><span>来源 IP</span><span>结果</span><span></span></div>
      ${items.map(renderAuditRow).join('')}
    </div>
    ${items.length ? '' : '<div class="audit-empty"><h3>暂无审计记录</h3><p>当前筛选条件下没有可展示的审计日志。</p></div>'}
    <div class="audit-pager">
      <button class="audit-page-btn${prevPage == null ? ' disabled' : ''}" data-audit-page="${prevPage ?? ''}" ${prevPage == null ? 'disabled' : ''}>上一页</button>
      <span>第 ${page} / ${pages} 页 · 共 ${total} 条</span>
      <button class="audit-page-btn${nextPage == null ? ' disabled' : ''}" data-audit-page="${nextPage ?? ''}" ${nextPage == null ? 'disabled' : ''}>下一页</button>
    </div>
  </article>`;
}

export function renderAuditDetailMarkup(entry = {}, options = {}) {
  if (!entry?.id) {
    return `<div class="audit-state"><h3>${options.loading ? '正在加载审计详情' : '尚未选择审计记录'}</h3><p>从日志列表选择一条记录查看详情。</p><button class="primary" data-audit-view="audit-log">返回日志列表</button></div>`;
  }
  const hasReason = String(entry.reason ?? '').trim() !== '';
  const showFailure = entry.result !== 'success' && hasReason;
  return `<div class="audit-detail">
    <div class="audit-section-head"><div><button class="audit-back" data-audit-view="audit-log">← 日志列表</button><h3>${safeText(entry.id)}</h3><p>${safeText(auditActionLabel(entry.action))} · ${safeText(entry.resource_name || '未命名对象')}</p></div><span class="audit-source ${safeText(entry.source ?? '')}">${safeText(auditSourceLabel(entry.source))}</span></div>
    ${showFailure ? `<div class="audit-failure" role="alert"><strong>${safeText(auditResultLabel(entry.result))}原因</strong><p>${safeText(entry.reason)}</p></div>` : ''}
    <div class="audit-meta-grid">
      <article class="audit-panel"><span class="audit-kicker">META</span><h3>元信息</h3><dl class="audit-facts">
        <div><dt>编号</dt><dd>${safeText(entry.id)}</dd></div>
        <div><dt>时间</dt><dd>${safeText(formatAuditFullTime(entry.at))}</dd></div>
        <div><dt>操作者</dt><dd>${safeText(entry.actor)}</dd></div>
        <div><dt>操作者类型</dt><dd>${safeText(actorTypeLabel(entry.actor_type))}</dd></div>
        <div><dt>来源 IP</dt><dd>${safeText(entry.source_ip || '—')}</dd></div>
        <div><dt>客户端</dt><dd>${safeText(entry.client || '—')}</dd></div>
        <div><dt>结果</dt><dd>${safeText(auditResultLabel(entry.result))}</dd></div>
      </dl></article>
      <article class="audit-panel"><span class="audit-kicker">CONTEXT</span><h3>操作对象</h3><dl class="audit-facts">
        <div><dt>资源类型</dt><dd>${safeText(resourceTypeLabel(entry.resource_type))}</dd></div>
        <div><dt>资源 ID</dt><dd>${safeText(entry.resource_id || '—')}</dd></div>
        <div><dt>资源名称</dt><dd>${safeText(entry.resource_name || '—')}</dd></div>
        <div><dt>实例</dt><dd>${safeText(entry.instance_name || entry.instance_id || '—')}</dd></div>
      </dl></article>
    </div>
    <article class="audit-panel"><span class="audit-kicker">PARAMETERS</span><h3>详情参数</h3><div class="audit-detail-fields">${renderDetailFields(entry.detail ?? {})}</div></article>
    <article class="audit-panel"><span class="audit-kicker">RAW</span><h3>原始 JSON</h3><pre class="audit-json">${safeText(JSON.stringify(entry.detail ?? {}, null, 2))}</pre></article>
  </div>`;
}

export function createAuditCenter({ root, api, scope, permissions = {}, onToast = () => {} }) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('audit root is required');
  if (!api) throw new TypeError('audit api is required');

  const state = {
    view: 'overview',
    scope: normalizeScope(scope),
    permissions: { manage: permissions.manage === true },
    filters: { action: '', result: '', instance_id: '', actor: '', from: '', to: '', query: '' },
    offset: 0,
    limit: 15,
    instanceOptions: [],
    source: null,
    overview: null,
    entries: null,
    detail: null,
    selectedId: null,
    loading: false,
    error: null,
  };
  let activeRequest = null;
  let requestVersion = 0;

  root.addEventListener('click', (event) => {
    const target = typeof event.target?.closest === 'function'
      ? event.target.closest('[data-audit-view],[data-audit-entry],[data-audit-retry],[data-audit-page],[data-audit-export]')
      : null;
    if (!target) return;
    if (target.dataset.auditView) {
      state.view = target.dataset.auditView;
      resetSelection();
      reload();
    } else if (target.dataset.auditEntry) {
      loadDetail(target.dataset.auditEntry);
    } else if (target.hasAttribute('data-audit-retry')) {
      state.selectedId ? loadDetail(state.selectedId) : reload();
    } else if (target.hasAttribute('data-audit-page')) {
      const page = Number(target.dataset.auditPage);
      if (Number.isInteger(page) && page >= 1) {
        state.offset = (page - 1) * state.limit;
        reload();
      }
    } else if (target.hasAttribute('data-audit-export')) {
      onToast('日志导出需在受控导出流程中处理');
    }
  });

  root.addEventListener('change', (event) => {
    const target = event.target;
    if (!target?.dataset) return;
    if (target.dataset.auditFilter) {
      const field = target.dataset.auditFilter;
      if (field === 'from' || field === 'to') {
        const range = validateAuditRange(
          field === 'from' ? target.value : state.filters.from,
          field === 'to' ? target.value : state.filters.to,
        );
        if (range.kind !== 'valid') {
          onToast(range.kind === 'invalid-range' ? '开始时间必须早于结束时间' : '时间格式不正确');
          return;
        }
      }
      state.filters[field] = target.value;
      state.offset = 0;
      reload();
    }
  });

  root.addEventListener('input', (event) => {
    const target = event.target;
    if (target?.dataset?.auditFilter === 'query') {
      state.filters.query = target.value;
      state.offset = 0;
      reload();
    }
  });

  function open(view = 'overview') {
    state.view = ['overview', 'audit-log', 'audit-detail'].includes(view) ? view : 'overview';
    resetSelection();
    reload();
  }

  function setScope(nextScope) {
    state.scope = normalizeScope(nextScope);
    resetSelection();
    reload();
  }

  function resetSelection() {
    abortActive();
    state.selectedId = null;
    state.detail = null;
    state.entries = null;
    state.overview = null;
    state.source = null;
    state.offset = 0;
    state.error = null;
  }

  function reload() {
    abortActive();
    const controller = new AbortController();
    activeRequest = controller;
    const version = ++requestVersion;
    state.loading = true;
    state.error = null;
    state.source = null;
    render();
    const request = state.view === 'overview'
      ? api.getOverview(state.scope, controller.signal)
      : state.view === 'audit-log'
        ? api.listEntries(state.scope, buildAuditQuery() ?? {}, controller.signal)
        : api.getEntry(state.scope, state.selectedId, controller.signal);
    request.then((result) => {
      if (version !== requestVersion || controller.signal.aborted) return;
      applyResult(result);
      state.loading = false;
      render();
    }).catch((error) => {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.loading = false;
      state.error = error;
      render();
    });
  }

  function loadDetail(id) {
    abortActive();
    const controller = new AbortController();
    activeRequest = controller;
    const version = ++requestVersion;
    state.view = 'audit-detail';
    state.selectedId = String(id);
    state.detail = null;
    state.error = null;
    state.loading = true;
    render();
    api.getEntry(state.scope, state.selectedId, controller.signal).then((result) => {
      if (version !== requestVersion || controller.signal.aborted) return;
      state.detail = { ...(result?.entry ?? result ?? {}), source: result?.source };
      state.source = result?.source ?? null;
      state.loading = false;
      render();
    }).catch((error) => {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.loading = false;
      state.error = error;
      render();
    });
  }

  function applyResult(result) {
    const safe = result ?? {};
    if (state.view === 'overview') {
      state.overview = safe;
      if (Array.isArray(safe.instances)) state.instanceOptions = safe.instances;
    } else if (state.view === 'audit-log') {
      state.entries = safe;
    } else {
      state.detail = { ...(safe.entry ?? safe), source: safe.source };
    }
    state.source = safe.source ?? null;
  }

  function buildAuditQuery() {
    const range = validateAuditRange(state.filters.from, state.filters.to);
    if (range.kind !== 'valid') {
      onToast(range.kind === 'invalid-range' ? '开始时间必须早于结束时间' : '时间格式不正确');
      return null;
    }
    return {
      action: state.filters.action,
      result: state.filters.result,
      instance_id: state.filters.instance_id,
      actor: state.filters.actor,
      query: state.filters.query,
      from: range.from,
      to: range.to,
      offset: state.offset,
      limit: state.limit,
    };
  }

  function abortActive() {
    activeRequest?.abort();
    activeRequest = null;
  }

  function render() {
    root.innerHTML = renderAuditWorkbench(state);
  }

  render();
  return {
    open,
    setScope,
    refresh: reload,
    getState: () => ({ ...state, scope: { ...state.scope }, filters: { ...state.filters } }),
  };
}

export function renderAuditWorkbench(state) {
  const source = state.source ? `<span class="audit-source ${safeText(state.source)}">${safeText(auditSourceLabel(state.source))}</span>` : '';
  const body = state.error
    ? renderAuditError(state.error)
    : state.loading && !state.overview && !state.entries && !state.detail
      ? '<div class="audit-state" role="status"><span class="audit-spinner"></span><h3>正在加载审计日志</h3><p>读取当前项目的操作记录，请稍候。</p></div>'
      : state.view === 'audit-log'
        ? renderAuditLogView(state)
        : state.view === 'audit-detail'
          ? renderAuditDetailMarkup(state.detail ?? {}, { loading: state.loading })
          : renderAuditOverviewMarkup(state.overview, state.permissions, state.source);
  return `<section class="audit-center">
    <div class="audit-hero"><div><span class="eyebrow">DBPILOT · AUDIT LOG</span><h2>审计日志</h2><p>按租户与项目作用域追溯敏感操作、权限变更与配置修改记录。</p></div><div class="audit-hero-meta">${source}<span class="audit-scope">${safeText(state.scope.tenantId)} / ${safeText(state.scope.projectId)}</span></div></div>
    <div class="audit-toolbar">
      <nav class="audit-tabs" aria-label="审计视图"><button class="${state.view === 'overview' ? 'active' : ''}" data-audit-view="overview">审计概览</button><button class="${state.view === 'audit-log' ? 'active' : ''}" data-audit-view="audit-log">日志列表</button>${state.view === 'audit-detail' ? '<button class="active" data-audit-view="audit-detail">日志详情</button>' : ''}</nav>
      ${state.permissions.manage ? '<button class="secondary" data-audit-export>导出日志</button>' : ''}
    </div>
    ${state.loading && (state.overview || state.entries || state.detail) ? '<div class="audit-progress" role="status">正在刷新…</div>' : ''}
    ${body}
  </section>`;
}

function renderAuditLogView(state) {
  const filters = state.filters;
  const instanceOptions = Array.isArray(state.instanceOptions) ? state.instanceOptions : [];
  return `<div class="audit-log">
    <div class="audit-section-head"><div><h3>日志列表</h3><p>按操作类型、结果、实例、操作者与时间范围筛选审计记录。</p></div></div>
    <div class="audit-filter-bar">
      <label>操作类型<select class="audit-select" data-audit-filter="action"><option value="">全部</option>${AUDIT_ACTIONS.map(([key, label]) => `<option value="${key}" ${filters.action === key ? 'selected' : ''}>${label}</option>`).join('')}</select></label>
      <label>结果<select class="audit-select" data-audit-filter="result"><option value="">全部</option>${Object.entries(RESULT_LABELS).map(([key, label]) => `<option value="${key}" ${filters.result === key ? 'selected' : ''}>${label}</option>`).join('')}</select></label>
      <label>实例<select class="audit-select" data-audit-filter="instance_id"><option value="">全部</option>${instanceOptions.map((item) => `<option value="${safeText(item.id)}" ${filters.instance_id === item.id ? 'selected' : ''}>${safeText(item.name || item.id)}</option>`).join('')}</select></label>
      <label>操作者<input class="audit-input" type="text" data-audit-filter="actor" value="${safeText(filters.actor)}" placeholder="账号名"></label>
      <label>开始<input class="audit-input" type="datetime-local" data-audit-filter="from" value="${safeText(filters.from)}"></label>
      <label>结束<input class="audit-input" type="datetime-local" data-audit-filter="to" value="${safeText(filters.to)}"></label>
      <label>搜索<input class="audit-input" type="search" data-audit-filter="query" value="${safeText(filters.query)}" placeholder="全文搜索"></label>
    </div>
    ${renderAuditListMarkup({ items: state.entries?.items ?? [], source: state.source, total: state.entries?.total ?? 0, offset: state.offset, limit: state.limit, filters })}
  </div>`;
}

function renderAuditRow(item) {
  return `<div class="audit-table-row" role="row">
    <span>${safeText(formatAuditTime(item.at))}</span>
    <span><b>${safeText(auditActionLabel(item.action))}</b></span>
    <span>${safeText(item.resource_name || '—')}</span>
    <span>${safeText(item.instance_name || '—')}</span>
    <span>${safeText(item.actor)}</span>
    <span>${safeText(item.source_ip || '—')}</span>
    <span><i class="audit-tag ${safeText(item.result)}">${safeText(auditResultLabel(item.result))}</i></span>
    <span><button class="audit-link" data-audit-entry="${safeText(item.id)}">查看</button></span>
  </div>`;
}

function renderAuditError(error) {
  const forbidden = error?.kind === 'forbidden';
  return `<div class="audit-state error ${forbidden ? 'forbidden' : ''}" role="alert"><span class="audit-state-icon">${forbidden ? '⌾' : '!'}</span><h3>${forbidden ? '无法查看此项目' : '审计数据加载失败'}</h3><p>${safeText(auditFailureMessage(error))}</p><button class="primary" data-audit-retry>重试</button></div>`;
}

function renderDetailFields(value) {
  if (value == null || value === '') return '<p class="audit-empty-line">—</p>';
  if (Array.isArray(value)) {
    return `<div class="audit-detail-field"><span>值</span><code>${safeText(JSON.stringify(value))}</code></div>`;
  }
  if (typeof value !== 'object') {
    return `<div class="audit-detail-field"><span>值</span><code>${safeText(String(value))}</code></div>`;
  }
  const entries = Object.entries(value);
  if (!entries.length) return '<p class="audit-empty-line">无参数</p>';
  return entries.map(([key, item]) => {
    if (item != null && typeof item === 'object') {
      return `<div class="audit-detail-field nested"><span>${safeText(key)}</span><div class="audit-detail-nested">${renderDetailFields(item)}</div></div>`;
    }
    return `<div class="audit-detail-field"><span>${safeText(key)}</span><code>${safeText(item == null ? '—' : String(item))}</code></div>`;
  }).join('');
}

function statCard(label, value, status) {
  return `<article class="audit-stat-card ${status}"><span>${safeText(label)}</span><strong>${safeText(String(value))}</strong><i></i></article>`;
}

function normalizeScope(scope) {
  return {
    tenantId: typeof scope?.tenantId === 'string' && scope.tenantId.trim() ? scope.tenantId.trim() : '未配置',
    projectId: typeof scope?.projectId === 'string' && scope.projectId.trim() ? scope.projectId.trim() : '未配置',
  };
}

function resourceTypeLabel(value) {
  return RESOURCE_TYPE_LABELS[value] ?? String(value ?? '—');
}

function actorTypeLabel(value) {
  return { user: '用户', system: '系统', agent: '智能体' }[value] ?? String(value ?? '—');
}

function formatAuditTime(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  return date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
}

function formatAuditFullTime(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  return date.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

if (typeof window !== 'undefined') {
  window.DBPilotAuditCenter = { create: createAuditCenter };
}
