const VIEW_COPY = {
  overview: ['工单概览', '变更工单的统计、近期工单与状态分布。'],
  tickets: ['工单列表', '按状态、类型、实例与关键字筛选变更工单。'],
  create: ['创建工单', '提交 DDL / DML / DCL 变更，SQL 与原因中不得包含密码或凭据。'],
  'ticket-detail': ['工单详情', '查看变更内容、执行日志与审批流历史。'],
};

const STATUS_LABELS = {
  pending: '待审批',
  approved: '已批准',
  rejected: '已拒绝',
  executing: '执行中',
  executed: '已执行',
  failed: '执行失败',
  rolled_back: '已回滚',
};

const TYPE_LABELS = {
  DDL: 'DDL 结构变更',
  DML: 'DML 数据变更',
  DCL: 'DCL 权限变更',
};

const RISK_LABELS = {
  high: '高风险',
  medium: '中风险',
  low: '低风险',
};

const FAILURE_LABELS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '工单不存在或已无权访问',
  conflict: '工单状态已更新，请刷新后重试',
  validation: '工单内容不符合要求，请修改后重试',
  unavailable: '工单服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const SENSITIVE_PATTERN = /(?:\b(?:password|passwd|pwd|token|secret|credential|api[_\s-]?key)\b|connectionstring|dsn)/i;

const INSTANCE_OPTIONS = [
  { id: 'mysql-prod-order-01', name: '订单主库', engine: 'MySQL' },
  { id: 'pgsql-user-primary', name: '用户中心', engine: 'PostgreSQL' },
  { id: 'redis-session-01', name: '缓存集群', engine: 'Redis' },
  { id: 'mysql-analytics-replica', name: '分析从库', engine: 'MySQL' },
];

const ACTION_CONFIRM_COPY = {
  approve: '确认批准该工单？批准后工单进入待执行状态。',
  reject: '确认拒绝该工单？拒绝后需重新提交才能再次审批。',
  execute: '确认执行该变更？执行前请确认审批已通过。',
  rollback: '确认回滚该变更？回滚将执行反向变更并标记为已回滚。',
};

const CURRENT_ACTOR = 'ops-01';

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function ticketStatusLabel(status) {
  return STATUS_LABELS[String(status ?? '')] ?? '未知';
}

export function ticketTypeLabel(type) {
  return TYPE_LABELS[String(type ?? '')] ?? '未知';
}

export function riskLabel(risk) {
  return RISK_LABELS[String(risk ?? '')] ?? '未知';
}

export function workOrderSourceLabel(source) {
  if (source === 'demo') return '演示数据';
  if (source === 'http' || source === 'control-plane') return '控制面服务';
  return '来源未确认';
}

export function workOrderFailureMessage(error, subject = '工单数据') {
  return FAILURE_LABELS[error?.kind] ?? `${subject}加载失败，请稍后重试`;
}

export function buildTicketFilters(entries) {
  const source = entries instanceof Map ? entries : new Map(Object.entries(entries ?? {}));
  return Object.fromEntries([...source].filter(([, value]) => String(value ?? '').trim() !== ''));
}

export function validateTicket(input = {}) {
  const errors = {};
  const title = String(input.title ?? '').trim();
  const sql = String(input.sql ?? '').trim();
  const reason = String(input.reason ?? '').trim();
  const rollbackSql = String(input.rollback_sql ?? '').trim();
  if (!title) errors.title = '请填写工单标题';
  if (!sql) errors.sql = '请填写变更 SQL';
  else if (SENSITIVE_PATTERN.test(sql)) errors.sql = 'SQL 中不能包含密码或凭据';
  if (!reason) errors.reason = '请填写变更原因';
  else if (SENSITIVE_PATTERN.test(reason)) errors.reason = '原因中不能包含密码或凭据';
  if (rollbackSql && SENSITIVE_PATTERN.test(rollbackSql)) errors.rollback_sql = '回滚 SQL 中不能包含密码或凭据';
  return errors;
}

export function renderTicketListMarkup({ items = [], filters = {}, source = '', page = 1, pageSize = 10, total = 0, totalPages = 1 } = {}) {
  const rows = (Array.isArray(items) ? items : []).map((item) => {
    const instanceName = item.instance_name ?? item.instance_id ?? '—';
    const engine = item.engine ?? '';
    return `<div class="wo-table-row" role="row">
      <span><b class="wo-ticket-id">${safeText(item.id)}</b></span>
      <span class="wo-cell-title">${safeText(item.title ?? '—')}</span>
      <span>${safeText(ticketTypeLabel(item.type))}</span>
      <span><i class="wo-engine ${safeText(engine)}">${safeText(engine)}</i>${safeText(instanceName)}</span>
      <span><i class="wo-tag ${safeText(item.risk ?? '')}">${safeText(riskLabel(item.risk))}</i></span>
      <span><i class="wo-tag ${safeText(item.status ?? '')}">${safeText(ticketStatusLabel(item.status))}</i></span>
      <span>${safeText(item.created_by ?? '—')}</span>
      <span>${safeText(formatTime(item.created_at))}</span>
      <span><button type="button" class="wo-btn-secondary wo-row-action" data-wo-ticket="${safeText(item.id)}">查看</button></span>
    </div>`;
  }).join('');
  const sourceBadge = source ? `<span class="wo-source ${safeText(source)}">${safeText(workOrderSourceLabel(source))}</span>` : '';
  const statusOptions = Object.entries(STATUS_LABELS).map(([value, label]) => `<option value="${value}" ${filters.status === value ? 'selected' : ''}>${label}</option>`).join('');
  const typeOptions = Object.entries(TYPE_LABELS).map(([value, label]) => `<option value="${value}" ${filters.type === value ? 'selected' : ''}>${label}</option>`).join('');
  const instanceOptions = INSTANCE_OPTIONS.map((option) => `<option value="${option.id}" ${filters.instance_id === option.id ? 'selected' : ''}>${option.id} · ${option.name}（${option.engine}）</option>`).join('');
  const empty = (Array.isArray(items) ? items : []).length ? '' : '<div class="wo-empty"><h3>暂无工单</h3><p>当前筛选条件下没有可展示的变更工单。</p></div>';
  return `<div class="wo-tickets">
    <div class="wo-section-head"><div><span class="wo-kicker">TICKET LIST</span><h3>工单列表</h3><p>按状态、类型、实例与关键字筛选当前项目内的变更工单。</p></div>${sourceBadge}</div>
    <div class="wo-filter" role="search">
      <label>状态<select class="wo-select" data-wo-filter="status"><option value="">全部</option>${statusOptions}</select></label>
      <label>类型<select class="wo-select" data-wo-filter="type"><option value="">全部</option>${typeOptions}</select></label>
      <label>实例<select class="wo-select" data-wo-filter="instance_id"><option value="">全部</option>${instanceOptions}</select></label>
      <label>搜索<input class="wo-input" data-wo-filter="search" value="${safeText(filters.search ?? '')}" placeholder="编号 / 标题 / SQL" autocomplete="off" /></label>
    </div>
    <article class="wo-panel wo-table-wrap"><div class="wo-table" role="table"><div class="wo-table-row head" role="row"><span>编号</span><span>标题</span><span>类型</span><span>实例</span><span>风险</span><span>状态</span><span>提交人</span><span>提交时间</span><span></span></div>${rows}</div>${empty}</article>
    <div class="wo-pager"><span>共 ${total} 条</span><div><button type="button" class="wo-btn-secondary" data-wo-prev ${page <= 1 ? 'disabled' : ''}>上一页</button><span>第 ${page} / ${totalPages} 页</span><button type="button" class="wo-btn-secondary" data-wo-next ${page >= totalPages ? 'disabled' : ''}>下一页</button></div></div>
  </div>`;
}

export function renderTicketDetailMarkup(ticket = {}, options = {}) {
  const canManage = options.canManage === true;
  if (!ticket || ticket.id == null) {
    return '<div class="wo-empty"><h3>暂无工单详情</h3><p>无法读取该工单的内容，请返回列表重试。</p><button type="button" class="wo-btn-secondary" data-wo-view="tickets">返回工单列表</button></div>';
  }
  const log = Array.isArray(ticket.log) ? ticket.log : [];
  const history = Array.isArray(ticket.history) ? ticket.history : [];
  const meta = [
    ['工单编号', ticket.id],
    ['类型', ticketTypeLabel(ticket.type)],
    ['风险等级', riskLabel(ticket.risk)],
    ['目标实例', ticket.instance_name ? `${ticket.instance_name}（${ticket.engine ?? ''}）` : (ticket.instance_id ?? '—')],
    ['提交人', ticket.created_by],
    ['提交时间', formatTime(ticket.created_at)],
    ['审批人', ticket.approver],
    ['审批时间', formatTime(ticket.approved_at)],
    ['执行人', ticket.executor],
    ['执行时间', formatTime(ticket.executed_at)],
    ['影响行数', ticket.affected_rows == null ? '—' : String(ticket.affected_rows)],
    ['执行耗时', ticket.duration_ms == null ? '—' : `${ticket.duration_ms} ms`],
  ];
  const logMarkup = log.length
    ? `<ol class="wo-timeline">${log.map((entry) => `<li class="level-${safeText(entry.level ?? 'info')}"><time>${safeText(formatTime(entry.at))}</time><span>${safeText(entry.message ?? '')}</span></li>`).join('')}</ol>`
    : '<p>暂无执行日志。</p>';
  const historyMarkup = history.length
    ? `<ol class="wo-timeline">${history.map((entry) => `<li><time>${safeText(formatTime(entry.at))}</time><span><b>${safeText(ticketStatusLabel(entry.status))}</b> · ${safeText(entry.by ?? '—')}：${safeText(entry.note ?? '')}</span></li>`).join('')}</ol>`
    : '<p>暂无审批记录。</p>';
  const rollbackMarkup = ticket.rollback_sql
    ? `<article class="wo-panel"><h4>回滚 SQL</h4><pre class="wo-code rollback">${safeText(ticket.rollback_sql)}</pre></article>`
    : '';
  return `<div class="wo-detail">
    <div class="wo-detail-head"><button type="button" class="wo-back" data-wo-back>← 返回工单列表</button><div><h3>工单详情</h3><p>${safeText(ticket.title ?? ticket.id)}</p></div><span class="wo-tag ${safeText(ticket.status ?? '')}">${safeText(ticketStatusLabel(ticket.status))}</span></div>
    <div class="wo-detail-grid">
      <div class="wo-detail-main">
        <article class="wo-panel"><h4>基本信息</h4><dl class="wo-kv">${meta.map(([key, value]) => `<div><dt>${safeText(key)}</dt><dd>${safeText(value ?? '—')}</dd></div>`).join('')}</dl></article>
        <article class="wo-panel"><h4>变更原因</h4><p class="wo-reason">${safeText(ticket.reason ?? '—')}</p></article>
        <article class="wo-panel"><h4>变更 SQL</h4><pre class="wo-code">${safeText(ticket.sql ?? '')}</pre></article>
        ${rollbackMarkup}
        <article class="wo-panel"><h4>执行日志</h4>${logMarkup}</article>
        <article class="wo-panel"><h4>审批流历史</h4>${historyMarkup}</article>
      </div>
      <aside class="wo-detail-side">
        <article class="wo-panel"><h4>工单操作</h4>${canManage ? actionButtons(ticket) : '<p>当前账号没有该项目的操作权限。</p>'}</article>
      </aside>
    </div>
  </div>`;
}

function actionButtons(ticket) {
  const actions = {
    pending: [['approve', '批准工单', 'wo-btn-primary'], ['reject', '拒绝工单', 'wo-btn-danger']],
    approved: [['execute', '执行变更', 'wo-btn-primary']],
    executed: [['rollback', '回滚变更', 'wo-btn-danger']],
  }[ticket.status] ?? [];
  if (!actions.length) return '<p>当前状态下没有可执行的操作。</p>';
  return `<div class="wo-detail-actions">${actions.map(([action, label, tone]) => `<button type="button" class="${tone}" data-wo-action="${action}" data-wo-ticket="${safeText(ticket.id)}">${label}</button>`).join('')}</div>`;
}

export function createWorkOrderCenter({ root, api, scope, permissions = {}, onToast = () => {} } = {}) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('work order root is required');
  if (!api) throw new TypeError('work order api is required');

  const state = {
    view: 'overview',
    scope: normalizeScope(scope),
    permissions: { manage: permissions.manage === true },
    filters: { status: '', type: '', instance_id: '', search: '' },
    page: 1,
    pageSize: 10,
    source: null,
    overview: null,
    list: null,
    detail: null,
    selectedId: null,
    confirmAction: null,
    loading: false,
    error: null,
  };
  let activeRequest = null;
  let requestVersion = 0;
  let searchTimer = null;

  root.addEventListener('click', (event) => {
    const target = typeof event.target?.closest === 'function'
      ? event.target.closest('[data-wo-view],[data-wo-ticket],[data-wo-back],[data-workorder-retry],[data-wo-action],[data-wo-confirm-yes],[data-wo-confirm-no],[data-wo-prev],[data-wo-next]')
      : null;
    if (!target) return;
    if (target.dataset.woView) {
      open(target.dataset.woView);
    } else if (target.dataset.woTicket) {
      loadDetail(target.dataset.woTicket);
    } else if (target.hasAttribute('data-wo-back')) {
      open('tickets');
    } else if (target.hasAttribute('data-workorder-retry')) {
      reload();
    } else if (target.hasAttribute('data-wo-prev')) {
      state.page = Math.max(1, state.page - 1);
      reload();
    } else if (target.hasAttribute('data-wo-next')) {
      state.page += 1;
      reload();
    } else if (target.dataset.woAction) {
      state.confirmAction = { action: target.dataset.woAction, id: String(target.dataset.woTicket) };
      render();
    } else if (target.hasAttribute('data-wo-confirm-yes')) {
      runConfirmedAction();
    } else if (target.hasAttribute('data-wo-confirm-no')) {
      state.confirmAction = null;
      render();
    }
  });

  root.addEventListener('change', (event) => {
    const target = event.target;
    if (!target?.dataset || !target.dataset.woFilter || target.dataset.woFilter === 'search') return;
    state.filters[target.dataset.woFilter] = target.value;
    state.page = 1;
    reload();
  });

  root.addEventListener('input', (event) => {
    const target = event.target;
    if (!target?.dataset || target.dataset.woFilter !== 'search') return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.filters.search = target.value;
      state.page = 1;
      reload();
    }, 200);
  });

  root.addEventListener('submit', (event) => {
    const form = typeof event.target?.closest === 'function' ? event.target.closest('[data-wo-create-form]') : null;
    if (!form) return;
    event.preventDefault();
    submitCreate(form);
  });

  function open(view = 'overview') {
    const allowed = ['overview', 'tickets', 'create', 'ticket-detail'];
    if (!allowed.includes(view)) view = 'overview';
    if (view === 'create' && !state.permissions.manage) {
      onToast('当前账号没有该项目的操作权限');
      view = state.view === 'create' ? 'tickets' : state.view;
    }
    if (view === 'ticket-detail' && !state.selectedId) view = 'tickets';
    state.view = view;
    if (view !== 'ticket-detail') {
      state.selectedId = null;
      state.detail = null;
    }
    reload();
  }

  function setScope(nextScope) {
    state.scope = normalizeScope(nextScope);
    state.filters = { status: '', type: '', instance_id: '', search: '' };
    state.page = 1;
    state.selectedId = null;
    state.detail = null;
    state.overview = null;
    state.list = null;
    state.confirmAction = null;
    reload();
  }

  function loadDetail(id) {
    state.selectedId = String(id);
    state.view = 'ticket-detail';
    reload();
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
      let result;
      if (state.view === 'tickets') {
        result = await api.listTickets(state.scope, buildTicketFilters({ ...state.filters, page: state.page, pageSize: state.pageSize }), controller.signal);
      } else if (state.view === 'ticket-detail') {
        if (!state.selectedId) state.view = 'tickets';
        result = state.view === 'tickets'
          ? await api.listTickets(state.scope, buildTicketFilters({ ...state.filters, page: state.page, pageSize: state.pageSize }), controller.signal)
          : await api.getTicket(state.scope, state.selectedId, controller.signal);
      } else if (state.view === 'create') {
        state.loading = false;
        render();
        return;
      } else {
        result = await api.getOverview(state.scope, controller.signal);
      }
      if (version !== requestVersion || controller.signal.aborted) return;
      if (state.view === 'tickets') state.list = result;
      else if (state.view === 'ticket-detail') state.detail = result;
      else state.overview = result;
      state.source = result?.source ?? null;
      state.loading = false;
      render();
    } catch (error) {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.loading = false;
      state.error = error;
      render();
    }
  }

  async function runConfirmedAction() {
    const confirm = state.confirmAction;
    if (!confirm) return;
    state.confirmAction = null;
    const { action, id } = confirm;
    const signal = activeRequest?.signal;
    try {
      let message = '操作已完成';
      if (action === 'approve') {
        await api.approveTicket(state.scope, id, { approver: CURRENT_ACTOR, note: '' }, signal);
        message = '工单已批准';
      } else if (action === 'reject') {
        await api.rejectTicket(state.scope, id, { approver: CURRENT_ACTOR, note: '' }, signal);
        message = '工单已拒绝';
      } else if (action === 'execute') {
        await api.executeTicket(state.scope, id, { executor: CURRENT_ACTOR }, signal);
        message = '变更已执行';
      } else if (action === 'rollback') {
        await api.rollbackTicket(state.scope, id, { executor: CURRENT_ACTOR }, signal);
        message = '变更已回滚';
      }
      onToast(message);
      await loadDetail(id);
    } catch (error) {
      if (error?.name === 'AbortError') return;
      onToast(workOrderFailureMessage(error, '工单'));
      render();
    }
  }

  async function submitCreate(form) {
    if (!state.permissions.manage) return;
    const data = new FormData(form);
    const input = {
      title: String(data.get('title') ?? '').trim(),
      type: String(data.get('type') ?? 'DDL').trim(),
      instance_id: String(data.get('instance_id') ?? '').trim(),
      risk: String(data.get('risk') ?? 'medium').trim(),
      sql: String(data.get('sql') ?? ''),
      rollback_sql: String(data.get('rollback_sql') ?? ''),
      reason: String(data.get('reason') ?? '').trim(),
      created_by: CURRENT_ACTOR,
    };
    const instance = INSTANCE_OPTIONS.find((option) => option.id === input.instance_id);
    input.engine = instance?.engine ?? '';
    const errors = validateTicket(input);
    const output = form.querySelector('[data-wo-form-errors]');
    if (Object.keys(errors).length) {
      if (output) output.textContent = Object.values(errors).join(' ');
      return;
    }
    if (output) output.textContent = '';
    form.querySelectorAll('button, input, select, textarea').forEach((element) => { element.disabled = true; });
    try {
      await api.createTicket(state.scope, input, activeRequest?.signal);
      onToast('工单已提交');
      open('tickets');
    } catch (error) {
      if (error?.name === 'AbortError') return;
      if (output) output.textContent = workOrderFailureMessage(error, '工单');
      form.querySelectorAll('button, input, select, textarea').forEach((element) => { element.disabled = false; });
    }
  }

  function abortActive() {
    clearTimeout(searchTimer);
    if (activeRequest) {
      activeRequest.abort();
      activeRequest = null;
    }
  }

  function render() {
    root.innerHTML = renderWorkbench(state);
  }

  render();
  return {
    open,
    setScope,
    getState: () => ({ ...state, scope: { ...state.scope }, filters: { ...state.filters }, permissions: { ...state.permissions } }),
  };
}

function renderWorkbench(state) {
  const [title, description] = VIEW_COPY[state.view] ?? VIEW_COPY.overview;
  const source = state.source ? `<span class="wo-source ${safeText(state.source)}">${safeText(workOrderSourceLabel(state.source))}</span>` : '';
  const body = state.error
    ? renderError(state.error)
    : state.view === 'tickets'
      ? renderTicketsView(state)
      : state.view === 'create'
        ? renderCreateView(state)
        : state.view === 'ticket-detail'
          ? renderDetailView(state)
          : renderOverviewView(state);
  return `<section class="wo-center" data-wo-view="${safeText(state.view)}" aria-label="工单管理">
    <div class="wo-hero"><div><span class="eyebrow">DBPILOT · 工单管理</span><h2>${safeText(title)}</h2><p>${safeText(description)}</p></div><div class="wo-hero-meta">${source}<span class="wo-scope">${safeText(state.scope.tenantId)} / ${safeText(state.scope.projectId)}</span></div></div>
    <nav class="wo-tabs" aria-label="工单视图"><button type="button" class="${state.view === 'overview' ? 'active' : ''}" data-wo-view="overview">工单概览</button><button type="button" class="${state.view === 'tickets' || state.view === 'ticket-detail' ? 'active' : ''}" data-wo-view="tickets">工单列表</button>${state.permissions.manage ? '<button type="button" class="wo-tab-create" data-wo-view="create">创建工单</button>' : ''}</nav>
    ${state.loading && !state.error && state.view !== 'create' ? '<div class="wo-progress" role="status">正在加载…</div>' : ''}
    ${body}
  </section>`;
}

function renderOverviewView(state) {
  if (state.loading && !state.overview) {
    return '<div class="wo-state" role="status"><span class="wo-spinner"></span><h3>正在加载工单概览</h3><p>统计与近期工单即将呈现。</p></div>';
  }
  const overview = state.overview ?? {};
  const stats = overview.stats ?? {};
  const recent = Array.isArray(overview.recent) ? overview.recent : [];
  const distribution = overview.distribution ?? {};
  const statCards = [
    ['待审批', stats.pending ?? 0, 'pending', '等待审批人处理的变更工单'],
    ['执行中', stats.executing ?? 0, 'executing', '正在目标实例执行的变更'],
    ['今日完成', stats.executed_today ?? 0, 'executed', '今日执行完成的变更工单'],
    ['回滚次数', stats.rolled_back ?? 0, 'rolled_back', '累计回滚的变更工单'],
  ].map(([label, value, tone, hint]) => `<article class="wo-stat-card ${tone}"><span>${safeText(label)}</span><strong>${safeText(String(value))}</strong><p>${safeText(hint)}</p><i></i></article>`).join('');
  const recentRows = recent.length
    ? recent.map((ticket) => `<button type="button" class="wo-recent-row" data-wo-ticket="${safeText(ticket.id)}"><span><b>${safeText(ticket.title ?? ticket.id)}</b><small>${safeText(ticket.id)} · ${safeText(ticket.instance_name ?? ticket.instance_id ?? '')}</small></span><span>${safeText(ticketTypeLabel(ticket.type))}</span><i class="wo-tag ${safeText(ticket.risk ?? '')}">${safeText(riskLabel(ticket.risk))}</i><i class="wo-tag ${safeText(ticket.status ?? '')}">${safeText(ticketStatusLabel(ticket.status))}</i><span>${safeText(ticket.created_by ?? '')}</span></button>`).join('')
    : '<div class="wo-empty"><h3>暂无近期工单</h3><p>当前项目还没有变更工单。</p></div>';
  const distributionKeys = [['pending', '待审批'], ['approved', '已批准'], ['executing', '执行中'], ['executed', '已执行'], ['failed', '执行失败'], ['rolled_back', '已回滚'], ['rejected', '已拒绝']];
  const total = distributionKeys.reduce((sum, [key]) => sum + (Number(distribution[key]) || 0), 0);
  const bars = distributionKeys.map(([key, label]) => {
    const count = Number(distribution[key]) || 0;
    const percent = total ? Math.round(count / total * 100) : 0;
    return `<div class="wo-dist-row"><span>${safeText(label)}</span><i class="wo-dist-bar"><b class="${key}" style="width:${percent}%"></b></i><span>${count}</span></div>`;
  }).join('');
  return `<div class="wo-overview">
    <div class="wo-section-head"><div><span class="wo-kicker">OVERVIEW</span><h3>工单概览</h3><p>变更工单的统计、近期工单与状态分布。</p></div><span class="wo-source ${safeText(overview.source ?? '')}">${safeText(workOrderSourceLabel(overview.source))}</span></div>
    <div class="wo-stats">${statCards}</div>
    <div class="wo-overview-grid">
      <article class="wo-panel"><div class="wo-panel-head"><div><span class="wo-kicker">RECENT</span><h3>近期工单</h3></div><button type="button" class="wo-btn-secondary" data-wo-view="tickets">查看全部 →</button></div>${recentRows}</article>
      <article class="wo-panel"><div class="wo-panel-head"><div><span class="wo-kicker">DISTRIBUTION</span><h3>状态分布</h3></div></div>${total ? `<div class="wo-dist">${bars}</div>` : '<p>暂无工单数据。</p>'}</article>
    </div>
  </div>`;
}

function renderTicketsView(state) {
  if (state.loading && !state.list) {
    return '<div class="wo-state" role="status"><span class="wo-spinner"></span><h3>正在加载工单列表</h3><p>筛选条件变更后将重新请求当前项目内的工单。</p></div>';
  }
  const list = state.list ?? {};
  return renderTicketListMarkup({
    items: list.items ?? [],
    filters: state.filters,
    source: list.source ?? state.source,
    page: Number(list.page ?? state.page) || 1,
    pageSize: Number(list.pageSize ?? state.pageSize) || 10,
    total: Number(list.total ?? 0) || 0,
    totalPages: Number(list.totalPages ?? 1) || 1,
  });
}

function renderDetailView(state) {
  if (state.loading && !state.detail) {
    return '<div class="wo-state" role="status"><span class="wo-spinner"></span><h3>正在加载工单详情</h3><p>读取变更内容与执行日志，请稍候。</p></div>';
  }
  if (!state.detail) {
    return '<div class="wo-state"><h3>尚未选择工单</h3><p>从工单列表选择一个工单查看详情。</p><button type="button" class="wo-btn-primary" data-wo-view="tickets">返回工单列表</button></div>';
  }
  const confirmBar = state.confirmAction ? renderConfirmBar(state.confirmAction) : '';
  return `${confirmBar}${renderTicketDetailMarkup(state.detail, { canManage: state.permissions.manage })}`;
}

function renderCreateView(state) {
  if (!state.permissions.manage) {
    return '<div class="wo-state"><h3>当前账号没有该项目的操作权限</h3><p>创建工单需要项目管理权限。</p><button type="button" class="wo-btn-primary" data-wo-view="tickets">返回工单列表</button></div>';
  }
  const typeOptions = Object.entries(TYPE_LABELS).map(([value, label]) => `<option value="${value}">${label}</option>`).join('');
  const instanceOptions = INSTANCE_OPTIONS.map((option) => `<option value="${option.id}">${option.id} · ${option.name}（${option.engine}）</option>`).join('');
  const riskOptions = [['high', '高风险'], ['medium', '中风险'], ['low', '低风险']].map(([value, label]) => `<option value="${value}">${label}</option>`).join('');
  return `<div class="wo-create">
    <div class="wo-section-head"><div><span class="wo-kicker">NEW TICKET</span><h3>创建工单</h3><p>提交变更内容，审批通过后由执行人执行。SQL 与原因中不得包含密码或凭据。</p></div></div>
    <form class="wo-panel wo-form" data-wo-create-form novalidate>
      <label>工单标题<input class="wo-input" name="title" required maxlength="120" placeholder="例如：订单主库 orders 表增加渠道索引" autocomplete="off" /></label>
      <div class="wo-form-grid">
        <label>变更类型<select class="wo-select" name="type" required>${typeOptions}</select></label>
        <label>目标实例<select class="wo-select" name="instance_id" required>${instanceOptions}</select></label>
        <label>风险等级<select class="wo-select" name="risk" required>${riskOptions}</select></label>
      </div>
      <label>变更 SQL<textarea class="wo-input wo-sql-input" name="sql" rows="7" required placeholder="输入待执行的 DDL / DML / DCL 语句" spellcheck="false"></textarea></label>
      <label>回滚 SQL<textarea class="wo-input" name="rollback_sql" rows="4" placeholder="可选的回滚语句；不填写时代表无需回滚" spellcheck="false"></textarea></label>
      <label>变更原因<textarea class="wo-input" name="reason" rows="4" required placeholder="说明变更目的与影响范围" spellcheck="false"></textarea></label>
      <p class="wo-form-errors" data-wo-form-errors role="alert" aria-live="polite"></p>
      <div class="wo-form-actions"><button type="button" class="wo-btn-secondary" data-wo-view="tickets">取消</button><button type="submit" class="wo-btn-primary">提交工单</button></div>
    </form>
  </div>`;
}

function renderError(error) {
  const forbidden = error?.kind === 'forbidden';
  return `<div class="wo-error" role="alert"><span class="wo-error-icon">${forbidden ? '⌾' : '!'}</span><h3>${forbidden ? '无法查看工单' : '工单数据加载失败'}</h3><p>${safeText(workOrderFailureMessage(error, '工单数据'))}</p><button type="button" class="wo-btn-primary" data-workorder-retry>重试</button></div>`;
}

function renderConfirmBar(confirm) {
  const message = ACTION_CONFIRM_COPY[confirm.action] ?? '确认执行该操作？';
  return `<div class="wo-confirm" role="alertdialog" aria-label="确认操作"><p>${safeText(message)}</p><div><button type="button" class="wo-btn-primary" data-wo-confirm-yes>确认</button><button type="button" class="wo-btn-secondary" data-wo-confirm-no>取消</button></div></div>`;
}

function normalizeScope(scope) {
  return {
    tenantId: typeof scope?.tenantId === 'string' && scope.tenantId.trim() ? scope.tenantId.trim() : '未配置',
    projectId: typeof scope?.projectId === 'string' && scope.projectId.trim() ? scope.projectId.trim() : '未配置',
  };
}

function formatTime(value) {
  if (value == null || String(value).trim() === '') return '—';
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
    : '—';
}

if (typeof window !== 'undefined') {
  window.DBPilotWorkOrderCenter = { create: createWorkOrderCenter };
}
