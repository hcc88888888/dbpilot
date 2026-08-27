const VIEW_COPY = {
  overview: ['锁透视', '锁等待、死锁与事务回放的核心洞察。'],
  locks: ['锁事件列表', '按类型、实例、状态与关键字筛选锁等待与死锁事件。'],
  'lock-detail': ['锁事件详情', '查看阻塞者与等待者、锁对象与死锁回放。'],
};

const TYPE_LABELS = {
  'lock-wait': '锁等待',
  deadlock: '死锁',
  'long-txn': '长事务',
  uncommitted: '未提交事务',
};

const STATUS_LABELS = {
  active: '进行中',
  resolved: '已解除',
};

const MODE_LABELS = {
  X: '排他锁',
  S: '共享锁',
  IX: '意向排他',
  IS: '意向共享',
  RX: '行排他',
  RS: '行共享',
};

const SESSION_STATE_LABELS = {
  sleep: '休眠',
  running: '运行中',
  waiting: '等待中',
};

const FAILURE_LABELS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '锁事件不存在或已无权访问',
  conflict: '锁事件状态已更新，请刷新后重试',
  validation: '锁事件查询参数不符合要求，请修改后重试',
  unavailable: '锁透视服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const INSTANCE_OPTIONS = [
  { instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL' },
  { instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL' },
  { instance_id: 'oracle-finance-01', instance_name: '财务核心库', engine: 'Oracle' },
];

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function lockTypeLabel(type) {
  return TYPE_LABELS[String(type ?? '')] ?? '未知';
}

export function lockStatusLabel(status) {
  return STATUS_LABELS[String(status ?? '')] ?? '未知';
}

export function lockModeLabel(mode) {
  const key = String(mode ?? '');
  if (MODE_LABELS[key]) return MODE_LABELS[key];
  return key === '' ? '未知' : key;
}

export function formatDuration(value) {
  if (value == null || String(value).trim() === '') return '—';
  const ms = Number(value);
  if (!Number.isFinite(ms) || ms < 0) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${trimDuration(seconds)}s`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${trimDuration(minutes)}min`;
  const hours = minutes / 60;
  if (hours < 24) return `${trimDuration(hours)}h`;
  return `${trimDuration(hours / 24)}d`;
}

export function locksSourceLabel(source) {
  if (source === 'demo') return '演示数据';
  if (source === 'http' || source === 'control-plane') return '控制面服务';
  return '来源未确认';
}

export function locksFailureMessage(error, subject = '锁透视数据') {
  return FAILURE_LABELS[error?.kind] ?? `${subject}加载失败，请稍后重试`;
}

export function buildLockFilters(entries) {
  const source = entries instanceof Map ? entries : new Map(Object.entries(entries ?? {}));
  return Object.fromEntries([...source].filter(([, value]) => String(value ?? '').trim() !== ''));
}

export function renderLockListMarkup({ items = [], filters = {}, source = '', page = 1, pageSize = 12, total = 0, totalPages = 1, instances = INSTANCE_OPTIONS } = {}) {
  const rows = (Array.isArray(items) ? items : []).map((item) => `<div class="lck-table-row" role="row">
      <span><i class="lck-tag ${safeText(item.type ?? '')}">${safeText(lockTypeLabel(item.type))}</i></span>
      <span class="lck-cell-summary" title="${safeText(item.summary ?? '')}">${safeText(item.summary ?? '—')}</span>
      <span><b class="lck-instance">${safeText(item.instance_name ?? item.instance_id ?? '—')}</b><small>${safeText(item.engine ?? '')}</small></span>
      <span>${safeText(formatTime(item.first_seen))}</span>
      <span>${safeText(formatDuration(item.duration_ms))}</span>
      <span><i class="lck-tag ${safeText(item.status ?? '')}">${safeText(lockStatusLabel(item.status))}</i></span>
      <span><button type="button" class="lck-btn-secondary lck-row-action" data-locks-item="${safeText(item.id)}">查看</button></span>
    </div>`).join('');
  const sourceBadge = source ? `<span class="lck-source ${safeText(source)}">${safeText(locksSourceLabel(source))}</span>` : '';
  const typeOptions = Object.entries(TYPE_LABELS).map(([value, label]) => `<option value="${value}" ${filters.type === value ? 'selected' : ''}>${label}</option>`).join('');
  const statusOptions = Object.entries(STATUS_LABELS).map(([value, label]) => `<option value="${value}" ${filters.status === value ? 'selected' : ''}>${label}</option>`).join('');
  const instanceOptions = (Array.isArray(instances) ? instances : []).map((option) => `<option value="${safeText(option.instance_id)}" ${filters.instance_id === option.instance_id ? 'selected' : ''}>${safeText(option.instance_name ?? option.instance_id)}（${safeText(option.engine ?? '')}）</option>`).join('');
  const empty = (Array.isArray(items) ? items : []).length ? '' : '<div class="lck-empty"><h3>暂无锁事件</h3><p>当前筛选条件下没有可展示的锁事件。</p></div>';
  return `<div class="lck-locks">
    <div class="lck-section-head"><div><span class="lck-kicker">LOCK EVENTS</span><h3>锁事件列表</h3><p>按类型、实例、状态与关键字筛选当前项目内的锁等待、死锁与长事务。</p></div>${sourceBadge}</div>
    <div class="lck-filter" role="search">
      <label>类型<select class="lck-select" data-locks-filter="type"><option value="">全部</option>${typeOptions}</select></label>
      <label>实例<select class="lck-select" data-locks-filter="instance_id"><option value="">全部</option>${instanceOptions}</select></label>
      <label>状态<select class="lck-select" data-locks-filter="status"><option value="">全部</option>${statusOptions}</select></label>
      <label>搜索<input class="lck-input lck-search" data-locks-filter="search" value="${safeText(filters.search ?? '')}" placeholder="编号 / 摘要 / 实例 / SQL" autocomplete="off" /></label>
    </div>
    <article class="lck-panel lck-table-wrap"><div class="lck-table" role="table"><div class="lck-table-row head" role="row">
      <span>类型</span><span>摘要</span><span>实例</span><span>首次出现</span><span>持续时长</span><span>状态</span><span></span>
    </div>${rows}</div>${empty}</article>
    <div class="lck-pager"><span>共 ${total} 条</span><div><button type="button" class="lck-btn-secondary" data-locks-prev ${page <= 1 ? 'disabled' : ''}>上一页</button><span>第 ${page} / ${totalPages} 页</span><button type="button" class="lck-btn-secondary" data-locks-next ${page >= totalPages ? 'disabled' : ''}>下一页</button></div></div>
  </div>`;
}

export function renderLockDetailMarkup(item = {}) {
  if (!item || item.id == null) {
    return '<div class="lck-empty"><h3>暂无锁事件详情</h3><p>无法读取该锁事件，请返回列表重试。</p><button type="button" class="lck-btn-secondary" data-locks-view="locks">返回锁事件列表</button></div>';
  }
  const blocker = item.blocker && typeof item.blocker === 'object' ? item.blocker : {};
  const waiter = item.waiter && typeof item.waiter === 'object' ? item.waiter : {};
  const objects = Array.isArray(item.objects) ? item.objects : [];
  const meta = [
    ['实例', item.instance_name ? `${item.instance_name}（${item.engine ?? ''}）` : (item.instance_id ?? '—')],
    ['首次出现', formatTime(item.first_seen)],
    ['最后出现', formatTime(item.last_seen)],
    ['持续时长', formatDuration(item.duration_ms)],
  ];
  const objectRows = objects.length
    ? objects.map((entry) => {
      const mode = String(entry.lock_mode ?? '');
      const strong = mode === 'X' || mode === 'RX';
      const objectName = entry.schema ? `${entry.schema}.${entry.table}` : String(entry.table ?? '—');
      return `<div class="lck-table-row" role="row">
        <span><b class="lck-object-name">${safeText(objectName)}</b></span>
        <span><i class="lck-mode ${strong ? 'strong' : ''}">${safeText(lockModeLabel(entry.lock_mode))}</i></span>
        <span>${entry.index ? safeText(entry.index) : '—'}</span>
      </div>`;
    }).join('')
    : '<div class="lck-empty compact"><p>暂无锁对象信息。</p></div>';
  const replay = item.type === 'deadlock' && item.detail
    ? `<article class="lck-panel lck-replay"><div class="lck-panel-head"><div><span class="lck-kicker">REPLAY</span><h3>死锁回放</h3></div></div><pre class="lck-code replay">${safeText(item.detail)}</pre></article>`
    : '';
  return `<div class="lck-detail">
    <div class="lck-detail-head"><button type="button" class="lck-back" data-locks-back>← 返回锁事件列表</button><div><h3>锁事件详情</h3><p>${safeText(item.id)}</p></div><i class="lck-tag ${safeText(item.type ?? '')}">${safeText(lockTypeLabel(item.type))}</i><i class="lck-tag ${safeText(item.status ?? '')}">${safeText(lockStatusLabel(item.status))}</i></div>
    <article class="lck-panel lck-meta-panel"><dl class="lck-kv">${meta.map(([key, value]) => `<div><dt>${safeText(key)}</dt><dd>${safeText(value ?? '—')}</dd></div>`).join('')}</dl></article>
    <div class="lck-duel">
      <article class="lck-panel lck-side blocker"><div class="lck-panel-head"><div><span class="lck-kicker">BLOCKER</span><h3>阻塞者</h3></div><i class="lck-session-state ${safeText(blocker.state ?? '')}">${safeText(sessionStateLabel(blocker.state))}</i></div>
        <dl class="lck-facts"><div><dt>会话 ID</dt><dd>${safeText(blocker.session_id ?? '—')}</dd></div><div><dt>用户</dt><dd>${safeText(blocker.user ?? '—')}</dd></div><div><dt>主机</dt><dd>${safeText(blocker.host ?? '—')}</dd></div><div><dt>事务年龄</dt><dd>${safeText(formatDuration(blocker.txn_age_ms))}</dd></div></dl>
        <pre class="lck-code">${safeText(blocker.sql ?? '')}</pre>
      </article>
      <article class="lck-panel lck-side waiter"><div class="lck-panel-head"><div><span class="lck-kicker">WAITER</span><h3>等待者</h3></div><i class="lck-session-state ${safeText(waiter.state ?? '')}">${safeText(sessionStateLabel(waiter.state))}</i></div>
        <dl class="lck-facts"><div><dt>会话 ID</dt><dd>${safeText(waiter.session_id ?? '—')}</dd></div><div><dt>用户</dt><dd>${safeText(waiter.user ?? '—')}</dd></div><div><dt>主机</dt><dd>${safeText(waiter.host ?? '—')}</dd></div><div><dt>等待时长</dt><dd>${safeText(formatDuration(waiter.wait_ms))}</dd></div></dl>
        <pre class="lck-code">${safeText(waiter.sql ?? '')}</pre>
      </article>
    </div>
    <article class="lck-panel lck-object"><div class="lck-panel-head"><div><span class="lck-kicker">LOCKED OBJECTS</span><h3>锁对象</h3></div><span>红色强调排他锁</span></div><div class="lck-table" role="table"><div class="lck-table-row head" role="row"><span>锁对象</span><span>锁模式</span><span>索引</span></div>${objectRows}</div></article>
    <article class="lck-panel lck-event-timeline-panel"><div class="lck-panel-head"><div><span class="lck-kicker">TIMELINE</span><h3>事件时间线</h3></div><span>${safeText(formatDuration(item.duration_ms))}</span></div>
      <ol class="lck-event-timeline">
        <li class="start"><time>${safeText(formatTime(item.first_seen))}</time><span>首次出现 · 锁事件开始</span></li>
        <li class="span"><span>持续 ${safeText(formatDuration(item.duration_ms))}</span></li>
        <li class="end"><time>${safeText(formatTime(item.last_seen))}</time><span>最后出现 · ${safeText(lockStatusLabel(item.status))}</span></li>
      </ol>
    </article>
    ${replay}
  </div>`;
}

export function renderLockOverview(value = {}) {
  const stats = value.stats ?? {};
  const active = Array.isArray(value.active) ? value.active : [];
  const deadlocks = Array.isArray(value.deadlocks) ? value.deadlocks : [];
  const statCards = [
    ['当前锁等待', String(stats.lock_waits ?? 0), 'lock-wait'],
    ['今日死锁', String(stats.deadlocks_today ?? 0), 'deadlock'],
    ['长事务', String(stats.long_txns ?? 0), 'long-txn'],
    ['未提交事务', String(stats.uncommitted ?? 0), 'uncommitted'],
  ].map(([label, cardValue, tone]) => `<article class="lck-stat-card ${tone}"><span>${safeText(label)}</span><strong>${safeText(cardValue)}</strong><i></i></article>`).join('');
  const activeRows = active.length
    ? active.map((item) => `<button type="button" class="lck-active-row" data-locks-item="${safeText(item.id)}"><i class="lck-tag ${safeText(item.type ?? '')}">${safeText(lockTypeLabel(item.type))}</i><span><b>${safeText(item.summary ?? '')}</b><small>${safeText(item.instance_name ?? item.instance_id ?? '')} · ${safeText(item.engine ?? '')}</small></span><span>${safeText(formatDuration(item.duration_ms))}</span><i class="lck-tag ${safeText(item.status ?? '')}">${safeText(lockStatusLabel(item.status))}</i></button>`).join('')
    : '<div class="lck-empty"><h3>暂无活跃锁事件</h3><p>当前项目没有进行中的锁等待或死锁。</p></div>';
  const timeline = deadlocks.length
    ? `<ol class="lck-timeline">${deadlocks.map((item) => `<li class="${safeText(item.status)}"><time>${safeText(formatTime(item.first_seen))}</time><span><b>${safeText(lockTypeLabel(item.type))}</b> · ${safeText(item.summary ?? '')}</span><small>${safeText(item.instance_name ?? item.instance_id ?? '')} · ${safeText(formatDuration(item.duration_ms))}</small></li>`).join('')}</ol>`
    : '<div class="lck-empty compact"><p>暂无死锁记录。</p></div>';
  return `<div class="lck-overview">
    <div class="lck-section-head"><div><span class="lck-kicker">OVERVIEW</span><h3>锁透视概览</h3><p>当前锁等待与长事务为进行中事件，今日死锁按首次出现时间排序。</p></div><span class="lck-source ${safeText(value.source ?? '')}">${safeText(locksSourceLabel(value.source))}</span></div>
    <div class="lck-stats">${statCards}</div>
    <div class="lck-overview-grid">
      <article class="lck-panel"><div class="lck-panel-head"><div><span class="lck-kicker">ACTIVE</span><h3>活跃锁事件</h3></div><button type="button" class="lck-btn-secondary" data-locks-view="locks">查看全部 →</button></div>${activeRows}</article>
      <article class="lck-panel"><div class="lck-panel-head"><div><span class="lck-kicker">DEADLOCK</span><h3>死锁时间线</h3></div></div>${timeline}</article>
    </div>
  </div>`;
}

export function createLocksCenter({ root, api, scope, permissions = {}, onToast = () => {} } = {}) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('locks root is required');
  if (!api) throw new TypeError('locks api is required');

  const state = {
    view: 'overview',
    scope: normalizeScope(scope),
    permissions: { manage: permissions.manage === true },
    filters: { type: '', instance_id: '', status: '', search: '' },
    page: 1,
    pageSize: 12,
    instances: INSTANCE_OPTIONS,
    source: null,
    overview: null,
    list: null,
    detail: null,
    selectedId: null,
    loading: false,
    error: null,
  };
  let activeRequest = null;
  let requestVersion = 0;
  let searchTimer = null;

  root.addEventListener('click', (event) => {
    const target = typeof event.target?.closest === 'function'
      ? event.target.closest('[data-locks-view],[data-locks-item],[data-locks-back],[data-locks-retry],[data-locks-prev],[data-locks-next]')
      : null;
    if (!target) return;
    if (target.dataset.locksView) {
      open(target.dataset.locksView);
    } else if (target.dataset.locksItem) {
      loadDetail(target.dataset.locksItem);
    } else if (target.hasAttribute('data-locks-back')) {
      open('locks');
    } else if (target.hasAttribute('data-locks-retry')) {
      reload();
    } else if (target.hasAttribute('data-locks-prev')) {
      state.page = Math.max(1, state.page - 1);
      reload();
    } else if (target.hasAttribute('data-locks-next')) {
      state.page += 1;
      reload();
    }
  });

  root.addEventListener('change', (event) => {
    const target = event.target;
    if (!target?.dataset || !target.dataset.locksFilter || target.dataset.locksFilter === 'search') return;
    state.filters[target.dataset.locksFilter] = target.value;
    state.page = 1;
    reload();
  });

  root.addEventListener('input', (event) => {
    const target = event.target;
    if (!target?.dataset || target.dataset.locksFilter !== 'search') return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.filters.search = target.value;
      state.page = 1;
      reload();
    }, 200);
  });

  function open(view = 'overview') {
    const allowed = ['overview', 'locks', 'lock-detail'];
    if (!allowed.includes(view)) view = 'overview';
    if (view === 'lock-detail' && !state.selectedId) view = 'locks';
    state.view = view;
    if (view !== 'lock-detail') {
      state.selectedId = null;
      state.detail = null;
    }
    reload();
  }

  function setScope(nextScope) {
    state.scope = normalizeScope(nextScope);
    state.filters = { type: '', instance_id: '', status: '', search: '' };
    state.page = 1;
    state.selectedId = null;
    state.detail = null;
    state.overview = null;
    state.list = null;
    state.source = null;
    reload();
  }

  function loadDetail(id) {
    state.selectedId = String(id);
    state.view = 'lock-detail';
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
      if (state.view === 'locks') {
        result = await api.listLocks(state.scope, buildLockFilters({ ...state.filters, page: state.page, pageSize: state.pageSize }), controller.signal);
      } else if (state.view === 'lock-detail') {
        if (!state.selectedId) state.view = 'locks';
        result = state.view === 'locks'
          ? await api.listLocks(state.scope, buildLockFilters({ ...state.filters, page: state.page, pageSize: state.pageSize }), controller.signal)
          : await api.getLock(state.scope, state.selectedId, controller.signal);
      } else {
        result = await api.getOverview(state.scope, controller.signal);
      }
      if (version !== requestVersion || controller.signal.aborted) return;
      if (state.view === 'locks') state.list = result;
      else if (state.view === 'lock-detail') state.detail = result;
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

  function abortActive() {
    clearTimeout(searchTimer);
    if (activeRequest) {
      activeRequest.abort();
      activeRequest = null;
    }
  }

  function render() {
    root.innerHTML = renderLockWorkbench(state);
  }

  render();
  return {
    open,
    setScope,
    refresh: reload,
    getState: () => ({ ...state, scope: { ...state.scope }, filters: { ...state.filters }, permissions: { ...state.permissions } }),
  };
}

function renderLockWorkbench(state) {
  const [title, description] = VIEW_COPY[state.view] ?? VIEW_COPY.overview;
  const source = state.source ? `<span class="lck-source ${safeText(state.source)}">${safeText(locksSourceLabel(state.source))}</span>` : '';
  const body = state.error
    ? renderLockError(state.error)
    : state.view === 'locks'
      ? renderLockListView(state)
      : state.view === 'lock-detail'
        ? renderLockDetailView(state)
        : renderLockOverviewView(state);
  return `<section class="lck-center" data-locks-view="${safeText(state.view)}" aria-label="锁透视">
    <div class="lck-hero"><div><span class="eyebrow">DBPILOT · LOCK INSIGHT</span><h2>${safeText(title)}</h2><p>${safeText(description)}</p></div><div class="lck-hero-meta">${source}<span class="lck-scope">${safeText(state.scope.tenantId)} / ${safeText(state.scope.projectId)}</span></div></div>
    <nav class="lck-tabs" aria-label="锁透视视图"><button type="button" class="${state.view === 'overview' ? 'active' : ''}" data-locks-view="overview">锁概览</button><button type="button" class="${state.view === 'locks' || state.view === 'lock-detail' ? 'active' : ''}" data-locks-view="locks">锁事件列表</button></nav>
    ${state.loading && !state.error ? '<div class="lck-progress" role="status">正在加载…</div>' : ''}
    ${body}
  </section>`;
}

function renderLockOverviewView(state) {
  if (state.loading && !state.overview) {
    return '<div class="lck-state" role="status"><span class="lck-spinner"></span><h3>正在加载锁透视概览</h3><p>统计与活跃锁事件即将呈现。</p></div>';
  }
  return renderLockOverview(state.overview ?? {});
}

function renderLockListView(state) {
  if (state.loading && !state.list) {
    return '<div class="lck-state" role="status"><span class="lck-spinner"></span><h3>正在加载锁事件列表</h3><p>筛选条件变更后将重新请求当前项目内的锁事件。</p></div>';
  }
  const list = state.list ?? {};
  return renderLockListMarkup({
    items: list.items ?? [],
    filters: state.filters,
    source: list.source ?? state.source,
    page: Number(list.page ?? state.page) || 1,
    pageSize: Number(list.pageSize ?? state.pageSize) || 12,
    total: Number(list.total ?? 0) || 0,
    totalPages: Number(list.totalPages ?? 1) || 1,
    instances: state.instances ?? [],
  });
}

function renderLockDetailView(state) {
  if (state.loading && !state.detail) {
    return '<div class="lck-state" role="status"><span class="lck-spinner"></span><h3>正在加载锁事件详情</h3><p>读取阻塞者与等待者信息，请稍候。</p></div>';
  }
  if (!state.detail) {
    return '<div class="lck-state"><h3>尚未选择锁事件</h3><p>从列表选择一个锁事件查看详情。</p><button type="button" class="lck-btn-primary" data-locks-view="locks">返回锁事件列表</button></div>';
  }
  return renderLockDetailMarkup(state.detail);
}

function renderLockError(error) {
  const forbidden = error?.kind === 'forbidden';
  return `<div class="lck-state error" role="alert"><span class="lck-state-icon">${forbidden ? '⌾' : '!'}</span><h3>${forbidden ? '无法查看锁透视数据' : '锁透视数据加载失败'}</h3><p>${safeText(locksFailureMessage(error))}</p><button type="button" class="lck-btn-primary" data-locks-retry>重试</button></div>`;
}

function sessionStateLabel(state) {
  return SESSION_STATE_LABELS[String(state ?? '')] ?? String(state ?? '未知');
}

function trimDuration(value) {
  return String(Math.round(value * 10) / 10);
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
  window.DBPilotLocksCenter = { create: createLocksCenter };
}
