const STATUS_LABELS = {
  completed: '已完成',
  running: '对比中',
};

const OBJECT_STATUS_LABELS = {
  added: '新增',
  removed: '删除',
  changed: '变更',
  identical: '一致',
};

const OBJECT_TYPE_LABELS = {
  table: '表',
  index: '索引',
  view: '视图',
  procedure: '存储过程',
  function: '函数',
  trigger: '触发器',
};

const FAILURE_LABELS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '对比任务不存在或已无权访问',
  conflict: '对比任务状态已更新，请刷新后重试',
  validation: '对比请求参数不符合要求，请修改后重试',
  unavailable: '结构对比服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const INSTANCE_OPTIONS = [
  { id: 'mysql-prod-order-01', name: '订单主库', engine: 'MySQL' },
  { id: 'pgsql-user-primary', name: '用户中心', engine: 'PostgreSQL' },
  { id: 'redis-session-01', name: '缓存集群', engine: 'Redis' },
  { id: 'mysql-analytics-replica', name: '分析从库', engine: 'MySQL' },
];

const SYNC_CONFIRM_COPY = '确认将该对比结果同步到目标实例？同步后将写入变更记录。';

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function diffStatusLabel(status) {
  return STATUS_LABELS[String(status ?? '')] ?? '未知';
}

export function objectStatusLabel(status) {
  return OBJECT_STATUS_LABELS[String(status ?? '')] ?? '未知';
}

export function objectTypeLabel(type) {
  return OBJECT_TYPE_LABELS[String(type ?? '')] ?? String(type ?? '');
}

export function schemaDiffSourceLabel(source) {
  if (source === 'demo') return '演示数据';
  if (source === 'http' || source === 'control-plane') return '控制面服务';
  return '来源未确认';
}

export function schemaDiffFailureMessage(error, subject = '结构对比数据') {
  return FAILURE_LABELS[error?.kind] ?? `${subject}加载失败，请稍后重试`;
}

export function buildDiffFilters(entries) {
  const source = entries instanceof Map ? entries : new Map(Object.entries(entries ?? {}));
  return Object.fromEntries([...source].filter(([, value]) => String(value ?? '').trim() !== ''));
}

export function validateDiffRequest(input = {}) {
  const errors = {};
  const title = String(input.title ?? '').trim();
  const sourceInstanceId = String(input.source_instance_id ?? '').trim();
  const targetInstanceId = String(input.target_instance_id ?? '').trim();
  const objectTypes = Array.isArray(input.object_types) ? input.object_types : [];
  if (!title) errors.title = '请填写对比标题';
  if (!sourceInstanceId) errors.source_instance_id = '请选择源实例';
  if (!targetInstanceId) errors.target_instance_id = '请选择目标实例';
  if (sourceInstanceId && targetInstanceId && sourceInstanceId === targetInstanceId) {
    errors.target_instance_id = '源实例与目标实例不能相同';
  }
  if (!objectTypes.length) errors.object_types = '请至少选择一种对象类型';
  return errors;
}

export function renderDiffListMarkup({ items = [], filters = {}, source = '', page = 1, pageSize = 8, total = 0, totalPages = 1 } = {}) {
  const rows = (Array.isArray(items) ? items : []).map((item) => {
    const sourceName = item.source?.instance_name ?? item.source?.instance_id ?? '—';
    const targetName = item.target?.instance_name ?? item.target?.instance_id ?? '—';
    const pending = (item.summary?.added ?? 0) + (item.summary?.removed ?? 0) + (item.summary?.changed ?? 0);
    return `<div class="scd-table-row" role="row">
      <span><b class="scd-diff-id">${safeText(item.id)}</b></span>
      <span class="scd-cell-title">${safeText(item.title ?? '—')}</span>
      <span class="scd-cell-route">${safeText(sourceName)} → ${safeText(targetName)}</span>
      <span class="scd-cell-pending">${pending}</span>
      <span><i class="scd-tag ${safeText(item.status)}">${safeText(diffStatusLabel(item.status))}</i></span>
      <span>${safeText(formatTime(item.created_at))}</span>
      <span><button type="button" class="scd-btn-secondary scd-row-action" data-scd-diff="${safeText(item.id)}">查看</button></span>
    </div>`;
  }).join('');
  const sourceBadge = source ? `<span class="scd-source ${safeText(source)}">${safeText(schemaDiffSourceLabel(source))}</span>` : '';
  const statusOptions = Object.entries(STATUS_LABELS).map(([value, label]) => `<option value="${value}" ${filters.status === value ? 'selected' : ''}>${label}</option>`).join('');
  const empty = (Array.isArray(items) ? items : []).length ? '' : '<div class="scd-empty"><h3>暂无对比任务</h3><p>当前筛选条件下没有可展示的结构对比任务。</p></div>';
  return `<div class="scd-list">
    <div class="scd-section-head"><div><span class="scd-kicker">DIFF LIST</span><h3>对比列表</h3><p>按状态与关键字筛选当前项目内的结构对比任务。</p></div>${sourceBadge}</div>
    <div class="scd-filter" role="search">
      <label>状态<select class="scd-select" data-scd-filter="status"><option value="">全部</option>${statusOptions}</select></label>
      <label>搜索<input class="scd-input scd-input-search" data-scd-filter="search" value="${safeText(filters.search ?? '')}" placeholder="编号 / 标题 / 实例" autocomplete="off" /></label>
    </div>
    <article class="scd-panel scd-table-wrap"><div class="scd-table" role="table"><div class="scd-table-row head" role="row"><span>编号</span><span>标题</span><span>源 → 目标</span><span>差异数</span><span>状态</span><span>创建时间</span><span></span></div>${rows}</div>${empty}</article>
    <div class="scd-pager"><span>共 ${total} 条</span><div><button type="button" class="scd-btn-secondary" data-scd-prev ${page <= 1 ? 'disabled' : ''}>上一页</button><span>第 ${page} / ${totalPages} 页</span><button type="button" class="scd-btn-secondary" data-scd-next ${page >= totalPages ? 'disabled' : ''}>下一页</button></div></div>
  </div>`;
}

export function renderDiffDetailMarkup(diff = {}, options = {}) {
  const canManage = options.canManage === true;
  if (!diff || diff.id == null) {
    return '<div class="scd-empty"><h3>暂无对比详情</h3><p>无法读取该对比任务的内容，请返回列表重试。</p><button type="button" class="scd-btn-secondary" data-scd-back>返回对比列表</button></div>';
  }
  const source = diff.source ?? {};
  const target = diff.target ?? {};
  const summary = diff.summary ?? {};
  const objects = Array.isArray(diff.objects) ? diff.objects : [];
  const running = diff.status === 'running';
  const meta = [
    ['源实例', `${source.instance_name ?? ''}（${source.instance_id ?? '—'}）`],
    ['目标实例', `${target.instance_name ?? ''}（${target.instance_id ?? '—'}）`],
    ['创建人', diff.created_by],
    ['创建时间', formatTime(diff.created_at)],
    ['同步时间', diff.synced_at ? formatTime(diff.synced_at) : '尚未同步'],
  ];
  const summaryBlocks = [
    ['新增', summary.added ?? 0, 'added'],
    ['删除', summary.removed ?? 0, 'removed'],
    ['变更', summary.changed ?? 0, 'changed'],
    ['一致', summary.identical ?? 0, 'identical'],
  ].map(([label, count, tone]) => `<div class="scd-summary-block ${tone}"><span>${safeText(label)}</span><strong>${safeText(String(count))}</strong></div>`).join('');
  const objectRows = objects.length
    ? objects.map(renderObjectRow).join('')
    : '<div class="scd-empty"><h3>暂无比对对象</h3><p>对比仍在进行中，结果尚未生成。</p></div>';
  const statusText = running ? '对比中…' : diffStatusLabel(diff.status);
  const syncMarkup = canManage && !running && !diff.synced_at
    ? `<button type="button" class="scd-btn-primary" data-scd-sync>同步到目标</button>`
    : '';
  const syncHint = diff.synced_at ? '<p class="scd-synced-hint">该任务已同步到目标实例。</p>' : '';
  return `<div class="scd-detail">
    <div class="scd-detail-head"><button type="button" class="scd-back" data-scd-back>← 返回对比列表</button><div><h3>对比详情</h3><p>${safeText(diff.title ?? diff.id)}</p></div><i class="scd-tag ${safeText(diff.status)}">${safeText(statusText)}</i></div>
    <article class="scd-panel"><h4>基本信息</h4><dl class="scd-kv">${meta.map(([key, value]) => `<div><dt>${safeText(key)}</dt><dd>${safeText(value ?? '—')}</dd></div>`).join('')}</dl>${syncHint}</article>
    <article class="scd-panel"><div class="scd-panel-head"><div><span class="scd-kicker">DIFF SUMMARY</span><h3>差异摘要</h3></div>${running ? '<span class="scd-running-note">对比中…</span>' : ''}</div><div class="scd-summary">${summaryBlocks}</div></article>
    <article class="scd-panel"><div class="scd-panel-head"><div><span class="scd-kicker">OBJECTS</span><h3>对象差异列表</h3></div></div><div class="scd-diff-list">${objectRows}</div></article>
    <article class="scd-panel scd-ddl-panel"><div class="scd-panel-head"><div><span class="scd-kicker">GENERATED DDL</span><h3>生成的 DDL</h3></div><button type="button" class="scd-btn-secondary" data-scd-copy-ddl>复制 DDL</button></div><pre class="scd-ddl">${safeText(diff.generated_ddl ?? '')}</pre></article>
    <div class="scd-detail-actions">${syncMarkup}</div>
  </div>`;
}

export function createSchemaDiffCenter({ root, api, scope, permissions = {}, onToast = () => {} } = {}) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('schema diff root is required');
  if (!api) throw new TypeError('schema diff api is required');

  const state = {
    view: 'overview',
    scope: normalizeScope(scope),
    permissions: { manage: permissions.manage === true },
    filters: { status: '', search: '' },
    page: 1,
    pageSize: 8,
    source: null,
    overview: null,
    list: null,
    detail: null,
    selectedId: null,
    confirmSync: null,
    createOpen: false,
    loading: false,
    error: null,
  };
  let activeRequest = null;
  let requestVersion = 0;
  let searchTimer = null;
  let detailTimer = null;

  root.addEventListener('click', (event) => {
    const target = typeof event.target?.closest === 'function'
      ? event.target.closest('[data-scd-view],[data-scd-diff],[data-scd-back],[data-schemadiff-retry],[data-scd-prev],[data-scd-next],[data-scd-new],[data-scd-create-close],[data-scd-sync],[data-scd-confirm-yes],[data-scd-confirm-no],[data-scd-copy-ddl]')
      : null;
    if (!target) return;
    if (target.dataset.scdView) {
      open(target.dataset.scdView);
    } else if (target.dataset.scdDiff) {
      loadDetail(target.dataset.scdDiff);
    } else if (target.hasAttribute('data-scd-back')) {
      state.view = 'schema-diff';
      state.selectedId = null;
      state.detail = null;
      state.confirmSync = null;
      reload();
    } else if (target.hasAttribute('data-schemadiff-retry')) {
      reload();
    } else if (target.hasAttribute('data-scd-prev')) {
      state.page = Math.max(1, state.page - 1);
      reload();
    } else if (target.hasAttribute('data-scd-next')) {
      state.page += 1;
      reload();
    } else if (target.hasAttribute('data-scd-new')) {
      if (!state.permissions.manage) {
        onToast('当前账号没有该项目的操作权限');
        return;
      }
      state.createOpen = true;
      render();
    } else if (target.hasAttribute('data-scd-create-close')) {
      const insideCard = typeof event.target?.closest === 'function' ? event.target.closest('.scd-modal-card') : null;
      if (insideCard && target !== event.target) return;
      state.createOpen = false;
      render();
    } else if (target.hasAttribute('data-scd-sync')) {
      state.confirmSync = state.selectedId;
      render();
    } else if (target.hasAttribute('data-scd-confirm-yes')) {
      runSync();
    } else if (target.hasAttribute('data-scd-confirm-no')) {
      state.confirmSync = null;
      render();
    } else if (target.hasAttribute('data-scd-copy-ddl')) {
      onToast('DDL 已复制到剪贴板');
    }
  });

  root.addEventListener('change', (event) => {
    const target = event.target;
    if (!target?.dataset) return;
    if (target.dataset.scdFilter) {
      if (target.dataset.scdFilter === 'search') return;
      state.filters[target.dataset.scdFilter] = target.value;
      state.page = 1;
      reload();
    } else if (target.dataset.scdCreateInstance) {
      updateAutoTitle(target);
    }
  });

  root.addEventListener('input', (event) => {
    const target = event.target;
    if (!target?.dataset || target.dataset.scdFilter !== 'search') return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.filters.search = target.value;
      state.page = 1;
      reload();
    }, 200);
  });

  root.addEventListener('submit', (event) => {
    const form = typeof event.target?.closest === 'function' ? event.target.closest('[data-scd-create-form]') : null;
    if (!form) return;
    event.preventDefault();
    submitCreate(form);
  });

  function open(view = 'overview') {
    const allowed = ['overview', 'schema-diff'];
    if (!allowed.includes(view)) view = 'overview';
    state.view = view;
    state.selectedId = null;
    state.detail = null;
    state.confirmSync = null;
    state.page = 1;
    reload();
  }

  function setScope(nextScope) {
    state.scope = normalizeScope(nextScope);
    state.filters = { status: '', search: '' };
    state.page = 1;
    state.selectedId = null;
    state.detail = null;
    state.overview = null;
    state.list = null;
    state.confirmSync = null;
    state.createOpen = false;
    reload();
  }

  function loadDetail(id) {
    state.selectedId = String(id);
    state.view = 'diff-detail';
    state.detail = null;
    state.confirmSync = null;
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
      if (state.view === 'schema-diff') {
        result = await api.listDiffs(state.scope, buildDiffFilters({ ...state.filters, page: state.page, pageSize: state.pageSize }), controller.signal);
      } else if (state.view === 'diff-detail') {
        if (!state.selectedId) state.view = 'schema-diff';
        result = state.view === 'schema-diff'
          ? await api.listDiffs(state.scope, buildDiffFilters({ ...state.filters, page: state.page, pageSize: state.pageSize }), controller.signal)
          : await api.getDiff(state.scope, state.selectedId, controller.signal);
      } else {
        result = await api.getOverview(state.scope, controller.signal);
      }
      if (version !== requestVersion || controller.signal.aborted) return;
      if (state.view === 'schema-diff') state.list = result;
      else if (state.view === 'diff-detail') state.detail = result;
      else state.overview = result;
      state.source = result?.source ?? null;
      state.loading = false;
      render();
      if (state.view === 'diff-detail' && result?.status === 'running') {
        detailTimer = setTimeout(() => loadDetail(state.selectedId), 1600);
        if (typeof detailTimer.unref === 'function') detailTimer.unref();
      }
    } catch (error) {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.loading = false;
      state.error = error;
      render();
    }
  }

  async function runSync() {
    const id = state.selectedId;
    if (!id) return;
    state.confirmSync = null;
    const signal = activeRequest?.signal;
    try {
      await api.applyDiff(state.scope, id, signal);
      onToast('已同步到目标实例');
      reload();
    } catch (error) {
      if (error?.name === 'AbortError') return;
      onToast(schemaDiffFailureMessage(error, '结构对比'));
      render();
    }
  }

  async function submitCreate(form) {
    if (!state.permissions.manage) return;
    const data = new FormData(form);
    const types = [...form.querySelectorAll('input[name="object_types"]:checked')].map((checkbox) => checkbox.value);
    const input = {
      title: String(data.get('title') ?? '').trim(),
      source_instance_id: String(data.get('source_instance_id') ?? '').trim(),
      target_instance_id: String(data.get('target_instance_id') ?? '').trim(),
      object_types: types,
    };
    const errors = validateDiffRequest(input);
    const output = form.querySelector('[data-scd-form-errors]');
    if (Object.keys(errors).length) {
      if (output) output.textContent = Object.values(errors).join(' ');
      return;
    }
    if (output) output.textContent = '';
    form.querySelectorAll('button, input, select').forEach((element) => { element.disabled = true; });
    try {
      const created = await api.createDiff(state.scope, input, activeRequest?.signal);
      state.createOpen = false;
      onToast('对比任务已创建');
      loadDetail(created.id);
    } catch (error) {
      if (error?.name === 'AbortError') return;
      if (output) output.textContent = schemaDiffFailureMessage(error, '结构对比');
      form.querySelectorAll('button, input, select').forEach((element) => { element.disabled = false; });
    }
  }

  function updateAutoTitle(trigger) {
    const form = typeof trigger?.closest === 'function' ? trigger.closest('[data-scd-create-form]') : null;
    if (!form) return;
    const titleInput = form.querySelector('[name="title"]');
    if (!titleInput) return;
    const source = String(form.querySelector('[name="source_instance_id"]')?.value ?? '').trim();
    const target = String(form.querySelector('[name="target_instance_id"]')?.value ?? '').trim();
    if (source && target && source !== target) {
      titleInput.value = `${instanceName(source)} → ${instanceName(target)} 结构对比`;
    }
  }

  function abortActive() {
    clearTimeout(searchTimer);
    clearTimeout(detailTimer);
    detailTimer = null;
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
  const source = state.source ? `<span class="scd-source ${safeText(state.source)}">${safeText(schemaDiffSourceLabel(state.source))}</span>` : '';
  const body = state.error
    ? renderError(state.error)
    : state.view === 'schema-diff'
      ? renderListView(state)
      : state.view === 'diff-detail'
        ? renderDetailView(state)
        : renderOverviewView(state);
  const modal = state.createOpen ? renderCreateModal(state) : '';
  return `<section class="scd-center" data-scd-view="${safeText(state.view)}" aria-label="结构对比">
    <div class="scd-hero"><div><span class="eyebrow">DBPILOT · SCHEMA DIFF</span><h2>${safeText(title)}</h2><p>${safeText(description)}</p></div><div class="scd-hero-meta">${source}<span class="scd-scope">${safeText(state.scope.tenantId)} / ${safeText(state.scope.projectId)}</span></div></div>
    <nav class="scd-tabs" aria-label="结构对比视图"><button type="button" class="${state.view === 'overview' ? 'active' : ''}" data-scd-view="overview">对比概览</button><button type="button" class="${state.view === 'schema-diff' || state.view === 'diff-detail' ? 'active' : ''}" data-scd-view="schema-diff">对比列表</button>${state.permissions.manage ? '<button type="button" class="scd-tab-create" data-scd-new>＋ 新建对比</button>' : ''}</nav>
    ${state.loading && !state.error && !state.createOpen ? '<div class="scd-progress" role="status">正在加载…</div>' : ''}
    ${body}
    ${modal}
  </section>`;
}

const VIEW_COPY = {
  overview: ['结构对比', '对比源实例与目标实例的对象结构，统计差异并生成可执行的 DDL。'],
  'schema-diff': ['对比列表', '按状态与关键字筛选当前项目内的结构对比任务。'],
  'diff-detail': ['对比详情', '查看对象差异明细与生成的同步 DDL。'],
};

function renderOverviewView(state) {
  if (state.loading && !state.overview) {
    return '<div class="scd-state" role="status"><span class="scd-spinner"></span><h3>正在加载对比概览</h3><p>统计与最近对比任务即将呈现。</p></div>';
  }
  const overview = state.overview ?? {};
  const recent = Array.isArray(overview.recent) ? overview.recent : [];
  const statCards = [
    ['对比任务', overview.total_diffs ?? 0, 'total', '当前项目发起的结构对比任务'],
    ['待处理差异', overview.pending_changes ?? 0, 'pending', '新增、删除与变更差异合计'],
    ['已同步任务', overview.synced_diffs ?? 0, 'synced', '已同步到目标实例的任务数'],
    ['最近对比', overview.recent_at ? formatTime(overview.recent_at) : '—', 'recent', '最近一次结构对比时间'],
  ].map(([label, value, tone, hint]) => `<article class="scd-stat-card ${tone}"><span>${safeText(label)}</span><strong>${safeText(String(value))}</strong><p>${safeText(hint)}</p><i></i></article>`).join('');
  const recentRows = recent.length
    ? recent.map((diff) => renderRecentRow(diff)).join('')
    : '<div class="scd-empty"><h3>暂无对比任务</h3><p>当前项目还没有结构对比任务。</p></div>';
  const newButton = state.permissions.manage ? '<button type="button" class="scd-btn-primary" data-scd-new>＋ 新建对比</button>' : '';
  return `<div class="scd-overview">
    <div class="scd-section-head"><div><span class="scd-kicker">OVERVIEW</span><h3>结构对比概览</h3><p>对比任务统计与最近一次结构差异扫描。</p></div>${newButton}</div>
    <div class="scd-stats">${statCards}</div>
    <article class="scd-panel"><div class="scd-panel-head"><div><span class="scd-kicker">RECENT</span><h3>最近对比</h3></div><button type="button" class="scd-btn-secondary" data-scd-view="schema-diff">查看全部 →</button></div>${recentRows}</article>
  </div>`;
}

function renderListView(state) {
  if (state.loading && !state.list) {
    return '<div class="scd-state" role="status"><span class="scd-spinner"></span><h3>正在加载对比列表</h3><p>筛选条件变更后将重新请求当前项目内的任务。</p></div>';
  }
  const list = state.list ?? {};
  return renderDiffListMarkup({
    items: list.items ?? [],
    filters: state.filters,
    source: list.source ?? state.source,
    page: Number(list.page ?? state.page) || 1,
    pageSize: Number(list.pageSize ?? state.pageSize) || 8,
    total: Number(list.total ?? 0) || 0,
    totalPages: Number(list.totalPages ?? 1) || 1,
  });
}

function renderDetailView(state) {
  if (state.loading && !state.detail) {
    return '<div class="scd-state" role="status"><span class="scd-spinner"></span><h3>正在加载对比详情</h3><p>读取对象差异与 DDL，请稍候。</p></div>';
  }
  if (!state.detail) {
    return '<div class="scd-state"><h3>尚未选择对比任务</h3><p>从对比列表选择一个任务查看详情。</p><button type="button" class="scd-btn-primary" data-scd-view="schema-diff">返回对比列表</button></div>';
  }
  const confirmBar = state.confirmSync ? renderConfirmBar(state.confirmSync) : '';
  return `${confirmBar}${renderDiffDetailMarkup(state.detail, { canManage: state.permissions.manage })}`;
}

function renderRecentRow(diff) {
  const pending = (diff.summary?.added ?? 0) + (diff.summary?.removed ?? 0) + (diff.summary?.changed ?? 0);
  const sourceName = diff.source?.instance_name ?? diff.source?.instance_id ?? '—';
  const targetName = diff.target?.instance_name ?? diff.target?.instance_id ?? '—';
  return `<button type="button" class="scd-recent-row" data-scd-diff="${safeText(diff.id)}"><span><b>${safeText(diff.title ?? diff.id)}</b><small>${safeText(diff.id)} · ${safeText(sourceName)} → ${safeText(targetName)}</small></span><span class="scd-recent-count">${pending} 项差异</span><i class="scd-tag ${safeText(diff.status)}">${safeText(diffStatusLabel(diff.status))}</i><span>${safeText(formatTime(diff.created_at))}</span></button>`;
}

function renderObjectRow(item) {
  const changes = Array.isArray(item.changes) ? item.changes : [];
  const changesMarkup = changes.length
    ? `<ul class="scd-diff-changes">${changes.map((change) => `<li>${safeText(change)}</li>`).join('')}</ul>`
    : '<span class="scd-diff-none">无差异</span>';
  return `<div class="scd-diff-row" data-status="${safeText(item.status)}">
    <span class="scd-object-type ${safeText(item.object_type)}">${safeText(objectTypeLabel(item.object_type))}</span>
    <span class="scd-object-name"><b>${safeText(item.schema ?? '')}</b>.${safeText(item.name ?? '—')}</span>
    <i class="scd-tag ${safeText(item.status)}">${safeText(objectStatusLabel(item.status))}</i>
    <span class="scd-diff-changes-wrap">${changesMarkup}</span>
  </div>`;
}

function renderConfirmBar(id) {
  return `<div class="scd-confirm" role="alertdialog" aria-label="确认同步"><p>${safeText(SYNC_CONFIRM_COPY)}</p><div><button type="button" class="scd-btn-primary" data-scd-confirm-yes>确认同步</button><button type="button" class="scd-btn-secondary" data-scd-confirm-no>取消</button></div></div>`;
}

function renderCreateModal(state) {
  const instanceOptions = (selected) => INSTANCE_OPTIONS.map((option) => `<option value="${option.id}" ${selected === option.id ? 'selected' : ''}>${option.id} · ${option.name}（${option.engine}）</option>`).join('');
  const typeOptions = Object.entries(OBJECT_TYPE_LABELS).map(([value, label]) => `<label class="scd-check"><input type="checkbox" name="object_types" value="${value}" checked /><span>${safeText(label)}</span></label>`).join('');
  return `<div class="scd-modal" data-scd-create-close role="dialog" aria-modal="true" aria-label="新建对比">
    <form class="scd-modal-card scd-form" data-scd-create-form novalidate>
      <div class="scd-modal-head"><div><h3>新建结构对比</h3><p>选择源实例与目标实例，指定需要扫描的对象类型。</p></div><button type="button" class="scd-modal-close" data-scd-create-close aria-label="关闭">×</button></div>
      <label>对比标题<input class="scd-input" name="title" required maxlength="120" placeholder="例如：订单主库 → 分析从库 结构对比" autocomplete="off" /></label>
      <div class="scd-form-grid">
        <label>源实例<select class="scd-select" name="source_instance_id" data-scd-create-instance required>${instanceOptions('mysql-prod-order-01')}</select></label>
        <label>目标实例<select class="scd-select" name="target_instance_id" data-scd-create-instance required>${instanceOptions('mysql-analytics-replica')}</select></label>
      </div>
      <fieldset class="scd-checkbox-group"><legend>对象类型</legend><div class="scd-checkboxes">${typeOptions}</div></fieldset>
      <p class="scd-form-errors" data-scd-form-errors role="alert" aria-live="polite"></p>
      <div class="scd-form-actions"><button type="button" class="scd-btn-secondary" data-scd-create-close>取消</button><button type="submit" class="scd-btn-primary">开始对比</button></div>
    </form>
  </div>`;
}

function renderError(error) {
  const forbidden = error?.kind === 'forbidden';
  return `<div class="scd-error" role="alert"><span class="scd-error-icon">${forbidden ? '⌾' : '!'}</span><h3>${forbidden ? '无法查看结构对比' : '结构对比数据加载失败'}</h3><p>${safeText(schemaDiffFailureMessage(error, '结构对比数据'))}</p><button type="button" class="scd-btn-primary" data-schemadiff-retry>重试</button></div>`;
}

function normalizeScope(scope) {
  return {
    tenantId: typeof scope?.tenantId === 'string' && scope.tenantId.trim() ? scope.tenantId.trim() : '未配置',
    projectId: typeof scope?.projectId === 'string' && scope.projectId.trim() ? scope.projectId.trim() : '未配置',
  };
}

function instanceName(id) {
  return INSTANCE_OPTIONS.find((option) => option.id === id)?.name ?? id ?? '';
}

function formatTime(value) {
  if (value == null || String(value).trim() === '') return '—';
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
    : '—';
}

if (typeof window !== 'undefined') {
  window.DBPilotSchemaDiffCenter = { create: createSchemaDiffCenter };
}
