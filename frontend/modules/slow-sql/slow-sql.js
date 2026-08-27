const VIEW_COPY = {
  overview: ['慢 SQL 治理', '慢 SQL 的统计、Top 排行与状态分布。'],
  'slow-sql': ['慢 SQL 列表', '按实例、耗时阈值、状态与关键字筛选慢 SQL。'],
  'slow-sql-detail': ['慢 SQL 详情', '查看 SQL 指纹、执行统计、耗时趋势与优化建议。'],
};

const STATE_LABELS = { open: '待处理', acknowledged: '已处理', ignored: '已忽略' };

const SUGGESTION_LABELS = { index: '索引建议', rewrite: '改写建议', stats: '统计信息' };

const FAILURE_LABELS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '慢 SQL 记录不存在或已无权访问',
  conflict: '慢 SQL 记录状态已更新，请刷新后重试',
  validation: '慢 SQL 查询参数不符合要求，请修改后重试',
  unavailable: '慢 SQL 治理服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const MAX_THRESHOLD_MS = 86_400_000;
const MAX_THRESHOLD_LABEL = '24h';

const INSTANCE_OPTIONS = [
  { instance_id: 'mysql-prod-order-01', instance_name: '订单主库', engine: 'MySQL' },
  { instance_id: 'mysql-analytics-replica', instance_name: '分析从库', engine: 'MySQL' },
  { instance_id: 'pgsql-user-primary', instance_name: '用户中心', engine: 'PostgreSQL' },
  { instance_id: 'oracle-finance-01', instance_name: '财务核心库', engine: 'Oracle' },
];

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function formatMilliseconds(value) {
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

export function formatDuration(value) {
  return formatMilliseconds(value);
}

export function slowSqlStateLabel(state) {
  return STATE_LABELS[String(state ?? '')] ?? '未知';
}

export function suggestionKindLabel(kind) {
  return SUGGESTION_LABELS[String(kind ?? '')] ?? '未知';
}

export function slowSqlSourceLabel(source) {
  if (source === 'demo') return '演示数据';
  if (source === 'http' || source === 'control-plane') return '控制面服务';
  return '来源未确认';
}

export function slowSqlFailureMessage(error, subject = '慢 SQL 数据') {
  return FAILURE_LABELS[error?.kind] ?? `${subject}加载失败，请稍后重试`;
}

export function buildSlowSqlFilters(entries) {
  const source = entries instanceof Map ? entries : new Map(Object.entries(entries ?? {}));
  return Object.fromEntries([...source].filter(([, value]) => String(value ?? '').trim() !== ''));
}

export function validateThreshold(value) {
  if (value == null || String(value).trim() === '') return { kind: 'valid', value: 0 };
  const number = Number(value);
  if (!Number.isFinite(number)) return { kind: 'invalid-number' };
  if (number < 0) return { kind: 'negative' };
  if (number > MAX_THRESHOLD_MS) return { kind: 'too-large' };
  return { kind: 'valid', value: number };
}

export function renderSlowSqlListMarkup({ items = [], filters = {}, source = '', page = 1, pageSize = 10, total = 0, totalPages = 1, sortBy = 'total', instances = [] } = {}) {
  const rows = (Array.isArray(items) ? items : []).map((item) => `<div class="ssq-table-row" role="row">
      <span class="ssq-fingerprint" title="${safeText(item.sql_fingerprint ?? '')}">${safeText(fingerprintSummary(item.sql_fingerprint))}</span>
      <span><b class="ssq-instance">${safeText(item.instance_name ?? item.instance_id ?? '—')}</b><small>${safeText(item.engine ?? '')}</small></span>
      <span>${safeText(formatMilliseconds(item.avg_duration_ms))}</span>
      <span>${safeText(formatMilliseconds(item.max_duration_ms))}</span>
      <span>${safeText(String(item.exec_count ?? 0))}</span>
      <span>${safeText(formatMilliseconds(item.total_duration_ms))}</span>
      <span>${safeText(formatTime(item.last_seen))}</span>
      <span><i class="ssq-tag ${safeText(item.state ?? '')}">${safeText(slowSqlStateLabel(item.state))}</i></span>
      <span><button type="button" class="ssq-btn-secondary ssq-row-action" data-slowsql-item="${safeText(item.id)}">查看</button></span>
    </div>`).join('');
  const sourceBadge = source ? `<span class="ssq-source ${safeText(source)}">${safeText(slowSqlSourceLabel(source))}</span>` : '';
  const instanceOptions = (Array.isArray(instances) ? instances : []).map((option) => `<option value="${safeText(option.instance_id)}" ${filters.instance_id === option.instance_id ? 'selected' : ''}>${safeText(option.instance_name ?? option.instance_id)}（${safeText(option.engine ?? '')}）</option>`).join('');
  const stateOptions = Object.entries(STATE_LABELS).map(([value, label]) => `<option value="${value}" ${filters.state === value ? 'selected' : ''}>${label}</option>`).join('');
  const empty = (Array.isArray(items) ? items : []).length ? '' : '<div class="ssq-empty"><h3>暂无慢 SQL</h3><p>当前筛选条件下没有可展示的慢 SQL。</p></div>';
  return `<div class="ssq-list">
    <div class="ssq-section-head"><div><span class="ssq-kicker">SLOW SQL LIST</span><h3>慢 SQL 列表</h3><p>按实例、最小耗时阈值、状态与关键字筛选当前项目内的慢 SQL。</p></div>${sourceBadge}</div>
    <div class="ssq-filter" role="search">
      <label>实例<select class="ssq-select" data-slowsql-filter="instance_id"><option value="">全部</option>${instanceOptions}</select></label>
      <label>最小耗时（ms）<input class="ssq-input" data-slowsql-filter="min_duration" value="${safeText(filters.min_duration ?? '')}" placeholder="如 800" inputmode="numeric" autocomplete="off" /></label>
      <label>状态<select class="ssq-select" data-slowsql-filter="state"><option value="">全部</option>${stateOptions}</select></label>
      <label>搜索<input class="ssq-input ssq-search" data-slowsql-filter="search" value="${safeText(filters.search ?? '')}" placeholder="指纹 / 实例 / 表名" autocomplete="off" /></label>
    </div>
    <article class="ssq-panel ssq-table-wrap"><div class="ssq-table" role="table"><div class="ssq-table-row head" role="row">
      <span>SQL 指纹</span>
      <span>实例</span>
      <span><button type="button" class="ssq-sort ${sortBy === 'avg' ? 'active' : ''}" data-slowsql-sort="avg">平均耗时${sortBy === 'avg' ? ' ↓' : ''}</button></span>
      <span>最大耗时</span>
      <span><button type="button" class="ssq-sort ${sortBy === 'count' ? 'active' : ''}" data-slowsql-sort="count">次数${sortBy === 'count' ? ' ↓' : ''}</button></span>
      <span><button type="button" class="ssq-sort ${sortBy === 'total' ? 'active' : ''}" data-slowsql-sort="total">总耗时${sortBy === 'total' ? ' ↓' : ''}</button></span>
      <span>最后出现</span>
      <span>状态</span>
      <span></span>
    </div>${rows}</div>${empty}</article>
    <div class="ssq-pager"><span>共 ${total} 条</span><div><button type="button" class="ssq-btn-secondary" data-slowsql-prev ${page <= 1 ? 'disabled' : ''}>上一页</button><span>第 ${page} / ${totalPages} 页</span><button type="button" class="ssq-btn-secondary" data-slowsql-next ${page >= totalPages ? 'disabled' : ''}>下一页</button></div></div>
  </div>`;
}

export function renderSlowSqlDetailMarkup(item = {}, options = {}) {
  const canManage = options.canManage === true;
  if (!item || item.id == null) {
    return '<div class="ssq-empty"><h3>暂无慢 SQL 详情</h3><p>无法读取该记录，请返回列表重试。</p><button type="button" class="ssq-btn-secondary" data-slowsql-view="slow-sql">返回慢 SQL 列表</button></div>';
  }
  const trend = item.trend && Array.isArray(item.trend.buckets) ? item.trend.buckets : [];
  const suggestion = item.suggestion && item.suggestion.kind ? item.suggestion : null;
  const suggestionBadge = suggestion ? `<i class="ssq-suggest-badge ${safeText(suggestion.kind)}">${safeText(suggestionKindLabel(suggestion.kind))}</i>` : '';
  const statCards = [
    ['平均耗时', formatMilliseconds(item.avg_duration_ms)],
    ['最大耗时', formatMilliseconds(item.max_duration_ms)],
    ['执行次数', String(item.exec_count ?? 0)],
    ['总耗时', formatMilliseconds(item.total_duration_ms)],
  ].map(([label, value]) => `<article class="ssq-stat-card"><span>${safeText(label)}</span><strong>${safeText(value)}</strong></article>`).join('');
  const suggestionCard = suggestion
    ? `<article class="ssq-panel ssq-suggest"><div class="ssq-panel-head"><div><span class="ssq-kicker">SUGGESTION</span><h3>优化建议</h3></div>${suggestionBadge}</div><p>${safeText(suggestion.message ?? '')}</p>${suggestion.ddl ? `<pre class="ssq-code">${safeText(suggestion.ddl)}</pre>` : ''}</article>`
    : '';
  const actions = canManage
    ? `<div class="ssq-detail-actions"><button type="button" class="ssq-btn-primary" data-slowsql-ack="${safeText(item.id)}">标记已处理</button><button type="button" class="ssq-btn-secondary" data-slowsql-ignore="${safeText(item.id)}">忽略</button></div>`
    : '<p class="ssq-muted">当前账号没有该项目的操作权限。</p>';
  const meta = [
    ['数据库', item.database],
    ['表名', item.table_name],
    ['首次出现', formatTime(item.first_seen)],
    ['最后出现', formatTime(item.last_seen)],
    ['采样数', String(item.sample_count ?? item.exec_count ?? 0)],
  ];
  return `<div class="ssq-detail">
    <div class="ssq-detail-head"><button type="button" class="ssq-back" data-slowsql-back>← 返回慢 SQL 列表</button><div><h3>慢 SQL 详情</h3><p>${safeText(item.id)}</p></div><i class="ssq-tag ${safeText(item.state ?? '')}">${safeText(slowSqlStateLabel(item.state))}</i></div>
    <article class="ssq-panel"><div class="ssq-panel-head"><div><span class="ssq-kicker">FINGERPRINT</span><h3>SQL 指纹</h3></div><span>${safeText(item.engine ?? '')}</span></div><pre class="ssq-code">${safeText(item.sql_fingerprint ?? '')}</pre></article>
    <article class="ssq-panel"><div class="ssq-panel-head"><div><span class="ssq-kicker">SAMPLE</span><h3>SQL 样本</h3></div></div><pre class="ssq-code sample">${safeText(item.sql_sample ?? '')}</pre></article>
    <div class="ssq-detail-grid">
      <div class="ssq-detail-main">
        <article class="ssq-panel"><div class="ssq-panel-head"><div><span class="ssq-kicker">EXECUTION</span><h3>执行统计</h3></div><span>基于 ${safeText(String(item.sample_count ?? item.exec_count ?? 0))} 个采样</span></div><div class="ssq-stats">${statCards}</div></article>
        <article class="ssq-panel"><div class="ssq-panel-head"><div><span class="ssq-kicker">TREND</span><h3>耗时趋势</h3></div><span>${trend.length} 个采样窗口</span></div>${renderTrendBars(trend)}</article>
        ${suggestionCard}
        <article class="ssq-panel"><div class="ssq-panel-head"><div><span class="ssq-kicker">META</span><h3>元信息</h3></div></div><dl class="ssq-kv">${meta.map(([key, value]) => `<div><dt>${safeText(key)}</dt><dd>${safeText(value ?? '—')}</dd></div>`).join('')}</dl></article>
      </div>
      <aside class="ssq-detail-side">
        <article class="ssq-panel"><h4>治理操作</h4>${actions}</article>
      </aside>
    </div>
  </div>`;
}

export function renderSlowSqlOverview(value = {}) {
  const stats = value.stats ?? {};
  const top = Array.isArray(value.top) ? value.top : [];
  const distribution = value.distribution ?? {};
  const statCards = [
    ['慢 SQL 总数', String(stats.total ?? 0), 'total'],
    ['今日新增', String(stats.new_today ?? 0), 'new'],
    ['平均耗时', formatMilliseconds(stats.avg_duration_ms), 'avg'],
    ['总耗时占比', `${Number(stats.total_ratio) || 0}%`, 'ratio'],
  ].map(([label, cardValue, tone]) => `<article class="ssq-stat-card ${tone}"><span>${safeText(label)}</span><strong>${safeText(cardValue)}</strong><i></i></article>`).join('');
  const topMax = Math.max(...top.map((item) => Number(item.total_duration_ms) || 0), 1);
  const topRows = top.length
    ? top.map((item, index) => {
      const percent = Math.max(2, Math.round(Number(item.total_duration_ms) / topMax * 100));
      return `<div class="ssq-rank-row"><span class="ssq-rank">${index + 1}</span><span class="ssq-rank-main"><b title="${safeText(item.sql_fingerprint ?? '')}">${safeText(fingerprintSummary(item.sql_fingerprint))}</b><small>${safeText(item.instance_name ?? item.instance_id ?? '')} · ${safeText(item.engine ?? '')}</small></span><span class="ssq-rank-bar"><i><b style="width:${percent}%"></b></i></span><span><strong>${safeText(formatMilliseconds(item.total_duration_ms))}</strong><small>${safeText(String(item.exec_count ?? 0))} 次</small></span></div>`;
    }).join('')
    : '<div class="ssq-empty"><h3>暂无 Top 慢 SQL</h3><p>当前项目还没有积累慢 SQL 记录。</p></div>';
  const distributionKeys = [['open', '待处理'], ['acknowledged', '已处理'], ['ignored', '已忽略']];
  const distTotal = distributionKeys.reduce((sum, [key]) => sum + (Number(distribution[key]) || 0), 0);
  const distRows = distributionKeys.map(([key, label]) => {
    const count = Number(distribution[key]) || 0;
    const percent = distTotal ? Math.round(count / distTotal * 100) : 0;
    return `<div class="ssq-dist-row"><span>${safeText(label)}</span><i class="ssq-dist-bar"><b class="${key}" style="width:${percent}%"></b></i><span>${count}</span></div>`;
  }).join('');
  return `<div class="ssq-overview">
    <div class="ssq-section-head"><div><span class="ssq-kicker">OVERVIEW</span><h3>慢 SQL 治理概览</h3><p>按总耗时占比识别治理优先级，Top 排行按累计总耗时降序。</p></div><span class="ssq-source ${safeText(value.source ?? '')}">${safeText(slowSqlSourceLabel(value.source))}</span></div>
    <div class="ssq-stats">${statCards}</div>
    <div class="ssq-overview-grid">
      <article class="ssq-panel"><div class="ssq-panel-head"><div><span class="ssq-kicker">TOP 5</span><h3>Top 慢 SQL 排行</h3></div><button type="button" class="ssq-btn-secondary" data-slowsql-view="slow-sql">查看全部 →</button></div>${topRows}</article>
      <article class="ssq-panel"><div class="ssq-panel-head"><div><span class="ssq-kicker">DISTRIBUTION</span><h3>状态分布</h3></div></div>${distTotal ? `<div class="ssq-dist">${distRows}</div>` : '<p class="ssq-muted">暂无慢 SQL 数据。</p>'}</article>
    </div>
  </div>`;
}

export function createSlowSqlCenter({ root, api, scope, permissions = {}, onToast = () => {} } = {}) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('slow sql root is required');
  if (!api) throw new TypeError('slow sql api is required');

  const state = {
    view: 'overview',
    scope: normalizeScope(scope),
    permissions: { manage: permissions.manage === true },
    filters: { instance_id: '', min_duration: '', state: '', search: '' },
    sortBy: 'total',
    page: 1,
    pageSize: 10,
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
      ? event.target.closest('[data-slowsql-view],[data-slowsql-item],[data-slowsql-back],[data-slowsql-retry],[data-slowsql-prev],[data-slowsql-next],[data-slowsql-sort],[data-slowsql-ack],[data-slowsql-ignore]')
      : null;
    if (!target) return;
    if (target.dataset.slowsqlView) {
      open(target.dataset.slowsqlView);
    } else if (target.dataset.slowsqlItem) {
      loadDetail(target.dataset.slowsqlItem);
    } else if (target.hasAttribute('data-slowsql-back')) {
      open('slow-sql');
    } else if (target.hasAttribute('data-slowsql-retry')) {
      reload();
    } else if (target.hasAttribute('data-slowsql-prev')) {
      state.page = Math.max(1, state.page - 1);
      reload();
    } else if (target.hasAttribute('data-slowsql-next')) {
      state.page += 1;
      reload();
    } else if (target.dataset.slowsqlSort) {
      state.sortBy = target.dataset.slowsqlSort;
      state.page = 1;
      reload();
    } else if (target.hasAttribute('data-slowsql-ack')) {
      runStateChange('ack', target.dataset.slowsqlItem);
    } else if (target.hasAttribute('data-slowsql-ignore')) {
      runStateChange('ignore', target.dataset.slowsqlItem);
    }
  });

  root.addEventListener('change', (event) => {
    const target = event.target;
    if (!target?.dataset || !target.dataset.slowsqlFilter || target.dataset.slowsqlFilter === 'search') return;
    if (target.dataset.slowsqlFilter === 'min_duration') {
      const checked = validateThreshold(target.value);
      if (checked.kind !== 'valid') {
        onToast(thresholdFailureMessage(checked.kind));
        render();
        return;
      }
    }
    state.filters[target.dataset.slowsqlFilter] = target.value;
    state.page = 1;
    reload();
  });

  root.addEventListener('input', (event) => {
    const target = event.target;
    if (!target?.dataset || target.dataset.slowsqlFilter !== 'search') return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.filters.search = target.value;
      state.page = 1;
      reload();
    }, 200);
  });

  function open(view = 'overview') {
    const allowed = ['overview', 'slow-sql', 'slow-sql-detail'];
    if (!allowed.includes(view)) view = 'overview';
    if (view === 'slow-sql-detail' && !state.selectedId) view = 'slow-sql';
    state.view = view;
    if (view !== 'slow-sql-detail') {
      state.selectedId = null;
      state.detail = null;
    }
    reload();
  }

  function setScope(nextScope) {
    state.scope = normalizeScope(nextScope);
    state.filters = { instance_id: '', min_duration: '', state: '', search: '' };
    state.sortBy = 'total';
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
    state.view = 'slow-sql-detail';
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
      if (state.view === 'slow-sql') {
        result = await api.listSlowSql(state.scope, buildSlowSqlFilters({ ...state.filters, page: state.page, pageSize: state.pageSize, sortBy: state.sortBy }), controller.signal);
      } else if (state.view === 'slow-sql-detail') {
        if (!state.selectedId) state.view = 'slow-sql';
        result = state.view === 'slow-sql'
          ? await api.listSlowSql(state.scope, buildSlowSqlFilters({ ...state.filters, page: state.page, pageSize: state.pageSize, sortBy: state.sortBy }), controller.signal)
          : await api.getSlowSql(state.scope, state.selectedId, controller.signal);
      } else {
        result = await api.getOverview(state.scope, controller.signal);
      }
      if (version !== requestVersion || controller.signal.aborted) return;
      if (state.view === 'slow-sql') state.list = result;
      else if (state.view === 'slow-sql-detail') state.detail = result;
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

  async function runStateChange(action, id) {
    if (!state.permissions.manage || !id) return;
    try {
      if (action === 'ack') await api.ackSlowSql(state.scope, id, activeRequest?.signal);
      else await api.ignoreSlowSql(state.scope, id, activeRequest?.signal);
      onToast(action === 'ack' ? '已标记为已处理' : '已忽略该慢 SQL');
      await loadDetail(id);
    } catch (error) {
      if (error?.name === 'AbortError') return;
      onToast(slowSqlFailureMessage(error, '慢 SQL'));
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
    root.innerHTML = renderSlowSqlWorkbench(state);
  }

  render();
  return {
    open,
    setScope,
    refresh: reload,
    getState: () => ({ ...state, scope: { ...state.scope }, filters: { ...state.filters }, permissions: { ...state.permissions } }),
  };
}

function renderSlowSqlWorkbench(state) {
  const [title, description] = VIEW_COPY[state.view] ?? VIEW_COPY.overview;
  const source = state.source ? `<span class="ssq-source ${safeText(state.source)}">${safeText(slowSqlSourceLabel(state.source))}</span>` : '';
  const body = state.error
    ? renderSlowSqlError(state.error)
    : state.view === 'slow-sql'
      ? renderSlowSqlListView(state)
      : state.view === 'slow-sql-detail'
        ? renderSlowSqlDetailView(state)
        : renderSlowSqlOverviewView(state);
  return `<section class="ssq-center" data-slowsql-view="${safeText(state.view)}" aria-label="慢 SQL 治理">
    <div class="ssq-hero"><div><span class="eyebrow">DBPILOT · SLOW SQL</span><h2>${safeText(title)}</h2><p>${safeText(description)}</p></div><div class="ssq-hero-meta">${source}<span class="ssq-scope">${safeText(state.scope.tenantId)} / ${safeText(state.scope.projectId)}</span></div></div>
    <nav class="ssq-tabs" aria-label="慢 SQL 视图"><button type="button" class="${state.view === 'overview' ? 'active' : ''}" data-slowsql-view="overview">治理概览</button><button type="button" class="${state.view === 'slow-sql' || state.view === 'slow-sql-detail' ? 'active' : ''}" data-slowsql-view="slow-sql">慢 SQL 列表</button></nav>
    ${state.loading && !state.error ? '<div class="ssq-progress" role="status">正在加载…</div>' : ''}
    ${body}
  </section>`;
}

function renderSlowSqlOverviewView(state) {
  if (state.loading && !state.overview) {
    return '<div class="ssq-state" role="status"><span class="ssq-spinner"></span><h3>正在加载慢 SQL 概览</h3><p>统计与 Top 排行即将呈现。</p></div>';
  }
  return renderSlowSqlOverview(state.overview ?? {});
}

function renderSlowSqlListView(state) {
  if (state.loading && !state.list) {
    return '<div class="ssq-state" role="status"><span class="ssq-spinner"></span><h3>正在加载慢 SQL 列表</h3><p>筛选条件变更后将重新请求当前项目内的慢 SQL。</p></div>';
  }
  const list = state.list ?? {};
  return renderSlowSqlListMarkup({
    items: list.items ?? [],
    filters: state.filters,
    source: list.source ?? state.source,
    page: Number(list.page ?? state.page) || 1,
    pageSize: Number(list.pageSize ?? state.pageSize) || 10,
    total: Number(list.total ?? 0) || 0,
    totalPages: Number(list.totalPages ?? 1) || 1,
    sortBy: state.sortBy,
    instances: state.instances ?? [],
  });
}

function renderSlowSqlDetailView(state) {
  if (state.loading && !state.detail) {
    return '<div class="ssq-state" role="status"><span class="ssq-spinner"></span><h3>正在加载慢 SQL 详情</h3><p>读取 SQL 指纹与优化建议，请稍候。</p></div>';
  }
  if (!state.detail) {
    return '<div class="ssq-state"><h3>尚未选择慢 SQL</h3><p>从列表选择一条记录查看详情。</p><button type="button" class="ssq-btn-primary" data-slowsql-view="slow-sql">返回慢 SQL 列表</button></div>';
  }
  return renderSlowSqlDetailMarkup(state.detail, { canManage: state.permissions.manage });
}

function renderSlowSqlError(error) {
  const forbidden = error?.kind === 'forbidden';
  return `<div class="ssq-state error" role="alert"><span class="ssq-state-icon">${forbidden ? '⌾' : '!'}</span><h3>${forbidden ? '无法查看慢 SQL 治理数据' : '慢 SQL 数据加载失败'}</h3><p>${safeText(slowSqlFailureMessage(error))}</p><button type="button" class="ssq-btn-primary" data-slowsql-retry>重试</button></div>`;
}

function renderTrendBars(buckets) {
  if (!buckets.length) return '<div class="ssq-empty"><h3>暂无趋势数据</h3><p>该慢 SQL 尚未积累采样。</p></div>';
  const max = Math.max(...buckets.map((bucket) => Number(bucket.avg) || 0), 1);
  return `<div class="ssq-bars" role="img" aria-label="耗时趋势">${buckets.map((bucket) => {
    const avg = Number(bucket.avg) || 0;
    const height = avg ? Math.max(4, Math.round(avg / max * 100)) : 0;
    return `<span class="ssq-bar" title="${safeText(formatTime(bucket.at))}：平均 ${safeText(formatMilliseconds(bucket.avg))} / ${bucket.count} 次"><em>${safeText(String(bucket.count))}</em><i style="height:${height}%"></i></span>`;
  }).join('')}</div><div class="ssq-trend-foot"><span>${safeText(formatTime(buckets[0]?.at))}</span><span>柱高按平均耗时占比</span><span>${safeText(formatTime(buckets.at(-1)?.at))}</span></div>`;
}

function fingerprintSummary(value) {
  const text = String(value ?? '');
  return text.length > 60 ? `${text.slice(0, 60)}…` : text;
}

function trimDuration(value) {
  return String(Math.round(value * 10) / 10);
}

function thresholdFailureMessage(kind) {
  return {
    'invalid-number': '最小耗时阈值必须是数字（毫秒）',
    negative: '最小耗时阈值不能为负数',
    'too-large': `最小耗时阈值不能超过 ${MAX_THRESHOLD_LABEL}`,
  }[kind] ?? '最小耗时阈值无效';
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
  window.DBPilotSlowSqlCenter = { create: createSlowSqlCenter };
}
