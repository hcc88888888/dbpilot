const MAX_RANGE_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_BUCKETS = 1000;

const STATUS_LABELS = {
  healthy: '健康',
  stale: '数据陈旧',
  offline: '离线',
};

const FAILURE_LABELS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的查看权限',
  'not-found': '请求的监控对象不存在或已无权访问',
  validation: '监控查询范围或参数不符合要求',
  'query-limit': '监控查询结果过大，请缩短时间范围或增大采样步长',
  unavailable: '监控服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

export function validateRange(fromValue, toValue, stepValue = '5m') {
  const from = new Date(fromValue);
  const to = new Date(toValue);
  if (!Number.isFinite(from.getTime()) || !Number.isFinite(to.getTime()) || from >= to) return { kind: 'invalid-range' };
  const span = to - from;
  if (span > MAX_RANGE_MS) return { kind: 'range-too-large' };
  const stepMs = parseStep(stepValue);
  if (!stepMs) return { kind: 'invalid-step' };
  if (Math.floor(span / stepMs) + 1 > MAX_BUCKETS) return { kind: 'too-many-buckets' };
  return { kind: 'valid', from: from.toISOString(), to: to.toISOString(), step: String(stepValue) };
}

export function buildMonitoringQuery(value = {}) {
  const result = {};
  if (value.from != null || value.to != null || value.step != null) {
    const range = validateRange(value.from, value.to, value.step ?? '5m');
    if (range.kind !== 'valid') return { error: range.kind };
    Object.assign(result, { from: range.from, to: range.to, step: range.step });
  }
  for (const field of ['engine', 'status']) {
    if (typeof value[field] === 'string' && value[field].trim()) result[field] = value[field].trim();
  }
  for (const field of ['limit', 'offset']) {
    const number = Number(value[field]);
    if (Number.isInteger(number) && (field === 'limit' ? number >= 1 && number <= 200 : number >= 0)) result[field] = number;
  }
  return result;
}

export function safeMetricValue(value, unit = '') {
  if (value === null || value === undefined || value === '' || !Number.isFinite(Number(value))) return '—';
  const number = Number(value);
  const formatted = Number.isInteger(number) ? String(number) : number.toLocaleString('zh-CN', { maximumFractionDigits: 2 });
  return `${formatted}${unit || ''}`;
}

export function formatMonitoringStatus(status) {
  return STATUS_LABELS[status] ?? '未知';
}

export function monitoringSourceLabel(source) {
  if (source === 'demo') return '演示数据';
  if (source === 'control-plane') return '控制面服务';
  return '来源未确认';
}

export function monitoringFailureMessage(error, subject = '监控数据') {
  return FAILURE_LABELS[error?.kind] ?? `${subject}加载失败，请稍后重试`;
}

export function createMonitoringCenter({ root, api, scope, permissions = {}, onToast = () => {} }) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('monitoring root is required');
  if (!api) throw new TypeError('monitoring api is required');

  const initialTo = new Date();
  const state = {
    view: 'overview',
    scope: normalizeScope(scope),
    permissions: { manage: permissions.manage === true },
    range: rangeEndingAt(initialTo, 60 * 60_000, '5m'),
    filters: { engine: '', status: '', limit: 50, offset: 0 },
    source: null,
    overview: null,
    instances: null,
    detail: null,
    selectedInstanceId: null,
    loading: false,
    error: null,
  };
  let activeRequest = null;
  let requestVersion = 0;

  root.addEventListener('click', (event) => {
    const target = typeof event.target?.closest === 'function' ? event.target.closest('[data-monitor-view],[data-monitor-instance],[data-monitor-range],[data-monitor-retry],[data-monitor-custom]') : null;
    if (!target) return;
    if (target.dataset.monitorView) {
      state.view = target.dataset.monitorView;
      state.selectedInstanceId = null;
      state.detail = null;
      reload();
    } else if (target.dataset.monitorInstance) {
      loadDetail(target.dataset.monitorInstance);
    } else if (target.dataset.monitorRange) {
      const hours = Number(target.dataset.monitorRange);
      state.range = rangeEndingAt(new Date(), hours * 60 * 60_000, stepForHours(hours));
      resetSelection();
      reload();
    } else if (target.hasAttribute('data-monitor-retry')) {
      state.selectedInstanceId ? loadDetail(state.selectedInstanceId) : reload();
    } else if (target.hasAttribute('data-monitor-custom')) {
      onToast('自定义指标需在受控配置流程中创建');
    }
  });

  root.addEventListener('change', (event) => {
    const target = event.target;
    if (!target?.dataset) return;
    if (target.dataset.monitorFilter) {
      state.filters[target.dataset.monitorFilter] = target.value;
      state.filters.offset = 0;
      resetSelection();
      reload();
    } else if (target.dataset.monitorStep) {
      const checked = validateRange(state.range.from, state.range.to, target.value);
      if (checked.kind !== 'valid') {
        onToast(rangeFailureMessage(checked.kind));
        render();
        return;
      }
      state.range = checked;
      resetSelection();
      reload();
    } else if (target.dataset.monitorMetric && state.selectedInstanceId) {
      loadSeries(target.value);
    }
  });

  function open(view = 'overview') {
    state.view = ['overview', 'instances', 'instance-detail'].includes(view) ? view : 'overview';
    resetSelection();
    reload();
  }

  function setScope(nextScope) {
    state.scope = normalizeScope(nextScope);
    resetSelection();
    reload();
  }

  function setRange(from, to, step = state.range.step) {
    const checked = validateRange(from, to, step);
    if (checked.kind !== 'valid') {
      onToast(rangeFailureMessage(checked.kind));
      return checked;
    }
    state.range = checked;
    resetSelection();
    reload();
    return checked;
  }

  function resetSelection() {
    abortActive();
    state.selectedInstanceId = null;
    state.detail = null;
    state.source = null;
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
    const rangeQuery = { from: state.range.from, to: state.range.to, step: state.range.step };
    const instanceQuery = buildMonitoringQuery(state.filters);
    try {
      const [overview, instances] = await Promise.all([
        api.getOverview(state.scope, rangeQuery, controller.signal),
        api.listInstances(state.scope, instanceQuery, controller.signal),
      ]);
      if (version !== requestVersion || controller.signal.aborted) return;
      state.overview = overview;
      state.instances = instances;
      state.source = overview.source ?? instances.source ?? null;
      state.loading = false;
      render();
    } catch (error) {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.loading = false;
      state.error = error;
      render();
    }
  }

  async function loadDetail(id) {
    abortActive();
    const controller = new AbortController();
    activeRequest = controller;
    const version = ++requestVersion;
    state.view = 'instance-detail';
    state.selectedInstanceId = String(id);
    state.detail = null;
    state.error = null;
    state.loading = true;
    render();
    try {
      const detail = await api.getInstance(state.scope, state.selectedInstanceId, state.range, controller.signal);
      if (version !== requestVersion || controller.signal.aborted) return;
      state.detail = detail;
      state.source = detail.source ?? null;
      state.loading = false;
      render();
    } catch (error) {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.loading = false;
      state.error = error;
      render();
    }
  }

  async function loadSeries(metric) {
    abortActive();
    const controller = new AbortController();
    activeRequest = controller;
    const version = ++requestVersion;
    state.loading = true;
    render();
    try {
      const response = await api.getSeries(state.scope, { instanceId: state.selectedInstanceId, metric, ...state.range }, controller.signal);
      if (version !== requestVersion || controller.signal.aborted) return;
      const series = response.series;
      const detail = state.detail ?? {};
      state.detail = { ...detail, metrics: [series, ...(detail.metrics ?? []).filter((item) => item.name !== series.name)] };
      state.source = response.source ?? state.source;
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
    activeRequest?.abort();
    activeRequest = null;
  }

  function render() {
    root.innerHTML = renderMonitoringWorkbench(state);
  }

  render();
  return {
    open,
    setScope,
    setRange,
    refresh: reload,
    getState: () => ({ ...state, scope: { ...state.scope }, range: { ...state.range }, filters: { ...state.filters } }),
  };
}

export function renderMonitoringWorkbench(state) {
  const source = state.source ? `<span class="monitor-source ${safeText(state.source)}">${safeText(monitoringSourceLabel(state.source))}</span>` : '';
  const body = state.error
    ? renderMonitoringError(state.error)
    : state.loading && !state.overview && !state.detail
      ? '<div class="monitor-state" role="status"><span class="monitor-spinner"></span><h3>正在加载监控数据</h3><p>查询当前项目的受控指标，请稍候。</p></div>'
      : state.view === 'instances'
        ? renderMonitoringInstances(state.instances, state.filters)
        : state.view === 'instance-detail'
          ? renderMonitoringDetail(state.detail, state.loading)
          : renderMonitoringOverview(state.overview, state.permissions);
  return `<section class="monitoring-center">
    <div class="monitor-hero"><div><span class="eyebrow">DBPILOT · BASIC MONITORING</span><h2>基础监控</h2><p>按租户与项目作用域查看数据库实例健康、指标最新值和时间趋势。</p></div><div class="monitor-hero-meta">${source}<span class="monitor-scope">${safeText(state.scope.tenantId)} / ${safeText(state.scope.projectId)}</span></div></div>
    <div class="monitor-toolbar">
      <nav class="monitor-tabs" aria-label="监控视图"><button class="${state.view === 'overview' ? 'active' : ''}" data-monitor-view="overview">监控概览</button><button class="${state.view === 'instances' ? 'active' : ''}" data-monitor-view="instances">实例列表</button>${state.view === 'instance-detail' ? '<button class="active" data-monitor-view="instance-detail">实例详情</button>' : ''}</nav>
      <div class="monitor-range" aria-label="时间范围"><span>时间范围</span>${[1, 6, 24, 168].map((hours) => `<button data-monitor-range="${hours}" class="${rangeHours(state.range) === hours ? 'active' : ''}">${hours === 168 ? '7 天' : `${hours} 小时`}</button>`).join('')}<label>步长<select data-monitor-step>${['1m', '5m', '15m', '1h'].map((step) => `<option value="${step}" ${state.range.step === step ? 'selected' : ''}>${step}</option>`).join('')}</select></label></div>
    </div>
    ${state.loading && (state.overview || state.detail) ? '<div class="monitor-progress" role="status">正在刷新…</div>' : ''}
    ${body}
  </section>`;
}

export function renderMonitoringOverview(value = {}, permissions = {}) {
  const trend = value?.trend ?? { buckets: [] };
  return `<div class="monitor-overview">
    <div class="monitor-section-head"><div><span class="monitor-source ${safeText(value?.source ?? '')}">${safeText(monitoringSourceLabel(value?.source))}</span><h3>监控概览</h3><p>陈旧与离线实例不会计入健康状态，缺失采样保持为空。</p></div>${permissions.manage === true ? '<button class="secondary" data-monitor-custom>＋ 自定义指标</button>' : ''}</div>
    <div class="monitor-health-grid">
      ${healthCard('受管实例', value?.total_instances ?? 0, 'total')}
      ${healthCard('健康', value?.healthy ?? 0, 'healthy')}
      ${healthCard('数据陈旧', value?.stale ?? 0, 'stale')}
      ${healthCard('离线', value?.offline ?? 0, 'offline')}
    </div>
    <article class="monitor-panel monitor-trend"><div class="monitor-panel-head"><div><span class="monitor-kicker">METRIC TREND</span><h3>${safeText(metricLabel(trend.name))}</h3></div><span>${safeText(trend.aggregation || 'avg')} · ${safeText(trend.unit || '')}</span></div>${renderMetricTrend(trend)}</article>
    <article class="monitor-panel"><div class="monitor-panel-head"><div><span class="monitor-kicker">ATTENTION</span><h3>需要关注的实例</h3></div><button data-monitor-view="instances">查看全部 →</button></div>${renderInstanceRows((value?.instances ?? []).filter((item) => item.status !== 'healthy'))}</article>
  </div>`;
}

export function renderMonitoringInstances(response = {}, filters = {}) {
  return `<div class="monitor-instances">
    <div class="monitor-section-head"><div><h3>实例列表</h3><p>状态来自采样新鲜度和 Agent 心跳，不用旧数据伪装健康。</p></div><div class="monitor-filters"><label>数据库<select data-monitor-filter="engine"><option value="">全部</option>${['mysql', 'postgres', 'oracle'].map((item) => `<option value="${item}" ${filters.engine === item ? 'selected' : ''}>${engineLabel(item)}</option>`).join('')}</select></label><label>状态<select data-monitor-filter="status"><option value="">全部</option>${Object.entries(STATUS_LABELS).map(([key, label]) => `<option value="${key}" ${filters.status === key ? 'selected' : ''}>${label}</option>`).join('')}</select></label></div></div>
    <article class="monitor-panel monitor-table-wrap"><div class="monitor-table" role="table"><div class="monitor-table-row head" role="row"><span>实例</span><span>引擎</span><span>状态</span><span>CPU / 连接</span><span>最近采样</span><span></span></div>${renderInstanceRows(response?.items ?? [], true)}</div>${(response?.items ?? []).length ? '' : '<div class="monitor-empty"><h3>暂无实例</h3><p>当前筛选条件下没有可展示的受管实例。</p></div>'}</article>
  </div>`;
}

export function renderMonitoringDetail(response = {}, refreshing = false) {
  if (!response?.instance) return `<div class="monitor-state"><h3>${refreshing ? '正在加载实例详情' : '尚未选择实例'}</h3><p>从实例列表选择一个实例查看指标。</p><button data-monitor-view="instances">返回实例列表</button></div>`;
  const instance = response.instance;
  const metrics = Array.isArray(response.metrics) ? response.metrics : [];
  const active = metrics[0] ?? { name: '', buckets: [] };
  return `<div class="monitor-detail">
    <div class="monitor-section-head"><div><button class="monitor-back" data-monitor-view="instances">← 实例列表</button><h3>${safeText(instance.id)}</h3><p>${safeText(engineLabel(instance.engine))} ${safeText(instance.version || '')} · ${safeText(instance.host || '主机未上报')}</p></div><span class="monitor-status ${safeText(instance.status)}">${safeText(formatMonitoringStatus(instance.status))}</span></div>
    <div class="monitor-detail-grid"><article class="monitor-panel"><span class="monitor-kicker">LATEST VALUES</span><h3>最新指标</h3><div class="monitor-latest">${Object.entries(instance.latest ?? {}).map(([name, value]) => `<div><span>${safeText(metricLabel(name))}</span><strong class="${value == null ? 'missing' : ''}">${safeText(safeMetricValue(value, metricUnit(name)))}</strong></div>`).join('') || '<p>尚无最新指标。</p>'}</div></article><article class="monitor-panel"><span class="monitor-kicker">FRESHNESS</span><h3>采集状态</h3><dl class="monitor-facts"><div><dt>最近采样</dt><dd>${safeText(formatTime(instance.last_sample_at))}</dd></div><div><dt>最近心跳</dt><dd>${safeText(formatTime(instance.last_heartbeat_at))}</dd></div><div><dt>采集周期</dt><dd>${safeText(formatCollectionInterval(instance.collect_every))}</dd></div></dl></article></div>
    <article class="monitor-panel monitor-trend"><div class="monitor-panel-head"><div><span class="monitor-kicker">INSTANCE TREND</span><h3>${safeText(metricLabel(active.name))}</h3></div>${metrics.length > 1 ? `<label>指标<select data-monitor-metric>${metrics.map((item) => `<option value="${safeText(item.name)}">${safeText(metricLabel(item.name))}</option>`).join('')}</select></label>` : ''}</div>${renderMetricTrend(active)}</article>
  </div>`;
}

function renderMonitoringError(error) {
  const unauthorized = error?.kind === 'unauthorized' || error?.kind === 'forbidden';
  return `<div class="monitor-state error ${unauthorized ? 'unauthorized' : ''}" role="alert"><span class="monitor-state-icon">${unauthorized ? '⌾' : '!'}</span><h3>${unauthorized ? '无法查看此项目' : '监控数据加载失败'}</h3><p>${safeText(monitoringFailureMessage(error))}</p><button class="primary" data-monitor-retry>重试</button></div>`;
}

function renderMetricTrend(series = {}) {
  const buckets = Array.isArray(series.buckets) ? series.buckets : [];
  if (!buckets.length) return '<div class="monitor-empty"><h3>暂无趋势数据</h3><p>所选时间范围内没有采样。</p></div>';
  const finite = buckets.map((item) => item.value).filter((value) => value != null && Number.isFinite(Number(value))).map(Number);
  const max = finite.length ? Math.max(...finite, 1) : 1;
  return `<div class="monitor-bars" role="img" aria-label="${safeText(metricLabel(series.name))} 时间趋势">${buckets.map((bucket) => bucket.value == null
    ? `<span class="monitor-bar gap" data-gap="true" title="${safeText(formatTime(bucket.at))}：缺失采样"><i></i></span>`
    : `<span class="monitor-bar" data-gap="false" title="${safeText(formatTime(bucket.at))}：${safeText(safeMetricValue(bucket.value, series.unit))}"><i style="height:${Math.max(3, Math.round(Number(bucket.value) / max * 100))}%"></i></span>`).join('')}</div><div class="monitor-trend-foot"><span>${safeText(formatTime(buckets[0]?.at))}</span><span>虚线表示缺失采样，不计为 0</span><span>${safeText(formatTime(buckets.at(-1)?.at))}</span></div>`;
}

function renderInstanceRows(items, table = false) {
  if (!items.length) return table ? '' : '<div class="monitor-empty compact"><p>没有需要关注的实例。</p></div>';
  return items.map((item) => {
    const latest = item.latest ?? {};
    if (table) return `<button class="monitor-table-row" role="row" data-monitor-instance="${safeText(item.id)}"><span><b>${safeText(item.id)}</b><small>${safeText(item.host || '主机未上报')}</small></span><span>${safeText(engineLabel(item.engine))}</span><span><i class="monitor-status ${safeText(item.status)}">${safeText(formatMonitoringStatus(item.status))}</i></span><span>${safeText(safeMetricValue(latest['host.cpu'], '%'))} / ${safeText(safeMetricValue(latest['db.connections']))}</span><span>${safeText(formatTime(item.last_sample_at))}</span><span>详情 →</span></button>`;
    return `<button class="monitor-attention-row" data-monitor-instance="${safeText(item.id)}"><span class="engine-mark ${safeText(item.engine)}">${safeText(engineMark(item.engine))}</span><span><b>${safeText(item.id)}</b><small>${safeText(engineLabel(item.engine))} · ${safeText(formatTime(item.last_sample_at))}</small></span><i class="monitor-status ${safeText(item.status)}">${safeText(formatMonitoringStatus(item.status))}</i><span>查看详情 →</span></button>`;
  }).join('');
}

function healthCard(label, value, status) {
  return `<article class="monitor-health-card ${status}"><span>${safeText(label)}</span><strong>${safeText(String(value))}</strong><i></i></article>`;
}

function rangeEndingAt(toValue, spanMs, step) {
  const to = new Date(toValue);
  return { kind: 'valid', from: new Date(to - spanMs).toISOString(), to: to.toISOString(), step };
}

function rangeHours(range) {
  return Math.round((new Date(range.to) - new Date(range.from)) / 3_600_000);
}

function stepForHours(hours) {
  if (hours <= 1) return '5m';
  if (hours <= 6) return '5m';
  if (hours <= 24) return '15m';
  return '1h';
}

function parseStep(value) {
  const match = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(String(value ?? '').trim());
  if (!match) return 0;
  const factor = { ms: 1, s: 1000, m: 60_000, h: 3_600_000 }[match[2]];
  const result = Number(match[1]) * factor;
  return Number.isFinite(result) && result > 0 ? result : 0;
}

function normalizeScope(scope) {
  return {
    tenantId: typeof scope?.tenantId === 'string' && scope.tenantId.trim() ? scope.tenantId.trim() : '未配置',
    projectId: typeof scope?.projectId === 'string' && scope.projectId.trim() ? scope.projectId.trim() : '未配置',
  };
}

function rangeFailureMessage(kind) {
  return {
    'invalid-range': '开始时间必须早于结束时间',
    'range-too-large': '时间范围不能超过 7 天',
    'invalid-step': '采样步长必须是正数时长',
    'too-many-buckets': '采样桶不能超过 1000 个，请增大步长',
  }[kind] ?? '监控查询参数无效';
}

function metricLabel(name) {
  return {
    'host.cpu': 'CPU 使用率',
    'host.memory': '内存使用率',
    'db.connections': '数据库连接数',
    'db.sessions': '数据库会话数',
    'db.qps': '每秒查询数',
    'db.transactions': '事务吞吐',
    'db.wait_time': '等待时间',
  }[name] ?? name ?? '监控指标';
}

function metricUnit(name) {
  return name === 'host.cpu' || name === 'host.memory' ? '%' : '';
}

function engineLabel(engine) {
  return { mysql: 'MySQL', postgres: 'PostgreSQL', oracle: 'Oracle' }[engine] ?? engine ?? '未知引擎';
}

function engineMark(engine) {
  return { mysql: 'MY', postgres: 'PG', oracle: 'OR' }[engine] ?? 'DB';
}

function formatTime(value) {
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '未上报';
  return date.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
}

function formatCollectionInterval(value) {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return '未上报';
  const seconds = number > 1_000_000 ? number / 1_000_000_000 : number;
  return seconds >= 60 ? `${Math.round(seconds / 60)} 分钟` : `${Math.round(seconds)} 秒`;
}

function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]);
}

if (typeof window !== 'undefined') {
  window.DBPilotMonitoringCenter = { create: createMonitoringCenter };
}
