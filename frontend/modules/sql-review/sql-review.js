const VIEW_COPY = {
  overview: ['审核概览', 'SQL 审核的统计、近期审核记录与规则命中排行。'],
  'sql-review': ['审核列表', '按状态、风险、实例与关键字筛选 SQL 审核记录。'],
  'review-detail': ['审核详情', '查看 SQL 内容、规则命中、审核摘要与历史。'],
  create: ['提交审核', '提交待审核 SQL，规则引擎将进行静态扫描。'],
  rules: ['审核规则', '规则引擎的静态匹配规则，启停即时生效。'],
};

const STATUS_LABELS = {
  pending: '待审核',
  reviewing: '审核中',
  approved: '已批准',
  rejected: '已拒绝',
};

const RISK_LABELS = {
  high: '高风险',
  medium: '中风险',
  low: '低风险',
};

const SEVERITY_LABELS = {
  error: '错误',
  warning: '警告',
  info: '提示',
};

const FAILURE_LABELS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '审核记录不存在或已无权访问',
  conflict: '审核记录状态已更新，请刷新后重试',
  validation: '审核内容不符合要求，请修改后重试',
  unavailable: 'SQL 审核服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const SENSITIVE_PATTERN = /(?:\b(?:password|passwd|pwd|token|secret|credential|api[_\s-]?key)\b|connectionstring|dsn)/i;

const INSTANCE_OPTIONS = [
  { id: 'mysql-prod-order-01', name: '订单主库', engine: 'MySQL' },
  { id: 'pgsql-user-primary', name: '用户中心', engine: 'PostgreSQL' },
  { id: 'redis-session-01', name: '缓存集群', engine: 'Redis' },
  { id: 'mysql-analytics-replica', name: '分析从库', engine: 'MySQL' },
];

const CONFIRM_COPY = {
  approve: '确认批准该 SQL 审核？批准后记录进入已批准状态。',
  reject: '确认驳回该审核？驳回后提交人可修改后重新提交。',
};

const CURRENT_ACTOR = 'ops-01';

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function reviewStatusLabel(status) {
  return STATUS_LABELS[String(status ?? '')] ?? '未知';
}

export function riskLevelLabel(risk) {
  return RISK_LABELS[String(risk ?? '')] ?? '未知';
}

export function severityLabel(severity) {
  return SEVERITY_LABELS[String(severity ?? '')] ?? '未知';
}

export function sqlReviewSourceLabel(source) {
  if (source === 'demo') return '演示数据';
  if (source === 'http' || source === 'control-plane') return '控制面服务';
  return '来源未确认';
}

export function sqlReviewFailureMessage(error, subject = 'SQL 审核数据') {
  return FAILURE_LABELS[error?.kind] ?? `${subject}加载失败，请稍后重试`;
}

export function buildReviewFilters(entries) {
  const source = entries instanceof Map ? entries : new Map(Object.entries(entries ?? {}));
  return Object.fromEntries([...source].filter(([, value]) => String(value ?? '').trim() !== ''));
}

export function validateReviewSubmission(input = {}) {
  const errors = {};
  const title = String(input.title ?? '').trim();
  const sql = String(input.sql ?? '').trim();
  if (!title) errors.title = '请填写审核标题';
  if (!sql) errors.sql = '请填写待审核 SQL';
  else if (SENSITIVE_PATTERN.test(sql)) errors.sql = 'SQL 中不能包含密码或凭据';
  return errors;
}

export function simulateRuleEngine(sql, rules = []) {
  const text = String(sql ?? '');
  const enabled = (Array.isArray(rules) ? rules : []).filter((rule) => rule.enabled !== false);
  const findRule = (id) => enabled.find((rule) => String(rule.id) === String(id));
  const hits = [];
  const hit = (ruleId, message, suggestion, pattern) => {
    const rule = findRule(ruleId);
    if (!rule) return;
    hits.push({
      rule_id: rule.id,
      rule_name: rule.name ?? ruleId,
      severity: rule.severity ?? 'info',
      message,
      position: pattern ? text.search(pattern) : null,
      suggestion,
    });
  };
  if (/\bselect\s+\*/i.test(text)) hit('R-001', '避免 SELECT *，应显式列出字段', '列出明确字段', /\bselect\s+\*/i);
  if (/\bselect\b/i.test(text) && !/\blimit\b/i.test(text)) hit('R-002', '查询缺少 LIMIT 限制', '添加 LIMIT', /\bselect\b/i);
  if (/(?:delete\s+from|update\s+\w+)/i.test(text) && !/\bwhere\b/i.test(text)) hit('R-003', '高危变更缺少 WHERE 条件', '补充 WHERE 并二次确认', /(?:delete\s+from|update\s+\w+)/i);
  if (/like\s*'%/i.test(text)) hit('R-004', '模糊查询可能导致全表扫描', '考虑前缀匹配或全文索引', /like\s*'%/i);
  if (/\b(?:drop\s+table|truncate)\b/i.test(text)) hit('R-005', '禁止的破坏性语句', '走工单审批流程', /\b(?:drop\s+table|truncate)\b/i);
  if (/\balter\s+table\b/i.test(text) && !/\bbackup\b/i.test(text)) hit('R-006', 'DDL 变更建议先备份', '执行前备份', /\balter\s+table\b/i);
  if (SENSITIVE_PATTERN.test(text)) hit('R-007', 'SQL 中出现疑似凭据', '移除凭据字面量', SENSITIVE_PATTERN);
  return hits;
}

export function deriveReviewAssessment(hits = []) {
  const list = Array.isArray(hits) ? hits : [];
  const errors = list.filter((hit) => hit.severity === 'error').length;
  const warnings = list.filter((hit) => hit.severity === 'warning').length;
  const infos = list.filter((hit) => hit.severity === 'info').length;
  const risk = errors > 0 ? 'high' : warnings > 0 ? 'medium' : 'low';
  const score = Math.max(0, 100 - errors * 30 - warnings * 10 - infos * 3);
  return { risk, score, summary: { errors, warnings, infos } };
}

export function evaluateSqlReview(sql, rules = []) {
  const hits = simulateRuleEngine(sql, rules);
  return { hits, ...deriveReviewAssessment(hits) };
}

export function renderReviewListMarkup({ items = [], filters = {}, source = '', page = 1, pageSize = 10, total = 0, totalPages = 1 } = {}) {
  const rows = (Array.isArray(items) ? items : []).map((item) => {
    const instanceName = item.instance_name ?? item.instance_id ?? '—';
    const engine = item.engine ?? '';
    return `<div class="srv-table-row" role="row">
      <span><b class="srv-review-id">${safeText(item.id)}</b></span>
      <span class="srv-cell-title">${safeText(item.title ?? '—')}</span>
      <span><i class="srv-engine ${safeText(engine)}">${safeText(engine)}</i>${safeText(instanceName)}</span>
      <span><i class="srv-tag ${safeText(item.risk ?? '')}">${safeText(riskLevelLabel(item.risk))}</i></span>
      <span><i class="srv-score-pill ${safeText(item.risk ?? '')}">${safeText(item.score == null ? '—' : String(item.score))}</i></span>
      <span><i class="srv-tag ${safeText(item.status ?? '')}">${safeText(reviewStatusLabel(item.status))}</i></span>
      <span>${safeText(item.submitter ?? '—')}</span>
      <span>${safeText(formatTime(item.submitted_at))}</span>
      <span><button type="button" class="srv-btn-secondary srv-row-action" data-sqlreview-review="${safeText(item.id)}">查看</button></span>
    </div>`;
  }).join('');
  const sourceBadge = source ? `<span class="srv-source ${safeText(source)}">${safeText(sqlReviewSourceLabel(source))}</span>` : '';
  const statusOptions = Object.entries(STATUS_LABELS).map(([value, label]) => `<option value="${value}" ${filters.status === value ? 'selected' : ''}>${label}</option>`).join('');
  const riskOptions = [['high', '高风险'], ['medium', '中风险'], ['low', '低风险']].map(([value, label]) => `<option value="${value}" ${filters.risk === value ? 'selected' : ''}>${label}</option>`).join('');
  const instanceOptions = INSTANCE_OPTIONS.map((option) => `<option value="${option.id}" ${filters.instance_id === option.id ? 'selected' : ''}>${option.id} · ${option.name}（${option.engine}）</option>`).join('');
  const empty = (Array.isArray(items) ? items : []).length ? '' : '<div class="srv-empty"><h3>暂无审核记录</h3><p>当前筛选条件下没有可展示的 SQL 审核记录。</p></div>';
  return `<div class="srv-list">
    <div class="srv-section-head"><div><span class="srv-kicker">REVIEW LIST</span><h3>审核列表</h3><p>按状态、风险、实例与关键字筛选当前项目的 SQL 审核记录。</p></div>${sourceBadge}</div>
    <div class="srv-filter" role="search">
      <label>状态<select class="srv-select" data-sqlreview-filter="status"><option value="">全部</option>${statusOptions}</select></label>
      <label>风险<select class="srv-select" data-sqlreview-filter="risk"><option value="">全部</option>${riskOptions}</select></label>
      <label>实例<select class="srv-select" data-sqlreview-filter="instance_id"><option value="">全部</option>${instanceOptions}</select></label>
      <label>搜索<input class="srv-input" data-sqlreview-search value="${safeText(filters.search ?? '')}" placeholder="编号 / 标题 / SQL" autocomplete="off" /></label>
    </div>
    <article class="srv-panel srv-table-wrap"><div class="srv-table" role="table"><div class="srv-table-row head" role="row"><span>编号</span><span>标题</span><span>实例</span><span>风险</span><span>分数</span><span>状态</span><span>提交人</span><span>提交时间</span><span></span></div>${rows}</div>${empty}</article>
    <div class="srv-pager"><span>共 ${total} 条</span><div><button type="button" class="srv-btn-secondary" data-sqlreview-prev ${page <= 1 ? 'disabled' : ''}>上一页</button><span>第 ${page} / ${totalPages} 页</span><button type="button" class="srv-btn-secondary" data-sqlreview-next ${page >= totalPages ? 'disabled' : ''}>下一页</button></div></div>
  </div>`;
}

export function renderReviewDetailMarkup(review = {}, options = {}) {
  const canManage = options.canManage === true;
  if (!review || review.id == null) {
    return '<div class="srv-empty"><h3>暂无审核详情</h3><p>无法读取该审核记录的内容，请返回列表重试。</p><button type="button" class="srv-btn-secondary" data-sqlreview-view="sql-review">返回审核列表</button></div>';
  }
  const hits = Array.isArray(review.hits) ? review.hits : [];
  const summary = review.summary ?? {};
  const history = Array.isArray(review.history) ? review.history : [];
  const meta = [
    ['审核编号', review.id],
    ['审核标题', review.title],
    ['风险等级', riskLevelLabel(review.risk)],
    ['目标实例', review.instance_name ? `${review.instance_name}（${review.engine ?? ''}）` : (review.instance_id ?? '—')],
    ['提交人', review.submitter],
    ['提交时间', formatTime(review.submitted_at)],
    ['审核人', review.reviewer || '—'],
    ['审核时间', formatTime(review.reviewed_at)],
  ];
  const hitsMarkup = hits.length
    ? hits.map((hit) => `<div class="srv-hit"><i class="srv-severity ${safeText(hit.severity ?? '')}"></i><span><b>${safeText(hit.rule_name ?? hit.rule_id ?? '')}</b>${hit.position != null ? `<em>@ ${safeText(String(hit.position))}</em>` : ''}</span><p>${safeText(hit.message ?? '')}</p>${hit.suggestion ? `<p class="srv-hit-suggestion">建议：${safeText(hit.suggestion)}</p>` : ''}</div>`).join('')
    : '<div class="srv-empty compact"><p>未命中任何规则。</p></div>';
  const historyMarkup = history.length
    ? `<ol class="srv-timeline">${history.map((entry) => `<li><time>${safeText(formatTime(entry.at))}</time><span><b>${safeText(reviewStatusLabel(entry.status))}</b> · ${safeText(entry.by ?? '—')}：${safeText(entry.note ?? '')}</span></li>`).join('')}</ol>`
    : '<p>暂无审核记录。</p>';
  const actions = canManage && (review.status === 'pending' || review.status === 'reviewing')
    ? `<div class="srv-detail-actions"><button type="button" class="srv-btn-primary" data-sqlreview-action="approve" data-sqlreview-target="${safeText(review.id)}">批准审核</button><button type="button" class="srv-btn-danger" data-sqlreview-action="reject" data-sqlreview-target="${safeText(review.id)}">驳回审核</button></div>`
    : `<p>${canManage ? '当前状态下没有可执行的审核操作。' : '当前账号没有该项目的操作权限。'}</p>`;
  return `<div class="srv-detail">
    <div class="srv-detail-head"><button type="button" class="srv-back" data-sqlreview-back>← 返回审核列表</button><div><h3>审核详情</h3><p>${safeText(review.title ?? review.id)}</p></div><span class="srv-tag ${safeText(review.status ?? '')}">${safeText(reviewStatusLabel(review.status))}</span></div>
    <div class="srv-detail-grid">
      <div class="srv-detail-main">
        <article class="srv-panel"><h4>基本信息</h4><dl class="srv-kv">${meta.map(([key, value]) => `<div><dt>${safeText(key)}</dt><dd>${safeText(value ?? '—')}</dd></div>`).join('')}</dl></article>
        <article class="srv-panel"><div class="srv-panel-head"><div><span class="srv-kicker">SQL CONTENT</span><h4>SQL 内容</h4></div><span class="srv-score-block ${safeText(review.risk ?? '')}"><b>${safeText(review.score == null ? '—' : String(review.score))}</b><em>风险 ${safeText(riskLevelLabel(review.risk))}</em></span></div><pre class="srv-code">${safeText(review.sql ?? '')}</pre></article>
        <article class="srv-panel"><h4>规则命中（${hits.length}）</h4>${hitsMarkup}</article>
        <article class="srv-panel"><h4>审核历史</h4>${historyMarkup}</article>
      </div>
      <aside class="srv-detail-side">
        <article class="srv-panel"><h4>审核摘要</h4><div class="srv-summary">${summaryRow('error', summary.errors)}${summaryRow('warning', summary.warnings)}${summaryRow('info', summary.infos)}</div></article>
        <article class="srv-panel"><h4>审核操作</h4>${actions}</article>
      </aside>
    </div>
  </div>`;
}

function summaryRow(kind, value) {
  return `<div class="srv-summary-row ${kind}"><span>${kind === 'error' ? '错误' : kind === 'warning' ? '警告' : '提示'}</span><b>${safeText(value == null ? '0' : String(value))}</b></div>`;
}

export function createSqlReviewCenter({ root, api, scope, permissions = {}, onToast = () => {} } = {}) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('sql review root is required');
  if (!api) throw new TypeError('sql review api is required');

  const state = {
    view: 'overview',
    scope: normalizeScope(scope),
    permissions: { manage: permissions.manage === true },
    filters: { status: '', risk: '', instance_id: '', search: '' },
    page: 1,
    pageSize: 10,
    source: null,
    overview: null,
    list: null,
    detail: null,
    rules: null,
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
      ? event.target.closest('[data-sqlreview-view],[data-sqlreview-review],[data-sqlreview-back],[data-sqlreview-retry],[data-sqlreview-prev],[data-sqlreview-next],[data-sqlreview-action],[data-sqlreview-confirm-yes],[data-sqlreview-confirm-no],[data-sqlreview-rule-toggle]')
      : null;
    if (!target) return;
    if (target.dataset.sqlreviewView) {
      open(target.dataset.sqlreviewView);
    } else if (target.dataset.sqlreviewReview) {
      loadDetail(target.dataset.sqlreviewReview);
    } else if (target.hasAttribute('data-sqlreview-back')) {
      open('sql-review');
    } else if (target.hasAttribute('data-sqlreview-retry')) {
      reload();
    } else if (target.hasAttribute('data-sqlreview-prev')) {
      state.page = Math.max(1, state.page - 1);
      reload();
    } else if (target.hasAttribute('data-sqlreview-next')) {
      state.page += 1;
      reload();
    } else if (target.dataset.sqlreviewAction) {
      state.confirmAction = { action: target.dataset.sqlreviewAction, id: String(target.dataset.sqlreviewTarget ?? '') };
      render();
    } else if (target.hasAttribute('data-sqlreview-confirm-yes')) {
      runConfirmedAction();
    } else if (target.hasAttribute('data-sqlreview-confirm-no')) {
      state.confirmAction = null;
      render();
    } else if (target.dataset.sqlreviewRuleToggle) {
      toggleRule(target);
    }
  });

  root.addEventListener('change', (event) => {
    const target = event.target;
    if (!target?.dataset || !target.dataset.sqlreviewFilter) return;
    state.filters[target.dataset.sqlreviewFilter] = target.value;
    state.page = 1;
    reload();
  });

  root.addEventListener('input', (event) => {
    const target = event.target;
    if (!target?.dataset || !target.dataset.sqlreviewSearch) return;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.filters.search = target.value;
      state.page = 1;
      reload();
    }, 200);
  });

  root.addEventListener('submit', (event) => {
    const form = typeof event.target?.closest === 'function' ? event.target.closest('[data-sqlreview-create-form]') : null;
    if (!form) return;
    event.preventDefault();
    submitCreate(form);
  });

  function open(view = 'overview') {
    const allowed = ['overview', 'sql-review', 'review-detail', 'create', 'rules'];
    if (!allowed.includes(view)) view = 'overview';
    if (view === 'create' && !state.permissions.manage) {
      onToast('当前账号没有该项目的操作权限');
      view = state.view === 'create' ? 'sql-review' : state.view;
    }
    if (view === 'review-detail' && !state.selectedId) view = 'sql-review';
    state.view = view;
    if (view !== 'review-detail') {
      state.selectedId = null;
      state.detail = null;
    }
    reload();
  }

  function setScope(nextScope) {
    state.scope = normalizeScope(nextScope);
    state.filters = { status: '', risk: '', instance_id: '', search: '' };
    state.page = 1;
    state.selectedId = null;
    state.detail = null;
    state.overview = null;
    state.list = null;
    state.rules = null;
    state.confirmAction = null;
    reload();
  }

  function loadDetail(id) {
    state.selectedId = String(id);
    state.view = 'review-detail';
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
      if (state.view === 'sql-review') {
        result = await api.listReviews(state.scope, buildReviewFilters({ ...state.filters, page: state.page, pageSize: state.pageSize }), controller.signal);
      } else if (state.view === 'review-detail') {
        if (!state.selectedId) state.view = 'sql-review';
        result = state.view === 'sql-review'
          ? await api.listReviews(state.scope, buildReviewFilters({ ...state.filters, page: state.page, pageSize: state.pageSize }), controller.signal)
          : await api.getReview(state.scope, state.selectedId, controller.signal);
      } else if (state.view === 'rules') {
        result = await api.listRules(state.scope, controller.signal);
      } else if (state.view === 'create') {
        state.loading = false;
        render();
        return;
      } else {
        result = await api.getOverview(state.scope, controller.signal);
      }
      if (version !== requestVersion || controller.signal.aborted) return;
      if (state.view === 'sql-review') state.list = result;
      else if (state.view === 'review-detail') state.detail = result;
      else if (state.view === 'rules') state.rules = result;
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
      if (action === 'approve') {
        await api.approveReview(state.scope, id, { reviewer: CURRENT_ACTOR, note: '' }, signal);
        onToast('审核已批准');
      } else if (action === 'reject') {
        await api.rejectReview(state.scope, id, { reviewer: CURRENT_ACTOR, note: '' }, signal);
        onToast('审核已驳回');
      }
      await loadDetail(id);
    } catch (error) {
      if (error?.name === 'AbortError') return;
      onToast(sqlReviewFailureMessage(error, '审核记录'));
      render();
    }
  }

  async function submitCreate(form) {
    if (!state.permissions.manage) return;
    const data = new FormData(form);
    const input = {
      title: String(data.get('title') ?? '').trim(),
      instance_id: String(data.get('instance_id') ?? '').trim(),
      sql: String(data.get('sql') ?? ''),
      submitter: CURRENT_ACTOR,
    };
    const instance = INSTANCE_OPTIONS.find((option) => option.id === input.instance_id);
    input.engine = instance?.engine ?? '';
    const errors = validateReviewSubmission(input);
    const output = form.querySelector('[data-srv-form-errors]');
    if (Object.keys(errors).length) {
      if (output) output.textContent = Object.values(errors).join(' ');
      return;
    }
    if (output) output.textContent = '';
    form.querySelectorAll('button, input, select, textarea').forEach((element) => { element.disabled = true; });
    try {
      const created = await api.submitReview(state.scope, input, activeRequest?.signal);
      onToast('SQL 审核已提交');
      state.selectedId = created?.id ?? null;
      open('review-detail');
    } catch (error) {
      if (error?.name === 'AbortError') return;
      if (output) output.textContent = sqlReviewFailureMessage(error, '审核提交');
      form.querySelectorAll('button, input, select, textarea').forEach((element) => { element.disabled = false; });
    }
  }

  async function toggleRule(target) {
    if (!state.permissions.manage) return;
    const id = String(target.dataset.sqlreviewRuleToggle);
    const enabled = target.dataset.enabled !== 'true';
    const signal = activeRequest?.signal;
    try {
      await api.setRuleEnabled(state.scope, id, enabled, signal);
      onToast(enabled ? '规则已启用' : '规则已停用');
      reload();
    } catch (error) {
      if (error?.name === 'AbortError') return;
      onToast(sqlReviewFailureMessage(error, '审核规则'));
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
  const source = state.source ? `<span class="srv-source ${safeText(state.source)}">${safeText(sqlReviewSourceLabel(state.source))}</span>` : '';
  const body = state.error
    ? renderError(state.error)
    : state.view === 'sql-review'
      ? renderListView(state)
      : state.view === 'review-detail'
        ? renderDetailView(state)
        : state.view === 'create'
          ? renderCreateView(state)
          : state.view === 'rules'
            ? renderRulesView(state)
            : renderOverviewView(state);
  return `<section class="srv-center" aria-label="SQL 审核">
    <div class="srv-hero"><div><span class="eyebrow">DBPILOT · SQL 审核</span><h2>${safeText(title)}</h2><p>${safeText(description)}</p></div><div class="srv-hero-meta">${source}<span class="srv-scope">${safeText(state.scope.tenantId)} / ${safeText(state.scope.projectId)}</span></div></div>
    <nav class="srv-tabs" aria-label="SQL 审核视图"><button type="button" class="${state.view === 'overview' ? 'active' : ''}" data-sqlreview-view="overview">审核概览</button><button type="button" class="${state.view === 'sql-review' || state.view === 'review-detail' ? 'active' : ''}" data-sqlreview-view="sql-review">审核列表</button>${state.permissions.manage ? '<button type="button" class="srv-tab-create" data-sqlreview-view="create">提交审核</button>' : ''}<button type="button" class="${state.view === 'rules' ? 'active' : ''}" data-sqlreview-view="rules">审核规则</button></nav>
    ${state.loading && !state.error && state.view !== 'create' ? '<div class="srv-progress" role="status">正在加载…</div>' : ''}
    ${body}
  </section>`;
}

function renderOverviewView(state) {
  if (state.loading && !state.overview) {
    return '<div class="srv-state" role="status"><span class="srv-spinner"></span><h3>正在加载审核概览</h3><p>统计与近期审核记录即将呈现。</p></div>';
  }
  const overview = state.overview ?? {};
  const stats = overview.stats ?? {};
  const recent = Array.isArray(overview.recent) ? overview.recent : [];
  const topRules = Array.isArray(overview.top_rules) ? overview.top_rules : [];
  const rate = stats.approved_today_rate;
  const statCards = [
    ['待审核', stats.pending ?? 0, 'pending', '等待人工审核的 SQL 提交'],
    ['高风险', stats.high_risk ?? 0, 'high', '规则引擎判定为高风险的审核记录'],
    ['今日审核通过率', rate == null ? '—' : `${rate}%`, 'rate', `今日已审核 ${stats.reviewed_today ?? 0} 条，通过 ${stats.approved_today ?? 0} 条`],
    ['规则总数启用数', `${stats.rules_enabled ?? 0} / ${stats.rules_total ?? 0}`, 'rules', '当前启用的 SQL 审核规则'],
  ].map(([label, value, tone, hint]) => `<article class="srv-stat-card ${tone}"><span>${safeText(label)}</span><strong>${safeText(String(value))}</strong><p>${safeText(hint)}</p><i></i></article>`).join('');
  const recentRows = recent.length
    ? recent.map((review) => `<button type="button" class="srv-recent-row" data-sqlreview-review="${safeText(review.id)}"><span><b>${safeText(review.title ?? review.id)}</b><small>${safeText(review.id)} · ${safeText(review.instance_name ?? review.instance_id ?? '')}</small></span><span>${safeText(reviewStatusLabel(review.status))}</span><i class="srv-tag ${safeText(review.risk ?? '')}">${safeText(riskLevelLabel(review.risk))}</i><span>${safeText(review.submitter ?? '')}</span></button>`).join('')
    : '<div class="srv-empty"><h3>暂无近期审核</h3><p>当前项目还没有 SQL 审核记录。</p></div>';
  const maxCount = topRules.length ? Math.max(...topRules.map((item) => item.count ?? 0), 1) : 1;
  const topRuleBars = topRules.length
    ? `<div class="srv-toprule">${topRules.map((item) => {
        const count = Number(item.count) || 0;
        const percent = Math.round(count / maxCount * 100);
        return `<div class="srv-toprule-row"><span>${safeText(item.rule_name ?? '—')}</span><i class="srv-toprule-bar"><b style="width:${percent}%"></b></i><span>${count}</span></div>`;
      }).join('')}</div>`
    : '<p>暂无规则命中数据。</p>';
  return `<div class="srv-overview">
    <div class="srv-section-head"><div><span class="srv-kicker">OVERVIEW</span><h3>审核概览</h3><p>SQL 审核的统计、近期审核记录与规则命中排行。</p></div><span class="srv-source ${safeText(overview.source ?? '')}">${safeText(sqlReviewSourceLabel(overview.source))}</span></div>
    <div class="srv-stats">${statCards}</div>
    <div class="srv-overview-grid">
      <article class="srv-panel"><div class="srv-panel-head"><div><span class="srv-kicker">RECENT</span><h3>近期审核</h3></div><button type="button" class="srv-btn-secondary" data-sqlreview-view="sql-review">查看全部 →</button></div>${recentRows}</article>
      <article class="srv-panel"><div class="srv-panel-head"><div><span class="srv-kicker">TOP RULES</span><h3>规则命中 Top</h3></div></div>${topRuleBars}</article>
    </div>
  </div>`;
}

function renderListView(state) {
  if (state.loading && !state.list) {
    return '<div class="srv-state" role="status"><span class="srv-spinner"></span><h3>正在加载审核列表</h3><p>筛选条件变更后将重新请求当前项目的审核记录。</p></div>';
  }
  const list = state.list ?? {};
  return renderReviewListMarkup({
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
    return '<div class="srv-state" role="status"><span class="srv-spinner"></span><h3>正在加载审核详情</h3><p>读取 SQL 内容与规则命中，请稍候。</p></div>';
  }
  if (!state.detail) {
    return '<div class="srv-state"><h3>尚未选择审核记录</h3><p>从审核列表选择一条记录查看详情。</p><button type="button" class="srv-btn-primary" data-sqlreview-view="sql-review">返回审核列表</button></div>';
  }
  const confirmBar = state.confirmAction ? renderConfirmBar(state.confirmAction) : '';
  return `${confirmBar}${renderReviewDetailMarkup(state.detail, { canManage: state.permissions.manage })}`;
}

function renderCreateView(state) {
  if (!state.permissions.manage) {
    return '<div class="srv-state"><h3>当前账号没有该项目的操作权限</h3><p>提交 SQL 审核需要项目管理权限。</p><button type="button" class="srv-btn-primary" data-sqlreview-view="sql-review">返回审核列表</button></div>';
  }
  const instanceOptions = INSTANCE_OPTIONS.map((option) => `<option value="${option.id}">${option.id} · ${option.name}（${option.engine}）</option>`).join('');
  return `<div class="srv-create">
    <div class="srv-section-head"><div><span class="srv-kicker">SUBMIT REVIEW</span><h3>提交审核</h3><p>提交待审核 SQL，规则引擎将进行静态扫描，结果供人工复核。</p></div></div>
    <form class="srv-panel srv-form" data-sqlreview-create-form novalidate>
      <label>审核标题<input class="srv-input" name="title" required maxlength="120" placeholder="例如：订单主库清理历史草稿订单" autocomplete="off" /></label>
      <label>目标实例<select class="srv-select" name="instance_id" required>${instanceOptions}</select></label>
      <label>待审核 SQL<textarea class="srv-input srv-sql-input" name="sql" rows="8" required placeholder="输入待审核的 SELECT / DML / DDL 语句" spellcheck="false"></textarea></label>
      <p class="srv-form-errors" data-srv-form-errors role="alert" aria-live="polite"></p>
      <div class="srv-form-actions"><button type="button" class="srv-btn-secondary" data-sqlreview-view="sql-review">取消</button><button type="submit" class="srv-btn-primary">提交审核</button></div>
    </form>
  </div>`;
}

function renderRulesView(state) {
  if (state.loading && !state.rules) {
    return '<div class="srv-state" role="status"><span class="srv-spinner"></span><h3>正在加载审核规则</h3><p>规则引擎的匹配规则即将呈现。</p></div>';
  }
  const items = Array.isArray(state.rules?.items) ? state.rules.items : [];
  const rows = items.map((rule) => `<div class="srv-rule-row" role="row">
    <span><b class="srv-rule-id">${safeText(rule.id)}</b></span>
    <span class="srv-cell-title">${safeText(rule.name ?? '—')}</span>
    <span>${safeText(rule.category ?? '—')}</span>
    <span><i class="srv-tag ${safeText(rule.severity ?? '')}">${safeText(severityLabel(rule.severity))}</i></span>
    <span>${safeText(rule.description ?? '—')}</span>
    <span><i class="srv-tag ${rule.enabled ? 'enabled' : 'disabled'}">${rule.enabled ? '已启用' : '已停用'}</i></span>
    ${state.permissions.manage ? `<span><button type="button" class="srv-btn-secondary" data-sqlreview-rule-toggle="${safeText(rule.id)}" data-enabled="${rule.enabled ? 'true' : 'false'}">${rule.enabled ? '停用' : '启用'}</button></span>` : '<span></span>'}
  </div>`).join('');
  const empty = items.length ? '' : '<div class="srv-empty"><h3>暂无审核规则</h3><p>当前项目还没有配置审核规则。</p></div>';
  return `<div class="srv-rules">
    <div class="srv-section-head"><div><span class="srv-kicker">RULE ENGINE</span><h3>审核规则</h3><p>规则引擎按顺序对 SQL 文本做静态匹配，启停即时生效。</p></div></div>
    <article class="srv-panel srv-table-wrap"><div class="srv-table" role="table"><div class="srv-table-row head" role="row"><span>编号</span><span>规则名</span><span>分类</span><span>级别</span><span>描述</span><span>状态</span><span></span></div>${rows}</div>${empty}</article>
  </div>`;
}

function renderError(error) {
  const forbidden = error?.kind === 'forbidden';
  return `<div class="srv-error" role="alert"><span class="srv-error-icon">${forbidden ? '⌾' : '!'}</span><h3>${forbidden ? '无法查看 SQL 审核' : 'SQL 审核数据加载失败'}</h3><p>${safeText(sqlReviewFailureMessage(error, 'SQL 审核数据'))}</p><button type="button" class="srv-btn-primary" data-sqlreview-retry>重试</button></div>`;
}

function renderConfirmBar(confirm) {
  const message = CONFIRM_COPY[confirm.action] ?? '确认执行该操作？';
  return `<div class="srv-confirm" role="alertdialog" aria-label="确认操作"><p>${safeText(message)}</p><div><button type="button" class="srv-btn-primary" data-sqlreview-confirm-yes>确认</button><button type="button" class="srv-btn-secondary" data-sqlreview-confirm-no>取消</button></div></div>`;
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
  window.DBPilotSqlReviewCenter = { create: createSqlReviewCenter };
}
