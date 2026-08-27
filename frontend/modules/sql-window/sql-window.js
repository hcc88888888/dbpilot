import { DEMO_INSTANCES, validateSql } from './sql-window-api.js';

export { detectStatementType, extractColumns, validateSql } from './sql-window-api.js';

const FAILURE_LABELS = {
  unauthorized: '登录状态已失效，请重新登录',
  forbidden: '当前账号没有该项目的操作权限',
  'not-found': '请求的 SQL 对象不存在或已无权访问',
  conflict: 'SQL 会话已失效或存在冲突，请刷新后重试',
  validation: 'SQL 内容不符合执行要求，请修改后重试',
  unavailable: 'SQL 执行服务暂时不可用，请稍后重试',
  network: '无法连接控制面服务，请检查网络后重试',
};

const HISTORY_LIMIT = 20;
const HISTORY_SUMMARY_MAX = 60;

const SQL_WINDOW_VIEWS = ['overview', 'plan', 'history'];

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function sqlSourceLabel(source) {
  if (source === 'demo') return '演示数据';
  if (source === 'http') return '控制面服务';
  return '来源未确认';
}

export function sqlFailureMessage(error) {
  if (error?.kind === 'forbidden') return '当前账号没有该项目的操作权限';
  return FAILURE_LABELS[error?.kind] ?? 'SQL 执行服务暂时不可用，请稍后重试';
}

export function csvEscape(value) {
  const text = String(value ?? '');
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function buildQueryPayload({ instanceId, sql } = {}) {
  const checked = validateSql(sql);
  if (checked.kind !== 'valid') return { error: checked.kind };
  return { instance_id: String(instanceId ?? '').trim() || null, sql: checked.sql };
}

export function renderQueryResultMarkup(result = {}, source = null) {
  const columns = Array.isArray(result.columns) ? result.columns : [];
  const data = Array.isArray(result.data) ? result.data : [];
  const sourceBadge = source ? `<span class="sqlw-source ${safeText(source)}">${safeText(sqlSourceLabel(source))}</span>` : '';
  const warning = String(result.warning ?? '').trim()
    ? `<div class="sqlw-warning" role="alert">${safeText(result.warning)}</div>`
    : '';
  const truncated = result.truncated === true || data.length > 100;
  const meta = `<div class="sqlw-result-meta"><span>耗时 ${safeText(result.duration_ms ?? '—')} ms</span><span>${data.length} 行</span>${truncated ? '<span class="sqlw-truncated">结果已截断</span>' : ''}</div>`;
  if (!columns.length) {
    return `<div class="sqlw-result"><div class="sqlw-result-head"><div><h3>执行结果</h3>${sourceBadge}</div></div>${warning}${meta}<div class="sqlw-empty">该语句没有可展示的结果集。</div></div>`;
  }
  const head = columns.map((column) => `<th class="sqlw-th">${safeText(column.name)}${column.type ? `<small>${safeText(column.type)}</small>` : ''}</th>`).join('');
  const rows = data.map((row) => `<tr>${columns.map((column, index) => `<td class="sqlw-cell">${safeText(row[index] ?? '')}</td>`).join('')}</tr>`).join('');
  return `<div class="sqlw-result">
    <div class="sqlw-result-head"><div><h3>执行结果</h3>${sourceBadge}</div></div>
    ${warning}
    ${meta}
    <div class="sqlw-table-wrap"><table class="sqlw-table"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table></div>
  </div>`;
}

export function renderPlanMarkup(plan = {}, source = null) {
  const nodes = Array.isArray(plan.nodes) ? plan.nodes : [];
  const sourceBadge = source ? `<span class="sqlw-source ${safeText(source)}">${safeText(sqlSourceLabel(source))}</span>` : '';
  const meta = `<div class="sqlw-plan-meta"><span>实例 <b>${safeText(plan.instance_name ?? plan.instance_id ?? '—')}</b></span><span>总成本 <b>${safeText(plan.total_cost ?? '—')}</b></span><span>总行数 <b>${safeText(plan.total_rows ?? '—')}</b></span><span class="sqlw-plan-sql">${safeText(summarizeSql(plan.sql))}</span></div>`;
  return `<div class="sqlw-plan">
    <div class="sqlw-result-head"><div><h3>执行计划</h3>${sourceBadge}</div></div>
    ${meta}
    ${renderPlanNodes(nodes)}
  </div>`;
}

export function renderHistoryMarkup(response = {}, source = null) {
  const items = Array.isArray(response?.items) ? response.items : [];
  const sourceBadge = source ? `<span class="sqlw-source ${safeText(source)}">${safeText(sqlSourceLabel(source))}</span>` : '';
  const rows = items.length
    ? items.map((item) => `<button class="sqlw-history-row" data-sqlwindow-history="${safeText(item.id)}"><span class="sqlw-history-sql">${safeText(summarizeSql(item.sql))}</span><span class="sqlw-history-instance">${safeText(item.instance_name ?? item.instance_id ?? '')}</span><span class="sqlw-history-time">${safeText(formatTime(item.run_at))}</span><span class="sqlw-history-duration">${safeText(item.duration_ms ?? '—')} ms</span><span class="sqlw-history-rows">${safeText(item.rows ?? 0)} 行</span></button>`).join('')
    : '<div class="sqlw-empty"><p>暂无查询历史，执行过的 SQL 会自动记录在这里。</p></div>';
  return `<div class="sqlw-history">
    <div class="sqlw-result-head"><div><h3>查询历史</h3>${sourceBadge}</div><button class="sqlw-btn-secondary" data-sqlwindow-clear-history>清空历史</button></div>
    <div class="sqlw-history-list">${rows}</div>
  </div>`;
}

export function renderSqlWindowWorkbench(state) {
  const source = state.source ? `<span class="sqlw-source ${safeText(state.source)}">${safeText(sqlSourceLabel(state.source))}</span>` : '';
  const body = state.error
    ? renderError(state.error)
    : state.view === 'history'
      ? renderHistoryMarkup(state.history ?? { items: [] }, state.source)
      : state.view === 'plan'
        ? renderPlanMarkup(state.plan, state.source)
        : renderQueryView(state);
  const progress = state.loading
    ? `<div class="sqlw-progress" role="status">${state.view === 'plan' ? '正在生成执行计划…' : '正在执行…'}</div>`
    : '';
  return `<section class="sqlw-center">
    <div class="sqlw-hero"><div><span class="eyebrow">DBPILOT · SQL WINDOW</span><h2>SQL 窗口与执行</h2><p>在线执行查询、查看执行计划，并将结果安全导出为 CSV。</p></div><div class="sqlw-hero-meta">${source}<span class="sqlw-scope">${safeText(state.scope.tenantId)} / ${safeText(state.scope.projectId)}</span></div></div>
    <div class="sqlw-toolbar">
      <nav class="sqlw-tabs" aria-label="SQL 窗口视图"><button class="${state.view === 'overview' ? 'active' : ''}" data-sqlwindow-view="overview">SQL 查询</button><button class="${state.view === 'plan' ? 'active' : ''}" data-sqlwindow-view="plan">执行计划</button><button class="${state.view === 'history' ? 'active' : ''}" data-sqlwindow-view="history">查询历史</button></nav>
      <span class="sqlw-hint">Ctrl / Cmd + Enter 执行</span>
    </div>
    ${progress}
    ${body}
  </section>`;
}

export function createSqlWindowCenter({ root, api, scope, permissions = {}, onToast = () => {} }) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('sql-window root is required');
  if (!api) throw new TypeError('sql-window api is required');

  const state = {
    view: 'overview',
    scope: normalizeScope(scope),
    permissions: { execute: permissions.execute === true },
    instanceId: DEMO_INSTANCES[0].id,
    sql: '',
    source: null,
    result: null,
    plan: null,
    history: null,
    loading: false,
    error: null,
  };
  let activeRequest = null;
  let requestVersion = 0;

  root.addEventListener('click', (event) => {
    const target = typeof event.target?.closest === 'function'
      ? event.target.closest('[data-sqlwindow-view],[data-sqlwindow-run],[data-sqlwindow-explain],[data-sqlwindow-clear],[data-sqlwindow-export],[data-sqlwindow-history],[data-sqlwindow-clear-history],[data-sqlwindow-retry]')
      : null;
    if (!target) return;
    if (target.dataset.sqlwindowView) {
      switchView(target.dataset.sqlwindowView);
    } else if (target.dataset.sqlwindowRun) {
      runQuery();
    } else if (target.dataset.sqlwindowExplain) {
      runExplain();
    } else if (target.dataset.sqlwindowClear) {
      clearEditor();
    } else if (target.dataset.sqlwindowExport) {
      exportCsv();
    } else if (target.dataset.sqlwindowHistory) {
      backfillHistory(target.dataset.sqlwindowHistory);
    } else if (target.hasAttribute('data-sqlwindowClearHistory')) {
      clearHistory();
    } else if (target.hasAttribute('data-sqlwindowRetry')) {
      retry();
    }
  });

  root.addEventListener('change', (event) => {
    const target = event.target;
    if (!target?.dataset) return;
    if (target.dataset.sqlwindowInstance) {
      state.instanceId = target.value;
    }
  });

  root.addEventListener('input', (event) => {
    const target = event.target;
    if (target?.dataset?.sqlwindowEditor) {
      state.sql = target.value;
    }
  });

  root.addEventListener('keydown', (event) => {
    const target = event.target;
    if (target?.dataset?.sqlwindowEditor && (event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      runQuery();
    }
  });

  function open(view = 'overview') {
    state.view = SQL_WINDOW_VIEWS.includes(view) ? view : 'overview';
    state.error = null;
    render();
    if (state.view !== 'plan' || !state.plan) loadHistory();
  }

  function setScope(nextScope) {
    abortActive();
    state.scope = normalizeScope(nextScope);
    state.source = null;
    state.result = null;
    state.plan = null;
    state.history = null;
    state.error = null;
    render();
    loadHistory();
  }

  function switchView(view) {
    state.view = SQL_WINDOW_VIEWS.includes(view) ? view : 'overview';
    state.error = null;
    render();
    if (view === 'history' || (view === 'overview')) loadHistory();
  }

  function clearEditor() {
    state.sql = '';
    state.result = null;
    state.error = null;
    render();
  }

  async function runQuery() {
    abortActive();
    const payload = buildQueryPayload({ instanceId: state.instanceId, sql: state.sql });
    if (payload.error) {
      onToast('SQL 不能为空，请输入要执行的语句');
      return;
    }
    const controller = new AbortController();
    activeRequest = controller;
    const version = ++requestVersion;
    state.loading = true;
    state.error = null;
    state.result = null;
    state.source = null;
    render();
    try {
      const result = await api.runQuery(state.scope, payload, controller.signal);
      if (version !== requestVersion || controller.signal.aborted) return;
      state.result = result;
      state.source = result.source ?? null;
      state.loading = false;
      render();
    } catch (error) {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.loading = false;
      state.error = error;
      render();
    }
  }

  async function runExplain() {
    abortActive();
    const payload = buildQueryPayload({ instanceId: state.instanceId, sql: state.sql });
    if (payload.error) {
      onToast('SQL 不能为空，请输入要执行的语句');
      return;
    }
    const controller = new AbortController();
    activeRequest = controller;
    const version = ++requestVersion;
    state.view = 'plan';
    state.loading = true;
    state.error = null;
    state.plan = null;
    state.source = null;
    render();
    try {
      const plan = await api.explainQuery(state.scope, payload, controller.signal);
      if (version !== requestVersion || controller.signal.aborted) return;
      state.plan = plan;
      state.source = plan.source ?? null;
      state.loading = false;
      render();
    } catch (error) {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.loading = false;
      state.error = error;
      render();
    }
  }

  async function loadHistory() {
    abortActive();
    const controller = new AbortController();
    activeRequest = controller;
    const version = ++requestVersion;
    state.error = null;
    render();
    try {
      const response = await api.listHistory(state.scope, { limit: HISTORY_LIMIT }, controller.signal);
      if (version !== requestVersion || controller.signal.aborted) return;
      state.history = response;
      state.source = response?.source ?? state.source;
      render();
    } catch (error) {
      if (error?.name === 'AbortError' || version !== requestVersion) return;
      state.error = error;
      render();
    }
  }

  async function clearHistory() {
    abortActive();
    try {
      await api.clearHistory(state.scope);
      onToast('查询历史已清空');
    } catch (error) {
      if (error?.name === 'AbortError') return;
      onToast('清空查询历史失败，请稍后重试');
    }
    loadHistory();
  }

  function backfillHistory(id) {
    const item = (state.history?.items ?? []).find((entry) => String(entry.id) === String(id));
    if (!item) return;
    state.sql = item.sql;
    if (item.instance_id) state.instanceId = item.instance_id;
    state.view = 'overview';
    state.result = null;
    state.plan = null;
    state.error = null;
    render();
  }

  function retry() {
    state.error = null;
    render();
    loadHistory();
  }

  function exportCsv() {
    const result = state.result;
    if (!result) return;
    const columns = Array.isArray(result.columns) ? result.columns : [];
    const rows = Array.isArray(result.data) ? result.data : [];
    const head = columns.map((column) => csvEscape(column.name)).join(',');
    const body = rows.map((row) => row.map(csvEscape).join(',')).join('\r\n');
    const csv = `\uFEFF${head}\r\n${body}`;
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `query-result-${Date.now()}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  function abortActive() {
    activeRequest?.abort();
    activeRequest = null;
  }

  function render() {
    root.innerHTML = renderSqlWindowWorkbench(state);
  }

  render();
  return {
    open,
    setScope,
    getState: () => ({ ...state, scope: { ...state.scope } }),
  };
}

function renderQueryView(state) {
  const instanceOptions = DEMO_INSTANCES.map((item) => `<option value="${safeText(item.id)}" ${item.id === state.instanceId ? 'selected' : ''}>${safeText(item.name)} · ${safeText(engineLabel(item.engine))} (${safeText(item.id)})</option>`).join('');
  const resultArea = state.result
    ? renderQueryResultMarkup(state.result, state.source)
    : '<div class="sqlw-empty"><h3>等待执行</h3><p>在下方编辑器中输入 SQL，点击「执行」查看结果，或点击「执行计划」生成查询计划。</p></div>';
  return `<div class="sqlw-query">
    <div class="sqlw-editor">
      <div class="sqlw-toolbar-row">
        <label class="sqlw-field">实例<select class="sqlw-select" data-sqlwindow-instance>${instanceOptions}</select></label>
        <span class="sqlw-actions">
          <button class="sqlw-btn-primary" data-sqlwindow-run>执行</button>
          <button class="sqlw-btn-secondary" data-sqlwindow-explain>执行计划</button>
          <button class="sqlw-btn-secondary" data-sqlwindow-clear>清空</button>
          ${state.result ? '<button class="sqlw-btn-secondary" data-sqlwindow-export>导出 CSV</button>' : ''}
        </span>
      </div>
      <textarea class="sqlw-textarea" data-sqlwindow-editor spellcheck="false" placeholder="SELECT * FROM orders WHERE created_at &gt; NOW() LIMIT 10;   -- Ctrl / Cmd + Enter 执行">${safeText(state.sql)}</textarea>
      ${resultArea}
    </div>
  </div>`;
}

function renderError(error) {
  const forbidden = error?.kind === 'forbidden';
  return `<div class="sqlw-state error ${forbidden ? 'forbidden' : ''}" role="alert"><span class="sqlw-state-icon">${forbidden ? '⌾' : '!'}</span><h3>${forbidden ? '无法执行 SQL' : 'SQL 窗口加载失败'}</h3><p>${safeText(sqlFailureMessage(error))}</p><button class="sqlw-btn-primary" data-sqlwindow-retry>重试</button></div>`;
}

function renderPlanNodes(nodes) {
  if (!nodes.length) return '<div class="sqlw-empty">没有可展示的执行计划节点，请先在查询页生成执行计划。</div>';
  const ids = new Set(nodes.map((node) => String(node.id)));
  const byParent = new Map();
  for (const node of nodes) {
    const key = node.parent == null || !ids.has(String(node.parent)) ? 'root' : String(node.parent);
    if (!byParent.has(key)) byParent.set(key, []);
    byParent.get(key).push(node);
  }
  const lines = [];
  const walk = (node, depth) => {
    lines.push(renderPlanNode(node, depth));
    for (const child of byParent.get(String(node.id)) ?? []) walk(child, depth + 1);
  };
  for (const root of byParent.get('root') ?? []) walk(root, 0);
  return `<div class="sqlw-plan-tree">${lines.join('')}</div>`;
}

function renderPlanNode(node, depth) {
  return `<div class="sqlw-node" data-depth="${depth}" style="--sqlw-depth:${depth}"><span class="sqlw-node-type">${safeText(node.type)}</span><span class="sqlw-node-table">${safeText(node.table ?? '')}</span><span class="sqlw-node-rows">${safeText(node.rows ?? '')} 行</span><span class="sqlw-node-cost">cost=${safeText(node.cost ?? '')}</span>${node.detail ? `<span class="sqlw-node-detail">${safeText(node.detail)}</span>` : ''}</div>`;
}

function summarizeSql(sql) {
  const text = String(sql ?? '').replace(/\s+/g, ' ').trim();
  return text.length > HISTORY_SUMMARY_MAX ? `${text.slice(0, HISTORY_SUMMARY_MAX)}…` : text;
}

function formatTime(value) {
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

function engineLabel(engine) {
  return { mysql: 'MySQL', postgres: 'PostgreSQL', redis: 'Redis' }[String(engine ?? '').toLowerCase()] ?? engine ?? '数据库';
}

if (typeof window !== 'undefined') {
  window.DBPilotSqlWindowCenter = { create: createSqlWindowCenter };
}
