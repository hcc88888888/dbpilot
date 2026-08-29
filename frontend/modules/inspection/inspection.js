const VIEWS = new Set(['overview', 'policies', 'runs', 'report-detail']);
const TERMINAL_RUNS = new Set(['completed', 'partial', 'failed', 'cancelled']);
const RUN_LABELS = { queued: '排队中', collecting: '采集中', evaluating: '评估中', generating_report: '生成报告', completed: '已完成', partial: '部分完成', failed: '失败', cancelled: '已取消' };
const FINDING_LABELS = { healthy: '健康', warning: '警告', critical: '严重', unsupported: '不支持', missing_data: '数据缺失' };
const TARGET_LABELS = { pending: '等待中', collecting: '采集中', evaluating: '评估中', succeeded: '成功', failed: '失败', unsupported: '不支持', cancelled: '已取消' };
const INSPECTION_PAGE_LIMIT = 100;
const MAX_POLICY_TARGETS = 10000;
const MAX_POLICY_ITEMS = 200;

export function inspectionFailureMessage(error, subject = '巡检数据') {
  if (error?.kind === 'forbidden') return '当前账号没有该项目的巡检查看权限';
  if (error?.kind === 'unauthorized') return '登录状态已失效，请重新登录';
  if (error?.kind === 'not-found') return '巡检对象不存在或已无权访问';
  if (error?.kind === 'conflict') return '巡检对象已更新，请刷新后重试';
  if (error?.kind === 'validation') return '巡检参数不符合要求，请检查后重试';
  if (error?.kind === 'network') return '无法连接控制面服务，请检查网络后重试';
  return `暂时无法加载${subject}`;
}

const INSPECTION_LABEL_ERROR = '标签必须每行使用 key=value，键值不得重复且最多 32 项';

export function parseInspectionLabels(input) {
  const text = String(input ?? '');
  if (!text.trim()) return { labels: {}, error: '' };
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== '');
  if (lines.length > 32) return { labels: null, error: INSPECTION_LABEL_ERROR };
  const labels = {};
  for (const line of lines) {
    const separator = line.indexOf('=');
    if (separator <= 0) return { labels: null, error: INSPECTION_LABEL_ERROR };
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!/^[A-Za-z_.-][A-Za-z0-9_.-]{0,127}$/.test(key) || !value || value.length > 128 || Object.hasOwn(labels, key)) return { labels: null, error: INSPECTION_LABEL_ERROR };
    labels[key] = value;
  }
  return { labels, error: '' };
}

export function renderInspectionOverviewMarkup(value = {}) {
  const levels = value.finding_level_counts ?? {};
  const runs = value.latest_run_status_counts ?? {};
  return `<div class="ins-overview-grid">
      ${overviewCard('主机目标', value.target_count ?? 0, `${value.online_target_count ?? 0} 台在线`, 'targets')}
      ${overviewCard('健康', levels.healthy ?? 0, '检查项正常', 'healthy')}
      ${overviewCard('警告', levels.warning ?? 0, '需要关注', 'warning')}
      ${overviewCard('严重', levels.critical ?? 0, '需要立即处理', 'critical')}
      ${overviewCard('不支持', levels.unsupported ?? 0, 'Agent 能力不足', 'unsupported')}
      ${overviewCard('数据缺失', levels.missing_data ?? 0, '证据不完整', 'missing')}
    </div>
    <article class="ins-panel"><div class="ins-panel-head"><div><span class="ins-kicker">LATEST RUNS</span><h3>最近执行状态</h3></div><button type="button" class="ins-link" data-inspection-view="runs">查看执行记录 →</button></div>
      <div class="ins-status-strip">${Object.entries(RUN_LABELS).map(([status, label]) => `<div><span class="ins-state ${status}">${label}</span><strong>${Number(runs[status] ?? 0)}</strong></div>`).join('')}</div>
      <p class="ins-partial-note">部分完成表示至少一个目标成功，同时存在失败、不支持或数据缺失的目标。</p>
    </article>`;
}

export function renderInspectionPolicyMarkup(value = {}, permissions = {}) {
  const policies = Array.isArray(value.policies) ? value.policies : [];
  const targets = Array.isArray(value.targets) ? value.targets : [];
  const items = Array.isArray(value.items) ? value.items : [];
  const editing = value.editing_policy ?? null;
  const selectedTargets = new Set(editing?.target_ids ?? []);
  const selectedItems = new Set((editing?.item_versions ?? []).map((item) => `${item.item_id}:${Number(item.version)}`));
  const labelsText = Object.entries(editing?.labels ?? {}).sort(([left], [right]) => left.localeCompare(right)).map(([key, labelValue]) => `${key}=${labelValue}`).join('\n');
  const form = permissions.manage === true ? `<form class="ins-panel ins-policy-form" data-inspection-policy-form ${editing ? `data-inspection-policy-id="${safe(editing.id)}" data-inspection-policy-etag="${safe(editing.etag)}"` : ''}>
    <div class="ins-panel-head"><div><span class="ins-kicker">POLICY</span><h3>${editing ? '编辑巡检策略' : '创建巡检策略'}</h3></div>${editing ? '<button type="button" class="ins-link" data-inspection-policy-edit-cancel>取消编辑</button>' : ''}</div>
    <label>策略名称<input name="name" required maxlength="120" autocomplete="off" value="${safe(editing?.name ?? '')}"></label>
    <label class="ins-check"><input type="checkbox" name="enabled"${editing?.enabled !== false ? ' checked' : ''}><span><b>启用策略</b></span></label>
    <label>目标标签<textarea name="labels" rows="4" placeholder="role=database&#10;zone=east">${safe(labelsText)}</textarea><small>每行 key=value，最多 32 项</small></label>
    <fieldset aria-label="巡检目标"><legend>巡检目标</legend>${targets.map((target) => `<label class="ins-check"><input type="checkbox" name="target_id" value="${safe(target.agent_id)}"${selectedTargets.has(target.agent_id) ? ' checked' : ''}><span><b>${safe(target.display_name)}</b><small>${safe(target.host)}</small></span></label>`).join('') || '<p class="ins-empty">暂无可用目标</p>'}</fieldset>
    <fieldset aria-label="巡检项"><legend>巡检项</legend>${items.map((item) => { const key = `${item.id}:${Number(item.version)}`; return `<label class="ins-check"><input type="checkbox" name="item_version" value="${safe(key)}"${selectedItems.has(key) ? ' checked' : ''}><span><b>${safe(item.name)}</b><small>${safe(item.category)} · v${Number(item.version)}</small></span></label>`; }).join('') || '<p class="ins-empty">暂无可用巡检项</p>'}</fieldset>
    <div class="ins-form-grid"><label>Cron 表达式<input name="cron" placeholder="0 2 * * *" value="${safe(editing?.schedule?.cron ?? '')}"></label><label>时区<input name="timezone" value="${safe(editing?.schedule?.timezone ?? 'Asia/Shanghai')}"></label></div>
    <div class="ins-form-grid"><label>目标超时（秒）<input type="number" name="target_timeout_seconds" min="1" max="3600" value="${Number(editing?.target_timeout_seconds ?? 60)}"></label><label>最大并发<input type="number" name="max_concurrency" min="1" max="1000" value="${Number(editing?.max_concurrency ?? 10)}"></label></div>
    <button type="submit" class="ins-primary" data-inspection-policy-save>${editing ? '更新策略' : '保存策略'}</button>
  </form>` : '';
  const list = policies.length ? policies.map((policy) => `<article class="ins-policy-row"><div><span class="ins-state ${policy.enabled ? 'enabled' : 'disabled'}">${policy.enabled ? '已启用' : '已停用'}</span><h3>${safe(policy.name)}</h3><p>v${Number(policy.version)} · ${policy.target_ids?.length ?? 0} 个目标 · ${policy.item_versions?.length ?? 0} 个巡检项</p></div><div class="ins-row-actions">${permissions.manage === true ? `<button type="button" class="ins-secondary" data-inspection-policy-edit="${safe(policy.id)}">编辑</button>` : ''}${permissions.execute === true ? `<button type="button" class="ins-primary" data-inspection-policy-run="${safe(policy.id)}">立即执行</button>` : ''}</div></article>`).join('') : '<div class="ins-empty"><h3>暂无巡检策略</h3><p>创建策略后可按计划调度或立即执行。</p></div>';
  const page = value.policy_page ?? {};
  const previous = value.policy_has_previous === true;
  const next = page.has_more === true && Boolean(page.next_cursor);
  const pager = previous || next ? `<nav class="ins-pager" aria-label="巡检策略分页">${previous ? '<button type="button" class="ins-secondary" data-inspection-policy-page="previous">上一页</button>' : ''}${next ? '<button type="button" class="ins-secondary" data-inspection-policy-page="next">下一页</button>' : ''}</nav>` : '';
  return `<div class="ins-policy-layout"><section class="ins-panel"><div class="ins-panel-head"><div><span class="ins-kicker">POLICIES</span><h3>巡检策略</h3></div></div>${list}${pager}</section>${form}</div>`;
}

export function renderInspectionRunMarkup(run = {}, permissions = {}) {
  if (!run.id) return '<div class="ins-empty"><h3>暂无执行记录</h3></div>';
  const targets = Array.isArray(run.targets) ? run.targets : [];
  const findings = Array.isArray(run.findings) ? run.findings : [];
  const completed = Number(run.completed_target_count ?? 0);
  const total = Math.max(0, Number(run.target_count ?? 0));
  const percent = total ? Math.min(100, Math.round((completed / total) * 100)) : 0;
  const actions = permissions.execute === true
    ? `${!TERMINAL_RUNS.has(run.status) ? `<button type="button" class="ins-secondary" data-inspection-cancel="${safe(run.id)}">取消执行</button>` : ''}${['partial', 'failed'].includes(run.status) ? `<button type="button" class="ins-primary" data-inspection-retry="${safe(run.id)}">重试执行</button>` : ''}`
    : '';
  return `<article class="ins-panel ins-run-detail"><div class="ins-panel-head"><div><span class="ins-kicker">RUN ${safe(run.id)}</span><h3>${safe(RUN_LABELS[run.status] ?? '未知状态')}</h3></div><div class="ins-row-actions">${run.report_id ? `<button type="button" class="ins-link" data-inspection-report="${safe(run.report_id)}">查看报告</button>` : ''}${actions}</div></div>
    <div class="ins-progress" role="progressbar" aria-valuemin="0" aria-valuemax="${total}" aria-valuenow="${completed}"><div style="width:${percent}%"></div></div><p class="ins-progress-label">${completed} / ${total} 个目标已完成 · ${Number(run.failed_target_count ?? 0)} 个失败</p>
    <div class="ins-target-list">${targets.map((target) => `<div class="ins-target-row"><b>${safe(target.target_id)}</b><span>${safe(target.agent_id)}</span><span class="ins-state ${safe(target.status)}">${safe(targetLabel(target))}</span></div>`).join('') || '<p class="ins-empty">目标状态尚未生成。</p>'}</div>
    <div class="ins-findings">${findings.map(renderFinding).join('') || '<p class="ins-empty">暂无巡检发现。</p>'}</div>
  </article>`;
}

export function renderInspectionReportMarkup(report = {}) {
  if (!report.id) return '<div class="ins-empty"><h3>报告不存在</h3></div>';
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const targets = Array.isArray(report.targets) ? report.targets : [];
  const references = report.references ?? {};
  const formats = new Set((report.artifacts ?? []).map((artifact) => String(artifact.artifact_id ?? '').toLowerCase().split('.').at(-1)));
  const downloads = ['html', 'json'].filter((format) => formats.has(format)).map((format) => `<button type="button" class="ins-primary" data-inspection-report-download="${safe(report.id)}" data-inspection-report-format="${format}">下载 ${format.toUpperCase()}</button>`).join('');
  const targetNavigation = targets.length ? `<nav class="ins-target-navigation" aria-label="报告目标">${targets.map((target) => `<a href="#inspection-report-target-${safe(target.target_id)}">${safe(target.display_name || target.target_id)}</a>`).join('')}</nav><div class="ins-report-targets">${targets.map((target) => `<article id="inspection-report-target-${safe(target.target_id)}"><b>${safe(target.display_name || target.target_id)}</b><span>${safe(target.host)}</span><span>${safe(TARGET_LABELS[target.status] ?? target.status)}</span><code>${safe(target.command_id)}</code></article>`).join('')}</div>` : '';
  const commandReferences = Array.isArray(references.commands) ? references.commands : [];
  return `<article class="ins-panel ins-report-detail"><div class="ins-panel-head"><div><span class="ins-kicker">IMMUTABLE REPORT</span><h3>${safe(report.id)}</h3><p>${safe(report.summary)}</p></div><div class="ins-row-actions">${downloads}</div></div>
    <dl class="ins-report-meta"><div><dt>执行</dt><dd>${safe(report.run_id)}</dd></div><div><dt>状态</dt><dd>${safe(report.status === 'completed' ? '已完成' : report.status)}</dd></div><div><dt>生成时间</dt><dd>${safe(formatTime(report.generated_at))}</dd></div><div><dt>Job</dt><dd>${safe(references.job_id)}</dd></div><div><dt>Audit</dt><dd>${safe(references.audit_correlation)}</dd></div><div><dt>命令</dt><dd>${commandReferences.map((reference) => `${safe(reference.target_id)}: ${safe(reference.command_id)}`).join('<br>')}</dd></div></dl>
    ${targetNavigation}
    <div class="ins-findings">${findings.map(renderFinding).join('') || '<p class="ins-empty">报告中暂无发现。</p>'}</div>
  </article>`;
}

export function createInspectionCenter({ root, api, scope, permissions = {}, onToast = () => {} } = {}) {
  if (!root || typeof root.addEventListener !== 'function') throw new TypeError('inspection root is required');
  if (!api) throw new TypeError('inspection api is required');
  const state = { view: 'overview', scope: normalizeScope(scope), permissions: { view: permissions.view !== false, manage: permissions.manage === true, execute: permissions.execute === true }, loading: false, error: null, data: null, selectedReport: null, editingPolicy: null, policyCursor: '', policyHistory: [] };
  let active = null;
  let version = 0;

  root.addEventListener('click', (event) => {
    const target = event.target?.closest?.('[data-inspection-view],[data-inspection-retry-load],[data-inspection-policy-run],[data-inspection-policy-edit],[data-inspection-policy-edit-cancel],[data-inspection-policy-page],[data-inspection-run],[data-inspection-report],[data-inspection-cancel],[data-inspection-retry],[data-inspection-report-download]');
    if (!target) return;
    if (target.dataset.inspectionView) open(target.dataset.inspectionView);
    else if (target.hasAttribute('data-inspection-retry-load')) reload();
    else if (target.dataset.inspectionPolicyRun) action(() => api.runPolicy(state.scope, target.dataset.inspectionPolicyRun, newKey('policy-run')), '巡检已开始');
    else if (target.dataset.inspectionPolicyPage) pagePolicies(target.dataset.inspectionPolicyPage);
    else if (target.dataset.inspectionPolicyEdit) editPolicy(target.dataset.inspectionPolicyEdit);
    else if (target.hasAttribute('data-inspection-policy-edit-cancel')) cancelPolicyEdit();
    else if (target.dataset.inspectionRun) openRun(target.dataset.inspectionRun);
    else if (target.dataset.inspectionReport) openReport(target.dataset.inspectionReport);
    else if (target.dataset.inspectionCancel) action(() => api.cancelRun(state.scope, target.dataset.inspectionCancel, newKey('cancel')), '已提交取消请求');
    else if (target.dataset.inspectionRetry) action(() => api.retryRun(state.scope, target.dataset.inspectionRetry, newKey('retry')), '已创建重试执行');
    else if (target.dataset.inspectionReportDownload) download(target.dataset.inspectionReportDownload, target.dataset.inspectionReportFormat);
  });
  root.addEventListener('submit', (event) => {
    const form = event.target?.closest?.('[data-inspection-policy-form]');
    if (!form) return;
    event.preventDefault();
    const data = new FormData(form);
    const targets = data.getAll('target_id').map(String);
    const items = data.getAll('item_version').map((value) => { const [item_id, raw] = String(value).split(':'); return { item_id, version: Number(raw) }; });
    const cron = String(data.get('cron') ?? '').trim();
    const value = { name: String(data.get('name') ?? '').trim(), enabled: data.get('enabled') === 'on', target_ids: targets, item_versions: items, labels_text: String(data.get('labels') ?? ''), target_timeout_seconds: Number(data.get('target_timeout_seconds')), max_concurrency: Number(data.get('max_concurrency')), ...(cron ? { schedule: { cron, timezone: String(data.get('timezone') ?? '').trim() } } : {}) };
    submitPolicy(value);
  });

  function open(view = 'overview') { const next = VIEWS.has(view) ? view : 'overview'; if (next === 'policies' && state.view !== 'policies') { state.policyCursor = ''; state.policyHistory = []; } state.view = next; if (state.view !== 'report-detail') state.selectedReport = null; if (state.view !== 'policies') state.editingPolicy = null; return reload(); }
  function setScope(next) { active?.abort(); state.scope = normalizeScope(next); state.view = 'overview'; state.data = null; state.selectedReport = null; state.editingPolicy = null; state.policyCursor = ''; state.policyHistory = []; return reload(); }
  function openRun(id) { state.view = 'runs'; state.data = { selectedRunId: String(id) }; reload(); }
  function openReport(id) { state.view = 'report-detail'; state.selectedReport = String(id); state.data = null; reload(); }
  async function reload() {
    if (!state.permissions.view) {
      active?.abort();
      state.loading = false;
      state.data = null;
      state.error = { kind: 'forbidden' };
      render();
      return;
    }
    active?.abort();
    const controller = new AbortController(); active = controller; const current = ++version;
    state.loading = true; state.error = null; render();
    try {
      let value;
      if (state.view === 'policies') {
        const [policies, targets, items] = await Promise.all([
          api.listPolicies(state.scope, { limit: INSPECTION_PAGE_LIMIT, ...(state.policyCursor ? { cursor: state.policyCursor } : {}) }, controller.signal),
          loadInspectionSelectionPages(api.listTargets.bind(api), state.scope, controller.signal, MAX_POLICY_TARGETS),
          loadInspectionSelectionPages(api.listItems.bind(api), state.scope, controller.signal, MAX_POLICY_ITEMS),
        ]);
        value = { source: policies.source, policies: policies.items ?? [], policy_page: policies.page ?? {}, policy_has_previous: state.policyHistory.length > 0, targets: targets.items, items: items.items, editing_policy: state.editingPolicy };
      } else if (state.view === 'runs') {
        const selected = state.data?.selectedRunId;
        value = selected ? await api.getRun(state.scope, selected, controller.signal) : await api.listRuns(state.scope, { limit: 50 }, controller.signal);
      } else if (state.view === 'report-detail') value = await api.getReport(state.scope, state.selectedReport, controller.signal);
      else value = await api.getOverview(state.scope, controller.signal);
      if (controller.signal.aborted || current !== version) return;
      state.data = value; state.loading = false; render();
    } catch (error) {
      if (error?.name === 'AbortError' || controller.signal.aborted || current !== version) return;
      state.loading = false; state.error = error; state.data = null; render();
    }
  }
  async function editPolicy(id) {
    if (!state.permissions.manage) return;
    active?.abort();
    const controller = new AbortController(); active = controller; const current = ++version;
    state.loading = true; state.error = null; render();
    try {
      const policy = await api.getPolicy(state.scope, String(id), controller.signal);
      if (controller.signal.aborted || current !== version) return;
      state.editingPolicy = policy;
      state.data = { ...(state.data ?? {}), editing_policy: policy };
      state.loading = false;
      render();
      return policy;
    } catch (error) {
      if (error?.name === 'AbortError' || controller.signal.aborted || current !== version) return;
      state.loading = false;
      state.error = error;
      render();
    }
  }
  function cancelPolicyEdit() {
    state.editingPolicy = null;
    if (state.data) state.data = { ...state.data, editing_policy: null };
    render();
  }
  async function savePolicy(value) {
    const editing = state.editingPolicy;
    if (!editing || !state.permissions.manage) return;
    active?.abort();
    const controller = new AbortController(); active = controller; const current = ++version;
    try {
      await api.updatePolicy(state.scope, editing.id, value, editing.etag, newKey('policy-update'), controller.signal);
      if (controller.signal.aborted || current !== version) return;
      state.editingPolicy = null;
      onToast('巡检策略已更新');
      await reload();
    } catch (error) {
      if (error?.name === 'AbortError' || controller.signal.aborted || current !== version) return;
      if (error?.status === 412 || error?.code === 'precondition_failed') {
        state.editingPolicy = null;
        onToast('策略已被其他操作者更新，已刷新最新版本');
        await reload();
        return;
      }
      onToast(inspectionFailureMessage(error, '策略'));
    }
  }
  function submitPolicy(input) {
    const parsed = parseInspectionLabels(input?.labels_text);
    if (parsed.error) {
      onToast(parsed.error);
      return Promise.resolve();
    }
    const value = { ...input, labels: parsed.labels };
    delete value.labels_text;
    const targets = Array.isArray(value.target_ids) ? value.target_ids : [];
    const items = Array.isArray(value.item_versions) ? value.item_versions : [];
    if (!String(value.name ?? '').trim() || items.length === 0 || (targets.length === 0 && Object.keys(value.labels).length === 0)) {
      onToast('请填写策略名称、选择巡检项，并配置目标或标签');
      return Promise.resolve();
    }
    if (state.editingPolicy) return savePolicy(value);
    return action(() => api.createPolicy(state.scope, value, newKey('policy')), '巡检策略已创建');
  }
  function pagePolicies(direction) {
    if (state.view !== 'policies') return Promise.resolve();
    if (direction === 'next') {
      const next = state.data?.policy_page?.next_cursor;
      if (!next || state.data?.policy_page?.has_more !== true) return Promise.resolve();
      state.policyHistory.push(state.policyCursor);
      state.policyCursor = String(next);
    } else if (direction === 'previous') {
      if (state.policyHistory.length === 0) return Promise.resolve();
      state.policyCursor = state.policyHistory.pop();
    } else return Promise.resolve();
    return reload();
  }
  function action(callback, message) { return Promise.resolve().then(callback).then(() => { onToast(message); return reload(); }).catch((error) => onToast(inspectionFailureMessage(error, '操作'))); }
  function download(id, format) { action(async () => { const descriptor = await api.downloadReport(state.scope, id, format, newKey(`download-${format}`)); if (descriptor?.url && typeof globalThis.open === 'function') globalThis.open(descriptor.url, '_blank', 'noopener,noreferrer'); }, '报告下载已授权'); }
  function render() {
    const source = state.data?.source;
    const sourceBadge = source ? `<span class="ins-shell-source ${safe(source)}">${safe(sourceLabel(source))}</span>` : '';
    const body = state.error ? `<div class="ins-state-page error" role="alert"><h3>巡检数据加载失败</h3><p>${safe(inspectionFailureMessage(state.error))}</p><button type="button" class="ins-primary" data-inspection-retry-load>重试</button></div>`
      : state.loading && !state.data ? '<div class="ins-state-page" role="status"><span class="ins-spinner"></span><h3>正在加载巡检数据</h3></div>'
        : renderView();
    root.innerHTML = `<section class="inspection-center"><header class="ins-hero"><div><span class="eyebrow">DBPILOT · HOST INSPECTION</span><h2>主机巡检</h2><p>统一策略、证据、执行进度与不可变报告。</p></div><div class="ins-hero-meta">${sourceBadge}<span class="ins-scope">${safe(state.scope.tenantId)} / ${safe(state.scope.projectId)}</span></div></header><nav class="ins-tabs" aria-label="主机巡检视图"><button data-inspection-view="overview" class="${state.view === 'overview' ? 'active' : ''}">巡检概览</button><button data-inspection-view="policies" class="${state.view === 'policies' ? 'active' : ''}">巡检策略</button><button data-inspection-view="runs" class="${state.view === 'runs' ? 'active' : ''}">执行记录</button></nav>${state.loading && state.data ? '<div class="ins-refresh" role="status">正在刷新…</div>' : ''}${body}</section>`;
  }
  function renderView() {
    if (state.view === 'policies') return renderInspectionPolicyMarkup(state.data ?? {}, state.permissions);
    if (state.view === 'report-detail') return renderInspectionReportMarkup(state.data ?? {});
    if (state.view === 'runs') {
      if (state.data?.id) return renderInspectionRunMarkup(state.data, state.permissions);
      const runs = Array.isArray(state.data?.items) ? state.data.items : [];
      return `<section class="ins-panel"><div class="ins-panel-head"><h3>执行记录</h3></div>${runs.map((run) => `<button type="button" class="ins-run-row" data-inspection-run="${safe(run.id)}"><span class="ins-state ${safe(run.status)}">${safe(RUN_LABELS[run.status] ?? '未知')}</span><b>${safe(run.id)}</b><span>${Number(run.completed_target_count ?? 0)} / ${Number(run.target_count ?? 0)}</span><time>${safe(formatTime(run.created_at))}</time></button>`).join('') || '<div class="ins-empty">暂无执行记录。</div>'}</section>`;
    }
    return renderInspectionOverviewMarkup(state.data ?? {});
  }
  return { open, setScope, reload, editPolicy, savePolicy, submitPolicy, pagePolicies, openRun, openReport };
}

async function loadInspectionSelectionPages(load, scope, signal, cap) {
  const items = [];
  const seen = new Set();
  let cursor = '';
  let source;
  while (true) {
    if (signal?.aborted) throw abortInspectionLoad();
    const page = await load(scope, { limit: INSPECTION_PAGE_LIMIT, ...(cursor ? { cursor } : {}) }, signal);
    if (signal?.aborted) throw abortInspectionLoad();
    if (source === undefined) source = page?.source;
    else if (page?.source !== source) throw Object.assign(new Error('inspection page source changed'), { kind: 'validation' });
    items.push(...(Array.isArray(page?.items) ? page.items : []));
    if (items.length > cap) throw Object.assign(new Error('inspection selection exceeds contract cap'), { kind: 'validation' });
    if (page?.page?.has_more !== true) return { source, items };
    const next = String(page?.page?.next_cursor ?? '');
    if (!next || seen.has(next)) throw Object.assign(new Error('invalid inspection cursor chain'), { kind: 'validation' });
    seen.add(next);
    cursor = next;
  }
}

function abortInspectionLoad() { return Object.assign(new Error('inspection load aborted'), { name: 'AbortError' }); }

function overviewCard(label, value, note, tone) { return `<article class="ins-overview-card ${tone}"><span>${label}</span><strong>${Number(value)}</strong><p>${note}</p></article>`; }
function renderFinding(finding) { const evidence = finding.evidence_fields && typeof finding.evidence_fields === 'object' ? finding.evidence_fields : parseFindingEvidence(finding.evidence); return `<article class="ins-finding ${safe(finding.level)}"><div><span class="ins-state ${safe(finding.level)}">${safe(FINDING_LABELS[finding.level] ?? '未知')}</span><b>${safe(finding.item_id)} v${Number(finding.item_version)}</b><small>${safe(finding.target_id)}</small></div><dl><div><dt>警告阈值</dt><dd>${safe(finding.warning_threshold ?? '—')}</dd></div><div><dt>严重阈值</dt><dd>${safe(finding.critical_threshold ?? '—')}</dd></div>${Object.entries(evidence).map(([key, value]) => `<div><dt>${safe(key)}</dt><dd>${safe(value)}</dd></div>`).join('')}</dl><p>${safe(finding.summary)}</p><p class="ins-recommendation">${safe(finding.recommendation)}</p></article>`; }
function parseFindingEvidence(value) { try { const parsed = JSON.parse(String(value ?? '{}')); return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}; } catch { return {}; } }
function targetLabel(target) { if (target.error_code === 'missing_data') return FINDING_LABELS.missing_data; if (target.error_code === 'unsupported') return FINDING_LABELS.unsupported; return TARGET_LABELS[target.status] ?? '未知'; }
function sourceLabel(source) { return source === 'demo' ? '演示数据 · 非生产' : source === 'control-plane' ? '控制面服务' : '来源未确认'; }
function safe(value) { return String(value ?? '').replace(/[&<>'"]/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[character]); }
function normalizeScope(scope) { const tenantId = String(scope?.tenantId ?? '').trim(); const projectId = String(scope?.projectId ?? '').trim(); if (!tenantId || !projectId) throw new TypeError('inspection scope is required'); return { tenantId, projectId }; }
function newKey(prefix) { return `${prefix}-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`}`; }
function formatTime(value) { const at = new Date(value); return Number.isNaN(at.getTime()) ? '—' : at.toLocaleString('zh-CN', { hour12: false }); }

if (typeof window !== 'undefined') window.DBPilotInspectionCenter = { create: createInspectionCenter };
