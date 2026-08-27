const ALERT_VIEWS = [
  ['overview', '监控概览'],
  ['alerts', '告警列表'],
  ['alert-detail', '告警详情'],
  ['rules', '规则管理'],
  ['policies', '通知策略'],
  ['templates', '模板管理'],
  ['silences', '静默管理'],
];

const VIEW_COPY = {
  overview: ['监控概览', '当前项目的告警健康、规则评估和近期事件将在这里集中呈现。'],
  alerts: ['告警列表', '按状态、严重级别和资源筛选告警，并进入事件详情完成处置。'],
  'alert-detail': ['告警详情', '选择告警后可查看资源、证据、投递记录和处置时间线。'],
  rules: ['规则管理', '统一维护指标阈值、持续时长、评估周期和通知策略引用。'],
  policies: ['通知策略', '管理项目内的路由条件、通知渠道和安全的 Secret 引用状态。'],
  templates: ['模板管理', '维护通知标题和正文模板，并查看允许使用的变量。'],
  silences: ['静默管理', '管理维护窗口的匹配条件、原因和有效期。'],
};

const SEVERITY_LABELS = {
  critical: '紧急',
  warning: '警告',
  info: '提示',
  none: '无',
};

const SENSITIVE_VALUE_PATTERN = /(?:\b(?:password|passwd|pwd|token|secret|authorization|credential|api[_\s-]?key|access[_\s-]?key|client[_\s-]?secret)\b|\bbearer\s+\S+|\b[a-z][a-z0-9+.-]*:\/\/[^\s/@:]+(?::[^\s/@]*)?@[^\s/]+)/i;

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function formatSeverity(value) {
  return SEVERITY_LABELS[String(value ?? '').toLowerCase()] || '未知';
}

export function validateReason(value) {
  return SENSITIVE_VALUE_PATTERN.test(String(value ?? ''))
    ? '原因中不能包含凭据或连接串'
    : '';
}

export function buildAlertFilters(entries) {
  return Object.fromEntries([...entries].filter(([, value]) => String(value ?? '').trim() !== ''));
}

export function validateDisposition(input = {}) {
  const errors = {};
  if (!String(input.category ?? '').trim()) errors.category = '请选择处置分类';
  const reasonError = validateReason(input.reason);
  if (reasonError) errors.reason = reasonError;
  return errors;
}

export function validateRule(input = {}) {
  const errors = {};
  const metric = String(input.metric ?? '').trim();
  const threshold = Number(input.threshold);
  const duration = String(input.for ?? '').trim();
  const period = String(input.evaluationEvery ?? input.evaluation_every ?? '').trim();
  const policyIds = input.notificationPolicyIds ?? input.notification_policy_ids;

  if (!metric) errors.metric = '请选择指标';
  if (!Number.isFinite(threshold) || threshold <= 0) errors.threshold = '阈值必须大于 0';
  if (!/^\d+[smhd]$/.test(duration)) errors.for = '持续时长格式应为 5m 或 1h';
  if (!period) errors.evaluationEvery = '请选择评估周期';
  if (!Array.isArray(policyIds) || policyIds.length === 0) errors.notificationPolicyIds = '至少选择一个通知策略';
  return errors;
}

export function validatePolicy(input = {}) {
  const errors = {};
  const channel = String(input.channel ?? '').trim();
  const templateId = String(input.templateId ?? input.template_id ?? '').trim();
  if (!String(input.name ?? '').trim()) errors.name = '请填写策略名称';
  if (!['webhook', 'email', 'sms'].includes(channel)) errors.channel = '请选择通知渠道';
  if (!String(input.target ?? '').trim()) errors.target = '请填写渠道目标';
  if (!templateId) errors.templateId = '请选择通知模板';
  return errors;
}

export function sanitizePolicyForDisplay(policy = {}) {
  const {
    secret_ref: secretRefSnake,
    secretRef,
    has_secret: hasSecretSnake,
    hasSecret,
    secret_configured: secretConfiguredSnake,
    secretConfigured,
    ...safe
  } = policy;
  return {
    ...safe,
    secretConfigured: Boolean(secretRefSnake || secretRef || hasSecretSnake || hasSecret || secretConfiguredSnake || secretConfigured),
  };
}

function isSensitiveText(value) {
  return SENSITIVE_VALUE_PATTERN.test(String(value ?? ''));
}

function displayValue(value, fallback = '—') {
  const text = String(value ?? '').trim();
  if (!text) return fallback;
  return safeText(isSensitiveText(text) ? '敏感值已隐藏' : text);
}

function displayTime(value) {
  const timestamp = Date.parse(value);
  return Number.isNaN(timestamp) ? displayValue(value) : safeText(new Date(timestamp).toLocaleString('zh-CN', { hour12: false }));
}

function statusClass(value) {
  const normalized = String(value ?? '').toLowerCase();
  if (normalized === 'critical' || normalized === 'firing' || normalized === 'failed') return 'status-critical';
  if (normalized === 'warning' || normalized === 'acknowledged') return 'status-warning';
  if (normalized === 'resolved' || normalized === 'healthy' || normalized === 'delivered') return 'status-success';
  return 'status-info';
}

function stateLabel(value) {
  return ({ firing: '告警中', acknowledged: '已确认', resolved: '已恢复', pending: '待处理' })[String(value ?? '').toLowerCase()] || displayValue(value, '未知');
}

function localAlertValue(item, key) {
  if (key === 'rule') return item.rule_name ?? item.ruleName ?? item.rule_id ?? item.ruleId;
  if (key === 'resource') return item.resource_name ?? item.resourceName ?? item.instance ?? item.labels?.instance ?? item.resource?.name;
  return item[key];
}

function filterRenderedAlerts(items, filters) {
  return (Array.isArray(items) ? items : []).filter((item) => {
    if (filters.severity && String(item.severity) !== filters.severity) return false;
    if (filters.rule && !String(localAlertValue(item, 'rule') ?? '').toLowerCase().includes(String(filters.rule).toLowerCase())) return false;
    if (filters.resource && !String(localAlertValue(item, 'resource') ?? '').toLowerCase().includes(String(filters.resource).toLowerCase())) return false;
    const occurredAt = Date.parse(item.last_seen ?? item.lastSeen ?? item.fired_at ?? item.firedAt ?? item.updated_at ?? item.updatedAt);
    if (filters.from && !Number.isNaN(occurredAt) && occurredAt < Date.parse(filters.from)) return false;
    if (filters.to && !Number.isNaN(occurredAt) && occurredAt > Date.parse(filters.to)) return false;
    return true;
  });
}

function renderOverviewMarkup(overview = {}) {
  const counts = overview.state_counts ?? overview.stateCounts ?? overview.events ?? {};
  const evaluator = overview.evaluator ?? overview.evaluation ?? {};
  const trend = Array.isArray(overview.trend ?? overview.trend_24h ?? overview.events24h) ? (overview.trend ?? overview.trend_24h ?? overview.events24h) : [];
  const instances = Array.isArray(overview.focal_instances ?? overview.focalInstances ?? overview.instances) ? (overview.focal_instances ?? overview.focalInstances ?? overview.instances) : [];
  const events = Array.isArray(overview.recent_events ?? overview.recentEvents ?? overview.alerts) ? (overview.recent_events ?? overview.recentEvents ?? overview.alerts) : [];
  const health = evaluator.healthy === false ? '评估异常' : '评估健康';
  return `
    <div class="alert-overview-grid">
      <article class="alert-health-card"><span class="alert-status-tag ${statusClass(evaluator.healthy === false ? 'failed' : 'healthy')}">${health}</span><strong>${displayValue(overview.health ?? overview.summary ?? health)}</strong><p>当前项目的告警评估与事件状态。</p></article>
      <article class="alert-count-card"><span>告警中</span><strong>${displayValue(counts.firing ?? 0, '0')}</strong><p>需要优先关注的事件</p></article>
      <article class="alert-count-card"><span>已确认</span><strong>${displayValue(counts.acknowledged ?? 0, '0')}</strong><p>等待恢复或继续处置</p></article>
      <article class="alert-count-card"><span>已恢复</span><strong>${displayValue(counts.resolved ?? 0, '0')}</strong><p>最近处置完成的事件</p></article>
    </div>
    <div class="alert-overview-panels">
      <article class="alert-panel"><div class="alert-panel-head"><h4>24 小时事件趋势</h4><span>${trend.length ? `${trend.length} 个时段` : '暂无趋势数据'}</span></div><div class="alert-trend" aria-label="最近 24 小时事件趋势">${trend.length ? trend.map((point) => `<i style="--alert-height:${Math.max(8, Math.min(100, Number(point.count ?? point.value ?? 0) * 12))}%" title="${displayValue(point.at ?? point.time)}：${displayValue(point.count ?? point.value ?? 0)}"></i>`).join('') : '<p>当前项目尚未返回 24 小时趋势。</p>'}</div></article>
      <article class="alert-panel"><div class="alert-panel-head"><h4>规则评估</h4><span class="alert-status-tag ${statusClass(evaluator.healthy === false ? 'failed' : 'healthy')}">${health}</span></div><dl class="alert-kv"><div><dt>最近评估</dt><dd>${displayTime(evaluator.last_evaluated_at ?? evaluator.lastEvaluatedAt)}</dd></div><div><dt>异常规则</dt><dd>${displayValue(evaluator.unhealthy_rules ?? evaluator.unhealthyRules ?? 0, '0')}</dd></div></dl></article>
      <article class="alert-panel"><div class="alert-panel-head"><h4>重点实例</h4><span>${instances.length} 个</span></div><ul class="alert-simple-list">${instances.length ? instances.slice(0, 5).map((instance) => `<li><span>${displayValue(instance.name ?? instance.instance ?? instance.resource_name)}</span><b class="${statusClass(instance.state ?? instance.health)}">${displayValue(instance.state ?? instance.health ?? '正常')}</b></li>`).join('') : '<li>暂无重点实例</li>'}</ul></article>
      <article class="alert-panel"><div class="alert-panel-head"><h4>最近事件</h4><button type="button" class="alert-link-button" data-alert-view="alerts">查看列表</button></div><ul class="alert-simple-list">${events.length ? events.slice(0, 5).map((event) => `<li><button type="button" class="alert-event-link" data-alert-event="${safeText(event.id)}"><span>${displayValue(event.title ?? event.name)}</span><b class="${statusClass(event.severity)}">${formatSeverity(event.severity)}</b></button></li>`).join('') : '<li>暂无最近事件</li>'}</ul></article>
    </div>`;
}

function renderAlertListMarkup({ items, nextCursor, filters, source }) {
  return `
    <form class="alert-filter-bar" data-alert-filters>
      <label>状态<select name="state"><option value="">全部</option>${['firing', 'acknowledged', 'resolved'].map((value) => `<option value="${value}" ${filters.state === value ? 'selected' : ''}>${stateLabel(value)}</option>`).join('')}</select></label>
      <label>严重级别<select name="severity"><option value="">全部</option>${['critical', 'warning', 'info'].map((value) => `<option value="${value}" ${filters.severity === value ? 'selected' : ''}>${formatSeverity(value)}</option>`).join('')}</select></label>
      <label>规则<input name="rule" value="${displayValue(filters.rule, '')}" autocomplete="off" /></label>
      <label>资源<input name="resource" value="${displayValue(filters.resource, '')}" autocomplete="off" /></label>
      <label>开始时间<input type="datetime-local" name="from" value="${displayValue(filters.from, '')}" /></label>
      <label>结束时间<input type="datetime-local" name="to" value="${displayValue(filters.to, '')}" /></label>
      <button type="submit">筛选</button>
    </form>
    <p class="alert-filter-note">状态与分页由服务端在当前项目内处理；严重级别、规则、资源和时间仅在当前已加载结果中筛选。</p>
    <div class="alert-table-wrap">
      ${items.length ? `<table class="alert-table"><thead><tr><th>事件</th><th>状态</th><th>级别</th><th>资源</th><th>最近出现</th></tr></thead><tbody>${items.map((item) => `<tr><td><button type="button" class="alert-event-link" data-alert-event="${safeText(item.id)}">${displayValue(item.title ?? item.name ?? item.id)}</button></td><td><span class="alert-status-tag ${statusClass(item.state)}">${stateLabel(item.state)}</span></td><td><span class="alert-status-tag ${statusClass(item.severity)}">${formatSeverity(item.severity)}</span></td><td>${displayValue(localAlertValue(item, 'resource'))}</td><td>${displayTime(item.last_seen ?? item.lastSeen ?? item.fired_at ?? item.firedAt ?? item.updated_at ?? item.updatedAt)}</td></tr>`).join('')}</tbody></table>` : '<div class="alert-empty"><strong>暂无匹配告警</strong><p>请调整筛选条件或等待下一次规则评估。</p></div>'}
    </div>
    <div class="alert-pager"><span>来源：${displayValue(source === 'demo' ? '演示数据' : '控制面服务')}</span><div><button type="button" data-alert-prev ${alertCursor ? '' : 'disabled'}>上一页</button><button type="button" data-alert-next="${safeText(nextCursor ?? '')}" ${nextCursor ? '' : 'disabled'}>下一页</button></div></div>`;
}

function evidenceItems(event) {
  const evidence = Array.isArray(event.evidence) ? event.evidence : [];
  return evidence.map((item) => ({ label: item.label ?? item.type ?? '观测证据', value: item.summary ?? item.value, time: item.observed_at ?? item.observedAt ?? item.at }));
}

function timelineItems(event) {
  const timeline = event.disposition_timeline ?? event.dispositionTimeline ?? event.disposition_history ?? event.dispositionHistory ?? event.history;
  return Array.isArray(timeline) ? timeline.map((item) => ({ action: item.action ?? item.state ?? item.category ?? '处置记录', reason: item.reason, time: item.at ?? item.created_at ?? item.createdAt, actor: item.actor ?? item.operator })) : [];
}

function renderAlertDetailMarkup(event = {}, canManage = false) {
  const evidence = evidenceItems(event);
  const timeline = timelineItems(event);
  const delivery = Array.isArray(event.deliveries) ? event.deliveries : [];
  const resource = localAlertValue(event, 'resource');
  const state = event.state;
  return `
    <div class="alert-detail-top"><button type="button" class="alert-link-button" data-alert-back>← 返回告警列表</button><div><span class="alert-status-tag ${statusClass(state)}">${stateLabel(state)}</span><span class="alert-status-tag ${statusClass(event.severity)}">${formatSeverity(event.severity)}</span></div><div class="alert-detail-actions">${permissionsActionMarkup('acknowledge', state, canManage)}${permissionsActionMarkup('resolve', state, canManage)}</div></div>
    <div class="alert-detail-grid">
      <div class="alert-detail-main">
        <article class="alert-panel"><h4>${displayValue(event.title ?? event.name ?? event.id)}</h4><dl class="alert-kv"><div><dt>资源</dt><dd>${displayValue(resource)}</dd></div><div><dt>最近出现</dt><dd>${displayTime(event.last_seen ?? event.lastSeen ?? event.fired_at ?? event.firedAt)}</dd></div></dl></article>
        <article class="alert-panel"><h4>观测证据</h4>${evidence.length ? `<ul class="alert-evidence">${evidence.map((item) => `<li><b>${displayValue(item.label)}</b><span>${displayValue(item.value)}</span><time>${displayTime(item.time)}</time></li>`).join('')}</ul>` : '<p>暂无可展示的观测证据。</p>'}</article>
        <article class="alert-panel"><h4>根因提示</h4><p>${displayValue(event.root_cause_hint ?? event.rootCauseHint)}</p></article>
        <article class="alert-panel"><h4>处置时间线</h4>${timeline.length ? `<ol class="alert-timeline">${timeline.map((item) => `<li><b>${displayValue(item.action)}</b><span>${displayValue(item.reason)}</span><small>${displayValue(item.actor)} · ${displayTime(item.time)}</small></li>`).join('')}</ol>` : '<p>尚无处置记录。</p>'}</article>
      </div>
      <aside class="alert-detail-side">
        <article class="alert-panel"><h4>通知投递</h4>${delivery.length ? `<ul class="alert-simple-list">${delivery.map((item) => `<li><span>${displayValue(item.channel ?? item.provider ?? item.id)}</span><b class="${statusClass(item.status)}">${displayValue(item.status)}</b></li>`).join('')}</ul>` : '<p>暂无安全可展示的投递记录。</p>'}</article>
        <article class="alert-panel"><h4>关联规则</h4><p>${displayValue(event.rule_name ?? event.ruleName ?? event.rule_id ?? event.ruleId)}</p></article>
      </aside>
    </div>`;
}

function listItems(result) {
  return Array.isArray(result) ? result : Array.isArray(result?.items) ? result.items : [];
}

function valueOf(item, camel, snake = camel) {
  return item?.[camel] ?? item?.[snake];
}

function labelEntries(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
  return Object.entries(value).filter(([key, item]) => String(key).trim() && String(item ?? '').trim());
}

function labelsText(value) {
  return labelEntries(value).map(([key, item]) => `${key}=${item}`).join('\n');
}

function labelsFromText(value) {
  return String(value ?? '').split(/\r?\n|,/).reduce((labels, line) => {
    const [key, ...rest] = line.split('=');
    const name = String(key ?? '').trim();
    const item = rest.join('=').trim();
    if (name && item) labels[name] = item;
    return labels;
  }, {});
}

function selectorChips(value) {
  const entries = labelEntries(value);
  return entries.length
    ? `<span class="alert-selector-chips">${entries.map(([key, item]) => `<b>${displayValue(key)} = ${displayValue(item)}</b>`).join('')}</span>`
    : '<span class="alert-empty-value">未限制</span>';
}

function policyNames(ids, policies) {
  const names = new Map(policies.map((policy) => [String(policy.id), policy.name ?? policy.id]));
  const values = Array.isArray(ids) ? ids : [];
  return values.length ? values.map((id) => displayValue(names.get(String(id)) ?? id)).join('、') : '未配置';
}

function ruleSummary(rule, policies) {
  const aggregation = valueOf(rule, 'aggregation') || 'avg';
  const operator = valueOf(rule, 'operator') || '>';
  const threshold = valueOf(rule, 'threshold');
  const period = valueOf(rule, 'evaluationEvery', 'evaluation_every');
  const duration = valueOf(rule, 'for');
  const metric = valueOf(rule, 'metric');
  const policyIds = valueOf(rule, 'notificationPolicyIds', 'notification_policy_ids');
  return `${aggregation}(${metric || '未选择指标'}) ${operator} ${threshold ?? '—'}，每 ${period || '—'} 评估；持续 ${duration || '—'} 后通知 ${policyNames(policyIds, policies)}。`;
}

function secretConfigured(policy) {
  return sanitizePolicyForDisplay(policy).secretConfigured;
}

function safePolicyTarget(target) {
  const text = String(target ?? '').trim();
  if (!text) return '';
  try {
    const url = new URL(text);
    for (const key of [...url.searchParams.keys()]) {
      if (/(?:token|secret|password|passwd|pwd|authorization|credential|api[_-]?key|access[_-]?key)/i.test(key)) url.searchParams.set(key, '已隐藏');
    }
    return url.toString();
  } catch {
    return isSensitiveText(text) ? '敏感值已隐藏' : text;
  }
}

function ruleEditorMarkup(rule = {}, policies = {}, errors = {}) {
  const policyItems = Array.isArray(policies) ? policies : [];
  const policyIds = valueOf(rule, 'notificationPolicyIds', 'notification_policy_ids') ?? [];
  const selected = new Set(Array.isArray(policyIds) ? policyIds.map(String) : []);
  const period = valueOf(rule, 'evaluationEvery', 'evaluation_every') ?? '1m';
  const lookback = valueOf(rule, 'lookbackWindow', 'lookback_window') ?? period;
  return `
    <div class="alert-drawer-head"><div><span class="eyebrow">规则编辑</span><h3>${rule.id ? '编辑规则' : '新建规则'}</h3></div><button type="button" class="alert-drawer-close" data-alert-drawer-close aria-label="关闭">×</button></div>
    <form class="alert-config-form" data-rule-form>
      <label>规则名称<input name="name" required value="${safeText(valueOf(rule, 'name') ?? '')}" placeholder="例如：连接数过高" /></label>
      <div class="alert-form-grid"><label>指标<input name="metric" required value="${safeText(valueOf(rule, 'metric') ?? '')}" placeholder="db.connections" /></label><label>聚合<select name="aggregation">${['avg', 'max', 'min', 'sum'].map((value) => `<option value="${value}" ${value === (valueOf(rule, 'aggregation') ?? 'avg') ? 'selected' : ''}>${value}</option>`).join('')}</select></label></div>
      <div class="alert-form-grid"><label>运算符<select name="operator">${['>', '>=', '<', '<=', '==', '!='].map((value) => `<option value="${value}" ${value === (valueOf(rule, 'operator') ?? '>') ? 'selected' : ''}>${safeText(value)}</option>`).join('')}</select></label><label>阈值<input name="threshold" type="number" min="0" step="any" required value="${safeText(valueOf(rule, 'threshold') ?? '')}" /></label></div>
      <div class="alert-form-grid"><label>评估周期<select name="evaluationEvery">${['10s', '30s', '1m', '5m', '10m', '1h'].map((value) => `<option value="${value}" ${value === period ? 'selected' : ''}>${value}</option>`).join('')}</select></label><label>回看窗口<input name="lookbackWindow" value="${safeText(lookback)}" placeholder="1m" /></label></div>
      <div class="alert-form-grid"><label>持续时长<input name="for" required value="${safeText(valueOf(rule, 'for') ?? '5m')}" placeholder="5m" /></label><label>缺失数据<select name="missingData">${[['ignore', '忽略'], ['resolve', '恢复'], ['alert', '告警']].map(([value, label]) => `<option value="${value}" ${value === (valueOf(rule, 'missingData', 'missing_data') ?? 'ignore') ? 'selected' : ''}>${label}</option>`).join('')}</select></label></div>
      <div class="alert-form-grid"><label>严重级别<select name="severity">${['critical', 'warning', 'info'].map((value) => `<option value="${value}" ${value === (valueOf(rule, 'severity') ?? 'warning') ? 'selected' : ''}>${formatSeverity(value)}</option>`).join('')}</select></label><label class="alert-check-label"><input name="enabled" type="checkbox" ${(valueOf(rule, 'enabled') ?? true) ? 'checked' : ''} /> 保存后启用</label></div>
      <label>标签选择器<textarea name="labels" rows="3" placeholder="instance=db-01">${safeText(labelsText(valueOf(rule, 'labels')))}</textarea></label>
      <fieldset><legend>通知策略</legend>${policyItems.length ? policyItems.map((policy) => `<label class="alert-check-label"><input name="notificationPolicyIds" type="checkbox" value="${safeText(policy.id)}" ${selected.has(String(policy.id)) ? 'checked' : ''} />${displayValue(policy.name ?? policy.id)}</label>`).join('') : '<p class="alert-form-hint">暂无可引用的通知策略，请先创建通知策略。</p>'}</fieldset>
      <p class="alert-evaluation-summary" data-rule-summary>${safeText(ruleSummary({ ...rule, evaluationEvery: period, lookbackWindow: lookback }, policyItems))}</p>
      <p class="alert-form-errors" aria-live="polite">${safeText(Object.values(errors).join(' '))}</p>
      <div class="alert-drawer-actions"><button type="button" data-alert-drawer-close>取消</button><button type="submit">保存规则</button></div>
    </form>`;
}

function policyEditorMarkup(policy = {}, templates = [], errors = {}) {
  const safe = sanitizePolicyForDisplay(policy);
  const severities = new Set((valueOf(safe, 'severities') ?? []).map(String));
  const templateId = valueOf(safe, 'templateId', 'template_id') ?? '';
  return `
    <div class="alert-drawer-head"><div><span class="eyebrow">通知策略编辑</span><h3>${safe.id ? '编辑通知策略' : '新建通知策略'}</h3></div><button type="button" class="alert-drawer-close" data-alert-drawer-close aria-label="关闭">×</button></div>
    <form class="alert-config-form" data-policy-form>
      <label>策略名称<input name="name" required value="${safeText(valueOf(safe, 'name') ?? '')}" /></label>
      <div class="alert-form-grid"><label>通知渠道<select name="channel"><option value="">请选择</option>${[['webhook', 'Webhook'], ['email', '邮件'], ['sms', '短信']].map(([value, label]) => `<option value="${value}" ${value === (valueOf(safe, 'channel') ?? '') ? 'selected' : ''}>${label}</option>`).join('')}</select></label><label>渠道目标<input name="target" required value="${safeText(safePolicyTarget(valueOf(safe, 'target')))}" placeholder="Webhook 地址或邮箱" /></label></div>
      <label>通知模板<select name="templateId"><option value="">请选择模板</option>${templates.map((template) => `<option value="${safeText(template.id)}" ${String(template.id) === String(templateId) ? 'selected' : ''}>${displayValue(template.name ?? template.id)}</option>`).join('')}</select></label>
      ${templates.length ? '' : `<p class="alert-form-hint">暂无可选模板，请填写模板 ID 后保存。</p><label>模板 ID<input name="templateIdFallback" value="${safeText(templateId)}" placeholder="template-1" /></label>`}
      <fieldset><legend>严重级别范围</legend>${['critical', 'warning', 'info'].map((value) => `<label class="alert-check-label"><input name="severities" type="checkbox" value="${value}" ${severities.has(value) ? 'checked' : ''} />${formatSeverity(value)}</label>`).join('')}</fieldset>
      <label>路由标签匹配器<textarea name="matchLabels" rows="3" placeholder="database=orders">${safeText(labelsText(valueOf(safe, 'matchLabels', 'match_labels')))}</textarea></label>
      <div class="alert-form-grid"><label>开始时间（UTC）<input name="windowStartUtc" value="${safeText(valueOf(safe, 'windowStartUtc', 'window_start_utc') ?? '')}" placeholder="09:00" /></label><label>结束时间（UTC）<input name="windowEndUtc" value="${safeText(valueOf(safe, 'windowEndUtc', 'window_end_utc') ?? '')}" placeholder="17:00" /></label></div>
      <label>Secret 引用（可选）<input name="secretRef" type="password" autocomplete="new-password" placeholder="${safe.secretConfigured ? 'Secret 已配置；输入新引用以替换' : '例如 env://DBPILOT_WEBHOOK_TOKEN'}" /></label>
      <label class="alert-check-label"><input name="enabled" type="checkbox" ${(valueOf(safe, 'enabled') ?? true) ? 'checked' : ''} /> 保存后启用</label>
      <p class="alert-form-errors" aria-live="polite">${safeText(Object.values(errors).join(' '))}</p>
      <div class="alert-drawer-actions"><button type="button" data-alert-drawer-close>取消</button><button type="submit">保存策略</button></div>
    </form>`;
}

function renderRulesMarkup({ rules, policies, canManage }) {
  return `
    <div class="alert-config-toolbar"><div><strong>规则评估</strong><p>每条规则均在当前项目范围内评估。</p></div><div><button type="button" data-rule-create ${canManage ? '' : 'disabled'}>新建规则</button>${canManage ? '' : '<span class="alert-control-lock">需要项目管理权限</span>'}</div></div>
    <div class="alert-config-list">${rules.length ? rules.map((rule) => `<article class="alert-config-card"><div class="alert-config-card-head"><div><h4>${displayValue(valueOf(rule, 'name') ?? valueOf(rule, 'metric') ?? rule.id)}</h4><p>${safeText(ruleSummary(rule, policies))}</p></div><span class="alert-status-tag ${statusClass(valueOf(rule, 'severity'))}">${formatSeverity(valueOf(rule, 'severity'))}</span></div><dl class="alert-config-details"><div><dt>指标</dt><dd>${displayValue(valueOf(rule, 'metric'))}</dd></div><div><dt>评估 / 回看</dt><dd>${displayValue(valueOf(rule, 'evaluationEvery', 'evaluation_every'))} / ${displayValue(valueOf(rule, 'lookbackWindow', 'lookback_window'))}</dd></div><div><dt>缺失数据</dt><dd>${displayValue(valueOf(rule, 'missingData', 'missing_data'))}</dd></div><div><dt>标签选择器</dt><dd>${selectorChips(valueOf(rule, 'labels'))}</dd></div><div><dt>通知策略</dt><dd>${policyNames(valueOf(rule, 'notificationPolicyIds', 'notification_policy_ids'), policies)}</dd></div><div><dt>更新时间</dt><dd>${displayTime(valueOf(rule, 'updatedAt', 'updated_at'))}</dd></div></dl><div class="alert-config-card-actions"><span class="alert-status-tag ${valueOf(rule, 'enabled') === false ? 'status-info' : 'status-success'}">${valueOf(rule, 'enabled') === false ? '已停用' : '已启用'}</span><button type="button" data-rule-edit="${safeText(rule.id)}" ${canManage ? '' : 'disabled'}>编辑</button><button type="button" data-rule-enabled="${safeText(rule.id)}" data-rule-next-enabled="${valueOf(rule, 'enabled') === false ? 'true' : 'false'}" ${canManage ? '' : 'disabled'}>${valueOf(rule, 'enabled') === false ? '启用' : '停用'}</button>${canManage ? '' : '<span class="alert-control-lock">需要项目管理权限</span>'}</div></article>`).join('') : '<div class="alert-empty"><strong>暂无规则</strong><p>新建规则后将开始对当前项目进行评估。</p></div>'}</div>`;
}

function renderPoliciesMarkup({ policies, templates, canManage }) {
  const templateNames = new Map(templates.map((template) => [String(template.id), template.name ?? template.id]));
  return `
    <div class="alert-config-toolbar"><div><strong>通知投递</strong><p>Secret 仅显示配置状态，不显示引用或内容。</p></div><div><button type="button" data-policy-create ${canManage ? '' : 'disabled'}>新建通知策略</button>${canManage ? '' : '<span class="alert-control-lock">需要项目管理权限</span>'}</div></div>
    <div class="alert-config-list">${policies.length ? policies.map((policy) => { const safe = sanitizePolicyForDisplay(policy); const templateId = valueOf(safe, 'templateId', 'template_id'); return `<article class="alert-config-card"><div class="alert-config-card-head"><div><h4>${displayValue(valueOf(safe, 'name') ?? safe.id)}</h4><p>${displayValue(valueOf(safe, 'channel'))} · ${safeText(safePolicyTarget(valueOf(safe, 'target')))}</p></div><span class="alert-status-tag ${valueOf(safe, 'enabled') === false ? 'status-info' : 'status-success'}">${valueOf(safe, 'enabled') === false ? '已停用' : '已启用'}</span></div><dl class="alert-config-details"><div><dt>路由标签</dt><dd>${selectorChips(valueOf(safe, 'matchLabels', 'match_labels'))}</dd></div><div><dt>严重级别</dt><dd>${(valueOf(safe, 'severities') ?? []).map(formatSeverity).join('、') || '全部'}</dd></div><div><dt>投递渠道</dt><dd>${displayValue(valueOf(safe, 'channel'))} / ${safeText(safePolicyTarget(valueOf(safe, 'target')))}</dd></div><div><dt>通知模板</dt><dd>${displayValue(templateNames.get(String(templateId)) ?? templateId)}</dd></div><div><dt>Secret</dt><dd>${safe.secretConfigured ? '已配置' : '未配置'}</dd></div><div><dt>更新时间</dt><dd>${displayTime(valueOf(safe, 'updatedAt', 'updated_at'))}</dd></div></dl><div class="alert-config-card-actions"><button type="button" data-policy-edit="${safeText(safe.id)}" ${canManage ? '' : 'disabled'}>编辑</button>${canManage ? '' : '<span class="alert-control-lock">需要项目管理权限</span>'}</div></article>`; }).join('') : '<div class="alert-empty"><strong>暂无通知策略</strong><p>创建策略后可在规则中选择其作为通知目标。</p></div>'}</div>`;
}

function permissionsActionMarkup(action, state, canManage) {
  if (state === 'resolved' || !canManage) return '';
  const label = action === 'acknowledge' ? '确认告警' : '恢复告警';
  return `<form class="alert-disposition-form" data-disposition-action="${action}"><label>分类<select name="category"><option value="">选择分类</option><option value="investigating">处理中</option><option value="false-positive">误报</option><option value="recovered">已恢复</option></select></label><label>原因<textarea name="reason" maxlength="500" placeholder="填写不含凭据的处置原因"></textarea></label><p class="alert-form-errors" aria-live="polite"></p><button type="submit">${label}</button></form>`;
}

function showDispositionErrors(form, errors) {
  const output = form.querySelector('.alert-form-errors');
  if (output) output.textContent = Object.values(errors).join(' ');
}

function setBusy(form, busy) {
  form.querySelectorAll('button, input, select, textarea').forEach((element) => { element.disabled = busy; });
}

export function createAlertCenter({ root, api, scope, permissions = { manage: false }, onToast = () => {} }) {
  if (!root) throw new Error('alert center requires a root element');
  if (!api) throw new Error('alert center requires an alert API');

  let currentScope = { ...scope };
  let currentView = 'overview';
  let aborter = null;
  let destroyed = false;
  let selectedEventId = null;
  let alertFilters = {};
  let alertCursor = null;
  let alertCursorHistory = [];

  function isView(value) {
    return ALERT_VIEWS.some(([view]) => view === value);
  }

  function shellMarkup(content) {
    const [title, description] = VIEW_COPY[currentView];
    const viewLabel = ALERT_VIEWS.find(([view]) => view === currentView)?.[1] || title;
    return `
      <section class="alert-center" data-alert-view="${safeText(currentView)}" aria-label="告警中心">
        <header class="alert-center-header">
          <div>
            <span class="eyebrow">DBPILOT · 告警中心</span>
            <h2>${safeText(title)}</h2>
            <p>${safeText(description)}</p>
          </div>
          <div class="alert-context" aria-label="当前作用域">
            <span class="alert-scope">租户 ${safeText(currentScope.tenantId)} <i>/</i> 项目 ${safeText(currentScope.projectId)}</span>
            <span class="alert-source-badge">当前项目</span>
          </div>
        </header>
        <div class="alert-workbench">
          <nav class="alert-subnav" aria-label="告警中心导航">
            ${ALERT_VIEWS.map(([view, label]) => `<button type="button" class="${view === currentView ? 'is-active' : ''}" data-alert-view="${view}" aria-current="${view === currentView ? 'page' : 'false'}">${label}</button>`).join('')}
          </nav>
          <div class="alert-content">
            <div class="alert-content-head">
              <div><span class="alert-status-tag status-info">工作台</span><h3>${safeText(viewLabel)}</h3></div>
              <span class="alert-permission ${permissions.manage ? 'is-granted' : ''}">${permissions.manage ? '项目管理权限已启用' : '需要项目管理权限'}</span>
            </div>
            <div class="alert-view-body">${content}</div>
          </div>
        </div>
        <div class="alert-overlay" hidden aria-hidden="true"><div class="alert-drawer" role="dialog" aria-modal="true" aria-label="告警配置"></div></div>
        <div class="alert-toast" role="status" aria-live="polite" hidden><span class="alert-toast-progress"></span><span>操作处理中</span></div>
      </section>`;
  }

  function bindShell() {
    root.querySelectorAll('button[data-alert-view]').forEach((button) => {
      button.addEventListener('click', () => open(button.dataset.alertView));
    });
    root.querySelector('[data-alert-retry]')?.addEventListener('click', () => renderCurrent());
  }

  function renderLoading(label) {
    root.innerHTML = shellMarkup(`<div class="alert-loading" aria-label="正在加载 ${safeText(label)}"><i></i><i></i><i></i></div>`);
    bindShell();
  }

  function renderFailure(label) {
    root.innerHTML = shellMarkup(`<div class="alert-error" role="alert"><strong>暂时无法加载${safeText(label)}</strong><button type="button" data-alert-retry>重试</button></div>`);
    bindShell();
  }

  function renderCurrent() {
    aborter?.abort();
    aborter = new AbortController();
    if (destroyed) return Promise.resolve();
    const signal = aborter.signal;
    if (currentView === 'overview') return renderOverview(signal);
    if (currentView === 'alerts') return renderAlerts(signal);
    if (currentView === 'alert-detail') return renderAlertDetail(signal);
    if (currentView === 'rules') return renderRules(signal);
    if (currentView === 'policies') return renderPolicies(signal);
    root.innerHTML = shellMarkup(`<div class="alert-shell-message"><span class="alert-status-tag status-info">准备就绪</span><p>此专用页面已替代通用功能卡片。配置工作流将在相应模块加载时显示。</p></div>`);
    bindShell();
    return Promise.resolve();
  }

  function open(view = 'overview') {
    if (view === 'alert-detail' && !selectedEventId) view = 'alerts';
    currentView = isView(view) ? view : 'overview';
    return renderCurrent();
  }

  function setScope(nextScope) {
    aborter?.abort();
    currentScope = { ...nextScope };
    selectedEventId = null;
    alertCursor = null;
    alertCursorHistory = [];
    if (currentView === 'alert-detail') currentView = 'alerts';
    return renderCurrent();
  }

  function destroy() {
    destroyed = true;
    aborter?.abort();
    root.replaceChildren();
  }

  function closeDrawer() {
    const overlay = root.querySelector('.alert-overlay');
    if (!overlay) return;
    overlay.hidden = true;
    overlay.setAttribute('aria-hidden', 'true');
    overlay.querySelector('.alert-drawer').replaceChildren();
  }

  function showDrawer(markup) {
    const overlay = root.querySelector('.alert-overlay');
    if (!overlay) return null;
    overlay.hidden = false;
    overlay.setAttribute('aria-hidden', 'false');
    const drawer = overlay.querySelector('.alert-drawer');
    drawer.innerHTML = markup;
    drawer.querySelectorAll('[data-alert-drawer-close]').forEach((button) => button.addEventListener('click', closeDrawer));
    return drawer;
  }

  return { open, setScope, destroy };

  async function renderOverview(signal) {
    renderLoading('监控概览');
    try {
      const overview = await api.getOverview(currentScope, signal);
      if (signal.aborted || destroyed) return;
      root.innerHTML = shellMarkup(renderOverviewMarkup(overview));
      bindShell();
      root.querySelectorAll('[data-alert-event]').forEach((row) => row.addEventListener('click', () => {
        selectedEventId = row.dataset.alertEvent;
        open('alert-detail');
      }));
    } catch (error) {
      if (!signal.aborted && !destroyed) renderFailure('监控概览');
    }
  }

  async function renderAlerts(signal) {
    renderLoading('告警数据');
    try {
      const requestFilters = { ...alertFilters, limit: 25 };
      const result = await api.listAlerts(currentScope, requestFilters, alertCursor, signal);
      if (signal.aborted || destroyed) return;
      const items = filterRenderedAlerts(result.items, alertFilters);
      root.innerHTML = shellMarkup(renderAlertListMarkup({ items, nextCursor: result.nextCursor, filters: alertFilters, source: result.source }));
      bindShell();
      bindAlertList();
    } catch (error) {
      if (!signal.aborted && !destroyed) renderFailure('告警数据');
    }
  }

  async function renderAlertDetail(signal) {
    if (!selectedEventId) return open('alerts');
    renderLoading('告警详情');
    try {
      const event = await api.getAlert(currentScope, selectedEventId, signal);
      if (signal.aborted || destroyed) return;
      root.innerHTML = shellMarkup(renderAlertDetailMarkup(event, permissions.manage));
      bindShell();
      bindAlertDetail(event.id);
    } catch (error) {
      if (signal.aborted || destroyed) return;
      if (error?.kind === 'not-found' || error?.kind === 'forbidden') {
        selectedEventId = null;
        currentView = 'alerts';
        onToast('对象已被删除或无权访问');
        return renderCurrent();
      }
      renderFailure('告警详情');
    }
  }

  async function renderRules(signal) {
    renderLoading('规则');
    try {
      const [ruleResult, policyResult] = await Promise.all([
        api.listRules(currentScope, signal),
        api.listNotificationPolicies(currentScope, signal),
      ]);
      if (signal.aborted || destroyed) return;
      const rules = listItems(ruleResult);
      const policies = listItems(policyResult).map(sanitizePolicyForDisplay);
      root.innerHTML = shellMarkup(renderRulesMarkup({ rules, policies, canManage: permissions.manage }));
      bindShell();
      bindRules(rules, policies);
    } catch (error) {
      if (!signal.aborted && !destroyed) renderFailure('规则');
    }
  }

  async function renderPolicies(signal) {
    renderLoading('通知策略');
    try {
      const work = [api.listNotificationPolicies(currentScope, signal)];
      if (typeof api.listTemplates === 'function') work.push(api.listTemplates(currentScope, signal));
      const [policyResult, templateResult] = await Promise.all(work);
      if (signal.aborted || destroyed) return;
      const policies = listItems(policyResult).map(sanitizePolicyForDisplay);
      const templates = listItems(templateResult);
      root.innerHTML = shellMarkup(renderPoliciesMarkup({ policies, templates, canManage: permissions.manage }));
      bindShell();
      bindPolicies(policies, templates);
    } catch (error) {
      if (!signal.aborted && !destroyed) renderFailure('通知策略');
    }
  }

  function bindAlertList() {
    root.querySelector('[data-alert-filters]')?.addEventListener('submit', (event) => {
      event.preventDefault();
      alertFilters = buildAlertFilters(new FormData(event.currentTarget));
      alertCursor = null;
      alertCursorHistory = [];
      renderCurrent();
    });
    root.querySelectorAll('[data-alert-event]').forEach((row) => row.addEventListener('click', () => {
      selectedEventId = row.dataset.alertEvent;
      open('alert-detail');
    }));
    root.querySelector('[data-alert-next]')?.addEventListener('click', (event) => {
      alertCursorHistory.push(alertCursor);
      alertCursor = event.currentTarget.dataset.alertNext;
      renderCurrent();
    });
    root.querySelector('[data-alert-prev]')?.addEventListener('click', () => {
      alertCursor = alertCursorHistory.pop() ?? null;
      renderCurrent();
    });
  }

  function bindAlertDetail(id) {
    root.querySelector('[data-alert-back]')?.addEventListener('click', () => open('alerts'));
    root.querySelectorAll('[data-disposition-action]').forEach((form) => form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const action = form.dataset.dispositionAction;
      const disposition = { category: form.category.value, reason: form.reason.value.trim() };
      const errors = validateDisposition(disposition);
      showDispositionErrors(form, errors);
      if (Object.keys(errors).length) return;
      setBusy(form, true);
      try {
        await (action === 'acknowledge'
          ? api.acknowledgeAlert(currentScope, id, disposition, aborter?.signal)
          : api.resolveAlert(currentScope, id, disposition, aborter?.signal));
        onToast(action === 'acknowledge' ? '告警已确认并写入审计记录' : '告警已恢复并写入审计记录');
        await open('alert-detail');
      } catch (error) {
        if (error?.kind === 'not-found' || error?.kind === 'forbidden') {
          selectedEventId = null;
          currentView = 'alerts';
          onToast('对象已被删除或无权访问');
          return renderCurrent();
        }
        onToast('操作未完成，请稍后重试');
        setBusy(form, false);
      }
    }));
  }

  function bindRules(rules, policies) {
    root.querySelector('[data-rule-create]')?.addEventListener('click', () => openRuleDrawer({}, policies));
    root.querySelectorAll('[data-rule-edit]').forEach((button) => button.addEventListener('click', () => {
      const rule = rules.find((item) => String(item.id) === button.dataset.ruleEdit);
      if (rule) openRuleDrawer(rule, policies);
    }));
    root.querySelectorAll('[data-rule-enabled]').forEach((button) => button.addEventListener('click', async () => {
      if (!permissions.manage) return;
      button.disabled = true;
      try {
        await api.setRuleEnabled(currentScope, button.dataset.ruleEnabled, button.dataset.ruleNextEnabled === 'true', aborter?.signal);
        onToast(button.dataset.ruleNextEnabled === 'true' ? '规则已启用' : '规则已停用');
        await renderCurrent();
      } catch (error) {
        onToast(error?.kind === 'conflict' ? '对象已更新或存在引用冲突，请刷新后重试' : '操作未完成，请稍后重试');
        button.disabled = false;
      }
    }));
  }

  function openRuleDrawer(rule, policies, errors = {}) {
    if (!permissions.manage) return;
    const drawer = showDrawer(ruleEditorMarkup(rule, policies, errors));
    const form = drawer?.querySelector('[data-rule-form]');
    if (!form) return;
    const updateSummary = () => {
      const formData = new FormData(form);
      const selectedPolicies = [...form.querySelectorAll('input[name="notificationPolicyIds"]:checked')].map((input) => input.value);
      const draft = {
        ...rule,
        metric: formData.get('metric'), aggregation: formData.get('aggregation'), operator: formData.get('operator'), threshold: formData.get('threshold'),
        evaluationEvery: formData.get('evaluationEvery'), for: formData.get('for'), notificationPolicyIds: selectedPolicies,
      };
      const summary = form.querySelector('[data-rule-summary]');
      if (summary) summary.textContent = ruleSummary(draft, policies);
    };
    form.addEventListener('input', updateSummary);
    form.addEventListener('change', updateSummary);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(form);
      const notificationPolicyIds = [...form.querySelectorAll('input[name="notificationPolicyIds"]:checked')].map((input) => input.value);
      const input = {
        metric: String(formData.get('metric') ?? '').trim(),
        threshold: Number(formData.get('threshold')), for: String(formData.get('for') ?? '').trim(),
        evaluationEvery: String(formData.get('evaluationEvery') ?? '').trim(), notificationPolicyIds,
      };
      const validation = validateRule(input);
      const output = form.querySelector('.alert-form-errors');
      if (Object.keys(validation).length) {
        if (output) output.textContent = Object.values(validation).join(' ');
        return;
      }
      const payload = {
        ...(rule.id ? { id: rule.id } : {}),
        name: String(formData.get('name') ?? '').trim(), metric: input.metric, aggregation: String(formData.get('aggregation') ?? 'avg'), operator: String(formData.get('operator') ?? '>'),
        threshold: input.threshold, evaluation_every: input.evaluationEvery, lookback_window: String(formData.get('lookbackWindow') ?? '').trim() || input.evaluationEvery,
        for: input.for, missing_data: String(formData.get('missingData') ?? 'ignore'), severity: String(formData.get('severity') ?? 'warning'),
        notification_policy_ids: notificationPolicyIds, labels: labelsFromText(formData.get('labels')), enabled: form.querySelector('input[name="enabled"]').checked,
      };
      setBusy(form, true);
      try {
        await api.saveRule(currentScope, payload, aborter?.signal);
        closeDrawer();
        onToast('规则已保存');
        await renderCurrent();
      } catch (error) {
        if (output) output.textContent = error?.kind === 'conflict' ? '对象已更新或存在引用冲突，请刷新后重试' : '操作未完成，请稍后重试';
        setBusy(form, false);
      }
    });
  }

  function bindPolicies(policies, templates) {
    root.querySelector('[data-policy-create]')?.addEventListener('click', () => openPolicyDrawer({}, templates));
    root.querySelectorAll('[data-policy-edit]').forEach((button) => button.addEventListener('click', () => {
      const policy = policies.find((item) => String(item.id) === button.dataset.policyEdit);
      if (policy) openPolicyDrawer(policy, templates);
    }));
  }

  function openPolicyDrawer(policy, templates, errors = {}) {
    if (!permissions.manage) return;
    const safePolicy = sanitizePolicyForDisplay(policy);
    const drawer = showDrawer(policyEditorMarkup(safePolicy, templates, errors));
    const form = drawer?.querySelector('[data-policy-form]');
    if (!form) return;
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(form);
      const templateId = String(formData.get('templateId') ?? '').trim() || String(formData.get('templateIdFallback') ?? '').trim();
      const input = { name: String(formData.get('name') ?? '').trim(), channel: String(formData.get('channel') ?? '').trim(), target: String(formData.get('target') ?? '').trim(), templateId };
      const validation = validatePolicy(input);
      const output = form.querySelector('.alert-form-errors');
      if (Object.keys(validation).length) {
        if (output) output.textContent = Object.values(validation).join(' ');
        return;
      }
      const secretRef = String(formData.get('secretRef') ?? '').trim();
      const payload = {
        ...(safePolicy.id ? { id: safePolicy.id } : {}),
        name: input.name, channel: input.channel, target: input.target, template_id: templateId,
        severities: [...form.querySelectorAll('input[name="severities"]:checked')].map((item) => item.value),
        match_labels: labelsFromText(formData.get('matchLabels')), window_start_utc: String(formData.get('windowStartUtc') ?? '').trim(),
        window_end_utc: String(formData.get('windowEndUtc') ?? '').trim(), enabled: form.querySelector('input[name="enabled"]').checked,
        ...(secretRef ? { secret_ref: secretRef } : {}),
      };
      setBusy(form, true);
      try {
        await api.saveNotificationPolicy(currentScope, payload, aborter?.signal);
        closeDrawer();
        onToast('通知策略已保存');
        await renderCurrent();
      } catch (error) {
        if (output) output.textContent = error?.kind === 'conflict' ? '对象已更新或存在引用冲突，请刷新后重试' : '操作未完成，请稍后重试';
        setBusy(form, false);
      }
    });
  }
}

if (typeof window !== 'undefined') {
  window.DBPilotAlertCenter = { create: createAlertCenter };
}
