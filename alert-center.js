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

export function safeText(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[character]);
}

export function formatSeverity(value) {
  return SEVERITY_LABELS[String(value ?? '').toLowerCase()] || '未知';
}

export function validateReason(value) {
  return /(?:password|token|secret|postgres(?:ql)?:\/\/[^\s]+)/i.test(String(value ?? ''))
    ? '原因中不能包含凭据或连接串'
    : '';
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
  if (!/^\d+(?:m|h)$/.test(duration)) errors.for = '持续时长格式应为 5m 或 1h';
  if (!period) errors.evaluationEvery = '请选择评估周期';
  if (!Array.isArray(policyIds) || policyIds.length === 0) errors.notificationPolicyIds = '至少选择一个通知策略';
  return errors;
}

export function createAlertCenter({ root, api, scope, permissions = { manage: false }, onToast = () => {} }) {
  if (!root) throw new Error('alert center requires a root element');
  if (!api) throw new Error('alert center requires an alert API');

  let currentScope = { ...scope };
  let currentView = 'overview';
  let aborter = null;
  let destroyed = false;

  function isView(value) {
    return ALERT_VIEWS.some(([view]) => view === value);
  }

  function renderCurrent() {
    aborter?.abort();
    aborter = new AbortController();
    if (destroyed) return Promise.resolve();

    const [title, description] = VIEW_COPY[currentView];
    const viewLabel = ALERT_VIEWS.find(([view]) => view === currentView)?.[1] || title;
    root.innerHTML = `
      <section class="alert-center" data-alert-view="${safeText(currentView)}" aria-label="告警中心">
        <header class="alert-center-header">
          <div>
            <span class="eyebrow">DBPILOT · 告警中心</span>
            <h2>${safeText(title)}</h2>
            <p>${safeText(description)}</p>
          </div>
          <div class="alert-context" aria-label="当前作用域">
            <span class="alert-scope">租户 ${safeText(currentScope.tenantId)} <i>/</i> 项目 ${safeText(currentScope.projectId)}</span>
            <span class="alert-source-badge">演示数据</span>
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
            <div class="alert-shell-message">
              <span class="alert-status-tag status-info">准备就绪</span>
              <p>此专用页面已替代通用功能卡片。数据列表与编辑工作流将在相应模块加载时显示。</p>
            </div>
            <div class="alert-loading" aria-label="正在加载" hidden><i></i><i></i><i></i></div>
            <div class="alert-empty" hidden><strong>暂无数据</strong><p>当前项目没有可显示的告警资源。</p></div>
            <div class="alert-error" role="alert" hidden><strong>暂时无法加载告警数据</strong><button type="button" data-alert-retry>重试</button></div>
          </div>
        </div>
        <div class="alert-overlay" hidden aria-hidden="true">
          <div class="alert-drawer" role="dialog" aria-modal="true" aria-label="告警配置"></div>
        </div>
        <div class="alert-toast" role="status" aria-live="polite" hidden><span class="alert-toast-progress"></span><span>操作处理中</span></div>
      </section>`;

    root.querySelectorAll('[data-alert-view]').forEach((button) => {
      if (button.tagName === 'BUTTON') button.addEventListener('click', () => open(button.dataset.alertView));
    });
    root.querySelector('[data-alert-retry]')?.addEventListener('click', () => {
      onToast('正在重试加载告警数据');
      renderCurrent();
    });
    return Promise.resolve();
  }

  function open(view = 'overview') {
    currentView = isView(view) ? view : 'overview';
    return renderCurrent();
  }

  function setScope(nextScope) {
    aborter?.abort();
    currentScope = { ...nextScope };
    return renderCurrent();
  }

  function destroy() {
    destroyed = true;
    aborter?.abort();
    root.replaceChildren();
  }

  return { open, setScope, destroy };
}

if (typeof window !== 'undefined') {
  window.DBPilotAlertCenter = { create: createAlertCenter };
}
