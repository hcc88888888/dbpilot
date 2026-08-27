import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAlertFilters,
  alertFailureMessage,
  alertSourceLabel,
  createAlertCenter,
  formatSeverity,
  safeText,
  validateDisposition,
  validatePolicy,
  validateReason,
  validateRule,
  validateSilence,
  validateTemplate,
  isActiveSilence,
  isValidSilenceMatcherKey,
  normalizeDuration,
  policyEditorMarkup,
  resolveAlertContext,
  ruleEditorMarkup,
  renderAlertDetailMarkup,
  renderTemplatePreview,
  renderAlertListMarkup,
  sanitizePolicyForDisplay,
} from '../alert-center.js';

test('production bootstrap requires a validated authenticated context and never guesses manage permission', () => {
  assert.deepEqual(resolveAlertContext('', undefined), {
    available: true,
    scope: { tenantId: 'demo', projectId: 'production' },
    permissions: { manage: true },
  });
  assert.deepEqual(resolveAlertContext('https://control.example', {
    authenticated: true,
    tenantId: 'tenant-a',
    projectId: 'project-a',
    permissions: { manage: false },
  }), {
    available: true,
    scope: { tenantId: 'tenant-a', projectId: 'project-a' },
    permissions: { manage: false },
  });
  assert.deepEqual(resolveAlertContext('https://control.example', {
    authenticated: true,
    tenantId: 'tenant-a',
    projectId: 'project-a',
  }), {
    available: true,
    scope: { tenantId: 'tenant-a', projectId: 'project-a' },
    permissions: { manage: false },
  });
  assert.deepEqual(resolveAlertContext('https://control.example', { tenantId: 'demo', projectId: 'production', permissions: { manage: true } }), {
    available: false,
    scope: { tenantId: '未配置', projectId: '未配置' },
    permissions: { manage: false },
  });
});

test('dashboard bootstrap uses the validated alert context contract', async () => {
  const app = await (await import('node:fs/promises')).readFile(new URL('../app.js', import.meta.url), 'utf8');
  const docs = await (await import('node:fs/promises')).readFile(new URL('../docs/alert-center-integration.md', import.meta.url), 'utf8');
  assert.match(app, /resolveAlertContext/);
  assert.match(app, /available:alertContext\.available/);
  assert.doesNotMatch(app, /scope:\{tenantId:'demo',projectId:'production'\},permissions:\{manage:true\}/);
  assert.match(docs, /window\.DBPILOT_ALERT_CONTEXT/);
  assert.match(docs, /authenticated: true/);
});

test('demo responses have an explicit safe source label', () => {
  assert.equal(alertSourceLabel('demo'), '演示数据');
  assert.equal(alertSourceLabel('control-plane'), '控制面服务');
});

test('forbidden adapter failures preserve the user-safe permission message', () => {
  assert.equal(
    alertFailureMessage({ kind: 'forbidden', message: '当前账号没有该项目的操作权限' }, '告警数据'),
    '当前账号没有该项目的操作权限',
  );
});

test('alert-list pager renders without relying on controller-local cursor state', () => {
  const markup = renderAlertListMarkup({
    items: [],
    nextCursor: '25',
    filters: {},
    source: 'demo',
    cursor: null,
  });
  assert.match(markup, /data-alert-prev disabled/);
  assert.match(markup, /data-alert-next="25"/);
});

test('safeText prevents markup from becoming alert-detail HTML', () => {
  assert.equal(safeText('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
});

test('rule validation requires metric, positive threshold, duration, period, and policy references', () => {
  assert.deepEqual(validateRule({ metric: '', threshold: 0, for: 'soon', evaluationEvery: '', notificationPolicyIds: [] }), {
    metric: '请选择指标', threshold: '阈值必须大于 0', for: '持续时长格式应为 5m 或 1h', evaluationEvery: '请选择评估周期', notificationPolicyIds: '至少选择一个通知策略',
  });
});

test('valid rule has bounded duration fields and a policy reference', () => {
  assert.deepEqual(validateRule({ metric: 'db.connections', threshold: 80, for: '10m', evaluationEvery: '1m', notificationPolicyIds: ['policy-1'] }), {});
});

test('rule validation accepts control-plane duration units', () => {
  assert.deepEqual(validateRule({ metric: 'db.connections', threshold: 80, for: '1s', evaluationEvery: '1m', notificationPolicyIds: ['policy-1'] }), {});
});

test('numeric backend durations normalize from nanoseconds for rule editing and validation', () => {
  assert.equal(normalizeDuration(60_000_000_000), '1m');
  assert.equal(normalizeDuration(90_000_000_000), '1m30s');
  assert.equal(normalizeDuration(1_000_000), '1ms');
  assert.deepEqual(validateRule({ metric: 'db.connections', threshold: 80, for: 60_000_000_000, evaluationEvery: 30_000_000_000, notificationPolicyIds: ['policy-1'] }), {});
  const markup = ruleEditorMarkup({ evaluation_every: 60_000_000_000, lookback_window: 300_000_000_000, for: 90_000_000_000 }, []);
  assert.match(markup, /option value="1m" selected/);
  assert.match(markup, /name="lookbackWindow" value="5m"/);
  assert.match(markup, /name="for" required value="1m30s"/);
});

test('rule validation rejects a lookback duration the backend cannot parse', () => {
  assert.deepEqual(validateRule({ metric: 'db.connections', threshold: 80, for: '5m', evaluationEvery: '1m', lookbackWindow: 'one minute', notificationPolicyIds: ['policy-1'] }), {
    lookbackWindow: '回看窗口格式应为 5m 或 1h',
  });
});

test('policy validation requires a name, supported channel, target, and template', () => {
  assert.deepEqual(validatePolicy({ name: '', channel: 'pager', target: '', templateId: '' }), {
    name: '请填写策略名称',
    channel: '请选择通知渠道',
    target: '请填写渠道目标',
    templateId: '请选择通知模板',
  });
});

test('policy editor and validation use exactly the backend channel set', () => {
  for (const channel of ['webhook', 'smtp', 'in_app']) {
    assert.deepEqual(validatePolicy({ name: 'Ops', channel, target: 'operator', templateId: 'template-1' }), {});
  }
  for (const channel of ['email', 'sms']) {
    assert.deepEqual(validatePolicy({ name: 'Ops', channel, target: 'operator', templateId: 'template-1' }), { channel: '请选择通知渠道' });
  }
  const markup = policyEditorMarkup({}, []);
  assert.match(markup, /option value="webhook"/);
  assert.match(markup, /option value="smtp"/);
  assert.match(markup, /option value="in_app"/);
  assert.doesNotMatch(markup, /option value="email"|option value="sms"/);
});

test('policy display exposes configuration state but never a secret reference', () => {
  const safe = sanitizePolicyForDisplay({ name: '值班 Webhook', secret_ref: 'env://DBPILOT_TOKEN', target: 'https://hooks.example/ops' });
  assert.equal(safe.secretConfigured, true);
  assert.equal('secret_ref' in safe, false);
  assert.equal('secretRef' in safe, false);
});

test('tokenized policy target is removed and requires a replacement while a normal target remains editable', () => {
  const protectedPolicy = sanitizePolicyForDisplay({ target: 'https://hooks.example/ops?token=top-secret&route=primary' });
  assert.equal(protectedPolicy.target, '');
  assert.equal(protectedPolicy.targetRequiresReplacement, true);
  assert.equal(JSON.stringify(protectedPolicy).includes('top-secret'), false);
  assert.deepEqual(validatePolicy({ name: '值班', channel: 'webhook', target: protectedPolicy.target, templateId: 'template-1' }), {
    target: '请填写渠道目标',
  });

  const normalPolicy = sanitizePolicyForDisplay({ target: 'https://hooks.example/ops?route=primary' });
  assert.equal(normalPolicy.target, 'https://hooks.example/ops?route=primary');
  assert.equal(normalPolicy.targetRequiresReplacement, false);
});

test('policy target sanitizer hides signature and relative token query variants', () => {
  for (const target of [
    'https://hooks.example/ops?signature=top-secret',
    'https://hooks.example/ops?SIG=top-secret',
    '/ops?token=top-secret',
    '/ops?X-Auth_Key=top-secret',
  ]) {
    const safe = sanitizePolicyForDisplay({ target });
    assert.equal(safe.target, '');
    assert.equal(safe.targetRequiresReplacement, true);
    assert.equal(JSON.stringify(safe).includes('top-secret'), false);
  }
});

test('formatSeverity renders an understandable Chinese severity label', () => {
  assert.equal(formatSeverity('critical'), '紧急');
});

test('validateReason rejects obvious credentials and connection strings', () => {
  assert.equal(validateReason('请使用 postgres://operator:password@example.com/db 连接'), '原因中不能包含凭据或连接串');
});

test('validateReason rejects non-Postgres DSNs with credentials', () => {
  for (const reason of ['mysql://alice:pw@db.example/app', 'mongodb://user:pw@host.example/database']) {
    assert.equal(validateReason(reason), '原因中不能包含凭据或连接串');
  }
});

test('validateReason rejects bearer and API credential-bearing values', () => {
  for (const reason of ['Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature', 'api_key: sk_live_abc123']) {
    assert.equal(validateReason(reason), '原因中不能包含凭据或连接串');
  }
});

test('buildAlertFilters removes empty fields and keeps the selected time range', () => {
  assert.deepEqual(buildAlertFilters(new Map([['state', 'firing'], ['severity', ''], ['from', '2026-08-27T00:00']])), {
    state: 'firing', from: '2026-08-27T00:00',
  });
});

test('disposition validation requires category and rejects a token-like reason', () => {
  assert.deepEqual(validateDisposition({ category: '', reason: 'token=abc.def.ghi' }), {
    category: '请选择处置分类', reason: '原因中不能包含凭据或连接串',
  });
});

test('template validation requires name, subject, and body', () => {
  assert.deepEqual(validateTemplate({ name: '', subject: '', body: '' }), {
    name: '请填写模板名称', subject: '请填写通知标题', body: '请填写通知正文',
  });
});

test('template validation rejects variables the notification renderer does not support', () => {
  assert.deepEqual(validateTemplate({ name: '告警', subject: '{{unknown.value}}', body: '告警正文' }), {
    subject: '包含不支持的模板变量',
  });
});

test('template validation accepts server-valid whitespace around placeholders', () => {
  assert.deepEqual(validateTemplate({ name: '告警', subject: '{{ event.id }}', body: '{{ resource.database }} {{evidence.aggregate}}' }), {});
});

test('template preview resolves server-valid whitespace event and resource variables as text', () => {
  assert.equal(renderTemplatePreview({ subject: '{{ event.id }}', body: '{{ resource.database }}' }), 'alert-20260827-01\n\norders');
});

test('template validation rejects Unicode whitespace that the server placeholder grammar does not accept', () => {
  assert.deepEqual(validateTemplate({ name: '告警', subject: '{{\u00a0event.id\u00a0}}', body: '{{\ufeffresource.database\ufeff}}' }), {
    subject: '包含不支持的模板变量', body: '包含不支持的模板变量',
  });
  assert.equal(renderTemplatePreview({ subject: '{{ event.id }}', body: '{{ resource.database }}' }), 'alert-20260827-01\n\norders');
});

test('template validation rejects malformed and non-ASCII resource placeholders', () => {
  assert.deepEqual(validateTemplate({ name: '告警', subject: '告警 {{event.id', body: '{{resource.数据库}}' }), {
    subject: '包含不支持的模板变量', body: '包含不支持的模板变量',
  });
  assert.deepEqual(validateTemplate({ name: '告警', subject: '{{event id}}', body: '告警正文' }), {
    subject: '包含不支持的模板变量',
  });
});

test('silence must have matcher, future end time, and an ordinary-text reason', () => {
  assert.deepEqual(validateSilence({ matchers: {}, startsAt: '2026-08-27T10:00', endsAt: '2026-08-27T09:00', reason: 'secret=abc' }), {
    matchers: '至少添加一个匹配条件', endsAt: '结束时间必须晚于开始时间', reason: '原因中不能包含凭据或连接串',
  });
});

test('silence validation requires an ordinary-text reason', () => {
  assert.deepEqual(validateSilence({ matchers: { 'label.instance': 'mysql-01' }, startsAt: '2099-08-27T10:00', endsAt: '2099-08-27T11:00', reason: '   ' }), {
    reason: '请填写静默原因',
  });
});

test('silence validation rejects a matcher row with only a key or value', () => {
  assert.deepEqual(validateSilence({ matchers: { 'label.instance': 'mysql-01' }, hasIncompleteMatchers: true, startsAt: '2099-08-27T10:00', endsAt: '2099-08-27T11:00', reason: '例行维护' }), {
    matchers: '请完整填写每个匹配条件',
  });
});

test('silence validation rejects duplicate normalized matcher keys', () => {
  assert.deepEqual(validateSilence({ matchers: { 'label.instance': 'mysql-01' }, hasDuplicateMatchers: true, startsAt: '2099-08-27T10:00', endsAt: '2099-08-27T11:00', reason: '例行维护' }), {
    matchers: '匹配条件不能重复',
  });
});

test('silence matcher keys mirror the backend reserved and namespaced allowlist', () => {
  for (const key of ['fingerprint', 'resource', 'tenant_id', 'project_id', 'scope', 'label.instance', 'resource.database']) {
    assert.equal(isValidSilenceMatcherKey(key), true, key);
  }
  for (const key of ['instance', 'database', 'label.foo-bar', 'resource.password', 'unknown.namespace']) {
    assert.equal(isValidSilenceMatcherKey(key), false, key);
  }
  assert.deepEqual(validateSilence({ matchers: { instance: 'mysql-01' }, startsAt: '2099-08-27T10:00', endsAt: '2099-08-27T11:00', reason: '例行维护' }), {
    matchers: '匹配键必须使用保留键或 label. / resource. 前缀',
  });
});

test('alert detail safely renders map evidence, delivery history, dispositions, and related rule', () => {
  const markup = renderAlertDetailMarkup({
    id: 'alert-1', rule_id: 'rule-1', fingerprint: 'fp-1', state: 'firing', severity: 'critical',
    first_seen: '2026-08-27T09:00:00Z', last_seen: '2026-08-27T09:30:00Z',
    evidence: { aggregate: '<img src=x onerror=alert(1)>', samples: '12' },
    labels: { instance: 'mysql-01' },
    deliveries: [{ id: 'delivery-1', policy_id: 'policy-1', status: 'delivered', attempts: 1, delivered_at: '2026-08-27T09:31:00Z' }],
    dispositions: [{ kind: 'root_cause', category: 'capacity', reason: 'disk pressure', actor: 'operator-1', occurred_at: '2026-08-27T09:32:00Z' }],
    rule: { id: 'rule-1', name: 'Disk pressure', metric: 'disk.used', severity: 'critical' },
  }, false);
  assert.match(markup, /aggregate/);
  assert.match(markup, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(markup, /<img src=x/);
  assert.match(markup, /投递历史/);
  assert.match(markup, /policy-1/);
  assert.match(markup, /根因记录/);
  assert.match(markup, /disk pressure/);
  assert.match(markup, /Disk pressure/);
  assert.match(markup, /disk\.used/);
  assert.match(markup, /fp-1/);
});

test('active silence ends strictly before its end timestamp', () => {
  assert.equal(isActiveSilence({ startsAt: '2026-08-27T09:00:00Z', endsAt: '2026-08-27T10:00:00Z' }, new Date('2026-08-27T09:30:00Z')), true);
  assert.equal(isActiveSilence({ startsAt: '2026-08-27T09:00:00Z', endsAt: '2026-08-27T10:00:00Z' }, new Date('2026-08-27T10:00:00Z')), false);
});

test('confirmed silence-end click calls the scoped adapter, toasts, and reloads the silence DOM', async () => {
  const root = createAlertCenterRoot();
  const calls = [];
  const toasts = [];
  const previousWindow = globalThis.window;
  globalThis.window = { confirm: () => true };
  try {
    const api = {
      async listSilences() {
        calls.push('list');
        return calls.filter((call) => call === 'list').length === 1
          ? { source: 'demo', items: [{ id: 'silence-1', matchers: { 'label.instance': 'mysql-01' }, starts_at: '2026-01-01T00:00:00Z', ends_at: '2099-01-01T00:00:00Z', reason: '维护' }] }
          : { source: 'demo', items: [] };
      },
      async endSilence(scope, id) {
        calls.push({ scope, id });
      },
    };
    const controller = createAlertCenter({ root, api, scope: { tenantId: 'tenant-a', projectId: 'project-a' }, permissions: { manage: true }, onToast: (message) => toasts.push(message) });
    await controller.open('silences');
    root.endSilenceButton.click();
    await flushEvents();

    assert.deepEqual(calls.find((call) => typeof call === 'object'), { scope: { tenantId: 'tenant-a', projectId: 'project-a' }, id: 'silence-1' });
    assert.deepEqual(toasts, ['静默已结束并写入审计记录']);
    assert.equal(calls.filter((call) => call === 'list').length, 2);
    assert.match(root.innerHTML, /历史静默/);
  } finally {
    globalThis.window = previousWindow;
  }
});

test('scope switch clears a prior demo source when the next response has no source', async () => {
  const root = createAlertCenterRoot();
  const api = {
    async getOverview(scope) {
      return scope.tenantId === 'demo'
        ? { source: 'demo', events: { firing: 1 } }
        : { events: { firing: 0 } };
    },
  };
  const controller = createAlertCenter({ root, api, scope: { tenantId: 'demo', projectId: 'production' } });
  await controller.open('overview');
  assert.match(root.innerHTML, /演示数据/);
  await controller.setScope({ tenantId: 'tenant-b', projectId: 'project-b' });
  assert.match(root.innerHTML, /当前项目/);
  assert.doesNotMatch(root.innerHTML, /演示数据/);
});

test('failed refresh clears a prior response source badge', async () => {
  const root = createAlertCenterRoot();
  let attempts = 0;
  const api = {
    async getOverview() {
      attempts += 1;
      if (attempts === 1) return { source: 'demo', events: { firing: 1 } };
      throw { kind: 'unavailable' };
    },
  };
  const controller = createAlertCenter({ root, api, scope: { tenantId: 'demo', projectId: 'production' } });
  await controller.open('overview');
  await controller.open('overview');
  assert.match(root.innerHTML, /暂时无法加载监控概览/);
  assert.match(root.innerHTML, /当前项目/);
  assert.doesNotMatch(root.innerHTML, /演示数据/);
});

function createAlertCenterRoot() {
  const endSilenceButton = createEventButton();
  let markup = '';
  return {
    endSilenceButton,
    get innerHTML() { return markup; },
    set innerHTML(value) {
      markup = value;
      const id = String(value).match(/data-silence-end="([^"]+)"/)?.[1];
      endSilenceButton.dataset.silenceEnd = id ?? '';
    },
    querySelector(selector) {
      if (selector === '[data-alert-retry]') return null;
      return null;
    },
    querySelectorAll(selector) {
      if (selector === '[data-silence-end]' && endSilenceButton.dataset.silenceEnd) return [endSilenceButton];
      return [];
    },
    replaceChildren() { markup = ''; },
  };
}

function createEventButton() {
  const listeners = new Map();
  return {
    dataset: {},
    disabled: false,
    addEventListener(type, listener) { listeners.set(type, listener); },
    click() { listeners.get('click')?.({ currentTarget: this }); },
  };
}

async function flushEvents() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}
