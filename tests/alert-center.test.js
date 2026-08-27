import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAlertFilters,
  formatSeverity,
  safeText,
  validateDisposition,
  validatePolicy,
  validateReason,
  validateRule,
  validateSilence,
  validateTemplate,
  isActiveSilence,
  renderTemplatePreview,
  sanitizePolicyForDisplay,
} from '../alert-center.js';

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

test('policy validation requires a name, supported channel, target, and template', () => {
  assert.deepEqual(validatePolicy({ name: '', channel: 'pager', target: '', templateId: '' }), {
    name: '请填写策略名称',
    channel: '请选择通知渠道',
    target: '请填写渠道目标',
    templateId: '请选择通知模板',
  });
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

test('active silence ends strictly before its end timestamp', () => {
  assert.equal(isActiveSilence({ startsAt: '2026-08-27T09:00:00Z', endsAt: '2026-08-27T10:00:00Z' }, new Date('2026-08-27T09:30:00Z')), true);
  assert.equal(isActiveSilence({ startsAt: '2026-08-27T09:00:00Z', endsAt: '2026-08-27T10:00:00Z' }, new Date('2026-08-27T10:00:00Z')), false);
});
