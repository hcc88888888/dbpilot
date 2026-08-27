import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAlertFilters,
  formatSeverity,
  safeText,
  validateDisposition,
  validateReason,
  validateRule,
} from '../alert-center.js';

test('safeText prevents markup from becoming alert-detail HTML', () => {
  assert.equal(safeText('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
});

test('rule validation requires metric, positive threshold, duration, period, and policy references', () => {
  assert.deepEqual(validateRule({ metric: '', threshold: 0, for: 'soon', evaluationEvery: '', notificationPolicyIds: [] }), {
    metric: '请选择指标', threshold: '阈值必须大于 0', for: '持续时长格式应为 5m 或 1h', evaluationEvery: '请选择评估周期', notificationPolicyIds: '至少选择一个通知策略',
  });
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
