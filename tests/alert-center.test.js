import test from 'node:test';
import assert from 'node:assert/strict';
import { formatSeverity, safeText, validateReason, validateRule } from '../alert-center.js';

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
