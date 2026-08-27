import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildMonitoringQuery,
  createMonitoringCenter,
  formatMonitoringStatus,
  monitoringFailureMessage,
  monitoringSourceLabel,
  renderMonitoringOverview,
  safeMetricValue,
  validateRange,
} from '../monitoring-center.js';

test('range validation rejects invalid ordering, ranges over seven days, and unsafe steps', () => {
  assert.equal(validateRange('2026-08-27T10:00:00Z', '2026-08-27T09:00:00Z', '5m').kind, 'invalid-range');
  assert.equal(validateRange('2026-08-01T00:00:00Z', '2026-08-10T00:00:00Z', '5m').kind, 'range-too-large');
  assert.equal(validateRange('2026-08-27T09:00:00Z', '2026-08-27T10:00:00Z', '0s').kind, 'invalid-step');
  assert.equal(validateRange('2026-08-20T10:00:00Z', '2026-08-27T10:00:00Z', '1m').kind, 'too-many-buckets');
  assert.equal(validateRange('2026-08-27T09:00:00Z', '2026-08-27T10:00:00Z', '5m').kind, 'valid');
});

test('missing values and monitoring states remain visually distinct', () => {
  assert.equal(safeMetricValue(null), '—');
  assert.equal(safeMetricValue(undefined), '—');
  assert.equal(safeMetricValue(0), '0');
  assert.deepEqual(['healthy', 'stale', 'offline'].map(formatMonitoringStatus), ['健康', '数据陈旧', '离线']);
});

test('monitoring query builder emits normalized bounded values only', () => {
  assert.deepEqual(buildMonitoringQuery({
    from: '2026-08-27T09:00:00+00:00',
    to: '2026-08-27T10:00:00Z',
    step: '5m',
    engine: '',
    status: 'stale',
    limit: 50,
    offset: 0,
    secret: 'not-sent',
  }), {
    from: '2026-08-27T09:00:00.000Z',
    to: '2026-08-27T10:00:00.000Z',
    step: '5m',
    status: 'stale',
    limit: 50,
    offset: 0,
  });
});

test('overview markup labels demo source, stale/offline counts, and null trend gaps', () => {
  const markup = renderMonitoringOverview({
    source: 'demo',
    total_instances: 3,
    healthy: 1,
    stale: 1,
    offline: 1,
    trend: { name: 'host.cpu', buckets: [{ at: '2026-08-27T09:00:00Z', value: 0 }, { at: '2026-08-27T09:05:00Z', value: null }] },
    instances: [],
  }, { manage: false });

  assert.match(markup, /演示数据/);
  assert.match(markup, /数据陈旧/);
  assert.match(markup, /离线/);
  assert.match(markup, /data-gap="true"/);
  assert.doesNotMatch(markup, /自定义指标/);
});

test('manage permission only reveals custom metric entry and does not change authorization wording', () => {
  const markup = renderMonitoringOverview({ source: 'control-plane', instances: [], trend: { buckets: [] } }, { manage: true });
  assert.match(markup, /自定义指标/);
  assert.equal(monitoringFailureMessage({ kind: 'forbidden' }), '当前账号没有该项目的查看权限');
});

test('source and fixed failures have safe labels', () => {
  assert.equal(monitoringSourceLabel('demo'), '演示数据');
  assert.equal(monitoringSourceLabel('control-plane'), '控制面服务');
  assert.equal(monitoringFailureMessage({ kind: 'network', message: 'password=unsafe' }), '无法连接控制面服务，请检查网络后重试');
});

test('scope change aborts the previous load, clears selection, and reloads scoped data', async () => {
  const roots = [];
  const root = {
    innerHTML: '',
    addEventListener(type, handler) { roots.push([type, handler]); },
  };
  const calls = [];
  const pending = () => new Promise(() => {});
  const api = {
    getOverview(scope, query, signal) { calls.push(['overview', { ...scope }, query, signal]); return pending(); },
    listInstances(scope, query, signal) { calls.push(['instances', { ...scope }, query, signal]); return pending(); },
    getCapabilities() { return Promise.resolve({ source: 'control-plane', items: [] }); },
  };
  const center = createMonitoringCenter({ root, api, scope: { tenantId: 't1', projectId: 'p1' }, permissions: {} });
  center.open('overview');
  const firstSignal = calls[0][3];
  center.setScope({ tenantId: 't2', projectId: 'p2' });

  assert.equal(firstSignal.aborted, true);
  assert.equal(calls.some(([, scoped]) => scoped.tenantId === 't2' && scoped.projectId === 'p2'), true);
  assert.equal(center.getState().selectedInstanceId, null);
  assert.equal(roots.some(([type]) => type === 'click'), true);
});
