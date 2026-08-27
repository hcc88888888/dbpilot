import test from 'node:test';
import assert from 'node:assert/strict';
import { createMonitoringApi } from '../modules/monitoring/monitoring-api.js';

const scope = { tenantId: 'tenant-a', projectId: 'project-a' };

test('monitoring HTTP paths are always scoped and query fields are allowlisted', async () => {
  const seen = [];
  const api = createMonitoringApi({
    baseUrl: 'https://control.example/',
    fetchImpl: async (url) => {
      seen.push(url);
      return new Response(JSON.stringify({ source: 'control-plane', items: [] }));
    },
  });

  await api.getOverview(
    { tenantId: 't/1', projectId: 'p 1' },
    { from: '2026-08-27T09:00:00Z', to: '2026-08-27T10:00:00Z', ignored: 'secret' },
  );

  assert.equal(seen[0], 'https://control.example/api/v1/tenants/t%2F1/projects/p%201/monitoring/overview?from=2026-08-27T09%3A00%3A00Z&to=2026-08-27T10%3A00%3A00Z');
});

test('all monitoring routes encode identifiers and retain the validated caller scope', async () => {
  const seen = [];
  const api = createMonitoringApi({
    baseUrl: 'https://control.example',
    fetchImpl: async (url) => {
      seen.push(url);
      const path = new URL(url).pathname;
      if (path.endsWith('/instances')) return new Response(JSON.stringify({ source: 'control-plane', scope: { tenant_id: 'wrong' }, items: [], next_offset: 20 }));
      if (path.includes('/instances/')) return new Response(JSON.stringify({ source: 'control-plane', instance: { id: 'db / 1' }, metrics: [] }));
      if (path.endsWith('/series')) return new Response(JSON.stringify({ source: 'control-plane', series: { name: 'host.cpu', buckets: [] } }));
      return new Response(JSON.stringify({ source: 'control-plane', items: [] }));
    },
  });

  const page = await api.listInstances(scope, { engine: 'mysql', status: 'stale', limit: 20, offset: 0, query: 'not-sent' });
  const detail = await api.getInstance(scope, 'db / 1', { from: '2026-08-27T09:00:00Z', to: '2026-08-27T10:00:00Z' });
  await api.getSeries(scope, { instanceId: 'db / 1', metric: 'host.cpu', from: '2026-08-27T09:00:00Z', to: '2026-08-27T10:00:00Z', step: '5m' });
  await api.getCapabilities(scope);

  assert.deepEqual(seen.map((value) => value.replace('https://control.example', '')), [
    '/api/v1/tenants/tenant-a/projects/project-a/monitoring/instances?engine=mysql&status=stale&limit=20&offset=0',
    '/api/v1/tenants/tenant-a/projects/project-a/monitoring/instances/db%20%2F%201?from=2026-08-27T09%3A00%3A00Z&to=2026-08-27T10%3A00%3A00Z',
    '/api/v1/tenants/tenant-a/projects/project-a/monitoring/series?instance_id=db%20%2F%201&metric=host.cpu&from=2026-08-27T09%3A00%3A00Z&to=2026-08-27T10%3A00%3A00Z&step=5m',
    '/api/v1/tenants/tenant-a/projects/project-a/monitoring/capabilities',
  ]);
  assert.deepEqual(page.scope, scope);
  assert.equal(page.nextOffset, 20);
  assert.deepEqual(detail.scope, scope);
});

test('HTTP DTO normalization strips secrets, raw payloads, connection strings, and server errors recursively', async () => {
  const api = createMonitoringApi({
    baseUrl: 'https://control.example',
    fetchImpl: async () => new Response(JSON.stringify({
      source: 'control-plane',
      instance: {
        id: 'db-1',
        raw_payload: 'unsafe',
        server_error: 'driver trace',
        labels: { zone: 'cn-a', password: 'unsafe', connection_string: 'postgres://unsafe' },
        latest: { 'host.cpu': null },
      },
      metrics: [{ name: 'host.cpu', buckets: [{ at: '2026-08-27T10:00:00Z', value: null, token: 'unsafe' }] }],
    })),
  });

  const result = await api.getInstance(scope, 'db-1');
  const encoded = JSON.stringify(result);
  assert.equal(encoded.includes('unsafe'), false);
  assert.equal(encoded.includes('driver trace'), false);
  assert.equal(result.instance.labels.zone, 'cn-a');
  assert.equal(result.instance.latest['host.cpu'], null);
  assert.equal(result.metrics[0].buckets[0].value, null);
});

test('HTTP failures expose fixed messages and never fall back to demo data', async () => {
  const api = createMonitoringApi({
    baseUrl: 'https://control.example',
    fetchImpl: async () => new Response(JSON.stringify({ error: { message: 'postgres password=unsafe' } }), { status: 403 }),
  });

  await assert.rejects(api.getOverview(scope), (error) => {
    assert.equal(error.kind, 'forbidden');
    assert.equal(error.message, '当前账号没有该项目的查看权限');
    assert.equal(error.message.includes('unsafe'), false);
    return true;
  });
});

test('demo responses are explicitly marked and include distinct stale, offline, and null data', async () => {
  const api = createMonitoringApi();
  const [overview, page, detail] = await Promise.all([
    api.getOverview(scope),
    api.listInstances(scope),
    api.getInstance(scope, 'mysql-demo-01'),
  ]);

  assert.equal(overview.source, 'demo');
  assert.deepEqual(overview.scope, scope);
  assert.equal(page.items.some((item) => item.status === 'stale'), true);
  assert.equal(page.items.some((item) => item.status === 'offline'), true);
  assert.equal(detail.metrics[0].buckets.some((bucket) => bucket.value === null), true);
});

test('unavailable production bootstrap does not issue a request or use demo data', async () => {
  let calls = 0;
  const api = createMonitoringApi({ baseUrl: 'https://control.example', available: false, fetchImpl: async () => { calls += 1; } });
  await assert.rejects(api.getCapabilities(scope), { kind: 'unavailable' });
  assert.equal(calls, 0);
});
