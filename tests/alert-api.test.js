import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createAlertApi } from '../alert-api.js';

const scope = { tenantId: 't1', projectId: 'p1' };

test('the HTML loads the adapter as a module before the dashboard script', async () => {
  const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  const adapter = html.indexOf('<script type="module" src="alert-api.js"></script>');
  const dashboard = html.indexOf('<script src="app.js"></script>');
  assert.ok(adapter >= 0);
  assert.ok(adapter < dashboard);
});

test('HTTP adapter escapes scope and never accepts a response scope override', async () => {
  const requested = [];
  const api = createAlertApi({
    baseUrl: 'https://control.example',
    fetchImpl: async (url) => {
      requested.push(url);
      return new Response(JSON.stringify({ scope: { tenant_id: 'other', project_id: 'other' }, items: [] }));
    },
  });
  const result = await api.listAlerts({ tenantId: 'east/ops', projectId: 'core db' }, {}, null);
  assert.equal(requested[0], 'https://control.example/api/v1/tenants/east%2Fops/projects/core%20db/alerts');
  assert.deepEqual(result.scope, { tenantId: 'east/ops', projectId: 'core db' });
});

test('demo adapter marks data as demo and removes unsafe delivery fields', async () => {
  const api = createAlertApi();
  const detail = await api.getAlert({ tenantId: 'demo', projectId: 'production' }, 'alert-1');
  assert.equal(detail.source, 'demo');
  assert.equal('secret_ref' in detail.deliveries[0], false);
  assert.equal('body' in detail.deliveries[0], false);
});

test('HTTP failure never falls back to demo data', async () => {
  const api = createAlertApi({
    baseUrl: 'https://control.example',
    fetchImpl: async () => new Response('{}', { status: 403 }),
  });
  await assert.rejects(
    () => api.listRules(scope),
    (error) => error.kind === 'forbidden' && error.message === '当前账号没有该项目的操作权限',
  );
});

test('HTTP failures expose fixed Chinese messages without server error details', async () => {
  for (const [status, kind, message] of [
    [401, 'unauthorized', '登录状态已失效，请重新登录'],
    [404, 'not-found', '请求的对象不存在或已无权访问'],
    [409, 'conflict', '对象已更新或存在引用冲突，请刷新后重试'],
    [413, 'validation', '请求参数或内容不符合要求，请修改后重试'],
    [503, 'unavailable', '服务暂时不可用，请稍后重试'],
  ]) {
    const api = createAlertApi({
      baseUrl: 'https://control.example',
      fetchImpl: async () => new Response(JSON.stringify({ message: 'untrusted internal error' }), { status }),
    });
    await assert.rejects(
      () => api.getAlert(scope, 'alert-1'),
      (error) => error.kind === kind && error.message === message && !error.message.includes('internal'),
    );
  }
});

test('alert list maps a cursor and state server-side, then filters normalized items locally', async () => {
  let requested;
  const api = createAlertApi({
    baseUrl: 'https://control.example',
    fetchImpl: async (url) => {
      requested = url;
      return new Response(JSON.stringify([
        { id: 'first', state: 'firing', severity: 'warning' },
        { id: 'second', state: 'firing', severity: 'critical' },
      ]));
    },
  });

  const result = await api.listAlerts(scope, { state: ['firing'], severity: 'critical', limit: 2 }, 'offset:4');

  assert.equal(requested, 'https://control.example/api/v1/tenants/t1/projects/p1/alerts?state=firing&limit=2&offset=4');
  assert.deepEqual(result.items.map((item) => item.id), ['second']);
  assert.equal(result.nextCursor, 'offset:6');
  assert.deepEqual(result.scope, scope);
});

test('mutation methods use scoped control-plane URLs and JSON request bodies', async () => {
  const requests = [];
  const api = createAlertApi({
    baseUrl: 'https://control.example/',
    fetchImpl: async (url, init) => {
      requests.push({ url, init });
      return new Response(JSON.stringify({ id: 'server-id', secret_ref: 'env://unsafe' }));
    },
  });

  await api.acknowledgeAlert(scope, 'alert / 1', { category: 'investigating', reason: 'checking' });
  await api.setRuleEnabled(scope, 'rule / 1', false);
  await api.saveNotificationPolicy(scope, { id: 'policy / 1', name: 'Webhook', secret_ref: 'env://token' });
  await api.endSilence(scope, 'silence / 1');

  assert.deepEqual(requests.map(({ url, init }) => [url, init.method, init.body]), [
    ['https://control.example/api/v1/tenants/t1/projects/p1/alerts/alert%20%2F%201/acknowledge', 'POST', '{"category":"investigating","reason":"checking"}'],
    ['https://control.example/api/v1/tenants/t1/projects/p1/rules/rule%20%2F%201/enable', 'POST', '{"enabled":false}'],
    ['https://control.example/api/v1/tenants/t1/projects/p1/notification-policies/policy%20%2F%201', 'PUT', '{"name":"Webhook","secret_ref":"env://token"}'],
    ['https://control.example/api/v1/tenants/t1/projects/p1/silences/silence%20%2F%201', 'DELETE', undefined],
  ]);
});

test('remaining configuration methods use only documented scoped routes', async () => {
  const requested = [];
  const api = createAlertApi({
    baseUrl: 'https://control.example',
    fetchImpl: async (url, init = {}) => {
      requested.push([url, init.method ?? 'GET']);
      return init.method === 'DELETE'
        ? new Response(null, { status: 204 })
        : new Response(JSON.stringify([]));
    },
  });

  await api.resolveAlert(scope, 'alert-1', { category: 'fixed', reason: 'resolved' });
  await api.saveRule(scope, { name: 'CPU' });
  await api.listNotificationPolicies(scope);
  await api.listTemplates(scope);
  await api.saveTemplate(scope, { id: 'template-1', name: 'Default' });
  await api.listSilences(scope);
  await api.saveSilence(scope, { matchers: {}, reason: 'maintenance' });

  assert.deepEqual(requested, [
    ['https://control.example/api/v1/tenants/t1/projects/p1/alerts/alert-1/resolve', 'POST'],
    ['https://control.example/api/v1/tenants/t1/projects/p1/rules', 'POST'],
    ['https://control.example/api/v1/tenants/t1/projects/p1/notification-policies', 'GET'],
    ['https://control.example/api/v1/tenants/t1/projects/p1/templates', 'GET'],
    ['https://control.example/api/v1/tenants/t1/projects/p1/templates/template-1', 'PUT'],
    ['https://control.example/api/v1/tenants/t1/projects/p1/silences', 'GET'],
    ['https://control.example/api/v1/tenants/t1/projects/p1/silences', 'POST'],
  ]);
});
