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
  const [policy] = (await api.listNotificationPolicies({ tenantId: 'demo', projectId: 'production' })).items;
  assert.equal(detail.source, 'demo');
  assert.equal('secret_ref' in detail.deliveries[0], false);
  assert.equal('body' in detail.deliveries[0], false);
  assert.equal(policy.has_secret, true);
  assert.equal('secret_ref' in policy, false);
});

test('HTTP DTO normalization recursively removes secrets and raw delivery request bodies', async () => {
  const api = createAlertApi({
    baseUrl: 'https://control.example',
    fetchImpl: async () => new Response(JSON.stringify([{
      id: 'alert-1',
      token: 'top-level-token',
      private_key: 'private-key-material',
      connection_string: 'postgres://operator:password@db.example/alerts',
      dsn: 'postgres://operator:password@db.example/alerts',
      nested: { api_token: 'nested-token', safe: 'kept' },
      deliveries: [{
        id: 'delivery-1', status: 'delivered', token: 'delivery-token',
        request_body: 'raw request body', requestBody: 'raw camel request body', body: 'raw body',
        response_body: 'raw response body', safe: 'kept',
      }],
    }])),
  });

  const result = await api.listAlerts(scope, {}, null);

  assert.deepEqual(result.items, [{
    id: 'alert-1', nested: { safe: 'kept' },
    deliveries: [{ id: 'delivery-1', status: 'delivered', safe: 'kept' }],
  }]);
});

test('notification-policy normalization retains only a boolean secret configuration marker', async () => {
  const api = createAlertApi({
    baseUrl: 'https://control.example',
    fetchImpl: async () => new Response(JSON.stringify([{
      id: 'policy-1', name: '值班 Webhook', target: 'https://hooks.example/ops',
      has_secret: 'configured', secret_ref: 'env://DBPILOT_WEBHOOK_TOKEN',
    }])),
  });

  const [policy] = (await api.listNotificationPolicies(scope)).items;
  assert.deepEqual(policy, {
    id: 'policy-1', name: '值班 Webhook', target: 'https://hooks.example/ops', has_secret: true,
  });
  assert.equal('secret_ref' in policy, false);
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

test('saving listed configuration projects each resource to its accepted write DTO', async () => {
  const bodies = [];
  const listed = {
    '/rules': [{ id: 'rule-1', scope: { tenant_id: 'other', project_id: 'other' }, name: 'CPU', metric: 'host.cpu', aggregation: 'avg', operator: '>', threshold: 80, evaluation_every: '1m', lookback_window: '1m', for: '1m', missing_data: 'ignore', severity: 'critical', notification_policy_ids: ['policy-1'], labels: { database: 'orders' }, enabled: true, created_at: '2026-01-01T00:00:00Z' }],
    '/notification-policies': [{ id: 'policy-1', name: 'Inbox', channel: 'in_app', target: 'operator-1', template_id: 'template-1', severities: ['critical'], match_labels: { database: 'orders' }, window_start_utc: '09:00', window_end_utc: '17:00', enabled: true, has_secret: false, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z' }],
    '/templates': [{ id: 'template-1', name: 'Default', subject: 'Alert', body: '{{event.id}}', version: 4, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z' }],
    '/silences': [{ id: 'silence-1', matchers: { 'label.database': 'orders' }, starts_at: '2026-01-01T00:00:00Z', ends_at: '2026-01-01T01:00:00Z', created_by: 'operator-1', reason: 'maintenance', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z' }],
  };
  const api = createAlertApi({
    baseUrl: 'https://control.example',
    fetchImpl: async (url, init = {}) => {
      const path = new URL(url).pathname.replace('/api/v1/tenants/t1/projects/p1', '');
      if ((init.method ?? 'GET') === 'GET') return new Response(JSON.stringify(listed[path]));
      bodies.push([path, init.body]);
      return new Response(JSON.stringify({ id: path.split('/').at(-1) }));
    },
  });

  const [rule] = (await api.listRules(scope)).items;
  const [policy] = (await api.listNotificationPolicies(scope)).items;
  const [template] = (await api.listTemplates(scope)).items;
  const [silence] = (await api.listSilences(scope)).items;
  await api.saveRule(scope, rule);
  await api.saveNotificationPolicy(scope, policy);
  await api.saveTemplate(scope, template);
  await api.saveSilence(scope, silence);

  assert.deepEqual(bodies, [
    ['/rules/rule-1', '{"name":"CPU","metric":"host.cpu","aggregation":"avg","operator":">","threshold":80,"evaluation_every":"1m","lookback_window":"1m","for":"1m","missing_data":"ignore","severity":"critical","notification_policy_ids":["policy-1"],"labels":{"database":"orders"},"enabled":true}'],
    ['/notification-policies/policy-1', '{"name":"Inbox","channel":"in_app","target":"operator-1","template_id":"template-1","severities":["critical"],"match_labels":{"database":"orders"},"window_start_utc":"09:00","window_end_utc":"17:00","enabled":true}'],
    ['/templates/template-1', '{"name":"Default","subject":"Alert","body":"{{event.id}}"}'],
    ['/silences/silence-1', '{"matchers":{"label.database":"orders"},"starts_at":"2026-01-01T00:00:00Z","ends_at":"2026-01-01T01:00:00Z","reason":"maintenance"}'],
  ]);
});
