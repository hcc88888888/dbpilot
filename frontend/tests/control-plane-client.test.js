import test from 'node:test';
import assert from 'node:assert/strict';
import { ControlPlaneError, createControlPlaneClient } from '../shared/control-plane-client.js';

function capabilityResponse() {
  return new Response(JSON.stringify({ capabilities: [] }), {
    headers: { 'Content-Type': 'application/json' },
  });
}

function problemResponse({ status, code, detail = 'postgres password=unsafe' }) {
  return new Response(JSON.stringify({
    type: 'https://dbpilot.local/problems/request',
    title: 'Request failed',
    status,
    detail,
    code,
    request_id: 'req_01J8YZXB5PV7XJ3VP9AJ1FPQH3',
  }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  });
}

test('scope-bound platform URLs encode tenant and project identifiers', async () => {
  const requested = [];
  const client = createControlPlaneClient({
    baseUrl: 'https://control.example/',
    getAccessToken: () => 'token',
    requestIdFactory: () => 'req-scope',
    fetchImpl: async (url) => {
      requested.push(url);
      return capabilityResponse();
    },
  });

  await client.forScope({ tenantId: 'east / ops', projectId: 'core db' }).platform.getCapabilities();

  assert.deepEqual(requested, [
    'https://control.example/api/v1/tenants/east%20%2F%20ops/projects/core%20db/capabilities',
  ]);
});

test('each request reads a fresh bearer token and assigns a request id', async () => {
  const seen = [];
  let tokenReads = 0;
  let requestIds = 0;
  const scoped = createControlPlaneClient({
    baseUrl: 'https://control.example',
    getAccessToken: () => `token-${++tokenReads}`,
    requestIdFactory: () => `req-${++requestIds}`,
    fetchImpl: async (_url, init) => {
      seen.push(init.headers);
      return capabilityResponse();
    },
  }).forScope({ tenantId: 'tenant-a', projectId: 'project-a' });

  await scoped.platform.getCapabilities();
  await scoped.platform.getCapabilities();

  assert.equal(tokenReads, 2);
  assert.deepEqual(seen.map((headers) => ({
    authorization: headers.Authorization,
    requestId: headers['X-Request-ID'],
  })), [
    { authorization: 'Bearer token-1', requestId: 'req-1' },
    { authorization: 'Bearer token-2', requestId: 'req-2' },
  ]);
});

test('write request options propagate idempotency, entity tag, and abort signal', async () => {
  const seen = [];
  const controller = new AbortController();
  const scoped = createControlPlaneClient({
    baseUrl: 'https://control.example',
    getAccessToken: () => 'token',
    requestIdFactory: () => 'req-write',
    fetchImpl: async (url, init) => {
      seen.push({ url, init });
      return new Response(JSON.stringify({
        id: 'job-1',
        type: 'inspection.run',
        status: 'running',
        outcome: 'none',
        tenant_id: 'tenant-a',
        project_id: 'project-a',
        source_resource: { resource_type: 'inspection_run', resource_id: 'inspection-1' },
        version: 3,
        progress: { total_targets: 1, completed_targets: 0, failed_targets: 0, skipped_targets: 0 },
        artifacts: [],
        created_at: '2026-08-28T08:00:00Z',
        request_id: 'req-job',
        trace_id: 'trace-job',
      }), {
        status: 202,
        headers: { 'Content-Type': 'application/json' },
      });
    },
  }).forScope({ tenantId: 'tenant-a', projectId: 'project-a' });

  await scoped.platform.cancelJob(
    { jobId: 'job / 1' },
    scoped.requestOptions({ idempotencyKey: 'idem-1', etag: '"v3"', signal: controller.signal }),
  );

  assert.equal(seen[0].url, 'https://control.example/api/v1/tenants/tenant-a/projects/project-a/jobs/job%20%2F%201/actions/cancel');
  assert.equal(seen[0].init.headers['Idempotency-Key'], 'idem-1');
  assert.equal(seen[0].init.headers['If-Match'], '"v3"');
  assert.equal(seen[0].init.signal, controller.signal);
});

test('problem responses map a stable code to a safe control-plane error', async () => {
  const scoped = createControlPlaneClient({
    baseUrl: 'https://control.example',
    getAccessToken: () => 'token',
    requestIdFactory: () => 'req-problem',
    fetchImpl: async () => problemResponse({ status: 400, code: 'validation_failed' }),
  }).forScope({ tenantId: 'tenant-a', projectId: 'project-a' });

  await assert.rejects(scoped.platform.getCapabilities(), (error) => {
    assert.ok(error instanceof ControlPlaneError);
    assert.equal(error.code, 'validation_failed');
    assert.equal(error.kind, 'validation');
    assert.equal(error.requestId, 'req_01J8YZXB5PV7XJ3VP9AJ1FPQH3');
    assert.equal(error.message, '请求参数或内容不符合要求，请修改后重试');
    assert.equal(error.message.includes('unsafe'), false);
    return true;
  });
});

test('abort errors are preserved instead of being remapped', async () => {
  const aborted = new DOMException('cancelled by user', 'AbortError');
  const scoped = createControlPlaneClient({
    baseUrl: 'https://control.example',
    getAccessToken: () => 'token',
    requestIdFactory: () => 'req-abort',
    fetchImpl: async () => Promise.reject(aborted),
  }).forScope({ tenantId: 'tenant-a', projectId: 'project-a' });

  await assert.rejects(scoped.platform.getCapabilities(), (error) => error === aborted);
});

test('401 and 403 responses remain authorization failures and never return demo data', async () => {
  for (const [status, code, kind, message] of [
    [401, 'unauthorized', 'unauthorized', '登录状态已失效，请重新登录'],
    [403, 'forbidden', 'forbidden', '当前账号没有该项目的操作权限'],
  ]) {
    let requests = 0;
    const scoped = createControlPlaneClient({
      baseUrl: 'https://control.example',
      getAccessToken: () => 'token',
      requestIdFactory: () => 'req-auth',
      fetchImpl: async () => {
        requests += 1;
        return problemResponse({ status, code });
      },
    }).forScope({ tenantId: 'tenant-a', projectId: 'project-a' });

    await assert.rejects(scoped.platform.getCapabilities(), (error) => (
      error instanceof ControlPlaneError && error.kind === kind && error.message === message
    ));
    assert.equal(requests, 1);
  }
});
