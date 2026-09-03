import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { DefaultApi, Job, ManagedDatabaseInstance, ManagedDatabaseInstancePage } from '../../../../generated/api/dist/index.js';
import { renderFeature } from '../../test/renderFeature';
import { InstanceDetailPage } from './InstanceDetailPage';
import { InstanceListPage } from './InstanceListPage';

const instance: ManagedDatabaseInstance = {
  instanceId: 'db-1', tenantId: 'tenant-a', projectId: 'project-a', hostId: 'host-1', agentId: 'agent-1', databaseFamily: 'mysql', databaseVariant: 'mysql',
  displayName: '订单数据库', endpoint: '10.0.0.8:3306', version: '8.4.2', credentialRef: 'secret://mysql/orders', tlsRef: 'secret://tls/orders',
  pluginId: 'mysql-observer', desiredPluginVersion: '1.0.0', labels: { env: 'prod' }, capabilities: new Set(['metrics', 'plugin_available']),
  connectionTestStatus: 'authentication_failed', connectionTestAt: new Date('2026-09-01T00:05:00Z'), pluginAssignmentRevision: 4,
  managementStatus: 'degraded', etag: '"db-4"',
};

function api(status = 200) {
  const job: Job = {
    id: 'job-1', type: 'database_connection_test', status: 'queued', outcome: 'none', tenantId: 'tenant-a', projectId: 'project-a', instanceId: 'db-1',
    sourceResource: { resourceType: 'database_instance', resourceId: 'db-1' }, version: 1,
    progress: { totalTargets: 1, completedTargets: 0, failedTargets: 0, skippedTargets: 0 }, artifacts: [],
    createdAt: new Date('2026-09-01T00:06:00Z'), requestId: 'req-1', traceId: 'trace-1',
  };
  const permissionError = Object.assign(new Error('forbidden'), { response: new Response(null, { status }) });
  return {
    listDatabaseInstances: vi.fn(async (): Promise<ManagedDatabaseInstancePage> => {
      if (status !== 200) throw permissionError;
      return { items: [instance], page: { limit: 20, hasMore: false } };
    }),
    getDatabaseInstance: vi.fn(async () => instance),
    testDatabaseInstanceConnection: vi.fn(async () => job),
    getJob: vi.fn(async () => ({ ...job, status: 'succeeded', outcome: 'complete', progress: { ...job.progress, completedTargets: 1 } })),
  } as unknown as DefaultApi;
}

describe('Database instance management pages', () => {
  it('fails closed before requesting instances when view permission is absent', async () => {
    const client = api();
    renderFeature(<InstanceListPage api={client} />, []);
    expect(await screen.findByText('没有查看数据库实例的权限。')).not.toBeNull();
    expect(client.listDatabaseInstances).not.toHaveBeenCalled();
  });

  it('shows management, plugin and connection status honestly', async () => {
    renderFeature(<InstanceListPage api={api()} />, ['database-instances:view']);
    expect(await screen.findByRole('link', { name: '订单数据库' })).not.toBeNull();
    expect(screen.getByText('degraded')).not.toBeNull();
    expect(screen.getByText('authentication_failed')).not.toBeNull();
    expect(screen.getByText('mysql-observer')).not.toBeNull();
  });

  it('starts a connection-test job with an idempotency key and reports real job progress', async () => {
    const client = api();
    renderFeature(<InstanceDetailPage instanceId="db-1" api={client} />, ['database-instances:view', 'database-instances:test', 'platform.jobs.read']);
    expect(await screen.findByRole('heading', { name: '订单数据库' })).not.toBeNull();
    expect(screen.getByText('secret://mysql/orders')).not.toBeNull();
    expect(screen.queryByLabelText(/密码|secret/i)).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '测试连接' }));
    await waitFor(() => expect(client.testDatabaseInstanceConnection).toHaveBeenCalledWith({ instanceId: 'db-1', idempotencyKey: expect.any(String) }, expect.objectContaining({ signal: expect.any(AbortSignal) })));
    expect(await screen.findByText('succeeded')).not.toBeNull();
    expect(screen.getByText('1 / 1')).not.toBeNull();
    expect(client.getJob).toHaveBeenCalledWith({ jobId: 'job-1' }, expect.anything());
  });

  it('keeps the initial job status without polling when jobs view permission is absent', async () => {
    const client = api();
    renderFeature(<InstanceDetailPage instanceId="db-1" api={client} />, ['database-instances:view', 'database-instances:test']);
    await userEvent.click(await screen.findByRole('button', { name: '测试连接' }));

    expect(await screen.findByText('queued')).not.toBeNull();
    expect(screen.getByText('没有查看任务进度的权限，仅显示任务创建时状态。')).not.toBeNull();
    expect(client.getJob).not.toHaveBeenCalled();
  });

  it('disables connection testing when the plugin capability is unavailable', async () => {
    const client = api();
    client.getDatabaseInstance = vi.fn(async () => ({ ...instance, capabilities: new Set(['plugin_unavailable']) }));
    renderFeature(<InstanceDetailPage instanceId="db-1" api={client} />, ['database-instances:view', 'database-instances:test']);

    expect((await screen.findByRole('button', { name: '测试连接' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('当前插件不可用于连接测试。')).not.toBeNull();
  });

  it('keeps the connection-test button disabled while a test is pending', async () => {
    const client = api();
    client.getDatabaseInstance = vi.fn(async () => ({ ...instance, connectionTestStatus: 'pending' as const }));
    renderFeature(<InstanceDetailPage instanceId="db-1" api={client} />, ['database-instances:view', 'database-instances:test']);

    expect((await screen.findByRole('button', { name: '测试进行中…' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it.each([
    ['403', Object.assign(new Error('forbidden'), { response: new Response(null, { status: 403 }) }), '没有执行此操作的权限'],
    ['network', new TypeError('network down'), '请求失败，请稍后重试'],
  ])('stops and reports %s job polling failures without demo fallback', async (_kind, pollingError, expectedMessage) => {
    const client = api();
    client.getJob = vi.fn(async () => { throw pollingError; });
    renderFeature(<InstanceDetailPage instanceId="db-1" api={client} />, ['database-instances:view', 'database-instances:test', 'platform.jobs.read']);
    await userEvent.click(await screen.findByRole('button', { name: '测试连接' }));

    expect((await screen.findByRole('alert', undefined, { timeout: 2_500 })).textContent).toContain(expectedMessage);
    const calls = vi.mocked(client.getJob).mock.calls.length;
    if (_kind === '403') expect(calls).toBe(1);
    else expect(calls).toBe(2);
    await new Promise((resolve) => setTimeout(resolve, 2_100));
    expect(client.getJob).toHaveBeenCalledTimes(calls);
    expect(document.body.textContent).not.toMatch(/demo/i);
  });

  it('loads the next instance cursor instead of silently truncating inventory', async () => {
    const client = api();
    client.listDatabaseInstances = vi.fn(async (request) => request.cursor
      ? { items: [{ ...instance, instanceId: 'db-2', displayName: '订单数据库 02' }], page: { limit: 1, hasMore: false } }
      : { items: [instance], page: { limit: 1, hasMore: true, nextCursor: 'instance-cursor-2' } });
    renderFeature(<InstanceListPage api={client} />, ['database-instances:view']);

    await userEvent.click(await screen.findByRole('button', { name: '加载更多实例' }));
    expect(await screen.findByRole('link', { name: '订单数据库 02' })).not.toBeNull();
    expect(client.listDatabaseInstances).toHaveBeenLastCalledWith(expect.objectContaining({ cursor: 'instance-cursor-2' }), expect.anything());
  });

  it('shows 403 as a permission error with no demo fallback', async () => {
    const client = api(403);
    renderFeature(<InstanceListPage api={client} />, ['database-instances:view']);
    expect((await screen.findByRole('alert')).textContent).toContain('没有执行此操作的权限');
    expect(client.listDatabaseInstances).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).not.toMatch(/demo/i);
  });
});
