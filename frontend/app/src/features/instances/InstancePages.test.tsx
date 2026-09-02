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
  displayName: '订单数据库', endpoint: '10.0.0.8:3306', version: '8.4.2', credentialRef: 'vault://mysql/orders', tlsRef: 'vault://tls/orders',
  pluginId: 'mysql-observer', desiredPluginVersion: '1.0.0', labels: { env: 'prod' }, capabilities: new Set(['metrics']),
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
    renderFeature(<InstanceDetailPage instanceId="db-1" api={client} />, ['database-instances:view', 'database-instances:test']);
    expect(await screen.findByRole('heading', { name: '订单数据库' })).not.toBeNull();
    expect(screen.getByText('vault://mysql/orders')).not.toBeNull();
    expect(screen.queryByLabelText(/密码|secret/i)).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '测试连接' }));
    await waitFor(() => expect(client.testDatabaseInstanceConnection).toHaveBeenCalledWith({ instanceId: 'db-1', idempotencyKey: expect.any(String) }));
    expect(await screen.findByText('queued')).not.toBeNull();
    expect(screen.getByText('0 / 1')).not.toBeNull();
  });

  it('shows 403 as a permission error with no demo fallback', async () => {
    renderFeature(<InstanceListPage api={api(403)} />, ['database-instances:view']);
    expect((await screen.findByRole('alert')).textContent).toContain('没有执行此操作的权限');
    expect(document.body.textContent).not.toMatch(/demo/i);
  });
});
