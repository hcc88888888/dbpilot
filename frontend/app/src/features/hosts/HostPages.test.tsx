import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { DefaultApi, ManagedDatabaseInstancePage, ManagedHost, ManagedHostPage } from '../../../../generated/api/dist/index.js';
import { renderFeature } from '../../test/renderFeature';
import { HostDetailPage } from './HostDetailPage';
import { HostListPage } from './HostListPage';

const host: ManagedHost = {
  hostId: 'host-1', agentId: 'agent-1', tenantId: 'tenant-a', projectId: 'project-a',
  displayName: '支付主机 01', hostname: 'pay-db-01', operatingSystem: 'Kylin', operatingSystemVersion: 'V10',
  architecture: 'amd64', cpuSummary: { capacity: 16, available: 4 }, memorySummary: { capacity: 64, available: 12 },
  filesystemSummary: [], networkAddresses: new Set(['10.0.0.8']), labels: { zone: 'A' }, containerRuntime: 'docker',
  capabilities: [{ name: 'native_discovery', available: true }, { name: 'docker_discovery', available: false, reason: 'docker_discovery_unavailable' }],
  enrollmentRevision: 4, enrolledAt: new Date('2026-09-01T00:00:00Z'), lastHeartbeatAt: new Date('2026-09-01T00:05:00Z'),
  status: 'stale', etag: '"host-4"',
};

function api(): DefaultApi {
  return {
    listHosts: vi.fn(async (): Promise<ManagedHostPage> => ({ items: [host], page: { limit: 20, hasMore: false } })),
    getHost: vi.fn(async () => host),
    listDatabaseInstances: vi.fn(async (): Promise<ManagedDatabaseInstancePage> => ({
      items: [{ instanceId: 'db-1', tenantId: 'tenant-a', projectId: 'project-a', hostId: 'host-1', agentId: 'agent-1', databaseFamily: 'mysql', databaseVariant: 'mysql', displayName: '订单库', endpoint: '127.0.0.1:3306', credentialRef: 'vault://mysql/orders', labels: {}, capabilities: new Set(), connectionTestStatus: 'succeeded', pluginAssignmentRevision: 3, managementStatus: 'monitoring', etag: '"db-3"', pluginId: 'mysql-observer' }],
      page: { limit: 20, hasMore: false },
    })),
  } as unknown as DefaultApi;
}

describe('Host management pages', () => {
  it('fails closed before requesting host data when view permission is absent', async () => {
    const client = api();
    renderFeature(<HostListPage api={client} />, []);

    expect(await screen.findByText('没有查看主机的权限。')).not.toBeNull();
    expect(client.listHosts).not.toHaveBeenCalled();
  });

  it('passes TanStack cancellation through to the generated request', async () => {
    let requestSignal: AbortSignal | undefined;
    const client = {
      listHosts: vi.fn((_request, init) => new Promise<ManagedHostPage>((_resolve, reject) => {
        requestSignal = (init as RequestInit).signal ?? undefined;
        requestSignal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
      })),
    } as unknown as DefaultApi;
    const rendered = renderFeature(<HostListPage api={client} />, ['hosts:view']);
    await waitFor(() => expect(requestSignal).toBeDefined());
    await rendered.queryClient.cancelQueries({ queryKey: ['hosts'] });
    expect(requestSignal?.aborted).toBe(true);
  });

  it('shows scoped host status and resource truth without presenting stale data as current', async () => {
    renderFeature(<HostListPage api={api()} />, ['hosts:view']);

    expect(await screen.findByRole('link', { name: '支付主机 01' })).not.toBeNull();
    expect(screen.getByText('数据可能已过期')).not.toBeNull();
    expect(screen.getByText('CPU 可用 4 / 16')).not.toBeNull();
    expect(screen.getByText('内存可用 12 / 64')).not.toBeNull();
  });

  it('shows host capability evidence and an instance/plugin summary on detail', async () => {
    renderFeature(<HostDetailPage hostId="host-1" api={api()} />, ['hosts:view', 'database-instances:view']);

    expect(await screen.findByRole('heading', { name: '支付主机 01' })).not.toBeNull();
    expect(screen.getByText('Kylin V10')).not.toBeNull();
    expect(screen.getByText('Docker 发现不可用')).not.toBeNull();
    expect(await screen.findByText('mysql-observer')).not.toBeNull();
    expect(screen.getByText('订单库')).not.toBeNull();
  });
});
