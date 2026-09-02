import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { renderFeature } from '../../test/renderFeature';
import { MonitoringPage, requestMonitoringOverview, type MonitoringOverview } from './MonitoringPage';

const overview: MonitoringOverview = {
  source: 'control-plane',
  scope: { tenant_id: 'tenant-a', project_id: 'project-a' },
  from: '2026-09-02T09:00:00Z',
  to: '2026-09-02T10:00:00Z',
  total_instances: 2,
  healthy: 0,
  stale: 2,
  offline: 0,
  metrics: [
    series('system.cpu.utilization', 'host', 'agent-core', 'host-1', 42),
    series('system.memory.utilization', 'host', 'agent-core', 'host-1', 61),
    series('dbpilot.plugin.collection.status', 'plugin', 'mysql', 'assignment-1', 1),
    series('mysql.connections.current', 'database', 'mysql', 'mysql-1', 12),
    series('mysql.queries.total', 'database', 'mysql', 'mysql-1', 540),
    series('mysql.threads.running', 'database', 'mysql', 'mysql-1', 3),
    series('mysql.up', 'database', 'mysql', 'mysql-1', 1),
    series('mysql.uptime.seconds', 'database', 'mysql', 'mysql-1', 7200),
  ],
};

function series(name: string, scope: 'host' | 'plugin' | 'database', source: string, resourceId: string, value: number) {
  return {
    name, scope, source, status: 'stale' as const,
    unit: name === 'system.cpu.utilization' || name === 'system.memory.utilization' ? '%' : name === 'mysql.uptime.seconds' ? 's' : name === 'mysql.queries.total' ? '{query}' : '1',
    host_id: scope === 'host' ? resourceId : 'host-1',
    plugin_assignment_id: scope === 'plugin' ? resourceId : undefined,
    instance_id: scope === 'database' ? resourceId : undefined,
    from: '2026-09-02T09:00:00Z', to: '2026-09-02T10:00:00Z', step: 300_000_000_000,
    buckets: [{ at: '2026-09-02T09:45:00Z', value }, { at: '2026-09-02T10:00:00Z', value: null }],
  };
}

describe('MonitoringPage', () => {
  it('shows host CPU/memory and all five MySQL series with explicit source and stale status', async () => {
    const fetchApi = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(new Headers(init?.headers).get('Authorization')).toBe('Bearer test-token');
      return new Response(JSON.stringify(overview), { status: 200, headers: { 'Content-Type': 'application/json' } });
    });
    localStorage.setItem('unrelated', 'kept');
    renderFeature(<MonitoringPage fetchApi={fetchApi} now={() => new Date('2026-09-02T10:00:00Z')} />, []);

    expect(await screen.findByRole('heading', { name: '基础监控' })).not.toBeNull();
    expect(await screen.findByText('CPU 42%')).not.toBeNull();
    expect(screen.getByText('内存 61%')).not.toBeNull();
    for (const name of ['mysql.connections.current', 'mysql.queries.total', 'mysql.threads.running', 'mysql.up', 'mysql.uptime.seconds']) {
      expect(screen.getByText(name)).not.toBeNull();
    }
    expect(screen.getAllByText('数据陈旧').length).toBeGreaterThanOrEqual(7);
    expect(screen.getAllByText('mysql').length).toBeGreaterThanOrEqual(5);
    expect(document.body.textContent).not.toContain('test-token');
    expect(localStorage.getItem('unrelated')).toBe('kept');
    expect(sessionStorage.length).toBe(0);
  });

  it('reads the in-memory access token for every request and never falls back after HTTP failure', async () => {
    let token = 'first-token';
    const getAccessToken = vi.fn(async () => token);
    const fetchApi = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const authorization = new Headers(init?.headers).get('Authorization');
      if (authorization === 'Bearer first-token') return new Response(JSON.stringify(overview), { status: 200 });
      return new Response(JSON.stringify({ title: 'Forbidden' }), { status: 403 });
    });

    await expect(requestMonitoringOverview({ tenantId: 'tenant-a', projectId: 'project-a' }, getAccessToken, fetchApi, new Date('2026-09-02T10:00:00Z'))).resolves.toEqual(overview);
    token = 'second-token';
    await expect(requestMonitoringOverview({ tenantId: 'tenant-a', projectId: 'project-a' }, getAccessToken, fetchApi, new Date('2026-09-02T10:00:00Z'))).rejects.toMatchObject({ status: 403 });
    expect(getAccessToken).toHaveBeenCalledTimes(2);
    await waitFor(() => expect(fetchApi).toHaveBeenCalledTimes(2));
  });
});
