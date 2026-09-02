import React from 'react';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type {
  DefaultApi,
  Job,
  PluginAssignment,
  PluginDefinition,
  PluginVersion,
} from '../../../../generated/api/dist/index.js';
import { renderFeature } from '../../test/renderFeature';
import { AssignmentPage } from './AssignmentPage';
import { PluginCatalogPage } from './PluginCatalogPage';
import { pluginKeys } from './queries';

const definition: PluginDefinition = {
  pluginId: 'mysql-observer', name: 'MySQL Observer', databaseFamily: 'mysql', protocolVersion: 'v1',
  supportedVariants: new Set(['mysql', 'mariadb']), capabilities: new Set(['metrics.collect']), latestAvailableVersion: '1.1.0',
};

const version: PluginVersion = {
  versionId: 'version-110', pluginId: 'mysql-observer', version: '1.1.0', status: 'available', artifactId: 'artifact-110',
  packageSha256: 'a'.repeat(64), manifestDigest: 'b'.repeat(64), publisherId: 'publisher-a', signingKeyId: 'signing-key-a',
  supportedVariants: new Set(['mysql']), databaseVersionRange: '>=8.0', capabilities: new Set(['metrics.collect']), metricTemplateSchemaVersion: 1,
  platforms: [{ operatingSystem: 'linux', architecture: 'amd64', sha256: 'c'.repeat(64), sizeBytes: 1024 }],
  createdAt: new Date('2026-09-01T00:00:00Z'), approvedAt: new Date('2026-09-01T01:00:00Z'), etag: '"version-7"',
};

const assignment: PluginAssignment = {
  assignmentId: 'assignment-1', hostId: 'host-1', agentId: 'agent-1', pluginId: 'mysql-observer', databaseFamily: 'mysql',
  desiredVersion: '1.1.0', desiredState: 'running', configurationRevision: 8, operationRevision: 12, rolloutPercentage: 100,
  reconcileState: 'state_conflict', reconcileReason: 'observed version is behind desired version',
  observedState: {
    assignmentId: 'assignment-1', installedVersion: '1.0.0', activeSlot: 'a', processState: 'running', health: 'degraded', circuitState: 'open',
    restartCount: 3, boundInstanceCount: 4, activeConfigurationRevision: 7, observedOperationRevision: 11, observedAt: new Date('2026-09-01T02:00:00Z'),
  },
  createdAt: new Date('2026-09-01T00:00:00Z'), updatedAt: new Date('2026-09-01T02:00:00Z'), etag: '"assignment-12"',
};
const convergedAssignment: PluginAssignment = {
  ...assignment, reconcileState: 'converged', reconcileReason: undefined,
  observedState: { ...assignment.observedState!, installedVersion: '1.1.0', circuitState: 'closed', health: 'healthy' },
};
const stoppedAssignment: PluginAssignment = {
  ...assignment, desiredState: 'stopped', reconcileState: 'converged', reconcileReason: undefined,
  observedState: { ...assignment.observedState!, installedVersion: '1.1.0', processState: 'stopped', circuitState: 'closed', health: 'healthy' },
};
const absentAssignment: PluginAssignment = {
  ...assignment, desiredState: 'absent', reconcileState: 'converged', reconcileReason: undefined,
  observedState: { ...assignment.observedState!, installedVersion: undefined, processState: 'absent', circuitState: 'closed', health: 'unknown' },
};
const startingWithoutVersionAssignment: PluginAssignment = {
  ...assignment, reconcileState: 'pending', reconcileReason: undefined,
  observedState: { ...assignment.observedState!, installedVersion: undefined, processState: 'starting', circuitState: 'closed', health: 'unknown' },
};

const job: Job = {
  id: 'job-1', type: 'plugin.reconcile', status: 'queued', outcome: 'none', tenantId: 'tenant-a', projectId: 'project-a',
  sourceResource: { resourceType: 'plugin_assignment', resourceId: 'assignment-1' }, version: 1,
  progress: { totalTargets: 1, completedTargets: 0, failedTargets: 0, skippedTargets: 0 }, artifacts: [],
  createdAt: new Date('2026-09-01T03:00:00Z'), requestId: 'request-1', traceId: 'trace-1',
};

function pluginApi() {
  return {
    listPluginDefinitions: vi.fn(async () => ({ items: [definition], page: { limit: 100, hasMore: false } })),
    listPluginVersions: vi.fn(async () => ({ items: [version], page: { limit: 100, hasMore: false } })),
    uploadPluginVersionPackage: vi.fn(async () => version),
    listPluginAssignments: vi.fn(async () => ({ items: [assignment], page: { limit: 100, hasMore: false } })),
    updatePluginAssignment: vi.fn(async ({ updatePluginAssignmentRequest }) => ({ ...assignment, ...updatePluginAssignmentRequest, etag: '"assignment-13"' })),
    reconcilePluginAssignment: vi.fn(async () => job),
    getJob: vi.fn(async () => ({ ...job, status: 'succeeded', outcome: 'complete', progress: { ...job.progress, completedTargets: 1 } })),
  } as unknown as DefaultApi;
}

describe('Plugin management pages', () => {
  it('fails closed without issuing catalog or assignment requests', async () => {
    const client = pluginApi();
    renderFeature(<><PluginCatalogPage api={client} /><AssignmentPage api={client} /></>, []);

    expect(await screen.findByText('没有查看插件目录的权限。')).not.toBeNull();
    expect(screen.getByText('没有查看插件分配的权限。')).not.toBeNull();
    expect(client.listPluginDefinitions).not.toHaveBeenCalled();
    expect(client.listPluginAssignments).not.toHaveBeenCalled();
  });

  it('shows version status, signature and platform details in the version drawer', async () => {
    const client = pluginApi();
    renderFeature(<PluginCatalogPage api={client} />, ['plugins:view']);

    await userEvent.click(await screen.findByRole('button', { name: '查看 1.1.0' }));
    const drawer = screen.getByRole('dialog', { name: 'MySQL Observer 1.1.0' });
    expect(within(drawer).getByText('available')).not.toBeNull();
    expect(within(drawer).getByText('signing-key-a')).not.toBeNull();
    expect(within(drawer).getByText('publisher-a')).not.toBeNull();
    expect(within(drawer).getByText('linux / amd64')).not.toBeNull();
  });

  it('loads opaque catalog cursors', async () => {
    const client = pluginApi();
    client.listPluginDefinitions = vi.fn(async (request) => request.cursor
      ? { items: [{ ...definition, pluginId: 'postgres-observer', name: 'Postgres Observer' }], page: { limit: 1, hasMore: false } }
      : { items: [definition], page: { limit: 1, hasMore: true, nextCursor: 'opaque-plugin-cursor' } });
    renderFeature(<PluginCatalogPage api={client} />, ['plugins:view']);

    await userEvent.click(await screen.findByRole('button', { name: '加载更多插件' }));
    expect(await screen.findByText('Postgres Observer')).not.toBeNull();
    expect(client.listPluginDefinitions).toHaveBeenLastCalledWith(expect.objectContaining({ cursor: 'opaque-plugin-cursor' }), expect.anything());
  });

  it('scopes versions and definitions to the route plugin', async () => {
    const client = pluginApi();
    client.listPluginDefinitions = vi.fn(async () => ({ items: [definition, { ...definition, pluginId: 'postgres-observer', name: 'Postgres Observer' }], page: { limit: 100, hasMore: false } }));
    renderFeature(<PluginCatalogPage api={client} pluginId="mysql-observer" />, ['plugins:view']);

    expect(await screen.findByRole('link', { name: 'MySQL Observer' })).not.toBeNull();
    expect(screen.queryByText('Postgres Observer')).toBeNull();
    expect(client.listPluginVersions).toHaveBeenCalledWith(expect.objectContaining({ pluginId: 'mysql-observer' }), expect.anything());
  });

  it('uploads a bounded package with progress without rendering or logging file contents', async () => {
    const client = pluginApi();
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    renderFeature(<PluginCatalogPage api={client} />, ['plugins:view', 'plugins:publish']);
    const file = new File(['PRIVATE_PLUGIN_BYTES'], 'mysql-plugin.tar.gz', { type: 'application/gzip' });

    await userEvent.upload(await screen.findByLabelText('插件包'), file);
    await userEvent.click(screen.getByRole('button', { name: '上传插件包' }));

    await waitFor(() => expect(client.uploadPluginVersionPackage).toHaveBeenCalledWith(expect.objectContaining({
      body: file, contentLength: file.size, idempotencyKey: expect.any(String),
    }), expect.objectContaining({ signal: expect.any(AbortSignal) })));
    expect(screen.getByRole('progressbar').getAttribute('aria-valuenow')).toBe('100');
    expect(document.body.textContent).not.toContain('PRIVATE_PLUGIN_BYTES');
    expect(consoleSpy).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('does not invalidate unrelated assignment cache after a catalog upload', async () => {
    const client = pluginApi();
    const rendered = renderFeature(<PluginCatalogPage api={client} />, ['plugins:view', 'plugins:publish']);
    const assignmentKey = pluginKeys.assignments({ tenantId: 'tenant-a', projectId: 'project-a' }, {});
    rendered.queryClient.setQueryData(assignmentKey, { marker: 'keep' });
    const file = new File(['package'], 'mysql-plugin.tar.gz', { type: 'application/gzip' });

    await userEvent.upload(await screen.findByLabelText('插件包'), file);
    await userEvent.click(screen.getByRole('button', { name: '上传插件包' }));
    await screen.findByText('上传完成，服务端已返回版本元数据。');

    expect(rendered.queryClient.getQueryState(assignmentKey)?.isInvalidated).toBe(false);
  });

  it('separates desired and observed state and shows drift, circuit state and multi-instance count', async () => {
    renderFeature(<AssignmentPage api={pluginApi()} />, ['plugins:view']);

    expect(await screen.findByText('state_conflict')).not.toBeNull();
    expect(screen.getByText('running / 1.1.0')).not.toBeNull();
    expect(screen.getByText('running / 1.0.0')).not.toBeNull();
    expect(screen.getByText((_content, element) => element?.tagName === 'TD' && element.textContent === 'open4 个实例')).not.toBeNull();
  });

  it.each([
    ['converged running', convergedAssignment, ['停止', '升级'], ['部署', '回滚']],
    ['stopped', stoppedAssignment, ['部署'], ['停止', '升级', '回滚']],
    ['absent', absentAssignment, ['部署'], ['停止', '升级', '回滚']],
    ['starting without an installed version', startingWithoutVersionAssignment, ['停止'], ['部署', '升级', '回滚']],
    ['version drift', assignment, ['停止', '升级', '回滚'], ['部署']],
  ] as const)('shows only valid assignment actions for %s state', async (_label, value, visible, hidden) => {
    const client = pluginApi();
    client.listPluginAssignments = vi.fn(async () => ({ items: [value], page: { limit: 100, hasMore: false } }));
    renderFeature(<AssignmentPage api={client} />, ['plugins:view', 'plugins:manage', 'plugins:deploy']);

    await screen.findByText(value.assignmentId);
    for (const action of visible) expect(screen.getByRole('button', { name: `${action} ${value.assignmentId}` })).not.toBeNull();
    for (const action of hidden) expect(screen.queryByRole('button', { name: `${action} ${value.assignmentId}` })).toBeNull();
  });

  it.each([
    ['部署', stoppedAssignment, { desiredState: 'running' }],
    ['停止', assignment, { desiredState: 'stopped' }],
    ['升级', assignment, { desiredVersion: '1.2.0', desiredState: 'running' }],
    ['回滚', assignment, { desiredVersion: '1.0.0', desiredState: 'running' }],
  ] as const)('confirms %s and starts a real reconciliation job', async (action, sourceAssignment, expectedPatch) => {
    const client = pluginApi();
    client.listPluginAssignments = vi.fn(async () => ({ items: [sourceAssignment], page: { limit: 100, hasMore: false } }));
    renderFeature(<AssignmentPage api={client} />, ['plugins:view', 'plugins:manage', 'plugins:deploy', 'platform.jobs.read']);

    await userEvent.click(await screen.findByRole('button', { name: `${action} assignment-1` }));
    if (action === '升级') await userEvent.clear(screen.getByLabelText('目标版本'));
    if (action === '升级') await userEvent.type(screen.getByLabelText('目标版本'), '1.2.0');
    await userEvent.click(screen.getByRole('button', { name: `确认${action}` }));

    await waitFor(() => expect(client.updatePluginAssignment).toHaveBeenCalledWith(expect.objectContaining({
      assignmentId: 'assignment-1', ifMatch: '"assignment-12"', idempotencyKey: expect.any(String),
      updatePluginAssignmentRequest: expect.objectContaining(expectedPatch),
    }), expect.objectContaining({ signal: expect.any(AbortSignal) })));
    expect(client.reconcilePluginAssignment).toHaveBeenCalledWith(expect.objectContaining({ assignmentId: 'assignment-1', idempotencyKey: expect.any(String) }), expect.anything());
    expect(await screen.findByText('succeeded')).not.toBeNull();
    expect(screen.getByText('1 / 1')).not.toBeNull();
  });

  it('does not allow an upgrade with an empty target version', async () => {
    const client = pluginApi();
    renderFeature(<AssignmentPage api={client} />, ['plugins:view', 'plugins:manage', 'plugins:deploy']);

    await userEvent.click(await screen.findByRole('button', { name: '升级 assignment-1' }));
    await userEvent.clear(screen.getByLabelText('目标版本'));

    expect(screen.getByRole('button', { name: '确认升级' }).hasAttribute('disabled')).toBe(true);
    expect(client.updatePluginAssignment).not.toHaveBeenCalled();
  });

  it('refreshes assignments after desired state changed even when reconciliation fails', async () => {
    const client = pluginApi();
    client.reconcilePluginAssignment = vi.fn(async () => { throw Object.assign(new Error('conflict'), { response: new Response(null, { status: 409 }) }); });
    renderFeature(<AssignmentPage api={client} />, ['plugins:view', 'plugins:manage', 'plugins:deploy']);

    await userEvent.click(await screen.findByRole('button', { name: '停止 assignment-1' }));
    await userEvent.click(screen.getByRole('button', { name: '确认停止' }));

    expect(await screen.findByRole('alert')).not.toBeNull();
    await waitFor(() => expect(client.listPluginAssignments).toHaveBeenCalledTimes(2));
  });

  it('keeps plugin query keys isolated by tenant and project', () => {
    expect(pluginKeys.assignments({ tenantId: 'tenant-a', projectId: 'project-a' }, { pluginId: 'mysql' })).toEqual([
      'plugins', 'tenant-a', 'project-a', 'assignments', { pluginId: 'mysql' },
    ]);
    expect(pluginKeys.assignments({ tenantId: 'tenant-a', projectId: 'project-b' }, { pluginId: 'mysql' })).not.toEqual(
      pluginKeys.assignments({ tenantId: 'tenant-a', projectId: 'project-a' }, { pluginId: 'mysql' }),
    );
  });
});
