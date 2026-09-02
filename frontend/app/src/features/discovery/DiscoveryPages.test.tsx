import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { DefaultApi, DiscoveryCandidate, DiscoveryCandidatePage, ManagedDatabaseInstance } from '../../../../generated/api/dist/index.js';
import { renderFeature } from '../../test/renderFeature';
import { AppShell } from '../../shell/AppShell';
import { CandidateListPage } from './CandidateListPage';
import { hostKeys } from '../hosts/queries';
import { instanceKeys } from '../instances/queries';
import { discoveryKeys, useAcceptCandidate, useIgnoreCandidate } from './queries';

const nativeCandidate: DiscoveryCandidate = {
  candidateId: 'candidate-native', tenantId: 'tenant-a', projectId: 'project-a', hostId: 'host-1', agentId: 'agent-1',
  discoverySource: 'native', databaseFamily: 'mysql', databaseVariant: 'mysql', versionHint: '8.4', normalizedEndpoint: '127.0.0.1:3306',
  processIdentity: 'mysqld --password=must-not-render', confidence: 0.94,
  evidenceSummary: new Set([{ kind: 'listen_endpoint', value: 'tcp/3306' }, { kind: 'process_name', value: 'mysqld' }]),
  fingerprint: 'fp-native', possibleDuplicateOf: 'db-existing', ruleRevision: 3, observationRevision: 8,
  firstSeenAt: new Date('2026-09-01T00:00:00Z'), lastSeenAt: new Date('2026-09-01T00:05:00Z'), status: 'awaiting_confirmation', etag: '"candidate-8"',
};
const dockerCandidate: DiscoveryCandidate = {
  ...nativeCandidate, candidateId: 'candidate-docker', discoverySource: 'docker', databaseFamily: 'postgresql', databaseVariant: 'postgresql',
  containerIdentity: 'container-safe-id', containerImage: 'postgres:16', confidence: 0.82, fingerprint: 'fp-docker', possibleDuplicateOf: undefined,
};

function api() {
  const accepted: ManagedDatabaseInstance = {
    instanceId: 'db-new', tenantId: 'tenant-a', projectId: 'project-a', hostId: 'host-1', agentId: 'agent-1', databaseFamily: 'mysql', databaseVariant: 'mysql',
    displayName: '支付 MySQL', endpoint: '127.0.0.1:3306', credentialRef: 'secret://mysql/pay', tlsRef: 'secret://tls/pay', labels: {}, capabilities: new Set(),
    connectionTestStatus: 'pending', pluginAssignmentRevision: 0, managementStatus: 'provisioning', etag: '"db-1"',
  };
  return {
    listDiscoveryCandidates: vi.fn(async (): Promise<DiscoveryCandidatePage> => ({ items: [nativeCandidate, dockerCandidate], page: { limit: 20, hasMore: false } })),
    ignoreDiscoveryCandidate: vi.fn(async () => ({ ...nativeCandidate, status: 'ignored' })),
    acceptDiscoveryCandidate: vi.fn(async () => accepted),
  } as unknown as DefaultApi;
}

describe('Discovery candidate workflows', () => {
  it('fails closed before requesting candidates when view permission is absent', async () => {
    const client = api();
    renderFeature(<CandidateListPage api={client} />, []);
    expect(await screen.findByText('没有查看发现候选的权限。')).not.toBeNull();
    expect(client.listDiscoveryCandidates).not.toHaveBeenCalled();
  });

  it('closes project-specific drawers before the new project can reuse their candidate', async () => {
    const client = api();
    const permissions = ['discovery:view', 'discovery:manage'];
    renderFeature(<AppShell><CandidateListPage api={client} /></AppShell>, permissions, '/', permissions);
    await userEvent.click(await screen.findByRole('button', { name: '纳管 candidate-native' }));
    expect(screen.getByRole('dialog', { name: '纳管数据库实例' })).not.toBeNull();

    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Project' }), 'tenant-a/project-b');
    await waitFor(() => expect(screen.queryByRole('dialog', { name: '纳管数据库实例' })).toBeNull());
    expect(client.acceptDiscoveryCandidate).not.toHaveBeenCalled();
  });

  it('filters native and Docker candidates and shows bounded evidence plus duplicate risk', async () => {
    const client = api();
    renderFeature(<CandidateListPage api={client} />, ['discovery:view', 'discovery:manage']);

    expect(await screen.findByText('candidate-native')).not.toBeNull();
    expect(screen.getByText('candidate-docker')).not.toBeNull();
    await userEvent.selectOptions(screen.getByLabelText('发现来源'), 'docker');
    await waitFor(() => expect(client.listDiscoveryCandidates).toHaveBeenLastCalledWith(expect.objectContaining({ source: 'docker' }), expect.anything()));
    await userEvent.click(screen.getByRole('button', { name: '查看 candidate-native 证据' }));
    const drawer = screen.getByRole('dialog', { name: '发现证据' });
    expect(drawer.textContent).toContain('tcp/3306');
    expect(within(drawer).getByText(/可能与 db-existing 重复/)).not.toBeNull();
    expect(document.body.textContent).not.toContain('must-not-render');
  });

  it('requires explicit endpoint, variant, credential reference, TLS reference and review before acceptance', async () => {
    const client = api();
    renderFeature(<CandidateListPage api={client} />, ['discovery:view', 'discovery:manage']);
    await screen.findByText('candidate-native');
    await userEvent.click(screen.getByRole('button', { name: '纳管 candidate-native' }));
    expect(screen.getByRole('heading', { name: '确认候选' })).not.toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '下一步' }));
    await userEvent.clear(screen.getByLabelText('连接端点'));
    await userEvent.type(screen.getByLabelText('连接端点'), '10.0.0.8:3306');
    await userEvent.click(screen.getByRole('button', { name: '下一步' }));
    await userEvent.clear(screen.getByLabelText('数据库变体'));
    await userEvent.type(screen.getByLabelText('数据库变体'), 'mysql');
    await userEvent.click(screen.getByRole('button', { name: '下一步' }));
    await userEvent.type(screen.getByLabelText('凭据引用'), 'vault://mysql/pay');
    const credentialNext = screen.getByRole('button', { name: '下一步' }) as HTMLButtonElement;
    expect(credentialNext.disabled).toBe(true);
    await userEvent.clear(screen.getByLabelText('凭据引用'));
    await userEvent.type(screen.getByLabelText('凭据引用'), 'secret://mysql/pay');
    await userEvent.type(screen.getByLabelText('TLS 引用'), 'secret://tls/pay');
    await userEvent.click(credentialNext);
    expect(screen.getByRole('heading', { name: '复核并提交' })).not.toBeNull();
    expect(screen.getByText('secret://mysql/pay')).not.toBeNull();
    expect(screen.queryByLabelText(/密码|secret/i)).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '开始纳管' }));

    await waitFor(() => expect(client.acceptDiscoveryCandidate).toHaveBeenCalledWith({
      candidateId: 'candidate-native', ifMatch: '"candidate-8"', idempotencyKey: expect.any(String),
      acceptDiscoveryCandidateRequest: expect.objectContaining({
        databaseVariant: 'mysql', normalizedEndpoint: '10.0.0.8:3306', credentialRef: 'secret://mysql/pay', tlsRef: 'secret://tls/pay',
      }),
    }, expect.objectContaining({ signal: expect.any(AbortSignal) })));
    expect(await screen.findByText('provisioning')).not.toBeNull();
  });

  it('lets a candidate without a discovered endpoint proceed to endpoint entry', async () => {
    const client = api();
    const candidate = { ...nativeCandidate, candidateId: 'candidate-no-endpoint', normalizedEndpoint: undefined, unixSocket: undefined, possibleDuplicateOf: undefined };
    client.listDiscoveryCandidates = vi.fn(async () => ({ items: [candidate], page: { limit: 20, hasMore: false } }));
    renderFeature(<CandidateListPage api={client} />, ['discovery:view', 'discovery:manage']);

    await userEvent.click(await screen.findByRole('button', { name: '纳管 candidate-no-endpoint' }));
    const next = screen.getByRole('button', { name: '下一步' }) as HTMLButtonElement;
    expect(next.disabled).toBe(false);
    await userEvent.click(next);
    expect(screen.getByRole('heading', { name: '确认连接端点' })).not.toBeNull();
  });

  it('does not offer invalid transitions for terminal or provisioning candidates', async () => {
    const client = api();
    const accepted = { ...nativeCandidate, candidateId: 'candidate-accepted', status: 'accepted' as const };
    client.listDiscoveryCandidates = vi.fn(async () => ({ items: [accepted], page: { limit: 20, hasMore: false } }));
    renderFeature(<CandidateListPage api={client} />, ['discovery:view', 'discovery:manage']);

    await screen.findByText('candidate-accepted');
    expect(screen.queryByRole('button', { name: '纳管 candidate-accepted' })).toBeNull();
    expect(screen.queryByRole('button', { name: '忽略 candidate-accepted' })).toBeNull();
  });

  it('loads the next discovery cursor instead of silently truncating candidates', async () => {
    const client = api();
    client.listDiscoveryCandidates = vi.fn(async (request) => request.cursor
      ? { items: [{ ...dockerCandidate, candidateId: 'candidate-page-2' }], page: { limit: 1, hasMore: false } }
      : { items: [nativeCandidate], page: { limit: 1, hasMore: true, nextCursor: 'candidate-cursor-2' } });
    renderFeature(<CandidateListPage api={client} />, ['discovery:view']);

    await userEvent.click(await screen.findByRole('button', { name: '加载更多候选' }));
    expect(await screen.findByText('candidate-page-2')).not.toBeNull();
    expect(client.listDiscoveryCandidates).toHaveBeenLastCalledWith(expect.objectContaining({ cursor: 'candidate-cursor-2' }), expect.anything());
  });

  it('uses an idempotent ignore mutation and hides management actions without permission', async () => {
    const managedClient = api();
    const first = renderFeature(<CandidateListPage api={managedClient} />, ['discovery:view', 'discovery:manage']);
    await screen.findByText('candidate-native');
    await userEvent.click(screen.getByRole('button', { name: '忽略 candidate-native' }));
    await userEvent.click(screen.getByRole('button', { name: '确认忽略' }));
    await waitFor(() => expect(managedClient.ignoreDiscoveryCandidate).toHaveBeenCalledWith({
      candidateId: 'candidate-native', idempotencyKey: expect.any(String), ignoreDiscoveryCandidateRequest: { reasonCode: 'operator_ignored' },
    }, expect.objectContaining({ signal: expect.any(AbortSignal) })));
    first.unmount();

    renderFeature(<CandidateListPage api={api()} />, ['discovery:view']);
    await screen.findByText('candidate-native');
    expect(screen.queryByRole('button', { name: '纳管 candidate-native' })).toBeNull();
    expect(screen.queryByRole('button', { name: '忽略 candidate-native' })).toBeNull();
  });

  it('keeps one idempotency key across retry and aborts the old-scope mutation', async () => {
    const keys: string[] = [];
    let signal: AbortSignal | undefined;
    let calls = 0;
    const accepted = await api().acceptDiscoveryCandidate({} as never);
    const client = {
      acceptDiscoveryCandidate: vi.fn(async (request, init) => {
        keys.push(request.idempotencyKey);
        signal = (init as RequestInit | undefined)?.signal ?? undefined;
        calls += 1;
        if (calls === 1) throw new Error('lost acknowledgement');
        if (calls === 2) return accepted;
        return new Promise<ManagedDatabaseInstance>((_resolve, reject) => signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError'))));
      }),
    } as unknown as DefaultApi;
    const queryClient = new QueryClient({ defaultOptions: { mutations: { retry: 1, retryDelay: 0 } } });
    const wrapper = ({ children }: React.PropsWithChildren) => <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
    const { result, rerender } = renderHook(
      ({ scope }) => useAcceptCandidate(client, scope),
      { wrapper, initialProps: { scope: { tenantId: 'tenant-a', projectId: 'project-a' } } },
    );
    const request = { displayName: 'db', databaseFamily: 'mysql', databaseVariant: 'mysql', normalizedEndpoint: '127.0.0.1:3306', credentialRef: 'secret://mysql/db' };
    act(() => result.current.mutate({ candidate: nativeCandidate, request, idempotencyKey: 'operation-1' }));
    await waitFor(() => expect(client.acceptDiscoveryCandidate).toHaveBeenCalledTimes(2));
    expect(keys).toEqual(['operation-1', 'operation-1']);

    act(() => result.current.mutate({ candidate: nativeCandidate, request, idempotencyKey: 'operation-2' }));
    await waitFor(() => expect(client.acceptDiscoveryCandidate).toHaveBeenCalledTimes(3));
    rerender({ scope: { tenantId: 'tenant-a', projectId: 'project-b' } });
    await waitFor(() => expect(signal?.aborted).toBe(true));
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(client.acceptDiscoveryCandidate).toHaveBeenCalledTimes(3);
  });

  it('invalidates every affected scoped list family and seeds accepted instance detail', async () => {
    const scope = { tenantId: 'tenant-a', projectId: 'project-a' };
    const filterA = { status: 'awaiting_confirmation' as const };
    const filterB = { source: 'docker' as const };
    const client = api();
    const accepted = await client.acceptDiscoveryCandidate({} as never);
    const queryClient = new QueryClient();
    const wrapper = ({ children }: React.PropsWithChildren) => <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
    const discoveryA = discoveryKeys.list(scope, filterA);
    const discoveryB = discoveryKeys.list(scope, filterB);
    const instances = instanceKeys.list(scope, {});
    const hostInstances = hostKeys.instances(scope, nativeCandidate.hostId);
    for (const key of [discoveryA, discoveryB, instances, hostInstances]) queryClient.setQueryData(key, { marker: true });
    const { result } = renderHook(() => ({ accept: useAcceptCandidate(client, scope), ignore: useIgnoreCandidate(client, scope) }), { wrapper });
    const request = { displayName: 'db', databaseFamily: 'mysql', databaseVariant: 'mysql', normalizedEndpoint: '127.0.0.1:3306', credentialRef: 'secret://mysql/db' };

    await act(() => result.current.accept.mutateAsync({ candidate: nativeCandidate, request, idempotencyKey: 'accept-operation' }));
    expect(queryClient.getQueryState(discoveryA)?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(discoveryB)?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(instances)?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(hostInstances)?.isInvalidated).toBe(true);
    expect(queryClient.getQueryData(instanceKeys.detail(scope, accepted.instanceId))).toEqual(accepted);

    queryClient.setQueryData(discoveryA, { marker: true });
    queryClient.setQueryData(discoveryB, { marker: true });
    await act(() => result.current.ignore.mutateAsync({ candidate: nativeCandidate, idempotencyKey: 'ignore-operation' }));
    expect(queryClient.getQueryState(discoveryA)?.isInvalidated).toBe(true);
    expect(queryClient.getQueryState(discoveryB)?.isInvalidated).toBe(true);
  });
});
