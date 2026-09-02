import React from 'react';
import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { DefaultApi, DiscoveryCandidate, DiscoveryCandidatePage, ManagedDatabaseInstance } from '../../../../generated/api/dist/index.js';
import { renderFeature } from '../../test/renderFeature';
import { CandidateListPage } from './CandidateListPage';

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
    displayName: '支付 MySQL', endpoint: '127.0.0.1:3306', credentialRef: 'vault://mysql/pay', tlsRef: 'vault://tls/pay', labels: {}, capabilities: new Set(),
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
    await userEvent.type(screen.getByLabelText('TLS 引用'), 'vault://tls/pay');
    await userEvent.click(screen.getByRole('button', { name: '下一步' }));
    expect(screen.getByRole('heading', { name: '复核并提交' })).not.toBeNull();
    expect(screen.getByText('vault://mysql/pay')).not.toBeNull();
    expect(screen.queryByLabelText(/密码|secret/i)).toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '开始纳管' }));

    await waitFor(() => expect(client.acceptDiscoveryCandidate).toHaveBeenCalledWith({
      candidateId: 'candidate-native', ifMatch: '"candidate-8"', idempotencyKey: expect.any(String),
      acceptDiscoveryCandidateRequest: expect.objectContaining({
        databaseVariant: 'mysql', normalizedEndpoint: '10.0.0.8:3306', credentialRef: 'vault://mysql/pay', tlsRef: 'vault://tls/pay',
      }),
    }));
    expect(await screen.findByText('provisioning')).not.toBeNull();
  });

  it('uses an idempotent ignore mutation and hides management actions without permission', async () => {
    const managedClient = api();
    const first = renderFeature(<CandidateListPage api={managedClient} />, ['discovery:view', 'discovery:manage']);
    await screen.findByText('candidate-native');
    await userEvent.click(screen.getByRole('button', { name: '忽略 candidate-native' }));
    await userEvent.click(screen.getByRole('button', { name: '确认忽略' }));
    await waitFor(() => expect(managedClient.ignoreDiscoveryCandidate).toHaveBeenCalledWith({
      candidateId: 'candidate-native', idempotencyKey: expect.any(String), ignoreDiscoveryCandidateRequest: { reasonCode: 'operator_ignored' },
    }));
    first.unmount();

    renderFeature(<CandidateListPage api={api()} />, ['discovery:view']);
    await screen.findByText('candidate-native');
    expect(screen.queryByRole('button', { name: '纳管 candidate-native' })).toBeNull();
    expect(screen.queryByRole('button', { name: '忽略 candidate-native' })).toBeNull();
  });
});
