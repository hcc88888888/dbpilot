import React from 'react';
import type { DefaultApi, DiscoveryCandidate, DiscoveryCandidateStatus, DiscoverySource } from '../../../../generated/api/dist/index.js';
import { useProjectContext } from '../../auth/AuthProvider';
import { mutationKey } from '../../api/client';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import { DataTable } from '../../components/DataTable';
import { FilterBar } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { PermissionGate } from '../../components/PermissionGate';
import { StatusTag } from '../../components/StatusTag';
import { AcceptCandidateWizard } from './AcceptCandidateWizard';
import { useDiscoveryApi } from './api';
import { CandidateDetailDrawer } from './CandidateDetailDrawer';
import { useAcceptCandidate, useCandidateList, useIgnoreCandidate } from './queries';
import type { DiscoveryFilters } from './types';

export function CandidateListPage({ api: override }: { api?: DefaultApi }) {
  const project = useProjectContext();
  const api = useDiscoveryApi(override);
  const canView = project.permissions.has('discovery:view');
  const [source, setSource] = React.useState<DiscoverySource | undefined>();
  const [status, setStatus] = React.useState<DiscoveryCandidateStatus | undefined>('awaiting_confirmation');
  const [databaseFamily, setDatabaseFamily] = React.useState('');
  const filters: DiscoveryFilters = { source, status, databaseFamily: databaseFamily || undefined };
  const query = useCandidateList(api, project, filters, canView);
  const ignore = useIgnoreCandidate(api, project);
  const accept = useAcceptCandidate(api, project);
  const [evidence, setEvidence] = React.useState<DiscoveryCandidate>();
  const [toIgnore, setToIgnore] = React.useState<DiscoveryCandidate>();
  const [toAccept, setToAccept] = React.useState<DiscoveryCandidate>();
  const candidates = query.data?.pages.flatMap((page) => page.items) ?? [];

  if (!canView) return <section className="management-page"><PageHeader title="数据库发现" /><p role="alert" className="notice">没有查看发现候选的权限。</p></section>;
  return (
    <section className="management-page">
      <PageHeader title="数据库发现" description="核验 Agent 发现的原生进程和 Docker 数据库候选。" />
      <FilterBar label="发现候选筛选" onSubmit={(event) => event.preventDefault()}>
        <label>发现来源<select aria-label="发现来源" value={source ?? ''} onChange={(event) => setSource((event.target.value || undefined) as DiscoverySource | undefined)}><option value="">全部</option><option value="native">原生进程</option><option value="docker">Docker</option></select></label>
        <label>状态<select aria-label="候选状态" value={status ?? ''} onChange={(event) => setStatus((event.target.value || undefined) as DiscoveryCandidateStatus | undefined)}><option value="">全部</option><option value="discovered">新发现</option><option value="awaiting_confirmation">待确认</option><option value="accepted">已纳管</option><option value="provisioning">纳管中</option><option value="ignored">已忽略</option><option value="duplicate">重复</option><option value="disappeared">已消失</option></select></label>
        <label>数据库类型<input aria-label="数据库类型" value={databaseFamily} onChange={(event) => setDatabaseFamily(event.target.value.trim())} /></label>
      </FilterBar>
      <AsyncBoundary loading={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {candidates.length === 0 ? <p role="status" className="empty-state">没有匹配的发现候选。</p> : <DataTable<DiscoveryCandidate & { id: string }> caption="发现候选" rows={candidates.map((candidate) => ({ ...candidate, id: candidate.candidateId }))} columns={[
          { key: 'candidateId', header: '候选', render: (row) => <><strong>{row.candidateId}</strong>{row.possibleDuplicateOf ? <small className="truth-warning">可能与 {row.possibleDuplicateOf} 重复</small> : null}</> },
          { key: 'discoverySource', header: '来源', render: (row) => row.discoverySource === 'docker' ? 'Docker' : '原生进程' },
          { key: 'databaseFamily', header: '数据库', render: (row) => `${row.databaseFamily} / ${row.databaseVariant}` },
          { key: 'confidence', header: '可信度', render: (row) => <StatusTag status={`${Math.round(row.confidence * 100)}%`} tone={row.confidence >= 0.9 ? 'success' : 'warning'} /> },
          { key: 'evidenceSummary', header: '证据', render: (row) => <button type="button" onClick={() => setEvidence(row)} aria-label={`查看 ${row.candidateId} 证据`}>查看证据 ({row.evidenceSummary.size})</button> },
          { key: 'status', header: '状态', render: (row) => <StatusTag status={row.status} /> },
          { key: 'etag', header: '操作', render: (row) => (row.status === 'discovered' || row.status === 'awaiting_confirmation') ? <PermissionGate permission="discovery:manage"><div className="row-actions"><button type="button" onClick={() => setToAccept(row)} aria-label={`纳管 ${row.candidateId}`}>纳管</button><button type="button" onClick={() => setToIgnore(row)} aria-label={`忽略 ${row.candidateId}`}>忽略</button></div></PermissionGate> : <span className="muted">无可用操作</span> },
        ]} />}
        {query.hasNextPage ? <button type="button" disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>{query.isFetchingNextPage ? '正在加载…' : '加载更多候选'}</button> : null}
      </AsyncBoundary>
      <CandidateDetailDrawer candidate={evidence} onClose={() => setEvidence(undefined)} />
      <AcceptCandidateWizard candidate={toAccept} pending={accept.isPending} result={accept.data} onClose={() => { setToAccept(undefined); accept.reset(); }} onSubmit={(request) => toAccept && accept.mutate({ candidate: toAccept, request, idempotencyKey: mutationKey() })} />
      <ConfirmDialog open={Boolean(toIgnore)} title="忽略发现候选" confirmLabel="确认忽略" onCancel={() => setToIgnore(undefined)} onConfirm={() => { if (toIgnore) ignore.mutate({ candidate: toIgnore, idempotencyKey: mutationKey() }); setToIgnore(undefined); }}><p>该候选将不再出现在默认待处理列表中。</p></ConfirmDialog>
      {accept.error || ignore.error ? <AsyncBoundary error={accept.error ?? ignore.error} /> : null}
    </section>
  );
}
