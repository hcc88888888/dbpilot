import React from 'react';
import { Link, useParams } from 'react-router-dom';
import type { DefaultApi } from '../../../../generated/api/dist/index.js';
import { useProjectContext } from '../../auth/AuthProvider';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { PageHeader } from '../../components/PageHeader';
import { StatusTag } from '../../components/StatusTag';
import { useHostsApi } from './api';
import { useHost, useHostInstances } from './queries';

export function HostDetailPage({ hostId: explicitHostId, api: override }: { hostId?: string; api?: DefaultApi }) {
  const params = useParams();
  const hostId = explicitHostId ?? params.id ?? '';
  const project = useProjectContext();
  const api = useHostsApi(override);
  const canView = project.permissions.has('hosts:view');
  const hostQuery = useHost(api, project, hostId, canView);
  const canViewInstances = project.permissions.has('database-instances:view');
  const instanceQuery = useHostInstances(api, project, hostId, canView && canViewInstances);
  const host = hostQuery.data;
  const instances = instanceQuery.data?.pages.flatMap((page) => page.items) ?? [];

  if (!canView) return <section className="management-page"><PageHeader title="主机详情" /><p role="alert" className="notice">没有查看主机的权限。</p></section>;
  return (
    <section className="management-page">
      <Link to="/hosts">← 返回主机列表</Link>
      <AsyncBoundary loading={hostQuery.isPending} error={hostQuery.error} onRetry={() => void hostQuery.refetch()}>
        {host ? <>
          <PageHeader title={host.displayName} description={`${host.hostname} · ${host.hostId}`} actions={<StatusTag status={host.status} tone={host.status === 'online' ? 'success' : host.status === 'stale' ? 'warning' : 'danger'} />} />
          {host.status === 'stale' ? <p className="notice notice--warning">该主机心跳已陈旧，以下信息可能不是实时状态。</p> : null}
          {host.status === 'offline' ? <p className="notice notice--danger">Agent 当前离线，无法确认最新资源和插件状态。</p> : null}
          <div className="summary-grid">
            <article className="panel"><h2>系统信息</h2><dl><dt>操作系统</dt><dd>{host.operatingSystem}{host.operatingSystemVersion ? ` ${host.operatingSystemVersion}` : ''}</dd><dt>架构</dt><dd>{host.architecture}</dd><dt>Agent</dt><dd>{host.agentVersion ?? '未上报'}</dd></dl></article>
            <article className="panel"><h2>资源概览</h2><dl><dt>CPU</dt><dd>{host.cpuSummary ? `${host.cpuSummary.available} / ${host.cpuSummary.capacity} 可用` : '未上报'}</dd><dt>内存</dt><dd>{host.memorySummary ? `${host.memorySummary.available} / ${host.memorySummary.capacity} 可用` : '未上报'}</dd><dt>最后心跳</dt><dd>{host.lastHeartbeatAt?.toLocaleString() ?? '从未收到'}</dd></dl></article>
          </div>
          <article className="panel"><h2>采集与发现能力</h2><ul className="capability-list">{host.capabilities.map((capability) => <li key={capability.name}><StatusTag status={capability.available ? '可用' : '不可用'} tone={capability.available ? 'success' : 'warning'} /> <span>{capability.name === 'docker_discovery' ? 'Docker 发现' : capability.name === 'native_discovery' ? '原生进程发现' : capability.name}{!capability.available ? '不可用' : ''}</span></li>)}</ul></article>
          {canViewInstances ? <article className="panel"><h2>数据库与插件</h2><AsyncBoundary loading={instanceQuery.isPending} error={instanceQuery.error}>{instances.length ? <ul className="resource-list">{instances.map((instance) => <li key={instance.instanceId}><Link to={`/instances/${encodeURIComponent(instance.instanceId)}`}>{instance.displayName}</Link><span>{instance.databaseFamily}</span><span>{instance.pluginId ?? '插件未分配'}</span></li>)}</ul> : <p>暂无数据库实例。</p>}{instanceQuery.hasNextPage ? <button type="button" disabled={instanceQuery.isFetchingNextPage} onClick={() => void instanceQuery.fetchNextPage()}>加载更多数据库</button> : null}</AsyncBoundary></article> : <p className="notice">没有查看数据库实例的权限。</p>}
        </> : null}
      </AsyncBoundary>
    </section>
  );
}
