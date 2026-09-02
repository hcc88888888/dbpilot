import React from 'react';
import { Link } from 'react-router-dom';
import type { DefaultApi, HostStatus, ManagedHost } from '../../../../generated/api/dist/index.js';
import { useProjectContext } from '../../auth/AuthProvider';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { DataTable } from '../../components/DataTable';
import { FilterBar } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { StatusTag } from '../../components/StatusTag';
import { useHostsApi } from './api';
import { useHostList } from './queries';

function statusTone(status: string) {
  if (status === 'online') return 'success' as const;
  if (status === 'stale') return 'warning' as const;
  if (status === 'offline' || status === 'decommissioned') return 'danger' as const;
  return 'neutral' as const;
}

function resourceText(label: string, resource?: { available: number; capacity: number }) {
  return resource ? `${label}可用 ${resource.available} / ${resource.capacity}` : `${label}未上报`;
}

export function HostListPage({ api: override }: { api?: DefaultApi }) {
  const project = useProjectContext();
  const api = useHostsApi(override);
  const canView = project.permissions.has('hosts:view');
  const [status, setStatus] = React.useState<HostStatus | undefined>();
  const query = useHostList(api, project, { status }, canView);
  const rows = (query.data?.items ?? []).map((host) => ({ ...host, id: host.hostId }));

  if (!canView) return <section className="management-page"><PageHeader title="主机管理" /><p role="alert" className="notice">没有查看主机的权限。</p></section>;
  return (
    <section className="management-page">
      <PageHeader title="主机管理" description="查看 Agent 在线状态、主机资源与发现能力。" />
      <FilterBar label="主机筛选">
        <label>状态
          <select aria-label="主机状态" value={status ?? ''} onChange={(event) => setStatus((event.target.value || undefined) as HostStatus | undefined)}>
            <option value="">全部</option><option value="online">在线</option><option value="stale">数据陈旧</option><option value="offline">离线</option>
          </select>
        </label>
      </FilterBar>
      <AsyncBoundary loading={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {rows.length === 0 ? <p role="status" className="empty-state">当前项目没有匹配的主机。</p> : (
          <DataTable<ManagedHost & { id: string }> caption="已纳管主机" rows={rows} columns={[
            { key: 'displayName', header: '主机', render: (row) => <Link to={`/hosts/${encodeURIComponent(row.hostId)}`}>{row.displayName}</Link> },
            { key: 'status', header: '状态', render: (row) => <><StatusTag status={row.status} tone={statusTone(row.status)} />{row.status === 'stale' ? <small className="truth-warning">数据可能已过期</small> : null}{row.status === 'offline' ? <small className="truth-warning">Agent 离线，指标非实时</small> : null}</> },
            { key: 'cpuSummary', header: 'CPU', render: (row) => resourceText('CPU ', row.cpuSummary) },
            { key: 'memorySummary', header: '内存', render: (row) => resourceText('内存', row.memorySummary) },
            { key: 'operatingSystem', header: '系统', render: (row) => `${row.operatingSystem}${row.operatingSystemVersion ? ` ${row.operatingSystemVersion}` : ''}` },
            { key: 'capabilities', header: '能力', render: (row) => `${row.capabilities.filter((item) => item.available).length} / ${row.capabilities.length} 可用` },
          ]} />
        )}
      </AsyncBoundary>
    </section>
  );
}
