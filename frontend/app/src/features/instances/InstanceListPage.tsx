import React from 'react';
import { Link } from 'react-router-dom';
import type { DatabaseManagementStatus, DefaultApi, ManagedDatabaseInstance } from '../../../../generated/api/dist/index.js';
import { useProjectContext } from '../../auth/AuthProvider';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { DataTable } from '../../components/DataTable';
import { FilterBar } from '../../components/FilterBar';
import { PageHeader } from '../../components/PageHeader';
import { StatusTag } from '../../components/StatusTag';
import { useInstancesApi } from './api';
import { useInstanceList } from './queries';

export function InstanceListPage({ api: override }: { api?: DefaultApi }) {
  const project = useProjectContext();
  const api = useInstancesApi(override);
  const canView = project.permissions.has('database-instances:view');
  const [databaseFamily, setDatabaseFamily] = React.useState('');
  const [status, setStatus] = React.useState<DatabaseManagementStatus | undefined>();
  const query = useInstanceList(api, project, { databaseFamily: databaseFamily || undefined, status }, canView);
  const instances = query.data?.pages.flatMap((page) => page.items) ?? [];
  if (!canView) return <section className="management-page"><PageHeader title="数据库实例" /><p role="alert" className="notice">没有查看数据库实例的权限。</p></section>;
  return (
    <section className="management-page">
      <PageHeader title="数据库实例" description="查看纳管、插件与连接测试状态。" />
      <FilterBar label="数据库实例筛选" onSubmit={(event) => event.preventDefault()}><label>数据库类型<input aria-label="实例数据库类型" value={databaseFamily} onChange={(event) => setDatabaseFamily(event.target.value.trim())} /></label><label>管理状态<select aria-label="实例管理状态" value={status ?? ''} onChange={(event) => setStatus((event.target.value || undefined) as DatabaseManagementStatus | undefined)}><option value="">全部</option><option value="accepted">已接受</option><option value="provisioning">纳管中</option><option value="connection_testing">连接测试中</option><option value="managed">已纳管</option><option value="monitoring">监控中</option><option value="plugin_failed">插件失败</option><option value="authentication_failed">认证失败</option><option value="tls_failed">TLS 失败</option><option value="unreachable">不可达</option><option value="unsupported_version">版本不支持</option><option value="degraded">降级</option><option value="offline">离线</option><option value="retired">已退役</option></select></label></FilterBar>
      <AsyncBoundary loading={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {instances.length === 0 ? <p role="status" className="empty-state">当前项目没有匹配的数据库实例。</p> : <DataTable<ManagedDatabaseInstance & { id: string }> caption="已纳管数据库实例" rows={instances.map((instance) => ({ ...instance, id: instance.instanceId }))} columns={[
          { key: 'displayName', header: '实例', render: (row) => <Link to={`/instances/${encodeURIComponent(row.instanceId)}`}>{row.displayName}</Link> },
          { key: 'databaseFamily', header: '数据库', render: (row) => `${row.databaseFamily} / ${row.databaseVariant}` },
          { key: 'endpoint', header: '端点', render: (row) => row.endpoint ?? row.unixSocket ?? '未配置' },
          { key: 'managementStatus', header: '管理状态', render: (row) => <StatusTag status={row.managementStatus} tone={row.managementStatus === 'monitoring' || row.managementStatus === 'managed' ? 'success' : row.managementStatus === 'provisioning' || row.managementStatus === 'accepted' ? 'neutral' : 'warning'} /> },
          { key: 'connectionTestStatus', header: '连接状态', render: (row) => <StatusTag status={row.connectionTestStatus} tone={row.connectionTestStatus === 'succeeded' ? 'success' : row.connectionTestStatus === 'not_tested' || row.connectionTestStatus === 'pending' ? 'neutral' : 'danger'} /> },
          { key: 'pluginId', header: '采集插件', render: (row) => row.pluginId ?? '未分配' },
        ]} />}
        {query.hasNextPage ? <button type="button" disabled={query.isFetchingNextPage} onClick={() => void query.fetchNextPage()}>{query.isFetchingNextPage ? '正在加载…' : '加载更多实例'}</button> : null}
      </AsyncBoundary>
    </section>
  );
}
