import React from 'react';
import { Link, useParams } from 'react-router-dom';
import type { DefaultApi } from '../../../../generated/api/dist/index.js';
import { useProjectContext } from '../../auth/AuthProvider';
import { mutationKey } from '../../api/client';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { PageHeader } from '../../components/PageHeader';
import { StatusTag } from '../../components/StatusTag';
import { useInstancesApi } from './api';
import { ConnectionTestPanel } from './ConnectionTestPanel';
import { useConnectionJob, useConnectionTest, useInstance } from './queries';

export function InstanceDetailPage({ instanceId: explicitInstanceId, api: override }: { instanceId?: string; api?: DefaultApi }) {
  const params = useParams();
  const instanceId = explicitInstanceId ?? params.id ?? '';
  const project = useProjectContext();
  const api = useInstancesApi(override);
  const canView = project.permissions.has('database-instances:view');
  const query = useInstance(api, project, instanceId, canView);
  const test = useConnectionTest(api, project, instanceId);
  const canViewJobs = project.permissions.has('platform.jobs.read');
  const jobQuery = useConnectionJob(api, project, instanceId, test.data?.id, canViewJobs);
  const instance = query.data;
  if (!canView) return <section className="management-page"><PageHeader title="数据库实例详情" /><p role="alert" className="notice">没有查看数据库实例的权限。</p></section>;
  return (
    <section className="management-page">
      <Link to="/instances">← 返回实例列表</Link>
      <AsyncBoundary loading={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {instance ? <>
          <PageHeader title={instance.displayName} description={`${instance.databaseFamily} ${instance.version ?? ''} · ${instance.instanceId}`} actions={<StatusTag status={instance.managementStatus} tone={instance.managementStatus === 'monitoring' ? 'success' : 'warning'} />} />
          {instance.managementStatus === 'offline' ? <p className="notice notice--danger">实例当前离线，指标与连接信息不是实时状态。</p> : null}
          {instance.managementStatus === 'degraded' ? <p className="notice notice--warning">实例处于降级状态，请结合连接测试与插件状态排查。</p> : null}
          <div className="summary-grid"><article className="panel"><h2>连接配置</h2><dl><dt>端点</dt><dd>{instance.endpoint ?? instance.unixSocket ?? '未配置'}</dd><dt>凭据引用</dt><dd>{instance.credentialRef}</dd><dt>TLS 引用</dt><dd>{instance.tlsRef ?? '未配置'}</dd></dl></article><article className="panel"><h2>采集配置</h2><dl><dt>插件</dt><dd>{instance.pluginId ?? '未分配'}</dd><dt>期望版本</dt><dd>{instance.desiredPluginVersion ?? '未指定'}</dd><dt>分配版本</dt><dd>{instance.pluginAssignmentRevision}</dd></dl></article></div>
          <ConnectionTestPanel instance={instance} job={jobQuery.data ?? test.data} pending={test.isPending} tracking={canViewJobs} onTest={() => test.mutate(mutationKey())} />
          {test.error ? <AsyncBoundary error={test.error} /> : null}
          {jobQuery.error ? <><p className="notice notice--warning">进度跟踪失败，当前状态可能陈旧。</p><AsyncBoundary error={jobQuery.error} /></> : null}
        </> : null}
      </AsyncBoundary>
    </section>
  );
}
