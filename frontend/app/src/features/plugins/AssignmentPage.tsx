import React from 'react';
import type { DefaultApi, PluginAssignment } from '../../../../generated/api/dist/index.js';
import { mutationKey } from '../../api/client';
import { useProjectContext } from '../../auth/AuthProvider';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { DataTable } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { StatusTag } from '../../components/StatusTag';
import { usePluginsApi } from './api';
import { useChangeAssignment, usePluginAssignments, usePluginJob } from './queries';
import { RolloutDialog } from './RolloutDialog';
import type { AssignmentAction, AssignmentChange } from './types';

function JobState({ api, assignmentId, jobId, canView }: { api: DefaultApi; assignmentId: string; jobId?: string; canView: boolean }) {
  const scope = useProjectContext();
  const query = usePluginJob(api, scope, assignmentId, jobId, canView);
  if (!jobId) return null;
  if (!canView) return <p className="notice notice--warning">没有查看任务进度的权限，仅显示任务已创建。</p>;
  return <AsyncBoundary loading={query.isPending} error={query.error}>{query.data ? <div role="status" className="job-progress"><strong>{query.data.status}</strong><span>{query.data.progress.completedTargets} / {query.data.progress.totalTargets}</span></div> : null}</AsyncBoundary>;
}

export function AssignmentPage({ api: override }: { api?: DefaultApi }) {
  const project = useProjectContext();
  const api = usePluginsApi(override);
  const canView = project.permissions.has('plugins:view');
  const canManage = project.permissions.has('plugins:manage') && project.permissions.has('plugins:deploy');
  const canViewJobs = project.permissions.has('platform.jobs.read');
  const query = usePluginAssignments(api, project, {}, canView);
  const change = useChangeAssignment(api, project);
  const [selection, setSelection] = React.useState<{ action: AssignmentAction; assignment: PluginAssignment }>();
  const assignments = query.data?.pages.flatMap((page) => page.items) ?? [];
  if (!canView) return <section className="management-page"><PageHeader title="插件分配" /><p role="alert" className="notice">没有查看插件分配的权限。</p></section>;
  const run = (assignment: PluginAssignment, changeValue: AssignmentChange) => change.mutate({
    assignment, change: changeValue, updateKey: mutationKey(), reconcileKey: mutationKey(),
  });
  return (
    <section className="management-page">
      <PageHeader title="插件分配" description="对比期望与实际状态，通过可审计 Job 触发调谐。" />
      <AsyncBoundary loading={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        <DataTable caption="插件分配状态" rows={assignments.map((item) => ({ ...item, id: item.assignmentId }))} columns={[
          { key: 'assignmentId', header: '分配' }, { key: 'hostId', header: '主机' },
          { key: 'desiredState', header: '期望', render: (row) => `${row.desiredState} / ${row.desiredVersion}` },
          { key: 'observedState', header: '实际', render: (row) => row.observedState ? `${row.observedState.processState} / ${row.observedState.installedVersion ?? '未安装'}` : '未观测' },
          { key: 'reconcileState', header: '偏差', render: (row) => <><StatusTag status={row.reconcileState} tone={row.reconcileState === 'converged' ? 'success' : 'warning'} />{row.reconcileReason ? <small className="truth-warning">{row.reconcileReason}</small> : null}</> },
          { key: 'operationRevision', header: '电路/实例', render: (row) => <>{row.observedState?.circuitState ?? '未知'}<br />{row.observedState?.boundInstanceCount ?? 0} 个实例</> },
          { key: 'etag', header: '操作', render: (row) => canManage ? <div className="row-actions">{(['deploy', 'stop', 'upgrade', 'rollback'] as AssignmentAction[]).map((action) => {
            const label = { deploy: '部署', stop: '停止', upgrade: '升级', rollback: '回滚' }[action];
            return <button key={action} type="button" aria-label={`${label} ${row.assignmentId}`} onClick={() => setSelection({ action, assignment: row })}>{label}</button>;
          })}</div> : <span className="muted">无部署权限</span> },
        ]} />
        {query.hasNextPage ? <button type="button" onClick={() => void query.fetchNextPage()}>加载更多分配</button> : null}
      </AsyncBoundary>
      <AsyncBoundary error={change.error} />
      {change.data ? <JobState api={api} assignmentId={change.data.updated.assignmentId} jobId={change.data.job.id} canView={canViewJobs} /> : null}
      <RolloutDialog action={selection?.action} assignment={selection?.assignment} onCancel={() => setSelection(undefined)} onConfirm={(value) => {
        if (!selection) return;
        run(selection.assignment, value);
        setSelection(undefined);
      }} />
    </section>
  );
}
