import React from 'react';
import type { Job, ManagedDatabaseInstance } from '../../../../generated/api/dist/index.js';
import { PermissionGate } from '../../components/PermissionGate';
import { StatusTag } from '../../components/StatusTag';

export function ConnectionTestPanel({ instance, job, pending, tracking, onTest }: { instance: ManagedDatabaseInstance; job?: Job; pending: boolean; tracking: boolean; onTest(): void }) {
  return (
    <article className="panel">
      <header className="panel-header"><div><h2>连接测试</h2><p>测试通过 Agent 执行，仅使用已配置的凭据引用。</p></div><PermissionGate permission="database-instances:test" fallback={<span className="muted">无连接测试权限</span>}><button type="button" disabled={pending} onClick={onTest}>{pending ? '正在下发…' : '测试连接'}</button></PermissionGate></header>
      <dl><dt>最近状态</dt><dd><StatusTag status={instance.connectionTestStatus} tone={instance.connectionTestStatus === 'succeeded' ? 'success' : instance.connectionTestStatus === 'not_tested' || instance.connectionTestStatus === 'pending' ? 'neutral' : 'danger'} /></dd><dt>最近测试</dt><dd>{instance.connectionTestAt?.toLocaleString() ?? '尚未测试'}</dd></dl>
      {job ? <div role="status" className="job-progress"><strong>{job.status}</strong><span>{job.progress.completedTargets} / {job.progress.totalTargets}</span></div> : null}
      {job && !tracking && !['succeeded', 'failed', 'cancelled', 'timed_out'].includes(job.status) ? <p className="notice notice--warning">没有查看任务进度的权限，仅显示任务创建时状态。</p> : null}
    </article>
  );
}
