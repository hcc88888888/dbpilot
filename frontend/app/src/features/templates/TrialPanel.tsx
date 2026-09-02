import React from 'react';
import type { Job, MetricTemplateRevision } from '../../../../generated/api/dist/index.js';
import { ConfirmDialog } from '../../components/ConfirmDialog';

export function TrialPanel({ revision, resultRevision, job, pending, onCancel, onConfirm }: {
  revision?: MetricTemplateRevision; resultRevision?: MetricTemplateRevision; job?: Job; pending: boolean; onCancel(): void; onConfirm(instanceId: string, pluginVersionId: string): void;
}) {
  const [instanceId, setInstanceId] = React.useState('');
  const [pluginVersionId, setPluginVersionId] = React.useState('');
  React.useEffect(() => { if (revision) { setInstanceId(''); setPluginVersionId(''); } }, [revision?.revisionId]);
  return <>
    <ConfirmDialog open={Boolean(revision)} title="指标模板试运行" confirmLabel="确认试运行" onCancel={onCancel} onConfirm={() => {
      if (instanceId.trim() && pluginVersionId.trim()) onConfirm(instanceId.trim(), pluginVersionId.trim());
    }}>
      <div className="form-stack">
        <label>目标实例 ID<input aria-label="目标实例 ID" value={instanceId} onChange={(event) => setInstanceId(event.target.value)} /></label>
        <label>插件版本 ID<input aria-label="插件版本 ID" value={pluginVersionId} onChange={(event) => setPluginVersionId(event.target.value)} /></label>
      </div>
    </ConfirmDialog>
    {pending ? <p role="status">正在创建试运行任务…</p> : null}
    {job && resultRevision ? <article className="panel"><h2>试运行结果</h2><p>{resultRevision.valueMappings.length} 个候选指标</p><p>{resultRevision.labelMappings.length} 个标签</p><div role="status" className="job-progress"><strong>{job.status}</strong><span>{job.progress.completedTargets} / {job.progress.totalTargets}</span></div></article> : null}
  </>;
}
