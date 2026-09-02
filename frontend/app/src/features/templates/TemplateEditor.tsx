import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import type { DefaultApi, MetricTemplateRevision, MetricValueType } from '../../../../generated/api/dist/index.js';
import { mutationKey } from '../../api/client';
import { useProjectContext } from '../../auth/AuthProvider';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { DataTable } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { StatusTag } from '../../components/StatusTag';
import { ApprovalDrawer } from './ApprovalDrawer';
import { useTemplatesApi } from './api';
import { PublishDialog } from './PublishDialog';
import {
  useApproveRevision, useCreateRevision, usePublishRevision, useTemplateRevisions, useTrialJob, useTrialRevision, useValidateRevision,
} from './queries';
import { TrialPanel } from './TrialPanel';

function isConflict(error: unknown) {
  return Boolean(error && typeof error === 'object' && (error as { response?: unknown }).response instanceof Response && (error as { response: Response }).response.status === 409);
}

export function TemplateEditor({ templateId, api: override }: { templateId: string; api?: DefaultApi }) {
  const project = useProjectContext();
  const location = useLocation();
  const api = useTemplatesApi(override);
  const canView = project.permissions.has('metric-templates:view');
  const canManage = project.permissions.has('metric-templates:manage');
  const canApprove = project.permissions.has('metric-templates:approve');
  const canViewJobs = project.permissions.has('platform.jobs.read');
  const revisionsQuery = useTemplateRevisions(api, project, templateId, canView);
  const createRevision = useCreateRevision(api, project, templateId);
  const validateRevision = useValidateRevision(api, project, templateId);
  const trialRevision = useTrialRevision(api, project, templateId);
  const approveRevision = useApproveRevision(api, project, templateId);
  const publishRevision = usePublishRevision(api, project, templateId);
  const [statement, setStatement] = React.useState('');
  const [variants, setVariants] = React.useState('');
  const [metricSourceColumn, setMetricSourceColumn] = React.useState('');
  const [metricName, setMetricName] = React.useState('');
  const [metricType, setMetricType] = React.useState<MetricValueType>('gauge');
  const [metricUnit, setMetricUnit] = React.useState('1');
  const [labelSourceColumn, setLabelSourceColumn] = React.useState('');
  const [labelName, setLabelName] = React.useState('');
  const [trialTarget, setTrialTarget] = React.useState<MetricTemplateRevision>();
  const [approvalTarget, setApprovalTarget] = React.useState<MetricTemplateRevision>();
  const [publication, setPublication] = React.useState<{ revision: MetricTemplateRevision; rollback: boolean }>();
  const revisions = revisionsQuery.data?.pages.flatMap((page) => page.items) ?? [];
  const latestRevision = revisions.reduce<MetricTemplateRevision | undefined>((latest, item) => !latest || item.revision > latest.revision ? item : latest, undefined);
  const routeFamily = typeof location.state === 'object' && location.state !== null && 'databaseFamily' in location.state && typeof location.state.databaseFamily === 'string'
    ? location.state.databaseFamily
    : '';
  const initializedFor = React.useRef('');
  React.useEffect(() => {
    if (initializedFor.current === templateId || !latestRevision && !routeFamily) return;
    initializedFor.current = templateId;
    setVariants(latestRevision ? [...latestRevision.variants].join(',') : routeFamily);
    const valueMapping = latestRevision?.valueMappings[0];
    setMetricSourceColumn(valueMapping?.sourceColumn ?? '');
    setMetricName(valueMapping?.metricName ?? '');
    setMetricType(valueMapping?.metricType ?? 'gauge');
    setMetricUnit(valueMapping?.unit ?? '1');
    const labelMapping = latestRevision?.labelMappings[0];
    setLabelSourceColumn(labelMapping?.sourceColumn ?? '');
    setLabelName(labelMapping?.label ?? '');
  }, [latestRevision, routeFamily, templateId]);
  const trialJob = useTrialJob(api, project, trialRevision.data?.revision.revisionId ?? '', trialRevision.data?.job.id, canViewJobs);
  if (!canView) return <section className="management-page"><PageHeader title="指标模板详情" /><p role="alert" className="notice">没有查看指标模板详情的权限。</p></section>;
  return (
    <section className="management-page">
      <Link to="/metric-templates">← 返回指标模板</Link>
      <PageHeader title={templateId} description="SQL 仅作为纯文本提交给服务端与插件校验，浏览器不执行 SQL。" />
      {canManage ? <form className="panel form-stack" onSubmit={(event) => {
        event.preventDefault();
        const variantSet = new Set(variants.split(',').map((item) => item.trim()).filter(Boolean));
        if (!statement.trim() || variantSet.size === 0 || !metricSourceColumn.trim() || !metricName.trim() || !metricUnit.trim() || Boolean(labelSourceColumn.trim()) !== Boolean(labelName.trim())) return;
        createRevision.mutate({ idempotencyKey: mutationKey(), body: {
          variants: variantSet, name: latestRevision?.name ?? templateId, queryKind: 'sql', readOnlyStatement: statement.trim(), collectionIntervalSeconds: 60,
          timeoutSeconds: 5, maxRows: 10, maxColumns: 4,
          valueMappings: [{ sourceColumn: metricSourceColumn.trim(), metricName: metricName.trim(), metricType, unit: metricUnit.trim() }],
          labelMappings: labelSourceColumn.trim() && labelName.trim() ? [{ sourceColumn: labelSourceColumn.trim(), label: labelName.trim() }] : [], cardinalityLimit: 100,
        } });
      }}>
        <h2>新建修订</h2>
        <label>SQL 语句<textarea aria-label="SQL 语句" rows={8} value={statement} onChange={(event) => setStatement(event.target.value)} spellCheck={false} /></label>
        <label>数据库变体<input aria-label="数据库变体" value={variants} onChange={(event) => setVariants(event.target.value)} placeholder="mysql,mariadb" /></label>
        <label>指标源列<input aria-label="指标源列" value={metricSourceColumn} onChange={(event) => setMetricSourceColumn(event.target.value)} /></label>
        <label>指标名称<input aria-label="指标名称" value={metricName} onChange={(event) => setMetricName(event.target.value)} placeholder="mysql.connections.current" /></label>
        <label>指标类型<select aria-label="指标类型" value={metricType} onChange={(event) => setMetricType(event.target.value as MetricValueType)}><option value="gauge">gauge</option><option value="monotonic_gauge">monotonic_gauge</option><option value="counter">counter</option><option value="monotonic_counter">monotonic_counter</option></select></label>
        <label>指标单位<select aria-label="指标单位" value={metricUnit} onChange={(event) => setMetricUnit(event.target.value)}><option value="1">1</option><option value="By">By</option><option value="s">s</option><option value="ms">ms</option><option value="us">us</option><option value="ns">ns</option><option value="%">%</option></select></label>
        <label>标签源列（可选）<input aria-label="标签源列" value={labelSourceColumn} onChange={(event) => setLabelSourceColumn(event.target.value)} /></label>
        <label>标签名称（可选）<input aria-label="标签名称" value={labelName} onChange={(event) => setLabelName(event.target.value)} /></label>
        <button type="submit" disabled={!statement.trim() || !variants.trim() || !metricSourceColumn.trim() || !metricName.trim() || !metricUnit.trim() || Boolean(labelSourceColumn.trim()) !== Boolean(labelName.trim()) || createRevision.isPending}>保存新修订</button>
      </form> : null}
      <AsyncBoundary loading={revisionsQuery.isPending} error={revisionsQuery.error ?? createRevision.error} onRetry={() => void revisionsQuery.refetch()}>
        <DataTable caption="指标模板修订" rows={revisions.map((item) => ({ ...item, id: item.revisionId }))} columns={[
          { key: 'revision', header: '修订' },
          { key: 'status', header: '状态', render: (row) => <StatusTag status={row.status} tone={row.status === 'published' ? 'success' : row.status.endsWith('failed') || row.status === 'rejected' ? 'danger' : 'neutral'} /> },
          { key: 'queryDigest', header: '查询摘要' },
          { key: 'valueMappings', header: '映射', render: (row) => `${row.valueMappings.length} 个指标 / ${row.labelMappings.length} 个标签` },
          { key: 'etag', header: '操作', render: (row) => <div className="row-actions">
            {canManage && (row.status === 'draft' || row.status === 'validation_failed') ? <button type="button" aria-label={`校验 ${row.revisionId}`} onClick={() => validateRevision.mutate({ revision: row, idempotencyKey: mutationKey() })}>校验</button> : null}
            {canManage && row.status === 'validated' ? <button type="button" aria-label={`试运行 ${row.revisionId}`} onClick={() => setTrialTarget(row)}>试运行</button> : null}
            {canApprove && (row.status === 'trial_passed' || row.status === 'approval_pending') ? <button type="button" aria-label={`审批 ${row.revisionId}`} onClick={() => setApprovalTarget(row)}>审批</button> : null}
            {canApprove && row.status === 'approved' ? <button type="button" aria-label={`发布 ${row.revisionId}`} onClick={() => setPublication({ revision: row, rollback: false })}>发布</button> : null}
            {canApprove && row.status === 'superseded' ? <button type="button" aria-label={`回滚到 ${row.revisionId}`} onClick={() => setPublication({ revision: row, rollback: true })}>回滚</button> : null}
          </div> },
        ]} />
        {revisionsQuery.hasNextPage ? <button type="button" onClick={() => void revisionsQuery.fetchNextPage()}>加载更多修订</button> : null}
      </AsyncBoundary>
      <AsyncBoundary error={validateRevision.error ?? trialRevision.error ?? publishRevision.error} />
      {approveRevision.error ? <p role="alert">{isConflict(approveRevision.error) ? '不能审批自己创建的修订' : '审批失败，请稍后重试'}</p> : null}
      <TrialPanel revision={trialTarget} resultRevision={trialRevision.data?.revision} pending={trialRevision.isPending} job={trialJob.data ?? trialRevision.data?.job} onCancel={() => setTrialTarget(undefined)} onConfirm={(instanceId, pluginVersionId) => {
        if (!trialTarget) return;
        trialRevision.mutate({ revision: trialTarget, instanceId, pluginVersionId, idempotencyKey: mutationKey() });
        setTrialTarget(undefined);
      }} />
      {trialJob.error ? <><AsyncBoundary error={trialJob.error} /><p className="notice notice--warning">试运行任务状态可能已过期。</p></> : null}
      <ApprovalDrawer revision={approvalTarget} onCancel={() => setApprovalTarget(undefined)} onConfirm={(comment) => {
        if (!approvalTarget) return;
        approveRevision.mutate({ revision: approvalTarget, idempotencyKey: mutationKey(), comment });
        setApprovalTarget(undefined);
      }} />
      <PublishDialog revision={publication?.revision} rollback={publication?.rollback ?? false} onCancel={() => setPublication(undefined)} onConfirm={() => {
        if (!publication) return;
        publishRevision.mutate({ revision: publication.revision, idempotencyKey: mutationKey() });
        setPublication(undefined);
      }} />
    </section>
  );
}
