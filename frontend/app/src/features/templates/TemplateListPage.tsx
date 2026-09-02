import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import type { DefaultApi } from '../../../../generated/api/dist/index.js';
import { mutationKey } from '../../api/client';
import { useProjectContext } from '../../auth/AuthProvider';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { DataTable } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { useTemplatesApi } from './api';
import { useCreateTemplate, useTemplateList } from './queries';

export function TemplateListPage({ api: override }: { api?: DefaultApi }) {
  const project = useProjectContext();
  const api = useTemplatesApi(override);
  const navigate = useNavigate();
  const canView = project.permissions.has('metric-templates:view');
  const canManage = project.permissions.has('metric-templates:manage');
  const query = useTemplateList(api, project, {}, canView);
  const createTemplate = useCreateTemplate(api, project);
  const [templateId, setTemplateId] = React.useState('');
  const [databaseFamily, setDatabaseFamily] = React.useState('');
  const [name, setName] = React.useState('');
  const [description, setDescription] = React.useState('');
  const templates = query.data?.pages.flatMap((page) => page.items) ?? [];
  if (!canView) return <section className="management-page"><PageHeader title="指标模板" /><p role="alert" className="notice">没有查看指标模板的权限。</p></section>;
  return (
    <section className="management-page">
      <PageHeader title="指标模板" description="管理草稿、校验、试运行、审批与发布流程。" />
      {canManage ? <form className="panel form-stack" onSubmit={(event) => {
        event.preventDefault();
        if (!templateId.trim() || !databaseFamily.trim() || !name.trim()) return;
        createTemplate.mutate({
          idempotencyKey: mutationKey(), body: {
            templateId: templateId.trim(), databaseFamily: databaseFamily.trim(), name: name.trim(), description: description.trim() || undefined,
          },
        }, { onSuccess: (created) => navigate(`/metric-templates/${encodeURIComponent(created.templateId)}`, { state: { databaseFamily: created.databaseFamily } }) });
      }}>
        <h2>新建自定义指标模板</h2>
        <label>模板 ID<input aria-label="模板 ID" value={templateId} onChange={(event) => setTemplateId(event.target.value)} /></label>
        <label>数据库类型<input aria-label="数据库类型" value={databaseFamily} onChange={(event) => setDatabaseFamily(event.target.value)} /></label>
        <label>模板名称<input aria-label="模板名称" value={name} onChange={(event) => setName(event.target.value)} /></label>
        <label>模板描述<input aria-label="模板描述" value={description} onChange={(event) => setDescription(event.target.value)} /></label>
        <button type="submit" disabled={createTemplate.isPending || !templateId.trim() || !databaseFamily.trim() || !name.trim()}>创建指标模板</button>
        <AsyncBoundary error={createTemplate.error} />
      </form> : null}
      <AsyncBoundary loading={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        <DataTable caption="数据库指标模板" rows={templates.map((item) => ({ ...item, id: item.templateId }))} columns={[
          { key: 'name', header: '模板', render: (row) => <Link to={`/metric-templates/${encodeURIComponent(row.templateId)}`} state={{ databaseFamily: row.databaseFamily }}>{row.name}</Link> },
          { key: 'databaseFamily', header: '数据库' }, { key: 'builtin', header: '来源', render: (row) => row.builtin ? '系统内置' : '自定义' },
          { key: 'latestRevision', header: '最新修订' }, { key: 'publishedRevision', header: '已发布修订', render: (row) => row.publishedRevision ?? '未发布' },
        ]} />
        {query.hasNextPage ? <button type="button" onClick={() => void query.fetchNextPage()}>加载更多模板</button> : null}
      </AsyncBoundary>
    </section>
  );
}
