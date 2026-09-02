import React from 'react';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { Route, Routes, useParams } from 'react-router-dom';
import type { DefaultApi, Job, MetricTemplate, MetricTemplateRevision } from '../../../../generated/api/dist/index.js';
import { renderFeature } from '../../test/renderFeature';
import { TemplateEditor } from './TemplateEditor';
import { TemplateListPage } from './TemplateListPage';
import { templateKeys } from './queries';

const template: MetricTemplate = {
  templateId: 'mysql-connections', databaseFamily: 'mysql', name: 'MySQL Connections', description: 'Connection health', builtin: false,
  latestRevision: 2, publishedRevision: 1, createdAt: new Date('2026-09-01T00:00:00Z'),
};

const revision: MetricTemplateRevision = {
  revisionId: 'revision-2', templateId: 'mysql-connections', revision: 2, databaseFamily: 'mysql', variants: new Set(['mysql']),
  name: 'MySQL Connections', queryKind: 'sql', collectionIntervalSeconds: 60, timeoutSeconds: 5, maxRows: 10, maxColumns: 4,
  valueMappings: [
    { sourceColumn: 'threads_connected', metricName: 'mysql_threads_connected', metricType: 'gauge', unit: '1' },
    { sourceColumn: 'max_connections', metricName: 'mysql_max_connections', metricType: 'gauge', unit: '1' },
  ],
  labelMappings: [{ sourceColumn: 'instance', label: 'instance' }], cardinalityLimit: 100, createdBy: 'author-a', approvedBy: null,
  queryDigest: 'd'.repeat(64), status: 'trial_passed', createdAt: new Date('2026-09-01T01:00:00Z'), etag: '"revision-2"',
};

const oldRevision: MetricTemplateRevision = {
  ...revision, revisionId: 'revision-1', revision: 1, status: 'superseded', approvedBy: 'reviewer-b', etag: '"revision-1"',
};
const draftRevision: MetricTemplateRevision = { ...revision, revisionId: 'revision-draft', revision: 3, status: 'draft', etag: '"revision-draft"' };
const validatedRevision: MetricTemplateRevision = { ...revision, revisionId: 'revision-validated', revision: 4, status: 'validated', etag: '"revision-validated"' };
const approvedRevision: MetricTemplateRevision = { ...revision, revisionId: 'revision-approved', revision: 5, status: 'approved', approvedBy: 'reviewer-b', etag: '"revision-approved"' };

const job: Job = {
  id: 'trial-job-1', type: 'metric_template.trial', status: 'queued', outcome: 'none', tenantId: 'tenant-a', projectId: 'project-a', instanceId: 'instance-1',
  sourceResource: { resourceType: 'metric_template_revision', resourceId: 'revision-2' }, version: 1,
  progress: { totalTargets: 1, completedTargets: 0, failedTargets: 0, skippedTargets: 0 }, artifacts: [],
  resultSummary: 'RAW_ROW password=do-not-render', createdAt: new Date('2026-09-01T02:00:00Z'), requestId: 'request-1', traceId: 'trace-1',
};

function templateApi() {
  return {
    listMetricTemplates: vi.fn(async () => ({ items: [template], page: { limit: 100, hasMore: false } })),
    createMetricTemplate: vi.fn(async ({ createMetricTemplateRequest }) => ({ ...template, ...createMetricTemplateRequest, latestRevision: 0, publishedRevision: null })),
    listMetricTemplateRevisions: vi.fn(async () => ({ items: [revision, oldRevision], page: { limit: 100, hasMore: false } })),
    createMetricTemplateRevision: vi.fn(async () => revision),
    validateMetricTemplateRevision: vi.fn(async () => ({ ...revision, status: 'validated' })),
    trialMetricTemplateRevision: vi.fn(async () => job),
    approveMetricTemplateRevision: vi.fn(async () => ({ ...revision, status: 'approved', approvedBy: 'reviewer-b' })),
    publishMetricTemplateRevision: vi.fn(async ({ revisionId }) => ({ ...(revisionId === oldRevision.revisionId ? oldRevision : revision), status: 'published' })),
    getJob: vi.fn(async () => ({ ...job, status: 'succeeded', outcome: 'complete', progress: { ...job.progress, completedTargets: 1 } })),
  } as unknown as DefaultApi;
}

function TemplateEditorRouteForTest({ api }: { api: DefaultApi }) {
  const { id = '' } = useParams();
  return <TemplateEditor templateId={id} api={api} />;
}

describe('Metric template management pages', () => {
  it('fails closed without requesting templates or revisions', async () => {
    const client = templateApi();
    renderFeature(<><TemplateListPage api={client} /><TemplateEditor templateId="mysql-connections" api={client} /></>, []);

    expect(await screen.findByText('没有查看指标模板的权限。')).not.toBeNull();
    expect(screen.getByText('没有查看指标模板详情的权限。')).not.toBeNull();
    expect(client.listMetricTemplates).not.toHaveBeenCalled();
    expect(client.listMetricTemplateRevisions).not.toHaveBeenCalled();
  });

  it('shows template workflow status and loads opaque next cursors', async () => {
    const client = templateApi();
    client.listMetricTemplates = vi.fn(async (request) => request.cursor
      ? { items: [{ ...template, templateId: 'postgres-sessions', name: 'Postgres Sessions' }], page: { limit: 1, hasMore: false } }
      : { items: [template], page: { limit: 1, hasMore: true, nextCursor: 'opaque-template-cursor' } });
    renderFeature(<TemplateListPage api={client} />, ['metric-templates:view']);

    expect(await screen.findByText('MySQL Connections')).not.toBeNull();
    await userEvent.click(screen.getByRole('button', { name: '加载更多模板' }));
    expect(await screen.findByText('Postgres Sessions')).not.toBeNull();
    expect(client.listMetricTemplates).toHaveBeenLastCalledWith(expect.objectContaining({ cursor: 'opaque-template-cursor' }), expect.anything());
  });

  it('creates a custom template and enters its editor with a stable idempotency key', async () => {
    const client = templateApi();
    client.listMetricTemplateRevisions = vi.fn(async () => ({ items: [], page: { limit: 100, hasMore: false } }));
    renderFeature(<Routes><Route path="/metric-templates" element={<TemplateListPage api={client} />} /><Route path="/metric-templates/:id" element={<TemplateEditorRouteForTest api={client} />} /></Routes>, ['metric-templates:view', 'metric-templates:manage'], '/metric-templates');

    await userEvent.type(await screen.findByLabelText('模板 ID'), 'custom-mysql-health');
    await userEvent.type(screen.getByLabelText('数据库类型'), 'mysql');
    await userEvent.type(screen.getByLabelText('模板名称'), 'Custom MySQL Health');
    await userEvent.type(screen.getByLabelText('模板描述'), 'Internal health metrics');
    await userEvent.click(screen.getByRole('button', { name: '创建指标模板' }));

    await waitFor(() => expect(client.createMetricTemplate).toHaveBeenCalledWith(expect.objectContaining({
      idempotencyKey: expect.any(String),
      createMetricTemplateRequest: { templateId: 'custom-mysql-health', databaseFamily: 'mysql', name: 'Custom MySQL Health', description: 'Internal health metrics' },
    }), expect.objectContaining({ signal: expect.any(AbortSignal) })));
    expect(await screen.findByRole('heading', { name: 'custom-mysql-health' })).not.toBeNull();
  });

  it('edits SQL as inert plain text and creates a revision with stable bounded fields', async () => {
    const client = templateApi();
    renderFeature(<TemplateEditor templateId="mysql-connections" api={client} />, ['metric-templates:view', 'metric-templates:manage']);

    const editor = await screen.findByRole('textbox', { name: 'SQL 语句' });
    expect(editor.tagName).toBe('TEXTAREA');
    await userEvent.type(editor, 'SELECT threads_connected, instance FROM performance_schema.global_status');
    await userEvent.clear(screen.getByLabelText('数据库变体'));
    await userEvent.type(screen.getByLabelText('数据库变体'), 'mysql,mariadb');
    await userEvent.clear(screen.getByLabelText('指标源列'));
    await userEvent.type(screen.getByLabelText('指标源列'), 'threads_connected');
    await userEvent.clear(screen.getByLabelText('指标名称'));
    await userEvent.type(screen.getByLabelText('指标名称'), 'mysql.connections.current');
    await userEvent.selectOptions(screen.getByLabelText('指标单位'), '1');
    await userEvent.clear(screen.getByLabelText('标签源列'));
    await userEvent.type(screen.getByLabelText('标签源列'), 'instance');
    await userEvent.clear(screen.getByLabelText('标签名称'));
    await userEvent.type(screen.getByLabelText('标签名称'), 'instance');
    await userEvent.click(screen.getByRole('button', { name: '保存新修订' }));

    await waitFor(() => expect(client.createMetricTemplateRevision).toHaveBeenCalledWith(expect.objectContaining({
      templateId: 'mysql-connections', idempotencyKey: expect.any(String),
      createMetricTemplateRevisionRequest: expect.objectContaining({
        readOnlyStatement: 'SELECT threads_connected, instance FROM performance_schema.global_status', variants: new Set(['mysql', 'mariadb']),
        timeoutSeconds: 5, maxRows: 10, maxColumns: 4, cardinalityLimit: 100,
        valueMappings: [{ sourceColumn: 'threads_connected', metricName: 'mysql.connections.current', metricType: 'gauge', unit: '1' }],
        labelMappings: [{ sourceColumn: 'instance', label: 'instance' }],
      }),
    }), expect.objectContaining({ signal: expect.any(AbortSignal) })));
    expect(document.querySelector('iframe')).toBeNull();
    expect(document.querySelector('script')).toBeNull();
  });

  it('validates and trials a revision, showing metric counts and real job progress but no raw rows', async () => {
    const client = templateApi();
    client.listMetricTemplateRevisions = vi.fn(async () => ({ items: [draftRevision, validatedRevision], page: { limit: 100, hasMore: false } }));
    renderFeature(<TemplateEditor templateId="mysql-connections" api={client} />, ['metric-templates:view', 'metric-templates:manage', 'platform.jobs.read']);

    await userEvent.click(await screen.findByRole('button', { name: '校验 revision-draft' }));
    await waitFor(() => expect(client.validateMetricTemplateRevision).toHaveBeenCalledWith(expect.objectContaining({
      revisionId: 'revision-draft', ifMatch: '"revision-draft"', idempotencyKey: expect.any(String),
    }), expect.anything()));
    await userEvent.click(screen.getByRole('button', { name: '试运行 revision-validated' }));
    await userEvent.type(screen.getByLabelText('目标实例 ID'), 'instance-1');
    await userEvent.type(screen.getByLabelText('插件版本 ID'), 'plugin-version-1');
    await userEvent.click(screen.getByRole('button', { name: '确认试运行' }));

    expect(await screen.findByText('succeeded')).not.toBeNull();
    expect(screen.getByText('2 个候选指标')).not.toBeNull();
    expect(screen.getByText('1 个标签')).not.toBeNull();
    expect(document.body.textContent).not.toContain('RAW_ROW');
    expect(document.body.textContent).not.toContain('do-not-render');
  });

  it('keeps approval, publication and rollback distinct and lets the server reject self-approval', async () => {
    const client = templateApi();
    client.listMetricTemplateRevisions = vi.fn(async () => ({ items: [revision, approvedRevision, oldRevision], page: { limit: 100, hasMore: false } }));
    client.approveMetricTemplateRevision = vi.fn(async () => {
      throw Object.assign(new Error('self approval rejected'), { response: new Response(null, { status: 409 }) });
    });
    renderFeature(<TemplateEditor templateId="mysql-connections" api={client} />, ['metric-templates:view', 'metric-templates:approve']);

    await userEvent.click(await screen.findByRole('button', { name: '审批 revision-2' }));
    await userEvent.click(screen.getByRole('button', { name: '确认审批' }));
    expect((await screen.findByRole('alert')).textContent).toContain('不能审批自己创建的修订');
    expect(client.publishMetricTemplateRevision).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole('button', { name: '发布 revision-approved' }));
    await userEvent.click(screen.getByRole('button', { name: '确认发布' }));
    await waitFor(() => expect(client.publishMetricTemplateRevision).toHaveBeenCalledWith(expect.objectContaining({
      revisionId: 'revision-approved', ifMatch: '"revision-approved"', idempotencyKey: expect.any(String),
    }), expect.anything()));

    await userEvent.click(screen.getByRole('button', { name: '回滚到 revision-1' }));
    await userEvent.click(screen.getByRole('button', { name: '确认回滚' }));
    await waitFor(() => expect(client.publishMetricTemplateRevision).toHaveBeenCalledWith(expect.objectContaining({ revisionId: 'revision-1', ifMatch: '"revision-1"' }), expect.anything()));
  });

  it('keeps ETag and idempotency key stable across a retryable validation failure', async () => {
    const client = templateApi();
    client.listMetricTemplateRevisions = vi.fn(async () => ({ items: [draftRevision], page: { limit: 100, hasMore: false } }));
    client.validateMetricTemplateRevision = vi.fn()
      .mockRejectedValueOnce(new TypeError('network down'))
      .mockResolvedValueOnce({ ...revision, status: 'validated' });
    renderFeature(<TemplateEditor templateId="mysql-connections" api={client} />, ['metric-templates:view', 'metric-templates:manage']);

    await userEvent.click(await screen.findByRole('button', { name: '校验 revision-draft' }));
    await waitFor(() => expect(client.validateMetricTemplateRevision).toHaveBeenCalledTimes(2));
    const [first, second] = vi.mocked(client.validateMetricTemplateRevision).mock.calls;
    expect(second[0]).toEqual(first[0]);
    expect(first[0]).toEqual(expect.objectContaining({ revisionId: 'revision-draft', ifMatch: '"revision-draft"', idempotencyKey: expect.any(String) }));
  });

  it('stops and reports failed trial job polling without showing a fabricated result', async () => {
    const client = templateApi();
    client.listMetricTemplateRevisions = vi.fn(async () => ({ items: [validatedRevision], page: { limit: 100, hasMore: false } }));
    client.getJob = vi.fn(async () => { throw Object.assign(new Error('forbidden'), { response: new Response(null, { status: 403 }) }); });
    renderFeature(<TemplateEditor templateId="mysql-connections" api={client} />, ['metric-templates:view', 'metric-templates:manage', 'platform.jobs.read']);

    await userEvent.click(await screen.findByRole('button', { name: '试运行 revision-validated' }));
    await userEvent.type(screen.getByLabelText('目标实例 ID'), 'instance-1');
    await userEvent.type(screen.getByLabelText('插件版本 ID'), 'plugin-version-1');
    await userEvent.click(screen.getByRole('button', { name: '确认试运行' }));

    expect((await screen.findByRole('alert')).textContent).toContain('没有执行此操作的权限');
    expect(screen.getByText('试运行任务状态可能已过期。')).not.toBeNull();
    expect(client.getJob).toHaveBeenCalledTimes(1);
    await new Promise((resolve) => setTimeout(resolve, 2_100));
    expect(client.getJob).toHaveBeenCalledTimes(1);
    expect(document.body.textContent).not.toContain('RAW_ROW');
  });

  it('shows only state-valid template actions', async () => {
    const client = templateApi();
    client.listMetricTemplateRevisions = vi.fn(async () => ({ items: [draftRevision, validatedRevision, revision, approvedRevision, oldRevision], page: { limit: 100, hasMore: false } }));
    renderFeature(<TemplateEditor templateId="mysql-connections" api={client} />, ['metric-templates:view', 'metric-templates:manage', 'metric-templates:approve']);

    expect(await screen.findByRole('button', { name: '校验 revision-draft' })).not.toBeNull();
    expect(screen.queryByRole('button', { name: '试运行 revision-draft' })).toBeNull();
    expect(screen.getByRole('button', { name: '试运行 revision-validated' })).not.toBeNull();
    expect(screen.queryByRole('button', { name: '审批 revision-validated' })).toBeNull();
    expect(screen.getByRole('button', { name: '审批 revision-2' })).not.toBeNull();
    expect(screen.queryByRole('button', { name: '发布 revision-2' })).toBeNull();
    expect(screen.getByRole('button', { name: '发布 revision-approved' })).not.toBeNull();
    expect(screen.getByRole('button', { name: '回滚到 revision-1' })).not.toBeNull();
  });

  it('keeps template query keys isolated by tenant and project', () => {
    expect(templateKeys.revisions({ tenantId: 'tenant-a', projectId: 'project-a' }, 'template-1')).toEqual([
      'metric-templates', 'tenant-a', 'project-a', 'revisions', 'template-1', 'list',
    ]);
    expect(templateKeys.revisions({ tenantId: 'tenant-a', projectId: 'project-b' }, 'template-1')).not.toEqual(
      templateKeys.revisions({ tenantId: 'tenant-a', projectId: 'project-a' }, 'template-1'),
    );
  });
});
