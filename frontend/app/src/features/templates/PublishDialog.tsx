import React from 'react';
import type { MetricTemplateRevision } from '../../../../generated/api/dist/index.js';
import { ConfirmDialog } from '../../components/ConfirmDialog';

export function PublishDialog({ revision, rollback, onCancel, onConfirm }: { revision?: MetricTemplateRevision; rollback: boolean; onCancel(): void; onConfirm(): void }) {
  const action = rollback ? '回滚' : '发布';
  return <ConfirmDialog open={Boolean(revision)} title={`${action}指标模板`} confirmLabel={`确认${action}`} onCancel={onCancel} onConfirm={onConfirm}>
    <p>{rollback ? '将已审批的历史修订重新发布为当前版本。' : '将已审批修订发布到匹配的插件分配。'}</p>
    {revision ? <p>{revision.revisionId} · {revision.queryDigest}</p> : null}
  </ConfirmDialog>;
}
