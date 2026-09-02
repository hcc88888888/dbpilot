import React from 'react';
import type { MetricTemplateRevision } from '../../../../generated/api/dist/index.js';
import { ConfirmDialog } from '../../components/ConfirmDialog';

export function ApprovalDrawer({ revision, onCancel, onConfirm }: { revision?: MetricTemplateRevision; onCancel(): void; onConfirm(comment?: string): void }) {
  const [comment, setComment] = React.useState('');
  React.useEffect(() => setComment(''), [revision?.revisionId]);
  return <ConfirmDialog open={Boolean(revision)} title="审批指标模板" confirmLabel="确认审批" onCancel={onCancel} onConfirm={() => onConfirm(comment.trim() || undefined)}>
    <p>创建者不得审批自己的修订，服务端会以经验证的操作者身份执行该规则。</p>
    <label>审批意见<input aria-label="审批意见" value={comment} onChange={(event) => setComment(event.target.value)} /></label>
  </ConfirmDialog>;
}
