import React from 'react';
import type { PluginAssignment } from '../../../../generated/api/dist/index.js';
import { ConfirmDialog } from '../../components/ConfirmDialog';
import type { AssignmentAction, AssignmentChange } from './types';

const labels: Record<AssignmentAction, string> = { deploy: '部署', stop: '停止', upgrade: '升级', rollback: '回滚' };

export function RolloutDialog({ action, assignment, onCancel, onConfirm }: {
  action?: AssignmentAction; assignment?: PluginAssignment; onCancel(): void; onConfirm(change: AssignmentChange): void;
}) {
  const [version, setVersion] = React.useState('');
  React.useEffect(() => {
    if (!action || !assignment) return;
    setVersion(action === 'rollback' ? assignment.observedState?.installedVersion ?? '' : assignment.desiredVersion);
  }, [action, assignment]);
  if (!assignment) return null;
  const label = action ? labels[action] : '';
  return (
    <ConfirmDialog open={Boolean(action)} title={`${label}插件`} confirmLabel={`确认${label}`} onCancel={onCancel} onConfirm={() => {
      if (!action) return;
      if (action === 'stop') onConfirm({ desiredState: 'stopped' });
      else onConfirm({ desiredState: 'running', ...(action === 'upgrade' || action === 'rollback' ? { desiredVersion: version.trim() } : {}) });
    }}>
      <p>分配 {assignment.assignmentId} 的期望状态将被更新，随后创建调谐任务。</p>
      {action === 'upgrade' || action === 'rollback' ? <label>目标版本<input aria-label="目标版本" value={version} onChange={(event) => setVersion(event.target.value)} /></label> : null}
    </ConfirmDialog>
  );
}
