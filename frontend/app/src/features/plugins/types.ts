import type { PluginAssignment, PluginDesiredState, PluginVersionStatus } from '../../../../generated/api/dist/index.js';

export type PluginDefinitionFilters = { databaseFamily?: string };
export type PluginVersionFilters = { pluginId?: string; status?: PluginVersionStatus };
export type PluginAssignmentFilters = { hostId?: string; pluginId?: string };
export type AssignmentAction = 'deploy' | 'stop' | 'upgrade' | 'rollback';
export type AssignmentChange = {
  desiredVersion?: string;
  desiredState?: PluginDesiredState;
  rolloutPercentage?: number;
};

export function assignmentActions(assignment: PluginAssignment): AssignmentAction[] {
  const processState = assignment.observedState?.processState;
  const observedInactive = !processState || processState === 'absent' || processState === 'stopped' || processState === 'installed';
  if (assignment.desiredState === 'absent' || assignment.desiredState === 'stopped' || assignment.desiredState === 'installed') {
    return observedInactive ? ['deploy'] : [];
  }
  if (observedInactive) return ['deploy'];
  const actions: AssignmentAction[] = ['stop'];
  const installedVersion = assignment.observedState?.installedVersion?.trim();
  if (installedVersion) actions.push('upgrade');
  if (installedVersion && installedVersion !== assignment.desiredVersion) actions.push('rollback');
  return actions;
}
