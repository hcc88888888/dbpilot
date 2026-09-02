import type { PluginDesiredState, PluginVersionStatus } from '../../../../generated/api/dist/index.js';

export type PluginDefinitionFilters = { databaseFamily?: string };
export type PluginVersionFilters = { pluginId?: string; status?: PluginVersionStatus };
export type PluginAssignmentFilters = { hostId?: string; pluginId?: string };
export type AssignmentAction = 'deploy' | 'stop' | 'upgrade' | 'rollback';
export type AssignmentChange = {
  desiredVersion?: string;
  desiredState?: PluginDesiredState;
  rolloutPercentage?: number;
};
