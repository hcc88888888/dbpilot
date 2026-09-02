export type {
  DatabaseManagementStatus,
  Job,
  ManagedDatabaseInstance,
  UpdateDatabaseInstanceRequest,
} from '../../../../generated/api/dist/index.js';

export type InstanceFilters = {
  hostId?: string;
  databaseFamily?: string;
  status?: import('../../../../generated/api/dist/index.js').DatabaseManagementStatus;
};
