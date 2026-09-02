import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { DefaultApi } from '../../../../generated/api/dist/index.js';
import { mutationKey, type ApiProjectScope } from '../../api/client';
import type { InstanceFilters } from './types';

const scopeKey = (scope: ApiProjectScope) => [scope.tenantId, scope.projectId] as const;
export const instanceKeys = {
  all: (scope: ApiProjectScope) => ['instances', ...scopeKey(scope)] as const,
  list: (scope: ApiProjectScope, filters: InstanceFilters) => ['instances', ...scopeKey(scope), 'list', filters] as const,
  detail: (scope: ApiProjectScope, id: string) => ['instances', ...scopeKey(scope), 'detail', id] as const,
  connectionJob: (scope: ApiProjectScope, id: string) => ['instances', ...scopeKey(scope), 'connection-job', id] as const,
};

export function useInstanceList(api: DefaultApi, scope: ApiProjectScope, filters: InstanceFilters, enabled = true) {
  return useQuery({
    queryKey: instanceKeys.list(scope, filters),
    queryFn: ({ signal }) => api.listDatabaseInstances({ ...filters, limit: 100 }, { signal }),
    enabled,
  });
}

export function useInstance(api: DefaultApi, scope: ApiProjectScope, instanceId: string, enabled = true) {
  return useQuery({
    queryKey: instanceKeys.detail(scope, instanceId),
    queryFn: ({ signal }) => api.getDatabaseInstance({ instanceId }, { signal }),
    enabled: enabled && Boolean(instanceId),
  });
}

export function useConnectionTest(api: DefaultApi, scope: ApiProjectScope, instanceId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => api.testDatabaseInstanceConnection({ instanceId, idempotencyKey: mutationKey() }),
    onSuccess: (job) => {
      queryClient.setQueryData(instanceKeys.connectionJob(scope, instanceId), job);
      return queryClient.invalidateQueries({ queryKey: instanceKeys.detail(scope, instanceId), exact: true });
    },
  });
}
