import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import type { DefaultApi, JobStatus } from '../../../../generated/api/dist/index.js';
import type { ApiProjectScope } from '../../api/client';
import { retryScopedMutation, useScopedRequest } from '../../api/client';
import type { InstanceFilters } from './types';

const scopeKey = (scope: ApiProjectScope) => [scope.tenantId, scope.projectId] as const;
export const instanceKeys = {
  all: (scope: ApiProjectScope) => ['instances', ...scopeKey(scope)] as const,
  lists: (scope: ApiProjectScope) => ['instances', ...scopeKey(scope), 'list'] as const,
  list: (scope: ApiProjectScope, filters: InstanceFilters) => ['instances', ...scopeKey(scope), 'list', filters] as const,
  detail: (scope: ApiProjectScope, id: string) => ['instances', ...scopeKey(scope), 'detail', id] as const,
  connectionJob: (scope: ApiProjectScope, id: string, jobId: string) => ['instances', ...scopeKey(scope), 'connection-job', id, jobId] as const,
};

export function useInstanceList(api: DefaultApi, scope: ApiProjectScope, filters: InstanceFilters, enabled = true) {
  return useInfiniteQuery({
    queryKey: instanceKeys.list(scope, filters),
    initialPageParam: undefined as string | undefined,
    queryFn: ({ signal, pageParam }) => api.listDatabaseInstances({ ...filters, cursor: pageParam, limit: 100 }, { signal }),
    getNextPageParam: (lastPage) => lastPage.page.hasMore ? lastPage.page.nextCursor ?? undefined : undefined,
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
  const request = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedMutation,
    mutationFn: (idempotencyKey: string) => request((signal) => api.testDatabaseInstanceConnection({ instanceId, idempotencyKey }, { signal })),
    onSuccess: (job) => {
      queryClient.setQueryData(instanceKeys.connectionJob(scope, instanceId, job.id), job);
      return queryClient.invalidateQueries({ queryKey: instanceKeys.detail(scope, instanceId), exact: true });
    },
  });
}

const terminalJobs = new Set<JobStatus>(['succeeded', 'failed', 'cancelled', 'timed_out']);

export function useConnectionJob(api: DefaultApi, scope: ApiProjectScope, instanceId: string, jobId: string | undefined, enabled: boolean) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: instanceKeys.connectionJob(scope, instanceId, jobId ?? ''),
    queryFn: ({ signal }) => api.getJob({ jobId: jobId! }, { signal }),
    enabled: enabled && Boolean(jobId),
    refetchInterval: (current) => {
      if (current.state.error) return false;
      const status = current.state.data?.status;
      return status && terminalJobs.has(status) ? false : 2_000;
    },
  });
  React.useEffect(() => {
    if (!query.data || !terminalJobs.has(query.data.status)) return;
    void queryClient.invalidateQueries({ queryKey: instanceKeys.detail(scope, instanceId), exact: true });
    void queryClient.invalidateQueries({ queryKey: instanceKeys.lists(scope) });
  }, [instanceId, query.data?.status, queryClient, scope.projectId, scope.tenantId]);
  return query;
}
