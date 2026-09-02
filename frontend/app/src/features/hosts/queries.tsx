import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import type { DefaultApi } from '../../../../generated/api/dist/index.js';
import type { ApiProjectScope } from '../../api/client';
import type { HostFilters } from './types';

const scopeKey = (scope: ApiProjectScope) => [scope.tenantId, scope.projectId] as const;

export const hostKeys = {
  all: (scope: ApiProjectScope) => ['hosts', ...scopeKey(scope)] as const,
  list: (scope: ApiProjectScope, filters: HostFilters) => ['hosts', ...scopeKey(scope), 'list', filters] as const,
  detail: (scope: ApiProjectScope, hostId: string) => ['hosts', ...scopeKey(scope), 'detail', hostId] as const,
  instances: (scope: ApiProjectScope, hostId: string) => ['hosts', ...scopeKey(scope), 'instances', hostId] as const,
};

export function useHostList(api: DefaultApi, scope: ApiProjectScope, filters: HostFilters, enabled = true) {
  return useInfiniteQuery({
    queryKey: hostKeys.list(scope, filters),
    initialPageParam: undefined as string | undefined,
    queryFn: ({ signal, pageParam }) => api.listHosts({ ...filters, cursor: pageParam, limit: 100 }, { signal }),
    getNextPageParam: (lastPage) => lastPage.page.hasMore ? lastPage.page.nextCursor ?? undefined : undefined,
    enabled,
  });
}

export function useHost(api: DefaultApi, scope: ApiProjectScope, hostId: string, enabled = true) {
  return useQuery({
    queryKey: hostKeys.detail(scope, hostId),
    queryFn: ({ signal }) => api.getHost({ hostId }, { signal }),
    enabled: enabled && Boolean(hostId),
  });
}

export function useHostInstances(api: DefaultApi, scope: ApiProjectScope, hostId: string, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: hostKeys.instances(scope, hostId),
    initialPageParam: undefined as string | undefined,
    queryFn: ({ signal, pageParam }) => api.listDatabaseInstances({ hostId, cursor: pageParam, limit: 100 }, { signal }),
    getNextPageParam: (lastPage) => lastPage.page.hasMore ? lastPage.page.nextCursor ?? undefined : undefined,
    enabled: enabled && Boolean(hostId),
  });
}
