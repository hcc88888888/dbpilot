import { useInfiniteQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { AcceptDiscoveryCandidateRequest, DefaultApi, DiscoveryCandidate } from '../../../../generated/api/dist/index.js';
import type { ApiProjectScope } from '../../api/client';
import { retryScopedMutation, useScopedRequest } from '../../api/client';
import { hostKeys } from '../hosts/queries';
import { instanceKeys } from '../instances/queries';
import type { DiscoveryFilters } from './types';

const scopeKey = (scope: ApiProjectScope) => [scope.tenantId, scope.projectId] as const;
export const discoveryKeys = {
  all: (scope: ApiProjectScope) => ['discovery', ...scopeKey(scope)] as const,
  list: (scope: ApiProjectScope, filters: DiscoveryFilters) => ['discovery', ...scopeKey(scope), 'list', filters] as const,
  detail: (scope: ApiProjectScope, id: string) => ['discovery', ...scopeKey(scope), 'detail', id] as const,
};

export function useCandidateList(api: DefaultApi, scope: ApiProjectScope, filters: DiscoveryFilters, enabled = true) {
  return useInfiniteQuery({
    queryKey: discoveryKeys.list(scope, filters),
    initialPageParam: undefined as string | undefined,
    queryFn: ({ signal, pageParam }) => api.listDiscoveryCandidates({ ...filters, cursor: pageParam, limit: 100 }, { signal }),
    getNextPageParam: (lastPage) => lastPage.page.hasMore ? lastPage.page.nextCursor ?? undefined : undefined,
    enabled,
  });
}

export function useIgnoreCandidate(api: DefaultApi, scope: ApiProjectScope) {
  const queryClient = useQueryClient();
  const request = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedMutation,
    mutationFn: ({ candidate, idempotencyKey }: { candidate: DiscoveryCandidate; idempotencyKey: string }) => request((signal) => api.ignoreDiscoveryCandidate({
      candidateId: candidate.candidateId, idempotencyKey, ignoreDiscoveryCandidateRequest: { reasonCode: 'operator_ignored' },
    }, { signal })),
    onSuccess: (candidate) => {
      queryClient.setQueryData(discoveryKeys.detail(scope, candidate.candidateId), candidate);
      return queryClient.invalidateQueries({ queryKey: discoveryKeys.all(scope) });
    },
  });
}

export function useAcceptCandidate(api: DefaultApi, scope: ApiProjectScope) {
  const queryClient = useQueryClient();
  const scopedRequest = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedMutation,
    mutationFn: ({ candidate, request, idempotencyKey }: { candidate: DiscoveryCandidate; request: AcceptDiscoveryCandidateRequest; idempotencyKey: string }) => scopedRequest((signal) => api.acceptDiscoveryCandidate({
      candidateId: candidate.candidateId,
      idempotencyKey,
      ifMatch: candidate.etag,
      acceptDiscoveryCandidateRequest: request,
    }, { signal })),
    onSuccess: (instance, variables) => {
      void queryClient.removeQueries({ queryKey: discoveryKeys.detail(scope, variables.candidate.candidateId), exact: true });
      queryClient.setQueryData(instanceKeys.detail(scope, instance.instanceId), instance);
      return Promise.all([
        queryClient.invalidateQueries({ queryKey: discoveryKeys.all(scope) }),
        queryClient.invalidateQueries({ queryKey: instanceKeys.lists(scope) }),
        queryClient.invalidateQueries({ queryKey: hostKeys.instances(scope, variables.candidate.hostId), exact: true }),
      ]);
    },
  });
}
