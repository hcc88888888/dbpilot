import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { AcceptDiscoveryCandidateRequest, DefaultApi, DiscoveryCandidate } from '../../../../generated/api/dist/index.js';
import { mutationKey, type ApiProjectScope } from '../../api/client';
import type { DiscoveryFilters } from './types';

const scopeKey = (scope: ApiProjectScope) => [scope.tenantId, scope.projectId] as const;
export const discoveryKeys = {
  all: (scope: ApiProjectScope) => ['discovery', ...scopeKey(scope)] as const,
  list: (scope: ApiProjectScope, filters: DiscoveryFilters) => ['discovery', ...scopeKey(scope), 'list', filters] as const,
  detail: (scope: ApiProjectScope, id: string) => ['discovery', ...scopeKey(scope), 'detail', id] as const,
};

export function useCandidateList(api: DefaultApi, scope: ApiProjectScope, filters: DiscoveryFilters, enabled = true) {
  return useQuery({
    queryKey: discoveryKeys.list(scope, filters),
    queryFn: ({ signal }) => api.listDiscoveryCandidates({ ...filters, limit: 100 }, { signal }),
    enabled,
  });
}

export function useIgnoreCandidate(api: DefaultApi, scope: ApiProjectScope, filters: DiscoveryFilters) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (candidate: DiscoveryCandidate) => api.ignoreDiscoveryCandidate({
      candidateId: candidate.candidateId,
      idempotencyKey: mutationKey(),
      ignoreDiscoveryCandidateRequest: { reasonCode: 'operator_ignored' },
    }),
    onSuccess: (candidate) => {
      queryClient.setQueryData(discoveryKeys.detail(scope, candidate.candidateId), candidate);
      return queryClient.invalidateQueries({ queryKey: discoveryKeys.list(scope, filters), exact: true });
    },
  });
}

export function useAcceptCandidate(api: DefaultApi, scope: ApiProjectScope, filters: DiscoveryFilters) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ candidate, request }: { candidate: DiscoveryCandidate; request: AcceptDiscoveryCandidateRequest }) => api.acceptDiscoveryCandidate({
      candidateId: candidate.candidateId,
      idempotencyKey: mutationKey(),
      ifMatch: candidate.etag,
      acceptDiscoveryCandidateRequest: request,
    }),
    onSuccess: (_instance, variables) => {
      void queryClient.removeQueries({ queryKey: discoveryKeys.detail(scope, variables.candidate.candidateId), exact: true });
      return queryClient.invalidateQueries({ queryKey: discoveryKeys.list(scope, filters), exact: true });
    },
  });
}
