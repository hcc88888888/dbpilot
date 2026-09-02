import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import type { DefaultApi, JobStatus, MetricTemplateRevision } from '../../../../generated/api/dist/index.js';
import type { ApiProjectScope } from '../../api/client';
import { retryScopedRequest, useScopedRequest } from '../../api/client';
import type { TemplateFilters } from './types';

const scopeKey = (scope: ApiProjectScope) => [scope.tenantId, scope.projectId] as const;
export const templateKeys = {
  all: (scope: ApiProjectScope) => ['metric-templates', ...scopeKey(scope)] as const,
  lists: (scope: ApiProjectScope) => ['metric-templates', ...scopeKey(scope), 'list'] as const,
  list: (scope: ApiProjectScope, filters: TemplateFilters) => ['metric-templates', ...scopeKey(scope), 'list', filters] as const,
  revisionsRoot: (scope: ApiProjectScope, templateId: string) => ['metric-templates', ...scopeKey(scope), 'revisions', templateId] as const,
  revisions: (scope: ApiProjectScope, templateId: string) => ['metric-templates', ...scopeKey(scope), 'revisions', templateId, 'list'] as const,
  job: (scope: ApiProjectScope, revisionId: string, jobId: string) => ['metric-templates', ...scopeKey(scope), 'job', revisionId, jobId] as const,
};

export function useTemplateList(api: DefaultApi, scope: ApiProjectScope, filters: TemplateFilters, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: templateKeys.list(scope, filters), initialPageParam: undefined as string | undefined,
    queryFn: ({ signal, pageParam }) => api.listMetricTemplates({ ...filters, cursor: pageParam, limit: 100 }, { signal }),
    getNextPageParam: (page) => page.page.hasMore ? page.page.nextCursor ?? undefined : undefined,
    retry: retryScopedRequest, enabled,
  });
}

export function useTemplateRevisions(api: DefaultApi, scope: ApiProjectScope, templateId: string, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: templateKeys.revisions(scope, templateId), initialPageParam: undefined as string | undefined,
    queryFn: ({ signal, pageParam }) => api.listMetricTemplateRevisions({ templateId, cursor: pageParam, limit: 100 }, { signal }),
    getNextPageParam: (page) => page.page.hasMore ? page.page.nextCursor ?? undefined : undefined,
    retry: retryScopedRequest, enabled: enabled && Boolean(templateId),
  });
}

export function useCreateTemplate(api: DefaultApi, scope: ApiProjectScope) {
  const queryClient = useQueryClient();
  const request = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedRequest,
    mutationFn: ({ body, idempotencyKey }: { body: Parameters<DefaultApi['createMetricTemplate']>[0]['createMetricTemplateRequest']; idempotencyKey: string }) => request((signal) => api.createMetricTemplate({
      idempotencyKey, createMetricTemplateRequest: body,
    }, { signal })),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: templateKeys.lists(scope) }),
  });
}

function refreshRevision(queryClient: ReturnType<typeof useQueryClient>, scope: ApiProjectScope, templateId: string) {
  return Promise.all([
    queryClient.invalidateQueries({ queryKey: templateKeys.revisionsRoot(scope, templateId) }),
    queryClient.invalidateQueries({ queryKey: templateKeys.lists(scope) }),
  ]);
}

export function useCreateRevision(api: DefaultApi, scope: ApiProjectScope, templateId: string) {
  const queryClient = useQueryClient();
  const request = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedRequest,
    mutationFn: ({ body, idempotencyKey }: { body: Parameters<DefaultApi['createMetricTemplateRevision']>[0]['createMetricTemplateRevisionRequest']; idempotencyKey: string }) => request((signal) => api.createMetricTemplateRevision({
      templateId, idempotencyKey, createMetricTemplateRevisionRequest: body,
    }, { signal })),
    onSuccess: () => refreshRevision(queryClient, scope, templateId),
  });
}

export function useValidateRevision(api: DefaultApi, scope: ApiProjectScope, templateId: string) {
  const queryClient = useQueryClient();
  const request = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedRequest,
    mutationFn: ({ revision, idempotencyKey }: { revision: MetricTemplateRevision; idempotencyKey: string }) => request((signal) => api.validateMetricTemplateRevision({
      revisionId: revision.revisionId, ifMatch: revision.etag, idempotencyKey,
    }, { signal })),
    onSuccess: () => refreshRevision(queryClient, scope, templateId),
  });
}

export function useTrialRevision(api: DefaultApi, scope: ApiProjectScope, templateId: string) {
  const queryClient = useQueryClient();
  const request = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedRequest,
    mutationFn: ({ revision, instanceId, pluginVersionId, idempotencyKey }: {
      revision: MetricTemplateRevision; instanceId: string; pluginVersionId: string; idempotencyKey: string;
    }) => request(async (signal) => ({ revision, job: await api.trialMetricTemplateRevision({
      revisionId: revision.revisionId, idempotencyKey, metricTemplateTrialRequest: { instanceId, pluginVersionId },
    }, { signal }) })),
    onSuccess: ({ revision, job }) => {
      queryClient.setQueryData(templateKeys.job(scope, revision.revisionId, job.id), job);
      return refreshRevision(queryClient, scope, templateId);
    },
  });
}

export function useApproveRevision(api: DefaultApi, scope: ApiProjectScope, templateId: string) {
  const queryClient = useQueryClient();
  const request = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedRequest,
    mutationFn: ({ revision, idempotencyKey, comment }: { revision: MetricTemplateRevision; idempotencyKey: string; comment?: string }) => request((signal) => api.approveMetricTemplateRevision({
      revisionId: revision.revisionId, ifMatch: revision.etag, idempotencyKey, metricTemplateApprovalRequest: { approvalComment: comment },
    }, { signal })),
    onSuccess: () => refreshRevision(queryClient, scope, templateId),
  });
}

export function usePublishRevision(api: DefaultApi, scope: ApiProjectScope, templateId: string) {
  const queryClient = useQueryClient();
  const request = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedRequest,
    mutationFn: ({ revision, idempotencyKey }: { revision: MetricTemplateRevision; idempotencyKey: string }) => request((signal) => api.publishMetricTemplateRevision({
      revisionId: revision.revisionId, ifMatch: revision.etag, idempotencyKey,
    }, { signal })),
    onSuccess: () => refreshRevision(queryClient, scope, templateId),
  });
}

const terminal = new Set<JobStatus>(['succeeded', 'failed', 'cancelled', 'timed_out']);

export function useTrialJob(api: DefaultApi, scope: ApiProjectScope, revisionId: string, jobId: string | undefined, enabled: boolean) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: templateKeys.job(scope, revisionId, jobId ?? ''),
    queryFn: ({ signal }) => api.getJob({ jobId: jobId! }, { signal }),
    retry: retryScopedRequest, enabled: enabled && Boolean(jobId),
    refetchInterval: (current) => {
      if (current.state.error) return false;
      const status = current.state.data?.status;
      return status && terminal.has(status) ? false : 2_000;
    },
  });
  React.useEffect(() => {
    if (!query.data || !terminal.has(query.data.status)) return;
    void queryClient.invalidateQueries({ queryKey: templateKeys.all(scope) });
  }, [query.data?.status, queryClient, scope.projectId, scope.tenantId]);
  return query;
}
