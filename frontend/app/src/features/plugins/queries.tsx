import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import React from 'react';
import type { DefaultApi, JobStatus, PluginAssignment } from '../../../../generated/api/dist/index.js';
import type { ApiProjectScope } from '../../api/client';
import { retryScopedRequest, useScopedRequest } from '../../api/client';
import type { AssignmentChange, PluginAssignmentFilters, PluginDefinitionFilters, PluginVersionFilters } from './types';

const scopeKey = (scope: ApiProjectScope) => [scope.tenantId, scope.projectId] as const;
export const pluginKeys = {
  all: (scope: ApiProjectScope) => ['plugins', ...scopeKey(scope)] as const,
  definitionsRoot: (scope: ApiProjectScope) => ['plugins', ...scopeKey(scope), 'definitions'] as const,
  definitions: (scope: ApiProjectScope, filters: PluginDefinitionFilters) => ['plugins', ...scopeKey(scope), 'definitions', filters] as const,
  versionsRoot: (scope: ApiProjectScope) => ['plugins', ...scopeKey(scope), 'versions'] as const,
  versions: (scope: ApiProjectScope, filters: PluginVersionFilters) => ['plugins', ...scopeKey(scope), 'versions', filters] as const,
  assignmentsRoot: (scope: ApiProjectScope) => ['plugins', ...scopeKey(scope), 'assignments'] as const,
  assignments: (scope: ApiProjectScope, filters: PluginAssignmentFilters) => ['plugins', ...scopeKey(scope), 'assignments', filters] as const,
  assignment: (scope: ApiProjectScope, id: string) => ['plugins', ...scopeKey(scope), 'assignment', id] as const,
  job: (scope: ApiProjectScope, assignmentId: string, jobId: string) => ['plugins', ...scopeKey(scope), 'job', assignmentId, jobId] as const,
};

export function usePluginDefinitions(api: DefaultApi, scope: ApiProjectScope, filters: PluginDefinitionFilters, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: pluginKeys.definitions(scope, filters), initialPageParam: undefined as string | undefined,
    queryFn: ({ signal, pageParam }) => api.listPluginDefinitions({ ...filters, cursor: pageParam, limit: 100 }, { signal }),
    getNextPageParam: (page) => page.page.hasMore ? page.page.nextCursor ?? undefined : undefined,
    retry: retryScopedRequest, enabled,
  });
}

export function usePluginVersions(api: DefaultApi, scope: ApiProjectScope, filters: PluginVersionFilters, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: pluginKeys.versions(scope, filters), initialPageParam: undefined as string | undefined,
    queryFn: ({ signal, pageParam }) => api.listPluginVersions({ ...filters, cursor: pageParam, limit: 100 }, { signal }),
    getNextPageParam: (page) => page.page.hasMore ? page.page.nextCursor ?? undefined : undefined,
    retry: retryScopedRequest, enabled,
  });
}

export function useUploadPlugin(api: DefaultApi, scope: ApiProjectScope) {
  const queryClient = useQueryClient();
  const scopedRequest = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedRequest,
    mutationFn: ({ file, idempotencyKey }: { file: File; idempotencyKey: string }) => scopedRequest((signal) => api.uploadPluginVersionPackage({
      body: file, contentLength: file.size, idempotencyKey,
    }, { signal })),
    onSuccess: () => Promise.all([
      queryClient.invalidateQueries({ queryKey: pluginKeys.versionsRoot(scope) }),
      queryClient.invalidateQueries({ queryKey: pluginKeys.definitionsRoot(scope) }),
    ]),
  });
}

export function usePluginAssignments(api: DefaultApi, scope: ApiProjectScope, filters: PluginAssignmentFilters, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: pluginKeys.assignments(scope, filters), initialPageParam: undefined as string | undefined,
    queryFn: ({ signal, pageParam }) => api.listPluginAssignments({ ...filters, cursor: pageParam, limit: 100 }, { signal }),
    getNextPageParam: (page) => page.page.hasMore ? page.page.nextCursor ?? undefined : undefined,
    retry: retryScopedRequest, enabled,
  });
}

export function useChangeAssignment(api: DefaultApi, scope: ApiProjectScope) {
  const queryClient = useQueryClient();
  const scopedRequest = useScopedRequest(scope);
  return useMutation({
    retry: retryScopedRequest,
    mutationFn: ({ assignment, change, updateKey, reconcileKey }: {
      assignment: PluginAssignment; change: AssignmentChange; updateKey: string; reconcileKey: string;
    }) => scopedRequest(async (signal) => {
      const updated = await api.updatePluginAssignment({
        assignmentId: assignment.assignmentId, ifMatch: assignment.etag, idempotencyKey: updateKey,
        updatePluginAssignmentRequest: change,
      }, { signal });
      const job = await api.reconcilePluginAssignment({ assignmentId: updated.assignmentId, idempotencyKey: reconcileKey }, { signal });
      return { updated, job };
    }),
    onSuccess: ({ updated, job }) => {
      queryClient.setQueryData(pluginKeys.assignment(scope, updated.assignmentId), updated);
      queryClient.setQueryData(pluginKeys.job(scope, updated.assignmentId, job.id), job);
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: pluginKeys.assignmentsRoot(scope) }),
  });
}

const terminal = new Set<JobStatus>(['succeeded', 'failed', 'cancelled', 'timed_out']);

export function usePluginJob(api: DefaultApi, scope: ApiProjectScope, assignmentId: string, jobId: string | undefined, enabled: boolean) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: pluginKeys.job(scope, assignmentId, jobId ?? ''),
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
    void queryClient.invalidateQueries({ queryKey: pluginKeys.assignmentsRoot(scope) });
  }, [query.data?.status, queryClient, scope.projectId, scope.tenantId]);
  return query;
}
