import { Configuration, DefaultApi } from '../../../generated/api/dist/index.js';
import React from 'react';
import { useAccessToken, useProjectContext } from '../auth/AuthProvider';

export type ApiProjectScope = { tenantId: string; projectId: string };

export function projectApiBase(scope: ApiProjectScope): string {
  return `/api/v1/tenants/${encodeURIComponent(scope.tenantId)}/projects/${encodeURIComponent(scope.projectId)}`;
}

export function createGeneratedApiClient(
  scope: ApiProjectScope,
  getAccessToken: () => Promise<string | undefined>,
  fetchApi: typeof fetch = globalThis.fetch,
): DefaultApi {
  return new DefaultApi(
    new Configuration({
      basePath: projectApiBase(scope),
      accessToken: async () => (await getAccessToken()) ?? '',
      fetchApi,
    }),
  );
}

export function useGeneratedApiClient(override?: DefaultApi): DefaultApi {
  const scope = useProjectContext();
  const getAccessToken = useAccessToken();
  return React.useMemo(
    () => override ?? createGeneratedApiClient(scope, getAccessToken),
    [getAccessToken, override, scope.projectId, scope.tenantId],
  );
}

export function mutationKey(): string {
  return globalThis.crypto.randomUUID();
}

export function useScopedRequest(scope: ApiProjectScope) {
  const active = React.useRef(new Set<AbortController>());
  React.useEffect(() => () => {
    for (const controller of active.current) controller.abort();
    active.current.clear();
  }, [scope.projectId, scope.tenantId]);
  return React.useCallback(async <T,>(request: (signal: AbortSignal) => Promise<T>): Promise<T> => {
    const controller = new AbortController();
    active.current.add(controller);
    try {
      return await request(controller.signal);
    } finally {
      active.current.delete(controller);
    }
  }, [scope.projectId, scope.tenantId]);
}

export function retryScopedMutation(failureCount: number, error: unknown): boolean {
  const aborted = typeof error === 'object' && error !== null && 'name' in error && error.name === 'AbortError';
  return !aborted && failureCount < 1;
}
