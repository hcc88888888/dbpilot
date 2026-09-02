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
