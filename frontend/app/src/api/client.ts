import { Configuration, DefaultApi } from '../../../generated/api/dist/index.js';

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
