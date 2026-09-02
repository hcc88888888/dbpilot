import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider, type AuthManager } from '../auth/AuthProvider';

export function featureManager(permissions: readonly string[]): AuthManager {
  const profile = {
    sub: 'operator-1',
    dbpilot_projects: [{ tenant_id: 'tenant-a', project_id: 'project-a' }],
    dbpilot_grants: [{ tenant_id: 'tenant-a', project_id: 'project-a', permissions: [...permissions] }],
  };
  return {
    getUser: async () => ({ access_token: 'test-token', expired: false, profile }),
    signinRedirect: async () => undefined,
    signoutRedirect: async () => undefined,
    events: {
      addUserLoaded: () => undefined,
      removeUserLoaded: () => undefined,
      addUserUnloaded: () => undefined,
      removeUserUnloaded: () => undefined,
      addSilentRenewError: () => undefined,
      removeSilentRenewError: () => undefined,
    },
  };
}

export function renderFeature(ui: React.ReactElement, permissions: readonly string[], initialEntry = '/') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return {
    queryClient,
    ...render(
      <QueryClientProvider client={queryClient}>
        <AuthProvider manager={featureManager(permissions)} queryCache={queryClient}>
          <MemoryRouter initialEntries={[initialEntry]}>{ui}</MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>,
    ),
  };
}
