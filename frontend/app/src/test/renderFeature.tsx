import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider, type AuthManager } from '../auth/AuthProvider';

export function featureManager(permissions: readonly string[], secondaryPermissions?: readonly string[]): AuthManager {
  const projects = [{ tenant_id: 'tenant-a', project_id: 'project-a' }];
  const grants = [{ tenant_id: 'tenant-a', project_id: 'project-a', permissions: [...permissions] }];
  if (secondaryPermissions) {
    projects.push({ tenant_id: 'tenant-a', project_id: 'project-b' });
    grants.push({ tenant_id: 'tenant-a', project_id: 'project-b', permissions: [...secondaryPermissions] });
  }
  const profile = {
    sub: 'operator-1',
    dbpilot_projects: projects,
    dbpilot_grants: grants,
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

export function renderFeature(ui: React.ReactElement, permissions: readonly string[], initialEntry = '/', secondaryPermissions?: readonly string[]) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return {
    queryClient,
    ...render(
      <QueryClientProvider client={queryClient}>
        <AuthProvider manager={featureManager(permissions, secondaryPermissions)} queryCache={queryClient}>
          <MemoryRouter initialEntries={[initialEntry]}>{ui}</MemoryRouter>
        </AuthProvider>
      </QueryClientProvider>,
    ),
  };
}
