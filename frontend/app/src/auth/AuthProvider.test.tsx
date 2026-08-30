import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { WebStorageStateStore } from 'oidc-client-ts';

import {
  AuthProvider,
  type AuthManager,
  projectContextsFromProfile,
  useAccessToken,
  useAuthActions,
  useProjectContext,
} from './AuthProvider';
import { createOidcSettings } from './oidc';

const profile = {
  sub: 'operator-1',
  dbpilot_projects: [
    { tenant_id: 'tenant-a', project_id: 'project-a' },
    { tenant_id: 'tenant-a', project_id: 'project-b' },
  ],
  dbpilot_grants: [
    { tenant_id: 'tenant-a', project_id: 'project-a', permissions: ['hosts:read'] },
    { tenant_id: 'tenant-a', project_id: 'project-b', permissions: ['plugins:manage'] },
  ],
};

function createManager() {
  let loaded: ((user: Parameters<AuthManager['events']['addUserLoaded']>[0] extends (user: infer User) => void ? User : never) => void) | undefined;
  const manager: AuthManager = {
    getUser: vi.fn(async () => ({ access_token: 'secret-one', expired: false, profile })),
    signinRedirectCallback: vi.fn(async () => ({ access_token: 'secret-one', expired: false, profile })),
    signinRedirect: vi.fn(async () => undefined),
    signoutRedirect: vi.fn(async () => undefined),
    events: {
      addUserLoaded(callback) {
        loaded = callback;
      },
      removeUserLoaded(callback) {
        if (loaded === callback) loaded = undefined;
      },
    },
  };
  return { manager, load: (user: Parameters<NonNullable<typeof loaded>>[0]) => loaded?.(user) };
}

function Probe({ onToken = () => undefined }: { onToken?: (token: string | undefined) => void }) {
  const project = useProjectContext();
  const getAccessToken = useAccessToken();
  const { projects, switchProject } = useAuthActions();
  return (
    <>
      <output aria-label="scope">{`${project.tenantId}/${project.projectId}`}</output>
      <output aria-label="permissions">{[...project.permissions].join(',')}</output>
      <button type="button" onClick={() => void getAccessToken().then(onToken)}>
        Read token
      </button>
      <button type="button" onClick={() => void switchProject(projects[1])}>
        Switch project
      </button>
    </>
  );
}

describe('OIDC and project authentication', () => {
  it('persists only transient PKCE state while keeping OIDC user tokens in memory', async () => {
    const settings = createOidcSettings({
      authority: 'https://identity.example',
      clientId: 'dbpilot-web',
      redirectUri: 'https://dbpilot.example/auth/callback',
    });

    expect(settings.response_type).toBe('code');
    expect(settings.scope).toBe('openid profile');
    expect(settings.stateStore).toBeInstanceOf(WebStorageStateStore);
    expect(settings.userStore).toBeInstanceOf(WebStorageStateStore);
    expect(settings.automaticSilentRenew).toBe(true);
    await settings.stateStore!.set('callback', 'pkce-verifier');
    await settings.userStore!.set('current-user', 'access-token');
    expect(sessionStorage.getItem('oidc.callback')).toBe('pkce-verifier');
    expect(sessionStorage.getItem('oidc.current-user')).toBeNull();
    expect(localStorage.length).toBe(0);
    expect(await settings.userStore!.get('current-user')).toBe('access-token');
  });

  it('completes the authorization-code callback before restoring a user and removes callback parameters', async () => {
    window.history.replaceState({}, '', '/auth/callback?code=authorization-code&state=oidc-state');
    const callback = vi.fn(async () => ({ access_token: 'callback-token', expired: false, profile }));
    const authManager = {
      ...createManager().manager,
      getUser: vi.fn(async () => null),
      signinRedirectCallback: callback,
    };

    render(
      <AuthProvider manager={authManager}>
        <Probe />
      </AuthProvider>,
    );

    expect((await screen.findByLabelText('scope')).textContent).toBe('tenant-a/project-a');
    expect(callback).toHaveBeenCalledTimes(1);
    expect(authManager.getUser).not.toHaveBeenCalled();
    expect(window.location.pathname).toBe('/');
    expect(window.location.search).toBe('');
    expect(document.body.textContent).not.toContain('callback-token');
  });

  it('rejects malformed or ungranted project claims instead of guessing a scope', () => {
    expect(() => projectContextsFromProfile({ sub: 'operator-1' })).toThrow(/project claims/i);
    expect(() =>
      projectContextsFromProfile({
        sub: 'operator-1',
        dbpilot_projects: [{ tenant_id: 'tenant/a', project_id: 'project-a' }],
        dbpilot_grants: [],
      }),
    ).toThrow(/invalid project/i);
  });

  it('keeps the token in React memory and provides the latest token only on request', async () => {
    localStorage.setItem('unrelated', 'keep');
    sessionStorage.setItem('unrelated', 'keep');
    const { manager, load } = createManager();

    const observedTokens: Array<string | undefined> = [];
    render(
      <AuthProvider manager={manager}>
        <Probe onToken={(token) => observedTokens.push(token)} />
      </AuthProvider>,
    );

    expect((await screen.findByLabelText('scope')).textContent).toBe('tenant-a/project-a');
    expect(document.body.textContent).not.toContain('secret-one');
    await userEvent.click(screen.getByRole('button', { name: 'Read token' }));
    expect(observedTokens).toEqual(['secret-one']);

    act(() => load({ access_token: 'secret-two', expired: false, profile }));
    await userEvent.click(screen.getByRole('button', { name: 'Read token' }));
    expect(observedTokens).toEqual(['secret-one', 'secret-two']);
    expect(document.body.textContent).not.toContain('secret-two');
    expect(localStorage.getItem('unrelated')).toBe('keep');
    expect(sessionStorage.getItem('unrelated')).toBe('keep');
    expect(localStorage.length).toBe(1);
    expect(sessionStorage.length).toBe(1);
  });

  it('cancels active project queries and clears cached data before switching scope', async () => {
    const events: string[] = [];
    const cache = {
      cancelQueries: vi.fn(async () => {
        events.push('cancel');
      }),
      clear: vi.fn(() => {
        events.push('clear');
      }),
    };
    const { manager } = createManager();

    render(
      <AuthProvider manager={manager} queryCache={cache}>
        <Probe />
      </AuthProvider>,
    );

    expect((await screen.findByLabelText('scope')).textContent).toBe('tenant-a/project-a');
    await userEvent.click(screen.getByRole('button', { name: 'Switch project' }));
    await waitFor(() => expect(screen.getByLabelText('scope').textContent).toBe('tenant-a/project-b'));
    expect(events).toEqual(['cancel', 'clear']);
    expect(screen.getByLabelText('permissions').textContent).toContain('plugins:manage');
  });
});
