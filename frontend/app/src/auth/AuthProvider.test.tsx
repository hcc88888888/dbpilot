import React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { SigninState, UserManager, WebStorageStateStore, type INavigator } from 'oidc-client-ts';

import {
  AuthProvider,
  type AuthManager,
  projectContextsFromProfile,
  useAccessToken,
  useAuthActions,
  useProjectContext,
} from './AuthProvider';
import { createRouterAfterSigninCallback } from '../routing/bootstrap';
import { createAppRouter } from '../routing/router';
import { createOidcSettings } from './oidc';

const profile = {
  sub: 'operator-1',
  dbpilot_projects: [
    { tenant_id: 'tenant-a', project_id: 'project-a' },
    { tenant_id: 'tenant-a', project_id: 'project-b' },
    { tenant_id: 'tenant-a', project_id: 'project-c' },
  ],
  dbpilot_grants: [
    { tenant_id: 'tenant-a', project_id: 'project-a', permissions: ['hosts:read'] },
    { tenant_id: 'tenant-a', project_id: 'project-b', permissions: ['plugins:manage'] },
    { tenant_id: 'tenant-a', project_id: 'project-c', permissions: ['metric-templates:read'] },
  ],
};

function createManager() {
  let loaded: ((user: Parameters<AuthManager['events']['addUserLoaded']>[0] extends (user: infer User) => void ? User : never) => void) | undefined;
  let unloaded: (() => void) | undefined;
  let renewError: ((error: Error) => void) | undefined;
  const events = {
    addUserLoaded: vi.fn((callback: NonNullable<typeof loaded>) => {
      loaded = callback;
    }),
    removeUserLoaded: vi.fn((callback: NonNullable<typeof loaded>) => {
      if (loaded === callback) loaded = undefined;
    }),
    addUserUnloaded: vi.fn((callback: () => void) => {
      unloaded = callback;
    }),
    removeUserUnloaded: vi.fn((callback: () => void) => {
      if (unloaded === callback) unloaded = undefined;
    }),
    addSilentRenewError: vi.fn((callback: (error: Error) => void) => {
      renewError = callback;
    }),
    removeSilentRenewError: vi.fn((callback: (error: Error) => void) => {
      if (renewError === callback) renewError = undefined;
    }),
  };
  const manager: AuthManager = {
    getUser: vi.fn(async () => ({ access_token: 'secret-one', expired: false, profile })),
    signinRedirect: vi.fn(async () => undefined),
    signoutRedirect: vi.fn(async () => undefined),
    events,
  };
  return {
    manager,
    events,
    load: (user: Parameters<NonNullable<typeof loaded>>[0]) => loaded?.(user),
    unload: () => unloaded?.(),
    failRenew: (error: Error) => renewError?.(error),
  };
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

function ProjectSwitchProbe() {
  const project = useProjectContext();
  const { projects, switchProject } = useAuthActions();
  return (
    <>
      <output aria-label="scope">{project.projectId}</output>
      <button type="button" onClick={() => void switchProject(projects[1])}>Project B</button>
      <button type="button" onClick={() => void switchProject(projects[2])}>Project C</button>
    </>
  );
}

describe('OIDC and project authentication', () => {
  it('persists only transient PKCE state while keeping OIDC user tokens in memory', async () => {
    const settings = createOidcSettings({
      authority: 'https://identity.example',
      clientId: 'dbpilot-web',
      redirectUri: 'https://dbpilot.example/auth/callback',
      silentRedirectUri: 'https://dbpilot.example/auth/callback',
    });

    expect(settings.response_type).toBe('code');
    expect(settings.scope).toBe('openid profile offline_access');
    expect(settings.refreshTokenAllowedScope).toBe('openid profile');
    expect(settings.silent_redirect_uri).toBe('https://dbpilot.example/auth/callback');
    expect(settings.redirectMethod).toBe('replace');
    expect(settings.validateSubOnSilentRenew).toBe(true);
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

  it('completes a redirect callback before constructing the real browser router', async () => {
    window.history.replaceState({}, '', '/auth/callback?code=authorization-code&state=oidc-state');
    const events: string[] = [];
    const authManager = {
      signinCallback: vi.fn(async () => {
        events.push('callback');
        return { access_token: 'callback-token', expired: false, profile };
      }),
    };

    const result = await createRouterAfterSigninCallback(authManager, () => {
      events.push('router');
      return createAppRouter();
    });

    expect(events).toEqual(['callback', 'router']);
    expect(result.kind).toBe('application');
    if (result.kind !== 'application') throw new Error('application router was not created');
    expect(result.router.state.location.pathname).toBe('/');
    expect(result.router.state.errors).toBeNull();
  });

  it('uses the locked library request-type dispatcher for an iframe silent callback and does not create a router', async () => {
    const settings = createOidcSettings({
      authority: 'https://identity.example',
      clientId: 'dbpilot-web',
      redirectUri: 'https://dbpilot.example/auth/callback',
      silentRedirectUri: 'https://dbpilot.example/auth/callback',
    });
    const state = await SigninState.create({
      authority: settings.authority,
      client_id: settings.client_id,
      redirect_uri: settings.silent_redirect_uri!,
      scope: settings.scope!,
      request_type: 'si:s',
      code_verifier: false,
    });
    await settings.stateStore!.set(state.id, state.toStorageString());
    const unsupportedNavigator: INavigator = {
      prepare: vi.fn(async () => { throw new Error('navigation is not used in a callback'); }),
      callback: vi.fn(async () => undefined),
    };
    const iframeCallback = vi.fn(async () => undefined);
    const iframeNavigator: INavigator = {
      prepare: unsupportedNavigator.prepare,
      callback: iframeCallback,
    };
    const realManager = new UserManager(settings, unsupportedNavigator, unsupportedNavigator, iframeNavigator);
    const redirectCallback = vi.spyOn(realManager, 'signinRedirectCallback');
    const createRouter = vi.fn(createAppRouter);
    window.history.replaceState({}, '', `/auth/callback?code=silent-code&state=${state.id}`);

    const result = await createRouterAfterSigninCallback(realManager, createRouter);

    expect(result.kind).toBe('callback-only');
    expect(iframeCallback).toHaveBeenCalledWith(window.location.href);
    expect(redirectCallback).not.toHaveBeenCalled();
    expect(createRouter).not.toHaveBeenCalled();
  });

  it('rejects identity and grant claims the Server rejects', () => {
    expect(projectContextsFromProfile({ sub: 'operator-1' })).toEqual([]);
    expect(() => projectContextsFromProfile({ sub: 'operator-1', dbpilot_projects: 'invalid' })).toThrow(/project claims/i);
    expect(() =>
      projectContextsFromProfile({
        sub: 'operator-1',
        dbpilot_projects: [{ tenant_id: 'tenant/a', project_id: 'project-a' }],
        dbpilot_grants: [],
      }),
    ).toThrow(/invalid project/i);
    for (const subject of ['', ' operator', 'operator\t1', 'x'.repeat(257)]) {
      expect(() => projectContextsFromProfile({ ...profile, sub: subject })).toThrow(/subject/i);
    }
    expect(() => projectContextsFromProfile({
      ...profile,
      dbpilot_grants: [...profile.dbpilot_grants, profile.dbpilot_grants[0]],
    })).toThrow(/duplicate project grant/i);
    expect(() => projectContextsFromProfile({
      ...profile,
      dbpilot_grants: [{ tenant_id: 'tenant-a', project_id: 'project-a', permissions: ['hosts:read', 'hosts:read'] }],
    })).toThrow(/duplicate permission/i);
    expect(() => projectContextsFromProfile({
      ...profile,
      dbpilot_grants: [{ tenant_id: 'tenant-a', project_id: 'project-a', permissions: ['hosts:\tread'] }],
    })).toThrow(/invalid permission/i);
  });

  it('authenticates a valid subject with no project grants without mounting project-scoped children', async () => {
    const { manager } = createManager();
    const noProjectManager = {
      ...manager,
      getUser: vi.fn(async () => ({ access_token: 'unscoped-token', expired: false, profile: { sub: 'operator-1' } })),
    };
    render(
      <AuthProvider manager={noProjectManager}>
        <Probe />
      </AuthProvider>,
    );

    expect(await screen.findByRole('status')).not.toBeNull();
    expect(screen.getByRole('status').textContent).toContain('没有可访问的项目');
    expect(screen.queryByLabelText('scope')).toBeNull();
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

  it('tracks refreshed users and fails closed on unload or silent-renew errors', async () => {
    const { manager, events, load, unload, failRenew } = createManager();
    const observedTokens: Array<string | undefined> = [];
    const view = render(
      <AuthProvider manager={manager}>
        <Probe onToken={(token) => observedTokens.push(token)} />
      </AuthProvider>,
    );
    expect(await screen.findByLabelText('scope')).not.toBeNull();

    act(() => load({ access_token: 'refreshed-token', expired: false, profile }));
    await userEvent.click(screen.getByRole('button', { name: 'Read token' }));
    expect(observedTokens).toEqual(['refreshed-token']);

    act(() => failRenew(new Error('provider detail must not render')));
    expect(await screen.findByRole('alert')).not.toBeNull();
    expect(screen.getByRole('alert').textContent).toContain('续期失败');
    expect(document.body.textContent).not.toContain('provider detail');
    expect(screen.getByRole('button', { name: '登录' })).not.toBeNull();

    act(() => load({ access_token: 'recovered-token', expired: false, profile }));
    expect(await screen.findByLabelText('scope')).not.toBeNull();
    act(() => unload());
    expect(await screen.findByRole('button', { name: '登录' })).not.toBeNull();

    view.unmount();
    expect(events.removeUserLoaded).toHaveBeenCalledTimes(1);
    expect(events.removeUserUnloaded).toHaveBeenCalledTimes(1);
    expect(events.removeSilentRenewError).toHaveBeenCalledTimes(1);
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

  it('keeps the latest project selection when cancellation promises resolve out of order', async () => {
    const pending: Array<() => void> = [];
    const cache = {
      cancelQueries: vi.fn(() => new Promise<void>((resolve) => pending.push(resolve))),
      clear: vi.fn(),
    };
    const { manager } = createManager();
    render(
      <AuthProvider manager={manager} queryCache={cache}>
        <ProjectSwitchProbe />
      </AuthProvider>,
    );
    expect((await screen.findByLabelText('scope')).textContent).toBe('project-a');

    await userEvent.click(screen.getByRole('button', { name: 'Project B' }));
    await userEvent.click(screen.getByRole('button', { name: 'Project C' }));
    expect(pending).toHaveLength(2);
    await act(async () => pending[1]());
    expect(screen.getByLabelText('scope').textContent).toBe('project-c');
    await act(async () => pending[0]());
    expect(screen.getByLabelText('scope').textContent).toBe('project-c');
    expect(cache.clear).toHaveBeenCalledTimes(1);
  });
});
