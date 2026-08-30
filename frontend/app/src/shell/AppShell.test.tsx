import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import { createGeneratedApiClient } from '../api/client';
import { AuthProvider, type AuthManager, useAuthActions } from '../auth/AuthProvider';
import { AsyncBoundary } from '../components/AsyncBoundary';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { DataTable } from '../components/DataTable';
import { Drawer } from '../components/Drawer';
import { FormField } from '../components/FormField';
import { PermissionGate } from '../components/PermissionGate';
import { LegacyModuleHost, type LegacyModuleContext } from '../legacy/LegacyModuleHost';
import { AppShell } from './AppShell';

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

function manager(): AuthManager {
  return {
    getUser: async () => ({ access_token: 'not-rendered', expired: false, profile }),
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

describe('React management shell', () => {
  it('renders accessible navigation and switches the active project from the shell', async () => {
    const cache = { cancelQueries: vi.fn(async () => undefined), clear: vi.fn() };
    render(
      <AuthProvider manager={manager()} queryCache={cache}>
        <MemoryRouter>
          <AppShell>
            <h1>Hosts</h1>
          </AppShell>
        </MemoryRouter>
      </AuthProvider>,
    );

    expect(await screen.findByRole('navigation', { name: 'Primary' })).not.toBeNull();
    expect(screen.getByRole('main').textContent).toContain('Hosts');
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Project' }), 'tenant-a/project-b');
    await waitFor(() => expect(cache.clear).toHaveBeenCalledTimes(1));
  });

  it('uses the generated client with a fresh bearer token and same-origin scoped API path per request', async () => {
    const requests: Array<{ url: string; authorization: string | null }> = [];
    let token = 'token-one';
    const fetchApi: typeof fetch = vi.fn(async (input, init) => {
      const headers = new Headers(init?.headers);
      requests.push({ url: String(input), authorization: headers.get('Authorization') });
      return new Response(JSON.stringify({ items: [], page: { limit: 20, has_more: false } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    });
    const api = createGeneratedApiClient(
      { tenantId: 'tenant a', projectId: 'project/a' },
      async () => token,
      fetchApi,
    );

    await api.listHosts();
    token = 'token-two';
    await api.listHosts();

    expect(requests).toEqual([
      { url: '/api/v1/tenants/tenant%20a/projects/project%2Fa/hosts', authorization: 'Bearer token-one' },
      { url: '/api/v1/tenants/tenant%20a/projects/project%2Fa/hosts', authorization: 'Bearer token-two' },
    ]);
  });

  it.each([
    [401, '登录状态已失效'],
    [403, '没有执行此操作的权限'],
  ])('shows configured HTTP %s errors and never calls a demo fallback', async (status, message) => {
    const fetchApi: typeof fetch = vi.fn(async () =>
      new Response(JSON.stringify({ title: 'unsafe server detail' }), {
        status,
        headers: { 'Content-Type': 'application/problem+json' },
      }),
    );
    const api = createGeneratedApiClient(
      { tenantId: 'tenant-a', projectId: 'project-a' },
      async () => 'token',
      fetchApi,
    );
    let error: unknown;
    try {
      await api.listHosts();
    } catch (value) {
      error = value;
    }

    render(<AsyncBoundary error={error} />);
    expect(screen.getByRole('alert').textContent).toContain(message);
    expect(screen.queryByText(/demo/i)).toBeNull();
    expect(fetchApi).toHaveBeenCalledTimes(1);
  });

  it('fails permission gates closed', async () => {
    render(
      <AuthProvider manager={manager()}>
        <PermissionGate permission="plugins:manage" fallback={<span>Not allowed</span>}>
          <button type="button">Deploy plugin</button>
        </PermissionGate>
      </AuthProvider>,
    );

    expect(await screen.findByText('Not allowed')).not.toBeNull();
    expect(screen.queryByRole('button', { name: 'Deploy plugin' })).toBeNull();
  });

  it('provides labelled table/form/dialog primitives with keyboard dismissal and escaped server values', async () => {
    const closeDrawer = vi.fn();
    const cancel = vi.fn();
    render(
      <>
        <DataTable
          caption="Managed hosts"
          columns={[{ key: 'name', header: 'Name' }]}
          rows={[{ id: '1', name: '<img src=x onerror=alert(1)>' }]}
        />
        <FormField label="Display name" name="display-name" />
        <Drawer open title="Host details" onClose={closeDrawer}>
          Details
        </Drawer>
        <ConfirmDialog open title="Retire host" confirmLabel="Retire" onConfirm={() => undefined} onCancel={cancel}>
          This cannot be undone.
        </ConfirmDialog>
      </>,
    );

    expect(screen.getByRole('table', { name: 'Managed hosts' }).textContent).toContain('<img src=x onerror=alert(1)>');
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getByLabelText('Display name')).not.toBeNull();
    expect(screen.getAllByRole('dialog')).toHaveLength(2);
    await userEvent.keyboard('{Escape}');
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(closeDrawer).not.toHaveBeenCalled();
  });

  it('gives simultaneous dialog instances unique accessible title relationships', () => {
    render(
      <>
        <Drawer open title="First drawer" onClose={() => undefined}>First</Drawer>
        <Drawer open title="Second drawer" onClose={() => undefined}>Second</Drawer>
        <ConfirmDialog open title="First confirmation" confirmLabel="Confirm first" onConfirm={() => undefined} onCancel={() => undefined}>First</ConfirmDialog>
        <ConfirmDialog open title="Second confirmation" confirmLabel="Confirm second" onConfirm={() => undefined} onCancel={() => undefined}>Second</ConfirmDialog>
      </>,
    );

    const dialogs = [
      screen.getByRole('dialog', { name: 'First drawer' }),
      screen.getByRole('dialog', { name: 'Second drawer' }),
      screen.getByRole('dialog', { name: 'First confirmation' }),
      screen.getByRole('dialog', { name: 'Second confirmation' }),
    ];
    const titleIds = dialogs.map((dialog) => dialog.getAttribute('aria-labelledby'));
    expect(new Set(titleIds).size).toBe(4);
    for (const id of titleIds) expect(document.getElementById(id!)).not.toBeNull();
  });

  it('moves focus into a drawer and restores it to the opener after keyboard dismissal', async () => {
    function DrawerHarness() {
      const [open, setOpen] = React.useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>Open host details</button>
          <Drawer open={open} title="Host details" onClose={() => setOpen(false)}>Details</Drawer>
        </>
      );
    }
    render(<DrawerHarness />);

    const opener = screen.getByRole('button', { name: 'Open host details' });
    await userEvent.click(opener);
    const close = screen.getByRole('button', { name: 'Close' });
    expect(document.activeElement).toBe(close);
    await userEvent.tab();
    expect(document.activeElement).toBe(close);
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Host details' })).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it('moves focus into a confirmation dialog and restores it after cancellation', async () => {
    function DialogHarness() {
      const [open, setOpen] = React.useState(false);
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>Retire host</button>
          <ConfirmDialog
            open={open}
            title="Confirm retirement"
            confirmLabel="Retire"
            onConfirm={() => undefined}
            onCancel={() => setOpen(false)}
          >
            This cannot be undone.
          </ConfirmDialog>
        </>
      );
    }
    render(<DialogHarness />);

    const opener = screen.getByRole('button', { name: 'Retire host' });
    await userEvent.click(opener);
    const confirm = screen.getByRole('button', { name: 'Retire' });
    const cancel = screen.getByRole('button', { name: '取消' });
    expect(document.activeElement).toBe(cancel);
    await userEvent.tab({ shift: true });
    expect(document.activeElement).toBe(confirm);
    await userEvent.tab();
    expect(document.activeElement).toBe(cancel);
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Confirm retirement' })).toBeNull();
    expect(document.activeElement).toBe(opener);
  });

  it('remounts legacy modules with validated scope and permissions while aborting the previous lifecycle', async () => {
    const cleanup = vi.fn();
    const signals: AbortSignal[] = [];
    const contexts: LegacyModuleContext[] = [];
    const mount = vi.fn((root: HTMLElement, context: LegacyModuleContext, signal: AbortSignal) => {
      signals.push(signal);
      contexts.push(context);
      if (signals.length === 1) (context.permissions as Set<string>).add('plugins:manage');
      root.textContent = `Legacy ${context.scope.projectId}`;
      return cleanup;
    });
    function LegacyHarness() {
      const [, rerender] = React.useReducer((value) => value + 1, 0);
      const { projects, switchProject } = useAuthActions();
      return (
        <>
          <button type="button" onClick={() => void switchProject(projects[1])}>Switch legacy project</button>
          <button type="button" onClick={rerender}>Rerender permissions</button>
          <PermissionGate permission="plugins:manage" fallback={<span>No plugin access</span>}>
            <span>Plugin access</span>
          </PermissionGate>
          <LegacyModuleHost mount={mount} />
        </>
      );
    }
    const { unmount } = render(
      <AuthProvider manager={manager()}>
        <LegacyHarness />
      </AuthProvider>,
    );

    expect(await screen.findByText('Legacy project-a')).not.toBeNull();
    expect(Object.keys(contexts[0]).sort()).toEqual(['permissions', 'scope']);
    expect(contexts[0]).not.toHaveProperty('request');
    expect(contexts[0]).not.toHaveProperty('accessToken');
    expect(signals[0].aborted).toBe(false);
    await userEvent.click(screen.getByRole('button', { name: 'Rerender permissions' }));
    expect(screen.getByText('No plugin access')).not.toBeNull();
    expect(screen.queryByText('Plugin access')).toBeNull();

    await userEvent.click(screen.getByRole('button', { name: 'Switch legacy project' }));
    expect(await screen.findByText('Legacy project-b')).not.toBeNull();
    expect(signals[0].aborted).toBe(true);
    expect(signals[1].aborted).toBe(false);
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect([...contexts[1].permissions]).toEqual(['plugins:manage']);

    unmount();
    expect(signals[1].aborted).toBe(true);
    expect(cleanup).toHaveBeenCalledTimes(2);
  });
});
