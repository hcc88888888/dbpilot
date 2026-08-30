import React from 'react';
import { useAccessToken, useProjectContext } from '../auth/AuthProvider';
import { projectApiBase } from '../api/client';

export type LegacyModuleContext = {
  scope: { tenantId: string; projectId: string };
  request(path: string, init?: RequestInit): Promise<Response>;
};

export type LegacyModuleMount = (root: HTMLElement, context: LegacyModuleContext) => void | (() => void);

export function LegacyModuleHost({ mount }: { mount: LegacyModuleMount }) {
  const rootRef = React.useRef<HTMLDivElement>(null);
  const project = useProjectContext();
  const getAccessToken = useAccessToken();

  React.useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    root.replaceChildren();
    const scope = { tenantId: project.tenantId, projectId: project.projectId };
    const cleanup = mount(root, {
      scope,
      async request(path, init = {}) {
        const token = await getAccessToken();
        const headers = new Headers(init.headers);
        if (token) headers.set('Authorization', `Bearer ${token}`);
        const relativePath = path.startsWith('/') ? path : `/${path}`;
        return fetch(`${projectApiBase(scope)}${relativePath}`, { ...init, headers });
      },
    });
    return () => {
      cleanup?.();
      root.replaceChildren();
    };
  }, [getAccessToken, mount, project.projectId, project.tenantId]);

  return <div ref={rootRef} data-testid="legacy-module-host" data-legacy-isolation="restricted" />;
}
