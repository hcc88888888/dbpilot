import React from 'react';
import { useProjectContext } from '../auth/AuthProvider';

export type LegacyModuleContext = {
  scope: Readonly<{ tenantId: string; projectId: string }>;
  permissions: ReadonlySet<string>;
};

export type LegacyModuleMount = (
  root: HTMLElement,
  context: LegacyModuleContext,
  signal: AbortSignal,
) => void | (() => void);

export function LegacyModuleHost({ mount }: { mount: LegacyModuleMount }) {
  const rootRef = React.useRef<HTMLDivElement>(null);
  const project = useProjectContext();

  React.useEffect(() => {
    const root = rootRef.current;
    if (!root) return;
    root.replaceChildren();
    const controller = new AbortController();
    const context: LegacyModuleContext = Object.freeze({
      scope: Object.freeze({ tenantId: project.tenantId, projectId: project.projectId }),
      permissions: new Set(project.permissions),
    });
    const cleanup = mount(root, context, controller.signal);
    return () => {
      controller.abort();
      cleanup?.();
      root.replaceChildren();
    };
  }, [mount, project.permissions, project.projectId, project.tenantId]);

  return <div ref={rootRef} data-testid="legacy-module-host" />;
}
