import React from 'react';
import { useProjectContext } from '../auth/AuthProvider';

export function PermissionGate({ permission, fallback = null, children }: React.PropsWithChildren<{ permission: string; fallback?: React.ReactNode }>) {
  const project = useProjectContext();
  return project.permissions.has(permission) ? <>{children}</> : <>{fallback}</>;
}
