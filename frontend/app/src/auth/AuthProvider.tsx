import React from 'react';

export type ProjectContext = {
  authenticated: true;
  tenantId: string;
  projectId: string;
  permissions: ReadonlySet<string>;
};

type ProjectClaim = { tenant_id: string; project_id: string };
type GrantClaim = ProjectClaim & { permissions: string[] };

export type AuthUser = {
  access_token?: string;
  expired?: boolean;
  profile: Record<string, unknown>;
};

export type AuthManager = {
  getUser(): Promise<AuthUser | null>;
  signinRedirect(): Promise<void>;
  signoutRedirect(): Promise<void>;
  events: {
    addUserLoaded(callback: (user: AuthUser) => void): void;
    removeUserLoaded(callback: (user: AuthUser) => void): void;
    addUserUnloaded(callback: () => void): void;
    removeUserUnloaded(callback: () => void): void;
    addSilentRenewError(callback: (error: Error) => void): void;
    removeSilentRenewError(callback: (error: Error) => void): void;
  };
};

type QueryCache = {
  cancelQueries(): Promise<unknown>;
  clear(): void;
};

type AuthActions = {
  projects: readonly ProjectContext[];
  switchProject(project: ProjectContext): Promise<void>;
  signIn(): Promise<void>;
  signOut(): Promise<void>;
};

type AuthValue = {
  project: ProjectContext;
  getAccessToken: () => Promise<string | undefined>;
  actions: AuthActions;
};

const AuthContext = React.createContext<AuthValue | null>(null);
const safeIdentifier = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function isProjectClaim(value: unknown): value is ProjectClaim {
  if (!value || typeof value !== 'object') return false;
  const claim = value as Record<string, unknown>;
  return typeof claim.tenant_id === 'string' && typeof claim.project_id === 'string';
}

function scopeKey(project: ProjectClaim): string {
  return `${project.tenant_id}\u0000${project.project_id}`;
}

export function projectContextsFromProfile(profile: Record<string, unknown>): ProjectContext[] {
  const subject = profile.sub;
  if (
    typeof subject !== 'string'
    || subject.length === 0
    || subject.length > 256
    || subject.trim() !== subject
    || /[\r\n\t]/.test(subject)
  ) {
    throw new Error('Invalid OIDC subject claim');
  }
  const projectClaims = profile.dbpilot_projects == null ? [] : profile.dbpilot_projects;
  const grantClaims = profile.dbpilot_grants == null ? [] : profile.dbpilot_grants;
  if (!Array.isArray(projectClaims)) throw new Error('Invalid OIDC project claims');
  if (!Array.isArray(grantClaims)) throw new Error('Invalid OIDC grant claims');

  const permissionsByScope = new Map<string, ReadonlySet<string>>();
  for (const value of grantClaims) {
    if (!isProjectClaim(value) || !Array.isArray((value as GrantClaim).permissions)) {
      throw new Error('Invalid project grant claim');
    }
    const grant = value as GrantClaim;
    if (!safeIdentifier.test(grant.tenant_id) || !safeIdentifier.test(grant.project_id)) {
      throw new Error('Invalid project identifier in OIDC claims');
    }
    const key = scopeKey(grant);
    if (permissionsByScope.has(key)) throw new Error('Duplicate project grant in OIDC claims');
    const permissions = new Set<string>();
    for (const permission of grant.permissions) {
      if (
        typeof permission !== 'string'
        || permission.trim() !== permission
        || permission.length === 0
        || /[\r\n\t]/.test(permission)
      ) {
        throw new Error('Invalid permission in OIDC claims');
      }
      if (permissions.has(permission)) throw new Error('Duplicate permission in OIDC claims');
      permissions.add(permission);
    }
    permissionsByScope.set(key, permissions);
  }

  const seen = new Set<string>();
  return projectClaims.map((value) => {
    if (!isProjectClaim(value) || !safeIdentifier.test(value.tenant_id) || !safeIdentifier.test(value.project_id)) {
      throw new Error('Invalid project identifier in OIDC claims');
    }
    const key = scopeKey(value);
    if (seen.has(key)) throw new Error('Duplicate project in OIDC claims');
    seen.add(key);
    return {
      authenticated: true,
      tenantId: value.tenant_id,
      projectId: value.project_id,
      permissions: permissionsByScope.get(key) ?? new Set<string>(),
    };
  });
}

export function AuthProvider({
  manager,
  queryCache,
  children,
}: React.PropsWithChildren<{ manager: AuthManager; queryCache?: QueryCache }>) {
  const [user, setUser] = React.useState<AuthUser | null>();
  const [projects, setProjects] = React.useState<ProjectContext[]>([]);
  const [selectedKey, setSelectedKey] = React.useState('');
  const [error, setError] = React.useState<Error>();
  const [authMessage, setAuthMessage] = React.useState('');
  const userRef = React.useRef<AuthUser | null>(null);
  const projectGeneration = React.useRef(0);

  const acceptUser = React.useCallback((nextUser: AuthUser | null) => {
    projectGeneration.current += 1;
    if (!nextUser || nextUser.expired) {
      userRef.current = null;
      setUser(null);
      setProjects([]);
      setSelectedKey('');
      setError(undefined);
      return;
    }
    try {
      const nextProjects = projectContextsFromProfile(nextUser.profile);
      userRef.current = nextUser;
      setUser(nextUser);
      setProjects(nextProjects);
      setSelectedKey((current) => {
        if (nextProjects.length === 0) return '';
        return nextProjects.some((project) => scopeKey({ tenant_id: project.tenantId, project_id: project.projectId }) === current)
          ? current
          : scopeKey({ tenant_id: nextProjects[0].tenantId, project_id: nextProjects[0].projectId });
      });
      setError(undefined);
      setAuthMessage('');
    } catch (value) {
      userRef.current = null;
      setUser(null);
      setProjects([]);
      setSelectedKey('');
      setError(value instanceof Error ? value : new Error('Invalid OIDC claims'));
    }
  }, []);

  React.useEffect(() => {
    let active = true;
    const loaded = (nextUser: AuthUser) => {
      if (active) acceptUser(nextUser);
    };
    const unloaded = () => {
      if (active) {
        setAuthMessage('');
        acceptUser(null);
      }
    };
    const renewFailed = () => {
      if (active) {
        acceptUser(null);
        setAuthMessage('登录续期失败，请重新登录');
      }
    };
    manager.events.addUserLoaded(loaded);
    manager.events.addUserUnloaded(unloaded);
    manager.events.addSilentRenewError(renewFailed);
    void manager.getUser().then(
      (nextUser) => active && acceptUser(nextUser),
      () => active && setError(new Error('Unable to restore login')),
    );
    return () => {
      active = false;
      manager.events.removeUserLoaded(loaded);
      manager.events.removeUserUnloaded(unloaded);
      manager.events.removeSilentRenewError(renewFailed);
    };
  }, [acceptUser, manager]);

  if (error) return <div role="alert">{error.message}</div>;
  if (user === undefined) return <div role="status">正在恢复登录状态…</div>;
  if (!user || user.expired) {
    return (
      <main>
        <h1>DBPilot</h1>
        {authMessage ? <p role="alert">{authMessage}</p> : null}
        <button type="button" onClick={() => void manager.signinRedirect()}>
          登录
        </button>
      </main>
    );
  }

  const project = projects.find(
    (candidate) => scopeKey({ tenant_id: candidate.tenantId, project_id: candidate.projectId }) === selectedKey,
  );
  if (projects.length === 0) {
    return (
      <main>
        <h1>DBPilot</h1>
        <p role="status">没有可访问的项目</p>
        <button type="button" onClick={() => void manager.signoutRedirect()}>退出登录</button>
      </main>
    );
  }
  if (!project) return <div role="status">正在加载项目…</div>;

  const getAccessToken = async () => {
    const current = userRef.current;
    return current && !current.expired ? current.access_token : undefined;
  };
  const switchProject = async (nextProject: ProjectContext) => {
    const nextKey = scopeKey({ tenant_id: nextProject.tenantId, project_id: nextProject.projectId });
    if (!projects.some((candidate) => scopeKey({ tenant_id: candidate.tenantId, project_id: candidate.projectId }) === nextKey)) {
      throw new Error('Project is not granted by the validated OIDC claims');
    }
    const generation = ++projectGeneration.current;
    await queryCache?.cancelQueries();
    if (generation !== projectGeneration.current) return;
    queryCache?.clear();
    setSelectedKey(nextKey);
  };

  return (
    <AuthContext.Provider
      value={{
        project,
        getAccessToken,
        actions: {
          projects,
          switchProject,
          signIn: () => manager.signinRedirect(),
          signOut: () => manager.signoutRedirect(),
        },
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

function useAuthContext(): AuthValue {
  const value = React.useContext(AuthContext);
  if (!value) throw new Error('Authentication context is unavailable');
  return value;
}

export function useProjectContext(): ProjectContext {
  return useAuthContext().project;
}

export function useAccessToken(): () => Promise<string | undefined> {
  return useAuthContext().getAccessToken;
}

export function useAuthActions(): AuthActions {
  return useAuthContext().actions;
}
