import React from 'react';
import { Link, NavLink, Outlet } from 'react-router-dom';
import { useAuthActions, useProjectContext } from '../auth/AuthProvider';

const navigation = [
  { to: '/', label: '概览', end: true },
  { to: '/hosts', label: '主机' },
  { to: '/discovery', label: '数据库发现' },
  { to: '/instances', label: '数据库实例' },
  { to: '/plugins', label: '插件' },
  { to: '/metric-templates', label: '指标模板' },
] as const;

export function AppShell({ children }: React.PropsWithChildren) {
  const project = useProjectContext();
  const { projects, switchProject, signOut } = useAuthActions();
  const current = `${project.tenantId}/${project.projectId}`;
  return (
    <div className="app-shell">
      <aside className="shell-sidebar">
        <Link className="brand" to="/" aria-label="DBPilot home">DBPilot</Link>
        <label className="project-switcher">
          <span>Project</span>
          <select value={current} onChange={(event) => {
            const next = projects.find((candidate) => `${candidate.tenantId}/${candidate.projectId}` === event.target.value);
            if (next) void switchProject(next);
          }}>
            {projects.map((candidate) => {
              const value = `${candidate.tenantId}/${candidate.projectId}`;
              return <option key={value} value={value}>{candidate.tenantId} / {candidate.projectId}</option>;
            })}
          </select>
        </label>
        <nav aria-label="Primary">
          {navigation.map((item) => (
            <NavLink key={item.to} to={item.to} end={'end' in item ? item.end : false}>{item.label}</NavLink>
          ))}
        </nav>
        <button type="button" className="sign-out" onClick={() => void signOut()}>退出登录</button>
      </aside>
      <main className="shell-content">{children ?? <Outlet />}</main>
    </div>
  );
}
