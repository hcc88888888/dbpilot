import React from 'react';
import { createBrowserRouter } from 'react-router-dom';
import { PageHeader } from '../components/PageHeader';
import { CandidateListPage } from '../features/discovery/CandidateListPage';
import { HostDetailPage } from '../features/hosts/HostDetailPage';
import { HostListPage } from '../features/hosts/HostListPage';
import { InstanceDetailPage } from '../features/instances/InstanceDetailPage';
import { InstanceListPage } from '../features/instances/InstanceListPage';
import { AppShell } from '../shell/AppShell';

function WelcomePage() {
  return <PageHeader title="管理平台" description="主机、数据库实例与插件的统一管理入口" />;
}

function PendingFeaturePage() {
  return <PageHeader title="功能即将接入" description="页面路由已就绪，功能模块将在后续任务中接入。" />;
}

export function createAppRouter() {
  return createBrowserRouter([
    {
      path: '/',
      element: <AppShell />,
      children: [
        { index: true, element: <WelcomePage /> },
        { path: 'hosts', element: <HostListPage /> },
        { path: 'hosts/:id', element: <HostDetailPage /> },
        { path: 'discovery', element: <CandidateListPage /> },
        { path: 'instances', element: <InstanceListPage /> },
        { path: 'instances/:id', element: <InstanceDetailPage /> },
        { path: 'plugins', element: <PendingFeaturePage /> },
        { path: 'metric-templates', element: <PendingFeaturePage /> },
      ],
    },
  ]);
}
