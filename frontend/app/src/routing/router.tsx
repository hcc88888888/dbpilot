import React from 'react';
import { createBrowserRouter, useParams } from 'react-router-dom';
import { PageHeader } from '../components/PageHeader';
import { CandidateListPage } from '../features/discovery/CandidateListPage';
import { HostDetailPage } from '../features/hosts/HostDetailPage';
import { HostListPage } from '../features/hosts/HostListPage';
import { InstanceDetailPage } from '../features/instances/InstanceDetailPage';
import { InstanceListPage } from '../features/instances/InstanceListPage';
import { AssignmentPage } from '../features/plugins/AssignmentPage';
import { PluginCatalogPage } from '../features/plugins/PluginCatalogPage';
import { TemplateEditor } from '../features/templates/TemplateEditor';
import { TemplateListPage } from '../features/templates/TemplateListPage';
import { AppShell } from '../shell/AppShell';

function WelcomePage() {
  return <PageHeader title="管理平台" description="主机、数据库实例与插件的统一管理入口" />;
}

function PluginDetailRoute() {
  const { id = '' } = useParams();
  return <PluginCatalogPage pluginId={id} />;
}

function TemplateDetailRoute() {
  const { id = '' } = useParams();
  return <TemplateEditor templateId={id} />;
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
        { path: 'plugins', element: <PluginCatalogPage /> },
        { path: 'plugins/:id', element: <PluginDetailRoute /> },
        { path: 'plugin-assignments', element: <AssignmentPage /> },
        { path: 'metric-templates', element: <TemplateListPage /> },
        { path: 'metric-templates/:id', element: <TemplateDetailRoute /> },
      ],
    },
  ]);
}
