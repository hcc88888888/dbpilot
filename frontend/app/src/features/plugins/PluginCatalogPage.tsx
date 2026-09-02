import React from 'react';
import { Link } from 'react-router-dom';
import type { DefaultApi, PluginVersion } from '../../../../generated/api/dist/index.js';
import { mutationKey } from '../../api/client';
import { useProjectContext } from '../../auth/AuthProvider';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { DataTable } from '../../components/DataTable';
import { PageHeader } from '../../components/PageHeader';
import { StatusTag } from '../../components/StatusTag';
import { usePluginsApi } from './api';
import { PluginVersionDrawer } from './PluginVersionDrawer';
import { usePluginDefinitions, usePluginVersions, useUploadPlugin } from './queries';

const maxPluginBytes = 268_435_456;

export function PluginCatalogPage({ api: override, pluginId }: { api?: DefaultApi; pluginId?: string }) {
  const project = useProjectContext();
  const api = usePluginsApi(override);
  const canView = project.permissions.has('plugins:view');
  const canUpload = project.permissions.has('plugins:publish');
  const definitionsQuery = usePluginDefinitions(api, project, {}, canView);
  const versionsQuery = usePluginVersions(api, project, { pluginId }, canView);
  const upload = useUploadPlugin(api, project);
  const [file, setFile] = React.useState<File>();
  const [fileError, setFileError] = React.useState('');
  const [selected, setSelected] = React.useState<PluginVersion>();
  const definitions = definitionsQuery.data?.pages.flatMap((page) => page.items) ?? [];
  const visibleDefinitions = pluginId ? definitions.filter((item) => item.pluginId === pluginId) : definitions;
  const versions = versionsQuery.data?.pages.flatMap((page) => page.items) ?? [];
  const pluginName = definitions.find((item) => item.pluginId === selected?.pluginId)?.name ?? selected?.pluginId ?? '插件版本';
  if (!canView) return <section className="management-page"><PageHeader title="插件目录" /><p role="alert" className="notice">没有查看插件目录的权限。</p></section>;
  const uploadProgress = upload.isSuccess ? 100 : upload.isPending ? 50 : file ? 0 : 0;
  return (
    <section className="management-page">
      <PageHeader title="插件目录" description="管理经签名验证的数据库采集插件。" />
      {canUpload ? <form className="panel form-stack" onSubmit={(event) => {
        event.preventDefault();
        if (!file || fileError) return;
        upload.mutate({ file, idempotencyKey: mutationKey() });
      }}>
        <h2>上传签名插件包</h2>
        <label>插件包<input aria-label="插件包" type="file" accept=".gz,.tgz,application/gzip" onChange={(event) => {
          const next = event.target.files?.[0];
          setFile(next);
          setFileError(!next ? '请选择插件包' : next.size < 1 || next.size > maxPluginBytes ? '插件包大小必须在 1 B 至 256 MiB 之间' : '');
        }} /></label>
        {file ? <p>{file.name} · {file.size} B</p> : null}
        {fileError ? <p role="alert">{fileError}</p> : null}
        <progress aria-label="上传进度" value={uploadProgress} max={100} aria-valuenow={uploadProgress} />
        <button type="submit" disabled={!file || Boolean(fileError) || upload.isPending}>上传插件包</button>
        <AsyncBoundary error={upload.error}>{upload.isSuccess ? <p role="status">上传完成，服务端已返回版本元数据。</p> : null}</AsyncBoundary>
      </form> : null}
      <AsyncBoundary loading={definitionsQuery.isPending || versionsQuery.isPending} error={definitionsQuery.error ?? versionsQuery.error} onRetry={() => { void definitionsQuery.refetch(); void versionsQuery.refetch(); }}>
        <DataTable caption="插件定义" rows={visibleDefinitions.map((item) => ({ ...item, id: item.pluginId }))} columns={[
          { key: 'name', header: '插件', render: (row) => <Link to={`/plugins/${encodeURIComponent(row.pluginId)}`}>{row.name}</Link> }, { key: 'databaseFamily', header: '数据库' }, { key: 'protocolVersion', header: '协议' }, { key: 'latestAvailableVersion', header: '最新可用版本' },
        ]} />
        <DataTable caption="插件版本" rows={versions.map((item) => ({ ...item, id: item.versionId }))} columns={[
          { key: 'version', header: '版本' },
          { key: 'status', header: '状态', render: (row) => <StatusTag status={row.status} tone={row.status === 'available' ? 'success' : 'neutral'} /> },
          { key: 'publisherId', header: '发布者' },
          { key: 'versionId', header: '操作', render: (row) => <button type="button" aria-label={`查看 ${row.version}`} onClick={() => setSelected(row)}>查看详情</button> },
        ]} />
        {definitionsQuery.hasNextPage ? <button type="button" onClick={() => void definitionsQuery.fetchNextPage()}>加载更多插件</button> : null}
        {versionsQuery.hasNextPage ? <button type="button" onClick={() => void versionsQuery.fetchNextPage()}>加载更多版本</button> : null}
      </AsyncBoundary>
      <PluginVersionDrawer version={selected} pluginName={pluginName} onClose={() => setSelected(undefined)} />
    </section>
  );
}
