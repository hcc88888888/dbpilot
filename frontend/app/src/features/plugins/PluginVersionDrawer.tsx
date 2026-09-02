import React from 'react';
import type { PluginVersion } from '../../../../generated/api/dist/index.js';
import { Drawer } from '../../components/Drawer';
import { StatusTag } from '../../components/StatusTag';

export function PluginVersionDrawer({ version, pluginName, onClose }: { version?: PluginVersion; pluginName: string; onClose(): void }) {
  return (
    <Drawer open={Boolean(version)} title={version ? `${pluginName} ${version.version}` : pluginName} onClose={onClose}>
      {version ? <div className="form-stack">
        <StatusTag status={version.status} tone={version.status === 'available' ? 'success' : version.status === 'revoked' || version.status === 'rejected' ? 'danger' : 'neutral'} />
        <dl>
          <dt>发布者</dt><dd>{version.publisherId}</dd>
          <dt>签名密钥</dt><dd>{version.signingKeyId ?? '未提供'}</dd>
          <dt>包摘要</dt><dd>{version.packageSha256}</dd>
          <dt>Manifest</dt><dd>{version.manifestDigest}</dd>
          <dt>平台</dt><dd><ul className="resource-list">{version.platforms.map((platform) => <li key={`${platform.operatingSystem}-${platform.architecture}`}>{platform.operatingSystem} / {platform.architecture}</li>)}</ul></dd>
        </dl>
      </div> : null}
    </Drawer>
  );
}
