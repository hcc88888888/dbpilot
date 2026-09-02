import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { useAccessToken, useProjectContext } from '../../auth/AuthProvider';
import { AsyncBoundary } from '../../components/AsyncBoundary';
import { PageHeader } from '../../components/PageHeader';
import { StatusTag } from '../../components/StatusTag';

export type MonitoringStatus = 'healthy' | 'stale' | 'offline';
export type MonitoringMetricScope = 'host' | 'plugin' | 'database';

export type MonitoringSeries = {
  name: string;
  unit?: string;
  aggregation?: string;
  scope: MonitoringMetricScope;
  source: string;
  status: MonitoringStatus;
  host_id?: string;
  plugin_assignment_id?: string;
  instance_id?: string;
  from: string;
  to: string;
  step: number;
  buckets: Array<{ at: string; value: number | null }>;
};

export type MonitoringOverview = {
  source: string;
  scope: { tenant_id: string; project_id: string };
  from: string;
  to: string;
  total_instances: number;
  healthy: number;
  stale: number;
  offline: number;
  metrics: MonitoringSeries[];
};

type ProjectScope = { tenantId: string; projectId: string };

export class MonitoringRequestError extends Error {
  constructor(public readonly status: number) {
    super(status === 401 ? '登录状态已失效，请重新登录' : status === 403 ? '当前账号没有该项目的查看权限' : '监控数据加载失败，请稍后重试');
  }
}

export async function requestMonitoringOverview(
  scope: ProjectScope,
  getAccessToken: () => Promise<string | undefined>,
  fetchApi: typeof fetch,
  now: Date,
  signal?: AbortSignal,
): Promise<MonitoringOverview> {
  const token = await getAccessToken();
  const to = now.toISOString();
  const from = new Date(now.getTime() - 60 * 60_000).toISOString();
  const prefix = `/api/v1/tenants/${encodeURIComponent(scope.tenantId)}/projects/${encodeURIComponent(scope.projectId)}`;
  const query = new URLSearchParams({ from, to, step: '5m' });
  const response = await fetchApi(`${prefix}/monitoring/overview?${query}`, {
    signal,
    headers: token ? { Authorization: `Bearer ${token}`, Accept: 'application/json' } : { Accept: 'application/json' },
  });
  if (!response.ok) throw new MonitoringRequestError(response.status);
  const value = await response.json() as MonitoringOverview;
  if (!value || !Array.isArray(value.metrics) || value.scope?.tenant_id !== scope.tenantId || value.scope?.project_id !== scope.projectId) {
    throw new MonitoringRequestError(502);
  }
  return value;
}

export function MonitoringPage({ fetchApi = globalThis.fetch, now = () => new Date() }: { fetchApi?: typeof fetch; now?: () => Date }) {
  const scope = useProjectContext();
  const getAccessToken = useAccessToken();
  const query = useQuery({
    queryKey: ['monitoring', scope.tenantId, scope.projectId, 'overview'],
    queryFn: ({ signal }) => requestMonitoringOverview(scope, getAccessToken, fetchApi, now(), signal),
    retry: false,
  });
  const value = query.data;
  const host = value?.metrics.filter((series) => series.scope === 'host') ?? [];
  const database = value?.metrics.filter((series) => series.scope === 'database') ?? [];

  return (
    <section className="monitoring-page">
      <PageHeader title="基础监控" description="Agent 核心主机指标与独立数据库插件指标" />
      <AsyncBoundary loading={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
        {value ? <>
          <p>来源：{value.source}</p>
          <section aria-label="主机指标">
            <h2>主机资源</h2>
            <div className="summary-grid">
              {host.filter((series) => series.name === 'system.cpu.utilization' || series.name === 'system.memory.utilization').map((series) => (
                <article key={`${series.host_id}-${series.name}`}>
                  <strong>{series.name === 'system.cpu.utilization' ? 'CPU' : '内存'} {latestValue(series)}{series.unit ?? ''}</strong>
                  <span>{series.source}</span>
                  <StatusTag status={statusLabel(series.status)} tone={series.status === 'healthy' ? 'success' : series.status === 'stale' ? 'warning' : 'danger'} />
                </article>
              ))}
            </div>
          </section>
          <section aria-label="数据库指标">
            <h2>MySQL 指标</h2>
            <div className="data-table-wrap">
              <table className="data-table">
                <thead><tr><th>指标</th><th>实例</th><th>值</th><th>来源</th><th>状态</th></tr></thead>
                <tbody>{database.map((series) => (
                  <tr key={`${series.instance_id}-${series.name}`}>
                    <td>{series.name}</td><td>{series.instance_id}</td><td>{latestValue(series)}{series.unit ?? ''}</td><td>{series.source}</td>
                    <td><StatusTag status={statusLabel(series.status)} tone={series.status === 'healthy' ? 'success' : series.status === 'stale' ? 'warning' : 'danger'} /></td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          </section>
        </> : null}
      </AsyncBoundary>
    </section>
  );
}

function latestValue(series: MonitoringSeries): string {
  for (let index = series.buckets.length - 1; index >= 0; index -= 1) {
    const value = series.buckets[index]?.value;
    if (value !== null && value !== undefined && Number.isFinite(value)) return String(value);
  }
  return '—';
}

function statusLabel(status: MonitoringStatus): string {
  if (status === 'healthy') return '健康';
  if (status === 'stale') return '数据陈旧';
  return '离线';
}
