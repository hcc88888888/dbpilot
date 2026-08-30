import React from 'react';

function responseStatus(error: unknown): number | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const response = (error as { response?: unknown }).response;
  return response instanceof Response ? response.status : undefined;
}

export function AsyncBoundary({ loading = false, error, onRetry, children }: React.PropsWithChildren<{ loading?: boolean; error?: unknown; onRetry?: () => void }>) {
  if (loading) return <div role="status">正在加载…</div>;
  if (error) {
    const status = responseStatus(error);
    const message = status === 401
      ? '登录状态已失效，请重新登录'
      : status === 403
        ? '没有执行此操作的权限'
        : '请求失败，请稍后重试';
    return (
      <div role="alert">
        <p>{message}</p>
        {onRetry ? <button type="button" onClick={onRetry}>重试</button> : null}
      </div>
    );
  }
  return <>{children}</>;
}
