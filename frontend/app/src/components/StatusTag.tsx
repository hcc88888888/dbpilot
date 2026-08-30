import React from 'react';

export function StatusTag({ status, tone = 'neutral' }: { status: string; tone?: 'neutral' | 'success' | 'warning' | 'danger' }) {
  return <span className={`status-tag status-tag--${tone}`}>{status}</span>;
}
