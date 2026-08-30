import React from 'react';

export function FilterBar({ label = '筛选', children, onSubmit }: React.PropsWithChildren<{ label?: string; onSubmit?: React.FormEventHandler<HTMLFormElement> }>) {
  return (
    <form className="filter-bar" aria-label={label} onSubmit={onSubmit}>
      {children}
    </form>
  );
}
