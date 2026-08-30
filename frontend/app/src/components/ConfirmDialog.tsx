import React from 'react';

export function ConfirmDialog({ open, title, confirmLabel, onConfirm, onCancel, children }: React.PropsWithChildren<{ open: boolean; title: string; confirmLabel: string; onConfirm(): void; onCancel(): void }>) {
  const confirmButton = React.useRef<HTMLButtonElement>(null);
  const previousFocus = React.useRef<HTMLElement | null>(null);
  React.useEffect(() => {
    if (!open) return;
    previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    confirmButton.current?.focus();
    return () => previousFocus.current?.focus();
  }, [open]);
  if (!open) return null;
  return (
    <section className="dialog-backdrop" role="dialog" aria-modal="true" aria-labelledby="confirm-title" onKeyDown={(event) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onCancel();
      }
    }}>
      <div className="dialog-card">
        <h2 id="confirm-title">{title}</h2>
        <div>{children}</div>
        <footer>
          <button type="button" onClick={onCancel}>取消</button>
          <button ref={confirmButton} type="button" className="button button--danger" onClick={onConfirm}>{confirmLabel}</button>
        </footer>
      </div>
    </section>
  );
}
