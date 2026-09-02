import React from 'react';
import { trapModalFocus } from './focus';

export function ConfirmDialog({ open, title, confirmLabel, confirmDisabled = false, onConfirm, onCancel, children }: React.PropsWithChildren<{ open: boolean; title: string; confirmLabel: string; confirmDisabled?: boolean; onConfirm(): void; onCancel(): void }>) {
  const titleId = React.useId();
  const cancelButton = React.useRef<HTMLButtonElement>(null);
  const previousFocus = React.useRef<HTMLElement | null>(null);
  React.useEffect(() => {
    if (!open) return;
    previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelButton.current?.focus();
    return () => previousFocus.current?.focus();
  }, [open]);
  if (!open) return null;
  return (
    <section className="dialog-backdrop" role="dialog" aria-modal="true" aria-labelledby={titleId} onKeyDown={(event) => {
      trapModalFocus(event);
      if (event.key === 'Escape') {
        event.stopPropagation();
        onCancel();
      }
    }}>
      <div className="dialog-card">
        <h2 id={titleId}>{title}</h2>
        <div>{children}</div>
        <footer>
          <button ref={cancelButton} type="button" onClick={onCancel}>取消</button>
          <button type="button" className="button button--danger" disabled={confirmDisabled} onClick={onConfirm}>{confirmLabel}</button>
        </footer>
      </div>
    </section>
  );
}
