import React from 'react';

export function Drawer({ open, title, onClose, children }: React.PropsWithChildren<{ open: boolean; title: string; onClose(): void }>) {
  const closeButton = React.useRef<HTMLButtonElement>(null);
  const previousFocus = React.useRef<HTMLElement | null>(null);
  React.useEffect(() => {
    if (!open) return;
    previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeButton.current?.focus();
    return () => previousFocus.current?.focus();
  }, [open]);
  if (!open) return null;
  return (
    <section className="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title" onKeyDown={(event) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onClose();
      }
    }}>
      <header>
        <h2 id="drawer-title">{title}</h2>
        <button ref={closeButton} type="button" aria-label="Close" onClick={onClose}>×</button>
      </header>
      {children}
    </section>
  );
}
