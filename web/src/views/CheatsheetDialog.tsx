// The keyboard cheatsheet (`?`).  It renders the live registry from keys.ts,
// so it lists exactly the shortcuts the SPA honours; nothing here is a
// hand-written copy of the binding set.
//
// Focus contract, the same shape as the global search modal: the dialog takes
// the focus when it opens and returns it to whatever held it on close, Tab
// stays inside it (the dialog is its only focusable element, so Tab is
// intercepted rather than cycling), and Escape closes it.

import { useEffect, useRef } from "react";
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from "react";

import { displayCombo, isMac, shortcuts } from "../keys";
import type { Shortcut, ShortcutScope } from "../keys";
import { useDialogShellGuard } from "../components";

/** Section title and render order per scope. */
const SCOPE_LABELS: Array<[ShortcutScope, string]> = [
  ["global", "Everywhere"],
  ["view", "In the current view"],
];

function byCombo(left: Shortcut, right: Shortcut): number {
  return left.combo.localeCompare(right.combo);
}

export function CheatsheetDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}): ReactNode {
  const dialogRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!open) return undefined;
    restoreRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    dialogRef.current?.focus();
    return () => {
      restoreRef.current?.focus();
    };
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onFocusIn = (event: FocusEvent): void => {
      if (event.target instanceof Node && !dialogRef.current?.contains(event.target)) {
        dialogRef.current?.focus();
      }
    };
    document.addEventListener("focusin", onFocusIn);
    return () => document.removeEventListener("focusin", onFocusIn);
  }, [open]);

  // After focus restore so cleanup drops inert before returning focus to the shell.
  useDialogShellGuard(open);

  if (!open) return null;

  const bindings = shortcuts();
  const mac = isMac();
  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>): void => {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
    } else if (event.key === "Tab") {
      event.preventDefault();
      dialogRef.current?.focus();
    }
  };

  return (
    <div
      className="cheatsheet-overlay"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={dialogRef}
        className="cheatsheet-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Keyboard shortcuts"
        tabIndex={-1}
        onKeyDown={onKeyDown}
        data-shortcut-count={String(bindings.length)}
      >
        <div className="cheatsheet-head">
          <h2>Keyboard shortcuts</h2>
          <span className="muted">{bindings.length} registered</span>
        </div>
        <div className="cheatsheet-body">
          {SCOPE_LABELS.map(([scope, label]) => {
            const scoped = bindings.filter((entry) => entry.scope === scope).sort(byCombo);
            if (scoped.length === 0) return null;
            return (
              <section key={scope}>
                <h3>{label}</h3>
                <dl className="cheatsheet-list">
                  {scoped.map((entry) => (
                    <div className="cheatsheet-row" key={`${scope}-${entry.combo}`}>
                      <dt>
                        <kbd className="key">{displayCombo(entry.combo, mac)}</kbd>
                      </dt>
                      <dd>{entry.description}</dd>
                    </div>
                  ))}
                </dl>
              </section>
            );
          })}
        </div>
        <div className="cheatsheet-foot muted">Esc closes</div>
      </div>
    </div>
  );
}
