// The notification centre: a topbar button with the count of items the reader
// has not dismissed, opening a dialog over the feed `GET /api/notifications`
// derives from the action journal and the analysis log.
//
// Nothing here is stored server-side, so dismissal lives in the browser: the
// dismissed ids are kept in localStorage and filtered out of the count and the
// list, which is where the hosted portal keeps them too.  The dialog takes
// focus on open, returns it on close, cycles Tab among its controls, and
// closes on Escape.  It portals to `document.body` so the shell guard can
// inert sidebar+main without hiding the dialog itself.

import { useEffect, useRef, useState } from "react";
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router";

import { Icon } from "../icons";
import { api } from "../api";
import {
  Button,
  EmptyState,
  ErrorNote,
  Loading,
  SeverityBadge,
  Stamp,
  focusableElements,
  trapTabKey,
  useDialogShellGuard,
} from "../components";
import type { NotificationItem, NotificationsPayload } from "../types";
import { useAsync } from "../useAsync";

/** Where the dismissed ids live; a browser-local preference, never sent. */
const DISMISSED_KEY = "reportal.notifications.dismissed";

/** Items the dialog asks for, and the interval it refreshes on while mounted. */
const FEED_LIMIT = 25;
const REFRESH_MS = 20000;

function readDismissed(): string[] {
  try {
    const raw = window.localStorage.getItem(DISMISSED_KEY);
    const parsed: unknown = raw === null ? [] : JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((id): id is string => typeof id === "string") : [];
  } catch {
    // A corrupt or unavailable store is not an error: nothing is dismissed.
    return [];
  }
}

function writeDismissed(ids: string[]): void {
  try {
    window.localStorage.setItem(DISMISSED_KEY, JSON.stringify(ids));
  } catch {
    // Storage being unavailable only costs the memory of what was dismissed.
  }
}

// The bell's count stops here; the dialog states the exact number.
const MAX_BELL_COUNT = 99;

export function NotificationsBell(): ReactNode {
  const [open, setOpen] = useState(false);
  const [dismissed, setDismissed] = useState<string[]>(() => readDismissed());
  const { data, error, reload } = useAsync(
    () => api<NotificationsPayload>(`/notifications?limit=${FEED_LIMIT}`),
    [],
    true,
    REFRESH_MS,
  );
  const unseen = (data?.notifications ?? []).filter((item) => !dismissed.includes(item.id));
  const dismiss = (id: string): void => {
    const next = [...dismissed, id];
    setDismissed(next);
    writeDismissed(next);
  };
  const dismissAll = (): void => {
    const next = [...new Set([...dismissed, ...(data?.notifications ?? []).map((item) => item.id)])];
    setDismissed(next);
    writeDismissed(next);
  };
  return (
    <>
      <Button
        size="icon"
        tone="ghost"
        aria-label={unseen.length > 0 ? `Notifications, ${unseen.length} new` : "Notifications"}
        title={unseen.length > 0 ? `Notifications: ${unseen.length} new` : "Notifications"}
        onClick={() => {
          setOpen(true);
          reload();
        }}
      >
        <Icon name="bell" />
        {unseen.length > 0 ? (
          <span className="bell-count" aria-hidden="true">
            {unseen.length > MAX_BELL_COUNT ? `${MAX_BELL_COUNT}+` : unseen.length}
          </span>
        ) : null}
      </Button>
      <NotificationsDialog
        open={open}
        onClose={() => setOpen(false)}
        items={data?.notifications ?? []}
        dismissed={dismissed}
        error={error}
        loading={data === undefined && error === null}
        latest={data?.latest ?? null}
        onDismiss={dismiss}
        onDismissAll={dismissAll}
        onRetry={reload}
      />
    </>
  );
}

function NotificationsDialog({
  open,
  onClose,
  items,
  dismissed,
  error,
  loading,
  latest,
  onDismiss,
  onDismissAll,
  onRetry,
}: {
  open: boolean;
  onClose: () => void;
  items: NotificationItem[];
  dismissed: string[];
  error: unknown;
  loading: boolean;
  latest: string | null;
  onDismiss: (id: string) => void;
  onDismissAll: () => void;
  onRetry: () => void;
}): ReactNode {
  const dialogRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);

  // Declared first so its cleanup drops `inert` before the reset effect
  // below returns focus to the shell; restoring into an inert tree fails.
  useDialogShellGuard(open);

  useEffect(() => {
    if (!open) return undefined;
    restoreRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const root = dialogRef.current;
    if (root) {
      const first = focusableElements(root)[0];
      (first ?? root).focus();
    }
    return () => restoreRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onFocusIn = (event: FocusEvent): void => {
      const root = dialogRef.current;
      if (!root || !(event.target instanceof Node) || root.contains(event.target)) return;
      const first = focusableElements(root)[0];
      (first ?? root).focus();
    };
    document.addEventListener("focusin", onFocusIn);
    return () => document.removeEventListener("focusin", onFocusIn);
  }, [open]);

  if (!open) return null;
  const shown = items.filter((item) => !dismissed.includes(item.id));

  const onKeyDown = (event: ReactKeyboardEvent<HTMLDivElement>): void => {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      return;
    }
    if (dialogRef.current) trapTabKey(event, dialogRef.current);
  };

  return createPortal(
    <div
      className="notifications-overlay"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div
        className="notifications-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Notifications"
        tabIndex={-1}
        ref={dialogRef}
        onKeyDown={onKeyDown}
      >
        <div className="notifications-head">
          <strong>Notifications</strong>
          <span role="status">
            {loading
              ? "loading"
              : `${shown.length} new of ${items.length}${latest ? `, latest ${latest}` : ""}`}
          </span>
          <Button tone="ghost" onClick={onDismissAll} disabled={shown.length === 0}>
            Dismiss all
          </Button>
          <Button tone="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
        <div className="search-dialog-body">
          {error ? <ErrorNote error={error} onRetry={onRetry} /> : null}
          {loading ? <Loading label="Loading the notification feed" /> : null}
          {!loading && shown.length === 0 ? (
            <EmptyState>
              Nothing new. Every journaled write and analysis-log entry since the last dismissal
              shows here.
            </EmptyState>
          ) : null}
          {shown.map((item) => (
            <div className="notification-row" key={item.id}>
              <SeverityBadge level={item.severity} />
              <span className="notification-when">
                <Stamp at={item.at} />
              </span>
              <span className="notification-text">{item.message}</span>
              {item.binary_id ? (
                <Link to={`/binaries/${item.binary_id}`} onClick={onClose}>
                  {item.binary_name ?? `binary ${item.binary_id}`}
                </Link>
              ) : null}
              {item.action ? <span className="notification-src">{item.action}</span> : null}
              <Button
                tone="ghost"
                aria-label={`Dismiss notification: ${item.message}`}
                onClick={() => onDismiss(item.id)}
              >
                Dismiss
              </Button>
            </div>
          ))}
        </div>
      </div>
    </div>,
    document.body,
  );
}
