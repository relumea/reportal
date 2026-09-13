// The notification centre: a topbar button with the count of items the reader
// has not dismissed, opening a dialog over the feed `GET /api/notifications`
// derives from the action journal and the analysis log.
//
// Nothing here is stored server-side, so dismissal lives in the browser: the
// dismissed ids are kept in localStorage and filtered out of the count and the
// list, which is where the hosted portal keeps them too.  The dialog follows
// the same focus contract as the cheatsheet and the search modal: it takes the
// focus on open, returns it on close, keeps Tab inside it and closes on Escape.

import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api";
import { Button, EmptyState, ErrorNote, Loading, SeverityBadge } from "../components";
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
        tone={unseen.length > 0 ? "primary" : "ghost"}
        onClick={() => {
          setOpen(true);
          reload();
        }}
      >
        {unseen.length > 0 ? `Notifications (${unseen.length})` : "Notifications"}
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
  useEffect(() => {
    if (!open) return undefined;
    restoreRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    dialogRef.current?.focus();
    return () => restoreRef.current?.focus();
  }, [open]);
  if (!open) return null;
  const shown = items.filter((item) => !dismissed.includes(item.id));
  return (
    <div className="notifications-overlay" onClick={onClose}>
      <div
        className="notifications-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="Notifications"
        tabIndex={-1}
        ref={dialogRef}
        onClick={(event) => event.stopPropagation()}
        onKeyDown={(event) => {
          if (event.key === "Escape") onClose();
          if (event.key === "Tab") event.preventDefault();
        }}
      >
        <div className="notifications-head">
          <strong>Notifications</strong>
          <span>
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
              <span className="notification-when">{item.at}</span>
              <span className="notification-text">{item.message}</span>
              {item.binary_id ? (
                <a href={`#/binaries/${item.binary_id}`} onClick={onClose}>
                  {item.binary_name ?? `binary ${item.binary_id}`}
                </a>
              ) : null}
              {item.action ? <span className="notification-src">{item.action}</span> : null}
              <Button tone="ghost" onClick={() => onDismiss(item.id)}>
                Dismiss
              </Button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
