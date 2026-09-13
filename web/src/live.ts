// Live-edge change detection: the ids whose watched value changed since the
// previous render, so a row that moved is visible in peripheral vision.  It is
// inert under `prefers-reduced-motion`, which turns the flash off rather than
// shortening it.  Polling is not here: a live signal polls through the query
// that carries it (`useAsync`'s interval) rather than a hand-rolled timer.

import { useEffect, useRef, useState } from "react";

import { FLASH_MS } from "./design";

/** Whether the user asked the platform to reduce motion. */
function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

/**
 * The ids whose watched value changed since the previous render; each stays in
 * the returned set for FLASH_MS, then clears.  `entries` is a list of
 * `[id, value]` pairs, so the caller names what it watches rather than the
 * hook guessing at object identity.
 */
export function useChangedIds(
  entries: Array<[string, string]>,
  enabled = true,
): ReadonlySet<string> {
  const [changed, setChanged] = useState<ReadonlySet<string>>(() => new Set());
  // A string signature keeps the effect keyed on the data, not on a fresh
  // array identity every render.
  const signature = entries.map(([id, value]) => `${id}\u0001${value}`).join("\u0000");
  const previous = useRef<Map<string, string> | null>(null);

  useEffect(() => {
    const current = new Map<string, string>();
    if (signature !== "") {
      for (const part of signature.split("\u0000")) {
        const at = part.indexOf("\u0001");
        if (at > 0) current.set(part.slice(0, at), part.slice(at + 1));
      }
    }
    const before = previous.current;
    previous.current = current;
    if (before === null || !enabled || prefersReducedMotion()) return;
    const next = new Set<string>();
    for (const [id, value] of current) {
      const old = before.get(id);
      if (old !== undefined && old !== value) next.add(id);
    }
    if (next.size === 0) return;
    setChanged(next);
    const timer = window.setTimeout(() => setChanged(new Set()), FLASH_MS);
    return () => window.clearTimeout(timer);
  }, [signature, enabled]);

  return changed;
}
