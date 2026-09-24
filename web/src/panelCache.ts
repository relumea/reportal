// The detail panels' shared data cache.  Panels are keyed by a string that
// names the whole request (entity id plus query), so a panel loaded once is
// reused when the view unmounts and mounts again.  The store is react-query's
// cache: a panel is one query under `PANEL_KEY`, its value the panel entry the
// panels render, and a refresh is a fetch that notifies every mounted panel.
// Unmounted entries expire after `PANEL_GC_MS`; identity changes call
// `resetSessionCache` so a different bearer or active team cannot keep serving
// the previous caller's rows.

import { useQuery } from "@tanstack/react-query";
import { useRef } from "react";

import { queryClient } from "./queryClient";

export type PanelEntry<T> =
  | { state: "loading" }
  | { state: "ready"; data: T }
  | { state: "error"; error: unknown };

/** Every panel query shares this key prefix, so clearing them is one call. */
const PANEL_KEY = "panel";

// How long an unmounted panel stays in react-query's cache.  Remounts within
// this window reuse the entry without refetching (`staleTime: Infinity`); past
// it the entry is dropped so a long session cannot pin every panel ever opened.
export const PANEL_GC_MS = 5 * 60 * 1000;

function panelQueryKey(key: string): [string, string] {
  return [PANEL_KEY, key];
}

/** Run one loader and turn its outcome into the entry the panels render. */
async function loadEntry<T>(load: () => Promise<T>): Promise<PanelEntry<T>> {
  try {
    return { state: "ready", data: await load() };
  } catch (error) {
    return { state: "error", error };
  }
}

async function store<T>(key: string, load: () => Promise<T>): Promise<void> {
  // The loader always runs: a refresh is asked for after a write, and the cache
  // holds the panel for as long as the view lives.
  queryClient.setQueryData<PanelEntry<T>>(panelQueryKey(key), { state: "loading" });
  queryClient.setQueryData<PanelEntry<T>>(panelQueryKey(key), await loadEntry(load));
}

export function panelKey(...parts: Array<string | number>): string {
  return parts.join(":");
}

/** Re-read one mounted panel in the background, keeping its current entry until
 *  the new one lands: what a poll uses, so it never flashes a loading state. */
export function revalidatePanel(key: string): void {
  void queryClient.invalidateQueries({ queryKey: panelQueryKey(key), exact: true });
}

/** Re-read every mounted panel of one binary (`binary:<id>...` keys), keeping
 *  what each shows until its new answer lands. */
export function refreshBinaryPanels(binaryId: number): void {
  const prefix = panelKey("binary", binaryId);
  void queryClient.invalidateQueries({
    predicate: (query) =>
      query.queryKey[0] === PANEL_KEY &&
      (query.queryKey[1] === prefix || String(query.queryKey[1]).startsWith(`${prefix}:`)),
  });
}

/** Drop every cached panel after a mutation that is not scoped to one panel. */
export function clearPanels(): void {
  queryClient.removeQueries({ queryKey: [PANEL_KEY] });
}

/** Drop every react-query entry after the browser's identity or active team changes. */
export function resetSessionCache(): void {
  queryClient.clear();
}

/** Re-run a load that previously failed or needs refreshing. */
export function refreshPanel<T>(key: string, load: () => Promise<T>): void {
  void store(key, load);
}

/** Auto-load a panel once per key; returns undefined until the load resolves.
 *  While `enabled` is false nothing loads, but a `refreshPanel` still lands. */
export function usePanel<T>(
  key: string,
  load: () => Promise<T>,
  enabled = true,
): PanelEntry<T> | undefined {
  const loadRef = useRef(load);
  loadRef.current = load;
  const query = useQuery<PanelEntry<T>>({
    queryKey: panelQueryKey(key),
    queryFn: () => loadEntry(() => loadRef.current()),
    enabled,
    // A panel loaded once stays cached while mounted; a remount within
    // PANEL_GC_MS reuses it, and a mutation calls `refreshPanel`.
    staleTime: Infinity,
    gcTime: PANEL_GC_MS,
    refetchOnMount: false,
  });
  return query.data;
}

/** Read a panel without loading it, plus a runner for on-demand panels. */
export function useLazyPanel<T>(
  key: string,
): [PanelEntry<T> | undefined, (load: () => Promise<T>) => void] {
  const query = useQuery<PanelEntry<T>>({
    queryKey: panelQueryKey(key),
    // Never called: `run` supplies the loader through `store`.
    queryFn: () => Promise.resolve<PanelEntry<T>>({ state: "loading" }),
    enabled: false,
    staleTime: Infinity,
    gcTime: PANEL_GC_MS,
  });
  return [query.data, (load) => void store(key, load)];
}
