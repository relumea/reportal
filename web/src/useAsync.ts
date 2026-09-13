// The view data hook: one query per call, keyed by the caller's dependencies.
// react-query owns the cache, the in-flight state and the refetch; the hook
// keeps the shape the views were written against (`data`, `error`, `reload`)
// and polls on an interval when one is given.

import { useQuery } from "@tanstack/react-query";
import { useId, useRef } from "react";

export interface AsyncState<T> {
  data?: T;
  error?: unknown;
}

export interface AsyncResult<T> extends AsyncState<T> {
  reload: () => void;
}

/**
 * An interval in milliseconds, or a function of the data that returns one (or
 * `false` to stop).  The function form is what a signal that settles uses: it
 * polls while the run is `running` and stops on the answer that ends it.
 */
export type PollInterval<T> = number | false | ((data: T | undefined) => number | false);

export function useAsync<T>(
  load: () => Promise<T>,
  deps: ReadonlyArray<unknown>,
  enabled = true,
  poll?: PollInterval<T>,
): AsyncResult<T> {
  // `load` is recreated every render; the query key is the caller's `deps`, so
  // hold the loader in a ref and keep the query identity stable.
  const loadRef = useRef(load);
  loadRef.current = load;
  // The hook is per view, not a shared cache: `deps` alone would collide
  // between two views that pass `[]` (the health and the sidebar list both do),
  // so the instance's own id leads the key.  A remount starts fresh, as the
  // hook this replaces did.
  const instance = useId();
  const query = useQuery<T>({
    queryKey: [instance, ...deps],
    queryFn: () => loadRef.current(),
    enabled,
    // A mount always asks for fresh data, as the hook it replaces did.
    staleTime: 0,
    refetchOnMount: "always",
    refetchInterval: (query) => {
      if (poll === undefined) return false;
      return typeof poll === "function" ? poll(query.state.data) : poll;
    },
  });
  return {
    ...(query.data === undefined ? {} : { data: query.data }),
    ...(query.error === null ? {} : { error: query.error }),
    reload: () => {
      void query.refetch();
    },
  };
}
