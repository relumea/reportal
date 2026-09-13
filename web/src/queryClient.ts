// The one QueryClient the SPA fetches through.  The view hook (`useAsync`) and
// the panel cache both read and write this instance, which is what lets a
// panel's data be shared across mounts, deduplicated and invalidated without a
// hand-rolled map.

import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // reportal's hooks never retried and the views never refetched on focus:
      // a reload is asked for explicitly, and the live signals poll on their
      // own interval.
      retry: false,
      refetchOnWindowFocus: false,
    },
  },
});
