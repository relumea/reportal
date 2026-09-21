# Adding an SPA view

Prerequisites: read [App.tsx](../../web/src/App.tsx) (the lazy imports, the `routes` table, the
`RouteHandle`), [router.ts](../../web/src/router.ts) (`NavView`, `NAV_GROUPS`, `NAV_LABELS`,
`navPath`), a small view such as [TagsView.tsx](../../web/src/views/TagsView.tsx), and
[SPA.md](../SPA.md#what-loads-when).

## Steps

1. Add the view module under `web/src/views/`, exporting the component by name:

   ```tsx
   export function TagsView({ query }: { query: Record<string, string> }): ReactNode {
   ```

   Read data through `api` from `../api`, render with the shared widgets from `../components`
   (`Panel`, `DataTable`, `ErrorNote`, `Loading`, `EmptyState`), and type every payload in
   `../types`.
2. Declare the route in the `NavView` union in `web/src/router.ts`, then add it to a group in
   `NAV_GROUPS` and a label in `NAV_LABELS`. `NAV_VIEWS` is derived from the groups, so a view
   cannot exist without a group.
3. Import it lazily in `web/src/App.tsx`, beside the other `lazy` calls. Only the dashboard is a
   static import; every other view is `React.lazy`, and the bundle check fails when a view marker
   reaches the entry chunk.
4. Add a route object to the `routes` array in `App.tsx`:

   ```tsx
   { path: "/tags", element: <TagsRoute />, handle: { view: "tags", title: "Tags" } },
   ```

   `handle.view` is the `NavView` the sidebar highlights; `handle.title` is a string or a function
   of the route params. A route with a single path (no params) can pass the element directly.
5. Add a `g`-prefixed keyboard jump in `NAV_JUMPS` only when the view's initial is unique, as the
   comment above the table requires.
6. Add the route and its DOM markers to `ROUTE_CHECKS` in `tools/smoke_spa.py`. Each inner tuple is
   a group of alternatives; the route passes when the rendered DOM carries one marker per group.
7. Keep the first paint cheap: a view that opens a dialog or fetches on mount uses the existing
   `useAsync` and panel cache rather than a new global store. View-only CSS belongs in a
   co-located `*.css` imported by that view (or panel), not in `styles.css`; the entry
   stylesheet is budgeted by `tools/smoke_spa.py`.

## Verify

1. `(cd web && bun run typecheck)` proves the view, the route table and the types compile.
2. `(cd web && bun run lint)` proves the view passes oxlint.
3. `make spa` builds the Vite assets into `src/reportal/assets/dist/`, then
   `.venv/bin/python tools/smoke_spa.py` renders every route and asserts the markers, and fails
   when a view marker lands in the entry bundle.
4. `make check-fast` is the gate for the change; `make check` adds the browser smoke and audit.

## See also

- [ARCHITECTURE.md section](../ARCHITECTURE.md#spa)
- [SPA.md](../SPA.md)
