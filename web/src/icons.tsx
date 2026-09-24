// Authored stroke icons: one 16-unit grid, one stroke weight, drawn in
// currentColor so every theme colours them.  Styling is `.icon` in styles.css.

import type { ReactNode } from "react";

const PATHS = {
  back: "M10 3 5 8l5 5",
  forward: "m6 3 5 5-5 5",
  collapse: "M8 3 3 8l5 5M13 3 8 8l5 5",
  expand: "m3 3 5 5-5 5M8 3l5 5-5 5",
  ascending: "m4 10 4-4 4 4",
  descending: "m4 6 4 4 4-4",
  copy: "M6 6h7v7H6zM3.5 10.5v-7h7",
  check: "m3.5 8.5 3 3 6-7",
  bell: "M4 11.5V7a4 4 0 0 1 8 0v4.5l1 1H3zM6.5 14.5h3",
  edit: "M10.5 2.5l3 3-8 8h-3v-3zM8.5 4.5l3 3",
  // Sidebar views, keyed by their route id (router.ts `NavView`).
  dashboard: "M2.5 2.5h4.5v4.5H2.5zM9 2.5h4.5v4.5H9zM2.5 9h4.5v4.5H2.5zM9 9h4.5v4.5H9z",
  search: "M2.5 7a4.5 4.5 0 1 0 9 0a4.5 4.5 0 1 0-9 0M10.3 10.3l3.2 3.2",
  binaries: "M4 1.5h5.5l3 3v10H4zM9.5 1.5v3h3M6.5 8h3.5M6.5 11h3.5",
  functions:
    "M6 2.5c-1.4 0-2 .6-2 2v1.5c0 .9-.5 1.5-1.5 2 1 .5 1.5 1.1 1.5 2v1.5c0 1.4.6 2 2 2" +
    "M10 2.5c1.4 0 2 .6 2 2v1.5c0 .9.5 1.5 1.5 2-1 .5-1.5 1.1-1.5 2v1.5c0 1.4-.6 2-2 2",
  matches: "M2.5 5.5h9L9 3M13.5 10.5h-9L7 13",
  analyses: "M3 13.5v-4M8 13.5v-10M13 13.5v-7M1.5 13.5h13",
  collections: "M2.5 5.5 8 2.5l5.5 3L8 8.5zM2.5 8.5 8 11.5l5.5-3M2.5 11.5 8 14.5l5.5-3",
  tags: "M2.5 2.5h5.5l6 6-5.5 5.5-6-6zM5.5 5.5h.01",
  knowledge: "M3 13V3.5A2 2 0 0 1 5 1.5h8v10H5a2 2 0 0 0-2 2 2 2 0 0 0 2 2h8",
  graph:
    "M2.5 4a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0M10.5 4a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0" +
    "M6.5 12.5a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0M5.5 4h5M4.6 5.2l2.7 5.8M11.4 5.2l-2.7 5.8",
  external: "M9 2.5h4.5V7M13.5 2.5l-6 6M11.5 9.5v4h-9v-9h4",
  auto: "M9 1.5 3.5 9h4l-1 5.5L12.5 7h-4z",
  conversations: "M2.5 3h11v8H7.5l-3 2.5V11h-2z",
  jobs: "M2.5 4h1.5M6.5 4h7M2.5 8h1.5M6.5 8h7M2.5 12h1.5M6.5 12h7",
  journal: "M2.8 6.2A5.5 5.5 0 1 1 2.5 8M2.5 2.5V6H6M8 5v3.2l2 1.3",
  models:
    "M4.5 4.5h7v7h-7zM6.5 1.5v3M9.5 1.5v3M6.5 11.5v3M9.5 11.5v3" +
    "M1.5 6.5h3M1.5 9.5h3M11.5 6.5h3M11.5 9.5h3",
  components: "M1.5 5h3.5v6H1.5zM6.25 5h3.5v6h-3.5zM11 5h3.5v6H11zM5 8h1.25M9.75 8H11",
  integrations: "M5.5 1.5v3M10.5 1.5v3M3.5 4.5h9V7a4.5 4.5 0 0 1-9 0zM8 11.5v3",
  users: "M5 5a3 3 0 1 0 6 0a3 3 0 1 0-6 0M2.5 14.5c.5-3 2.7-4.5 5.5-4.5s5 1.5 5.5 4.5",
  billing: "M1.5 3.5h13v9h-13zM1.5 6.5h13M4 10h3",
  docs: "M3.5 1.5h9v13h-9zM6 5h4M6 8h4M6 11h2.5",
} as const;

export type IconName = keyof typeof PATHS;

/** A decorative icon; the control it sits in carries the accessible name. */
export function Icon({ name }: { name: IconName }): ReactNode {
  return (
    <svg className="icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path d={PATHS[name]} />
    </svg>
  );
}
