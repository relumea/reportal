// The SPA's information architecture: which views exist, how the sidebar groups
// them, what each is called and the path it lives at.  Routing itself --
// matching a URL, reading its parameters and its query, pushing a new one -- is
// react-router's (see `App.tsx`), so this module owns no location state.

export type NavView =
  | "dashboard"
  | "search"
  | "binaries"
  | "analyses"
  | "functions"
  | "collections"
  | "matches"
  | "graph"
  | "auto"
  | "conversations"
  | "knowledge"
  | "journal"
  | "jobs"
  | "components"
  | "integrations"
  | "users";

export interface NavGroup {
  label: string;
  views: readonly NavView[];
}

// The sidebar's grouped information architecture.  `NAV_VIEWS` is derived from
// it, so a view cannot exist without a group.
export const NAV_GROUPS = [
  { label: "Overview", views: ["dashboard", "search"] },
  { label: "Targets", views: ["binaries", "analyses", "functions", "collections"] },
  { label: "Analysis", views: ["matches", "graph", "knowledge"] },
  { label: "Agent", views: ["auto", "conversations"] },
  { label: "System", views: ["jobs", "journal", "components", "integrations", "users"] },
] as const satisfies readonly NavGroup[];

export const NAV_VIEWS: readonly NavView[] = NAV_GROUPS.flatMap((group) => group.views);

export const NAV_LABELS: Record<NavView, string> = {
  dashboard: "Dashboard",
  binaries: "Binaries",
  analyses: "Analyses",
  functions: "Functions",
  matches: "Matches",
  auto: "Auto-mode",
  collections: "Collections",
  conversations: "Conversations",
  knowledge: "Knowledge",
  graph: "Graph",
  components: "Components",
  integrations: "Integrations",
  users: "Users",
  journal: "Journal",
  jobs: "Jobs",
  search: "Search",
};

/** Path the sidebar links a view to; the dashboard owns the index route. */
export function navPath(view: NavView): string {
  return view === "dashboard" ? "/" : `/${view}`;
}
