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
  | "tags"
  | "matches"
  | "graph"
  | "auto"
  | "conversations"
  | "knowledge"
  | "journal"
  | "jobs"
  | "models"
  | "external"
  | "components"
  | "integrations"
  | "docs"
  | "billing"
  | "users";

interface NavGroup {
  label: string;
  views: readonly NavView[];
}

// The sidebar's grouped information architecture.  `NAV_VIEWS` is derived from
// it, so a view cannot exist without a group.
// Ordered by an analyst's day: the corpus and its three core objects first,
// what informs them next, the agent, then the activity record and settings.
export const NAV_GROUPS = [
  { label: "Overview", views: ["dashboard", "search"] },
  {
    label: "Corpus",
    views: ["binaries", "functions", "matches", "analyses", "collections", "tags"],
  },
  { label: "Intelligence", views: ["knowledge", "graph", "external"] },
  { label: "Agent", views: ["auto", "conversations"] },
  { label: "Activity", views: ["jobs", "journal"] },
  {
    label: "Settings",
    views: ["models", "components", "integrations", "users", "billing", "docs"],
  },
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
  tags: "Tags",
  conversations: "Conversations",
  knowledge: "Knowledge",
  graph: "Graph",
  components: "Components",
  integrations: "Integrations",
  users: "Users",
  journal: "Journal",
  jobs: "Jobs",
  models: "Models",
  external: "External",
  docs: "Documentation",
  billing: "Billing",
  search: "Search",
};

/** Path the sidebar links a view to; the dashboard owns the index route. */
export function navPath(view: NavView): string {
  return view === "dashboard" ? "/" : `/${view}`;
}
