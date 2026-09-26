import { Component, Suspense, lazy, useCallback, useEffect, useRef, useState } from "react";
import type { ErrorInfo, ReactNode } from "react";

import {
  Link,
  matchRoutes,
  useLocation,
  useNavigate,
  useParams,
  useRoutes,
  useSearchParams,
} from "react-router";
import type { Params, RouteObject } from "react-router";

import { Icon } from "./icons";
import { api } from "./api";
import { Button, EmptyState, ErrorNote, Loading, Panel, ViewTitle } from "./components";
import {
  clickFocusedRowAction,
  clickFocusedSave,
  cycleViewSection,
  discardFocusedTypeEdit,
  displayCombo,
  focusMemoryGoto,
  focusPanel,
  focusViewFilter,
  focusViewFilters,
  installShortcuts,
  isMac,
  jumpTableRow,
  moveTableRow,
  registerShortcut,
} from "./keys";
import { toggleFunctionCodeView } from "./panels/codeViewSwitch";
import { NAV_GROUPS, NAV_LABELS, navPath } from "./router";
import type { NavView } from "./router";
import type { Health } from "./types";
import { DashboardView } from "./views/DashboardView";

// Every view but the dashboard is loaded when its route is first opened, so
// the initial bundle carries the shell, the dashboard and the shortcut layer
// rather than the whole workbench: the binary detail view alone (its panels,
// the memory dump and the data type editor) is a third of the source.  The
// dashboard stays eager because it is the landing route.  The shell's `Space`
// binding only imports `codeViewSwitch`, so FunctionPanels stays out of the
// entry chunk and loads with the function detail route.  Search, the cheatsheet
// and the notification centre load on first open so their fetch and render
// code stay off the critical path.
const AutoView = lazy(() => import("./views/AutoView").then((m) => ({ default: m.AutoView })));
const AnalysesView = lazy(() =>
  import("./views/AnalysesView").then((m) => ({ default: m.AnalysesView })),
);
const BinaryDetail = lazy(() =>
  import("./views/BinaryDetail").then((m) => ({ default: m.BinaryDetail })),
);
const BinariesView = lazy(() =>
  import("./views/BinariesView").then((m) => ({ default: m.BinariesView })),
);
const TagsView = lazy(() => import("./views/TagsView").then((m) => ({ default: m.TagsView })));

const CollectionsView = lazy(() =>
  import("./views/CollectionsView").then((m) => ({ default: m.CollectionsView })),
);
const ComponentsView = lazy(() =>
  import("./views/ComponentsView").then((m) => ({ default: m.ComponentsView })),
);
const ExternalView = lazy(() =>
  import("./views/ExternalView").then((m) => ({ default: m.ExternalView })),
);
const ConversationsView = lazy(() =>
  import("./views/ConversationsView").then((m) => ({ default: m.ConversationsView })),
);
const ConversationDetail = lazy(() =>
  import("./views/ConversationsView").then((m) => ({ default: m.ConversationDetail })),
);
const DocumentationView = lazy(() =>
  import("./views/DocumentationView").then((m) => ({ default: m.DocumentationView })),
);
const ChangelogView = lazy(() =>
  import("./views/DocumentationView").then((m) => ({ default: m.ChangelogView })),
);
const DiffView = lazy(() => import("./views/DiffView").then((m) => ({ default: m.DiffView })));
const FunctionDetail = lazy(() =>
  import("./views/FunctionDetail").then((m) => ({ default: m.FunctionDetail })),
);
const FunctionsView = lazy(() =>
  import("./views/FunctionsView").then((m) => ({ default: m.FunctionsView })),
);
const GraphView = lazy(() => import("./views/GraphView").then((m) => ({ default: m.GraphView })));
const IntegrationsView = lazy(() =>
  import("./views/IntegrationsView").then((m) => ({ default: m.IntegrationsView })),
);
const JobsView = lazy(() => import("./views/JobsView").then((m) => ({ default: m.JobsView })));
const JournalView = lazy(() =>
  import("./views/JournalView").then((m) => ({ default: m.JournalView })),
);
const KnowledgeView = lazy(() =>
  import("./views/KnowledgeView").then((m) => ({ default: m.KnowledgeView })),
);
const MatchesView = lazy(() =>
  import("./views/MatchesView").then((m) => ({ default: m.MatchesView })),
);
const ModelsView = lazy(() => import("./views/ModelsView").then((m) => ({ default: m.ModelsView })));
const SearchView = lazy(() =>
  import("./views/SearchView").then((m) => ({ default: m.SearchView })),
);
const UsersView = lazy(() => import("./views/UsersView").then((m) => ({ default: m.UsersView })));
const BillingView = lazy(() =>
  import("./views/BillingView").then((m) => ({ default: m.BillingView })),
);
const SearchModal = lazy(() =>
  import("./views/SearchModal").then((m) => ({ default: m.SearchModal })),
);
const CheatsheetDialog = lazy(() =>
  import("./views/CheatsheetDialog").then((m) => ({ default: m.CheatsheetDialog })),
);
// The sidebar foot's controls and the sign-in gate load on their own, off the
// entry bundle.
const SidebarFoot = lazy(() =>
  import("./SidebarFoot").then((m) => ({ default: m.SidebarFoot })),
);
const NotificationsBell = lazy(() =>
  import("./views/NotificationsDialog").then((m) => ({ default: m.NotificationsBell })),
);

// A chunk name this page no longer finds on the server: the SPA was rebuilt
// (an upgrade) since the page loaded, so its entry bundle points at old names.
const STALE_CHUNK = /Failed to fetch dynamically imported module|Importing a module script failed/u;
// sessionStorage key and window of the one automatic reload a stale chunk gets;
// a second failure inside the window is a real fault and is shown.
const STALE_RELOAD_KEY = "reportal-stale-chunk-reload";
const STALE_RELOAD_WINDOW_MS = 30_000;

/** Reload once for a stale chunk; false when the page already tried. */
function reloadForStaleChunk(): boolean {
  try {
    const last = Number(sessionStorage.getItem(STALE_RELOAD_KEY) ?? 0);
    if (Date.now() - last < STALE_RELOAD_WINDOW_MS) return false;
    sessionStorage.setItem(STALE_RELOAD_KEY, String(Date.now()));
  } catch {
    // Storage is blocked (a private window): without the guard a reload
    // could loop, so the error below stays on screen instead.
    return false;
  }
  window.location.reload();
  return true;
}

/** Catch a failed lazy chunk so a missing or broken view says so instead of
 * leaving the content pane blank. */
class ViewLoadBoundary extends Component<
  { children: ReactNode },
  { message: string | null }
> {
  override state: { message: string | null } = { message: null };

  static getDerivedStateFromError(error: unknown): { message: string } {
    const text = error instanceof Error ? error.message : "Failed to load this view";
    return { message: text };
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    if (STALE_CHUNK.test(error.message) && reloadForStaleChunk()) return;
    console.error("view chunk failed", error, info.componentStack);
  }

  override render(): ReactNode {
    if (this.state.message !== null) {
      return (
        <ErrorNote
          error={`Could not load this view (${this.state.message}). Reload the page, or rebuild the SPA if the build is stale.`}
          onRetry={() => window.location.reload()}
        />
      );
    }
    return this.props.children;
  }
}

// The `g` prefix jumps to a sidebar view: its initial where that is unique,
// otherwise a letter from the word (`g o` for Auto-mode, `g n` for
// Conversations, `g p` for Components, `g y` for Billing).  Every key names a
// control that exists, the sidebar link to that view.
const NAV_JUMPS: ReadonlyArray<readonly [string, NavView]> = [
  ["d", "dashboard"],
  ["s", "search"],
  ["b", "binaries"],
  ["a", "analyses"],
  ["f", "functions"],
  ["c", "collections"],
  ["t", "tags"],
  ["m", "matches"],
  ["g", "graph"],
  ["k", "knowledge"],
  ["o", "auto"],
  ["n", "conversations"],
  ["j", "journal"],
  ["p", "components"],
  ["i", "integrations"],
  ["h", "docs"],
  ["e", "external"],
  ["u", "users"],
  ["q", "jobs"],
  ["l", "models"],
  ["y", "billing"],
];

/** What a matched route contributes to the shell: the sidebar section it
 * belongs to and the topbar title, which may depend on its parameters. */
interface RouteHandle {
  /** The sidebar entry this route belongs to; null for a page no entry owns. */
  view: NavView | null;
  title: string | ((params: Params<string>) => string);
}

type AppRoute = RouteObject & { handle: RouteHandle };

/** The brand mark (BRAND.md section 2): a lowercase r in 3×3 coverage cells on a
 * 24-unit grid, as [x, y, class suffix]. The arm's end is the one lit cell. */
const MARK_CELLS: ReadonlyArray<readonly [number, number, "ink" | "cell" | "off"]> = [
  [1.5, 1.5, "ink"], [9, 1.5, "ink"], [16.5, 1.5, "cell"],
  [1.5, 9, "ink"], [9, 9, "off"], [16.5, 9, "off"],
  [1.5, 16.5, "ink"], [9, 16.5, "off"], [16.5, 16.5, "off"],
];

/** Route elements: each reads its own parameters and hands its view the props. */
/** A route no view owns: a stale or mistyped link says so, rather than landing
 * silently on the dashboard as if it had worked. */
function NotFound(): ReactNode {
  const location = useLocation();
  return (
    <Panel title="Page not found">
      <EmptyState>
        Nothing lives at <code>#{location.pathname}</code>. Pick a view from the sidebar, or{" "}
        <Link to="/">open the dashboard</Link>.
      </EmptyState>
    </Panel>
  );
}

function BinaryRoute(): ReactNode {
  const { binaryId } = useParams();
  const [params] = useSearchParams();
  // The data-type filters live in the hash, so a filtered model is a link the
  // convention the Analyses view already uses.
  return <BinaryDetail binaryId={Number(binaryId)} query={Object.fromEntries(params)} />;
}

function FunctionsRoute({ onOpenMatches }: { onOpenMatches: (id: number) => void }): ReactNode {
  const { binaryId } = useParams();
  const [params] = useSearchParams();
  return (
    <FunctionsView
      binaryId={binaryId === undefined ? null : Number(binaryId)}
      query={Object.fromEntries(params)}
      onOpenMatches={onOpenMatches}
    />
  );
}

function MatchesRoute({
  functionId,
  onSelectFunction,
}: {
  functionId: number | null;
  onSelectFunction: (functionId: number | null) => void;
}): ReactNode {
  const [params] = useSearchParams();
  const fromQuery = Number(params.get("function"));
  const queried = Number.isFinite(fromQuery) && fromQuery > 0 ? fromQuery : null;
  return (
    <MatchesView functionId={queried ?? functionId} onSelectFunction={onSelectFunction} />
  );
}

function FunctionRoute(): ReactNode {
  const { functionId } = useParams();
  return <FunctionDetail functionId={Number(functionId)} />;
}

function DiffRoute(): ReactNode {
  const { functionId, candidateId } = useParams();
  return <DiffView functionId={Number(functionId)} candidateId={Number(candidateId)} />;
}

function ConversationRoute(): ReactNode {
  const { conversationId } = useParams();
  return <ConversationDetail conversationId={Number(conversationId)} />;
}

function AutoRoute(): ReactNode {
  const { binaryId } = useParams();
  return <AutoView binaryId={binaryId === undefined ? null : Number(binaryId)} />;
}

function JournalRoute(): ReactNode {
  const { action } = useParams();
  const [params] = useSearchParams();
  return <JournalView action={action ?? null} query={Object.fromEntries(params)} />;
}

function AnalysesRoute(): ReactNode {
  const [params] = useSearchParams();
  return <AnalysesView query={Object.fromEntries(params)} />;
}

function JobsRoute(): ReactNode {
  const [params] = useSearchParams();
  return <JobsView query={Object.fromEntries(params)} />;
}

function BinariesRoute(): ReactNode {
  const [params] = useSearchParams();
  return <BinariesView query={Object.fromEntries(params)} />;
}

function TagsRoute(): ReactNode {
  const [params] = useSearchParams();
  return <TagsView query={Object.fromEntries(params)} />;
}

function CollectionsRoute(): ReactNode {
  const [params] = useSearchParams();
  return <CollectionsView query={Object.fromEntries(params)} />;
}

/** Where the shell remembers whether the sidebar is collapsed. */
const SIDEBAR_STORAGE_KEY = "reportal.sidebar.collapsed";

/** Where the in-app history stack lives; it is per tab, not per install. */
const HISTORY_STORAGE_KEY = "reportal.history";

/** How many entries the in-app history keeps. */
const HISTORY_LIMIT = 50;

function storedCollapsed(): boolean {
  try {
    return window.localStorage.getItem(SIDEBAR_STORAGE_KEY) === "1";
  } catch {
    // Storage disabled: the sidebar starts open and forgets the toggle.
    return false;
  }
}

function storedHistory(): { stack: string[]; index: number } {
  try {
    const raw = window.sessionStorage.getItem(HISTORY_STORAGE_KEY);
    if (raw === null) return { stack: [], index: -1 };
    const parsed = JSON.parse(raw) as { stack?: string[]; index?: number };
    return { stack: parsed.stack ?? [], index: parsed.index ?? -1 };
  } catch {
    return { stack: [], index: -1 };
  }
}

export function App(): ReactNode {
  const navigate = useNavigate();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(storedCollapsed);
  const history = useRef(storedHistory());
  // Set while `stepHistory` navigates, so recording the new location does not
  // push the entry the reader just stepped off.
  const rewinding = useRef(false);
  const [canGoBack, setCanGoBack] = useState(false);
  const [canGoForward, setCanGoForward] = useState(false);
  const [health, setHealth] = useState<Health | null>(null);
  const [selectedFunctionId, setSelectedFunctionId] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [cheatsheetOpen, setCheatsheetOpen] = useState(false);
  // The name a loaded detail row publishes, keyed to the path it loaded for, so
  // a title from a view the router already left cannot linger on the next one.
  const [viewTitle, setViewTitle] = useState<{ path: string; title: string } | null>(null);
  const publishTitle = useCallback(
    (title: string | null) => {
      setViewTitle(title === null ? null : { path: location.pathname, title });
    },
    [location.pathname],
  );

  useEffect(() => {
    let active = true;
    api<Health>("/health").then(
      (data) => {
        if (active) setHealth(data);
      },
      () => {},
    );
    return () => {
      active = false;
    };
  }, []);

  // The sidebar collapse is a preference, so it survives a reload.
  useEffect(() => {
    try {
      window.localStorage.setItem(SIDEBAR_STORAGE_KEY, collapsed ? "1" : "0");
    } catch {
      // See storedCollapsed.
    }
  }, [collapsed]);

  // The in-app history: every view the tab visited, oldest first, with the
  // index the reader is on.  It is kept in sessionStorage so it is per tab, and
  // the router's own back and forward still work beside it.
  const syncHistoryNav = (): void => {
    const { stack, index } = history.current;
    setCanGoBack(index > 0);
    setCanGoForward(index >= 0 && index < stack.length - 1);
  };

  const remember = (path: string): void => {
    const { stack, index } = history.current;
    if (stack[index] === path) {
      syncHistoryNav();
      return;
    }
    const trimmed = [...stack.slice(0, index + 1), path].slice(-HISTORY_LIMIT);
    history.current = { stack: trimmed, index: trimmed.length - 1 };
    try {
      window.sessionStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history.current));
    } catch {
      // See storedHistory.
    }
    syncHistoryNav();
  };

  useEffect(() => {
    const path = `${location.pathname}${location.search}`;
    if (rewinding.current) {
      rewinding.current = false;
      syncHistoryNav();
      return;
    }
    remember(path);
    // The recorded entry follows the location.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [location.pathname, location.search]);

  const stepHistory = (delta: number): void => {
    const { stack, index } = history.current;
    const next = index + delta;
    if (next < 0 || next >= stack.length) return;
    const target = stack[next];
    history.current = { stack, index: next };
    try {
      window.sessionStorage.setItem(HISTORY_STORAGE_KEY, JSON.stringify(history.current));
    } catch {
      // See storedHistory.
    }
    syncHistoryNav();
    rewinding.current = true;
    void navigate(target);
  };

  // The keyboard layer.  Every shortcut the shell honours is registered in one
  // place and installed once, which is what the cheatsheet renders; the keys
  // that belong to a view register themselves as `view`-scoped bindings.
  useEffect(() => {
    const registered = [
      registerShortcut({
        combo: "mod+k",
        scope: "global",
        description: "Open the global search",
        handler: () => setSearchOpen(true),
      }),
      registerShortcut({
        combo: "?",
        scope: "global",
        description: "Show this keyboard cheatsheet",
        handler: () => setCheatsheetOpen(true),
      }),
      ...NAV_JUMPS.map(([key, view]) =>
        registerShortcut({
          combo: `g ${key}`,
          scope: "global",
          description: `Go to ${NAV_LABELS[view]}`,
          handler: () => navigate(navPath(view)),
        }),
      ),
      registerShortcut({
        combo: "o",
        scope: "view",
        description: "Jump to Overview",
        handler: () => focusPanel("Binary details"),
      }),
      registerShortcut({
        combo: "f",
        scope: "view",
        description: "Jump to Functions",
        handler: () => {
          const match = window.location.hash.match(/#\/binaries\/(\d+)/);
          navigate(match ? `/binaries/${match[1]}/functions` : "/functions");
        },
      }),
      registerShortcut({
        combo: "d",
        scope: "view",
        description: "Jump to Match / Diff",
        handler: () => {
          if (!focusPanel("Matches")) navigate("/matches");
        },
      }),
      registerShortcut({
        combo: "t",
        scope: "view",
        description: "Jump to Data types",
        handler: () => focusPanel("Data types"),
      }),
      registerShortcut({
        combo: "s",
        scope: "view",
        description: "Jump to Sandbox",
        handler: () => focusPanel("Sandbox"),
      }),
      registerShortcut({
        combo: "a",
        scope: "view",
        description: "Jump to Agents",
        handler: () => {
          if (!focusPanel("Conversations")) navigate("/conversations");
        },
      }),
      registerShortcut({
        combo: "m",
        scope: "view",
        description: "Jump to Memory",
        handler: () => focusPanel("Memory"),
      }),
      registerShortcut({
        combo: "shift+g",
        scope: "view",
        description: "Focus the memory address box",
        handler: () => focusMemoryGoto(),
      }),
      registerShortcut({
        combo: "j",
        scope: "view",
        description: "Focus the next row of the view's table",
        handler: () => moveTableRow(1),
      }),
      registerShortcut({
        combo: "k",
        scope: "view",
        description: "Focus the previous row of the view's table",
        handler: () => moveTableRow(-1),
      }),
      registerShortcut({
        combo: "shift+j",
        scope: "view",
        description: "Focus the last row of the view's table",
        handler: () => jumpTableRow(true),
      }),
      registerShortcut({
        combo: "shift+k",
        scope: "view",
        description: "Focus the first row of the view's table",
        handler: () => jumpTableRow(false),
      }),
      registerShortcut({
        combo: "r",
        scope: "view",
        description: "Rename the focused function",
        handler: () => clickFocusedRowAction("Rename"),
      }),
      registerShortcut({
        combo: "/",
        scope: "view",
        description: "Focus the view's filter box",
        handler: () => focusViewFilter(),
      }),
      registerShortcut({
        combo: "p",
        scope: "view",
        description: "Focus the view's filters",
        handler: () => focusViewFilters(),
      }),
      registerShortcut({
        combo: "mod+enter",
        scope: "view",
        description: "Save the focused type",
        whenTyping: true,
        handler: () => clickFocusedSave(),
      }),
      registerShortcut({
        combo: "escape",
        scope: "view",
        description: "Discard the focused type edit",
        whenTyping: true,
        handler: () => discardFocusedTypeEdit(),
      }),
      registerShortcut({
        combo: "[",
        scope: "view",
        description: "Scroll to the previous section",
        handler: () => cycleViewSection(-1),
      }),
      registerShortcut({
        combo: "]",
        scope: "view",
        description: "Scroll to the next section",
        handler: () => cycleViewSection(1),
      }),
      registerShortcut({
        combo: "space",
        scope: "view",
        description: "Toggle Disassembly and Control flow or AI decompilation",
        handler: () => toggleFunctionCodeView(),
      }),
      registerShortcut({
        combo: "mod+b",
        scope: "global",
        description: "Collapse or expand the sidebar",
        handler: () => setCollapsed((current) => !current),
      }),
      registerShortcut({
        combo: "alt+arrowleft",
        scope: "global",
        description: "Go back in this tab's view history",
        handler: () => stepHistory(-1),
      }),
      registerShortcut({
        combo: "alt+arrowright",
        scope: "global",
        description: "Go forward in this tab's view history",
        handler: () => stepHistory(1),
      }),
      registerShortcut({
        combo: "{",
        scope: "global",
        description: "Go back in this tab's view history",
        handler: () => stepHistory(-1),
      }),
      registerShortcut({
        combo: "}",
        scope: "global",
        description: "Go forward in this tab's view history",
        handler: () => stepHistory(1),
      }),
    ];
    const uninstall = installShortcuts();
    return () => {
      uninstall();
      for (const remove of registered) remove();
    };
  }, []);

  const openMatches = (functionId: number): void => {
    setSelectedFunctionId(functionId);
    navigate(navPath("matches"));
  };

  // One table is the single source of truth: react-router renders it, and the
  // same table is matched against the current location for the topbar title and
  // the sidebar's active section, so no path is written down twice.
  const routes: AppRoute[] = [
    { path: "/", element: <DashboardView />, handle: { view: "dashboard", title: "Dashboard" } },
    {
      path: "/search",
      element: <SearchView query={query} onQuery={setQuery} />,
      handle: { view: "search", title: "Search" },
    },
    {
      path: "/binaries",
      element: <BinariesRoute />,
      handle: { view: "binaries", title: "Binaries" },
    },
    {
      path: "/binaries/:binaryId",
      element: <BinaryRoute />,
      handle: { view: "binaries", title: (params) => `Binary #${params.binaryId}` },
    },
    {
      path: "/binaries/:binaryId/functions",
      element: <FunctionsRoute onOpenMatches={openMatches} />,
      handle: { view: "functions", title: "Functions" },
    },
    {
      path: "/functions",
      element: <FunctionsRoute onOpenMatches={openMatches} />,
      handle: { view: "functions", title: "Functions" },
    },
    {
      path: "/functions/:functionId",
      element: <FunctionRoute />,
      handle: { view: "functions", title: (params) => `Function #${params.functionId}` },
    },
    {
      path: "/diff/:functionId/:candidateId",
      element: <DiffRoute />,
      handle: {
        view: "functions",
        title: (params) => `Diff #${params.functionId} / #${params.candidateId}`,
      },
    },
    {
      path: "/analyses",
      element: <AnalysesRoute />,
      handle: { view: "analyses", title: "Analyses" },
    },
    {
      path: "/matches",
      element: (
        <MatchesRoute
          functionId={selectedFunctionId}
          onSelectFunction={setSelectedFunctionId}
        />
      ),
      handle: { view: "matches", title: "Matches" },
    },
    { path: "/auto", element: <AutoRoute />, handle: { view: "auto", title: "Auto-mode" } },
    {
      path: "/auto/:binaryId",
      element: <AutoRoute />,
      handle: { view: "auto", title: (params) => `Auto-mode \u00b7 binary #${params.binaryId}` },
    },
    {
      path: "/collections",
      element: <CollectionsRoute />,
      handle: { view: "collections", title: "Collections" },
    },
    {
      path: "/tags",
      element: <TagsRoute />,
      handle: { view: "tags", title: "Tags" },
    },
    {
      path: "/conversations",
      element: <ConversationsView />,
      handle: { view: "conversations", title: "Conversations" },
    },
    {
      path: "/conversations/:conversationId",
      element: <ConversationRoute />,
      handle: { view: "conversations", title: (params) => `Conversation #${params.conversationId}` },
    },
    { path: "/jobs", element: <JobsRoute />, handle: { view: "jobs", title: "Jobs" } },
    { path: "/models", element: <ModelsView />, handle: { view: "models", title: "Models" } },
    { path: "/external", element: <ExternalView />, handle: { view: "external", title: "External" } },
    { path: "/billing", element: <BillingView />, handle: { view: "billing", title: "Billing" } },
    { path: "/journal", element: <JournalRoute />, handle: { view: "journal", title: "Journal" } },
    {
      path: "/journal/:action",
      element: <JournalRoute />,
      handle: { view: "journal", title: (params) => `Journal \u00b7 action ${params.action}` },
    },
    {
      path: "/knowledge",
      element: <KnowledgeView />,
      handle: { view: "knowledge", title: "Knowledge" },
    },
    { path: "/graph", element: <GraphView />, handle: { view: "graph", title: "Graph" } },
    {
      path: "/components",
      element: <ComponentsView />,
      handle: { view: "components", title: "Components" },
    },
    {
      path: "/integrations",
      element: <IntegrationsView />,
      handle: { view: "integrations", title: "Integrations" },
    },
    {
      path: "/users",
      element: <UsersView />,
      handle: { view: "users", title: "Users" },
    },
    {
      path: "/docs",
      element: <DocumentationView />,
      handle: { view: "docs", title: "Documentation" },
    },
    {
      path: "/docs/:slug",
      element: <DocumentationView />,
      handle: { view: "docs", title: (params) => `Docs \u00b7 ${params.slug}` },
    },
    {
      path: "/changelog",
      element: <ChangelogView />,
      handle: { view: "docs", title: "Changelog" },
    },
    {
      path: "*",
      element: <NotFound />,
      handle: { view: null, title: "Page not found" },
    },
  ];
  const content = useRoutes(routes);
  const last = (matchRoutes(routes, location) ?? []).at(-1);
  const route = last?.route.handle as RouteHandle | undefined;
  const activeView: NavView | null = route === undefined ? "dashboard" : route.view;
  const routeTitle =
    typeof route?.title === "function"
      ? route.title((last?.params ?? {}) as Params<string>)
      : (route?.title ?? "relumea");
  const title =
    viewTitle !== null && viewTitle.path === location.pathname ? viewTitle.title : routeTitle;

  // The tab names the row the reader is on, like the shell title does.
  useEffect(() => {
    document.title = `${title} · relumea`;
  }, [title]);

  return (
    <div className={collapsed ? "layout sidebar-collapsed" : "layout"}>
      <a className="skip-link" href="#content">
        Skip to content
      </a>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" focusable="false">
              {MARK_CELLS.map(([x, y, kind]) => (
                <rect key={`${x}-${y}`} className={`brand-mark-${kind}`} x={x} y={y} width="6" height="6" rx="1.5" />
              ))}
            </svg>
          </span>
          <span className="brand-name">relumea</span>
          <button
            type="button"
            className="sidebar-toggle"
            aria-label={collapsed ? "Expand the sidebar" : "Collapse the sidebar"}
            aria-expanded={!collapsed}
            title="Toggle the sidebar (Ctrl/Command+B)"
            onClick={() => setCollapsed((current) => !current)}
          >
            <Icon name={collapsed ? "expand" : "collapse"} />
          </button>
        </div>
        <nav className="nav" aria-label="Sections">
          {NAV_GROUPS.map((group) => (
            <div className="nav-group" key={group.label}>
              <span className="nav-group-label">{group.label}</span>
              {group.views.map((view) => {
                const current = activeView === view;
                const label = NAV_LABELS[view];
                return (
                  <Link
                    key={view}
                    to={navPath(view)}
                    data-view={view}
                    className={current ? "nav-link active" : "nav-link"}
                    aria-current={current ? "page" : undefined}
                    title={label}
                  >
                    <Icon name={view} />
                    <span className="nav-link-text">{label}</span>
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
        {/* Workspace facts and the one per-reader preference: not page
            controls, so they sit with the navigation, not in every page head. */}
        <div className="sidebar-foot">
          <Suspense fallback={null}>
            <SidebarFoot />
          </Suspense>
          <span className="health" id="health">
            {health ? (
              <>
                <span className="health-dot" aria-hidden="true" />
                {`v${health.version} · ${health.counts.binaries} ${health.counts.binaries === 1 ? "binary" : "binaries"} · ${health.counts.functions} function${health.counts.functions === 1 ? "" : "s"}`}
              </>
            ) : null}
          </span>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="topbar-heading">
            <div className="history-nav" role="group" aria-label="View history">
              <Button
                tone="ghost"
                size="sm"
                disabled={!canGoBack}
                aria-label="Go back"
                title={`Go back (Alt+\u2190)`}
                onClick={() => stepHistory(-1)}
              >
                <Icon name="back" />
              </Button>
              <Button
                tone="ghost"
                size="sm"
                disabled={!canGoForward}
                aria-label="Go forward"
                title={`Go forward (Alt+\u2192)`}
                onClick={() => stepHistory(1)}
              >
                <Icon name="forward" />
              </Button>
            </div>
            <h1 id="title">{title}</h1>
          </div>
          <button
            type="button"
            className="btn btn-ghost btn-sm topbar-search"
            aria-keyshortcuts={isMac() ? "Meta+K" : "Control+K"}
            onClick={() => setSearchOpen(true)}
          >
            <Icon name="search" />
            Search
            <kbd className="key">{displayCombo("mod+k", isMac())}</kbd>
          </button>
          <Suspense fallback={null}>
            <NotificationsBell />
          </Suspense>
        </header>
        <div className="content" id="content" tabIndex={-1}>
          <ViewLoadBoundary>
            <ViewTitle.Provider value={publishTitle}>
              <Suspense fallback={<Loading label="Loading the view" />}>{content}</Suspense>
            </ViewTitle.Provider>
          </ViewLoadBoundary>
        </div>
      </main>
      {searchOpen ? (
        <ViewLoadBoundary>
          <Suspense fallback={null}>
            <SearchModal open onClose={() => setSearchOpen(false)} />
          </Suspense>
        </ViewLoadBoundary>
      ) : null}
      {cheatsheetOpen ? (
        <ViewLoadBoundary>
          <Suspense fallback={null}>
            <CheatsheetDialog open onClose={() => setCheatsheetOpen(false)} />
          </Suspense>
        </ViewLoadBoundary>
      ) : null}
    </div>
  );
}
