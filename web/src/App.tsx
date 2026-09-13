import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import {
  Link,
  Navigate,
  matchRoutes,
  useLocation,
  useNavigate,
  useParams,
  useRoutes,
  useSearchParams,
} from "react-router";
import type { Params, RouteObject } from "react-router";

import { api } from "./api";
import { focusViewFilter, installShortcuts, moveTableRow, registerShortcut } from "./keys";
import { NAV_GROUPS, NAV_LABELS, navPath } from "./router";
import type { NavView } from "./router";
import type { Health } from "./types";
import { AutoView } from "./views/AutoView";
import { AnalysesView } from "./views/AnalysesView";
import { BinaryDetail } from "./views/BinaryDetail";
import { BinariesView } from "./views/BinariesView";
import { CollectionsView } from "./views/CollectionsView";
import { ComponentsView } from "./views/ComponentsView";
import { IntegrationsView } from "./views/IntegrationsView";
import { ConversationDetail, ConversationsView } from "./views/ConversationsView";
import { DashboardView } from "./views/DashboardView";
import { DiffView } from "./views/DiffView";
import { FunctionDetail } from "./views/FunctionDetail";
import { FunctionsView } from "./views/FunctionsView";
import { GraphView } from "./views/GraphView";
import { JobsView } from "./views/JobsView";
import { ExternalView } from "./views/ExternalView";
import { ModelsView } from "./views/ModelsView";
import { JournalView } from "./views/JournalView";
import { KnowledgeView } from "./views/KnowledgeView";
import { MatchesView } from "./views/MatchesView";
import { CheatsheetDialog } from "./views/CheatsheetDialog";
import { NotificationsBell } from "./views/NotificationsDialog";
import { SearchModal } from "./views/SearchModal";
import { SearchView } from "./views/SearchView";
import { UsersView } from "./views/UsersView";

// The `g` prefix jumps to a sidebar view: its initial where that is unique,
// otherwise a letter from the word (`g o` for Auto-mode, `g n` for
// Conversations, `g p` for Components).  Every key names a control that exists,
// the sidebar link to that view.
const NAV_JUMPS: ReadonlyArray<readonly [string, NavView]> = [
  ["d", "dashboard"],
  ["s", "search"],
  ["b", "binaries"],
  ["a", "analyses"],
  ["f", "functions"],
  ["c", "collections"],
  ["m", "matches"],
  ["g", "graph"],
  ["k", "knowledge"],
  ["o", "auto"],
  ["n", "conversations"],
  ["j", "journal"],
  ["p", "components"],
  ["i", "integrations"],
];

/** What a matched route contributes to the shell: the sidebar section it
 * belongs to and the topbar title, which may depend on its parameters. */
interface RouteHandle {
  view: NavView;
  title: string | ((params: Params<string>) => string);
}

type AppRoute = RouteObject & { handle: RouteHandle };

/** Route elements: each reads its own parameters and hands its view the props. */
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
  return <JournalView action={action ?? null} />;
}

function AnalysesRoute(): ReactNode {
  const [params] = useSearchParams();
  return <AnalysesView query={Object.fromEntries(params)} />;
}

export function App(): ReactNode {
  const navigate = useNavigate();
  const location = useLocation();
  const [health, setHealth] = useState<Health | null>(null);
  const [selectedFunctionId, setSelectedFunctionId] = useState<number | null>(null);
  const [query, setQuery] = useState("");
  const [searchOpen, setSearchOpen] = useState(false);
  const [cheatsheetOpen, setCheatsheetOpen] = useState(false);

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
        combo: "/",
        scope: "view",
        description: "Focus the view's filter box",
        handler: () => focusViewFilter(),
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
    navigate("#/matches");
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
      element: <BinariesView />,
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
        <MatchesView functionId={selectedFunctionId} onSelectFunction={setSelectedFunctionId} />
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
      element: <CollectionsView />,
      handle: { view: "collections", title: "Collections" },
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
    { path: "/jobs", element: <JobsView />, handle: { view: "jobs", title: "Jobs" } },
    { path: "/models", element: <ModelsView />, handle: { view: "models", title: "Models" } },
    { path: "/external", element: <ExternalView />, handle: { view: "external", title: "External" } },
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
      path: "*",
      element: <Navigate to="/" replace />,
      handle: { view: "dashboard", title: "Dashboard" },
    },
  ];
  const content = useRoutes(routes);
  const last = (matchRoutes(routes, location) ?? []).at(-1);
  const route = last?.route.handle as RouteHandle | undefined;
  const activeView: NavView = route?.view ?? "dashboard";
  const title =
    typeof route?.title === "function"
      ? route.title((last?.params ?? {}) as Params<string>)
      : (route?.title ?? "reportal");

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-dot" aria-hidden="true" />
          <span>reportal</span>
          <span className="brand-tag">workbench</span>
        </div>
        <nav className="nav" aria-label="Sections">
          {NAV_GROUPS.map((group) => (
            <div className="nav-group" key={group.label}>
              <span className="nav-group-label">{group.label}</span>
              {group.views.map((view) => {
                const current = activeView === view;
                return (
                  <Link
                    key={view}
                    to={navPath(view)}
                    data-view={view}
                    className={current ? "nav-link active" : "nav-link"}
                    aria-current={current ? "page" : undefined}
                  >
                    {NAV_LABELS[view]}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>
      <main className="main">
        <header className="topbar">
          <h1 id="title">{title}</h1>
          <NotificationsBell />
          <span className="health" id="health">
            {health ? (
              <>
                <span className="health-dot" aria-hidden="true" />
                {`v${health.version} · ${health.counts.binaries} binaries · ${health.counts.functions} functions`}
              </>
            ) : null}
          </span>
        </header>
        <div className="content" id="content">
          {content}
        </div>
      </main>
      <SearchModal open={searchOpen} onClose={() => setSearchOpen(false)} />
      <CheatsheetDialog open={cheatsheetOpen} onClose={() => setCheatsheetOpen(false)} />
    </div>
  );
}
