// Playwright global setup: seed the workspace, start `reportal serve` against
// it, and publish the state the specs read.
//
// A global setup rather than the config's `webServer` because the server needs
// a database that only exists after seeding: the two steps are one ordered
// unit, and a `webServer` would start before or independently of the seed.

import { existsSync } from "node:fs";
import { join } from "node:path";

import { writeE2eState } from "./e2e-state";
import { seedWorkspace } from "./seed";
import { startServer } from "./server";
import {
  SERVER_HOST,
  baseUrl,
  databasePath,
  port,
  pythonPath,
  rebrewPath,
  repoRoot,
  workspacePath,
} from "./workspace";

export default async function globalSetup(): Promise<void> {
  const rebrew = rebrewPath();
  if (!existsSync(rebrew)) {
    throw new Error(
      `missing rebrew CLI at ${rebrew}; run make setup (installs .venv/bin/rebrew) or cd ../rebrew && make setup`,
    );
  }
  const seed = seedWorkspace();
  const url = baseUrl();
  const server = await startServer({
    python: pythonPath(),
    host: SERVER_HOST,
    port: port(),
    baseUrl: url,
    cwd: seed.workspace,
    env: {
      ...process.env,
      REPORTAL_DB: databasePath(),
      REPORTAL_REBREW: rebrew,
      // The seeded workspace carries no docs/ of its own, so the documentation
      // view reads this checkout's documents.
      REPORTAL_DOCS: join(repoRoot(), "docs"),
    },
  });
  writeE2eState({
    baseUrl: url,
    port: port(),
    pid: server.pid,
    workspace: workspacePath(),
    ids: seed.ids,
    function_name: seed.function_name,
    collections: seed.collections,
    types: seed.types,
    tag_name: seed.tag_name,
    large_binary_id: seed.large_binary_id,
    large_function_count: seed.large_function_count,
    stale_run: seed.stale_run,
    team: seed.team,
    similar: seed.similar,
  });
}
