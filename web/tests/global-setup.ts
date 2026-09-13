// Playwright global setup: seed the workspace, start `reportal serve` against
// it, and publish the state the specs read.
//
// A global setup rather than the config's `webServer` because the server needs
// a database that only exists after seeding: the two steps are one ordered
// unit, and a `webServer` would start before or independently of the seed.

import { existsSync } from "node:fs";

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
  workspacePath,
} from "./workspace";

export default async function globalSetup(): Promise<void> {
  const rebrew = rebrewPath();
  if (!existsSync(rebrew)) {
    throw new Error(`missing the sibling rebrew CLI at ${rebrew}; install ../rebrew first`);
  }
  const seed = seedWorkspace();
  const url = baseUrl();
  const server = await startServer({
    python: pythonPath(),
    host: SERVER_HOST,
    port: port(),
    baseUrl: url,
    cwd: seed.workspace,
    env: { ...process.env, REPORTAL_DB: databasePath(), REPORTAL_REBREW: rebrew },
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
  });
}
