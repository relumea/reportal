// Starting and stopping the `reportal serve` the specs drive.  The server
// runs detached in its own process group, so the teardown can stop it and any
// child it spawned with one group signal.

import { spawn } from "node:child_process";

export const HEALTH_PATH = "/api/health";

const START_TIMEOUT_MS = 30_000;
const STOP_TIMEOUT_MS = 10_000;
const POLL_INTERVAL_MS = 250;
const HEALTH_TIMEOUT_MS = 2_000;
const MAX_LOG_CHARS = 8_000;

export interface RunningServer {
  /** Process-group leader; `stopServerGroup` sends to `-pid`. */
  pid: number;
  logs: () => string;
}

export interface StartServerOptions {
  python: string;
  host: string;
  port: number;
  baseUrl: string;
  cwd: string;
  env: NodeJS.ProcessEnv;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function healthy(baseUrl: string): Promise<boolean> {
  try {
    const response = await fetch(`${baseUrl}${HEALTH_PATH}`, {
      signal: AbortSignal.timeout(HEALTH_TIMEOUT_MS),
    });
    return response.ok;
  } catch {
    return false;
  }
}

function alive(pid: number): boolean {
  try {
    process.kill(-pid, 0);
    return true;
  } catch {
    return false;
  }
}

export async function startServer(options: StartServerOptions): Promise<RunningServer> {
  const child = spawn(
    options.python,
    [
      "-m",
      "reportal",
      "serve",
      "--host",
      options.host,
      "--port",
      String(options.port),
      "--no-open",
    ],
    { cwd: options.cwd, env: options.env, detached: true, stdio: ["ignore", "pipe", "pipe"] },
  );
  const chunks: string[] = [];
  const record = (data: Buffer): void => {
    chunks.push(data.toString());
    while (chunks.join("").length > MAX_LOG_CHARS) chunks.shift();
  };
  child.stdout?.on("data", record);
  child.stderr?.on("data", record);

  const pid = child.pid;
  if (pid === undefined) throw new Error("reportal serve did not spawn");
  const logs = (): string => chunks.join("");
  const deadline = Date.now() + START_TIMEOUT_MS;
  for (;;) {
    if (await healthy(options.baseUrl)) return { pid, logs };
    if (child.exitCode !== null) {
      throw new Error(`reportal serve exited with ${child.exitCode}:\n${logs()}`);
    }
    if (Date.now() >= deadline) {
      await stopServerGroup(pid);
      throw new Error(`reportal serve never answered ${options.baseUrl}:\n${logs()}`);
    }
    await delay(POLL_INTERVAL_MS);
  }
}

export async function stopServerGroup(pid: number): Promise<void> {
  if (!alive(pid)) return;
  process.kill(-pid, "SIGTERM");
  const deadline = Date.now() + STOP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (!alive(pid)) return;
    await delay(POLL_INTERVAL_MS);
  }
  process.kill(-pid, "SIGKILL");
}
