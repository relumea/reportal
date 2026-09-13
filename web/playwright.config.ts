import { defineConfig } from "@playwright/test";

import { baseUrl } from "./tests/workspace";

// Timeouts sized for the engine-backed routes (the function detail's
// disassembly and cross-references go through the sibling rebrew CLI).
const TEST_TIMEOUT_MS = 60_000;
const EXPECT_TIMEOUT_MS = 15_000;

// Traces, failure screenshots and error contexts land in the repo's
// gitignored .scratch/, like the smoke and audit workspaces.
const OUTPUT_DIR = "../.scratch/playwright";

// The browser comes from the local Playwright cache: package.json pins
// @playwright/test to 1.62.1, the version whose bundled chromium build
// (chromium-1234) is already under ~/.cache/ms-playwright. A different pin
// resolves a different revision the cache does not hold, so the run fails
// instead of launching; nothing downloads a browser at test time.
export default defineConfig({
  testDir: "tests",
  outputDir: OUTPUT_DIR,
  timeout: TEST_TIMEOUT_MS,
  expect: { timeout: EXPECT_TIMEOUT_MS },
  // One seeded workspace and one server, so writers must not race readers.
  fullyParallel: false,
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: [["list"]],
  // Seeding and the server live in the global setup, not in the config's
  // `webServer`: the server needs the database the seed creates, so the two
  // are one ordered unit rather than two Playwright-managed features.
  globalSetup: "./tests/global-setup.ts",
  globalTeardown: "./tests/global-teardown.ts",
  use: {
    baseURL: baseUrl(),
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    viewport: { width: 1280, height: 800 },
  },
  projects: [{ name: "chromium" }],
});
