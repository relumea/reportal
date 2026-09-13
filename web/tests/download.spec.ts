// The stored-binary download: the per-row action in the Binaries view and the
// route it points at, over the real HTTP server.

import type { Page } from "@playwright/test";

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

// The engine's PE magic, the first bytes of every stored notepad.exe.
const PE_MAGIC = "MZ";

function binariesPanel(page: Page) {
  return panelByTitle(page, "Binaries");
}

test("the download route serves the stored bytes with its headers", async ({ page }) => {
  const response = await page.request.get(`/api/binaries/${state.ids.binary_id}/download`);
  const body = await response.body();

  expect(response.status()).toBe(200);
  expect(response.headers()["content-disposition"]).toBe('attachment; filename="notepad.exe"');
  expect(response.headers()["content-length"]).toBe(String(body.length));
  expect(response.headers()["cache-control"]).toContain("immutable");
  expect(body.subarray(0, PE_MAGIC.length).toString("utf8")).toBe(PE_MAGIC);
});

test("the binaries table carries a per-row Download action", async ({ page }) => {
  await page.goto("/#/binaries");
  const panel = binariesPanel(page);
  const row = panel.locator("table.data-table tbody tr").filter({ hasText: "notepad.exe" }).first();
  await expect(row).toBeVisible();

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    row.getByRole("link", { name: "Download", exact: true }).click(),
  ]);

  expect(download.suggestedFilename()).toBe("notepad.exe");
  const path = await download.path();
  expect(path).not.toBeNull();
});
