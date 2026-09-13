// The Memory panel's full-file mode: load a page through the engine's own
// section map, page once, select a byte range and copy it as hex.  The copied
// text is rendered in the panel, so the assertion reads it without clipboard
// permissions; the actual clipboard write is best-effort.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("the full-file view pages and copies a selected range as hex", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const panel = panelByTitle(page, "Memory");

  await panel.getByLabel("Mode").selectOption("file");
  await panel.getByRole("button", { name: "Load page" }).click();
  await expect(panel.locator(".memory-row").first()).toBeVisible();

  const firstRow = async (): Promise<string> => panel.locator(".memory-row").first().innerText();
  const before = await firstRow();
  await panel.getByRole("button", { name: "Next page" }).click();
  await expect.poll(firstRow).not.toBe(before);

  const bytes = panel.locator("button.byte");
  await bytes.nth(0).click();
  await bytes.nth(3).click({ modifiers: ["Shift"] });
  await expect(panel.getByText(/Selected /)).toBeVisible();

  await panel.getByRole("button", { name: "Copy hex" }).click();
  const copied = panel.getByText(/Copied: /);
  await expect(copied).toBeVisible();
  // Four bytes selected, so the hex readout is four space-separated pairs.
  await expect(copied).toHaveText(/Copied: [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2}/);
});
