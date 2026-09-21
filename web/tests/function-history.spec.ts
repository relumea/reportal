// The function History panel: a rename records a row that names its actor
// with a relative age, and renaming back restores the seeded name.

import { e2eState } from "./e2e-state";
import { expect, test } from "./fixtures";

const state = e2eState();

test("a rename records history naming its actor with a relative age", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const title = page.locator(".detail-title-name");
  await expect(title).toBeVisible();
  const seeded = (await title.innerText()).trim();

  await title.click();
  const editor = page.locator(".detail-title input");
  await editor.fill(`${seeded}_e2e`);
  await editor.press("Enter");
  await expect(title).toHaveText(`${seeded}_e2e`);

  // The rename refreshes the history panel itself; no reload needed.
  const panel = page.locator(".panel").filter({
    has: page.getByRole("heading", { name: "History", exact: true }),
  });
  const newest = panel.locator("table.data-table tbody tr").first();
  await expect(newest).toContainText(`${seeded}_e2e`);
  // Each row names its actor with a relative age, like the type histories.
  await expect(newest).toContainText("spa, just now");

  // Restore the seeded name so the shared workspace keeps its shape.
  await title.click();
  await editor.fill(seeded);
  await editor.press("Enter");
  await expect(title).toHaveText(seeded);
});
