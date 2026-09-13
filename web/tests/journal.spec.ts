// The action journal: a change made through the UI records its inverse, the
// journal view lists it, and reverting it through the UI restores the state.

import { e2eState } from "./e2e-state";
import { panelByTitle, rowContaining, uniqueName } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("a UI write appears in the journal and its revert restores the state", async ({ page }) => {
  const name = uniqueName("e2e-journal");
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const tags = panelByTitle(page, "Tags");
  await tags.getByLabel("Tag", { exact: true }).fill(name);
  await tags.getByRole("button", { name: "Add tag" }).click();
  await expect(rowContaining(tags, name)).toBeVisible();

  const actionLink = tags.locator('a[href^="#/journal/"]');
  await expect(actionLink).toBeVisible();
  const action = ((await actionLink.textContent()) ?? "").trim();
  expect(action).not.toBe("");
  await actionLink.click();

  await expect(page.locator("#title")).toHaveText(`Journal · action ${action}`);
  const entry = page
    .locator("table.data-table tbody tr")
    .filter({ hasText: action })
    .first();
  await expect(entry).toBeVisible();
  await entry.getByRole("button", { name: "Revert action" }).click();
  await expect(page.getByText("Revert all?")).toBeVisible();
  await entry.getByRole("button", { name: "Revert action" }).click();
  await expect(page.getByText(/reverted \d+/)).toBeVisible();

  // Back to the binary through the SPA (a hash navigation, not a reload): the
  // tag panel must reflect the revert, not a cached list from before it.
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const tagsAfter = panelByTitle(page, "Tags");
  await expect(tagsAfter.getByRole("button", { name: "Add tag" })).toBeVisible();
  await expect(rowContaining(tagsAfter, name)).toHaveCount(0);
});
