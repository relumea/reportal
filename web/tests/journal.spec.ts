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
  await expect(page.getByText("Revert every entry this action made?")).toBeVisible();
  await entry.getByRole("button", { name: "Revert action" }).click();
  await expect(page.getByText(/reverted \d+/)).toBeVisible();

  // Back to the binary through the SPA (a hash navigation, not a reload): the
  // tag panel must reflect the revert, not a cached list from before it.
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const tagsAfter = panelByTitle(page, "Tags");
  await expect(tagsAfter.getByRole("button", { name: "Add tag" })).toBeVisible();
  await expect(rowContaining(tagsAfter, name)).toHaveCount(0);
});

test("the journal filters by actor and by page size", async ({ page }) => {
  // A write through the UI records the local operator as the entry's actor.
  const name = uniqueName("e2e-journal-actor");
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const tags = panelByTitle(page, "Tags");
  await tags.getByLabel("Tag", { exact: true }).fill(name);
  await tags.getByRole("button", { name: "Add tag" }).click();
  await expect(rowContaining(tags, name)).toBeVisible();

  await page.goto("/#/journal");
  const panel = panelByTitle(page, "Journal");
  const rows = panel.locator("table.data-table tbody tr");
  await expect(rows.first()).toBeVisible();
  await expect(panel.getByRole("columnheader", { name: "Actor" })).toBeVisible();

  // The actor is read from the API rather than assumed, and every row the
  // filter keeps carries it (the column is the fifth: Entry, Action, Kind,
  // Status, Actor).
  const listed = (await (await page.request.get("/api/journal?limit=100")).json()) as {
    actors: string[];
  };
  expect(listed.actors.length).toBeGreaterThan(0);
  const actor = listed.actors[0];
  await panel.getByRole("combobox", { name: /^Actor/ }).selectOption(actor);
  await expect(page).toHaveURL(new RegExp(`actor=${actor}`));
  await expect(rows.first()).toBeVisible();
  const shown = await rows.locator("td:nth-child(5)").allTextContents();
  expect([...new Set(shown.map((text) => text.trim()))]).toEqual([actor]);

  // The page size is a filter too, and Clear resets both.
  await panel.getByRole("spinbutton", { name: /^Show/ }).fill("1");
  await expect(page).toHaveURL(/limit=1/);
  await expect(rows).toHaveCount(1);
  await panel.getByRole("button", { name: "Clear" }).click();
  await expect(page).toHaveURL(/#\/journal$/);
});
