// Real write paths through the UI: create a collection, add and remove a tag,
// and ingest a note.  Each asserts the list the write belongs to re-rendered
// with the new state.

import { e2eState } from "./e2e-state";
import { panelByTitle, rowContaining, uniqueName } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("creating a collection adds a row to the collection table", async ({ page }) => {
  const name = uniqueName("e2e-collection");
  await page.goto("/#/collections");
  await page.getByLabel("Name", { exact: true }).fill(name);
  await page.getByLabel("Description", { exact: true }).fill("created by the playwright suite");
  await page.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("cell", { name, exact: true })).toBeVisible();
});

test("adding and removing a tag updates the tag list", async ({ page }) => {
  const name = uniqueName("e2e-tag");
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const tags = panelByTitle(page, "Tags");
  await tags.getByLabel("Tag", { exact: true }).fill(name);
  await tags.getByRole("button", { name: "Add tag" }).click();
  await expect(rowContaining(tags, name)).toBeVisible();

  const row = rowContaining(tags, name);
  await row.getByRole("button", { name: "Remove" }).click();
  await row.getByRole("button", { name: "Remove" }).click();
  await expect(rowContaining(tags, name)).toHaveCount(0);
});

test("ingesting a note adds a row to the document list", async ({ page }) => {
  const title = uniqueName("e2e-note");
  await page.goto("/#/knowledge");
  await page.getByLabel("Title", { exact: true }).fill(title);
  await page.getByLabel("Note text", { exact: true }).fill(`Note body for ${title}: the dialog procedure owns the table.`);
  await page.getByRole("button", { name: "Save note" }).click();
  await expect(page.getByText(`Ingested ${title} as document #`)).toBeVisible();
  await expect(page.getByRole("cell", { name: title, exact: true })).toBeVisible();
});
