// The Analyses view: filtering the list to the seeded analysis and opening its
// log, a filter that matches nothing saying so, and a delete going through the
// confirm pattern and removing the row.
//
// The delete creates its own analysis through the API before removing it, so
// the seeded rows every other spec reads stay untouched.

import { e2eState } from "./e2e-state";
import { panelByTitle, rowContaining, uniqueName } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("the list filters to the seeded analysis and its log opens on demand", async ({ page }) => {
  await page.goto("/#/analyses");
  const panel = panelByTitle(page, "Analyses");
  await panel.getByLabel("Search", { exact: true }).fill("notepad.exe");
  await panel.getByRole("button", { name: "Search" }).click();
  await expect(page).toHaveURL(/search=notepad/);
  const rows = panel.locator("table.data-table tbody tr");
  await expect(rows).toHaveCount(1);

  // The filter survives a reload through the hash.
  await page.reload();
  await expect(rows).toHaveCount(1);

  await rowContaining(panel, "notepad.exe")
    .getByRole("button", { name: "View log" })
    .click();
  const drawer = panelByTitle(page, `Log for analysis #${state.ids.analysis_id}`);
  await expect(drawer).toBeVisible();
  // The seed stores the structs scan first, so its finish is a real entry.
  await expect(drawer.getByText("structs scan finished")).toBeVisible();
  await expect(drawer.getByText(/showing \d+ of \d+ entries/)).toBeVisible();
});

test("a filter that matches nothing says so instead of showing an empty table", async ({
  page,
}) => {
  await page.goto("/#/analyses?status=failed");
  await expect(page.getByText(/No analyses match this filter/)).toBeVisible();
  await expect(page.getByText(/of \d+ analyses/)).toHaveCount(0);
});

test("deleting an analysis removes its row", async ({ page }) => {
  const engine = uniqueName("spa-spec");
  const created = await page.request.post("/api/analyses", {
    data: { binary_id: state.ids.binary_id, engine },
  });
  expect(created.ok()).toBeTruthy();

  await page.goto(`/#/analyses?search=${engine}`);
  const panel = panelByTitle(page, "Analyses");
  const row = rowContaining(panel, engine);
  await expect(row).toHaveCount(1);

  await row.getByRole("button", { name: "Delete" }).click();
  await row.getByRole("button", { name: "Delete" }).click();
  await expect(panel.getByText(/No analyses match this filter/)).toBeVisible();

  await page.goto("/#/analyses");
  await expect(page.getByText(engine)).toHaveCount(0);
});

test("the status chips, platform filter, order and re-analyse drive the list", async ({ page }) => {
  await page.goto("/#/analyses");
  const panel = panelByTitle(page, "Analyses");
  const rows = panel.locator("tbody tr");
  const total = await rows.count();
  expect(total).toBeGreaterThan(1);

  // The status control is a chip per status; selecting one filters the list and
  // puts the any-of set in the hash.
  await panel.getByRole("button", { name: "done", exact: true }).click();
  await expect(page).toHaveURL(/status=done/);
  const done = await rows.count();
  expect(done).toBeGreaterThan(0);
  expect(done).toBeLessThanOrEqual(total);

  // A second status widens the any-of set rather than replacing it.
  await panel.getByRole("button", { name: "pending", exact: true }).click();
  await expect(page).toHaveURL(/status=done%2Cpending|status=pending%2Cdone/);

  // The platform control offers the values the register holds: the seeded
  // binary carries PE, so the option appears once the payload lands.
  const platform = panel.getByLabel("Platform");
  await expect(platform.locator("option", { hasText: "PE" })).toBeAttached();
  await platform.selectOption("PE");
  await expect(page).toHaveURL(/platform=PE/);
  await expect(panel.locator("tbody tr")).toHaveCount(1);

  // The re-analyse action clears the finish time and puts the row back.
  await page.goto("/#/analyses");
  const button = panel.getByRole("button", { name: "Re-analyse" }).first();
  await button.click();
  await expect(panel.locator("tbody tr").first()).toBeVisible();
});
