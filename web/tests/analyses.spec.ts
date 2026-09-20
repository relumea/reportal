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
  await expect(panel.getByRole("button", { name: "Upload binary" })).toBeVisible();
  await expect(panel.getByLabel("Search", { exact: true })).toHaveAttribute("type", "search");
  await panel.getByLabel("Search", { exact: true }).fill("notepad.exe");
  await panel.getByRole("button", { name: "Search" }).click();
  await expect(page).toHaveURL(/search=notepad/);
  await expect(panel.locator(".chip").filter({ hasText: /Search notepad/ })).toBeVisible();
  const rows = panel.locator("table.data-table tbody tr");
  await expect(rows).toHaveCount(1);
  await expect(rows.first().locator(".hash-identicon")).toHaveCount(1);
  await expect(rows.first().locator(".copy-row .mono")).toHaveText(/…$/);
  await expect(rows.first().getByTitle("team-scoped")).toHaveCount(0);
  await expect(
    rows.first().getByRole("link", { name: "Download" }),
  ).toHaveAttribute("href", `/api/binaries/${state.ids.binary_id}/download`);
  await rows.first().locator("td").nth(1).click();
  await expect(page).toHaveURL(new RegExp(`#/binaries/${state.ids.binary_id}`));
  await page.goBack();
  await expect(page).toHaveURL(/search=notepad/);
  const [popup] = await Promise.all([
    page.context().waitForEvent("page"),
    rows.first().locator("td").nth(1).click({ modifiers: ["ControlOrMeta"] }),
  ]);
  await expect(popup).toHaveURL(new RegExp(`#/binaries/${state.ids.binary_id}`));
  await popup.close();
  await expect(page).toHaveURL(/search=notepad/);

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

  // The drawer lists the analysis's own stored scans with the inputs they ran
  // with, which is the read the binary detail's panel cannot make for an older
  // analysis.
  await expect(drawer.getByText("Scans", { exact: true })).toBeVisible();
  await expect(drawer.getByText("structs", { exact: true })).toBeVisible();
  await expect(drawer.getByText("min_severity=low")).toBeVisible();
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

test("a row's tags are added and removed inline", async ({ page }) => {
  const name = uniqueName("e2e-rowtag");
  await page.goto("/#/analyses");
  const panel = panelByTitle(page, "Analyses");
  const row = rowContaining(panel, "notepad.exe");
  await expect(row).toBeVisible();

  // The add field is per row, and Enter posts the whole set through the
  // analysis's own tags route (the scope reportal tags at).
  await row.getByLabel(/^Add tag to analysis/).fill(name);
  await row.getByLabel(/^Add tag to analysis/).press("Enter");
  await expect(row.getByText(name, { exact: true })).toBeVisible();

  // Removing it takes the chip away again, and the binary's own Tags panel
  // agrees, which is what makes the two surfaces one store.
  await row.getByLabel(`Remove tag ${name}`).click();
  await expect(row.getByText(name, { exact: true })).toHaveCount(0);
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  await expect(panelByTitle(page, "Tags").getByText(name, { exact: true })).toHaveCount(0);
});

test("the status chips, platform filter, order and re-analyse drive the list", async ({ page }) => {
  await page.goto("/#/analyses");
  const panel = panelByTitle(page, "Analyses");
  const rows = panel.locator("tbody tr");
  // A filter change re-keys the query, so the table empties for as long as the
  // fetch runs; every count below is read from a settled table rather than
  // sampled while the rows are still out.
  await expect(rows.first()).toBeVisible();
  await expect.poll(async () => rows.count()).toBeGreaterThan(1);
  const total = await rows.count();

  // The status control is a chip per status; selecting one filters the list and
  // puts the any-of set in the hash.
  await panel.getByRole("button", { name: "done", exact: true }).click();
  await expect(page).toHaveURL(/status=done/);
  await expect.poll(async () => rows.count()).toBeGreaterThan(0);
  const done = await rows.count();
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

test("the page size bounds the list and says what it is hiding", async ({ page }) => {
  await page.goto("/#/analyses");
  const panel = panelByTitle(page, "Analyses");
  const rows = panel.locator("tbody tr");
  await expect(rows.first()).toBeVisible();
  const counted = await panel.getByText(/^\d+ of \d+ analyses/).innerText();
  const total = Number(/of (\d+)/.exec(counted)?.[1] ?? 0);
  expect(total).toBeGreaterThan(1);

  // The control asks the route for that many rows, and the URL carries it.
  const asked = page.waitForRequest(
    (request) => request.url().includes("/api/analyses?") && request.url().includes("limit=2"),
  );
  await panel.getByRole("spinbutton", { name: /^Show/ }).fill("2");
  await asked;
  await expect(page).toHaveURL(/limit=2/);
  await expect(rows).toHaveCount(2);
  // With rows left over, the line says so rather than reading as the whole set.
  await expect(panel.getByText(/raise Show \(up to 1000\) to list the rest/)).toBeVisible();

  // The default bound is the one the hash leaves out, so the URL stays clean.
  await panel.getByRole("spinbutton", { name: /^Show/ }).fill("100");
  await expect(page).toHaveURL(/#\/analyses$/);
  await expect(rows).toHaveCount(total);
  await expect(panel.getByText(/raise Show/)).toHaveCount(0);
});
