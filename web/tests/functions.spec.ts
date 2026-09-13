// The Functions view's server-side filter and sort controls: a filter narrows
// the row set and says how much of the binary it kept, the state lands in the
// URL hash so a reload keeps it, and a header sorts the listing.
//
// The seeded workspace stores one match for the first function and one analysis
// holding every function, so the counts below come from real rows.  A select's
// label text carries its options, so its accessible name is matched without
// `exact`.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

// The Size column of the functions table: checkbox, ID, VA, Name, Size.
const SIZE_COLUMN = "table.data-table tbody tr td:nth-of-type(5)";

function isSorted(values: number[], upwards: boolean): boolean {
  return values.every((value, index) => {
    if (index === 0) return true;
    return upwards ? values[index - 1] <= value : values[index - 1] >= value;
  });
}

test("a filter narrows the row set and states the counts", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}/functions`);
  const panel = panelByTitle(page, "Functions");
  await expect(panel.getByText("6 of 6 functions")).toBeVisible();

  await panel.getByLabel("Match").selectOption("unmatched");
  await expect(page).toHaveURL(/match=unmatched/);
  // One of the six seeded functions is the source of a stored match.
  await expect(panel.getByText("5 of 6 functions")).toBeVisible();

  await page.reload();
  await expect(panel.getByText("5 of 6 functions")).toBeVisible();
});

test("a filter that matches nothing explains itself", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}/functions?capability=console`);
  const panel = panelByTitle(page, "Functions");
  await expect(panel.getByText(/No functions match this filter/)).toBeVisible();
});

test("a header sorts the listing and keeps the order in the URL", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}/functions`);
  const panel = panelByTitle(page, "Functions");
  const sizes = async (): Promise<number[]> =>
    (await panel.locator(SIZE_COLUMN).allInnerTexts()).map(Number);

  await panel.getByRole("button", { name: /^Size/ }).click();
  await expect(page).toHaveURL(/sort=size/);
  await expect.poll(async () => isSorted(await sizes(), true)).toBe(true);

  await panel.getByRole("button", { name: /^Size/ }).click();
  await expect(page).toHaveURL(/order=desc/);
  await expect.poll(async () => isSorted(await sizes(), false)).toBe(true);
});
