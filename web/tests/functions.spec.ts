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

test("the name and address filters narrow the list through the API", async ({ page }) => {
  // The wide binary carries 5,000 functions, so a filter narrowing to one row
  // is a real filter rather than a coincidence of a small list.  "Name" alone
  // would match the "Name source" select too, so each control is addressed by
  // its role.
  await page.goto(`/#/binaries/${state.large_binary_id}/functions`);
  const panel = panelByTitle(page, "Functions");
  const rows = panel.locator("table.data-table tbody tr");
  await expect(rows.first()).toBeVisible();
  const name = "sub_1000";

  const nameField = panel.getByRole("searchbox", { name: "Name" });
  await nameField.fill(name);
  await nameField.press("Enter");

  await expect(page).toHaveURL(new RegExp(`name=${name}`));
  // The needle is a substring, so it can match more than one name; what the
  // table draws is the count the route answered with.
  const filtered = (await (
    await page.request.get(`/api/binaries/${state.large_binary_id}/functions?name=${name}`)
  ).json()) as { count: number };
  expect(filtered.count).toBeGreaterThan(0);
  expect(filtered.count).toBeLessThan(state.large_function_count);
  await expect(
    panel.getByText(`${filtered.count} of ${state.large_function_count} functions`),
  ).toBeVisible();
  await expect(rows).toHaveCount(filtered.count);
  await expect(rows.first()).toContainText(name);

  // The address reads as the hex an analyst pastes, and one address is one
  // function.
  await page.goto(`/#/binaries/${state.large_binary_id}/functions?va=0x1000`);
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText(name);
  await expect(panel.getByRole("textbox", { name: "Address" })).toHaveValue("0x1000");

  // A malformed address is refused by the route (400 `invalid va`) and the view
  // draws that note in place; the suite's page guard treats any error response
  // as a defect, so the refusal is covered where it is answered, in
  // tests/test_strings_sort.py, tests/test_cli.py and tests/test_mcp.py.
});
