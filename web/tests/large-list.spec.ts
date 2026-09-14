// The functions table on a long list: only the visible rows are in the DOM, and
// scrolling reaches the end of the list rather than the end of the window.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

/** The last seeded function's address, which the window has to reach. */
function lastFunctionName(): string {
  const va = 0x1000 + (state.large_function_count - 1) * 0x20;
  return `sub_${va.toString(16)}`;
}

test("a long function list renders a window and still reaches its last row", async ({ page }) => {
  await page.goto(`/#/binaries/${state.large_binary_id}/functions`);
  const panel = panelByTitle(page, "Functions");
  const table = panel.locator(".table-scroll").first();
  const rows = table.locator("tbody tr");

  // The count line proves the whole list is the source, and the DOM holds a
  // window of it rather than every row: 5,000 rows would be 5,000 nodes.
  await expect(panel.getByText(`${state.large_function_count} of`, { exact: false })).toBeVisible();
  await expect(rows.first()).toBeVisible();
  const rendered = await rows.count();
  expect(rendered).toBeGreaterThan(0);
  expect(rendered).toBeLessThan(300);

  // The window follows the scroll: the last row of the list is reachable and
  // rendered, and the DOM is still a window when it is.
  await table.evaluate((element) => {
    element.scrollTop = element.scrollHeight;
  });
  const last = table.locator("tbody tr", { hasText: lastFunctionName() });
  await expect(last).toBeVisible();
  expect(await rows.count()).toBeLessThan(300);
});
