// The function page's Similar functions panel: Find similar ranks the seeded
// function's lineage copy (the same cached listing) first, links it and its
// binary, and records nothing.  The copy's own page is not opened: its binary
// has no rebrew context, so its code panels would answer no-engine-context.

import { e2eState } from "./e2e-state";
import { expect, test } from "./fixtures";

const state = e2eState();

test("find similar ranks the seeded counterpart first and links it", async ({ page }) => {
  await page.goto(`/#/functions/${state.similar.function_id}?tab=matches`);

  const panel = page
    .locator(".panel")
    .filter({ has: page.getByRole("heading", { name: /^Similar functions/ }) });

  await expect(panel.getByText("Not searched.", { exact: false })).toBeVisible();

  const response = page.waitForResponse(
    (candidate) =>
      candidate.url().endsWith(`/functions/${state.similar.function_id}/similar`) &&
      candidate.request().method() === "POST",
  );

  await panel.getByRole("button", { name: "Find similar", exact: true }).click();

  const answered = await response;

  expect(answered.status()).toBe(200);

  const first = panel.locator("table.data-table tbody tr").first();
  const link = first.getByRole("link", { name: state.similar.counterpart_name, exact: true });

  await expect(link).toHaveAttribute("href", `#/functions/${state.similar.counterpart_id}`);
  await expect(first.getByRole("link", { name: "notepad-copy.exe", exact: true })).toBeVisible();
  await expect(first).toContainText("100.0%");
  await expect(panel.getByText("(index)", { exact: false })).toBeVisible();
  await expect(panel.getByRole("button", { name: "Search again", exact: true })).toBeVisible();
});
