// A page loaded before the SPA was rebuilt asks for view chunks the server no
// longer has.  The view boundary reloads once and the view renders, instead of
// leaving an error note in the pane.
//
// Playwright's own `test`, not the guarded fixture: the missing chunk is the
// point here, and its 404 and console error are exactly what that guard fails on.

import { expect, test } from "@playwright/test";

import { e2eState } from "./e2e-state";

const state = e2eState();

test("a view chunk missing after a rebuild reloads the page once", async ({ page }) => {
  let refused = 0;
  await page.route(/\/static\/assets\/FunctionDetail-[^/]+\.js$/u, async (route) => {
    if (refused === 0) {
      refused += 1;

      await route.fulfill({ status: 404, body: "gone" });

      return;
    }

    await route.continue();
  });
  let loads = 0;
  page.on("load", () => {
    loads += 1;
  });
  await page.goto(`/#/functions/${state.ids.function_id}`);
  await expect(page.locator(".detail-head")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText(/Could not load this view/)).toHaveCount(0);
  expect(refused).toBe(1);
  expect(loads).toBe(2);
});
