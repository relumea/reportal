// The grouped sidebar: every group is labelled, every link in it navigates to
// its view, and the landed link is the marked-active one.

import { NAV_GROUPS, NAV_LABELS, NAV_VIEWS, navPath } from "../src/router";
import { escapeRegExp } from "./helpers";
import { expect, test } from "./fixtures";

test("the sidebar renders every group and view from the nav table", async ({ page }) => {
  await page.goto("/#/");
  await expect(page.locator(".nav-group")).toHaveCount(NAV_GROUPS.length);
  await expect(page.locator(".nav-link")).toHaveCount(NAV_VIEWS.length);
  for (const group of NAV_GROUPS) {
    await expect(page.locator(".nav-group-label", { hasText: group.label })).toBeVisible();
  }
});

for (const group of NAV_GROUPS) {
  test(`group ${group.label} links land on their views and mark the active link`, async ({
    page,
  }) => {
    await page.goto("/#/");
    for (const view of group.views) {
      const link = page.locator(`.nav-link[data-view="${view}"]`);
      await link.click();
      await expect(link).toHaveAttribute("aria-current", "page");
      await expect(link).toHaveClass(/\bactive\b/);
      await expect(page.locator("#title")).toHaveText(NAV_LABELS[view]);
      await expect(page).toHaveURL(new RegExp(`${escapeRegExp(navPath(view))}$`));
    }
  });
}
