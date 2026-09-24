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

test("an unknown route says so instead of showing the dashboard", async ({ page }) => {
  await page.goto("/#/collections/404");
  await expect(page.locator("#title")).toHaveText("Page not found");
  await expect(page.getByText("Nothing lives at #/collections/404.")).toBeVisible();
  await expect(page.locator(".nav-link.active")).toHaveCount(0);
  await page.getByRole("link", { name: "open the dashboard" }).click();
  await expect(page).toHaveURL(/#\/$/);
});

test("the collapsed sidebar shows one icon per view and keeps each link's name", async ({
  page,
}) => {
  await page.goto("/#/");
  await page.getByRole("button", { name: "Collapse the sidebar" }).click();
  for (const view of NAV_VIEWS) {
    const link = page.locator(`.nav-link[data-view="${view}"]`);
    await expect(link.locator("svg.icon")).toBeVisible();
    // The label is clipped, not removed: the link is still announced by name.
    await expect(link).toHaveAccessibleName(NAV_LABELS[view]);
  }
  // The mark and the toggle stack on the icon column instead of crowding one row.
  const centre = async (selector: string): Promise<number> => {
    const box = await page.locator(selector).first().boundingBox();
    expect(box).not.toBeNull();
    return box === null ? 0 : box.x + box.width / 2;
  };
  const iconCentre = await centre('.nav-link[data-view="dashboard"] svg.icon');
  expect(Math.abs((await centre(".brand-mark")) - iconCentre)).toBeLessThanOrEqual(1);
  expect(Math.abs((await centre(".sidebar-toggle")) - iconCentre)).toBeLessThanOrEqual(1);
  await page.getByRole("button", { name: "Expand the sidebar" }).click();
});

test("a stored collapse does not fold the narrow top bar", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 700 });
  await page.addInitScript(() => localStorage.setItem("reportal.sidebar.collapsed", "1"));
  await page.goto("/#/");
  await expect(page.locator(".brand-name")).toBeVisible();
  await expect(page.locator('.nav-link[data-view="dashboard"] .nav-link-text')).toBeVisible();
  await expect(page.locator(".sidebar-toggle")).toBeHidden();
});
