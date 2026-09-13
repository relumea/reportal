// The narrow shell: at 480px the two-column grid collapses, the sidebar turns
// into a horizontally scrollable strip that keeps every group label, and the
// document does not overflow horizontally.

import { NAV_GROUPS, NAV_VIEWS } from "../src/router";
import { expect, test } from "./fixtures";

const NARROW_VIEWPORT = { width: 480, height: 900 };
const OVERFLOW_TOLERANCE_PX = 1;

test.use({ viewport: NARROW_VIEWPORT });

test("at 480px the sidebar collapses, keeps the nav grouping, and does not overflow", async ({
  page,
}) => {
  await page.goto("/#/binaries");
  await expect(page.locator("#title")).toHaveText("Binaries");

  const layout = await page
    .locator(".layout")
    .evaluate((element) => getComputedStyle(element).gridTemplateColumns);
  expect(layout.trim().split(/\s+/)).toHaveLength(1);

  const sidebar = page.locator(".sidebar");
  expect(await sidebar.evaluate((element) => getComputedStyle(element).position)).toBe("sticky");
  expect(await sidebar.evaluate((element) => getComputedStyle(element).flexDirection)).toBe("row");

  const labels = page.locator(".nav-group-label");
  await expect(labels).toHaveCount(NAV_GROUPS.length);
  for (const label of await labels.all()) {
    await expect(label).toBeVisible();
    expect(((await label.textContent()) ?? "").trim()).not.toBe("");
  }
  await expect(page.locator(".nav-link")).toHaveCount(NAV_VIEWS.length);

  // The strip scrolls horizontally instead of widening the page.
  expect(await page.locator(".nav").evaluate((element) => getComputedStyle(element).overflowX)).toBe(
    "auto",
  );

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow).toBeLessThanOrEqual(OVERFLOW_TOLERANCE_PX);
});
