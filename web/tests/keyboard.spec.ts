// Keyboard access: Tab reaches the primary nav and the row actions of the
// first data table, and Enter on a focused row opens its detail route.

import { escapeRegExp, tabUntil } from "./helpers";
import { expect, test } from "./fixtures";

// Enough steps to cross the sidebar, the panel toolbar and one table row.
const MAX_TAB_STEPS = 150;

const ROW_ACTION_FOCUSED = `document.activeElement instanceof HTMLButtonElement && document.activeElement.closest("table.data-table tbody tr") !== null`;
const ROW_FOCUSED = `document.activeElement === document.querySelector("table.data-table tbody tr[role='link']")`;

test("tab reaches the primary nav and the first table's row actions", async ({ page }) => {
  await page.goto("/#/functions");
  await expect(page.locator("table.data-table tbody tr").first()).toBeVisible();

  // The sidebar's collapse control is the first stop, then the nav links.
  await page.keyboard.press("Tab");
  await expect(page.locator(".sidebar-toggle:focus")).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.locator(".nav-link:focus")).toHaveAttribute("data-view", "dashboard");

  expect(await tabUntil(page, ROW_ACTION_FOCUSED, MAX_TAB_STEPS)).toBe(true);
});

test("Enter on a focused table row opens its detail route", async ({ page }) => {
  await page.goto("/#/functions");
  const firstRow = page.locator("table.data-table tbody tr").first();
  await expect(firstRow).toBeVisible();
  const href = await firstRow.locator("a").first().getAttribute("href");
  expect(href).not.toBeNull();

  expect(await tabUntil(page, ROW_FOCUSED, MAX_TAB_STEPS)).toBe(true);
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`${escapeRegExp(href ?? "")}$`));
});
