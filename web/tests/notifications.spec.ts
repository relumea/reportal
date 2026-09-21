// The notifications bell and dialog: opening the feed, Escape closing it
// and returning the focus to the bell that opened it.

import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";

function dialog(page: Page) {
  return page.getByRole("dialog", { name: "Notifications" });
}

test("Escape closes the dialog and returns the focus to the bell", async ({ page }) => {
  await page.goto("/#/binaries");
  const bell = page.getByRole("button", { name: /^Notifications/ });
  await bell.focus();
  await expect(bell).toBeFocused();

  await bell.click();
  await expect(dialog(page)).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(dialog(page)).toHaveCount(0);
  await expect.poll(() => bell.evaluate((node) => node === document.activeElement), {
    timeout: 5000,
  }).toBe(true);
});
