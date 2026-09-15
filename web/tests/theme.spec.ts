// The theme layer: the picker writes `<html data-theme>` and localStorage, the
// choice survives a reload, and `?theme=` outranks the stored one (which is how
// `tools/audit_ui.py` renders a palette).

import { THEMES, THEME_LABELS, THEME_STORAGE_KEY } from "../src/theme";
import { expect, test } from "./fixtures";

const PICKER = "Theme";

test("the picker offers every theme and applies the one chosen", async ({ page }) => {
  await page.goto("/#/jobs");
  const picker = page.getByLabel(PICKER);
  await expect(picker).toHaveValue("system");
  await expect(picker.locator("option")).toHaveCount(THEMES.length);
  for (const name of THEMES) {
    await expect(picker.locator(`option[value="${name}"]`)).toHaveText(THEME_LABELS[name]);
  }

  await picker.selectOption("zine");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "zine");
  await expect(page.locator(".topbar h1")).toHaveCSS("color", "rgb(255, 255, 255)");
});

test("the chosen theme survives a reload", async ({ page }) => {
  await page.goto("/#/jobs");
  await page.getByLabel(PICKER).selectOption("light");
  expect(
    await page.evaluate((key) => window.localStorage.getItem(key), THEME_STORAGE_KEY),
  ).toBe("light");

  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await expect(page.getByLabel(PICKER)).toHaveValue("light");
});

test("the theme query parameter outranks the stored choice", async ({ page }) => {
  await page.goto("/#/jobs");
  await page.getByLabel(PICKER).selectOption("light");

  await page.goto("/?theme=zine#/jobs");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "zine");
});

test("system resolves to a real palette rather than staying unset", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/?theme=system#/jobs");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");

  await page.emulateMedia({ colorScheme: "light" });
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
});
