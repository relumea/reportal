// The global search modal (`⌘K` / `Ctrl+K`): the shortcut, the query types,
// the keyboard path through the results, the focus trap and the focus return.

import type { Locator, Page } from "@playwright/test";

import { e2eState } from "./e2e-state";
import { expect, test } from "./fixtures";

const state = e2eState();

// The dialog is the scope for every result locator: selects on the page behind
// it also expose `<option>` nodes, so a bare `getByRole("option")` would match
// them too. The shell is inert while the modal is open; scoping still keeps
// the assertions honest if that guard regresses.
function dialog(page: Page): Locator {
  return page.getByRole("dialog", { name: "Global search" });
}

/** One hit row of a given kind inside the modal. */
function hit(page: Page, kind: string): Locator {
  return dialog(page).locator(`[data-hit-kind="${kind}"]`);
}

/** True when the modal's own query input holds the focus. */
const INPUT_FOCUSED = `document.activeElement !== null && document.activeElement.classList.contains("search-input")`;

async function openModal(page: Page): Promise<void> {
  await page.keyboard.press("Control+k");
  await expect(dialog(page)).toBeVisible();
  expect(await page.evaluate<boolean>(INPUT_FOCUSED)).toBe(true);
}

test("Ctrl+K opens the modal and Enter opens the highlighted hit", async ({ page }) => {
  await page.goto("/#/binaries");
  await openModal(page);

  await page.keyboard.type("Notepad");
  const row = hit(page, "binary").filter({ hasText: "notepad.exe" }).first();
  await expect(row).toBeVisible();
  await expect(row.locator(".mono").first()).toBeVisible();
  await expect(row.getByText(/T\d{2}:\d{2}/)).toBeVisible();
  await expect(row).toHaveAttribute("aria-selected", "true");

  await page.keyboard.press("Enter");
  await expect(dialog(page)).toHaveCount(0);
  await expect(page).toHaveURL(new RegExp(`#/binaries/${state.ids.binary_id}$`));
});

test("clicking a result navigates and closes the modal", async ({ page }) => {
  await page.goto("/#/binaries");
  await openModal(page);

  await page.keyboard.type("Notepad");
  const row = hit(page, "binary").filter({ hasText: "notepad.exe" }).first();
  await expect(row).toBeVisible();
  await row.getByRole("link").click();
  await expect(dialog(page)).toHaveCount(0);
  await expect(page).toHaveURL(new RegExp(`#/binaries/${state.ids.binary_id}$`));
});

test("Escape closes the modal and returns the focus it took", async ({ page }) => {
  await page.goto("/#/binaries");
  const navLink = page.locator('.nav-link[data-view="binaries"]');
  await navLink.focus();
  expect(await page.evaluate<string | null>("document.activeElement?.getAttribute('data-view')")).toBe(
    "binaries",
  );

  await page.keyboard.press("Control+k");
  await expect(dialog(page)).toBeVisible();
  expect(await page.evaluate<boolean>(INPUT_FOCUSED)).toBe(true);

  await page.keyboard.press("Escape");
  await expect(dialog(page)).toHaveCount(0);
  expect(await page.evaluate<string | null>("document.activeElement?.getAttribute('data-view')")).toBe(
    "binaries",
  );
});

test("the shortcut stays quiet while a text field owns the keyboard", async ({ page }) => {
  await page.goto("/#/analyses");
  await page.getByLabel("Search", { exact: true }).fill("notepad");
  await page.keyboard.press("Control+k");
  await expect(dialog(page)).toHaveCount(0);
});

test("Tab cycles the query type and keeps the focus trapped", async ({ page }) => {
  await page.goto("/#/binaries");
  await openModal(page);

  const all = page.getByRole("tab", { name: "All" });
  await expect(all).toHaveAttribute("aria-selected", "true");

  await page.keyboard.press("Tab");
  await expect(page.getByRole("tab", { name: "SHA-256 Hash" })).toHaveAttribute("aria-selected", "true");
  expect(await page.evaluate<boolean>(INPUT_FOCUSED)).toBe(true);

  await page.keyboard.press("Shift+Tab");
  await expect(all).toHaveAttribute("aria-selected", "true");
  expect(await page.evaluate<boolean>(INPUT_FOCUSED)).toBe(true);
});

test("a 64-character hex paste selects the SHA-256 Hash query type", async ({ page }) => {
  await page.goto("/#/binaries");
  await openModal(page);
  await page.keyboard.insertText("a".repeat(64));
  await expect(page.getByRole("tab", { name: "SHA-256 Hash" })).toHaveAttribute("aria-selected", "true");
});

test("the arrow keys move the highlight and the tag query narrows the results", async ({ page }) => {
  await page.goto("/#/binaries");
  await openModal(page);

  await page.getByRole("tab", { name: "Tag" }).click();
  await page.keyboard.type(state.tag_name);
  const binaryRow = hit(page, "binary").first();
  const tagRow = hit(page, "tag").first();
  await expect(binaryRow).toBeVisible();
  await expect(tagRow).toBeVisible();
  // The binary group comes first, so the highlight starts on the binary.
  await expect(binaryRow).toHaveAttribute("aria-selected", "true");
  await expect(tagRow).toHaveAttribute("aria-selected", "false");

  await page.keyboard.press("ArrowDown");
  await expect(tagRow).toHaveAttribute("aria-selected", "true");
  await expect(binaryRow).toHaveAttribute("aria-selected", "false");
  await page.keyboard.press("ArrowUp");
  await expect(binaryRow).toHaveAttribute("aria-selected", "true");
});

test("the collection and function query types narrow the results", async ({ page }) => {
  await page.goto("/#/binaries");
  await openModal(page);

  const collection = state.collections[0]?.name ?? "";
  await page.getByRole("tab", { name: "Collection" }).click();
  await page.keyboard.type(collection);
  await expect(hit(page, "collection").first()).toBeVisible();
  await expect(hit(page, "collection").first()).toHaveAttribute("aria-selected", "true");
  await expect(hit(page, "collection").first().getByText("public")).toBeVisible();

  await page.keyboard.press("Control+a");
  await page.keyboard.press("Backspace");
  await page.getByRole("tab", { name: "Binary" }).click();
  await page.keyboard.type(state.function_name);
  await expect(page.getByText(`No results for "${state.function_name}" as Binary.`)).toBeVisible();
});
