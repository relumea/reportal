// The keyboard layer: the registry's own rules in the Node context, then the
// real shortcuts, the cheatsheet and the focus contract in the browser.
//
// The registry rules run against the module itself, in their own process-side
// instance; the browser tests drive the instance App installs.

import { NAV_LABELS } from "../src/router";
import type { NavView } from "../src/router";
import {
  displayCombo,
  isPrefix,
  normalizeCombo,
  registerShortcut,
  resolveShortcut,
} from "../src/keys";
import { e2eState } from "./e2e-state";
import { expect, test } from "./fixtures";

const CHEATSHEET = "Keyboard shortcuts";

function dialog(page: import("@playwright/test").Page) {
  return page.getByRole("dialog", { name: CHEATSHEET });
}

/** The bindings the shell registers outside the `g` prefix jumps. */
// Shell bindings outside the per-view `g` jumps: search, the cheatsheet, the
// two table row moves, the first/last row jumps, the focused-row rename, the
// filter focus, the filters row, the type save, the type discard, the two
// section steps, the seven analysis-section jumps, the memory go-to, the
// code-view switch, the sidebar collapse and the four history steps.
const SHELL_BINDINGS = 27;

// One `g` jump per sidebar view plus the shell bindings above.
const DECLARED_SHORTCUTS = 21 + SHELL_BINDINGS;

test("a conflicting binding is refused at registration", () => {
  const probe = (): void => {};
  const dispose = registerShortcut({
    combo: "zz1",
    scope: "global",
    description: "probe",
    handler: probe,
  });
  expect(() =>
    registerShortcut({ combo: "zz1", scope: "global", description: "dupe", handler: probe }),
  ).toThrow(/already registered/);

  // The same combo in the other scope is not a conflict, and the view's wins.
  const scoped = registerShortcut({
    combo: "zz1",
    scope: "view",
    description: "probe view",
    handler: probe,
  });
  expect(resolveShortcut("zz1")?.scope).toBe("view");

  scoped();
  dispose();
  expect(resolveShortcut("zz1")).toBeUndefined();
});

test("a combo has one canonical spelling", () => {
  expect(normalizeCombo("Mod+K")).toBe("mod+k");
  expect(normalizeCombo("Ctrl+K")).toBe("mod+k");
  expect(normalizeCombo("Cmd+K")).toBe("mod+k");
  expect(normalizeCombo("g  d")).toBe("g d");
  expect(normalizeCombo("Space")).toBe("space");
  expect(isPrefix("zz9")).toBe(false);
});

test("a combo renders for the platform it runs on", () => {
  expect(displayCombo("mod+k", false)).toBe("Ctrl+K");
  expect(displayCombo("mod+k", true)).toBe("⌘K");
  expect(displayCombo("g d", false)).toBe("G then D");
  expect(displayCombo("?", false)).toBe("?");
  expect(displayCombo("space", false)).toBe("Space");
});

test("? opens the cheatsheet, Escape closes it and returns the focus", async ({ page }) => {
  await page.goto("/#/binaries");
  const navLink = page.locator('.nav-link[data-view="binaries"]');
  await navLink.focus();

  await page.keyboard.press("?");
  await expect(dialog(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog(page)).toHaveCount(0);
  await expect
    .poll(
      () => page.evaluate<boolean>(`document.activeElement?.dataset.view === "binaries"`),
      { timeout: 5000 },
    )
    .toBe(true);
});

test("the cheatsheet lists the registered set", async ({ page }) => {
  await page.goto("/#/binaries");
  await page.keyboard.press("?");
  const sheet = dialog(page);
  await expect(sheet).toBeVisible();

  // Every sidebar view is registered as a `g` jump, so the sheet has one row
  // per nav link: the list is read out of the live registry, not written down.
  const views = await page
    .locator(".nav-link")
    .evaluateAll((links) => links.map((link) => (link as HTMLElement).dataset.view ?? ""));
  const descriptions = await sheet.locator(".cheatsheet-row dd").allTextContents();
  for (const view of views) {
    expect(descriptions).toContain(`Go to ${NAV_LABELS[view as NavView]}`);
  }
  expect(descriptions).toContain("Open the global search");
  expect(descriptions).toContain("Show this keyboard cheatsheet");

  const declared = Number(await sheet.getAttribute("data-shortcut-count"));
  expect(declared).toBe(descriptions.length);
  expect(views).toHaveLength(21);
  expect(declared).toBe(DECLARED_SHORTCUTS);

  // The visible keys are the combos, not the registry's spelling of them.
  const keys = await sheet.locator("kbd.key").allTextContents();
  expect(keys).toContain("?");
  expect(keys).toContain("G then D");
});

test("no binding fires while a text field owns the keyboard", async ({ page }) => {
  await page.goto("/#/analyses");
  const field = page.getByLabel("Search", { exact: true });
  await field.fill("notepad");

  await page.keyboard.press("?");
  await expect(dialog(page)).toHaveCount(0);
  await page.keyboard.press("j");
  await expect(field).toBeFocused();
  await page.keyboard.press("/");
  await expect(field).toBeFocused();
});

test("/ focuses the view's filter box", async ({ page }) => {
  await page.goto("/#/search");
  const field = page.locator('#content input[type="search"]').first();
  await expect(field).toBeVisible();
  await page.keyboard.press("/");
  await expect(field).toBeFocused();
});

test("p focuses the view's first filter control", async ({ page }) => {
  await page.goto("/#/functions");
  await expect(page.locator("table.data-table tbody tr").first()).toBeVisible();
  await page.keyboard.press("p");
  await expect(page.getByLabel("Name source")).toBeFocused();
});

test("j and k move through the rows of the view's table", async ({ page }) => {
  await page.goto("/#/functions");
  await expect(page.locator("table.data-table tbody tr").first()).toBeVisible();

  await page.keyboard.press("j");
  expect(await page.evaluate<boolean>(`document.activeElement === document.querySelector("table.data-table tbody tr[tabindex='0']")`)).toBe(
    true,
  );
  await expect(page.locator("table.data-table tbody tr[tabindex='0']").first()).toHaveCSS(
    "box-shadow",
    /inset/,
  );
  await page.keyboard.press("j");
  expect(await page.evaluate<boolean>(`document.activeElement === document.querySelectorAll("table.data-table tbody tr[tabindex='0']")[1]`)).toBe(
    true,
  );
  await page.keyboard.press("k");
  expect(await page.evaluate<boolean>(`document.activeElement === document.querySelector("table.data-table tbody tr[tabindex='0']")`)).toBe(
    true,
  );
});

test("Shift+J and Shift+K jump to the last and first rows", async ({ page }) => {
  await page.goto("/#/functions");
  await expect(page.locator("table.data-table tbody tr").first()).toBeVisible();
  await page.keyboard.press("Shift+J");
  expect(
    await page.evaluate<boolean>(
      `document.activeElement === Array.from(document.querySelectorAll("table.data-table tbody tr[tabindex='0']")).at(-1)`,
    ),
  ).toBe(true);
  await page.keyboard.press("Shift+K");
  expect(
    await page.evaluate<boolean>(
      `document.activeElement === document.querySelector("table.data-table tbody tr[tabindex='0']")`,
    ),
  ).toBe(true);
});

test("r clicks Rename on the focused function row", async ({ page }) => {
  await page.goto("/#/functions");
  await expect(page.locator("table.data-table tbody tr").first()).toBeVisible();
  await page.keyboard.press("j");
  await page.keyboard.press("r");
  const editor = page.getByRole("textbox", { name: /^New name for function #/ });
  await expect(editor).toBeFocused();
  await editor.press("Escape");
  await expect(editor).toHaveCount(0);
});

test("the g prefix jumps to a view", async ({ page }) => {
  await page.goto("/#/binaries");
  await page.keyboard.press("g");
  await page.keyboard.press("j");
  await expect(page).toHaveURL(/#\/journal$/);
});

test("{ and } step this tab's view history", async ({ page }) => {
  await page.goto("/#/binaries");
  await page.goto("/#/functions");
  await expect(page).toHaveURL(/#\/functions/);
  await page.keyboard.press("{");
  await expect(page).toHaveURL(/#\/binaries/);
  await page.keyboard.press("}");
  await expect(page).toHaveURL(/#\/functions/);
});

test("o and m jump to Binary details and Memory on a binary page", async ({ page }) => {
  const binaryId = e2eState().ids.binary_id;
  await page.goto(`/#/binaries/${binaryId}`);
  await expect(page.getByRole("heading", { name: "Binary Details", exact: true })).toBeVisible();
  await expect(page.locator(".detail-head .hash-identicon")).toHaveCount(1);
  await expect(page.locator(".detail-head .copy-row .mono")).toHaveText(/…$/);
  await page.keyboard.press("m");
  await expect(page.getByRole("heading", { name: "Memory", exact: true })).toBeInViewport();
  await page.keyboard.press("o");
  await expect(page.getByRole("heading", { name: "Binary Details", exact: true })).toBeInViewport();
});

test("Shift+G focuses the memory address box", async ({ page }) => {
  const binaryId = e2eState().ids.binary_id;
  await page.goto(`/#/binaries/${binaryId}`);
  await expect(page.getByRole("heading", { name: "Binary Details", exact: true })).toBeVisible();
  await page.keyboard.press("Shift+G");
  await expect(page.getByLabel("Address", { exact: true })).toBeFocused();
});

test("f jumps from a binary page to its functions", async ({ page }) => {
  const binaryId = e2eState().ids.binary_id;
  await page.goto(`/#/binaries/${binaryId}`);
  await expect(page.getByRole("heading", { name: "Binary Details", exact: true })).toBeVisible();
  await page.keyboard.press("f");
  await expect(page).toHaveURL(new RegExp(`#/binaries/${binaryId}/functions`));
});

test("Space on a diff toggles Disassembly and AI decompilation", async ({ page }) => {
  const { function_id, candidate_function_id } = e2eState().ids;
  await page.goto(`/#/diff/${function_id}/${candidate_function_id}`);
  await expect(page.getByRole("button", { name: "Transfer Symbol" })).toBeVisible();
  await expect(page.locator(".diff-table thead .copy-row").first()).toBeVisible();
  await expect(page.getByRole("link", { name: /binary #/ }).first()).toHaveAttribute(
    "href",
    /#\/binaries\/\d+/,
  );
  await expect(page.getByText(/Suggested names \(\d+\)/)).toBeVisible();
  const kind = page.getByLabel("Kind");
  await expect(kind).toHaveValue("disasm");
  await expect(kind.locator("option[value='decomp']")).toHaveText("Decompilation");
  await expect(kind.locator("option[value='disasm']")).toHaveText("Disassembly");
  await page.locator("#content").click();
  await page.keyboard.press("Space");
  await expect(kind).toHaveValue("decomp");
  await page.keyboard.press("Space");
  await expect(kind).toHaveValue("disasm");
});
