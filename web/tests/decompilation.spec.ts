// The function detail's Decompilation panel colours the C through highlight.js:
// each token class lands on its own span, and the code stays text (markup in
// the source never becomes an element).

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

// Covers the scopes listing.css colours, a decompiler typedef the stock C
// grammar does not know, and markup inside a string that must stay text.
const HIGHLIGHT_SOURCE = [
  "#include <stdio.h>",
  "/* entry point */",
  "undefined4 FUN_00401000(DWORD count)",
  "{",
  '  printf("<b>%d</b>", 0x2a); // trailing note',
  "  return NULL;",
  "}",
  "",
].join("\n");

test("the stored decompilation renders keyword, type and function title spans", async ({
  page,
}) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const source = panelByTitle(page, "Decompilation").locator("pre.c-source");

  await expect(source).toContainText("return");
  await expect(source.locator(".hljs-keyword", { hasText: "return" })).toHaveCount(1);
  await expect(source.locator(".hljs-type", { hasText: "void" }).first()).toBeVisible();
  await expect(source.locator(".hljs-title.function_")).toHaveCount(1);
});

test("each C token class gets its highlight.js span and markup stays text", async ({ page }) => {
  await page.route(`**/api/functions/${state.ids.function_id}/decompilation?*`, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ va: 0x401000, backend: "kuna", named: false, code: HIGHLIGHT_SOURCE }),
    });
  });
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const source = panelByTitle(page, "Decompilation").locator("pre.c-source");

  await expect(source).toHaveText(HIGHLIGHT_SOURCE);
  const include = source.locator(".hljs-meta");
  await expect(include).toContainText("#include");
  await expect(include.locator(".hljs-string")).toHaveText("<stdio.h>");
  await expect(source.locator(".hljs-comment").first()).toHaveText("/* entry point */");
  await expect(source.locator(".hljs-comment").nth(1)).toHaveText("// trailing note");
  await expect(source.locator(".hljs-type", { hasText: "undefined4" })).toHaveCount(1);
  await expect(source.locator(".hljs-type", { hasText: "DWORD" })).toHaveCount(1);
  await expect(source.locator(".hljs-title.function_")).toHaveText("FUN_00401000");
  await expect(source.locator(".hljs-built_in")).toHaveText("printf");
  await expect(source.locator(".hljs-string", { hasText: "%d" })).toHaveText('"<b>%d</b>"');
  await expect(source.locator(".hljs-number")).toHaveText("0x2a");
  await expect(source.locator(".hljs-keyword", { hasText: "return" })).toHaveCount(1);
  await expect(source.locator(".hljs-literal")).toHaveText("NULL");
  await expect(source.locator("b")).toHaveCount(0);

  // The token spans take the listing's hues, not the inherited text colour.
  const keywordColour = await source
    .locator(".hljs-keyword", { hasText: "return" })
    .evaluate((node) => getComputedStyle(node).color);
  const plainColour = await source.evaluate((node) => getComputedStyle(node).color);
  expect(keywordColour).not.toBe(plainColour);
});

test("a called function the server links opens from the decompiled code", async ({ page }) => {
  const code = "int sub_401000(void)\n{\n  parse_header(1);\n  helper();\n  return 0;\n}\n";
  await page.route(`**/api/functions/${state.ids.function_id}/decompilation?*`, async (route) => {
    if (route.request().method() !== "GET") return route.continue();
    await route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({
        va: 0x401000,
        backend: "kuna",
        named: false,
        code,
        links: { parse_header: state.ids.candidate_function_id },
      }),
    });
  });
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const source = panelByTitle(page, "Decompilation").locator("pre.c-source");

  // The listing text is unchanged; only the linked name became an anchor.
  await expect(source).toHaveText(code);
  await expect(source.getByRole("link")).toHaveCount(1);
  await source.getByRole("link", { name: "parse_header" }).click();
  await expect(page).toHaveURL(new RegExp(`#/functions/${state.ids.candidate_function_id}$`, "u"));
});

test("a laptop-wide window shows the listing and the decompilation side by side", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const listing = panelByTitle(page, "Disassembly");
  const decompiled = panelByTitle(page, "Decompilation");
  await expect(listing).toBeVisible();
  await expect(decompiled).toBeVisible();
  const [left, right] = await Promise.all([listing.boundingBox(), decompiled.boundingBox()]);
  expect(left).not.toBeNull();
  expect(right).not.toBeNull();
  if (left === null || right === null) return;
  expect(Math.abs(left.y - right.y)).toBeLessThanOrEqual(1);
  expect(right.x).toBeGreaterThan(left.x + left.width);
});
