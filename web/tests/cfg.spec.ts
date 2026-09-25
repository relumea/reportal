// The function detail page's control-flow view: the Disassembly / Control flow
// toggle, the address-ordered block list with each block's address, size,
// instruction count and first/last instruction text, and the per-block edge
// list whose jump controls move focus to the target block.  The graph comes
// from GET /api/functions/<id>/cfg, so a real engine call is behind it.

import type { Locator, Page } from "@playwright/test";

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

/** Open the seeded function's control-flow view and return its panel. */
async function openControlFlow(page: Page): Promise<Locator> {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const disassembly = panelByTitle(page, "Disassembly");
  await expect(disassembly.locator(".listing-row").first()).toBeVisible();
  await disassembly.getByRole("button", { name: "Control flow", exact: true }).click();
  const cfg = panelByTitle(page, "Control flow");
  await expect(cfg.locator(".cfg-block").first()).toBeVisible();
  return cfg;
}

test("the toggle swaps the code panel between the listing and the graph", async ({ page }) => {
  await page.goto(`/#/functions/${state.ids.function_id}`);
  const disassembly = panelByTitle(page, "Disassembly");
  await expect(disassembly.locator(".listing-row").first()).toBeVisible();

  const toggle = disassembly.getByRole("button", { name: "Control flow", exact: true });
  await expect(toggle).toHaveAttribute("aria-pressed", "false");
  await toggle.click();

  // The graph replaces the listing rather than stacking below it.
  const cfg = panelByTitle(page, "Control flow");
  await expect(cfg.getByText(/\d+ basic blocks, \d+ edges?/)).toBeVisible();
  await expect(panelByTitle(page, "Disassembly")).toHaveCount(0);

  await cfg.getByRole("button", { name: "Disassembly", exact: true }).click();
  await expect(panelByTitle(page, "Disassembly").locator(".listing-row").first()).toBeVisible();
});

test("a block carries its address, byte size, instruction count and instruction text", async ({
  page,
}) => {
  const cfg = await openControlFlow(page);
  const first = cfg.locator(".cfg-block").first();
  const head = first.locator(".cfg-block-head");

  await expect(head.getByText("B0", { exact: true })).toBeVisible();
  await expect(head.getByText(/^0x[0-9a-f]+$/)).toBeVisible();
  await expect(head.getByText(/\d+ bytes/)).toBeVisible();
  await expect(head.getByText(/\d+ instructions?/)).toBeVisible();
  // The first and last instruction are labelled inside the block.
  await expect(first.locator(".cfg-instrs").getByText("first", { exact: true })).toBeVisible();
});

test("an edge is a labelled jump control that focuses its target block", async ({ page }) => {
  const cfg = await openControlFlow(page);
  const jump = cfg.locator(".cfg-edge-jump").first();

  await expect(jump).toHaveAccessibleName(/Go to block B\d+ at 0x[0-9a-f]+/);
  const label = (await jump.getAttribute("aria-label")) ?? "";
  const target = /at (0x[0-9a-f]+)$/.exec(label)?.[1] ?? "";
  expect(target).toMatch(/^0x[0-9a-f]+$/);

  await jump.click();
  const focused = await page.evaluate<string>(() => document.activeElement?.id ?? "");
  // blockId() renders 0x10018b0 as cfg-block-10018b0.
  expect(focused).toBe(`cfg-block-${target.slice(2)}`);
});

test("the graph does not overflow the 480px shell", async ({ page }) => {
  // The UI audit renders each route in its default state, which is the
  // disassembly listing, so the graph's own layout is measured here.
  await page.setViewportSize({ width: 480, height: 900 });
  const cfg = await openControlFlow(page);
  await expect(cfg.locator(".cfg-block").first()).toBeVisible();

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});
