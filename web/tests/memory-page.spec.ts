// The Memory panel's full-file mode: load a page through the engine's own
// section map, page once, select a byte range and copy it as hex.  The copied
// text is rendered in the panel, so the assertion reads it without clipboard
// permissions; the actual clipboard write is best-effort.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("the full-file view pages and copies a selected range as hex", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}?tab=memory`);
  const panel = panelByTitle(page, "Memory");

  await panel.getByLabel("Mode").selectOption("file");
  await panel.getByRole("button", { name: "Load page" }).click();
  await expect(panel.locator(".memory-row").first()).toBeVisible();
  const rowBytes = panel.locator(".memory-row").first().locator(".memory-bytes > .byte");
  await expect(rowBytes).toHaveCount(16);
  await expect(rowBytes.nth(7)).toHaveCSS("margin-right", "12px");
  await expect(rowBytes.nth(6)).toHaveCSS("margin-right", "0px");

  const firstRow = async (): Promise<string> => panel.locator(".memory-row").first().innerText();
  const before = await firstRow();
  await panel.getByRole("button", { name: "Next page" }).click();
  await expect.poll(firstRow).not.toBe(before);

  const bytes = panel.locator("button.byte");
  await bytes.nth(0).click();
  await bytes.nth(3).click({ modifiers: ["Shift"] });
  await expect(panel.getByText(/Selected /)).toBeVisible();

  await panel.getByRole("button", { name: "Copy hex" }).click();
  const copied = panel.getByText(/Copied: /);
  await expect(copied).toBeVisible();
  // Four bytes selected, so the hex readout is four space-separated pairs.
  await expect(copied).toHaveText(/Copied: [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2}/);
  await panel.getByRole("button", { name: "Clear selection" }).click();
  await bytes.nth(0).click();
  await bytes.nth(3).click({ modifiers: ["Shift"] });
  await panel.locator(".memory-grid").press("Control+c");
  await expect(copied).toHaveText(/Copied: [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2} [0-9a-f]{2}/);
  await panel.getByRole("button", { name: "Copy ASCII" }).click();
  await expect(copied).toHaveText(/Copied: .{4}$/);
  await panel.getByRole("button", { name: "Clear selection" }).click();
  const ascii = panel.locator("button[aria-label^='ascii ']");
  await ascii.nth(0).click();
  await ascii.nth(3).click({ modifiers: ["Shift"] });
  await panel.locator(".memory-grid").press("Control+c");
  await expect(copied).toHaveText(/Copied: .{4}$/);
  await panel.locator(".memory-grid").press("Escape");
  await expect(panel.getByText(/Selected /)).toHaveCount(0);
});

test("the continuous view scrolls the whole binary and links from a section", async ({ page }) => {
  await page.goto(`/#/binaries/${state.ids.binary_id}`);
  const panel = panelByTitle(page, "Memory");
  const sections = page
    .locator(".panel")
    .filter({ has: page.getByRole("heading", { name: /^Sections / }) });
  await sections.locator("button.panel-fold").click();

  // The section table's virtual-address column is the link into the dump.
  const link = sections.locator("a.address-link").first();
  await expect(link).toBeVisible();
  const href = await link.getAttribute("href");
  const target = (href ?? "").split("memory=")[1]?.split("&")[0];
  expect(target).toMatch(/^0x[0-9a-f]+$/);
  const fileLink = sections.getByRole("columnheader", { name: "File offset" });
  await expect(fileLink).toBeVisible();
  const offsetHref = await sections.locator("a.address-link").nth(1).getAttribute("href");
  expect(offsetHref).toMatch(/memory=0x[0-9a-f]+&memoryKind=file/);
  await link.click();

  // The dump opens in the continuous mode, on the linked address, and reads
  // bytes rather than placeholders.
  await expect(panel.getByLabel("Go to address")).toHaveValue(target);
  await expect(panel.locator(".memory-row").first()).toBeVisible();
  // The rows above the linked offset are off screen and unread, so the first
  // rendered line is a placeholder; the bytes that are on screen are real, and
  // the linked row is the selected one.
  await expect(panel.locator("button.byte").first()).toBeVisible();
  await expect(panel.locator(".memory-row .byte-selected").first()).toBeVisible();

  // Scrolling keeps reading: the readout counts the loaded bytes upward as the
  // dump walks on from the linked address.
  const readout = panel.getByText(/bytes loaded/);
  const loaded = async (): Promise<number> =>
    Number(/(\d+) bytes loaded/.exec(await readout.innerText())?.[1] ?? "0");
  const before = await loaded();
  await panel.locator(".memory-scroll").evaluate((node) => {
    node.scrollTop = node.scrollHeight;
    node.dispatchEvent(new Event("scroll", { bubbles: true }));
  });
  await expect.poll(loaded).toBeGreaterThan(before);

  // The keyboard layer: `G` focuses the address box and Tab switches columns.
  await panel.locator(".memory-scroll").press("g");
  await expect(panel.getByLabel("Go to address")).toBeFocused();
  await panel.getByLabel("Go to address").fill("0xdead");
  await panel.getByLabel("Go to address").press("Escape");
  await expect(panel.getByLabel("Go to address")).toHaveValue("");
  await expect(panel.locator(".memory-scroll")).toBeFocused();

  // Tab inside the address box toggles the column without leaving the input.
  await panel.locator(".memory-scroll").press("g");
  await expect(panel.getByLabel("Go to address")).toBeFocused();
  await expect(panel.getByLabel("Columns")).toHaveValue("va");
  await panel.getByLabel("Go to address").press("Tab");
  await expect(panel.getByLabel("Columns")).toHaveValue("file");
  await expect(panel.getByLabel("Go to address")).toBeFocused();
  await panel.getByLabel("Go to address").press("Tab");
  await expect(panel.getByLabel("Columns")).toHaveValue("va");
});
