// The binary register's filters: the search (name or SHA-256), the tag, the
// format and the order narrow the table through the API, and every control
// lives in the route hash, so a filtered register is a link.
//
// The counts are never assumed: the suite runs against one shared workspace, so
// the assertions read a filtered result (one row) or compare the rendered order
// against the route's own answer.

import { e2eState } from "./e2e-state";
import { panelByTitle } from "./helpers";
import { expect, test } from "./fixtures";

const state = e2eState();

test("the register filters by name, hash and tag, and orders its rows", async ({ page }) => {
  await page.goto("/#/binaries");
  const panel = panelByTitle(page, "Binaries");
  const rows = panel.locator("table.data-table tbody tr");
  await expect(rows.first()).toBeVisible();
  const search = panel.getByRole("searchbox", { name: /Search/ });

  // The name search, applied with Enter, narrows in place.
  await search.fill("wide");
  await search.press("Enter");
  await expect(page).toHaveURL(/search=wide/);
  await expect(rows).toHaveCount(1);
  await expect(panel.getByText(/^1 of \d+ binaries$/)).toBeVisible();

  // Clear puts the whole register back.  The select's own value is waited for,
  // because the next control writes the hash from the render it is in: acting
  // while the cleared filters are still on screen would keep the old one.
  await panel.getByRole("button", { name: "Clear" }).click();
  await expect(page).toHaveURL(/#\/binaries$/);
  await expect(panel.getByRole("combobox", { name: "Tag", exact: true })).toHaveValue("");
  await expect(rows.filter({ hasText: "wide.exe" })).toHaveCount(1);

  // The hash: a prefix of a stored binary's own digest finds that binary.
  const register = (await (await page.request.get("/api/binaries")).json()) as {
    binaries: Array<{ name: string; sha256: string }>;
  };
  const target = register.binaries[0];
  await search.fill(target.sha256.slice(0, 12));
  await search.press("Enter");
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText(target.name);

  // The tag filter, built from the tags the register holds.
  await panel.getByRole("button", { name: "Clear" }).click();
  await expect(panel.getByRole("combobox", { name: "Tag", exact: true })).toHaveValue("");
  await panel
    .getByRole("combobox", { name: "Tag", exact: true })
    .selectOption(state.tag_name);
  await expect(page).toHaveURL(new RegExp(`tag=${state.tag_name}`));
  await expect(rows).toHaveCount(1);

  // The order: what the table draws is the order the route applied.
  await panel.getByRole("button", { name: "Clear" }).click();
  await expect(panel.getByRole("combobox", { name: "Tag", exact: true })).toHaveValue("");
  await panel.getByRole("combobox", { name: "Order", exact: true }).selectOption("name-desc");
  await expect(page).toHaveURL(/order=name-desc/);
  const ordered = (await (
    await page.request.get("/api/binaries?order=name-desc")
  ).json()) as { binaries: Array<{ name: string }> };
  await expect
    .poll(() =>
      rows.evaluateAll((nodes) =>
        nodes.map((node) => node.querySelector("td:nth-child(3)")?.textContent?.trim() ?? ""),
      ),
    )
    .toEqual(ordered.binaries.map((binary) => binary.name));

  // The controls survive a reload, which is what keeping them in the hash buys.
  await page.reload();
  await expect(panel.getByRole("combobox", { name: "Order", exact: true })).toHaveValue(
    "name-desc",
  );
});
