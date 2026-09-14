// The in-app manual: the page index, and the reading-order pager the server
// sends with each page (the hosted manual's previous/next pair).  The order is
// the server's `docs._page_files`, so the index and the pager cannot disagree.

import { expect, test } from "./fixtures";

test("the manual's index lists the pages and no pager", async ({ page }) => {
  await page.goto("/#/docs");
  await expect(page.locator("a.doc-card").first()).toBeVisible();
  await expect(page.locator('a.doc-card[href="#/docs/cli"]')).toHaveCount(1);
  await expect(page.getByRole("navigation", { name: "Previous and next page" })).toHaveCount(0);
});

test("a page carries the pair that walks the manual both ways", async ({ page }) => {
  await page.goto("/#/docs/cli");
  const pager = page.getByRole("navigation", { name: "Previous and next page" });
  await expect(pager.getByRole("link", { name: /Previous/ })).toHaveAttribute(
    "href",
    /docs\/api/,
  );
  const next = pager.getByRole("link", { name: /Next/ });
  await expect(next).toHaveAttribute("href", /docs\/spa/);

  await next.click();

  await expect(page).toHaveURL(/docs\/spa/);
  const back = page
    .getByRole("navigation", { name: "Previous and next page" })
    .getByRole("link", { name: /Previous/ });
  await expect(back).toHaveAttribute("href", /docs\/cli/);
});

test("the changelog is last, so its pager offers no next", async ({ page }) => {
  await page.goto("/#/changelog");
  const pager = page.getByRole("navigation", { name: "Previous and next page" });
  await expect(pager.getByRole("link", { name: /Previous/ })).toBeVisible();
  await expect(pager.getByRole("link", { name: /Next/ })).toHaveCount(0);
});
