// The Integrations view folds each registry to one line, so the nine seams fit
// on a screen, and opens one on demand to its parts table.

import { expect, test } from "./fixtures";

test("each registry is folded until opened", async ({ page }) => {
  await page.goto("/#/integrations");
  const seam = page.locator("details.seam-card", {
    has: page.locator(".seam-name", { hasText: /^pipeline components/u }),
  });
  await expect(seam).toBeVisible();
  await expect(seam).not.toHaveAttribute("open");
  await expect(seam.getByRole("table")).toBeHidden();

  await seam.locator("summary").click();
  await expect(seam).toHaveAttribute("open");
  await expect(seam.getByRole("table", { name: "pipeline components" })).toBeVisible();
  await expect(seam.getByRole("cell", { name: "prepare", exact: true })).toBeVisible();
});
