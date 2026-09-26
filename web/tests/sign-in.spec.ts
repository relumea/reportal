// The sign-in gate: with token auth on, a caller without an accepted token gets
// the sign-in view instead of the workspace; a checked token lets it in, and
// sign-out drops back to the gate.  The e2e server runs with auth off, so the
// refusal is `GET /api/iam/me` answering `unauthorized` until the right token.

import { expect, test } from "./fixtures";

const TOKEN = "e2e-sign-in-token";

test.use({ expectedRefused: ["unauthorized"] });

test("a refused caller signs in with a checked token and signs out again", async ({ page }) => {
  await page.route("**/api/iam/me", async (route) => {
    if (route.request().headers().authorization === `Bearer ${TOKEN}`) {
      await route.fulfill({
        json: { auth: "required", user: null, role: "analyst", permissions: [], teams: [] },
      });
      return;
    }
    await route.fulfill({
      status: 401,
      json: { error: "unauthorized", detail: "send Authorization: Bearer <token>" },
    });
  });

  await page.goto("/#/");
  const heading = page.getByRole("heading", { name: "Sign in" });
  await expect(heading).toBeVisible();

  await page.getByLabel("Access token").fill("not-the-token");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toHaveText("That token was not accepted.");

  await page.getByLabel("Access token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(heading).toHaveCount(0);
  await expect(page.locator("#title")).toBeVisible();
  // Sign-out reloads the page; let the dashboard's requests finish first.
  await page.waitForLoadState("networkidle");

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(heading).toBeVisible();
});

test("an open install shows the workspace with no sign-in or sign-out", async ({ page }) => {
  await page.goto("/#/");
  await expect(page.locator("#title")).toHaveText("Dashboard");
  await expect(page.locator(".theme-picker")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Sign in" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Sign out" })).toHaveCount(0);
});
