// Small shared helpers for the specs: locating a panel by its title, finding a
// table row by its text, keyboard tabbing with a page-side predicate, and
// unique names so a retry never collides with the previous attempt's rows.

import type { Locator, Page } from "@playwright/test";

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

let counter = 0;

/** A fresh name per call, so re-running a spec does not hit a stored duplicate. */
export function uniqueName(prefix: string): string {
  counter += 1;
  return `${prefix}-${Date.now().toString(36)}-${counter}`;
}

/** Press Tab until *predicate* (a page-side expression) is true. */
export async function tabUntil(page: Page, predicate: string, steps: number): Promise<boolean> {
  for (let step = 0; step < steps; step += 1) {
    await page.keyboard.press("Tab");
    if (await page.evaluate<boolean>(predicate)) return true;
  }
  return false;
}

/** The `.panel` section whose heading is exactly *title*. */
export function panelByTitle(page: Page, title: string): Locator {
  return page
    .locator(".panel")
    .filter({ has: page.getByRole("heading", { name: title, exact: true }) });
}

// Clickable rows carry `role="link"` (DataTable overrides the row role when
// the row navigates), so rows are located structurally rather than by role.
export function rowContaining(scope: Locator, text: string): Locator {
  return scope.locator("table.data-table tbody tr").filter({ hasText: text });
}
