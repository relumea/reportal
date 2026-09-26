// Test base with a page-level guard: every test fails when the page logs a
// console error, throws, drops a network request or gets an error response.
// The guard is what makes "the route rendered" meaningful: an error note the
// app drew from a 500, or an uncaught rejection, is a defect.
//
// Benign noise, and nothing else, is filtered: a stored-only read answers 404
// with a documented empty-result code (`no-scan`, `no-artifact`, `no-run`,
// `no-graph`) when nothing is stored yet, and the panel renders that as its
// nothing-stored hint.  Chromium logs its own "404" console line for such a
// response, so both the response and that console line are dropped together,
// keyed by URL.  Any other status, any other code, any other request, any
// page error and any console error still fails the test.

import { expect, test as base } from "@playwright/test";
import type { Page, Response } from "@playwright/test";

export interface PageIssues {
  consoleErrors: string[];
  pageErrors: string[];
  failedRequests: string[];
  errorResponses: string[];
}

export const EMPTY_PAGE_ISSUES: PageIssues = {
  consoleErrors: [],
  pageErrors: [],
  failedRequests: [],
  errorResponses: [],
};

// The API's 404 codes for "nothing is stored yet" (mirrored in src/constants.ts).
export const EMPTY_RESULT_CODES = new Set([
  "no-scan",
  "no-artifact",
  "no-run",
  "no-graph",
  "no-symbols",
  "no-docs",
  "no-doc",
]);
const EMPTY_RESULT_STATUS = 404;

/** The status a refused caller gets (token auth on, no accepted token). */
const REFUSED_STATUS = 401;

// A navigation cancels requests still in flight; the browser reports those as
// ERR_ABORTED, which is not an application failure.
const ABORTED_REQUEST = "net::ERR_ABORTED";

interface PendingResponse {
  status: number;
  method: string;
  url: string;
  code: Promise<string | undefined>;
}

interface PendingConsoleError {
  text: string;
  url: string;
}

function resultCode(response: Response): Promise<string | undefined> {
  return response.json().then(
    (body: unknown) => {
      if (typeof body !== "object" || body === null) return undefined;
      const code = (body as { error?: unknown }).error;
      return typeof code === "string" ? code : undefined;
    },
    () => undefined,
  );
}

export const test = base.extend<{
  page: Page;
  expectedMissing: string[];
  expectedRefused: string[];
}>({
  // 404 codes a spec provokes on purpose (a detail route for a row that does
  // not exist); a spec opts in with `test.use({ expectedMissing: [...] })`.
  expectedMissing: [[], { option: true }],
  // 401 codes a spec provokes on purpose (the sign-in gate), the same way.
  expectedRefused: [[], { option: true }],
  page: async ({ page, expectedMissing, expectedRefused }, use) => {
    const issues: PageIssues = {
      consoleErrors: [],
      pageErrors: [],
      failedRequests: [],
      errorResponses: [],
    };
    const consoleErrors: PendingConsoleError[] = [];
    const responses: PendingResponse[] = [];

    page.on("console", (message) => {
      if (message.type() === "error") {
        consoleErrors.push({ text: message.text(), url: message.location().url });
      }
    });
    page.on("pageerror", (error) => issues.pageErrors.push(error.message));
    page.on("requestfailed", (request) => {
      const failure = request.failure()?.errorText ?? "unknown";
      if (failure === ABORTED_REQUEST) return;
      issues.failedRequests.push(`${request.method()} ${request.url()}: ${failure}`);
    });
    page.on("response", (response) => {
      if (response.status() < 400) return;
      responses.push({
        status: response.status(),
        method: response.request().method(),
        url: response.url(),
        code: resultCode(response),
      });
    });

    await use(page);

    const emptyResultUrls = new Set<string>();
    for (const entry of responses) {
      const code = await entry.code;
      if (
        entry.status === EMPTY_RESULT_STATUS &&
        code !== undefined &&
        (EMPTY_RESULT_CODES.has(code) || expectedMissing.includes(code))
      ) {
        emptyResultUrls.add(entry.url);
        continue;
      }
      if (entry.status === REFUSED_STATUS && code !== undefined && expectedRefused.includes(code)) {
        emptyResultUrls.add(entry.url);
        continue;
      }
      issues.errorResponses.push(
        `${entry.status} ${entry.method} ${entry.url}${code === undefined ? "" : ` (${code})`}`,
      );
    }
    for (const entry of consoleErrors) {
      if (entry.url !== "" && emptyResultUrls.has(entry.url)) continue;
      issues.consoleErrors.push(entry.text);
    }

    expect(
      issues,
      "the page logged an error, dropped a request or got an error response",
    ).toEqual(EMPTY_PAGE_ISSUES);
  },
});

export { expect };
