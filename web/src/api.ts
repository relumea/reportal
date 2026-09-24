// Typed fetch wrapper over the reportal JSON API.  Every route answers a JSON
// object; a non-2xx answer carries {"error", "detail"}, which becomes an
// ApiError so callers can branch on the stable error name.

interface ApiErrorBody {
  error?: string;
  detail?: string;
}

export class ApiError extends Error {
  readonly detail: string;
  /** The HTTP status that carried the error; 0 for one raised in the browser. */
  readonly status: number;

  constructor(message: string, detail = "", status = 0) {
    super(message);
    this.name = "ApiError";
    this.detail = detail;
    this.status = status;
  }
}

export function errorText(error: unknown): string {
  if (isApiErrorCode(error, LLM_UNAVAILABLE)) return NO_MODEL_MESSAGE;
  if (error instanceof ApiError) {
    return error.detail ? `${error.message}: ${error.detail}` : error.message;
  }
  return error instanceof Error ? error.message : String(error);
}

export function isApiErrorCode(error: unknown, code: string): boolean {
  return error instanceof ApiError && error.message === code;
}

/** True for a 404: the row the request named does not exist or is out of scope. */
export function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

interface RequestOptions {
  method?: string;
  /** JSON request body; serialized with the JSON content type. */
  json?: unknown;
  /** Raw body, used for the multipart upload FormData. */
  body?: FormData;
}

const API_PREFIX = "/api";

/**
 * A JSON route on a loopback install answers in seconds; two minutes of
 * silence is a wedged server.  The timer is this request's inverse: it aborts
 * the fetch, and the `finally` below clears it the moment the response
 * settles, so a finished request leaves no timer and a wedged one cannot pin
 * a socket for the life of the page.  Multipart uploads carry a file of
 * unbounded size, so they run without the cap.
 */
const JSON_TIMEOUT_MS = 120_000;

/**
 * One request's abort deadline: the timer aborts the signal at *timeoutMs*
 * and `dispose` is the inverse the caller runs once the response has settled,
 * so a finished request keeps no timer and a wedged one cannot pin the call
 * for the life of the page.  Raw fetches outside `api()` take the same cap
 * through this helper instead of growing their own.
 */
export function abortDeadline(timeoutMs: number = JSON_TIMEOUT_MS): {
  signal: AbortSignal;
  dispose: () => void;
} {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  return { signal: controller.signal, dispose: () => window.clearTimeout(timer) };
}

/**
 * The whole binary register projected to `id` and `name`, which is what a
 * binary picker renders.  The full register row carries the sha256, the path,
 * the operator notes and both aggregate counts, so a picker that reads the
 * whole register pays megabytes of JSON for two columns.
 */
export const BINARY_OPTIONS_PATH = "/binaries?summary=true";

import { COMMENT_AUTHOR_STORAGE_KEY, LLM_UNAVAILABLE, NO_MODEL_MESSAGE } from "./constants";
import { resetSessionCache } from "./panelCache";

/** Where the browser keeps the bearer token an authenticated install needs. */
const TOKEN_STORAGE_KEY = "reportal.token";

/** The token the browser holds, or an empty string. */
export function storedToken(): string {
  try {
    return window.localStorage.getItem(TOKEN_STORAGE_KEY) ?? "";
  } catch {
    // A browser with storage disabled can still read an open install; it just
    // cannot remember a token across reloads.
    return "";
  }
}

/** Remember (or forget, with an empty value) the token the browser sends. */
export function storeToken(token: string): void {
  const previous = storedToken();
  try {
    if (token) window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
    else window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Nothing to do: the header still comes from storedToken() this session.
  }
  // Panels and view queries are keyed by entity id alone; a different bearer
  // must not keep serving the previous caller's cached rows.  The free-text
  // comment author is personal data bound to that session, so it goes too.
  if (token !== previous) {
    resetSessionCache();
    try {
      window.localStorage.removeItem(COMMENT_AUTHOR_STORAGE_KEY);
    } catch {
      // Private mode: nothing to clear.
    }
  }
}

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const init: RequestInit = { method: options.method ?? "GET", headers: {} };
  if (options.json !== undefined) {
    init.body = JSON.stringify(options.json);
    init.headers = { "Content-Type": "application/json" };
  } else if (options.body !== undefined) {
    init.body = options.body;
  }
  const token = storedToken();
  if (token) {
    init.headers = { ...(init.headers as Record<string, string>), Authorization: `Bearer ${token}` };
  }
  const deadline = options.body instanceof FormData ? null : abortDeadline();
  if (deadline !== null) init.signal = deadline.signal;
  try {
    const response = await fetch(`${API_PREFIX}${path}`, init);
    const payload: unknown = await response.json().catch((failure: unknown) => {
      // An abort mid-body must surface as the request's failure, not be
      // mistaken for the empty payload a malformed answer becomes.
      if (failure instanceof DOMException && failure.name === "AbortError") throw failure;
      return {};
    });
    if (!response.ok) {
      const failure = payload as ApiErrorBody;
      throw new ApiError(
        failure.error ?? `request failed: ${response.status}`,
        failure.detail ?? "",
        response.status,
      );
    }
    // The wrapper trusts the server's declared response shape; the type argument
    // names the contract of the route being called.
    return payload as T;
  } finally {
    deadline?.dispose();
  }
}
