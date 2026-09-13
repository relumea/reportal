// Typed fetch wrapper over the reportal JSON API.  Every route answers a JSON
// object; a non-2xx answer carries {"error", "detail"}, which becomes an
// ApiError so callers can branch on the stable error name.

export interface ApiErrorBody {
  error?: string;
  detail?: string;
}

export class ApiError extends Error {
  readonly detail: string;

  constructor(message: string, detail = "") {
    super(message);
    this.name = "ApiError";
    this.detail = detail;
  }
}

export function errorText(error: unknown): string {
  if (error instanceof ApiError) {
    return error.detail ? `${error.message}: ${error.detail}` : error.message;
  }
  return error instanceof Error ? error.message : String(error);
}

export function isApiErrorCode(error: unknown, code: string): boolean {
  return error instanceof ApiError && error.message === code;
}

export interface RequestOptions {
  method?: string;
  /** JSON request body; serialized with the JSON content type. */
  json?: unknown;
  /** Raw body, used for the multipart upload FormData. */
  body?: FormData;
}

const API_PREFIX = "/api";

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const init: RequestInit = { method: options.method ?? "GET", headers: {} };
  if (options.json !== undefined) {
    init.body = JSON.stringify(options.json);
    init.headers = { "Content-Type": "application/json" };
  } else if (options.body !== undefined) {
    init.body = options.body;
  }
  const response = await fetch(`${API_PREFIX}${path}`, init);
  const payload: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const failure = payload as ApiErrorBody;
    throw new ApiError(failure.error ?? `request failed: ${response.status}`, failure.detail ?? "");
  }
  // The wrapper trusts the server's declared response shape; the type argument
  // names the contract of the route being called.
  return payload as T;
}
