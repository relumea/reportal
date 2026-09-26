import { useState } from "react";
import type { FormEvent, ReactNode } from "react";

import { api, errorText, isApiErrorCode, storeToken } from "../api";

/** Where a visitor without a token asks for one: the landing page's waitlist. */
const WAITLIST_URL = "https://relumea.ai/#waitlist";

/** The sign-in screen SidebarFoot shows while the install refuses the caller.  A
 * token is checked against `GET /api/iam/me` before it is kept; an accepted one
 * reloads the page, so every view starts from a clean cache under it. */
export function SignInView(): ReactNode {
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError("");
    storeToken(token.trim());

    try {
      await api("/iam/me");
      window.location.reload();
    } catch (failure) {
      storeToken("");
      setError(
        isApiErrorCode(failure, "unauthorized")
          ? "That token was not accepted."
          : errorText(failure),
      );
      setBusy(false);
    }
  }

  return (
    <main className="signin">
      <div className="signin-card">
        <p className="signin-brand">
          <img src="/static/favicon.svg" alt="" width="20" height="20" />
          relumea
        </p>
        <h1>Sign in</h1>
        <p className="muted">Paste the access token your administrator gave you.</p>
        <form onSubmit={(event) => void submit(event)}>
          <label htmlFor="signin-token">Access token</label>
          <input
            id="signin-token"
            type="password"
            autoComplete="current-password"
            required
            value={token}
            onChange={(event) => setToken(event.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="signin-error" role="alert">
            {error}
          </p>
        </form>
        <p className="muted signin-foot">
          No token? The hosted workspace is invite-only: <a href={WAITLIST_URL}>join the waitlist</a>.
        </p>
      </div>
    </main>
  );
}
