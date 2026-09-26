import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";

import { api, isApiErrorCode, storeToken, storedToken } from "./api";
import { THEMES, THEME_LABELS, setTheme, storedTheme } from "./theme";
import type { Theme } from "./theme";
import { SignInView } from "./views/SignInView";
import "./SidebarFoot.css";

function ThemePicker(): ReactNode {
  const [theme, setCurrent] = useState<Theme>(storedTheme);
  return (
    <label className="theme-picker">
      <span className="theme-picker-label">Theme</span>
      <select
        value={theme}
        onChange={(event) => {
          const next = event.target.value as Theme;
          setCurrent(next);
          setTheme(next);
        }}
      >
        {THEMES.map((name) => (
          <option key={name} value={name}>
            {THEME_LABELS[name]}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Forgets the stored token; the reload lands on the sign-in view. */
function SignOut(): ReactNode {
  if (storedToken() === "") return null;

  return (
    <button
      type="button"
      className="sign-out"
      onClick={() => {
        storeToken("");
        window.location.reload();
      }}
    >
      Sign out
    </button>
  );
}

/** The sidebar foot's reader controls (the theme and, when a token is held,
 * sign-out) and the install's sign-in gate.  With token auth on and no accepted
 * token, `GET /api/iam/me` answers `unauthorized` and the sign-in view covers the
 * page.  It lives in this lazy chunk, not the shell, to keep the entry bundle
 * under its budget. */
export function SidebarFoot(): ReactNode {
  const [signedOut, setSignedOut] = useState(false);

  useEffect(() => {
    async function check(): Promise<void> {
      try {
        await api("/iam/me");
      } catch (failure) {
        setSignedOut(isApiErrorCode(failure, "unauthorized"));
      }
    }

    void check();
  }, []);

  return (
    <>
      <ThemePicker />
      <SignOut />
      {signedOut ? createPortal(<SignInView />, document.body) : null}
    </>
  );
}
