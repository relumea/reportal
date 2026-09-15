// Which palette the token layer in `styles.css` serves.  Every theme but
// `system` is one `:root[data-theme="..."]` block there; `system` resolves to
// dark or light from the OS preference, so the attribute is always set and the
// stylesheet needs no media query.
//
// Resolution is first match wins: the `?theme=` query parameter (what
// `tools/audit_ui.py` renders a theme with), then `localStorage`, then the OS.

export const THEMES = ["system", "dark", "light", "zine"] as const;

export type Theme = (typeof THEMES)[number];

export const THEME_LABELS: Record<Theme, string> = {
  system: "System",
  dark: "Dark",
  light: "Light",
  zine: "Windows 2000",
};

export const THEME_STORAGE_KEY = "reportal.theme";

const DARK_QUERY = "(prefers-color-scheme: dark)";

function isTheme(value: string | null): value is Theme {
  return value !== null && (THEMES as readonly string[]).includes(value);
}

/** The theme this browser should start in. */
export function storedTheme(): Theme {
  try {
    const fromUrl = new URLSearchParams(window.location.search).get("theme");
    if (isTheme(fromUrl)) return fromUrl;
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (isTheme(stored)) return stored;
  } catch {
    // Storage disabled: the portal follows the OS and forgets the choice.
  }
  return "system";
}

/** Put *theme* on `<html>`, resolving `system` against the OS preference. */
export function applyTheme(theme: Theme): void {
  const resolved =
    theme === "system" ? (window.matchMedia(DARK_QUERY).matches ? "dark" : "light") : theme;
  document.documentElement.setAttribute("data-theme", resolved);
}

/** Remember *theme* and apply it. */
export function setTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Storage disabled: the choice holds for this page load only.
  }
  applyTheme(theme);
}

/** Apply the stored theme and keep `system` following the OS while it is set. */
export function installTheme(): void {
  applyTheme(storedTheme());
  window.matchMedia(DARK_QUERY).addEventListener("change", () => {
    if (storedTheme() === "system") applyTheme("system");
  });
}
