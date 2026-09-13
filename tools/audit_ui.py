"""audit_ui.py: gate the reportal SPA for layout and contrast defects.

Boots the same seeded workspace the browser smoke uses (``tools/smoke_spa.py``),
serves it, and drives headless Chrome over the DevTools protocol through
``--remote-debugging-pipe`` (no websocket dependency).  Every smoke route is
rendered at each viewport in ``VIEWPORTS`` and each colour scheme in ``THEMES``
(headless Chrome defaults to light, so the dark palette is emulated
explicitly) and checked inside the page for:

* horizontal document overflow (``scrollWidth > innerWidth``);
* clipped text, an element whose scroll box is larger than its client box on an
  axis that does not scroll;
* text whose composited foreground/background contrast is under
  ``CONTRAST_SMALL_TEXT``, with ``CONTRAST_LARGE_TEXT`` for text at least
  ``LARGE_TEXT_PX`` or at least ``LARGE_BOLD_PX`` at ``BOLD_FONT_WEIGHT``;
* a box reaching outside the viewport horizontally, unless an ancestor already
  clips that axis;
* an interactive element with no accessible name.

The thresholds are the module constants below; the same numbers are passed into
the page so the report and the gate cannot drift apart.

Exit status is 0 when every render is clean and 1 when any check fails, so it
works as a gate.  With no browser on PATH the audit prints a skip and exits 0,
matching ``tools/smoke_spa.py``.

Usage::

    uv run --python .venv/bin/python tools/audit_ui.py
    uv run --python .venv/bin/python tools/audit_ui.py --base-url http://127.0.0.1:8731
    uv run --python .venv/bin/python tools/audit_ui.py --json
    uv run --python .venv/bin/python tools/audit_ui.py --viewport 1600x1000 --theme dark
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = next(
    candidate
    for candidate in (Path(__file__).resolve().parent, *Path(__file__).resolve().parent.parents)
    if (candidate / "pyproject.toml").is_file()
)
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tools import smoke_spa  # noqa: E402
from tools.cdp import (  # noqa: E402
    CdpError,
    CdpPipe,
    browser_session,
    evaluate,
    render,
)

# ── Thresholds (WCAG AA and the two pixel tolerances the checks need) ──────

# Small text needs 4.5:1, large text 3:1 (WCAG 1.4.3).
CONTRAST_SMALL_TEXT = 4.5
CONTRAST_LARGE_TEXT = 3.0
# A text element counts as large at 18px, or at 14px when bold.
LARGE_TEXT_PX = 18.0
LARGE_BOLD_PX = 14.0
BOLD_FONT_WEIGHT = 700
# Sub-pixel layout rounding, so a one-pixel difference is not a defect.
BOX_TOLERANCE_PX = 1

# Viewports every route is audited at: the workbench size and a narrow phone.
VIEWPORTS: tuple[tuple[int, int], ...] = ((1600, 1000), (480, 900))

# Colour schemes every route is audited in.  Headless Chrome defaults to light,
# so the dark palette is emulated, never assumed.
THEMES: tuple[str, ...] = ("dark", "light")

WORKSPACE_RELATIVE = Path(".scratch") / "audit-ui"
EXIT_OK = 0
EXIT_FAIL = 1

# Limits handed to the page; keys are read by AUDIT_SCRIPT.
PAGE_LIMITS: dict[str, float] = {
    "contrastSmall": CONTRAST_SMALL_TEXT,
    "contrastLarge": CONTRAST_LARGE_TEXT,
    "largeTextPx": LARGE_TEXT_PX,
    "largeBoldPx": LARGE_BOLD_PX,
    "boldWeight": float(BOLD_FONT_WEIGHT),
    "tolerance": float(BOX_TOLERANCE_PX),
}

AUDIT_SCRIPT = r"""(() => {
  const L = __LIMITS__;
  const violations = [];
  const seen = new Set();

  const describe = (el) => {
    if (!(el instanceof Element)) return "document";
    const parts = [];
    let node = el;
    for (let depth = 0; node && node.nodeType === 1 && depth < 4; depth += 1) {
      let part = node.tagName.toLowerCase();
      if (node.id) {
        parts.unshift(part + "#" + node.id);
        return parts.join(" > ");
      }
      const classes = (node.getAttribute("class") || "").split(/\s+/).filter(Boolean).slice(0, 2);
      if (classes.length) part += "." + classes.join(".");
      parts.unshift(part);
      node = node.parentElement;
    }
    return parts.join(" > ");
  };

  const record = (kind, el, detail) => {
    const selector = describe(el);
    const key = kind + "|" + selector + "|" + detail;
    if (seen.has(key)) return;
    seen.add(key);
    violations.push({ kind, selector, detail });
  };

  const isVisible = (el) => {
    if (typeof el.checkVisibility === "function") {
      return el.checkVisibility({
        checkOpacity: true,
        checkVisibilityCSS: true,
        contentVisibilityAuto: true,
      });
    }
    const style = getComputedStyle(el);
    return (
      style.display !== "none" &&
      style.visibility !== "hidden" &&
      parseFloat(style.opacity) !== 0
    );
  };

  const isInactive = (el) => el.closest("[disabled],[aria-disabled='true'],[hidden]") !== null;

  const hasDirectText = (el) => {
    for (const node of el.childNodes) {
      if (node.nodeType === 3 && node.textContent && node.textContent.trim() !== "") return true;
    }
    return false;
  };

  const parseColor = (value) => {
    const match = /rgba?\(([^)]+)\)/.exec(value || "");
    if (!match) return null;
    const parts = match[1].split(",").map((part) => parseFloat(part));
    if (parts.length < 3 || parts.slice(0, 3).some((part) => Number.isNaN(part))) return null;
    return {
      r: parts[0],
      g: parts[1],
      b: parts[2],
      a: parts.length > 3 && !Number.isNaN(parts[3]) ? parts[3] : 1,
    };
  };

  const over = (src, dst) => {
    const alpha = src.a + dst.a * (1 - src.a);
    if (alpha === 0) return { r: 0, g: 0, b: 0, a: 0 };
    return {
      r: (src.r * src.a + dst.r * dst.a * (1 - src.a)) / alpha,
      g: (src.g * src.a + dst.g * dst.a * (1 - src.a)) / alpha,
      b: (src.b * src.a + dst.b * dst.a * (1 - src.a)) / alpha,
      a: alpha,
    };
  };

  const luminance = (color) => {
    const channel = (value) => {
      const scaled = value / 255;
      return scaled <= 0.04045 ? scaled / 12.92 : Math.pow((scaled + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b);
  };

  const contrast = (a, b) => {
    const first = luminance(a);
    const second = luminance(b);
    return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
  };

  const backdropOf = (el) => {
    const layers = [];
    for (let node = el; node; node = node.parentElement) {
      const color = parseColor(getComputedStyle(node).backgroundColor);
      if (color && color.a > 0) layers.push(color);
    }
    let backdrop = { r: 255, g: 255, b: 255, a: 1 };
    for (let index = layers.length - 1; index >= 0; index -= 1) {
      backdrop = over(layers[index], backdrop);
    }
    return backdrop;
  };

  const format = (color) =>
    "rgb(" + Math.round(color.r) + ", " + Math.round(color.g) + ", " + Math.round(color.b) + ")";

  const insideHorizontalClip = (el) => {
    for (let node = el.parentElement; node; node = node.parentElement) {
      const overflowX = getComputedStyle(node).overflowX;
      if (overflowX === "auto" || overflowX === "scroll" || overflowX === "hidden") return true;
    }
    return false;
  };

  const accessibleName = (el) => {
    const label = el.getAttribute("aria-label");
    if (label && label.trim()) return label.trim();
    const labelledBy = el.getAttribute("aria-labelledby");
    if (labelledBy) {
      const text = labelledBy
        .split(/\s+/)
        .map((id) => {
          const target = document.getElementById(id);
          return target ? target.textContent || "" : "";
        })
        .join(" ")
        .trim();
      if (text) return text;
    }
    if (el.textContent && el.textContent.trim()) return el.textContent.trim();
    if (el.labels && el.labels.length) {
      const text = Array.from(el.labels)
        .map((item) => item.textContent || "")
        .join(" ")
        .trim();
      if (text) return text;
    }
    if (
      el instanceof HTMLInputElement &&
      (el.type === "submit" || el.type === "button" || el.type === "reset") &&
      el.value
    ) {
      return el.value;
    }
    return "";
  };

  const innerWidth = window.innerWidth;
  if (document.documentElement.scrollWidth > innerWidth + L.tolerance) {
    record(
      "document-overflow",
      document.documentElement,
      "scrollWidth " + document.documentElement.scrollWidth + " > viewport " + innerWidth,
    );
  }

  for (const el of document.querySelectorAll("body *")) {
    if (!isVisible(el)) continue;
    const style = getComputedStyle(el);
    const rect = el.getBoundingClientRect();

    if (hasDirectText(el) && !isInactive(el)) {
      if (style.display !== "inline") {
        // An axis that scrolls already exposes the content, so only a
        // non-scrolling overflow (visible or clip) counts as clipped text.
        const scrolls = (value) =>
          value === "auto" || value === "scroll" || value === "hidden";
        const clippedX =
          !scrolls(style.overflowX) && el.scrollWidth > el.clientWidth + L.tolerance;
        const clippedY =
          !scrolls(style.overflowY) && el.scrollHeight > el.clientHeight + L.tolerance;
        if (clippedX || clippedY) {
          record(
            "clipped-text",
            el,
            "scroll " +
              el.scrollWidth +
              "x" +
              el.scrollHeight +
              " > client " +
              el.clientWidth +
              "x" +
              el.clientHeight,
          );
        }
      }

      const foreground = parseColor(style.color);
      if (foreground) {
        const backdrop = backdropOf(el);
        const composited = over(foreground, backdrop);
        const fontSize = parseFloat(style.fontSize);
        const fontWeight = parseInt(style.fontWeight, 10) || 400;
        const large =
          fontSize >= L.largeTextPx ||
          (fontWeight >= L.boldWeight && fontSize >= L.largeBoldPx);
        const minimum = large ? L.contrastLarge : L.contrastSmall;
        const value = contrast(composited, backdrop);
        if (value < minimum) {
          record(
            "contrast",
            el,
            value.toFixed(2) +
              ":1 (need " +
              minimum +
              ") " +
              style.color +
              " on " +
              format(backdrop),
          );
        }
      }
    }

    if (
      rect.width > 0 &&
      (rect.left < -L.tolerance || rect.right > innerWidth + L.tolerance) &&
      !insideHorizontalClip(el)
    ) {
      record(
        "outside-viewport",
        el,
        "rect " + Math.round(rect.left) + ".." + Math.round(rect.right) + " vs 0.." + innerWidth,
      );
    }
  }

  for (const el of document.querySelectorAll("button, a[href], input, select, textarea")) {
    if (!isVisible(el) || isInactive(el)) continue;
    if (el instanceof HTMLInputElement && el.type === "hidden") continue;
    if (accessibleName(el)) continue;
    record("no-accessible-name", el, el.tagName.toLowerCase() + " has no name");
  }

  return violations;
})()"""


def emit(message: str) -> None:
    """Write one audit result line to stdout."""
    sys.stdout.write(f"{message}\n")
    sys.stdout.flush()


def route_url(base_url: str, route: str, render_index: int) -> str:
    """Absolute URL for a hash route, reloaded fresh on every render.

    A query string that changes per render forces a full navigation; an
    unchanged one would make Chrome treat a different hash as a fragment jump
    and skip the load event the settle waits on.
    """
    return f"{base_url}/?audit={render_index}{route}"


def set_theme(cdp: CdpPipe, session_id: str, theme: str) -> None:
    """Emulate *theme* as the page's ``prefers-color-scheme``."""
    cdp.send(
        "Emulation.setEmulatedMedia",
        {"features": [{"name": "prefers-color-scheme", "value": theme}]},
        session_id=session_id,
    )


def audit_route(
    cdp: CdpPipe,
    session_id: str,
    base_url: str,
    route: str,
    width: int,
    height: int,
    theme: str,
    index: int,
) -> list[dict[str, str]]:
    """Render one route in one theme and return its page-level violations."""
    set_theme(cdp, session_id, theme)
    render(cdp, session_id, route_url(base_url, route, index), width, height)
    script = AUDIT_SCRIPT.replace("__LIMITS__", json.dumps(PAGE_LIMITS))
    violations = evaluate(cdp, session_id, script)
    if not isinstance(violations, list):
        raise CdpError("the page returned no violation list")
    return [violation for violation in violations if isinstance(violation, dict)]


def start_server(workspace: Path, env: dict[str, str]) -> tuple[subprocess.Popen[bytes], str]:
    """Start ``reportal serve`` on a free port and return the process and URL."""
    port = smoke_spa.free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "reportal",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--no-open",
        ],
        cwd=str(workspace),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    if not smoke_spa.wait_for_server(port):
        smoke_spa.stop_server(proc)
        raise RuntimeError(f"the reportal server never became healthy on port {port}")
    return proc, f"http://127.0.0.1:{port}"


def parse_viewport(value: str) -> tuple[int, int]:
    """Parse a ``WIDTHxHEIGHT`` viewport argument."""
    try:
        width_text, height_text = value.lower().split("x", 1)
        width, height = int(width_text), int(height_text)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not WIDTHxHEIGHT: {value!r}") from error
    if width <= 0 or height <= 0:
        raise argparse.ArgumentTypeError(f"not a positive viewport: {value!r}")
    return width, height


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the command line."""
    parser = argparse.ArgumentParser(
        description="Audit the reportal SPA for layout and contrast defects."
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Audit a server already running at this URL instead of booting one.",
    )
    parser.add_argument(
        "--viewport",
        type=parse_viewport,
        action="append",
        default=None,
        metavar="WxH",
        help=(
            "Viewport to audit, repeatable "
            f"(default: {', '.join(f'{w}x{h}' for w, h in VIEWPORTS)})."
        ),
    )
    parser.add_argument(
        "--theme",
        choices=THEMES,
        action="append",
        default=None,
        help=f"Colour scheme to audit, repeatable (default: {', '.join(THEMES)}).",
    )
    parser.add_argument("--json", action="store_true", help="Print the report as JSON.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the audit; 0 when every render is clean or on a clean skip."""
    args = parse_args(argv)
    viewports: tuple[tuple[int, int], ...] = tuple(args.viewport) if args.viewport else VIEWPORTS
    themes: tuple[str, ...] = tuple(args.theme) if args.theme else THEMES

    browser = smoke_spa.find_browser()
    if browser is None:
        emit(f"skip: no headless browser ({' or '.join(smoke_spa.BROWSERS)}) on PATH")
        return EXIT_OK

    base_url = args.base_url.rstrip("/") if args.base_url else None
    workspace = _REPO_ROOT / WORKSPACE_RELATIVE
    server: subprocess.Popen[bytes] | None = None
    ids = {"binary_id": 1, "function_id": 1, "candidate_function_id": 2, "conversation_id": 1}
    try:
        if base_url is None:
            missing = _missing_prerequisites()
            if missing is not None:
                emit(f"missing prerequisite: {missing}")
                return EXIT_FAIL
            if smoke_spa.ensure_frontend_built():
                return EXIT_FAIL
            project_dir = smoke_spa.sibling(smoke_spa.NOTEPAD_PROJECT_RELATIVE)
            ids = smoke_spa.build_workspace(
                workspace,
                project_dir,
                project_dir / "original" / "notepad.exe",
                project_dir / "src" / "NP" / "functions.txt",
            )
            env = {
                **os.environ,
                "REPORTAL_DB": str(workspace / "reportal.db"),
                "REPORTAL_REBREW": str(smoke_spa.sibling(smoke_spa.REBREW_RELATIVE)),
            }
            server, base_url = start_server(workspace, env)

        violations = _audit_routes(browser, base_url, viewports, themes, ids)
    except (CdpError, RuntimeError, KeyError, OSError) as error:
        emit(f"audit failed: {error}")
        return EXIT_FAIL
    finally:
        if server is not None:
            smoke_spa.stop_server(server)
            shutil.rmtree(workspace, ignore_errors=True)

    renders = len(smoke_spa.ROUTE_CHECKS) * len(viewports) * len(themes)
    summary = f"audit: {renders} route render(s), {len(violations)} violation(s)"
    if args.json:
        sys.stdout.write(
            json.dumps(
                {
                    "base_url": base_url,
                    "viewports": [f"{width}x{height}" for width, height in viewports],
                    "themes": list(themes),
                    "renders": renders,
                    "violations": violations,
                    "summary": summary,
                },
                indent=2,
            )
            + "\n"
        )
    else:
        _print_report(violations)
        emit(summary)
    return EXIT_OK if not violations else EXIT_FAIL


def _missing_prerequisites() -> Path | None:
    """Return the first missing sibling path the seeded audit needs."""
    project_dir = smoke_spa.sibling(smoke_spa.NOTEPAD_PROJECT_RELATIVE)
    for required in (
        smoke_spa.sibling(smoke_spa.REBREW_RELATIVE),
        project_dir / "original" / "notepad.exe",
        project_dir / "src" / "NP" / "functions.txt",
    ):
        if not required.is_file():
            return required
    return None


def _audit_routes(
    browser: str,
    base_url: str,
    viewports: tuple[tuple[int, int], ...],
    themes: tuple[str, ...],
    ids: dict[str, int],
) -> list[dict[str, str]]:
    """Render every smoke route at every viewport/theme and collect violations."""
    violations: list[dict[str, str]] = []
    scratch = _REPO_ROOT / ".scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    with (
        tempfile.TemporaryDirectory(dir=scratch, prefix="audit-chrome-") as profile,
        browser_session(browser, Path(profile)) as (cdp, session_id),
    ):
        index = 0
        for label, route, _markers in smoke_spa.ROUTE_CHECKS:
            path = route.format(**ids)
            for theme in themes:
                for width, height in viewports:
                    index += 1
                    found = audit_route(
                        cdp, session_id, base_url, path, width, height, theme, index
                    )
                    for violation in found:
                        violations.append(
                            {
                                "route": label,
                                "url": path,
                                "viewport": f"{width}x{height}",
                                "theme": theme,
                                "kind": str(violation.get("kind", "unknown")),
                                "selector": str(violation.get("selector", "?")),
                                "detail": str(violation.get("detail", "")),
                            }
                        )
    return violations


def _print_report(violations: list[dict[str, str]]) -> None:
    """Print the violations grouped by route, viewport and theme."""
    if not violations:
        return
    current = None
    for violation in violations:
        heading = (violation["route"], violation["viewport"], violation["theme"])
        if heading != current:
            current = heading
            emit(f"[FAIL] {violation['route']} at {violation['viewport']} ({violation['theme']})")
        emit(f"       {violation['kind']}: {violation['selector']}  {violation['detail']}")


if __name__ == "__main__":
    sys.exit(main())
