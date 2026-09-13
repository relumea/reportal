"""cdp.py — headless-Chrome rendering over the DevTools protocol, shared by the gates.

``tools/smoke_spa.py`` and ``tools/audit_ui.py`` both drive headless Chrome, and
they need the same two things: a browser launched with a DevTools pipe (no
websocket dependency) and a way to know when a hash route has actually rendered.
This module is that shared piece; it knows nothing about routes, markers or the
audit's checks.

The marker wait is the reason it exists.  ``--dump-dom`` with a
``--virtual-time-budget`` is a *cap on how far ahead the page's timers run*, not
a wait for a pending fetch, so a route whose data arrives later than the cap
dumps without it: that is what made ``tools/smoke_spa.py`` flake on a first run
and pass on a re-run.  :func:`render` waits for the app shell the same way the
audit always did, and a caller that needs page content polls for it with
:func:`evaluate` until a deadline, so the wait is on the content that has to be
there rather than on a timer budget.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import signal
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

# Chrome and the render settle.  The settle is bounded and polled: the app
# shell and the routed content must mount, and the route's first fetches get a
# grace period after that.
CDP_TIMEOUT_SECONDS = 30.0
RENDER_SETTLE_SECONDS = 2.0
RENDER_POLL_SECONDS = 0.25
RENDER_TIMEOUT_SECONDS = 20.0

# The browser launch: headless, no sandbox, and a dedicated profile under
# .scratch.  Scrollbars are hidden so the layout viewport width the audit's
# overflow check measures is the true content width.
BROWSER_FLAGS = (
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    "--no-first-run",
    "--disable-extensions",
    "--hide-scrollbars",
    "--force-device-scale-factor=1",
    "--remote-debugging-pipe",
)

# The DevTools pipe transport: Chrome reads commands from fd 3 and writes
# replies and events to fd 4.
CDP_READ_FD = 3
CDP_WRITE_FD = 4

# How long a browser process group gets to exit before it is killed.
SERVER_STOP_TIMEOUT_SECONDS = 10


class CdpError(RuntimeError):
    """Raised when the browser's DevTools pipe fails or a command times out."""


class CdpPipe:
    """A minimal DevTools client over Chrome's ``--remote-debugging-pipe``.

    The transport is the browser's fd 3 (input) and fd 4 (output), each message
    a JSON object terminated by a NUL byte.  Only one command is in flight at a
    time, so replies and events are demultiplexed synchronously.
    """

    def __init__(self, browser: str, profile_dir: Path) -> None:
        child_reads, parent_writes = os.pipe()
        parent_reads, child_writes = os.pipe()

        def map_pipe_fds() -> None:
            os.dup2(child_reads, CDP_READ_FD)
            os.dup2(child_writes, CDP_WRITE_FD)

        self._proc = subprocess.Popen(
            [browser, *BROWSER_FLAGS, f"--user-data-dir={profile_dir}", "about:blank"],
            # Chrome reads fd 3 and writes fd 4, so preexec_fn remaps the pipe
            # ends there.  Python closes every descriptor outside pass_fds right
            # after preexec_fn runs, so the target fds are listed too; both are
            # open in this process (they are the pipes just created).
            pass_fds=(child_reads, child_writes, CDP_READ_FD, CDP_WRITE_FD),
            preexec_fn=map_pipe_fds,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        # The parent keeps the far end of each pipe and closes the child's.
        os.close(child_reads)
        os.close(child_writes)
        self._to_browser = parent_writes
        self._from_browser = parent_reads
        self._buffer = b""
        self._events: dict[tuple[str | None, str], list[dict[str, Any]]] = {}
        self._next_id = 1

    def close(self) -> None:
        """Terminate the browser's process group and close the pipe."""
        with contextlib.suppress(ProcessLookupError):
            os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
        try:
            self._proc.wait(timeout=SERVER_STOP_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
            self._proc.wait(timeout=SERVER_STOP_TIMEOUT_SECONDS)
        with contextlib.suppress(OSError):
            os.close(self._to_browser)
        with contextlib.suppress(OSError):
            os.close(self._from_browser)

    def send(
        self, method: str, params: dict[str, Any] | None = None, session_id: str | None = None
    ) -> dict[str, Any]:
        """Run one CDP command and return its result object."""
        message: dict[str, Any] = {"id": self._next_id, "method": method, "params": params or {}}
        if session_id is not None:
            message["sessionId"] = session_id
        self._next_id += 1
        os.write(self._to_browser, json.dumps(message).encode("utf-8") + b"\0")
        deadline = time.monotonic() + CDP_TIMEOUT_SECONDS
        while True:
            event = self._read_message(deadline - time.monotonic())
            if event is None:
                raise CdpError(f"{method}: timed out waiting for the browser")
            if event.get("id") == message["id"]:
                if "error" in event:
                    raise CdpError(f"{method}: {event['error']}")
                return event.get("result", {})
            if "method" in event:
                key = (event.get("sessionId"), event["method"])
                self._events.setdefault(key, []).append(event)

    def events(self, session_id: str, method: str) -> list[dict[str, Any]]:
        """Every event of *method* seen for *session_id* so far."""
        return list(self._events.get((session_id, method), []))

    def wait_for_event(self, method: str, session_id: str, timeout: float) -> None:
        """Wait for one protocol event, dropping any that arrive first."""
        key = (session_id, method)
        deadline = time.monotonic() + timeout
        if self._events.get(key):
            self._events[key].pop(0)
            return
        while True:
            event = self._read_message(deadline - time.monotonic())
            if event is None:
                raise CdpError(f"{method}: timed out waiting for the event")
            if (
                "method" in event
                and event.get("sessionId") == session_id
                and event["method"] == method
            ):
                return
            if "method" in event:
                self._events.setdefault((event.get("sessionId"), event["method"]), []).append(event)

    def _read_message(self, timeout: float) -> dict[str, Any] | None:
        if timeout <= 0:
            return None
        deadline = time.monotonic() + timeout
        while True:
            while b"\0" in self._buffer:
                raw, self._buffer = self._buffer.split(b"\0", 1)
                if raw.strip():
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict):
                        return parsed
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([self._from_browser], [], [], remaining)
            if not ready:
                return None
            try:
                chunk = os.read(self._from_browser, 1 << 16)
            except OSError as error:
                raise CdpError(f"reading the DevTools pipe failed: {error}") from error
            if not chunk:
                raise CdpError("the browser closed the DevTools pipe")
            self._buffer += chunk


@contextlib.contextmanager
def browser_session(browser: str, profile_dir: Path) -> Iterator[tuple[CdpPipe, str]]:
    """Yield a connected ``CdpPipe`` with one attached page target."""
    cdp = CdpPipe(browser, profile_dir)
    try:
        target = cdp.send("Target.createTarget", {"url": "about:blank"})
        target_id = target["targetId"]
        attached = cdp.send("Target.attachToTarget", {"targetId": target_id, "flatten": True})
        session_id = attached["sessionId"]
        cdp.send("Page.enable", session_id=session_id)
        cdp.send("Runtime.enable", session_id=session_id)
        cdp.send("Network.enable", session_id=session_id)
        yield cdp, session_id
    finally:
        cdp.close()


def render(cdp: CdpPipe, session_id: str, url: str, width: int, height: int) -> None:
    """Navigate to *url* at the given viewport and wait for the SPA to settle.

    The settle waits for the app shell and the routed content to mount, then
    holds for ``RENDER_SETTLE_SECONDS`` while the route's fetches resolve.  It
    cannot wait for every spinner to disappear: the binary detail view carries
    lazy panels whose skeleton is their idle placeholder until a button asks.
    A caller that needs specific content present must poll for it after this
    returns, because a fetch that has not resolved yet is not this call's
    business to guess at.
    """
    cdp.send(
        "Emulation.setDeviceMetricsOverride",
        {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": False},
        session_id=session_id,
    )
    cdp.send("Page.navigate", {"url": url}, session_id=session_id)
    cdp.wait_for_event("Page.loadEventFired", session_id, RENDER_TIMEOUT_SECONDS)
    deadline = time.monotonic() + RENDER_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        state = evaluate(
            cdp,
            session_id,
            "document.readyState === 'complete' && document.getElementById('content') !== null",
        )
        if state is True:
            time.sleep(RENDER_SETTLE_SECONDS)
            return
        time.sleep(RENDER_POLL_SECONDS)
    raise CdpError(f"the SPA never settled rendering {url}")


# Substrings of Chromium's own console chatter for a response the app already
# handles.  A stored-only read answers 404 with a documented empty-result code
# and the panel renders its nothing-stored hint, but Chromium still logs the
# rejected fetch; the smoke treats that as the app working, not as a defect.
BENIGN_CONSOLE_MESSAGES = (
    "the server responded with a status of 404",
    "Failed to load resource: net::ERR_ABORTED",
)

# Request failures the browser reports for a navigation it cancelled itself.
BENIGN_LOAD_ERRORS = ("net::ERR_ABORTED",)


def page_errors(cdp: CdpPipe, session_id: str) -> list[str]:
    """The page's uncaught errors, error-level console lines and failed requests.

    This is the guard the SPA gate needs to make "the route rendered" mean more
    than "the DOM had a marker": an error note the app drew from a 500, an
    uncaught rejection or a dropped request is a defect the marker check alone
    would pass.  Benign browser chatter for a response the app handles (a
    stored-only 404, a navigation the page replaced) is filtered out.
    """
    found: list[str] = []
    for event in cdp.events(session_id, "Runtime.exceptionThrown"):
        details = event.get("params", {}).get("exceptionDetails", {})
        text = details.get("exception", {}).get("description") or details.get("text", "")
        found.append(f"page error: {str(text).splitlines()[0]}")
    for event in cdp.events(session_id, "Runtime.consoleAPICalled"):
        params = event.get("params", {})
        if params.get("type") != "error":
            continue
        text = " ".join(str(arg.get("value")) for arg in params.get("args", []) if "value" in arg)
        if any(benign in text for benign in BENIGN_CONSOLE_MESSAGES):
            continue
        found.append(f"console error: {text or params.get('type')}")
    for event in cdp.events(session_id, "Network.loadingFailed"):
        params = event.get("params", {})
        if params.get("canceled") or any(
            benign in str(params.get("errorText", "")) for benign in BENIGN_LOAD_ERRORS
        ):
            continue
        found.append(f"request failed: {params.get('errorText', 'unknown')}")
    return found


def evaluate(cdp: CdpPipe, session_id: str, expression: str) -> Any:
    """Evaluate one expression in the page and return its value."""
    result = cdp.send(
        "Runtime.evaluate",
        {"expression": expression, "returnByValue": True, "awaitPromise": False},
        session_id=session_id,
    )
    if result.get("exceptionDetails"):
        raise CdpError(f"page evaluation failed: {result['exceptionDetails']}")
    return result.get("result", {}).get("value")


def document_html(cdp: CdpPipe, session_id: str) -> str:
    """The page's current document markup, for a caller that checks markers."""
    value = evaluate(cdp, session_id, "document.documentElement.outerHTML")
    return value if isinstance(value, str) else ""
