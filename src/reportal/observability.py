"""Process-local request correlation and HTTP/job counters for the serving path.

uvicorn's access log is off (``server.run``), so the middleware records what an
operator needs from journalctl: a request id on every ``/api`` response, a
structured completion line when the call is interesting, and a cheap counter
snapshot ``GET /api/health`` exposes.  Background jobs store that request id at
submit and feed the same health payload with done/failed counts and latency, so
a queue that is failing is visible without scraping SQLite and a pool-thread
failure still greps back to the submit request.  No remote collector and no new
dependency: the signals an incident needs (did it succeed, how long, which
request, recent error rate, job queue health) stay in one process.
"""

from __future__ import annotations

import re
import threading
import uuid
from contextvars import ContextVar
from typing import Any

# Header clients may send and every ``/api`` response echoes.  Kept ASCII and
# bounded so a forged value cannot break a log line or a journal parser.
REQUEST_ID_HEADER = "X-Request-Id"
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Paths the SPA and supervisors poll; metrics still count them, completion
# lines at INFO would drown real work.
_QUIET_API_PREFIXES: tuple[str, ...] = ("/api/health", "/api/doctor")

# A completion slower than this is logged even on a quiet path.
SLOW_REQUEST_MS = 5_000

# A finished job slower than this gets a completion line even when it succeeded;
# shorter successes stay silent so a busy queue does not drown journalctl.
SLOW_JOB_MS = 60_000

_request_id: ContextVar[str] = ContextVar("reportal_request_id", default="")

_lock = threading.Lock()
_requests = 0
_errors_4xx = 0
_errors_5xx = 0
_duration_ms_sum = 0
_duration_ms_max = 0

_jobs_done = 0
_jobs_failed = 0
_jobs_duration_ms_sum = 0
_jobs_duration_ms_max = 0


def current_request_id() -> str:
    """The id of the request this thread is serving, or ``\"\"`` outside one."""
    return _request_id.get()


def set_request_id(value: str) -> Any:
    """Bind *value* for the current context; returns the token to reset."""
    return _request_id.set(value)


def reset_request_id(token: Any) -> None:
    """Restore the previous request id after a middleware scope ends."""
    _request_id.reset(token)


# Entropy source for minted request ids.  A test patches ``_mint_request_id``
# to pin the id a missing or forged header resolves to.
def _mint_request_id() -> str:
    return uuid.uuid4().hex


def resolve_request_id(raw: str | None) -> str:
    """Accept a well-formed client id, otherwise mint one."""
    candidate = (raw or "").strip()
    if candidate and _REQUEST_ID_RE.fullmatch(candidate):
        return candidate
    return _mint_request_id()


def record_request(*, status: int, duration_ms: int) -> None:
    """Accumulate one finished ``/api`` request into the process counters."""
    global _requests, _errors_4xx, _errors_5xx, _duration_ms_sum, _duration_ms_max
    elapsed = max(0, int(duration_ms))
    with _lock:
        _requests += 1
        _duration_ms_sum += elapsed
        if elapsed > _duration_ms_max:
            _duration_ms_max = elapsed
        if 400 <= status < 500:
            _errors_4xx += 1
        elif status >= 500:
            _errors_5xx += 1


def http_snapshot() -> dict[str, int]:
    """Counters since process start; cheap enough for ``GET /api/health``."""
    with _lock:
        return {
            "requests": _requests,
            "errors_4xx": _errors_4xx,
            "errors_5xx": _errors_5xx,
            "duration_ms_sum": _duration_ms_sum,
            "duration_ms_max": _duration_ms_max,
        }


def reset_http_stats() -> None:
    """Drop the counters; tests call this so one case does not leak into the next."""
    global _requests, _errors_4xx, _errors_5xx, _duration_ms_sum, _duration_ms_max
    with _lock:
        _requests = 0
        _errors_4xx = 0
        _errors_5xx = 0
        _duration_ms_sum = 0
        _duration_ms_max = 0


def record_job(*, failed: bool, duration_ms: int) -> None:
    """Accumulate one finished background job into the process counters."""
    global _jobs_done, _jobs_failed, _jobs_duration_ms_sum, _jobs_duration_ms_max
    elapsed = max(0, int(duration_ms))
    with _lock:
        if failed:
            _jobs_failed += 1
        else:
            _jobs_done += 1
        _jobs_duration_ms_sum += elapsed
        if elapsed > _jobs_duration_ms_max:
            _jobs_duration_ms_max = elapsed


def job_snapshot() -> dict[str, int]:
    """Job counters since process start; cheap enough for ``GET /api/health``."""
    with _lock:
        return {
            "done": _jobs_done,
            "failed": _jobs_failed,
            "duration_ms_sum": _jobs_duration_ms_sum,
            "duration_ms_max": _jobs_duration_ms_max,
        }


def reset_job_stats() -> None:
    """Drop the job counters; tests call this so one case does not leak into the next."""
    global _jobs_done, _jobs_failed, _jobs_duration_ms_sum, _jobs_duration_ms_max
    with _lock:
        _jobs_done = 0
        _jobs_failed = 0
        _jobs_duration_ms_sum = 0
        _jobs_duration_ms_max = 0


def should_log_completion(*, path: str, status: int, duration_ms: int) -> bool:
    """True when a structured completion line is worth emitting."""
    if status >= 400 or duration_ms >= SLOW_REQUEST_MS:
        return True
    return not any(
        path == prefix or path.startswith(prefix + "/") for prefix in _QUIET_API_PREFIXES
    )


def configure_logging() -> None:
    """Raise the ``reportal`` logger to INFO so request lines reach journalctl.

    ``server.run`` keeps uvicorn at ``warning`` with access logging off; without
    this the structured completion lines would be silent under the root default.
    """
    import logging

    logging.getLogger("reportal").setLevel(logging.INFO)
