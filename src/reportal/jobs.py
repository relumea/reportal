"""The asynchronous operation workflow: queued jobs with a status and a cancel.

The hosted portal queues every long-running capability and answers a run id, so
a client polls a status instead of holding a request open.  reportal's scans ran
synchronously in the request that asked for them: the client waited, a timeout
lost the run, and nothing recorded that the run had happened.  This module is
the local equivalent, deliberately small:

- one ``jobs`` table holds a job's kind, its target, its status, its progress
  and its result or error;
- :data:`JOB_KINDS` names the operations that may be queued, each a thin
  wrapper over the scan runner the matching route already calls, wrapped in the
  same ``journal.journaled_scan`` the route uses, so a queued scan is journaled
  and revertible exactly like a synchronous one;
- :func:`submit` queues one, :func:`queue_stored_scans` maps stored scans onto
  those kinds, :func:`run_pending` executes the oldest queued job,
  and the bounded background pool (:func:`ensure_worker`) is what runs them in a
  serving process, so a route can answer with a run id at once;
- :func:`events` renders a job's state as server-sent events, so a client can
  follow a run instead of polling it.

Two ceilings are deliberate and stated rather than hidden.  A job is one step
today (``steps_total`` is 1 and ``progress`` is 0 or 100): the engine calls a
scan makes are not interruptible, so there is nothing finer to report.  And
cancelling a ``running`` job is refused rather than faked: the scan has already
entered the engine and cannot be stopped, so the caller may cancel only what has
not started (a ``queued`` job), which is the honest half of the hosted contract.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, replace
from typing import Any, Protocol

from reportal import (
    _paths,
    behavior,
    binary_actions,
    capabilities,
    composition,
    engines,
    families,
    filetypes,
    firmware,
    flirt_sigs,
    function_triage,
    gobuildinfo,
    hardening,
    journal,
    library,
    lineage,
    llm,
    matching,
    observability,
    pdf,
    pipeline,
    protocols,
    related,
    remediation,
    secrets,
    similarity,
    store,
    threat,
    unpack,
    unstrip,
)
from reportal._paths import WorkspaceNotFound

_log = logging.getLogger(__name__)
# Statuses a job moves through.  ``queued`` and ``running`` are the live ones;
# the other three are terminal and never change again.
STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
LIVE_STATUSES: tuple[str, ...] = (STATUS_QUEUED, STATUS_RUNNING)
STATUSES: tuple[str, ...] = (
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_CANCELLED,
)

# The table, and the bounds a reader or a submitter is held to.
TABLE = "jobs"
DEFAULT_JOB_LIMIT = 50
MAX_JOB_LIMIT = 500
MAX_QUEUED_JOBS = 100
# Terminal rows kept per submit; the oldest are pruned, so the table is a
# bounded operational log rather than an unbounded one.
MAX_KEPT_JOBS = 500
# Same default the structs HTTP route uses (`api.DEFAULT_STRUCT_LIMIT`).
DEFAULT_STRUCT_LIMIT = 50

# The background pool: how many jobs run at once, and how often an idle worker
# looks for one.
MAX_WORKERS = 2
POLL_SECONDS = 0.25
# Cap how often a wedged worker re-logs the same class of tick failure, so a
# missing database cannot flood journalctl every POLL_SECONDS.
WORKER_ERROR_LOG_SECONDS = 30.0

# The event stream's poll interval and its cap, so a stream always ends.
STREAM_INTERVAL_SECONDS = 0.5
STREAM_MAX_SECONDS = 30.0

# Sleep and monotonic clock for the SSE loop and worker error throttle.  A test
# patches ``_sleep`` to skip real waits and ``_monotonic`` to pin deadlines.
_sleep = time.sleep
_monotonic = time.monotonic

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {TABLE} (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    binary_id   INTEGER REFERENCES binaries(id) ON DELETE CASCADE,
    status      TEXT NOT NULL,
    progress    INTEGER NOT NULL DEFAULT 0,
    steps_total INTEGER NOT NULL DEFAULT 1,
    message     TEXT NOT NULL DEFAULT '',
    params_json TEXT NOT NULL DEFAULT '{{}}',
    result_json TEXT NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    started_at  TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    submitted_by TEXT NOT NULL DEFAULT '',
    submitted_by_user_id INTEGER,
    request_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON {TABLE}(status, id);
CREATE INDEX IF NOT EXISTS idx_jobs_binary ON {TABLE}(binary_id);
"""


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the jobs table when the database predates it."""
    conn.executescript(_SCHEMA)
    columns = {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({TABLE})")}
    if "submitted_by" not in columns:
        conn.execute(f"ALTER TABLE {TABLE} ADD COLUMN submitted_by TEXT NOT NULL DEFAULT ''")
    if "submitted_by_user_id" not in columns:
        conn.execute(f"ALTER TABLE {TABLE} ADD COLUMN submitted_by_user_id INTEGER")
    if "request_id" not in columns:
        conn.execute(f"ALTER TABLE {TABLE} ADD COLUMN request_id TEXT NOT NULL DEFAULT ''")
    conn.commit()


class ProgressPerform(Protocol):
    """A `perform` that also takes the runner's step sink."""

    def __call__(
        self,
        conn: sqlite3.Connection,
        binary_id: int,
        params: Mapping[str, Any],
        *,
        progress: Callable[[int, int], None] | None = None,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class JobKind:
    """One queued operation: what it is called and how it runs.

    ``run`` takes the connection, the target binary and the submitted params,
    and returns the payload the same operation's synchronous route would answer.
    ``scan_kind`` is the ``scans`` row the run stores (``None`` for an operation
    that stores something else), which is what the runner journals.
    """

    name: str
    label: str
    scan_kinds: str | Mapping[str, str] | None
    run: Callable[[sqlite3.Connection, int, Mapping[str, Any]], dict[str, Any]]
    params: tuple[str, ...] = ()
    # A kind whose write is not a scan row (a generated file) does its own
    # journaling through this, and the runner calls it instead of wrapping the
    # run in `journaled_scan`.
    perform: Callable[[sqlite3.Connection, int, Mapping[str, Any]], dict[str, Any]] | None = None
    # A kind that can report its own steps sets this instead of `perform`: the
    # runner passes a `progress(done, total)` sink that writes the job's row as
    # the run goes.  Every other kind is one step, because its engine calls are
    # not interruptible and there is nothing finer to report.
    perform_progress: ProgressPerform | None = None

    def scan_kind_for(self, params: Mapping[str, Any]) -> str | None:
        """The ``scans`` kind this job stores, or None when it stores another row."""
        if self.scan_kinds is None:
            return None
        if isinstance(self.scan_kinds, str):
            return self.scan_kinds
        return self.scan_kinds[_domain_of(params, tuple(self.scan_kinds), f"{self.name} domain")]


def _domain_of(params: Mapping[str, Any], domains: tuple[str, ...], what: str) -> str:
    """The domain a behavior or hardening job names, defaulting to the first."""
    domain = str(params.get("domain") or domains[0])
    if domain not in domains:
        raise ValueError(f"unknown {what} domain: {domain}; expected one of {', '.join(domains)}")
    return domain


def _is_int(value: Any) -> bool:
    """True for a real integer, false for a bool or a non-integer number."""
    return isinstance(value, int) and not isinstance(value, bool)


def _perform_match(
    conn: sqlite3.Connection,
    binary_id: int,
    params: Mapping[str, Any],
    *,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Run one binary's match, journaled the way its route runs it.

    The settings come from the job's params, so a queued run records the same
    rows a direct one would; ``matching.journaled_match`` snapshots and journals
    them, which is why this kind declares ``perform`` rather than a scan kind.
    *progress* is the runner's sink: a match run scores one source function at a
    time, so it is the one kind with steps to report.
    """
    settings = matching.MatchSettings.from_request(dict(params))
    return matching.journaled_match(
        conn,
        binary_id=binary_id,
        settings=settings,
        engine=engines.get_engine(),
        progress=progress,
    )


def _perform_enrich(
    conn: sqlite3.Connection,
    binary_id: int,
    params: Mapping[str, Any],
    *,
    progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Run the AI enrichment chain over a binary's functions, one run each.

    The whole-binary form of the per-function pipeline is a job rather than a
    route: every function costs a model call per LLM stage, so the caller
    queues it and polls instead of holding a request open for minutes.

    Each function gets its own pipeline run, which is the batch's own design,
    so one function failing leaves the rest intact and an analyst can revert
    one function's artifacts without touching the others.  *progress* reports
    the function count, the only granularity that exists: one function is
    several model calls and none of them is interruptible.
    """
    raw_ids = params.get("function_ids")
    function_ids = [int(value) for value in raw_ids] if isinstance(raw_ids, list) else None
    return pipeline.run_pipeline_batch(
        conn,
        binary_id=binary_id,
        limit=int(params.get("limit") or pipeline.DEFAULT_BATCH_LIMIT),
        function_ids=function_ids,
        progress=progress,
    )


def _engine_report(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """Run the engine's report into the workspace report directory.

    The engine call needs the binary's rebrew project context, which a binary
    imported without one does not have; that is a failed job carrying the
    reason rather than a job that never ran.
    """
    project_dir = store.get_rebrew_context(conn, binary_id)
    if project_dir is None:
        raise ValueError(f"binary {binary_id} has no rebrew project context")
    return engines.get_engine().report(project_dir, _paths.reports_dir(binary_id))


def _perform_pe_info(
    conn: sqlite3.Connection, binary_id: int, _params: Mapping[str, Any]
) -> dict[str, Any]:
    """Run the engine's PE metadata scan and store it, journaled like its route."""
    _binary, path = capabilities.require_binary_file(conn, binary_id)
    result = engines.get_engine().pe_info(path)
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_PE_INFO, result)
    return log.attach(result)


def _perform_triage(
    conn: sqlite3.Connection, binary_id: int, _params: Mapping[str, Any]
) -> dict[str, Any]:
    """Run the engine's one-shot dossier and store it, journaled like its route."""
    _binary, path = capabilities.require_binary_file(conn, binary_id)
    dossier = engines.get_engine().analyze(path)
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_TRIAGE, dossier)
    return log.attach(dossier)


def _perform_crypto(
    conn: sqlite3.Connection, binary_id: int, _params: Mapping[str, Any]
) -> dict[str, Any]:
    """Run the engine's crypto scan and store it, journaled like its route."""
    _binary, path = capabilities.require_binary_file(conn, binary_id)
    result = engines.get_engine().crypto_scan(path)
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        journal.journaled_scan_result(conn, log, binary_id, store.SCAN_KIND_CRYPTO, result)
    return log.attach(result)


def _perform_firmware(
    conn: sqlite3.Connection, binary_id: int, _params: Mapping[str, Any]
) -> dict[str, Any]:
    """Carve a stored firmware image and store it, journaled like its route."""
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        payload = journal.journaled_scan(
            conn,
            log,
            binary_id,
            store.SCAN_KIND_FIRMWARE,
            lambda: firmware.scan(conn, binary_id),
            engine="firmware",
        )
    return log.attach(payload)


def _run_library(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Identify library functions and store the reading."""
    raw = params.get("min_confidence")
    confidence = library.DEFAULT_MIN_CONFIDENCE if raw is None else float(raw)
    return library.run_library(
        conn,
        binary_id=binary_id,
        engine=engines.get_engine(),
        min_confidence=confidence,
    )


def _perform_security(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Run the engine's security scan and store it, journaled like its route."""
    project_dir = store.get_rebrew_context(conn, binary_id)
    if project_dir is None:
        raise ValueError(f"binary {binary_id} has no rebrew project context")
    min_severity = str(params.get("min_severity") or engines.DEFAULT_SECURITY_MIN_SEVERITY)
    result = engines.get_engine().security_scan(project_dir, min_severity)
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        journal.journaled_scan_result(
            conn,
            log,
            binary_id,
            store.SCAN_KIND_SECURITY,
            result,
            params={"min_severity": min_severity},
        )
    return log.attach(result)


def _run_threat(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Build a local threat report and store it."""
    return threat.build_threat_report(
        conn,
        binary_id=binary_id,
        engine=engines.get_engine(),
        narrative=bool(params.get("narrative")),
    )


def _perform_structs(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Recover structs through the engine and store them, journaled like the route."""
    project_dir = store.get_rebrew_context(conn, binary_id)
    if project_dir is None:
        raise ValueError(f"binary {binary_id} has no rebrew project context")
    decompiler = str(params.get("decompiler") or engines.DEFAULT_DECOMPILER_BACKEND)
    raw_limit = params.get("limit")
    limit = DEFAULT_STRUCT_LIMIT if raw_limit is None else int(raw_limit)
    result = engines.get_engine().structs(project_dir, decompiler=decompiler, limit=limit)
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        journal.journaled_scan_result(
            conn,
            log,
            binary_id,
            store.SCAN_KIND_STRUCTS,
            result,
            params={"decompiler": decompiler, "limit": limit},
        )
    return log.attach(result)


def _run_detect(
    conn: sqlite3.Connection, binary_id: int, _params: Mapping[str, Any]
) -> dict[str, Any]:
    """Match a binary against registered families and store the reading."""
    return families.detect_binary(conn, binary_id=binary_id, engine=engines.get_engine())


def _run_gobuildinfo(
    conn: sqlite3.Connection, binary_id: int, _params: Mapping[str, Any]
) -> dict[str, Any]:
    """Recover Go build information and store it."""
    return gobuildinfo.recover(conn, binary_id=binary_id)


def _run_flirt(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Match the binary against the enabled FLIRT signatures and store it.

    Queued like any other scan: matching reads the whole binary, and an
    install whose catalog covers a whole toolchain should not hold a request
    open for it.
    """
    return flirt_sigs.run_flirt(conn, binary_id=binary_id, arch=str(params.get("arch") or ""))


def _run_remediation(
    conn: sqlite3.Connection, binary_id: int, _params: Mapping[str, Any]
) -> dict[str, Any]:
    """Generate YARA, Snort and STIX artifacts and store them."""
    return remediation.build_remediation(conn, binary_id=binary_id, engine=engines.get_engine())


def _run_function_triage(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Summarize selected functions and store the aggregate."""
    raw_ids = params.get("function_ids")
    function_ids = [int(value) for value in raw_ids] if isinstance(raw_ids, list) else None
    raw_limit = params.get("limit")
    limit = function_triage.DEFAULT_LIMIT if raw_limit is None else int(raw_limit)
    return function_triage.summarize_functions(
        conn,
        binary_id=binary_id,
        function_ids=function_ids,
        limit=limit,
        client=llm.get_client(),
        engine=engines.get_engine(),
    )


def _run_related(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Rank related binaries and store the reading."""
    raw_limit = params.get("limit")
    limit = related.DEFAULT_LIMIT if raw_limit is None else int(raw_limit)
    return related.find_related(
        conn,
        binary_id=binary_id,
        engine=engines.get_engine(),
        limit=limit,
        include_unrelated=bool(params.get("include_unrelated")),
    )


def _run_lineage(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Replay stored lineage pairs, or one named partner."""
    raw_other = params.get("other_binary_id")
    if raw_other is not None:
        partners = [int(raw_other)]
    else:
        partners = [
            int(row["right_binary_id"]) for row in lineage.stored_comparisons(conn, binary_id)
        ]
    if not partners:
        raise ValueError(f"binary {binary_id} has no stored lineage comparison")
    refine = True if params.get("refine") is None else bool(params.get("refine"))
    last: dict[str, Any] = {}
    for other_id in partners:
        comparison = lineage.compare_binaries(
            conn,
            left_binary_id=binary_id,
            right_binary_id=other_id,
            engine=engines.get_engine(),
            refine=refine,
        )
        lineage.store_comparison(conn, comparison)
        last = comparison
    return last


def _perform_lineage(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Replay lineage pairs and journal the scan the way the route does."""
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        payload = journal.journaled_scan(
            conn,
            log,
            binary_id,
            store.SCAN_KIND_LINEAGE,
            lambda: _run_lineage(conn, binary_id, params),
        )
    return log.attach(payload)


def _perform_benchmark(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Score a match run against known counterparts and store it."""
    from reportal import benchmark

    right_binary_id = int(params["right_binary_id"])
    settings = matching.MatchSettings.from_request(
        {key: value for key, value in params.items() if key != "right_binary_id"}
    )
    settings = replace(settings, binary_ids=(right_binary_id,), include_self=False)
    result = benchmark.run(
        conn,
        left_binary_id=binary_id,
        right_binary_id=right_binary_id,
        engine=engines.get_engine(),
        settings=settings,
    )
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        journal.journaled_scan_result(
            conn,
            log,
            binary_id,
            store.SCAN_KIND_BENCHMARK,
            result,
            params={"right_binary_id": right_binary_id, **settings.payload()},
        )
    return log.attach(result)


def _perform_unpack(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Rebuild a packed image as a new binary. Requeue never maps onto this."""
    try:
        return binary_actions.unpack_binary(
            conn,
            binary_id,
            packer=str(params.get("packer") or ""),
            name=str(params.get("name") or ""),
        )
    except binary_actions.ExtractError as exc:
        raise ValueError(exc.detail) from exc


def render_pdf(
    conn: sqlite3.Connection, binary_id: int, params: Mapping[str, Any]
) -> dict[str, Any]:
    """Render the binary's PDF into one journaled action.

    The route, the CLI and the queued job all call this, so the file is written
    and journaled once, in one place: a queued report is revertible through the
    journal the same way a direct one is.
    """
    target = _paths.reports_dir(binary_id) / pdf.REPORT_PDF_NAME
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        previous = journal.read_bounded(target) if target.is_file() else None
        result = pdf.write_report(conn, binary_id=binary_id, path=target, generated=store.now())
        journal.journaled_file(log, target, previous=previous)
    return log.attach(result)


def builtin_kinds() -> tuple[JobKind, ...]:
    """The operations that may be queued, in registry order."""
    return (
        JobKind(
            name="filetype",
            label="File type, packer and protector detection",
            scan_kinds=store.SCAN_KIND_FILETYPE,
            run=lambda conn, binary_id, params: filetypes.run_filetype(
                conn, binary_id=binary_id, engine=engines.get_engine()
            ),
        ),
        JobKind(
            name="pe-info",
            label="PE identity, sections and security metadata",
            scan_kinds=store.SCAN_KIND_PE_INFO,
            run=_perform_pe_info,
            perform=_perform_pe_info,
        ),
        JobKind(
            name="triage",
            label="One-shot engine dossier",
            scan_kinds=store.SCAN_KIND_TRIAGE,
            run=_perform_triage,
            perform=_perform_triage,
        ),
        JobKind(
            name="capabilities",
            label="Capability classification",
            scan_kinds=store.SCAN_KIND_CAPABILITIES,
            run=lambda conn, binary_id, params: capabilities.run_capabilities(
                conn, binary_id=binary_id, engine=engines.get_engine()
            ),
        ),
        JobKind(
            name="secrets",
            label="Secrets and high-entropy value scan",
            scan_kinds=store.SCAN_KIND_SECRETS,
            run=lambda conn, binary_id, params: secrets.run_secrets(
                conn, binary_id=binary_id, engine=engines.get_engine()
            ),
        ),
        JobKind(
            name="protocols",
            label="Protocol inference",
            scan_kinds=store.SCAN_KIND_PROTOCOLS,
            run=lambda conn, binary_id, params: protocols.scan_protocols(
                conn, binary_id=binary_id, engine=engines.get_engine()
            ),
        ),
        JobKind(
            name="composition",
            label="Composition against the stored matches",
            scan_kinds=store.SCAN_KIND_COMPOSITION,
            run=lambda conn, binary_id, params: composition.run_composition(
                conn, binary_id=binary_id
            ),
        ),
        JobKind(
            name="report",
            label="Engine report over the reversed sources",
            scan_kinds=store.SCAN_KIND_REPORT,
            run=lambda conn, binary_id, params: _engine_report(conn, binary_id),
        ),
        JobKind(
            name="report-pdf",
            label="PDF report over the stored scans",
            scan_kinds=None,
            run=render_pdf,
            perform=render_pdf,
        ),
        JobKind(
            name="unstrip",
            label="Auto-unstrip identification proposals",
            scan_kinds=store.SCAN_KIND_UNSTRIP,
            run=lambda conn, binary_id, params: unstrip.run_unstrip(
                conn, binary_id=binary_id, engine=engines.get_engine()
            ),
        ),
        JobKind(
            name="crypto",
            label="Crypto constants and API scan",
            scan_kinds=store.SCAN_KIND_CRYPTO,
            run=_perform_crypto,
            perform=_perform_crypto,
        ),
        JobKind(
            name="library",
            label="Library identification",
            scan_kinds=store.SCAN_KIND_LIBRARY,
            params=("min_confidence",),
            run=_run_library,
        ),
        JobKind(
            name="firmware",
            label="Firmware region carve",
            scan_kinds=store.SCAN_KIND_FIRMWARE,
            run=_perform_firmware,
            perform=_perform_firmware,
        ),
        JobKind(
            name="security",
            label="Security findings over reversed sources",
            scan_kinds=store.SCAN_KIND_SECURITY,
            params=("min_severity",),
            run=_perform_security,
            perform=_perform_security,
        ),
        JobKind(
            name="threat",
            label="Local threat report",
            scan_kinds=store.SCAN_KIND_THREAT,
            params=("narrative",),
            run=_run_threat,
        ),
        JobKind(
            name="structs",
            label="Struct recovery through the engine",
            scan_kinds=store.SCAN_KIND_STRUCTS,
            params=("decompiler", "limit"),
            run=_perform_structs,
            perform=_perform_structs,
        ),
        JobKind(
            name="detect",
            label="Family detection against stored signatures",
            scan_kinds=store.SCAN_KIND_DETECT,
            run=_run_detect,
        ),
        JobKind(
            name="gobuildinfo",
            label="Go build information recovery",
            scan_kinds=store.SCAN_KIND_GOBUILDINFO,
            run=_run_gobuildinfo,
        ),
        JobKind(
            name="remediation",
            label="YARA, Snort and STIX artifacts",
            scan_kinds=store.SCAN_KIND_REMEDIATION,
            run=_run_remediation,
        ),
        JobKind(
            name="flirt",
            label="FLIRT signature matching",
            scan_kinds=store.SCAN_KIND_FLIRT,
            params=("arch",),
            run=_run_flirt,
        ),
        JobKind(
            name="function-triage",
            label="Per-function triage summaries",
            scan_kinds=store.SCAN_KIND_FUNCTION_TRIAGE,
            params=("limit", "function_ids"),
            run=_run_function_triage,
        ),
        JobKind(
            name="related",
            label="Related-binary ranking",
            scan_kinds=store.SCAN_KIND_RELATED,
            params=("limit", "include_unrelated"),
            run=_run_related,
        ),
        JobKind(
            name="lineage",
            label="Pairwise function lineage",
            scan_kinds=store.SCAN_KIND_LINEAGE,
            params=("other_binary_id", "refine"),
            run=_perform_lineage,
            perform=_perform_lineage,
        ),
        JobKind(
            name="benchmark",
            label="Match precision against a labelled partner",
            scan_kinds=store.SCAN_KIND_BENCHMARK,
            params=(
                "right_binary_id",
                "min_similarity",
                "min_confidence",
                "include_self",
                "top",
                "platforms",
                "architectures",
                "binary_ids",
                "collection_ids",
            ),
            run=_perform_benchmark,
            perform=_perform_benchmark,
        ),
        JobKind(
            name="behavior",
            label="Behavior scan of one domain",
            scan_kinds=behavior.DOMAIN_SCAN_KINDS,
            params=("domain",),
            run=lambda conn, binary_id, params: behavior.scan_domain(
                conn,
                binary_id=binary_id,
                domain=_domain_of(params, behavior.BEHAVIOR_DOMAINS, "behavior"),
                engine=engines.get_engine(),
            ),
        ),
        JobKind(
            name="hardening",
            label="Hardening scan of one domain",
            scan_kinds=hardening.DOMAIN_SCAN_KINDS,
            params=("domain",),
            run=lambda conn, binary_id, params: hardening.scan_hardening(
                conn,
                binary_id=binary_id,
                domain=_domain_of(params, hardening.HARDENING_DOMAINS, "hardening"),
                engine=engines.get_engine(),
            ),
        ),
        # Matching is the longest operation the portal runs (it scores every
        # function against the whole corpus), so it is the one a caller is most
        # likely to want in the background rather than inside a request.
        JobKind(
            name="match",
            label="Function matching against the corpus",
            scan_kinds=None,
            params=(
                "min_similarity",
                "min_confidence",
                "include_self",
                "top",
                "platforms",
                "architectures",
                "binary_ids",
                "collection_ids",
            ),
            run=_perform_match,
            perform_progress=_perform_match,
        ),
        # The AI enrichment chain is the one kind that runs a whole composition
        # per function: the model calls are what the caller is queuing for, and
        # a binary's worth of them is a batch, not a request.
        JobKind(
            name="ai-enrich",
            label="AI enrichment chain over a binary's functions",
            scan_kinds=None,
            params=("limit", "function_ids"),
            run=_perform_enrich,
            perform_progress=_perform_enrich,
        ),
        JobKind(
            name="unpack",
            label="Rebuild a packed image as a new binary",
            scan_kinds=None,
            params=("packer", "name"),
            run=_perform_unpack,
            perform=_perform_unpack,
        ),
    )


JOB_KINDS: dict[str, JobKind] = {kind.name: kind for kind in builtin_kinds()}


def job_kind_for_scan(scan_kind: str) -> tuple[str, dict[str, Any]] | None:
    """The job kind that stores *scan_kind*, plus any domain param it needs.

    Scans with no queued runner (unpack, which creates a new binary) return None:
    those stay a per-scan POST, not a background job.
    """
    for spec in JOB_KINDS.values():
        if spec.scan_kinds is None:
            continue
        if isinstance(spec.scan_kinds, str):
            if spec.scan_kinds == scan_kind:
                return spec.name, {}
            continue
        for domain, kind in spec.scan_kinds.items():
            if kind == scan_kind:
                return spec.name, {"domain": domain}
    return None


def queue_stored_scans(
    conn: sqlite3.Connection,
    log: journal.Journal,
    analysis_id: int,
    *,
    submitted_by: str = "",
    submitted_by_user_id: int | None = None,
) -> list[dict[str, Any]]:
    """Queue a job for each stored scan that has a job kind.

    Params the kind does not take are dropped. A scan with no job kind is
    skipped. Live duplicates return the existing row.
    """
    analysis = store.get_analysis(conn, analysis_id)
    if analysis is None:
        return []
    binary_id = int(analysis["binary_id"])
    queued: list[dict[str, Any]] = []
    for scan in store.list_scans(conn, analysis_id):
        mapped = job_kind_for_scan(str(scan["kind"]))
        if mapped is None:
            continue
        kind, extra = mapped
        allowed = set(JOB_KINDS[kind].params)
        params = {
            key: value for key, value in dict(scan.get("params") or {}).items() if key in allowed
        }
        params.update(extra)
        job = submit(
            conn,
            kind=kind,
            binary_id=binary_id,
            params=params,
            submitted_by=submitted_by,
            submitted_by_user_id=submitted_by_user_id,
        )
        job_id = int(job["id"])
        if any(int(row["id"]) == job_id for row in queued):
            continue
        journal.journaled_create(
            log,
            table=TABLE,
            key=job_id,
            description=f"queued {kind} job {job_id} for analysis {analysis_id}",
        )
        queued.append(job)
    return queued


# ── Rows ───────────────────────────────────────────────────────────


def _loads_column(raw: str, *, job_id: int, column: str) -> Any | None:
    """Parse one JSON column, or None when it is corrupt.

    A corrupt ``params_json`` or ``result_json`` must not take down every job
    listing: the row still exists, so the reader gets a safe empty value and a
    warning names the job and column an operator can repair.
    """
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _log.warning("job %s has corrupt %s: %s", job_id, column, exc)
        return None


def _row(row: sqlite3.Row | Mapping[str, Any]) -> dict[str, Any]:
    """One stored job as a plain dict, with its payload decoded."""
    job_id = int(row["id"])
    raw_result = str(row["result_json"] or "")
    raw_params = str(row["params_json"] or "{}")
    params = _loads_column(raw_params, job_id=job_id, column="params_json")
    if not isinstance(params, dict):
        if params is not None:
            _log.warning("job %s params_json is not a JSON object", job_id)
        params = {}
    result = _loads_column(raw_result, job_id=job_id, column="result_json") if raw_result else None
    columns = set(row.keys())
    raw_submitter_id = row["submitted_by_user_id"] if "submitted_by_user_id" in columns else None
    return {
        "id": job_id,
        "kind": str(row["kind"]),
        "label": JOB_KINDS[str(row["kind"])].label if str(row["kind"]) in JOB_KINDS else "",
        "binary_id": int(row["binary_id"]) if row["binary_id"] is not None else None,
        "status": str(row["status"]),
        "progress": int(row["progress"]),
        "steps_total": int(row["steps_total"]),
        "message": str(row["message"]),
        "params": params,
        "error": str(row["error"]),
        "result": result,
        "created_at": str(row["created_at"]),
        "started_at": str(row["started_at"]),
        "finished_at": str(row["finished_at"]),
        "submitted_by": str(row["submitted_by"]) if "submitted_by" in columns else "",
        "submitted_by_user_id": None if raw_submitter_id is None else int(raw_submitter_id),
        "request_id": str(row["request_id"]) if "request_id" in columns else "",
        "live": str(row["status"]) in LIVE_STATUSES,
    }


def get_job(conn: sqlite3.Connection, job_id: int) -> dict[str, Any] | None:
    """One job by id, or None."""
    ensure_schema(conn)
    row = conn.execute(f"SELECT * FROM {TABLE} WHERE id = ?", (job_id,)).fetchone()
    return _row(row) if row else None


def visible_job(
    conn: sqlite3.Connection, job_id: int, visible_to: Mapping[str, Any] | None
) -> dict[str, Any] | None:
    """One job by id when *visible_to* may see its binary, else None.

    A job names the binary it runs on, so it resolves to that binary like
    every other second-order kind; a missing job and a hidden one both read
    as None, the same 404-as-absent the per-object gate reports.
    """
    from reportal import auth

    job = get_job(conn, job_id)
    if job is None:
        return None
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is None:
        return job
    clause, params = scope
    row = conn.execute(
        f"SELECT b.id AS id FROM binaries b WHERE b.id = ? AND {clause}",
        [int(job["binary_id"]), *params],
    ).fetchone()
    return job if row is not None else None


def latest_job(
    conn: sqlite3.Connection, *, kind: str, binary_id: int | None = None
) -> dict[str, Any] | None:
    """The newest job of one kind, optionally for one binary, or None."""
    if kind not in JOB_KINDS:
        raise ValueError(f"unknown job kind: {kind}")
    ensure_schema(conn)
    sql = f"SELECT * FROM {TABLE} WHERE kind = ?"
    params: list[Any] = [kind]
    if binary_id is not None:
        sql += " AND binary_id = ?"
        params.append(binary_id)
    sql += " ORDER BY id DESC LIMIT 1"
    row = conn.execute(sql, params).fetchone()
    return _row(row) if row else None


def count_jobs(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> int:
    """How many jobs there are, optionally of one status.

    ``visible_to`` narrows to jobs of binaries the caller may see, like
    :func:`list_jobs`.
    """
    from reportal import auth

    ensure_schema(conn)
    clauses: list[str] = []
    params: list[Any] = []
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        scope_clause, scope_params = scope
        clauses.append(
            f"EXISTS (SELECT 1 FROM binaries b WHERE b.id = {TABLE}.binary_id AND {scope_clause})"
        )
        params.extend(scope_params)
    if status is not None:
        clauses.append(f"{TABLE}.status = ?")
        params.append(status)
    sql = f"SELECT COUNT(*) FROM {TABLE}"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    return int(conn.execute(sql, params).fetchone()[0])


def list_jobs(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    kind: str | None = None,
    binary_id: int | None = None,
    limit: int = DEFAULT_JOB_LIMIT,
    visible_to: Mapping[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """``(rows, total)`` newest first, optionally narrowed by status, kind and binary.

    *total* is the whole match, so a bounded page never reads as the whole
    queue.  An unknown status, an unknown kind or an out-of-range limit raises
    ``ValueError``.  ``visible_to`` narrows to jobs of binaries the caller may
    see, like the other listings.
    """
    from reportal import auth

    if status is not None and status not in STATUSES:
        raise ValueError(f"unknown job status: {status}")
    if kind is not None and kind not in JOB_KINDS:
        raise ValueError(f"unknown job kind: {kind}")
    if limit < 1 or limit > MAX_JOB_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_JOB_LIMIT}")
    ensure_schema(conn)
    clauses: list[str] = []
    params: list[Any] = []
    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    if scope is not None:
        scope_clause, scope_params = scope
        clauses.append(
            f"EXISTS (SELECT 1 FROM binaries b WHERE b.id = {TABLE}.binary_id AND {scope_clause})"
        )
        params.extend(scope_params)
    if status is not None:
        clauses.append(f"{TABLE}.status = ?")
        params.append(status)
    if kind is not None:
        clauses.append(f"{TABLE}.kind = ?")
        params.append(kind)
    if binary_id is not None:
        clauses.append(f"{TABLE}.binary_id = ?")
        params.append(binary_id)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    total = int(conn.execute(f"SELECT COUNT(*) FROM {TABLE}{where}", params).fetchone()[0])
    rows = conn.execute(
        f"SELECT {TABLE}.* FROM {TABLE}{where} ORDER BY {TABLE}.id DESC LIMIT ?",
        [*params, limit],
    ).fetchall()
    return [_row(row) for row in rows], total


def _prune(conn: sqlite3.Connection) -> None:
    """Drop the oldest terminal jobs once the table is past its bound."""
    conn.execute(
        f"DELETE FROM {TABLE} WHERE id IN ("
        f" SELECT id FROM {TABLE} WHERE status NOT IN (?, ?) ORDER BY id DESC LIMIT -1 OFFSET ?)",
        (STATUS_QUEUED, STATUS_RUNNING, MAX_KEPT_JOBS),
    )


def submit(
    conn: sqlite3.Connection,
    *,
    kind: str,
    binary_id: int,
    params: Mapping[str, Any] | None = None,
    submitted_by: str = "",
    submitted_by_user_id: int | None = None,
) -> dict[str, Any]:
    """Queue one job and return it; the caller decides whether to run it.

    A second submit of the same kind, binary and params while a matching job is
    queued or running returns that row instead of inserting another: metered kinds
    (``ai-enrich``) and writers must not run twice for one double-click.
    *submitted_by* names who queued it (and the stable id behind the name),
    so the worker thread that later runs it records the submitter's identity
    on the journal entries it writes.  The active HTTP ``request_id`` (when
    any) is stored on the row so a later pool thread can still emit
    ``job failed`` / ``job slow`` lines an operator can grep back to the
    submit request.

    Raises :class:`KeyError` for an unknown binary, :class:`ValueError` for an
    unknown kind, for a parameter a kind does not take, for a parameter a kind
    needs and for a queue that is already at :data:`MAX_QUEUED_JOBS`.
    """
    if kind not in JOB_KINDS:
        raise ValueError(f"unknown job kind: {kind}")
    spec = JOB_KINDS[kind]
    supplied = {str(key) for key in (params or {})}
    unexpected = sorted(supplied - set(spec.params))
    if unexpected:
        raise ValueError(f"job kind {kind} takes no parameter {unexpected[0]}")
    if store.get_binary(conn, binary_id) is None:
        raise KeyError(f"no binary with id {binary_id}")
    # Validate the parameters now rather than when the job runs: a typo should
    # be a 400 on submit, not a failed job later.
    resolved = dict(params or {})
    for name in spec.params:
        if name == "domain":
            what = "behavior" if kind == "behavior" else "hardening"
            domains = (
                behavior.BEHAVIOR_DOMAINS if kind == "behavior" else hardening.HARDENING_DOMAINS
            )
            # Persist the defaulted domain so the stored job matches the scan
            # that will run; submit must not leave params empty while execute
            # silently picks domains[0].
            resolved["domain"] = _domain_of(resolved, domains, what)
    if kind == "match":
        # The settings are the match routes' body shape, so a run queued here
        # records what the same settings would record there; a bad value, an
        # unknown scope id or an install without the scorer is refused now
        # rather than when the job runs.
        if not similarity.available():
            raise ValueError(
                "function matching requires the optional 'similarity' extra"
                " (uv sync --extra similarity)"
            )
        try:
            settings = matching.MatchSettings.from_request(resolved)
            matching.resolve_scope(conn, settings)
        except matching.InvalidSettingsError as exc:
            raise ValueError(f"{exc.error}: {exc.detail}") from exc
    if kind == "ai-enrich":
        # The batch's own bounds, checked now so a typo is a 400 on submit
        # rather than a failed job later.
        raw_limit = resolved.get("limit")
        try:
            limit = pipeline.DEFAULT_BATCH_LIMIT if raw_limit is None else int(raw_limit)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"limit must be an integer, got {raw_limit!r}") from exc
        if not 1 <= limit <= pipeline.MAX_BATCH_LIMIT:
            raise ValueError(f"limit must be between 1 and {pipeline.MAX_BATCH_LIMIT}, got {limit}")
        resolved["limit"] = limit
        ids = resolved.get("function_ids")
        if ids is not None and (not isinstance(ids, list) or not all(_is_int(v) for v in ids)):
            raise ValueError("function_ids must be a list of function ids")
    if kind == "library":
        raw_confidence = resolved.get("min_confidence")
        if raw_confidence is None:
            resolved["min_confidence"] = library.DEFAULT_MIN_CONFIDENCE
        else:
            try:
                confidence = float(raw_confidence)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"min_confidence must be a number, got {raw_confidence!r}"
                ) from exc
            if not 0.0 <= confidence <= 1.0:
                raise ValueError(f"min_confidence must be between 0 and 1, got {confidence}")
            resolved["min_confidence"] = confidence
    if kind == "security":
        raw_severity = resolved.get("min_severity")
        if raw_severity is None:
            resolved["min_severity"] = engines.DEFAULT_SECURITY_MIN_SEVERITY
        else:
            severity = str(raw_severity)
            if severity not in engines.SECURITY_SEVERITIES:
                raise ValueError(f"unsupported security severity: {severity}")
            resolved["min_severity"] = severity
    if kind == "threat":
        raw_narrative = resolved.get("narrative")
        if raw_narrative is None:
            resolved["narrative"] = False
        elif not isinstance(raw_narrative, bool):
            raise ValueError(f"narrative must be a boolean, got {raw_narrative!r}")
        else:
            resolved["narrative"] = raw_narrative
    if kind == "structs":
        raw_decompiler = resolved.get("decompiler")
        if raw_decompiler is None:
            resolved["decompiler"] = engines.DEFAULT_DECOMPILER_BACKEND
        else:
            decompiler = str(raw_decompiler)
            if decompiler not in engines.DECOMPILER_BACKENDS:
                raise ValueError(f"unsupported decompiler backend: {decompiler}")
            resolved["decompiler"] = decompiler
        raw_limit = resolved.get("limit")
        if raw_limit is None:
            resolved["limit"] = DEFAULT_STRUCT_LIMIT
        else:
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"limit must be an integer, got {raw_limit!r}") from exc
            if limit < 0:
                raise ValueError(f"limit must not be negative: {limit}")
            resolved["limit"] = limit
    if kind == "function-triage":
        raw_limit = resolved.get("limit")
        if raw_limit is None:
            resolved["limit"] = function_triage.DEFAULT_LIMIT
        else:
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"limit must be an integer, got {raw_limit!r}") from exc
            if not 1 <= limit <= function_triage.MAX_LIMIT:
                raise ValueError(
                    f"limit must be between 1 and {function_triage.MAX_LIMIT}, got {limit}"
                )
            resolved["limit"] = limit
        ids = resolved.get("function_ids")
        if ids is not None and (not isinstance(ids, list) or not all(_is_int(v) for v in ids)):
            raise ValueError("function_ids must be a list of function ids")
    if kind == "related":
        raw_limit = resolved.get("limit")
        if raw_limit is None:
            resolved["limit"] = related.DEFAULT_LIMIT
        else:
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"limit must be an integer, got {raw_limit!r}") from exc
            if limit <= 0:
                raise ValueError(f"limit must be positive, got {limit}")
            if limit > related.MAX_LIMIT:
                raise ValueError(f"limit must be at most {related.MAX_LIMIT}, got {limit}")
            resolved["limit"] = limit
        raw_unrelated = resolved.get("include_unrelated")
        if raw_unrelated is None:
            resolved["include_unrelated"] = False
        elif not isinstance(raw_unrelated, bool):
            raise ValueError(f"include_unrelated must be a boolean, got {raw_unrelated!r}")
        else:
            resolved["include_unrelated"] = raw_unrelated
    if kind == "lineage":
        raw_other = resolved.get("other_binary_id")
        if raw_other is not None:
            if not _is_int(raw_other):
                raise ValueError(f"other_binary_id must be an integer, got {raw_other!r}")
            if int(raw_other) == binary_id:
                raise ValueError(f"binary {binary_id} cannot be compared with itself")
            resolved["other_binary_id"] = int(raw_other)
        raw_refine = resolved.get("refine")
        if raw_refine is None:
            resolved["refine"] = True
        elif not isinstance(raw_refine, bool):
            raise ValueError(f"refine must be a boolean, got {raw_refine!r}")
        else:
            resolved["refine"] = raw_refine
    if kind == "benchmark":
        raw_right = resolved.get("right_binary_id")
        if isinstance(raw_right, bool) or not isinstance(raw_right, int):
            raise ValueError("right_binary_id is required")
        if raw_right == binary_id:
            raise ValueError("a benchmark compares two different binaries")
        resolved["right_binary_id"] = raw_right
        if not similarity.available():
            raise ValueError(
                "function matching requires the optional 'similarity' extra"
                " (uv sync --extra similarity)"
            )
        try:
            settings = matching.MatchSettings.from_request(resolved)
            matching.resolve_scope(conn, settings)
        except matching.InvalidSettingsError as exc:
            raise ValueError(f"{exc.error}: {exc.detail}") from exc
    if kind == "unpack":
        raw_packer = resolved.get("packer")
        if raw_packer is None:
            resolved["packer"] = ""
        else:
            packer = str(raw_packer).strip().lower()
            if packer and packer not in unpack.PACKERS:
                raise ValueError(f"packer must be one of {', '.join(unpack.PACKERS)}")
            resolved["packer"] = packer
        raw_name = resolved.get("name")
        resolved["name"] = "" if raw_name is None else str(raw_name).strip()
    ensure_schema(conn)
    # Stable encoding so a double-click that rebuilds the same params map still
    # matches the queued row; without sort_keys, insertion order alone would
    # make every retry look new.
    params_json = json.dumps(resolved, sort_keys=True)
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            f"SELECT * FROM {TABLE} WHERE status IN (?, ?) AND kind = ? AND binary_id = ?"
            " AND params_json = ? ORDER BY id LIMIT 1",
            (*LIVE_STATUSES, kind, binary_id, params_json),
        ).fetchone()
        if existing is not None:
            return _row(existing)
        queued = int(
            conn.execute(
                f"SELECT COUNT(*) FROM {TABLE} WHERE status = ?", (STATUS_QUEUED,)
            ).fetchone()[0]
        )
        if queued >= MAX_QUEUED_JOBS:
            raise ValueError(f"the queue is full: {queued} jobs are waiting")
        request_id = observability.current_request_id()
        cur = conn.execute(
            f"INSERT INTO {TABLE} (kind, binary_id, status, progress, steps_total, message,"
            " params_json, created_at, submitted_by, submitted_by_user_id, request_id)"
            " VALUES (?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?)",
            (
                kind,
                binary_id,
                STATUS_QUEUED,
                "queued",
                params_json,
                store.now(),
                submitted_by,
                submitted_by_user_id,
                request_id,
            ),
        )
        _prune(conn)
    job = get_job(conn, int(cur.lastrowid or 0))
    assert job is not None, "the row was just inserted"
    return job


def cancel(conn: sqlite3.Connection, job_id: int) -> dict[str, Any] | None:
    """Cancel a job that has not started; None when the id is unknown.

    A ``running`` job is refused with :class:`ValueError`: the engine call it
    already entered cannot be stopped, so pretending to cancel it would leave a
    scan writing its result after the client was told it had stopped.

    The status gate is the ``UPDATE`` predicate, not a prior read: a worker
    that claims the same row between a read and a write would otherwise leave
    the job ``cancelled`` while still executing.
    """
    job = get_job(conn, job_id)
    if job is None:
        return None
    if job["status"] != STATUS_QUEUED:
        raise ValueError(f"job {job_id} is {job['status']} and cannot be cancelled")
    cur = conn.execute(
        f"UPDATE {TABLE} SET status = ?, message = ?, finished_at = ? WHERE id = ? AND status = ?",
        (STATUS_CANCELLED, "cancelled before it started", store.now(), job_id, STATUS_QUEUED),
    )
    conn.commit()
    if cur.rowcount == 0:
        raced = get_job(conn, job_id)
        if raced is None:
            return None
        raise ValueError(f"job {job_id} is {raced['status']} and cannot be cancelled")
    return get_job(conn, job_id)


# ── Running ────────────────────────────────────────────────────────


def _claim(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Take the oldest queued job, marking it running; None when none is queued."""
    ensure_schema(conn)
    row = conn.execute(
        f"SELECT id FROM {TABLE} WHERE status = ? ORDER BY id LIMIT 1", (STATUS_QUEUED,)
    ).fetchone()
    if row is None:
        return None
    job_id = int(row["id"])
    cur = conn.execute(
        f"UPDATE {TABLE} SET status = ?, progress = 0, message = ?, started_at = ?"
        " WHERE id = ? AND status = ?",
        (STATUS_RUNNING, "running", store.now(), job_id, STATUS_QUEUED),
    )
    conn.commit()
    if cur.rowcount == 0:  # pragma: no cover - another worker claimed it first
        return None
    return get_job(conn, job_id)


# A progress report writes the job's row at most this often: a match run calls
# the sink once per source function, and a row write per function would spend
# more time on the database than on scoring.
PROGRESS_REPORT_EVERY = 25


def _progress_sink(conn: sqlite3.Connection, job_id: int) -> Callable[[int, int], None]:
    """A throttled writer for a kind that reports its own steps."""

    def report(done: int, total: int) -> None:
        if total <= 0 or (done % PROGRESS_REPORT_EVERY and done != total):
            return
        conn.execute(
            f"UPDATE {TABLE} SET progress = ?, steps_total = ?, message = ? WHERE id = ?",
            (min(100, int(100 * done / total)), total, f"{done} of {total} steps", job_id),
        )
        conn.commit()

    return report


def execute(conn: sqlite3.Connection, job: dict[str, Any]) -> dict[str, Any]:
    """Run one claimed job to its terminal state and return the stored row.

    The scan runs inside the same journaled action its synchronous route uses,
    so a queued run is revertible through the journal exactly like a direct one.
    An operation that fails records the failure and a bounded message; it never
    raises, because a failed job is a result the caller polls for.  The worker
    thread re-enters the submitter's identity, so the entries carry who queued
    the work rather than an empty actor.  When the row carries a stored
    ``request_id`` and this thread has none, it is bound for the run so
    completion lines still correlate to the submit request after the pool
    picked the job up.
    """
    spec = JOB_KINDS[job["kind"]]
    binary_id = int(job["binary_id"])
    params = dict(job.get("params") or {})
    job_id = int(job["id"])
    raw_user_id = job.get("submitted_by_user_id")
    submitter_id = int(raw_user_id) if isinstance(raw_user_id, int) else None
    submitter = str(job.get("submitted_by") or "")
    stored_request_id = str(job.get("request_id") or "")
    request_id_token: Any | None = None
    if stored_request_id and not observability.current_request_id():
        request_id_token = observability.set_request_id(stored_request_id)
    started = _monotonic()
    try:
        with journal.acting_as(submitter, user_id=submitter_id):
            try:
                scan_kind = spec.scan_kind_for(params)
                if spec.perform_progress is not None:
                    payload = spec.perform_progress(
                        conn, binary_id, params, progress=_progress_sink(conn, job_id)
                    )
                elif spec.perform is not None:
                    payload = spec.perform(conn, binary_id, params)
                elif scan_kind is None:  # pragma: no cover - every other kind stores a scan
                    payload = spec.run(conn, binary_id, params)
                else:
                    action = journal.new_action()
                    with journal.journaled(conn, action) as log:
                        payload = journal.journaled_scan(
                            conn,
                            log,
                            binary_id,
                            scan_kind,
                            lambda: spec.run(conn, binary_id, params),
                        )
                    payload = log.attach(payload)
                failure = ""
                failure_exc: BaseException | None = None
            except Exception as exc:
                payload = None
                failure = f"{type(exc).__name__}: {exc}"
                failure_exc = exc
        duration_ms = int((_monotonic() - started) * 1000)
        status = STATUS_FAILED if failure else STATUS_DONE
        observability.record_job(failed=bool(failure), duration_ms=duration_ms)
        if failure_exc is not None:
            _log_job_failure(
                job_id=job_id,
                kind=str(job["kind"]),
                binary_id=binary_id,
                duration_ms=duration_ms,
                error=failure[:200],
                exc=failure_exc,
            )
        elif duration_ms >= observability.SLOW_JOB_MS:
            _log_job_slow(
                job_id=job_id,
                kind=str(job["kind"]),
                binary_id=binary_id,
                duration_ms=duration_ms,
            )
    finally:
        if request_id_token is not None:
            observability.reset_request_id(request_id_token)
    conn.execute(
        f"UPDATE {TABLE} SET status = ?, progress = ?, message = ?, result_json = ?,"
        " error = ?, finished_at = ? WHERE id = ?",
        (
            status,
            100 if not failure else 0,
            "failed" if failure else "finished",
            json.dumps(payload) if payload is not None else "",
            failure[:500],
            store.now(),
            int(job["id"]),
        ),
    )
    conn.commit()
    stored = get_job(conn, int(job["id"]))
    assert stored is not None, "the row was just updated"
    return stored


def _log_job_failure(
    *,
    job_id: int,
    kind: str,
    binary_id: int,
    duration_ms: int,
    error: str,
    exc: BaseException,
) -> None:
    """One structured error line an operator can grep by job id or request id."""
    _log.error(
        "job failed id=%s kind=%s binary_id=%s duration_ms=%s error=%s%s",
        job_id,
        kind,
        binary_id,
        duration_ms,
        error,
        observability.request_id_suffix(),
        exc_info=exc,
    )


def _log_job_slow(
    *,
    job_id: int,
    kind: str,
    binary_id: int,
    duration_ms: int,
) -> None:
    """A successful job that took long enough to be worth noticing."""
    _log.warning(
        "job slow id=%s kind=%s binary_id=%s duration_ms=%s%s",
        job_id,
        kind,
        binary_id,
        duration_ms,
        observability.request_id_suffix(),
    )


def run_pending(conn: sqlite3.Connection, *, limit: int = 1) -> list[dict[str, Any]]:
    """Run up to *limit* queued jobs inline and return the finished rows.

    This is what the worker loop and the ``reportal job-run`` command call, and
    what a test drives when it wants a deterministic run with no thread.
    """
    finished: list[dict[str, Any]] = []
    for _ in range(max(limit, 0)):
        job = _claim(conn)
        if job is None:
            break
        finished.append(execute(conn, job))
    return finished


# ── The background pool ────────────────────────────────────────────

_worker: JobWorker | None = None
_worker_lock = threading.Lock()

# The pool can be switched off: a test does (so no thread runs a job behind an
# assertion), and so can an operator who would rather drive the queue with
# `reportal job-run`.  It is on by default, which is what makes a serving
# process pick a queued job up on its own.
POOL_ENV = "REPORTAL_JOBS_POOL"
# Keep in sync with ``settings.FLAG_FALSEY`` (pinned by ``tests/test_settings.py``).
_FALSEY = frozenset({"0", "false", "no", "off", "disabled"})


def pool_disabled() -> bool:
    """Whether this process was told not to run the background pool."""
    return os.environ.get(POOL_ENV, "").strip().lower() in _FALSEY


class JobWorker:
    """A bounded pool that drains the queue until it is stopped.

    Each worker opens its own connection: a SQLite connection is not shared
    across threads, and the queue lives in the database, so the pool needs no
    memory of its own.  A worker that finds nothing sleeps for
    :data:`POLL_SECONDS`.
    """

    def __init__(self, *, workers: int = MAX_WORKERS) -> None:
        self._stop = threading.Event()
        self._threads = [
            threading.Thread(target=self._loop, name=f"reportal-jobs-{index}", daemon=True)
            for index in range(max(1, workers))
        ]
        self._last_error_log = 0.0
        self._error_log_lock = threading.Lock()

    def start(self) -> None:
        for thread in self._threads:
            thread.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=timeout)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                with contextlib.closing(store.connect(_paths.db_path())) as conn:
                    if not run_pending(conn, limit=1):
                        self._stop.wait(POLL_SECONDS)
            except (sqlite3.Error, WorkspaceNotFound, OSError) as exc:
                # A database that is not there yet, or a locked one, is not a
                # reason to kill the worker: the next tick tries again.  Log
                # occasionally so an operator can see why the queue is stuck.
                now = _monotonic()
                with self._error_log_lock:
                    if now - self._last_error_log >= WORKER_ERROR_LOG_SECONDS:
                        self._last_error_log = now
                        should_log = True
                    else:
                        should_log = False
                if should_log:
                    _log.warning(
                        "job worker tick failed: %s: %s",
                        type(exc).__name__,
                        exc,
                        exc_info=exc,
                    )
                self._stop.wait(POLL_SECONDS)


def ensure_worker() -> JobWorker | None:
    """Start the process-wide pool once; None when there is no workspace yet."""
    global _worker
    if pool_disabled():
        return None
    with _worker_lock:
        if _worker is not None:
            return _worker
        try:
            _paths.db_path()
        except WorkspaceNotFound:  # pragma: no cover - the server refuses to start outside one
            return None
        _worker = JobWorker()
        _worker.start()
        return _worker


def stop_worker() -> None:
    """Stop the process-wide pool; a test calls this so no thread outlives it."""
    global _worker
    with _worker_lock:
        if _worker is not None:
            _worker.stop()
            _worker = None


# ── Events ─────────────────────────────────────────────────────────


def event_frame(job: dict[str, Any]) -> str:
    """One server-sent event carrying a job's state."""
    return f"event: job\ndata: {json.dumps(job)}\n\n"


def events(
    conn: sqlite3.Connection,
    job_id: int,
    *,
    interval: float = STREAM_INTERVAL_SECONDS,
    max_seconds: float = STREAM_MAX_SECONDS,
) -> Iterator[str]:
    """The job's state as server-sent events, ending when it is terminal.

    One frame per observed change (plus the current state at once, so a client
    that attaches late is not left blank), and a final frame with the terminal
    state.  The stream is bounded by *max_seconds* so a client can always
    reconnect rather than hold a socket open forever.
    """
    deadline = _monotonic() + max(0.0, max_seconds)
    last = ""
    while True:
        job = get_job(conn, job_id)
        if job is None:
            yield f"event: error\ndata: {json.dumps({'error': 'job not found'})}\n\n"
            return
        frame = event_frame(job)
        if frame != last:
            yield frame
            last = frame
        if not job["live"]:
            return
        if _monotonic() >= deadline:
            yield "event: timeout\ndata: {}\n\n"
            return
        _sleep(max(interval, 0.0))
