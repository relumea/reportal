"""The engine-verified LLM worker: reconstruct one function's C from the model.

``llm_c_source`` gathers what reportal already knows about a function (its
cached NASM listing, else ``rebrew asm``; its stored decompilation, else
``rebrew decompile``), asks the configured OpenAI-compatible bridge for a
complete MSVC 6 / C89 source file in rebrew's annotation format, and, when the
run is executing, writes it into the rebrew project's reversed source
directory and verifies it with ``rebrew test --json``.  Only a matching status
from that call is reported as ``matched``; anything else is ``improved`` (the
candidate compiled but did not match) or ``failed``.

The worker makes exactly one attempt per call.  The orchestrator owns the retry
budget: it calls again with ``previous`` set to the last attempt's detail, which
is where the mismatch summary it feeds back to the model comes from, and which
is how a retry knows the file it wrote is its own rather than a collision.

Nothing here invents annotation metadata: the marker line is
``// FUNCTION: <MODULE> 0x<VA>`` (``docs/ANNOTATIONS.md`` in rebrew), where the
module is the target's ``marker`` from ``rebrew-project.toml`` and the VA and
name are the function row reportal already stores.  STATUS, SIZE and CFLAGS stay
metadata-owned, so the generated file carries only the marker.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from rebrew.workspace import (
    default_target,
    read_config,
    target_marker,
    target_reversed_dir,
    targets_table,
)

from reportal import engines, llm, store
from reportal.auto_workers import (
    REASON_ENGINE_UNAVAILABLE,
    REASON_LLM_UNAVAILABLE,
    REASON_NO_ENGINE_CONTEXT,
    WORKER_FAILED,
    WORKER_IMPROVED,
    WORKER_LLM_C_SOURCE,
    WORKER_MATCHED,
    WORKER_SKIPPED,
    Worker,
    WorkerContext,
    WorkerResult,
    is_address_placeholder,
    is_matching_status,
)

# Disassembly format requested; the same format the disassembly route caches,
# so the worker reuses a listing the portal already showed.
DISASM_FORMAT = "nasm"

# Prompt-size bounds.  A listing or decompilation past these is truncated
# rather than sent whole; the head carries the entry and the hot path.
MAX_LISTING_CHARS = 24000
MAX_DECOMPILATION_CHARS = 24000

# Mismatch rows from `rebrew test --json` carried into the retry prompt.  The
# first few are the ones the model can act on; the tail is noise.
MAX_MISMATCHES_IN_PROMPT = 5

# Reasons the worker reports beyond the shared skip reasons.
REASON_NO_CANDIDATE = "no-candidate"
REASON_FILE_EXISTS = "source-file-exists"
REASON_NO_MARKER = "no-marker-module"
REASON_NO_MATCHING_STATUS = "no-matching-status"
REASON_ENGINE_ERROR = "engine-error"
REASON_LLM_ERROR = "llm-error"

# Kind the marker line declares for a non-library implementation.
MARKER_KIND = "FUNCTION"

# A source filename derived from a symbol keeps only identifier characters.
_SLUG_UNSAFE = re.compile(r"[^A-Za-z0-9_]")

# Filename stem for a function with no usable symbol.
_ADDRESS_SLUG_PREFIX = "func_"

_FENCE_OPEN = re.compile(r"^```[a-zA-Z0-9_+-]*[ \t]*\r?\n")
_FENCE_CLOSE = re.compile(r"\r?\n?[ \t]*```[ \t]*$")

SYSTEM_PROMPT = (
    "You reconstruct the original C implementation of one function from its"
    " disassembly and decompilation.  The target was built with Microsoft"
    " Visual C++ 6.0 in C89 mode and matched byte for byte, so use only C89"
    " constructs and MSVC 6 intrinsics where the disassembly shows them."
    "  Reply with the complete .c file contents and nothing else: no prose, no"
    " markdown fences."
)


def target_config(project_dir: str) -> dict[str, Any] | None:
    """Resolve the rebrew target's marker and reversed source directory.

    Mirrors ``rebrew.config``: the project's ``default_target`` (else the first
    target), its ``marker`` (else the target name upper-cased with
    non-identifier characters removed) and its ``reversed_dir`` (else
    ``src/<target>``).  Returns None when the project has no readable targets.
    """
    root = Path(project_dir)
    config = read_config(root)
    name = default_target(config)
    if name is None:
        return None
    entry = targets_table(config).get(name, {})
    return {
        "target": name,
        "marker": target_marker(name, entry),
        "reversed_dir": target_reversed_dir(root, name, entry),
    }


def marker_line(marker: str, va: int) -> str:
    """The annotation line rebrew expects for this function."""
    return f"// {MARKER_KIND}: {marker} {hex(va)}"


def source_slug(function: dict[str, Any]) -> str:
    """A safe source filename stem for one function row."""
    name = str(function["name"]).strip()
    if name and not is_address_placeholder(name):
        slug = _SLUG_UNSAFE.sub("_", name)
        if slug:
            return slug
    return f"{_ADDRESS_SLUG_PREFIX}{int(function['va']):x}"


def strip_fences(text: str) -> str:
    """Return *text* without a surrounding markdown code fence, if any."""
    body = text.strip()
    if body.startswith("```"):
        body = _FENCE_OPEN.sub("", body, count=1)
        body = _FENCE_CLOSE.sub("", body, count=1)
    return body.strip()


def ensure_marker(source: str, marker: str, va: int) -> str:
    """Return *source* carrying the canonical marker line as its first line."""
    line = marker_line(marker, va)
    body = strip_fences(source)
    if line in body.splitlines():
        return body if body.endswith("\n") else f"{body}\n"
    return f"{line}\n\n{body}\n"


def _truncate(text: str, limit: int) -> str:
    """Return *text*, capped at *limit* characters with a marker when cut."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n; ... truncated at {limit} characters"


def _mismatch_lines(result: dict[str, Any]) -> str:
    """Render the first mismatches of a `rebrew test` result for the prompt."""
    rows = result.get("mismatches")
    if not isinstance(rows, list) or not rows:
        return ""
    return "\n".join(
        f"  offset {row.get('offset')}: target {row.get('target')} got {row.get('got')}"
        for row in rows[:MAX_MISMATCHES_IN_PROMPT]
        if isinstance(row, dict)
    )


def build_messages(
    *,
    function: dict[str, Any],
    marker: str,
    disassembly: str,
    decompilation: str,
    previous: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Assemble the chat messages for one reconstruction attempt."""
    va = int(function["va"])
    engine_result = previous.get("engine_result") if isinstance(previous, dict) else None
    feedback = ""
    if isinstance(engine_result, dict):
        feedback = (
            f"\nThe previous attempt compiled but did not match: status"
            f" {engine_result.get('status')}, {engine_result.get('match_count')} of"
            f" {engine_result.get('total')} bytes equal.\n"
        )
        mismatches = _mismatch_lines(engine_result)
        if mismatches:
            feedback += f"First differing bytes:\n{mismatches}\n"
    body = (
        f"Reconstruct this function.\n"
        f"Marker line (first line of the file): {marker_line(marker, va)}\n"
        f"Symbol: {function['name']}\n"
        f"Virtual address: {hex(va)}\n"
        f"Size: {int(function['size'])} bytes\n"
        f"{feedback}\n"
        f"Disassembly:\n{_truncate(disassembly, MAX_LISTING_CHARS)}\n\n"
        f"Decompilation:\n{_truncate(decompilation, MAX_DECOMPILATION_CHARS)}\n"
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": body},
    ]


def _skip(ctx: WorkerContext, reason: str) -> WorkerResult:
    """A skip result for this worker's current function."""
    return WorkerResult(
        status=WORKER_SKIPPED,
        function_id=int(ctx.function["id"]),
        status_before=str(ctx.function["status"]),
        detail={"reason": reason},
    )


def _fail(ctx: WorkerContext, reason: str, detail: dict[str, Any] | None = None) -> WorkerResult:
    """A failure result for this worker's current function."""
    return WorkerResult(
        status=WORKER_FAILED,
        function_id=int(ctx.function["id"]),
        status_before=str(ctx.function["status"]),
        detail={"reason": reason, **(detail or {})},
    )


def _gather(ctx: WorkerContext) -> tuple[str, str] | WorkerResult:
    """Return ``(disassembly, decompilation)``, or the result that ends the attempt."""
    function_id = int(ctx.function["id"])
    disasm = store.get_disasm(ctx.conn, function_id)
    stored = store.get_decompilation(ctx.conn, function_id)
    decomp = str(stored["code"]) if stored is not None else None
    if disasm is not None and decomp is not None:
        return disasm, decomp
    engine = ctx.engine
    if engine is None or not engine.available():
        return _skip(ctx, REASON_ENGINE_UNAVAILABLE)
    va = int(ctx.function["va"])
    try:
        if disasm is None:
            disasm = engine.disassemble(
                str(ctx.project_dir), va, int(ctx.function["size"]), DISASM_FORMAT
            )
            store.set_disasm(ctx.conn, function_id, disasm)
        if decomp is None:
            decompiled = engine.decompile(str(ctx.project_dir), va)
            decomp = str(decompiled.get("code") or "")
            backend = str(decompiled.get("backend") or engines.DEFAULT_DECOMPILER_BACKEND)
            store.set_decompilation(ctx.conn, function_id, decomp, backend)
    except engines.EngineError as exc:
        return _fail(ctx, REASON_ENGINE_ERROR, {"detail": str(exc)})
    return disasm, decomp


def _owned_files(ctx: WorkerContext) -> set[str]:
    """Paths a previous attempt of this run wrote, which it may overwrite."""
    previous = ctx.previous
    if not isinstance(previous, dict):
        return set()
    raw = previous.get("written_files")
    if not isinstance(raw, list):
        return set()
    return {str(entry) for entry in raw if isinstance(entry, str)}


def _run_once(ctx: WorkerContext) -> WorkerResult:
    """One reconstruction attempt: gather context, ask, write, verify."""
    client = ctx.llm_client
    if client is None or not client.available():
        return _skip(ctx, REASON_LLM_UNAVAILABLE)
    if ctx.project_dir is None:
        return _skip(ctx, REASON_NO_ENGINE_CONTEXT)
    target = target_config(ctx.project_dir)
    if target is None:
        return _skip(ctx, REASON_NO_MARKER)
    gathered = _gather(ctx)
    if isinstance(gathered, WorkerResult):
        return gathered
    disassembly, decompilation = gathered

    function = ctx.function
    function_id = int(function["id"])
    before = str(function["status"])
    marker = str(target["marker"])
    try:
        answer = client.complete(
            build_messages(
                function=function,
                marker=marker,
                disassembly=disassembly,
                decompilation=decompilation,
                previous=ctx.previous,
            )
        )
    except llm.LlmUnavailable as exc:
        return WorkerResult(
            status=WORKER_SKIPPED,
            function_id=function_id,
            status_before=before,
            detail={"reason": REASON_LLM_UNAVAILABLE, "detail": str(exc)},
        )
    except llm.LlmError as exc:
        return _fail(ctx, REASON_LLM_ERROR, {"detail": str(exc)})

    source = strip_fences(answer)
    if not source:
        return _fail(ctx, REASON_NO_CANDIDATE)
    source = ensure_marker(source, marker, int(function["va"]))

    if not ctx.execute:
        return WorkerResult(
            status=WORKER_IMPROVED,
            function_id=function_id,
            status_before=before,
            detail={
                "reason": "dry-run",
                "source": source,
                "marker": marker_line(marker, int(function["va"])),
            },
            artifacts=[{"kind": "c-source", "source": source}],
        )

    path = Path(target["reversed_dir"]) / f"{source_slug(function)}.c"
    if path.exists() and str(path) not in _owned_files(ctx):
        return WorkerResult(
            status=WORKER_SKIPPED,
            function_id=function_id,
            status_before=before,
            detail={"reason": REASON_FILE_EXISTS, "path": str(path)},
        )
    engine = ctx.engine
    if engine is None or not engine.available():
        return _skip(ctx, REASON_ENGINE_UNAVAILABLE)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    try:
        result = engine.test_source(ctx.project_dir, str(path))
    except engines.EngineError as exc:
        return WorkerResult(
            status=WORKER_FAILED,
            function_id=function_id,
            status_before=before,
            detail={"reason": REASON_ENGINE_ERROR, "detail": str(exc), "path": str(path)},
            written_files=[str(path)],
        )

    status = str(result.get("status", ""))
    engine_result = {
        "status": status,
        "match_count": result.get("match_count"),
        "total": result.get("total"),
        "mismatches": result.get("mismatches"),
    }
    if is_matching_status(status):
        return WorkerResult(
            status=WORKER_MATCHED,
            function_id=function_id,
            status_before=before,
            status_after=status,
            verified=True,
            detail={"path": str(path), "engine_result": engine_result},
            artifacts=[{"kind": "c-source", "path": str(path)}],
            written_files=[str(path)],
            status_changes=[{"function_id": function_id, "before": before, "after": status}],
        )
    return WorkerResult(
        status=WORKER_FAILED,
        function_id=function_id,
        status_before=before,
        detail={
            "reason": REASON_NO_MATCHING_STATUS,
            "path": str(path),
            "engine_result": engine_result,
        },
        written_files=[str(path)],
    )


def _discard_failure(ctx: WorkerContext, result: WorkerResult) -> WorkerResult:
    """Drop a failed attempt's file unless the run keeps failures.

    A kept failure stays recorded so a revert still removes it; a discarded one
    leaves nothing behind, so the run records no file for it.
    """
    if result.status != WORKER_FAILED or ctx.keep_failures:
        return result
    for raw in result.written_files:
        Path(raw).unlink(missing_ok=True)
    result.written_files = []
    return result


def llm_c_source_worker() -> Worker:
    """The engine-verified LLM worker registered as ``llm_c_source``."""

    def run(ctx: WorkerContext) -> WorkerResult:
        return _discard_failure(ctx, _run_once(ctx))

    return Worker(
        name=WORKER_LLM_C_SOURCE,
        description=(
            "Ask the configured LLM for an MSVC6/C89 source file in rebrew's"
            " annotation format, then verify it with `rebrew test`; dry runs"
            " stop at the candidate source."
        ),
        run=run,
    )
