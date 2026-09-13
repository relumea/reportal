"""reportal's AI decompilation pipeline: a composition of components.

The hosted portal reports a fixed sequence of steps for one function (preparing
decompilation, reading the function trace, decompiling, searching for
functionality, resolving names, storing results, naming variables and types).
This module reproduces that locally as a composition of components
(:mod:`reportal.components`): each stage declares what it requires and what it
provides, the loader activates the stages whose requirements are satisfied, and
every persistent write is journaled with its inverse so a run can be reverted.

Nothing here is a hosted model.  Disassembly, decompilation, matching, name
resolution and knowledge retrieval read the local store and the rebrew engine;
the summary, the inline comments and the type suggestions come from the
optional OpenAI-compatible LLM bridge the user configures, and the stages that
need it are skipped with reason ``llm-unavailable`` when no endpoint is set.
Retrieved document text is untrusted input: the ``retrieve-knowledge`` stage
quotes it into a prompt as data to reason about and never executes it.

A run is stored in ``pipeline_runs`` plus one ``pipeline_steps`` row per
component.  The journaled undo descriptors travel with the run, so a revert
works from a later process.
"""

from __future__ import annotations

import re
import sqlite3
import time
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, cast

from reportal import components, effects, engines, journal, knowledge, llm, similarity, store
from reportal._paths import MARKER, WorkspaceNotFound, project_root
from reportal.components import (
    CHANGE_PROVIDE,
    CHANGE_REVOKE,
    EFFECT_FAILED,
    EFFECT_REVERTED,
    Component,
    Context,
)
from reportal.effects import (
    EFFECT_AI_ARTIFACT,
    EFFECT_CONTEXT_CHANGE,
    EFFECT_DECOMPILATION,
    EFFECT_DISASM,
    apply_descriptor,
    describe,
)

# Names a component declares in ``requires``/``provides``.  The ``SEED_`` names
# are bound by the runner before any component runs; the others are written by
# the component that produces them.
SEED_FUNCTION = "function"
SEED_BINARY = "binary"
SEED_PROJECT = "project"
SEED_CONN = "conn"
SEED_ENGINE = "engine"
SEED_LLM = "llm"

NAME_FUNCTION_META = "function_meta"
NAME_DISASSEMBLY = "disassembly"
NAME_CONTROL_FLOW = "control_flow"
NAME_CALL_TRACE = "call_trace"
NAME_DECOMPILATION = "decompilation"
NAME_SIMILAR_FUNCTIONS = "similar_functions"
NAME_PREDICTED_NAME = "predicted_name"
NAME_KNOWLEDGE = "knowledge"
NAME_TYPE_SUGGESTIONS = "type_suggestions"
NAME_INLINE_COMMENTS = "inline_comments"
NAME_SUMMARY = "summary"

# Component names.  They match the portal's reported steps where a step maps to
# one.
COMPONENT_PREPARE = "prepare"
COMPONENT_READ_TRACE = "read-trace"
COMPONENT_DECOMPILE = "decompile"
COMPONENT_SEARCH_FUNCTIONALITY = "search-functionality"
COMPONENT_RESOLVE_NAMES = "resolve-names"
COMPONENT_RETRIEVE_KNOWLEDGE = "retrieve-knowledge"
COMPONENT_NAME_VARIABLES = "name-variables"
COMPONENT_SUMMARIZE = "summarize"
COMPONENT_STORE = "store"

# Status a `pipeline_steps` row carries.  `running` never reaches a step: a row
# is written once the component finished, was skipped, failed, or was
# deactivated by a requirement going away mid-run.
STEP_DONE = store.PIPELINE_STEP_DONE
STEP_SKIPPED = store.PIPELINE_STEP_SKIPPED
STEP_FAILED = store.PIPELINE_STEP_FAILED
STEP_DEACTIVATED = store.PIPELINE_STEP_DEACTIVATED

# Status a `pipeline_runs` row carries once every component was decided.
RUN_DONE = store.PIPELINE_RUN_DONE
RUN_FAILED = store.PIPELINE_RUN_FAILED

# Reason recorded on a skipped step.  A requirement with no provider (a seed the
# runner withheld) gets its own name; a requirement whose provider was skipped
# or failed names that provider.
REASON_DISABLED = "disabled"
REASON_LLM_UNAVAILABLE = "llm-unavailable"
REASON_NO_ENGINE_CONTEXT = "no-engine-context"
REASON_ENGINE_UNAVAILABLE = "engine-unavailable"
REASON_DEPENDENCY_SKIPPED = "dependency-skipped"
REASON_DEPENDENCY_FAILED = "dependency-failed"
REASON_DEPENDENCY_DEACTIVATED = "dependency-deactivated"
# Reason prefix a deactivated step records, naming the requirement that went.
REASON_REQUIREMENT_REVOKED = "requires-revoked"
# Reason a live host records when it withdraws a component for a reload.
REASON_WITHDRAWN = "withdrawn"
# Reasons a withdrawal is refused: the component offers nothing to withdraw,
# and this process already withdrew it.
REASON_NOTHING_TO_WITHDRAW = "provides nothing and declares no revert"
REASON_ALREADY_WITHDRAWN = "already withdrawn in this process"
REQUIREMENT_REASONS: dict[str, str] = {
    SEED_LLM: REASON_LLM_UNAVAILABLE,
    SEED_PROJECT: REASON_NO_ENGINE_CONTEXT,
    SEED_ENGINE: REASON_ENGINE_UNAVAILABLE,
}

# Disassembly format `prepare` requests.  It is the format the disassembly
# route caches, so a pipeline run and a `GET /api/functions/<id>/disasm` share
# one cached listing.
DISASM_FORMAT = "nasm"

# Name source `resolve-names` reports for a library-identification proposal.
PREDICTED_NAME_SOURCE_UNSTRIP = "unstrip"
PREDICTED_NAME_SOURCE_MATCH = "match"

# `ai_artifacts` kind the run stores a predicted name under.  It is not an LLM
# artifact kind (llm.AI_KINDS); the store component writes it so a predicted
# name survives the run that produced it.
PREDICTED_NAME_KIND = "predicted-name"

# Artifact name -> `ai_artifacts` kind, for the artifacts a run persists.
ARTIFACT_KINDS: dict[str, str] = {
    NAME_SUMMARY: llm.AI_KIND_SUMMARY,
    NAME_INLINE_COMMENTS: llm.AI_KIND_COMMENTS,
    NAME_TYPE_SUGGESTIONS: llm.AI_KIND_TYPES,
    NAME_PREDICTED_NAME: PREDICTED_NAME_KIND,
}

# Header line `rebrew asm` prints before the listing, and the leading token of a
# line whose operand encoding is not what NASM would emit (rebrew writes the
# original instruction into the trailing comment).
_LISTING_HEADERS = ("bits ", "org ", "section ", "global ", "extern ")
_BYTE_DIRECTIVES = frozenset({"db", "dw", "dd", "dq", "dt"})

# A listing line's trailing `; <hex-va> <bytes or original instruction>`.
_LISTING_COMMENT = re.compile(r";\s*([0-9A-Fa-f]{4,})\s*(.*)$")

# A control-transfer operand that names an address; a register or memory
# operand names no target.
_ADDRESS_OPERAND = re.compile(r"^(0x[0-9A-Fa-f]+)$")
_SIZE_PREFIX = re.compile(r"^(?:short|near|far)\s+", re.IGNORECASE)

# Instructions that end a basic block.
_BLOCK_TERMINATORS = frozenset({"ret", "retn", "retf", "iret", "iretd"})


class StepFailure(RuntimeError):  # noqa: N818  # name fixed by the step contract
    """A component could not complete; its reason is recorded on the step."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class PipelineUnavailable(RuntimeError):  # noqa: N818  # name fixed by the pipeline contract
    """The pipeline itself cannot run: its component composition is unusable.

    A single component's failure is a failed step, recorded on the run; this is
    raised only when the registry cannot be assembled at all, which is the one
    case an API caller sees as 503 instead of a run record.
    """


class NotWithdrawableError(RuntimeError):
    """A component cannot be withdrawn from the live composition.

    ``reason`` names why: the component provides nothing and declares no revert,
    so there is nothing to take back, or this process already withdrew it.
    """

    def __init__(self, name: str, reason: str) -> None:
        self.name = name
        self.reason = reason
        super().__init__(f"component {name!r} cannot be withdrawn: {reason}")


def withdraw_refusal(component: Component) -> str | None:
    """Why *component* cannot be withdrawn, or None when it can.

    A component is withdrawable when it provides at least one name or declares a
    ``revert``; one that does neither has no contribution to take back.
    """
    if component.provides or component.revert is not None:
        return None
    return REASON_NOTHING_TO_WITHDRAW


# ── Activation ─────────────────────────────────────────────────────


def _provider_map(registered: Sequence[Component]) -> dict[str, str]:
    """Return ``provided name -> component name``, first declaration wins."""
    providers: dict[str, str] = {}
    for component in registered:
        for name in component.provides:
            providers.setdefault(name, component.name)
    return providers


def dependency_order(registered: Sequence[Component]) -> list[Component]:
    """Order *registered* so a provider precedes every component needing it.

    Ties keep declaration order, which is what makes the run deterministic: the
    built-in stages are declared in the order the portal reports them.
    """
    providers = _provider_map(registered)
    remaining = list(registered)
    done: set[str] = set()
    order: list[Component] = []
    while remaining:
        ready = [
            component
            for component in remaining
            if all(
                providers.get(name, component.name) == component.name or providers[name] in done
                for name in component.requires
            )
        ]
        chosen = ready[0] if ready else remaining[0]
        remaining.remove(chosen)
        done.add(chosen.name)
        order.append(chosen)
    return order


class _ActivationWatch:
    """The pending components whose requirements hold, re-evaluated on change.

    The loader subscribes this to the context before the first component runs,
    so a component becomes ready the moment its last requirement is bound and
    deactivates the moment one is revoked.  ``pending`` keeps the dependency
    order, which is what keeps activation deterministic: among ready components
    the first in that order runs.
    """

    def __init__(
        self, *, at: Context, pending: Sequence[Component], disabled: frozenset[str]
    ) -> None:
        self._ctx = at
        self._pending: list[Component] = list(pending)
        self._disabled = disabled
        self._ready: set[str] = set()
        self._deactivated: list[tuple[Component, str]] = []

    def on_change(self, name: str, kind: str) -> None:
        """Re-evaluate readiness after *name* changed (a provide, revoke or revert)."""
        self.evaluate()

    def evaluate(self) -> None:
        """Mark pending components ready; deactivate one that lost a requirement.

        A disabled component is never ready.  A component that was never ready
        stays pending, so the final pass can report the provider it is waiting
        on; a component that was ready and is not any more has been deactivated,
        which no later pass would otherwise report.
        """
        for component in list(self._pending):
            if component.name in self._disabled:
                continue
            missing = sorted(name for name in component.requires if not self._ctx.has(name))
            if not missing:
                self._ready.add(component.name)
            elif component.name in self._ready:
                self._ready.discard(component.name)
                self._pending.remove(component)
                self._deactivated.append((component, f"{REASON_REQUIREMENT_REVOKED}:{missing[0]}"))

    def next_component(self) -> Component | None:
        """The first ready component in dependency order, or None."""
        for component in self._pending:
            if component.name in self._ready:
                return component
        return None

    def decide(self, component: Component) -> None:
        """Record that *component* was decided and stop considering it.

        The loader calls this before a component's effect runs, so a component
        that withdraws one of its own requirements is not deactivated by its
        own change.
        """
        self._ready.discard(component.name)
        if component in self._pending:
            self._pending.remove(component)

    def take_deactivated(self) -> list[tuple[Component, str]]:
        """The components deactivated since the last call, with their reasons."""
        taken = self._deactivated
        self._deactivated = []
        return taken

    def pending(self) -> list[Component]:
        """The components not yet decided, in dependency order."""
        return list(self._pending)


def _record_deactivations(
    conn: sqlite3.Connection,
    *,
    run_id: int,
    watch: _ActivationWatch,
    decisions: dict[str, str],
) -> None:
    """Write one `deactivated` step per component that lost a requirement."""
    for component, reason in watch.take_deactivated():
        decisions[component.name] = STEP_DEACTIVATED
        store.add_pipeline_step(
            conn,
            run_id=run_id,
            name=component.name,
            status=STEP_DEACTIVATED,
            reason=reason,
            provides=sorted(component.provides),
        )


def _skip_reason(
    component: Component,
    available: set[str],
    disabled: frozenset[str],
    providers: dict[str, str],
    decisions: dict[str, str],
) -> str | None:
    """Return why *component* cannot run, or None when its requirements hold.

    *decisions* holds the status of every component already decided.  A
    requirement the runner withheld (``llm``, ``project``, ``engine``) reports
    its own reason, which is more specific than the provider it is missing;
    otherwise a requirement whose provider was skipped, failed or deactivated
    is reported with that provider's name.
    """
    if component.name in disabled:
        return REASON_DISABLED
    missing = sorted(name for name in component.requires if name not in available)
    if not missing:
        return None
    dependency_reason: str | None = None
    for name in missing:
        mapped = REQUIREMENT_REASONS.get(name)
        if mapped is not None:
            return mapped
        if dependency_reason is not None:
            continue
        provider = providers.get(name)
        if provider is None or provider == component.name:
            continue
        if decisions.get(provider) == STEP_SKIPPED:
            dependency_reason = f"{REASON_DEPENDENCY_SKIPPED}:{provider}"
        elif decisions.get(provider) == STEP_FAILED:
            dependency_reason = f"{REASON_DEPENDENCY_FAILED}:{provider}"
        elif decisions.get(provider) == STEP_DEACTIVATED:
            dependency_reason = f"{REASON_DEPENDENCY_DEACTIVATED}:{provider}"
    if dependency_reason is not None:
        return dependency_reason
    return f"requires-{missing[0]}"


def configured_disabled() -> frozenset[str]:
    """Component names the workspace ``reportal.toml`` ``[pipeline] disabled`` lists."""
    try:
        with (project_root() / MARKER).open("rb") as handle:
            document = tomllib.load(handle)
    except (WorkspaceNotFound, OSError, tomllib.TOMLDecodeError):
        return frozenset()
    table = document.get("pipeline")
    if not isinstance(table, dict):
        return frozenset()
    names = table.get("disabled")
    if not isinstance(names, list):
        return frozenset()
    return frozenset(name.strip() for name in names if isinstance(name, str) and name.strip())


# ── Listing analysis ───────────────────────────────────────────────


def _instruction_text(body: str, comment_tail: str) -> str:
    """Return the instruction a listing line carries.

    rebrew writes an operand encoding NASM would not echo as ``db <bytes>`` and
    puts the original instruction in the trailing comment, so the comment is
    what names the mnemonic for those lines.
    """
    first = body.split(None, 1)[0].lower() if body else ""
    if first in _BYTE_DIRECTIVES and comment_tail:
        return comment_tail.strip()
    return body


def parse_instructions(listing: str) -> list[tuple[int, str]]:
    """Return ``(va, instruction)`` for every line of a NASM listing."""
    instructions: list[tuple[int, str]] = []
    for raw in listing.splitlines():
        line = raw.split(";", 1)[0]
        body = line.strip()
        if not body or body.startswith(_LISTING_HEADERS) or body.endswith(":"):
            continue
        match = _LISTING_COMMENT.search(raw)
        if match is None:
            continue
        text = _instruction_text(body, match.group(2))
        if not text:
            continue
        instructions.append((int(match.group(1), 16), text))
    return instructions


def _branch(instruction: str) -> tuple[str, int | None] | None:
    """Return ``(kind, target)`` for a control transfer, else None.

    *kind* is ``call``, ``jump`` or ``conditional``; *target* is None for an
    indirect transfer, which names no address.
    """
    parts = instruction.split(None, 1)
    if not parts:
        return None
    opcode = parts[0].lower()
    if opcode == "call":
        kind = "call"
    elif opcode == "jmp":
        kind = "jump"
    elif opcode.startswith("loop") or (opcode.startswith("j") and opcode[1:].isalpha()):
        kind = "conditional"
    else:
        return None
    operand = _SIZE_PREFIX.sub("", parts[1].strip() if len(parts) > 1 else "")
    match = _ADDRESS_OPERAND.match(operand)
    return kind, int(match.group(1), 16) if match else None


def control_flow(instructions: Sequence[tuple[int, str]]) -> dict[str, Any]:
    """Basic-block boundaries and branch targets derived from a listing."""
    if not instructions:
        return {"blocks": [], "branches": [], "block_count": 0, "instruction_count": 0}
    addresses = {va for va, _ in instructions}
    branches: list[dict[str, Any]] = []
    terminators: set[int] = set()
    targets: set[int] = set()
    for position, (va, text) in enumerate(instructions):
        branch = _branch(text)
        if branch is None:
            if text.split(None, 1)[0].lower() in _BLOCK_TERMINATORS:
                terminators.add(position)
            continue
        kind, target = branch
        branches.append({"va": va, "target": target, "kind": kind})
        if target is not None and target in addresses:
            targets.add(target)
        if kind != "call":
            terminators.add(position)

    leaders = {0}
    for position in terminators:
        if position + 1 < len(instructions):
            leaders.add(position + 1)
    for position, (va, _) in enumerate(instructions):
        if va in targets:
            leaders.add(position)
    ordered = sorted(leaders)
    blocks = [
        {
            "start": instructions[start][0],
            "end": instructions[end][0],
            "instructions": end - start + 1,
        }
        for start, end in (
            (start, ordered[index + 1] - 1 if index + 1 < len(ordered) else len(instructions) - 1)
            for index, start in enumerate(ordered)
        )
    ]
    return {
        "blocks": blocks,
        "branches": branches,
        "block_count": len(blocks),
        "instruction_count": len(instructions),
    }


def call_trace(
    conn: sqlite3.Connection,
    function: dict[str, Any],
    instructions: Sequence[tuple[int, str]],
) -> dict[str, Any]:
    """Callees of *function*, named from the stored rows at their address."""
    names = {
        int(row["va"]): str(row["name"])
        for row in store.list_functions(conn, binary_id=int(function["binary_id"]))
    }
    seen: set[int] = set()
    callees: list[dict[str, Any]] = []
    for _, text in instructions:
        branch = _branch(text)
        if branch is None or branch[0] != "call" or branch[1] is None:
            continue
        target = branch[1]
        if target in seen:
            continue
        seen.add(target)
        callees.append({"va": target, "name": names.get(target, "")})
    return {"callees": callees, "count": len(callees)}


# ── Effects ────────────────────────────────────────────────────────


def _record_effect(ctx: Context, conn: sqlite3.Connection, descriptor: dict[str, Any]) -> None:
    """Journal *descriptor* through the shared dispatcher, inverse included."""
    ctx.record(
        describe(descriptor),
        lambda: apply_descriptor(conn, descriptor),
        descriptor,
    )


def _effect_prepare(ctx: Context) -> None:
    """Bind the function row's metadata and its NASM listing."""
    function = ctx.require(SEED_FUNCTION)
    conn = ctx.require(SEED_CONN)
    function_id = int(function["id"])
    ctx.provide(
        NAME_FUNCTION_META,
        {
            "id": function_id,
            "binary_id": int(function["binary_id"]),
            "va": int(function["va"]),
            "size": int(function["size"]),
            "name": str(function["name"]),
            "status": str(function["status"]),
            "name_source": str(function["name_source"]),
        },
    )
    cached = store.get_disasm(conn, function_id)
    if cached is not None:
        ctx.provide(NAME_DISASSEMBLY, cached)
        return
    binary_id = int(function["binary_id"])
    project_dir = store.get_rebrew_context(conn, binary_id)
    if project_dir is None:
        raise StepFailure(REASON_NO_ENGINE_CONTEXT)
    engine = ctx.require(SEED_ENGINE)
    if not engine.available():
        raise StepFailure(REASON_ENGINE_UNAVAILABLE)
    try:
        listing = engine.disassemble(
            project_dir, int(function["va"]), int(function["size"]), DISASM_FORMAT
        )
    except engines.EngineError as exc:
        raise StepFailure(f"engine-error: {exc}") from exc
    store.set_disasm(conn, function_id, listing)
    _record_effect(
        ctx,
        conn,
        {"kind": EFFECT_DISASM, "function_id": function_id},
    )
    ctx.provide(NAME_DISASSEMBLY, listing)


def _effect_read_trace(ctx: Context) -> None:
    """Derive the listing's control flow and its callees."""
    instructions = parse_instructions(ctx.require(NAME_DISASSEMBLY))
    ctx.provide(NAME_CONTROL_FLOW, control_flow(instructions))
    ctx.provide(
        NAME_CALL_TRACE,
        call_trace(ctx.require(SEED_CONN), ctx.require(SEED_FUNCTION), instructions),
    )


def _effect_decompile(ctx: Context) -> None:
    """Bind the function's decompiled C, reusing a stored row when there is one."""
    function = ctx.require(SEED_FUNCTION)
    conn = ctx.require(SEED_CONN)
    project_dir = ctx.require(SEED_PROJECT)
    function_id = int(function["id"])
    stored = store.get_decompilation(conn, function_id)
    if stored is not None:
        ctx.provide(
            NAME_DECOMPILATION,
            {"code": str(stored["code"]), "backend": str(stored["backend"]), "reused": True},
        )
        return
    engine = ctx.require(SEED_ENGINE)
    if not engine.available():
        raise StepFailure(REASON_ENGINE_UNAVAILABLE)
    try:
        result = engine.decompile(
            project_dir, int(function["va"]), engines.DEFAULT_DECOMPILER_BACKEND, False
        )
    except engines.EngineError as exc:
        raise StepFailure(f"engine-error: {exc}") from exc
    code = str(result.get("code") or "")
    backend = str(result.get("backend") or engines.DEFAULT_DECOMPILER_BACKEND)
    store.set_decompilation(conn, function_id, code, backend)
    _record_effect(
        ctx,
        conn,
        {"kind": EFFECT_DECOMPILATION, "function_id": function_id, "previous": None},
    )
    ctx.provide(NAME_DECOMPILATION, {"code": code, "backend": backend, "reused": False})


def _effect_search_functionality(ctx: Context) -> None:
    """Bind the recorded match candidates of the function; no matching is run."""
    function = ctx.require(SEED_FUNCTION)
    conn = ctx.require(SEED_CONN)
    rows = store.list_matches(conn, int(function["id"]))
    candidates = [
        {
            "function_id": int(row["candidate_function_id"]),
            "name": str(row["candidate_name"]),
            "va": int(row["candidate_va"]),
            "similarity": float(row["similarity"]),
            "confidence": float(row["confidence"]),
        }
        for row in rows
    ]
    ctx.provide(
        NAME_SIMILAR_FUNCTIONS,
        {"candidates": candidates, "count": len(candidates), "scored": similarity.available()},
    )


def _unstrip_proposal(
    conn: sqlite3.Connection, binary_id: int, function_id: int
) -> dict[str, Any] | None:
    """The stored auto-unstrip proposal for *function_id*, or None."""
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    if analysis_id is None:
        return None
    scan = store.get_scan(conn, analysis_id, store.SCAN_KIND_UNSTRIP)
    proposals = scan.get("proposals") if isinstance(scan, dict) else None
    if not isinstance(proposals, list):
        return None
    for proposal in proposals:
        if isinstance(proposal, dict) and int(proposal.get("function_id", -1)) == function_id:
            return proposal
    return None


def _effect_resolve_names(ctx: Context) -> None:
    """Bind the predicted name of the function with its evidence.

    A stored auto-unstrip proposal wins over a recorded match candidate; with
    neither, no name is predicted.
    """
    function = ctx.require(SEED_FUNCTION)
    conn = ctx.require(SEED_CONN)
    function_id = int(function["id"])
    proposal = _unstrip_proposal(conn, int(function["binary_id"]), function_id)
    if proposal is not None:
        ctx.provide(
            NAME_PREDICTED_NAME,
            {
                "name": str(proposal.get("proposed_name") or ""),
                "source": PREDICTED_NAME_SOURCE_UNSTRIP,
                "confidence": float(proposal.get("confidence") or 0.0),
                "evidence": {
                    "current_name": str(proposal.get("current_name") or ""),
                    "module": str(proposal.get("module") or ""),
                    "kind": str(proposal.get("kind") or ""),
                },
            },
        )
        return
    best = next(
        (
            row
            for row in store.list_matches(conn, function_id)
            if str(row["candidate_name"]).strip()
        ),
        None,
    )
    if best is None:
        ctx.provide(
            NAME_PREDICTED_NAME,
            {"name": None, "source": "", "confidence": 0.0, "evidence": {}},
        )
        return
    ctx.provide(
        NAME_PREDICTED_NAME,
        {
            "name": str(best["candidate_name"]),
            "source": PREDICTED_NAME_SOURCE_MATCH,
            "confidence": float(best["confidence"]),
            "evidence": {
                "candidate_function_id": int(best["candidate_function_id"]),
                "candidate_va": int(best["candidate_va"]),
                "similarity": float(best["similarity"]),
            },
        },
    )


def _knowledge_query(conn: sqlite3.Connection, function: dict[str, Any]) -> str:
    """The retrieval query for *function*: its name and VA plus any summary.

    A document that names the function or repeats its stored summary ranks
    highest.  The summary is optional: a function without one still searches
    by name and VA.
    """
    parts = [str(function["name"]).strip(), hex(int(function["va"]))]
    summary = store.get_ai_artifact(conn, int(function["id"]), llm.AI_KIND_SUMMARY)
    if summary is not None:
        payload = summary["payload"]
        if isinstance(payload, dict):
            parts.append(str(payload.get("summary") or "").strip())
    return " ".join(part for part in parts if part)


def function_knowledge(conn: sqlite3.Connection, function: dict[str, Any]) -> list[dict[str, Any]]:
    """The knowledge hits of *function*, scoped to its binary and bounded.

    Read-only: the hits are search results over stored documents, so the
    component that provides them journals nothing.
    """
    return knowledge.retrieve(
        conn,
        query=_knowledge_query(conn, function),
        scope_kind=knowledge.SCOPE_KIND_BINARY,
        scope_id=int(function["binary_id"]),
        limit=knowledge.RETRIEVAL_LIMIT,
    )


def _knowledge_context(ctx: Context) -> str:
    """The retrieved citation block to add to a prompt, "" when there is none."""
    hits = ctx.get(NAME_KNOWLEDGE)
    if not isinstance(hits, list):
        return ""
    return knowledge.as_context(hits)


def _effect_retrieve_knowledge(ctx: Context) -> None:
    """Bind the function's scoped knowledge hits; read-only, nothing journaled."""
    hits = function_knowledge(ctx.require(SEED_CONN), ctx.require(SEED_FUNCTION))
    ctx.provide(NAME_KNOWLEDGE, hits)


def _effect_name_variables(ctx: Context) -> None:
    """Ask the configured model for inline comments and type suggestions."""
    code = str(ctx.require(NAME_DECOMPILATION)["code"])
    client = ctx.require(SEED_LLM)
    context = _knowledge_context(ctx)
    try:
        comments = llm.inline_comments(code, client=client, context=context)
        suggestions = llm.suggest_types(code, client=client, context=context)
    except llm.LlmUnavailable as exc:
        raise StepFailure(REASON_LLM_UNAVAILABLE) from exc
    except llm.LlmError as exc:
        raise StepFailure(f"llm-error: {exc}") from exc
    ctx.provide(NAME_INLINE_COMMENTS, comments)
    ctx.provide(NAME_TYPE_SUGGESTIONS, suggestions)


def _effect_summarize(ctx: Context) -> None:
    """Ask the configured model for a one-paragraph summary of the function."""
    code = str(ctx.require(NAME_DECOMPILATION)["code"])
    client = ctx.require(SEED_LLM)
    context = _knowledge_context(ctx)
    try:
        summary = llm.summarize(code, client=client, context=context)
    except llm.LlmUnavailable as exc:
        raise StepFailure(REASON_LLM_UNAVAILABLE) from exc
    except llm.LlmError as exc:
        raise StepFailure(f"llm-error: {exc}") from exc
    ctx.provide(NAME_SUMMARY, summary)


def _model(client: llm.LlmClient | None) -> str:
    """Model name a run records, empty when no usable client was injected."""
    return client.model if client is not None and client.available() else ""


def _persist_decompilation(ctx: Context, conn: sqlite3.Connection, function_id: int) -> None:
    """Store the run's decompilation when the stored row does not already hold it."""
    provided = ctx.get(NAME_DECOMPILATION)
    if not isinstance(provided, dict):
        return
    code = str(provided.get("code") or "")
    previous = store.get_decompilation(conn, function_id)
    if previous is not None and str(previous["code"]) == code:
        return
    store.set_decompilation(conn, function_id, code, str(provided.get("backend") or ""))
    _record_effect(
        ctx,
        conn,
        {
            "kind": EFFECT_DECOMPILATION,
            "function_id": function_id,
            "previous": (
                {"code": str(previous["code"]), "backend": str(previous["backend"])}
                if previous is not None
                else None
            ),
        },
    )


def _persist_artifact(
    ctx: Context,
    conn: sqlite3.Connection,
    function_id: int,
    kind: str,
    payload: dict[str, Any],
    model: str,
) -> None:
    """Store one AI artifact of the run, journaling its inverse."""
    previous = store.get_ai_artifact(conn, function_id, kind)
    store.set_ai_artifact(conn, function_id, kind, payload, model)
    _record_effect(
        ctx,
        conn,
        {
            "kind": EFFECT_AI_ARTIFACT,
            "function_id": function_id,
            "artifact_kind": kind,
            "previous": (
                {"payload": previous["payload"], "model": previous["model"]}
                if previous is not None
                else None
            ),
        },
    )


def _effect_store(ctx: Context) -> None:
    """Persist the artifacts the run produced, journaling each write."""
    function = ctx.require(SEED_FUNCTION)
    conn = ctx.require(SEED_CONN)
    function_id = int(function["id"])
    client = ctx.get(SEED_LLM)
    model = _model(client)
    _persist_decompilation(ctx, conn, function_id)
    for name, kind in ARTIFACT_KINDS.items():
        if name == NAME_PREDICTED_NAME:
            continue
        payload = ctx.get(name)
        if isinstance(payload, dict):
            _persist_artifact(ctx, conn, function_id, kind, payload, model)
    predicted = ctx.get(NAME_PREDICTED_NAME)
    if isinstance(predicted, dict) and predicted.get("name"):
        _persist_artifact(ctx, conn, function_id, PREDICTED_NAME_KIND, predicted, model)


# ── Built-in composition ───────────────────────────────────────────


def builtin_components() -> tuple[Component, ...]:
    """The in-tree stages, in the order the portal reports them."""
    return (
        Component(
            name=COMPONENT_PREPARE,
            requires=frozenset({SEED_FUNCTION}),
            provides=frozenset({NAME_FUNCTION_META, NAME_DISASSEMBLY}),
            effect=_effect_prepare,
        ),
        Component(
            name=COMPONENT_READ_TRACE,
            requires=frozenset({NAME_DISASSEMBLY}),
            provides=frozenset({NAME_CONTROL_FLOW, NAME_CALL_TRACE}),
            effect=_effect_read_trace,
        ),
        Component(
            name=COMPONENT_DECOMPILE,
            requires=frozenset({SEED_FUNCTION, SEED_PROJECT}),
            provides=frozenset({NAME_DECOMPILATION}),
            effect=_effect_decompile,
        ),
        Component(
            name=COMPONENT_SEARCH_FUNCTIONALITY,
            requires=frozenset({SEED_FUNCTION}),
            provides=frozenset({NAME_SIMILAR_FUNCTIONS}),
            effect=_effect_search_functionality,
        ),
        Component(
            name=COMPONENT_RESOLVE_NAMES,
            requires=frozenset({SEED_FUNCTION}),
            provides=frozenset({NAME_PREDICTED_NAME}),
            effect=_effect_resolve_names,
        ),
        Component(
            name=COMPONENT_RETRIEVE_KNOWLEDGE,
            requires=frozenset({SEED_FUNCTION}),
            provides=frozenset({NAME_KNOWLEDGE}),
            effect=_effect_retrieve_knowledge,
        ),
        Component(
            name=COMPONENT_NAME_VARIABLES,
            requires=frozenset({NAME_DECOMPILATION, SEED_LLM}),
            provides=frozenset({NAME_TYPE_SUGGESTIONS, NAME_INLINE_COMMENTS}),
            effect=_effect_name_variables,
        ),
        Component(
            name=COMPONENT_SUMMARIZE,
            requires=frozenset({NAME_DECOMPILATION, SEED_LLM}),
            provides=frozenset({NAME_SUMMARY}),
            effect=_effect_summarize,
        ),
        Component(
            name=COMPONENT_STORE,
            requires=frozenset(),
            provides=frozenset(),
            effect=_effect_store,
        ),
    )


# ── Live composition ───────────────────────────────────────────────


class ComponentHost:
    """A live composition: one context plus the components active in it.

    ``run_pipeline`` reads one registry snapshot, journals into one context and
    returns.  A host stays live instead, so hot module replacement can withdraw
    a component and its dependents, swap the registry entry and run them again
    against the same context.  Deactivation records the ``deactivated``
    decision, calls the component's ``revert(ctx)`` when it declares one, and
    revokes the names it provided so activation re-provides them; activation
    runs a component whose requirements hold and then every component
    downstream that became ready, in dependency order.  ``sync`` re-reads the
    registry after a reload without touching the live context or the active
    set.
    """

    def __init__(
        self,
        values: Mapping[str, Any] | None = None,
        *,
        registered: Sequence[Component] | None = None,
        disabled: Iterable[str] | None = None,
    ) -> None:
        self._ctx = Context(values)
        self._registered: list[Component] = (
            list(registered) if registered is not None else list(components.components())
        )
        self._disabled = frozenset(disabled) if disabled is not None else configured_disabled()
        self._active: list[str] = []
        self._decisions: dict[str, str] = {}
        self._journal: list[dict[str, Any]] = []

    @property
    def context(self) -> Context:
        """The live context the host's components read and write."""
        return self._ctx

    def registered(self) -> tuple[Component, ...]:
        """The composition the host is driving, in declaration order."""
        return tuple(self._registered)

    def active(self) -> tuple[str, ...]:
        """The components currently active, in activation order."""
        return tuple(self._active)

    def decisions(self) -> dict[str, str]:
        """The status recorded per component name."""
        return dict(self._decisions)

    def journal(self) -> list[dict[str, Any]]:
        """The activation and deactivation decisions in the order they happened."""
        return list(self._journal)

    def sync(self) -> tuple[Component, ...]:
        """Re-read the component registry after a reload, keeping the live state."""
        self._registered = list(components.components())
        return tuple(self._registered)

    def activate(self, name: str) -> dict[str, Any]:
        """Run *name* and every downstream component that is ready.

        Raises :class:`KeyError` for a name the composition does not declare.
        Each component is run at most once per call; a downstream component
        whose other requirements are still missing is reported ``skipped`` with
        its reason and stays inactive.
        """
        entries: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for component in (self.component(name), *self._downstream(name)):
            if component.name in self._active:
                continue
            reason = self._unrunnable(component)
            if reason is not None:
                self._decisions[component.name] = STEP_SKIPPED
                skipped.append({"name": component.name, "status": STEP_SKIPPED, "reason": reason})
                continue
            entries.append(self._run(component))
        return {"activated": entries, "skipped": skipped, "active": list(self._active)}

    def deactivate(self, name: str) -> dict[str, Any]:
        """Withdraw *name* and every active component downstream of it.

        Dependents are withdrawn first, in reverse dependency order; the named
        component is withdrawn whether or not this host ever activated it, so a
        component's contribution can be taken back without composing it first.
        The component's ``revert(ctx)`` runs where it declares one and the names
        it provided are revoked.  Raises :class:`KeyError` for an unknown name
        and :class:`NotWithdrawableError` when the component provides nothing
        and declares no revert, or was already withdrawn by this host.
        """
        component = self.component(name)
        refusal = withdraw_refusal(component)
        if refusal is not None:
            raise NotWithdrawableError(name, refusal)
        if self._decisions.get(name) == STEP_DEACTIVATED and name not in self._active:
            raise NotWithdrawableError(name, REASON_ALREADY_WITHDRAWN)
        targets = [item for item in reversed(self._downstream(name)) if item.name in self._active]
        targets.append(component)
        entries: list[dict[str, Any]] = []
        changes: list[str] = []
        for target in targets:
            entries.append(self._withdraw(target))
            changes.extend(self._revoke_outputs(target))
        return {
            "deactivated": entries,
            "context_changes": changes,
            "active": list(self._active),
        }

    def component(self, name: str) -> Component:
        """The composition's component named *name*; raises :class:`KeyError` without one."""
        for component in self._registered:
            if component.name == name:
                return component
        raise KeyError(name)

    def _downstream(self, name: str) -> list[Component]:
        """The components that need *name*'s outputs, directly or transitively."""
        produced = set(self.component(name).provides)
        selected: set[str] = set()
        changed = True
        while changed:
            changed = False
            for component in self._registered:
                if component.name == name or component.name in selected:
                    continue
                if component.requires & produced:
                    selected.add(component.name)
                    produced |= set(component.provides)
                    changed = True
        return [item for item in dependency_order(self._registered) if item.name in selected]

    def _unrunnable(self, component: Component) -> str | None:
        """Why *component* cannot activate now, or None when it can."""
        if component.name in self._disabled:
            return REASON_DISABLED
        if all(self._ctx.has(name) for name in component.requires):
            return None
        return _skip_reason(
            component,
            set(self._ctx.names()),
            self._disabled,
            _provider_map(self._registered),
            self._decisions,
        )

    def _run(self, component: Component) -> dict[str, Any]:
        """Run one component's effect and record the decision it produced."""
        started = time.monotonic()
        try:
            component.effect(self._ctx)
        except Exception as exc:  # a failing component is a failed step, not a failed host
            detail = _failure_reason(exc)
            if component.revert is not None:
                try:
                    component.revert(self._ctx)
                except Exception as revert_exc:
                    detail = f"{detail}; revert: {revert_exc}"
            self._decisions[component.name] = STEP_FAILED
            entry: dict[str, Any] = {
                "name": component.name,
                "status": STEP_FAILED,
                "reason": detail,
                "duration_ms": _duration_ms(started),
            }
        else:
            self._active.append(component.name)
            self._decisions[component.name] = STEP_DONE
            entry = {
                "name": component.name,
                "status": STEP_DONE,
                "reason": "",
                "duration_ms": _duration_ms(started),
            }
        self._journal.append(entry)
        return entry

    def _withdraw(self, component: Component) -> dict[str, Any]:
        """Mark one component inactive, calling its revert when declared."""
        reverted: bool | None = None
        detail = ""
        if component.revert is not None:
            reverted = True
            try:
                component.revert(self._ctx)
            except Exception as exc:  # the withdrawal still happens
                reverted = False
                detail = _failure_reason(exc)
        if component.name in self._active:
            self._active.remove(component.name)
        self._decisions[component.name] = STEP_DEACTIVATED
        entry: dict[str, Any] = {
            "name": component.name,
            "status": STEP_DEACTIVATED,
            "reason": REASON_WITHDRAWN,
            "reverted": reverted,
            "detail": detail,
        }
        self._journal.append(entry)
        return entry

    def _revoke_outputs(self, component: Component) -> list[str]:
        """Revoke the names *component* still has bound, newest dependency first."""
        revoked = sorted(name for name in component.provides if self._ctx.has(name))
        for name in revoked:
            self._ctx.revoke(name)
        return revoked


# ── Live composition ───────────────────────────────────────────────
#
# A withdrawal acts on one process-wide host, so a component this process
# withdrew stays withdrawn until it composes again.  reportal is one process
# over one SQLite file, so there is one live composition to withdraw from.

_live_host: ComponentHost | None = None

# How many run contexts stay resolvable for a binding change.  An evicted run's
# bindings are reported as not applied by a revert, the same answer a later
# process gives; the cap keeps a long-lived server from holding every run's
# context forever.
RUN_CONTEXT_LIMIT = 64
_run_contexts: dict[int, Context] = {}


def live_host() -> ComponentHost:
    """The process-wide live composition a withdrawal acts on, built on first use."""
    global _live_host
    if _live_host is None:
        _live_host = ComponentHost({})
    return _live_host


def reset_live_state() -> None:
    """Drop the live host and every run context this process holds.

    A workspace switch and a test both need a process with no live composition
    and no resolvable run bindings, which is what this gives them.
    """
    global _live_host
    _live_host = None
    _run_contexts.clear()


def withdraw_component(conn: sqlite3.Connection, name: str) -> dict[str, Any]:
    """Withdraw *name* from the live composition and journal what it undid.

    The withdrawal runs against :func:`live_host`: it calls the component's
    ``revert(ctx)`` where it declares one and revokes the names it provided.
    Every durable write the withdrawal records on the context is folded into one
    action-journal entry, so the withdrawal is revertible through the same
    ``revert_journal_entry`` path as every other mutation; a withdrawal whose
    effect is a process-local binding records no entry, which the payload
    reports as ``journaled: false`` with no ``journal_action``.

    Raises :class:`KeyError` for an unknown name and
    :class:`NotWithdrawableError` when the component provides nothing and
    declares no revert, or was already withdrawn by this process.
    """
    host = live_host()
    host.sync()
    host.context.seed(SEED_CONN, conn)
    before = len(host.context.effects())
    payload = host.deactivate(name)
    effects = host.context.effects()[before:]
    with journal.journaled(conn, journal.new_action()) as log:
        for effect in effects:
            if effect.undo is not None:
                log.record(
                    str(effect.undo.get("kind", effect.kind)), effect.description, effect.undo
                )
    return {**log.attach(payload), "name": name, "journaled": log.recorded() > 0}


# ── Runner ─────────────────────────────────────────────────────────


def _failure_reason(exc: BaseException) -> str:
    """The reason a failed step records."""
    if isinstance(exc, StepFailure):
        return exc.reason
    return f"{type(exc).__name__}: {exc}"


def _duration_ms(started: float) -> int:
    """Milliseconds elapsed since a :func:`time.monotonic` reading."""
    return int((time.monotonic() - started) * 1000)


def _stored_plan(ctx: Context) -> list[dict[str, Any]]:
    """The run's stored plan: its durable writes and the bindings it changed.

    A binding change becomes an :data:`reportal.effects.EFFECT_CONTEXT_CHANGE`
    descriptor carrying the name and the direction only.  The value lived in the
    process that made the binding, so a later process has nothing to restore
    from and reports the change as not applied instead of inventing one.
    """
    plan: list[dict[str, Any]] = []
    for effect in ctx.effects():
        if effect.undo is not None:
            plan.append(effect.undo)
        elif effect.kind in (CHANGE_PROVIDE, CHANGE_REVOKE) and effect.name is not None:
            plan.append({"kind": EFFECT_CONTEXT_CHANGE, "change": effect.kind, "name": effect.name})
    return plan


def _store_run_context(run_id: int, ctx: Context) -> None:
    """Keep *ctx* resolvable for a same-process revert, bounded by the cap.

    A revert that runs in this process can take a binding back for real because
    the context that made it is still here; the oldest entry is dropped once the
    cap is reached, which degrades to the later-process answer.
    """
    while len(_run_contexts) >= RUN_CONTEXT_LIMIT:
        _run_contexts.pop(next(iter(_run_contexts)))
    _run_contexts[run_id] = ctx


def run_pipeline(
    conn: sqlite3.Connection,
    *,
    function_id: int,
    engine: engines.RebrewEngine | None = None,
    llm_client: llm.LlmClient | None = None,
    disabled: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Run the AI decompilation pipeline over one function and store the run.

    The context is seeded with the function row, its binary, its rebrew project
    directory (when it has one), the connection, the engine and the LLM client;
    a client that is not configured is not seeded, so every stage requiring
    ``llm`` is skipped with reason ``llm-unavailable``.

    *disabled* names components to skip; None (the default) reads the
    workspace ``reportal.toml`` ``[pipeline] disabled`` list.  Raises
    :class:`KeyError` for an unknown function.

    Returns the stored run with its steps and the function's durable artifacts.
    """
    function = store.get_function(conn, function_id)
    if function is None:
        raise KeyError(f"no function with id {function_id}")
    disabled_names = frozenset(disabled) if disabled is not None else configured_disabled()
    active_engine = engine if engine is not None else engines.get_engine()
    client = llm_client if llm_client is not None else llm.get_client()
    binary_id = int(function["binary_id"])
    project_dir = store.get_rebrew_context(conn, binary_id)

    try:
        registered = components.components()
    except components.RegistryError as exc:
        raise PipelineUnavailable(str(exc)) from exc

    values: dict[str, Any] = {
        SEED_FUNCTION: function,
        SEED_BINARY: store.get_binary(conn, binary_id),
        SEED_CONN: conn,
        SEED_ENGINE: active_engine,
    }
    if project_dir is not None:
        values[SEED_PROJECT] = project_dir
    if client is not None and client.available():
        values[SEED_LLM] = client

    ctx = Context(values)
    run_id = store.create_pipeline_run(conn, function_id=function_id, model=_model(client))
    providers = _provider_map(registered)
    decisions: dict[str, str] = {}
    failed = False
    # Activation is driven by the context, not decided once up front: the
    # watcher re-evaluates after every provide, revoke and revert, so a
    # component runs as soon as its requirements hold and is deactivated if one
    # of them is withdrawn before it ran.
    watch = _ActivationWatch(at=ctx, pending=dependency_order(registered), disabled=disabled_names)
    ctx.subscribe(watch.on_change)
    watch.evaluate()

    while True:
        _record_deactivations(conn, run_id=run_id, watch=watch, decisions=decisions)
        component = watch.next_component()
        if component is None:
            break
        # The running component leaves the pending set before its effect, so a
        # change it makes to the context is evaluated against the others only.
        watch.decide(component)
        started_at = store.now()
        started = time.monotonic()
        try:
            component.effect(ctx)
        except Exception as exc:  # a failing component is a failed step, not a failed run
            detail = _failure_reason(exc)
            if component.revert is not None:
                try:
                    component.revert(ctx)
                except Exception as revert_exc:
                    detail = f"{detail}; revert: {revert_exc}"
            decisions[component.name] = STEP_FAILED
            failed = True
            store.add_pipeline_step(
                conn,
                run_id=run_id,
                name=component.name,
                status=STEP_FAILED,
                reason=detail,
                started_at=started_at,
                finished_at=store.now(),
                duration_ms=_duration_ms(started),
                provides=sorted(component.provides),
            )
            continue
        decisions[component.name] = STEP_DONE
        store.add_pipeline_step(
            conn,
            run_id=run_id,
            name=component.name,
            status=STEP_DONE,
            started_at=started_at,
            finished_at=store.now(),
            duration_ms=_duration_ms(started),
            provides=sorted(component.provides),
        )

    _record_deactivations(conn, run_id=run_id, watch=watch, decisions=decisions)
    available = set(ctx.names())
    for component in watch.pending():
        reason = _skip_reason(component, available, disabled_names, providers, decisions)
        decisions[component.name] = STEP_SKIPPED
        store.add_pipeline_step(
            conn,
            run_id=run_id,
            name=component.name,
            status=STEP_SKIPPED,
            reason=cast(str, reason),
            provides=sorted(component.provides),
        )

    store.finish_pipeline_run(
        conn,
        run_id,
        status=RUN_FAILED if failed else RUN_DONE,
        effects=_stored_plan(ctx),
    )
    _store_run_context(run_id, ctx)
    stored = store.get_pipeline_run(conn, run_id)
    if stored is None:  # the row was written above; a missing one is a store fault
        raise RuntimeError(f"pipeline run {run_id} was not persisted")
    return run_payload(conn, stored)


def run_payload(conn: sqlite3.Connection, run: dict[str, Any]) -> dict[str, Any]:
    """A stored run with the function's durable artifacts attached."""
    return {**run, "artifacts": stored_artifacts(conn, int(run["function_id"]))}


def stored_artifacts(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    """The function's durable artifacts as a run's result view reads them."""
    decompilation = store.get_decompilation(conn, function_id)
    artifacts: dict[str, Any] = {
        "decompilation": (
            {"code": str(decompilation["code"]), "backend": str(decompilation["backend"])}
            if decompilation is not None
            else None
        ),
        "summary": None,
        "inline_comments": None,
        "type_suggestions": None,
        "predicted_name": None,
    }
    for name, kind in ARTIFACT_KINDS.items():
        artifact = store.get_ai_artifact(conn, function_id, kind)
        if artifact is not None:
            artifacts[name] = dict(artifact["payload"])
    return artifacts


def _revert_context_changes(
    live: Context | None, changes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Report the binding changes a revert walked, applying them where it can.

    *live* is the run's context when this process still holds it.  A change it
    can resolve is taken off that context for real and ``applied`` is true; one
    this process cannot resolve, or a plan replayed by a later process that
    never held it, is reported with ``applied`` false and never claimed as
    restored.
    """
    reported: list[dict[str, Any]] = []
    for descriptor in reversed(changes):
        name = str(descriptor.get("name", ""))
        change = str(descriptor.get("change", ""))
        applied = live is not None and live.take_binding_change(change, name)
        if applied:
            detail = ""
        elif live is None:
            detail = "binding is process-local and the process that made it is gone"
        else:
            detail = "the live context no longer journals this binding"
        reported.append({"name": name, "change": change, "applied": applied, "detail": detail})
    return reported


def revert_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any]:
    """Undo the writes a stored run journaled through the context, newest first.

    The run's durable descriptors are journaled on a context in their original
    order, so :meth:`reportal.components.Context.revert` walks them newest-first
    and each inverse goes through the shared dispatcher.  The plan is consumed
    by the call, so a second revert has nothing left to undo.

    The report is honest about what the pass covered.  ``reverted`` is the
    durable writes; ``context_changes`` names the bindings the run changed,
    each with whether this process applied it.  A binding this process still
    holds is revoked or restored for real; one a later process cannot resolve
    is reported ``applied: false``, never claimed as restored.  Raises
    :class:`KeyError` for an unknown run.
    """
    run = store.get_pipeline_run(conn, run_id)
    if run is None:
        raise KeyError(f"no pipeline run with id {run_id}")
    durable = [item for item in run["effects"] if item.get("kind") != EFFECT_CONTEXT_CHANGE]
    changes = [item for item in run["effects"] if item.get("kind") == EFFECT_CONTEXT_CHANGE]
    ctx = effects.plan_context(conn, durable)
    undone = ctx.revert()
    context_changes = _revert_context_changes(_run_contexts.pop(run_id, None), changes)
    store.set_pipeline_effects(conn, run_id, [])
    return {
        "run_id": run_id,
        "function_id": int(run["function_id"]),
        "reverted": undone,
        "context_changes": context_changes,
        "applied": sum(1 for entry in undone if entry["status"] == EFFECT_REVERTED),
        "failed": sum(1 for entry in undone if entry["status"] == EFFECT_FAILED),
    }


def latest_run(conn: sqlite3.Connection, function_id: int) -> dict[str, Any] | None:
    """The newest stored run of *function_id* with its artifacts, or None."""
    run = store.latest_pipeline_run(conn, function_id)
    return run_payload(conn, run) if run is not None else None
