"""Local function matching over the whole portal corpus.

For every function of a binary, :func:`match_binary` compares its assembly
listing against the candidate corpus, keeps the best candidates above a
similarity floor, and records them in the ``matches`` table with a softmax
confidence.  This is the local equivalent of the hosted portal's
function-matching results.

A run is shaped by :class:`MatchSettings`, the scope the hosted portal's Match
Settings sheet exposes: a minimum similarity, a minimum confidence, whether the
binary's own functions may be candidates, a platform and architecture filter,
and a restriction to a set of binaries or collections.  Every documented
setting has a default that reproduces the run from before the settings existed,
and a value outside its range or its closed vocabulary is refused rather than
coerced.  The settings a run used are stored on every row it records, so a
later reader can tell which run produced those rows, and each row also
stores the ISA pair of the two binaries.

:func:`transfer_matches` copies a candidate's name, signature, or both onto a
target function, for one row or a batch, journaling every row it writes so the
whole action reverts as one journal entry.

Scoring and disassembly are injected.  The scorer defaults to
:func:`reportal.similarity.similarity`; the disassembler defaults to a
cache-backed adapter over the binary's rebrew project context, so a second
run reads ``disasm_cache`` instead of spawning the engine again.

Scaling: scoring stays pairwise over the candidate corpus, so a run makes
``len(functions) * (len(corpus) - 1)`` ratio comparisons and that count grows
with the square of the corpus size.  :func:`reportal.similarity.similarity`
prepares each distinct listing once per process, which removes the repeated
tokenization and MinHash work but not the pairwise term.  The default scorer is
preceded by an exact prefilter: a pair whose MinHash Jaccard is below the floor
``min_similarity`` implies (see :func:`reportal.similarity.jaccard_floor`)
cannot reach that threshold, because the text-ratio term is capped, so the full
score is never computed for it.  That removes most of the pairwise cost without
changing a single recorded row; the prefilter applies to the default blended
scorer only, since the floor is derived from its weights.  LSH banding over the
packed fingerprints is the lever beyond it, for a threshold low enough that the
Jaccard floor proves nothing.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from reportal import engines, journal, similarity, store

# Default similarity floor, confidence floor, self-candidate permission and
# candidate cap, mirrored by the CLI, the API and the MCP tool.  The defaults
# reproduce the run from before the settings existed: the binary's own
# functions are candidates, no confidence floor and no scope restriction.
DEFAULT_MIN_SIMILARITY = 80.0
DEFAULT_MIN_CONFIDENCE = 0.0
DEFAULT_INCLUDE_SELF = True
DEFAULT_TOP = 10

# Validated bounds for the two thresholds.  A similarity is a percentage and a
# softmax confidence is a fraction, so a value outside its range is a request
# error rather than a run whose scope nobody can predict.
MIN_SIMILARITY_RANGE = (0.0, 100.0)
MIN_CONFIDENCE_RANGE = (0.0, 1.0)

# Platform labels the settings sheet offers.  Android and Linux ship the same
# ELF format tokens and the stored columns cannot tell the two apart, so both
# map onto the same set (see PLATFORM_FORMATS).
PLATFORM_WINDOWS = "windows"
PLATFORM_LINUX = "linux"
PLATFORM_ANDROID = "android"
PLATFORMS: tuple[str, ...] = (PLATFORM_WINDOWS, PLATFORM_LINUX, PLATFORM_ANDROID)

# Architecture labels, mapped onto the arch tokens a stored binary carries.
ARCHITECTURE_X86_64 = "x86_64"
ARCHITECTURE_X86_32 = "x86_32"
ARCHITECTURE_ARM64 = "arm64"
ARCHITECTURES: tuple[str, ...] = (ARCHITECTURE_X86_64, ARCHITECTURE_X86_32, ARCHITECTURE_ARM64)

# Format tokens each platform covers.  The tokens are compared case-folded
# against the fingerprint's header-derived `format` when one is stored, else
# the suffix-derived `format` column.  Android's entry repeats Linux's because
# the stored evidence cannot separate an Android module from a Linux one.
PLATFORM_FORMATS: dict[str, frozenset[str]] = {
    PLATFORM_WINDOWS: frozenset({"pe", "exe", "dll", "sys", "ocx", "cpl", "scr", "ne", "dos"}),
    PLATFORM_LINUX: frozenset({"elf", "so", "o", "bin"}),
    PLATFORM_ANDROID: frozenset({"elf", "so", "o", "bin"}),
}

# Arch tokens each architecture label covers, matched case-folded.
ARCHITECTURE_TOKENS: dict[str, frozenset[str]] = {
    ARCHITECTURE_X86_64: frozenset({"x86_64", "x64", "amd64"}),
    ARCHITECTURE_X86_32: frozenset({"x86_32", "x86", "i386", "i486", "i586", "i686"}),
    ARCHITECTURE_ARM64: frozenset({"aarch64", "arm64"}),
}

# Caveat a run with a platform or architecture scope carries.  The stored
# columns are suffix-derived best effort and the fingerprint carries the
# header-derived values, so the filter is coarse: it can exclude a binary whose
# stored evidence says another platform, and it cannot prove a candidate runs
# on the platform it admits.
PLATFORM_SCOPE_NOTE = (
    "the platform/architecture scope matches a binary's stored fingerprint when it has one,"
    " else its suffix-derived format/arch columns, so it is a coarse filter, not a guarantee"
)
ANDROID_SCOPE_NOTE = (
    "Android and Linux share the stored ELF tokens, so an Android-only selection also admits"
    " Linux ELF candidates"
)

# Transfer modes the apply path accepts.  `name` is the behaviour from before
# the modes existed; `both` writes the name and the signature in one action.
TRANSFER_MODE_NAME = "name"
TRANSFER_MODE_SIGNATURE = "signature"
TRANSFER_MODE_BOTH = "both"
TRANSFER_MODES: tuple[str, ...] = (TRANSFER_MODE_NAME, TRANSFER_MODE_SIGNATURE, TRANSFER_MODE_BOTH)
DEFAULT_TRANSFER_MODE = TRANSFER_MODE_NAME

# Ids one bulk transfer request may carry, mirroring bulk_actions.MAX_BULK_IDS.
MAX_TRANSFERS = 500

# The `matches` rows one binary's run replaces: every match whose source is a
# function of that binary.  The routes, the CLI, the MCP tool and a queued job
# all snapshot through this one scope, so a revert puts the same set back.
MATCHES_WHERE = (
    "function_id IN (SELECT f.id FROM functions f JOIN analyses a ON a.id = f.analysis_id"
    " WHERE a.binary_id = ?)"
)

# Per-row statuses the bulk report and the single route use.
TRANSFER_STATUS_APPLIED = "applied"
TRANSFER_STATUS_SKIPPED = "skipped"
TRANSFER_STATUS_FAILED = "failed"

# Failure reason codes, stable across the route, the CLI and the MCP tool.
REASON_UNKNOWN_FUNCTION = "unknown-function"
REASON_UNKNOWN_CANDIDATE = "unknown-candidate"
REASON_OUT_OF_BINARY = "not-in-binary"
REASON_NO_SUCH_MATCH = "no-such-match"
REASON_CANDIDATE_HAS_NO_NAME = "candidate-has-no-name"
REASON_CANDIDATE_HAS_NO_SIGNATURE = "candidate-has-no-signature"
REASON_SIGNATURE_CONFLICT = "signature-conflict"
REASON_WRITE_FAILED = "write-failed"

# The HTTP status and stable error name the single-transfer route answers per
# failure reason.  The bulk route reports the same reasons per row instead of
# failing the request, and the MCP tool raises the error name.
TRANSFER_FAILURE_RESPONSE: dict[str, tuple[int, str]] = {
    REASON_UNKNOWN_FUNCTION: (404, "function not found"),
    REASON_UNKNOWN_CANDIDATE: (404, "candidate not found"),
    REASON_OUT_OF_BINARY: (404, "function not found"),
    REASON_NO_SUCH_MATCH: (400, "no-such-match"),
    REASON_CANDIDATE_HAS_NO_NAME: (400, "candidate-has-no-name"),
    REASON_CANDIDATE_HAS_NO_SIGNATURE: (400, "candidate-has-no-signature"),
    REASON_SIGNATURE_CONFLICT: (409, "signature-conflict"),
    REASON_WRITE_FAILED: (500, "write-failed"),
}

# Source recorded on the rename and the signature-history row a transfer
# appends, so both are traceable to the match they came from.
TRANSFER_SOURCE = "match"

# Decimals a derived difference metric is rounded to, matching the similarity
# scores stored to one decimal.
DIFFERENCE_DECIMALS = 1

# C words that spell a primitive type or a qualifier rather than a local type.
# A declaration that references no other identifier is not a reference to a
# type the local model has to know about.
_TYPE_WORDS: frozenset[str] = frozenset(
    {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "unsigned",
        "const",
        "volatile",
        "struct",
        "union",
        "enum",
        "bool",
        "_Bool",
        "size_t",
        "wchar_t",
        "wint_t",
        "__int8",
        "__int16",
        "__int32",
        "__int64",
    }
)

# A trailing array dimension, stripped before a referenced type name is read.
_ARRAY_SUFFIX_RE = re.compile(r"\[[^\]]*\]")

# A function row (store.list_functions) -> its assembly text, or None when the
# function cannot be disassembled.
Disassembler = Callable[[dict[str, Any]], str | None]
Scorer = Callable[[str, str], float]


class InvalidSettingsError(ValueError):
    """A match request is outside the documented vocabulary or bounds.

    ``error`` is the stable code the API and the MCP tool answer with and
    ``detail`` the human sentence, so each caller maps it without inventing a
    second vocabulary.
    """

    def __init__(self, error: str, detail: str) -> None:
        super().__init__(detail)
        self.error = error
        self.detail = detail


@dataclass(frozen=True)
class MatchSettings:
    """The scope one match run uses.

    Every field has a default that reproduces the run from before the settings
    existed, so an omitted key never narrows the corpus.
    """

    min_similarity: float = DEFAULT_MIN_SIMILARITY
    min_confidence: float = DEFAULT_MIN_CONFIDENCE
    include_self: bool = DEFAULT_INCLUDE_SELF
    top: int = DEFAULT_TOP
    platforms: tuple[str, ...] = ()
    architectures: tuple[str, ...] = ()
    binary_ids: tuple[int, ...] = ()
    collection_ids: tuple[int, ...] = ()

    def payload(self) -> dict[str, Any]:
        """The settings as the JSON object stored on every recorded row."""
        return {
            "min_similarity": self.min_similarity,
            "min_confidence": self.min_confidence,
            "include_self": self.include_self,
            "top": self.top,
            "platforms": list(self.platforms),
            "architectures": list(self.architectures),
            "binary_ids": list(self.binary_ids),
            "collection_ids": list(self.collection_ids),
        }

    @classmethod
    def from_request(cls, body: Mapping[str, Any]) -> MatchSettings:
        """Parse and validate a request body into settings.

        Raises :class:`InvalidSettingsError` for a value outside its range or
        its closed vocabulary; an omitted key takes its documented default.
        """
        min_similarity = _request_number(body, "min_similarity", DEFAULT_MIN_SIMILARITY)
        _require_range("min_similarity", min_similarity, MIN_SIMILARITY_RANGE)
        min_confidence = _request_number(body, "min_confidence", DEFAULT_MIN_CONFIDENCE)
        _require_range("min_confidence", min_confidence, MIN_CONFIDENCE_RANGE)
        top = _request_int(body, "top", DEFAULT_TOP)
        if top < 1:
            raise InvalidSettingsError("top must be positive", "top is at least 1")
        return cls(
            min_similarity=min_similarity,
            min_confidence=min_confidence,
            include_self=_request_bool(body, "include_self", DEFAULT_INCLUDE_SELF),
            top=top,
            platforms=_request_choices(body, "platforms", "platform", PLATFORMS),
            architectures=_request_choices(body, "architectures", "architecture", ARCHITECTURES),
            binary_ids=_request_ids(body, "binary_ids"),
            collection_ids=_request_ids(body, "collection_ids"),
        )


@dataclass(frozen=True)
class TransferRequest:
    """One row of a bulk transfer: a target function, its candidate and a mode."""

    function_id: int
    candidate_function_id: int
    mode: str = DEFAULT_TRANSFER_MODE


@dataclass(frozen=True)
class TransferPlan:
    """What one symbol transfer changes, computed before any write.

    A planned transfer with status ``applied`` carries the name to write and,
    for a signature mode, the signature row to store.  ``missing_types`` names
    the local types the candidate's signature references that the target's
    binary has no data-type row for; the transfer still writes the signature,
    and the response reports them instead of dropping them silently.
    """

    function_id: int
    candidate_function_id: int
    mode: str
    status: str
    reason: str
    detail: str
    old_name: str
    new_name: str
    renames: bool
    signature: dict[str, Any] | None
    writes_signature: bool
    missing_types: tuple[str, ...]


def _request_number(body: Mapping[str, Any], key: str, default: float) -> float:
    """Return ``body[key]`` as a float, or raise for a non-number."""
    value = body.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidSettingsError(f"{key} must be a number", f"{key} must be a number")
    return float(value)


def _request_int(body: Mapping[str, Any], key: str, default: int) -> int:
    """Return ``body[key]`` as an int, or raise for a non-integer."""
    value = body.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidSettingsError(f"{key} must be an integer", f"{key} must be an integer")
    return value


def _request_bool(body: Mapping[str, Any], key: str, default: bool) -> bool:
    """Return ``body[key]`` as a boolean, or raise for a non-boolean."""
    value = body.get(key, default)
    if not isinstance(value, bool):
        raise InvalidSettingsError(f"{key} must be a boolean", f"{key} must be a boolean")
    return value


def _require_range(key: str, value: float, bounds: tuple[float, float]) -> None:
    """Raise when *value* is outside the inclusive *bounds*."""
    low, high = bounds
    if not low <= value <= high:
        raise InvalidSettingsError(f"invalid {key}", f"{key} is between {low:g} and {high:g}")


def _request_choices(
    body: Mapping[str, Any], key: str, label: str, allowed: Sequence[str]
) -> tuple[str, ...]:
    """Return a validated, de-duplicated selection from a closed vocabulary."""
    value = body.get(key, ())
    if not isinstance(value, (list, tuple)):
        raise InvalidSettingsError(f"{key} must be a list of strings", f"{key} must be a list")
    chosen: list[str] = []
    for item in value:
        token = item.strip().lower() if isinstance(item, str) else ""
        if token not in allowed:
            raise InvalidSettingsError(
                f"invalid {label}",
                f"unknown {label}: {item}; expected one of {', '.join(allowed)}",
            )
        if token not in chosen:
            chosen.append(token)
    return tuple(chosen)


def _request_ids(body: Mapping[str, Any], key: str) -> tuple[int, ...]:
    """Return a validated, de-duplicated list of ids from ``body[key]``."""
    value = body.get(key, ())
    if not isinstance(value, (list, tuple)):
        raise InvalidSettingsError(f"{key} must be a list of integers", f"{key} must be a list")
    ids: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            raise InvalidSettingsError(
                f"{key} must be a list of integers", f"{key} must be a list of integers"
            )
        if item not in ids:
            ids.append(item)
    return tuple(ids)


def parse_transfers(body: Mapping[str, Any]) -> tuple[TransferRequest, ...]:
    """Parse and validate the bulk route's ``transfers`` list.

    Raises :class:`InvalidSettingsError` for a missing or empty list, a list
    past :data:`MAX_TRANSFERS`, a row that is not an object, a non-integer id
    or an unknown mode.
    """
    raw = body.get("transfers")
    if not isinstance(raw, (list, tuple)) or not raw:
        raise InvalidSettingsError("transfers must be a non-empty list", "transfers must be a list")
    if len(raw) > MAX_TRANSFERS:
        raise InvalidSettingsError(
            "too many transfers", f"at most {MAX_TRANSFERS} transfers per request"
        )
    requests: list[TransferRequest] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise InvalidSettingsError("invalid transfer", f"transfers[{index}] must be an object")
        mode = entry.get("mode", DEFAULT_TRANSFER_MODE)
        if not isinstance(mode, str) or mode not in TRANSFER_MODES:
            raise InvalidSettingsError(
                "invalid mode",
                f"unknown mode: {mode}; expected one of {', '.join(TRANSFER_MODES)}",
            )
        requests.append(
            TransferRequest(
                function_id=_entry_int(entry, "function_id", index),
                candidate_function_id=_entry_int(entry, "candidate_function_id", index),
                mode=mode,
            )
        )
    return tuple(requests)


def _entry_int(entry: Mapping[str, Any], key: str, index: int) -> int:
    """Return a transfer row's integer *key*, or raise a named 400."""
    value = entry.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidSettingsError(
            "invalid transfer", f"transfers[{index}].{key} must be an integer"
        )
    return value


def scope_notes(settings: MatchSettings) -> list[str]:
    """The caveats a run with these settings carries, for its response."""
    if not settings.platforms and not settings.architectures:
        return []
    notes = [PLATFORM_SCOPE_NOTE]
    if PLATFORM_ANDROID in settings.platforms:
        notes.append(ANDROID_SCOPE_NOTE)
    return notes


def _collection_binary_ids(conn: sqlite3.Connection, collection_ids: Sequence[int]) -> set[int]:
    """The binary ids the given collections hold.

    ``store`` owns the join table's DDL and its per-collection writers; the
    match scope is the only reader that needs the members of several
    collections at once, so it reads the join table directly with bound ids.
    """
    placeholders = ", ".join("?" for _ in collection_ids)
    cursor = conn.execute(
        f"SELECT binary_id FROM collection_binaries WHERE collection_id IN ({placeholders})",
        tuple(collection_ids),
    )
    return {int(row["binary_id"]) for row in cursor.fetchall()}


def resolve_scope(
    conn: sqlite3.Connection,
    settings: MatchSettings,
    visible_to: Mapping[str, Any] | None = None,
) -> frozenset[int]:
    """The candidate binary ids a run may draw from, validating the named ids.

    An empty binary and collection scope means the whole register, reported as
    an empty set.  A named id no row carries raises
    :class:`InvalidSettingsError`.  ``visible_to`` narrows both the default
    register and any named scope to binaries the caller may see, like the
    other scoped reads; a named id outside it is refused as unknown, so the
    run never confirms that it exists.
    """
    from reportal import auth

    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    visible: set[int] | None = None
    if scope is not None:
        clause, params = scope
        visible = {
            int(row["id"])
            for row in conn.execute(f"SELECT b.id AS id FROM binaries b WHERE {clause}", params)
        }
    allowed: set[int] = set()
    named = bool(settings.binary_ids or settings.collection_ids)
    for binary_id in settings.binary_ids:
        if store.get_binary(conn, binary_id) is None or (
            visible is not None and binary_id not in visible
        ):
            raise InvalidSettingsError("unknown binary", f"no binary with id {binary_id}")
        allowed.add(binary_id)
    if settings.collection_ids:
        for collection_id in settings.collection_ids:
            if store.get_collection(conn, collection_id) is None:
                raise InvalidSettingsError(
                    "unknown collection", f"no collection with id {collection_id}"
                )
        allowed |= _collection_binary_ids(conn, settings.collection_ids)
        if visible is not None:
            allowed &= visible
    elif visible is not None and not named:
        allowed = set(visible)
    elif visible is not None:
        allowed &= visible
    return frozenset(allowed)


def _token(source: Mapping[str, Any] | None, key: str) -> str:
    """The trimmed, case-folded value of ``source[key]``, or the empty string."""
    if source is None:
        return ""
    return str(source.get(key) or "").strip().lower().lstrip(".")


def _binary_format_arch(
    conn: sqlite3.Connection, binary_id: int, cache: dict[int, tuple[str, str]]
) -> tuple[str, str]:
    """The ``(format, arch)`` tokens a binary's scope filter compares.

    The stored fingerprint's header-derived values win over the suffix-derived
    ``format``/``arch`` columns, so a run filters on the better evidence when
    the engine has written one.
    """
    cached = cache.get(binary_id)
    if cached is not None:
        return cached
    fingerprint = store.get_fingerprint(conn, binary_id)
    binary = store.get_binary(conn, binary_id)
    fmt = _token(fingerprint, "format") or _token(binary, "format")
    arch = _token(fingerprint, "arch") or _token(binary, "arch")
    resolved = (fmt, arch)
    cache[binary_id] = resolved
    return resolved


def _in_platform_architecture_scope(
    conn: sqlite3.Connection,
    binary_id: int,
    settings: MatchSettings,
    cache: dict[int, tuple[str, str]],
) -> bool:
    """Whether one binary's stored evidence falls inside the platform/arch scope."""
    if not settings.platforms and not settings.architectures:
        return True
    fmt, arch = _binary_format_arch(conn, binary_id, cache)
    platform_ok = not settings.platforms or any(
        fmt in PLATFORM_FORMATS[platform] for platform in settings.platforms
    )
    architecture_ok = not settings.architectures or any(
        arch in ARCHITECTURE_TOKENS[architecture] for architecture in settings.architectures
    )
    return platform_ok and architecture_ok


def cached_disassembler(conn: sqlite3.Connection, engine: engines.RebrewEngine) -> Disassembler:
    """Return a disassembler that reads and fills ``disasm_cache``.

    A function without a rebrew context, or whose engine call fails, yields
    None instead of aborting the run: one unresolvable function must not cost
    the whole corpus its matches.
    """

    def disassemble(function: dict[str, Any]) -> str | None:
        function_id = int(function["id"])
        cached = store.get_disasm(conn, function_id)
        if cached is not None:
            return cached
        project_dir = store.get_rebrew_context(conn, int(function["binary_id"]))
        if project_dir is None:
            return None
        extent_size = int(function["size"])
        try:
            text = engine.disassemble(project_dir, int(function["va"]), extent_size)
        except engines.EngineError:
            return None
        store.set_disasm(conn, function_id, text, extent_size=extent_size, project_dir=project_dir)
        return text

    return disassemble


def journaled_match(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    settings: MatchSettings,
    engine: engines.RebrewEngine,
    progress: Callable[[int, int], None] | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one binary's match inside a journaled action; the one write path.

    The binary's previous matches are snapshotted before the run and the rows it
    creates are journaled after, so reverting the returned ``journal_action``
    puts the earlier set back.  The routes, the CLI and the MCP tool call this,
    and so does a queued job, which is what makes a background run as revertible
    as a direct one.
    """
    resolve_scope(conn, settings, visible_to=visible_to)
    action = journal.new_action()
    with journal.journaled(conn, action) as log:
        before = journal.journaled_rows(
            conn,
            log,
            table="matches",
            where=MATCHES_WHERE,
            params=(binary_id,),
            description=f"replaced the matches of binary {binary_id}",
        )
        summary = match_binary(
            conn,
            binary_id=binary_id,
            engine=engine,
            settings=settings,
            progress=progress,
            visible_to=visible_to,
        )
        journal.journaled_new_rows(
            conn,
            log,
            table="matches",
            where=MATCHES_WHERE,
            params=(binary_id,),
            before=before,
            key=("id",),
            description=f"recorded a match of binary {binary_id}",
        )
    return log.attach(
        {
            **summary,
            "binary_id": binary_id,
            "settings": settings.payload(),
            "notes": scope_notes(settings),
        }
    )


def match_binary(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
    engine: engines.RebrewEngine,
    disassembler: Disassembler | None = None,
    scorer: Scorer | None = None,
    settings: MatchSettings | None = None,
    progress: Callable[[int, int], None] | None = None,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, int]:
    """Match every function of *binary_id* against the candidate corpus.

    Writes at most ``settings.top`` candidates per source function whose
    similarity clears ``settings.min_similarity`` and whose softmax confidence
    clears ``settings.min_confidence``, replacing that function's previous
    rows.  The candidate corpus is the whole register unless the settings name
    binaries, collections, platforms or architectures; the binary's own
    functions are candidates only while ``settings.include_self``, and the
    source function is never its own candidate.  Every recorded row carries the
    settings that produced it and the ISA pair of the two binaries.

    The confidence floor filters after the softmax over the similarity-floor
    survivors, so it drops candidates without re-ranking the ones it keeps.
    Returns ``{"functions", "matched", "pairs"}`` counts and raises
    :class:`InvalidSettingsError` for a scope id no row carries.

    *progress* is called with ``(done, total)`` after each source function, the
    one granularity a run has: the disassembly it reads is cached and the
    scoring loop is this module's, while the engine calls themselves are not
    interruptible.  A queued run turns that into a job's progress.
    """
    resolved = settings if settings is not None else MatchSettings()
    default_scorer = scorer is None
    if scorer is None:
        if not similarity.available():
            raise similarity.SimilarityUnavailable(
                "function matching requires the optional 'similarity' extra"
                " (uv sync --extra similarity)"
            )
        scorer = similarity.similarity
    if disassembler is None:
        disassembler = cached_disassembler(conn, engine)
    # The floor is a proof, not a heuristic, and it holds only for the blended
    # scorer whose weights it comes from, so a caller's own scorer is scored
    # without it.
    floor = similarity.jaccard_floor(resolved.min_similarity) if default_scorer else 0.0

    allowed = resolve_scope(conn, resolved, visible_to=visible_to)
    scoped = bool(resolved.binary_ids or resolved.collection_ids or visible_to is not None)
    scope_cache: dict[int, tuple[str, str]] = {}
    sources = store.list_functions(conn, binary_id=binary_id)
    if scoped:
        candidate_binary_ids = set(allowed)
    else:
        candidate_binary_ids = {int(row["id"]) for row in conn.execute("SELECT id FROM binaries")}
    if not resolved.include_self:
        candidate_binary_ids.discard(binary_id)
    candidate_binary_ids = {
        bid
        for bid in candidate_binary_ids
        if _in_platform_architecture_scope(conn, bid, resolved, scope_cache)
    }
    # Unscoped and unfiltered: one full scan beats one query per binary.
    # Scoped or platform/arch filtered: load only the binaries that remain.
    if not scoped and not resolved.platforms and not resolved.architectures:
        functions = store.list_functions(conn)
        candidates = [
            function
            for function in functions
            if resolved.include_self or int(function["binary_id"]) != binary_id
        ]
    else:
        candidates = []
        for bid in candidate_binary_ids:
            if bid == binary_id:
                candidates.extend(sources)
            else:
                candidates.extend(store.list_functions(conn, binary_id=bid))
    # A scope that admits no candidate leaves nothing to score, so the run only
    # clears the sources' rows; disassembling them would be work with no reader.
    texts: dict[int, str | None] = {}
    if candidates:
        relevant = {int(function["id"]): function for function in (*sources, *candidates)}
        texts = {function_id: disassembler(function) for function_id, function in relevant.items()}
    candidate_ids = [int(function["id"]) for function in candidates]
    function_binary = {
        int(function["id"]): int(function["binary_id"]) for function in (*sources, *candidates)
    }
    payload = resolved.payload()
    summary = {"functions": len(sources), "matched": 0, "pairs": 0}

    total = len(sources)
    for index, source in enumerate(sources, start=1):
        source_id = int(source["id"])
        store.clear_matches_for(conn, source_id)
        source_text = texts.get(source_id)
        if not source_text:
            if progress is not None:
                progress(index, total)
            continue
        scored: list[tuple[float, int]] = []
        for candidate_id in candidate_ids:
            if candidate_id == source_id:
                continue
            candidate_text = texts.get(candidate_id)
            if not candidate_text:
                continue
            if floor > 0.0 and similarity.jaccard(source_text, candidate_text) < floor:
                continue
            scored.append((scorer(source_text, candidate_text), candidate_id))
        scored.sort(key=lambda item: item[0], reverse=True)
        kept = [
            (score, candidate_id)
            for score, candidate_id in scored
            if score >= resolved.min_similarity
        ][: resolved.top]
        confidences = similarity.confidence_scores([score for score, _ in kept])
        recorded = 0
        for (score, candidate_id), confidence in zip(kept, confidences, strict=True):
            if confidence < resolved.min_confidence:
                continue
            store.record_match(
                conn,
                function_id=source_id,
                candidate_function_id=candidate_id,
                similarity=score,
                confidence=confidence,
                settings=payload,
                source_arch=_binary_format_arch(conn, function_binary[source_id], scope_cache)[1],
                candidate_arch=_binary_format_arch(
                    conn, function_binary[candidate_id], scope_cache
                )[1],
            )
            recorded += 1
        if recorded:
            summary["matched"] += 1
        summary["pairs"] += recorded
        if progress is not None:
            progress(index, total)

    return summary


def difference_of(similarity_score: float) -> float:
    """The platform's Difference metric: ``100 - similarity``.

    Difference is a derived complement, never a stored value; the matches
    payload reports it beside the similarity it came from.
    """
    return round(100.0 - float(similarity_score), DIFFERENCE_DECIMALS)


def binary_match_rows(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    """All recorded matches whose source is a function of *binary_id*.

    Each row pairs the source function with its candidate and carries the
    stored similarity and confidence, the ISA pair of the two binaries, the
    source function's name source, the candidate's owning binary, and the run
    settings the edge was recorded under.  Rows are ordered best similarity first.
    """
    rows: list[dict[str, Any]] = []
    for match in store.list_matches_for_binary(conn, binary_id):
        source_arch = str(match.get("source_arch") or "")
        candidate_arch = str(match.get("candidate_arch") or "")
        rows.append(
            {
                "source_function_id": int(match["source_function_id"]),
                "source_name": str(match["source_name"]),
                "source_va": int(match["source_va"]),
                "source_name_source": str(match.get("source_name_source") or ""),
                "candidate_function_id": int(match["candidate_function_id"]),
                "candidate_name": str(match["candidate_name"]),
                "candidate_va": int(match["candidate_va"]),
                "candidate_binary_id": int(match["candidate_binary_id"]),
                "candidate_binary_name": str(match["candidate_binary_name"]),
                "similarity": float(match["similarity"]),
                "confidence": float(match["confidence"]),
                "source_arch": source_arch,
                "candidate_arch": candidate_arch,
                "cross_arch": bool(
                    source_arch and candidate_arch and source_arch != candidate_arch
                ),
                "settings": match.get("settings"),
            }
        )
    return rows


# ── Symbol transfer ────────────────────────────────────────────────


def _convention(value: str) -> str:
    """A calling convention normalized for comparison: lower case, no underscores."""
    return value.strip().lstrip("_").lower()


def _signature_state(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The previous-state object a signature-history row records.

    Mirrors the shape ``reportal.signatures`` writes, so a transfer's history
    row reads back through the signature routes like any other mutation.
    """
    if row is None:
        return None
    return {
        "name": str(row["name"]),
        "return_type": str(row["return_type"]),
        "calling_convention": str(row["calling_convention"]),
        "parameters": [dict(parameter) for parameter in row["parameters"]],
        "source": str(row["source"]),
    }


def _parameter_pairs(parameters: Sequence[Mapping[str, Any]]) -> list[tuple[str, str]]:
    """A parameter list reduced to its ``(type, name)`` pairs, for comparison."""
    return [(str(parameter["type"]), str(parameter.get("name") or "")) for parameter in parameters]


def _signature_conflict(target: Mapping[str, Any] | None, candidate: Mapping[str, Any]) -> str:
    """The refusal sentence for an ABI-level signature mismatch, or "".

    A target with no signature, or with an empty calling convention, is not a
    conflict: absence is not a different convention.  A differing non-empty
    calling convention is refused, because overwriting it would silently
    change how the target is called.
    """
    if target is None:
        return ""
    current = _convention(str(target["calling_convention"]))
    incoming = _convention(str(candidate["calling_convention"]))
    if not current or not incoming or current == incoming:
        return ""
    return f"target calling convention __{current} differs from the candidate's __{incoming}"


def _signature_differs(target: Mapping[str, Any] | None, incoming: Mapping[str, Any]) -> bool:
    """Whether writing *incoming* would change the target's signature."""
    if target is None:
        return True
    return (
        str(target["return_type"]) != str(incoming["return_type"])
        or _convention(str(target["calling_convention"]))
        != _convention(str(incoming["calling_convention"]))
        or _parameter_pairs(target["parameters"]) != _parameter_pairs(incoming["parameters"])
    )


def _referenced_type_name(type_text: str) -> str:
    """The one local type name a declaration references, or "".

    Primitive and qualifier words, array dimensions and pointer stars are
    dropped.  A declaration referencing no local name, or more than one, yields
    "", so the report never names a type it cannot be sure of.
    """
    body = _ARRAY_SUFFIX_RE.sub(" ", type_text or "")
    names = [token for token in re.findall(r"[A-Za-z_]\w*", body) if token not in _TYPE_WORDS]
    return names[0] if len(names) == 1 else ""


def _missing_referenced_types(
    conn: sqlite3.Connection, binary_id: int, signature: Mapping[str, Any]
) -> tuple[str, ...]:
    """Local type names the signature references that the binary has no row for."""
    referenced: list[str] = []
    for type_text in (
        str(signature["return_type"]),
        *(str(parameter["type"]) for parameter in signature["parameters"]),
    ):
        name = _referenced_type_name(type_text)
        if name and name not in referenced:
            referenced.append(name)
    return tuple(
        name for name in referenced if store.find_data_type_by_name(conn, binary_id, name) is None
    )


def _failed_plan(
    function_id: int, candidate_function_id: int, mode: str, reason: str, detail: str
) -> TransferPlan:
    """A transfer plan that refuses, carrying its reason and sentence."""
    return TransferPlan(
        function_id=function_id,
        candidate_function_id=candidate_function_id,
        mode=mode,
        status=TRANSFER_STATUS_FAILED,
        reason=reason,
        detail=detail,
        old_name="",
        new_name="",
        renames=False,
        signature=None,
        writes_signature=False,
        missing_types=(),
    )


def plan_transfer(
    conn: sqlite3.Connection,
    *,
    function_id: int,
    candidate_function_id: int,
    mode: str = DEFAULT_TRANSFER_MODE,
) -> TransferPlan:
    """Plan one symbol transfer without writing anything.

    The collision policy for a signature transfer: the target's return type,
    calling convention and parameters are replaced, but a target that already
    carries a different non-empty calling convention is refused with reason
    ``signature-conflict``, so an ABI-level mismatch is never overwritten
    silently.  A target with no signature is not a conflict.
    """
    if mode not in TRANSFER_MODES:
        raise InvalidSettingsError(
            "invalid mode", f"unknown mode: {mode}; expected one of {', '.join(TRANSFER_MODES)}"
        )
    function = store.get_function(conn, function_id)
    if function is None:
        return _failed_plan(
            function_id,
            candidate_function_id,
            mode,
            REASON_UNKNOWN_FUNCTION,
            f"no function with id {function_id}",
        )
    candidate = store.get_function(conn, candidate_function_id)
    if candidate is None:
        return _failed_plan(
            function_id,
            candidate_function_id,
            mode,
            REASON_UNKNOWN_CANDIDATE,
            f"no function with id {candidate_function_id}",
        )
    if not store.has_match(conn, function_id, candidate_function_id):
        return _failed_plan(
            function_id,
            candidate_function_id,
            mode,
            REASON_NO_SUCH_MATCH,
            f"no recorded match for {function_id} -> {candidate_function_id}",
        )

    wants_name = mode in (TRANSFER_MODE_NAME, TRANSFER_MODE_BOTH)
    wants_signature = mode in (TRANSFER_MODE_SIGNATURE, TRANSFER_MODE_BOTH)
    target_name = str(function["name"])
    new_name = target_name
    renames = False
    if wants_name:
        candidate_name = str(candidate["name"]).strip()
        if not candidate_name:
            return _failed_plan(
                function_id,
                candidate_function_id,
                mode,
                REASON_CANDIDATE_HAS_NO_NAME,
                f"candidate {candidate_function_id} has no name",
            )
        renames = candidate_name != target_name
        new_name = candidate_name

    signature: dict[str, Any] | None = None
    missing_types: tuple[str, ...] = ()
    writes_signature = False
    if wants_signature:
        candidate_signature = store.get_signature(conn, candidate_function_id)
        if candidate_signature is None:
            return _failed_plan(
                function_id,
                candidate_function_id,
                mode,
                REASON_CANDIDATE_HAS_NO_SIGNATURE,
                f"candidate {candidate_function_id} has no signature",
            )
        target_signature = store.get_signature(conn, function_id)
        conflict = _signature_conflict(target_signature, candidate_signature)
        if conflict:
            return _failed_plan(
                function_id, candidate_function_id, mode, REASON_SIGNATURE_CONFLICT, conflict
            )
        signature = {
            "name": new_name,
            "return_type": str(candidate_signature["return_type"]),
            "calling_convention": str(candidate_signature["calling_convention"]),
            "parameters": [dict(parameter) for parameter in candidate_signature["parameters"]],
        }
        writes_signature = _signature_differs(target_signature, signature)
        missing_types = _missing_referenced_types(conn, int(function["binary_id"]), signature)

    applied = renames or writes_signature
    return TransferPlan(
        function_id=function_id,
        candidate_function_id=candidate_function_id,
        mode=mode,
        status=TRANSFER_STATUS_APPLIED if applied else TRANSFER_STATUS_SKIPPED,
        reason="" if applied else "already matches",
        detail="",
        old_name=target_name,
        new_name=new_name,
        renames=renames,
        signature=signature,
        writes_signature=writes_signature,
        missing_types=missing_types,
    )


def _journal_signature_write(
    conn: sqlite3.Connection,
    log: journal.Journal,
    function_id: int,
    signature: Mapping[str, Any],
    *,
    actor: str,
    actor_user_id: int | None = None,
) -> None:
    """Write one signature, journaling the row and history entry it changes.

    The previous state is recorded in ``signature_history`` before the upsert,
    the contract every signature writer follows, so a later history revert
    restores exactly what this write replaced.
    """
    before = journal.journaled_rows(
        conn,
        log,
        table="function_signatures",
        where="function_id = ?",
        params=(function_id,),
        description=f"replaced the signature of function {function_id}",
    )
    known = [{"id": int(row["id"])} for row in store.list_signature_history(conn, function_id)]
    current = store.get_signature(conn, function_id)
    store.add_signature_history(
        conn,
        function_id=function_id,
        previous=_signature_state(current),
        source=TRANSFER_SOURCE,
        actor=actor,
        actor_user_id=actor_user_id
        if actor_user_id is not None
        else journal.current_actor_user_id(),
    )
    store.upsert_signature(
        conn,
        function_id=function_id,
        name=str(signature["name"]),
        return_type=str(signature["return_type"]),
        calling_convention=str(signature["calling_convention"]),
        parameters=list(signature["parameters"]),
        source=TRANSFER_SOURCE,
    )
    journal.journaled_new_rows(
        conn,
        log,
        table="function_signatures",
        where="function_id = ?",
        params=(function_id,),
        before=before,
        key=("function_id",),
        description=f"signature of function {function_id}",
    )
    journal.journaled_new_rows(
        conn,
        log,
        table="signature_history",
        where="function_id = ?",
        params=(function_id,),
        before=known,
        key=("id",),
        description=f"signature history of function {function_id}",
    )


def apply_transfer(
    conn: sqlite3.Connection,
    log: journal.Journal,
    plan: TransferPlan,
    *,
    actor: str,
    actor_user_id: int | None = None,
) -> None:
    """Apply a planned transfer, journaling every row it changes.

    The name goes through the rename path and the signature through the
    signature-history contract, so one journal action reverts both.
    """
    if plan.renames:
        journal.journaled_rename(
            conn,
            log,
            plan.function_id,
            new_name=plan.new_name,
            actor=actor,
            source=TRANSFER_SOURCE,
            actor_user_id=actor_user_id,
        )
    if plan.writes_signature and plan.signature is not None:
        _journal_signature_write(
            conn, log, plan.function_id, plan.signature, actor=actor, actor_user_id=actor_user_id
        )


def plan_payload(plan: TransferPlan) -> dict[str, Any]:
    """The JSON report of one planned or applied transfer."""
    return {
        "function_id": plan.function_id,
        "candidate_function_id": plan.candidate_function_id,
        "mode": plan.mode,
        "status": plan.status,
        "reason": plan.reason,
        "detail": plan.detail,
        "name_changed": plan.renames,
        "old_name": plan.old_name,
        "new_name": plan.new_name,
        "signature_changed": plan.writes_signature,
        "missing_types": list(plan.missing_types),
    }


def transfer_matches(
    conn: sqlite3.Connection,
    log: journal.Journal | None,
    *,
    requests: Sequence[TransferRequest],
    actor: str,
    binary_id: int | None = None,
    dry_run: bool = False,
    visible_to: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Plan and apply a batch of symbol transfers as one journaled action.

    Each row is planned first.  A row that cannot be planned, or whose function
    does not belong to *binary_id* when one is given, is reported failed with
    its reason and never blocks the others; a row with nothing to change is
    reported skipped.  Without *dry_run* the applied rows are written and
    journaled into *log*, so the whole action reverts as one journal entry.
    With *dry_run* nothing is written and *log* may be None.

    A write that fails mid-batch is that row's failure, not the whole batch's:
    the rows that already applied keep their result and stay journaled.
    ``visible_to`` refuses a row whose candidate sits on a binary the caller
    may not see, so a transfer never copies a hidden name or signature; the
    refusal reads as unknown, like the match scope.
    """
    from reportal import auth

    scope = auth.visible_clause(conn, visible_to, prefix="b.")
    visible: set[int] | None = None
    if scope is not None:
        clause, params = scope
        visible = {
            int(row["id"])
            for row in conn.execute(f"SELECT b.id AS id FROM binaries b WHERE {clause}", params)
        }
    rows: list[dict[str, Any]] = []
    applied = 0
    skipped = 0
    failed = 0
    for request in requests:
        plan = plan_transfer(
            conn,
            function_id=request.function_id,
            candidate_function_id=request.candidate_function_id,
            mode=request.mode,
        )
        if plan.status == TRANSFER_STATUS_APPLIED and visible is not None:
            candidate = store.get_function(conn, request.candidate_function_id)
            candidate_binary = int(candidate["binary_id"]) if candidate is not None else -1
            if candidate_binary not in visible:
                plan = _failed_plan(
                    request.function_id,
                    request.candidate_function_id,
                    request.mode,
                    REASON_UNKNOWN_CANDIDATE,
                    f"no function with id {request.candidate_function_id}",
                )
        if plan.status == TRANSFER_STATUS_APPLIED and binary_id is not None:
            owner = store.get_function(conn, request.function_id)
            owner_binary = int(owner["binary_id"]) if owner is not None else -1
            if owner_binary != binary_id:
                plan = _failed_plan(
                    request.function_id,
                    request.candidate_function_id,
                    request.mode,
                    REASON_OUT_OF_BINARY,
                    f"function {request.function_id} is not a function of binary {binary_id}",
                )
        if plan.status == TRANSFER_STATUS_APPLIED and not dry_run:
            if log is None:
                raise ValueError("a non-dry-run transfer needs a journal")
            try:
                apply_transfer(conn, log, plan, actor=actor)
            except Exception as exc:  # one row's write failure must not strand the rest
                plan = _failed_plan(
                    request.function_id,
                    request.candidate_function_id,
                    request.mode,
                    REASON_WRITE_FAILED,
                    str(exc),
                )
        rows.append(plan_payload(plan))
        if plan.status == TRANSFER_STATUS_APPLIED:
            applied += 1
        elif plan.status == TRANSFER_STATUS_SKIPPED:
            skipped += 1
        else:
            failed += 1
    return {
        "requested": len(requests),
        "applied": applied,
        "skipped": skipped,
        "failed": failed,
        "dry_run": dry_run,
        "transfers": rows,
    }
