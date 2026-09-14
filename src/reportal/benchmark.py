"""Measuring how often a run finds the counterpart an analyst already knows.

reportal matches functions by assembly similarity and transfers names from the
candidates it ranks, but it never said how often it is right.  This module runs
the ordinary match over one labelled pair of binaries and reports precision,
recall, F1 and mean reciprocal rank against those labels, so a corpus that
matters can answer whether a setting, an extra or an engine change helped.

The labels are the analyst's: a corpus names, for a pair of binaries, the
function virtual addresses that correspond.  Without a corpus the labels are
derived from the two binaries' own function names, which is a weaker source and
the payload says so: a name the two share is exactly the case a name transfer
gets right for free, so a run labelled that way reads high.

Nothing here re-ranks or re-implements matching.  The run is
:func:`reportal.matching.match_binary` with the partner binary as its scope and
the metrics are read from the rows it recorded, so the benchmark measures the
matcher the portal actually uses.  The CLI reads a corpus file; the route and
the MCP tool take the pairs in the request body, so no request names a path.
The result is stored as the left binary's ``benchmark`` scan.

Rename proposals are not measured here.  A proposal's correctness needs a
labelled name (not only a labelled address) and a proposal source: the
deterministic one is the engine's library identification, which is what
``library.py`` stores.  The labels this module reads carry the counterpart, not
the name, and inventing a name metric from a signature match would measure the
label rather than the rename.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from reportal import engines, function_triage, matching, store

# The scan kind one benchmark is stored under.
SCAN_KIND = "benchmark"

LABEL_SOURCE_CORPUS = "corpus"
LABEL_SOURCE_NAMES = "names"

# Labels one run reads.  A corpus larger than this is truncated, and the note
# says so rather than reporting numbers from a silently smaller sample.
MAX_LABELS = 2000

ERROR_INVALID_LABELS = "invalid-labels"
ERROR_NO_LABELS = "no-labels"

NO_LABELS_DETAIL = (
    "no labels to score against: name the corresponding virtual addresses in the"
    " request body, or point the CLI at a corpus file, or import two binaries that"
    " share a real function name"
)
SAMPLED_NOTE = "the labels come from the two binaries' own names, not from a corpus"
CORPUS_NOTE = "the labels come from the corpus the caller supplied"
SCOPE_NOTE = "candidates are the partner binary's functions only"


class BenchmarkError(Exception):
    """A benchmark the caller refuses, as ``(code, detail)``."""

    code = ERROR_INVALID_LABELS

    def __init__(self, detail: str, code: str = ERROR_INVALID_LABELS) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


def _address(value: Any, field: str, index: int) -> int:
    """A virtual address from an int, a decimal string or a ``0x`` string."""
    if isinstance(value, bool):
        raise BenchmarkError(f"labels[{index}].{field} must be an integer address")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 0)
        except ValueError:
            raise BenchmarkError(f"labels[{index}].{field} is not an address: {value!r}") from None
    raise BenchmarkError(f"labels[{index}].{field} must be an integer address")


def _real_names(conn: sqlite3.Connection, binary_id: int) -> dict[str, dict[str, Any]]:
    """One binary's real function names, lowercased, ambiguous names dropped.

    A name that appears twice on a side cannot label anything: the pair would
    point at whichever row the map kept.
    """
    seen: dict[str, dict[str, Any] | None] = {}
    for function in store.list_functions(conn, binary_id=binary_id):
        name = str(function["name"] or "")
        if function_triage.is_placeholder_name(name):
            continue
        key = name.lower()
        seen[key] = (
            None
            if key in seen
            else {"name": name, "id": int(function["id"]), "va": int(function["va"])}
        )
    return {key: row for key, row in seen.items() if row is not None}


def _address_index(conn: sqlite3.Connection, binary_id: int) -> dict[int, dict[str, Any]]:
    """One binary's functions keyed by virtual address."""
    return {
        int(function["va"]): function
        for function in store.list_functions(conn, binary_id=binary_id)
    }


def labels_from_names(
    conn: sqlite3.Connection, left_binary_id: int, right_binary_id: int
) -> list[dict[str, Any]]:
    """The corresponding addresses the two binaries' own names state.

    A placeholder name is skipped, and so is a name either side carries twice,
    so the result is only the names that identify one function each.  Every
    shared name is returned, best name first; :func:`run` caps the list it
    scores at :data:`MAX_LABELS` and reports the cap.
    """
    left = _real_names(conn, left_binary_id)
    right = _real_names(conn, right_binary_id)
    labels: list[dict[str, Any]] = []
    for name in sorted(left):
        if name not in right:
            continue
        labels.append(
            {
                "name": left[name]["name"],
                "left_va": left[name]["va"],
                "right_va": right[name]["va"],
            }
        )
    return labels


def load_labels(path: str | Path) -> list[dict[str, Any]]:
    """Read a corpus file: ``{"pairs": [{"left_va", "right_va"}, ...]}``."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BenchmarkError(f"cannot read {path}: {exc}") from None
    if not isinstance(payload, Mapping):
        raise BenchmarkError("a corpus is a JSON object with a 'pairs' list")
    pairs = payload.get("pairs")
    if not isinstance(pairs, list) or not pairs:
        raise BenchmarkError("a corpus needs a non-empty 'pairs' list")
    rows: list[dict[str, Any]] = []
    for index, entry in enumerate(pairs):
        if not isinstance(entry, Mapping):
            raise BenchmarkError(f"pairs[{index}] is not an object")
        rows.append(dict(entry))
    return rows


def _resolve(
    raw: Sequence[Any],
    left_index: Mapping[int, Mapping[str, Any]],
    right_index: Mapping[int, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Resolve raw label entries into function ids, reporting the ones that miss."""
    resolved: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise BenchmarkError(f"labels[{index}] is not an object")
        left_va = _address(entry.get("left_va"), "left_va", index)
        right_va = _address(entry.get("right_va"), "right_va", index)
        left_row = left_index.get(left_va)
        right_row = right_index.get(right_va)
        if left_row is None or right_row is None:
            unmatched.append(
                {
                    "left_va": left_va,
                    "right_va": right_va,
                    "reason": (
                        f"no function at {left_va:#x} in the left binary"
                        if left_row is None
                        else f"no function at {right_va:#x} in the right binary"
                    ),
                }
            )
            continue
        resolved.append(
            {
                "name": str(entry.get("name") or left_row["name"]),
                "left_va": left_va,
                "left_function_id": int(left_row["id"]),
                "right_va": right_va,
                "right_function_id": int(right_row["id"]),
            }
        )
    return resolved, unmatched


def metrics(
    labels: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]], *, top: int
) -> dict[str, Any]:
    """Precision, recall, F1 and mean reciprocal rank of *rows* against *labels*.

    One query is one labelled source function.  Its retrieval is the recorded
    rows whose source it is, best similarity first and capped at *top* (the same
    cap the run wrote), and a hit is a row whose candidate is the labelled
    counterpart.  Precision is over the retrieved rows, so it answers "how many
    of the proposals were right"; recall is over the queries, so it answers "how
    many of the known pairs were found"; MRR averages the reciprocal rank of the
    first hit and counts a miss as zero.  Every query's rank is in ``detail``,
    so a miss can be read rather than guessed at.
    """
    by_source: dict[int, list[Mapping[str, Any]]] = {}
    for row in rows:
        by_source.setdefault(int(row["source_function_id"]), []).append(row)
    detail: list[dict[str, Any]] = []
    misses: list[dict[str, Any]] = []
    retrieved = 0
    hits = 0
    reciprocal = 0.0
    ranks: list[int] = []
    for label in labels:
        candidates = by_source.get(int(label["left_function_id"]), [])[:top]
        retrieved += len(candidates)
        rank: int | None = None
        score: float | None = None
        for position, row in enumerate(candidates, start=1):
            if int(row["candidate_function_id"]) == int(label["right_function_id"]):
                rank = position
                score = float(row["similarity"])
                break
        if rank is None:
            misses.append(
                {
                    "name": label["name"],
                    "left_va": label["left_va"],
                    "right_va": label["right_va"],
                    "candidates": len(candidates),
                }
            )
        else:
            hits += 1
            reciprocal += 1.0 / rank
            ranks.append(rank)
        detail.append(
            {
                "name": label["name"],
                "left_va": label["left_va"],
                "right_va": label["right_va"],
                "rank": rank,
                "similarity": score,
                "candidates": len(candidates),
            }
        )
    queries = len(labels)
    precision = hits / retrieved if retrieved else 0.0
    recall = hits / queries if queries else 0.0
    total = precision + recall
    return {
        "queries": queries,
        "retrieved": retrieved,
        "hits": hits,
        "top": top,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / total, 4) if total else 0.0,
        "mrr": round(reciprocal / queries, 4) if queries else 0.0,
        "mean_rank": round(sum(ranks) / len(ranks), 2) if ranks else None,
        "misses": misses,
        "detail": detail,
    }


def run(
    conn: sqlite3.Connection,
    *,
    left_binary_id: int,
    right_binary_id: int,
    engine: engines.RebrewEngine,
    labels: Sequence[Any] | None = None,
    settings: matching.MatchSettings | None = None,
    scorer: matching.Scorer | None = None,
    disassembler: matching.Disassembler | None = None,
) -> dict[str, Any]:
    """Match the left binary against the right and score the run against labels.

    *labels* is a sequence of ``{"left_va", "right_va"}`` objects; without one
    the labels are derived from the two binaries' own names.  *settings*
    defaults to the partner binary as the whole scope with ``include_self`` off,
    so the run answers "did the matcher find the known counterpart among the
    candidates from the binary it came from" and never scores a source function
    against itself.  A caller that names its own scope keeps it, and the payload
    still states the labels that scope cannot reach.

    Raises :class:`BenchmarkError` for an unknown binary, the same binary twice,
    a malformed label, or a label set that resolves to nothing.
    """
    left = store.get_binary(conn, left_binary_id)
    if left is None:
        raise BenchmarkError(f"no binary with id {left_binary_id}", code="binary not found")
    right = store.get_binary(conn, right_binary_id)
    if right is None:
        raise BenchmarkError(f"no binary with id {right_binary_id}", code="binary not found")
    if left_binary_id == right_binary_id:
        raise BenchmarkError("a benchmark compares two different binaries")
    resolved_settings = (
        settings
        if settings is not None
        else matching.MatchSettings(binary_ids=(right_binary_id,), include_self=False)
    )
    source = LABEL_SOURCE_CORPUS if labels is not None else LABEL_SOURCE_NAMES
    raw = (
        list(labels)
        if labels is not None
        else labels_from_names(conn, left_binary_id, right_binary_id)
    )
    if not raw:
        raise BenchmarkError(NO_LABELS_DETAIL, code=ERROR_NO_LABELS)
    truncated = len(raw) > MAX_LABELS
    resolved_labels, unmatched = _resolve(
        raw[:MAX_LABELS],
        _address_index(conn, left_binary_id),
        _address_index(conn, right_binary_id),
    )
    if not resolved_labels:
        raise BenchmarkError(
            f"{NO_LABELS_DETAIL}; none of the {len(raw)} label(s) names a stored function"
            " in both binaries",
            code=ERROR_NO_LABELS,
        )
    summary = matching.match_binary(
        conn,
        binary_id=left_binary_id,
        engine=engine,
        scorer=scorer,
        disassembler=disassembler,
        settings=resolved_settings,
    )
    scored = metrics(
        resolved_labels, matching.binary_match_rows(conn, left_binary_id), top=resolved_settings.top
    )
    notes = [CORPUS_NOTE if source == LABEL_SOURCE_CORPUS else SAMPLED_NOTE, SCOPE_NOTE]
    if source == LABEL_SOURCE_NAMES:
        notes.append(
            "a name the two binaries share is the case a name transfer gets right for"
            " free, so a run labelled this way reads high"
        )
    if resolved_settings.binary_ids != (right_binary_id,):
        notes.append(f"the candidates are the caller's scope {list(resolved_settings.binary_ids)}")
    if truncated:
        notes.append(f"the first {MAX_LABELS} of {len(raw)} labels were scored")
    if unmatched:
        notes.append(f"{len(unmatched)} label(s) name no stored function in both binaries")
    if summary["pairs"] == 0:
        notes.append(
            "the run recorded no candidate at or above the similarity floor, so every"
            " query missed; lower min_similarity or install the similarity extra"
        )
    return {
        "stored": True,
        "left": {"binary_id": left_binary_id, "name": str(left["name"])},
        "right": {"binary_id": right_binary_id, "name": str(right["name"])},
        "label_source": source,
        "labels": {
            "count": len(resolved_labels),
            "truncated": truncated,
            "unmatched": unmatched,
        },
        "settings": resolved_settings.payload(),
        "scope_notes": matching.scope_notes(resolved_settings),
        "matching": summary,
        "metrics": scored,
        "notes": notes,
    }


def describe(conn: sqlite3.Connection, binary_id: int) -> dict[str, Any]:
    """The stored benchmark of one binary, or an empty reading.

    Raises :class:`BenchmarkError` for an unknown binary.  A binary no benchmark
    scored answers ``stored: false`` and names the command that produces one,
    because "never measured" and "measured and missed everything" are different
    answers and only one of them is a result.
    """
    binary = store.get_binary(conn, binary_id)
    if binary is None:
        raise BenchmarkError(f"no binary with id {binary_id}", code="binary not found")
    analysis_id = store.latest_analysis_for_binary(conn, binary_id)
    stored = None if analysis_id is None else store.get_scan(conn, analysis_id, SCAN_KIND)
    if stored is None:
        return {
            "binary_id": binary_id,
            "binary_name": str(binary["name"]),
            "stored": False,
            "metrics": None,
            "notes": [f"no stored benchmark scan; run 'reportal benchmark {binary_id} <right-id>'"],
        }
    return stored
